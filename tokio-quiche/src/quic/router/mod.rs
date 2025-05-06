// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

pub(crate) mod acceptor;
pub(crate) mod connector;

use super::connection::ConnectionMap;
use super::connection::HandshakeInfo;
use super::connection::Incoming;
use super::connection::InitialQuicConnection;
use super::connection::QuicConnectionParams;
use super::io::worker::WriterConfig;
use super::QuicheConnection;
use crate::buf_factory::BufFactory;
use crate::buf_factory::PooledBuf;
use crate::metrics::labels;
use crate::metrics::quic_expensive_metrics_ip_reduce;
use crate::metrics::Metrics;
use crate::settings::Config;

use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use foundations::telemetry::log;
#[cfg(target_os = "linux")]
use foundations::telemetry::metrics::Counter;
#[cfg(target_os = "linux")]
use foundations::telemetry::metrics::TimeHistogram;
#[cfg(target_os = "linux")]
use libc::sockaddr_in;
#[cfg(target_os = "linux")]
use libc::sockaddr_in6;
use quiche::ConnectionId;
use quiche::Header;
use quiche::MAX_CONN_ID_LEN;
use std::default::Default;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;
use std::time::SystemTime;
use task_killswitch::spawn_with_killswitch;
use tokio::sync::mpsc;

type ConnStream<Tx, M> = mpsc::Receiver<io::Result<InitialQuicConnection<Tx, M>>>;

#[cfg(feature = "perf-quic-listener-metrics")]
mod listener_stage_timer {
    use foundations::telemetry::metrics::TimeHistogram;
    use std::time::Instant;

    pub(super) struct ListenerStageTimer {
        start: Instant,
        time_hist: TimeHistogram,
    }

    impl ListenerStageTimer {
        pub(super) fn new(
            start: Instant, time_hist: TimeHistogram,
        ) -> ListenerStageTimer {
            ListenerStageTimer { start, time_hist }
        }
    }

    impl Drop for ListenerStageTimer {
        fn drop(&mut self) {
            self.time_hist
                .observe((Instant::now() - self.start).as_nanos() as u64);
        }
    }
}

#[derive(Debug)]
struct PollRecvData {
    bytes: usize,
    // The packet's source, e.g., the peer's address
    src_addr: SocketAddr,
    // The packet's original destination. If the original destination is
    // different from the local listening address, this will be `None`.
    dst_addr_override: Option<SocketAddr>,
    rx_time: Option<SystemTime>,
    gro: Option<u16>,
}

/// A message to the listener notifiying a mapping for a connection should be
/// removed.
pub enum ConnectionMapCommand {
    UnmapCid(ConnectionId<'static>),
    RemoveScid(ConnectionId<'static>),
}

/// An `InboundPacketRouter` maintains a map of quic connections and routes
/// [`Incoming`] packets from the [recv half][rh] of a datagram socket to those
/// connections or some quic initials handler.
///
/// [rh]: datagram_socket::DatagramSocketRecv
///
/// When a packet (or batch of packets) is received, the router will either
/// route those packets to an established
/// [`QuicConnection`](super::QuicConnection) or have a them handled by a
/// `InitialPacketHandler` which either acts as a quic listener or
/// quic connector, a server or client respectively.
///
/// If you only have a single connection, or if you need more control over the
/// socket, use `QuicConnection` directly instead.
pub struct InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    socket_tx: Arc<Tx>,
    socket_rx: Rx,
    local_addr: SocketAddr,
    config: Config,
    conns: ConnectionMap,
    incoming_packet_handler: I,
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: mpsc::Receiver<()>,
    conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
    conn_map_cmd_rx: mpsc::UnboundedReceiver<ConnectionMapCommand>,
    accept_sink: mpsc::Sender<io::Result<InitialQuicConnection<Tx, M>>>,
    metrics: M,
    #[cfg(target_os = "linux")]
    udp_drop_count: u32,

    #[cfg(target_os = "linux")]
    reusable_cmsg_space: Vec<u8>,

    current_buf: PooledBuf,

    // We keep the metrics in here, to avoid cloning them each packet
    #[cfg(target_os = "linux")]
    metrics_handshake_time_seconds: TimeHistogram,
    #[cfg(target_os = "linux")]
    metrics_udp_drop_count: Counter,
}

impl<Tx, Rx, M, I> InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + 'static,
    Rx: DatagramSocketRecv,
    M: Metrics,
    I: InitialPacketHandler,
{
    pub(crate) fn new(
        config: Config, socket_tx: Arc<Tx>, socket_rx: Rx,
        local_addr: SocketAddr, incoming_packet_handler: I, metrics: M,
    ) -> (Self, ConnStream<Tx, M>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (accept_sink, accept_stream) = mpsc::channel(config.listen_backlog);
        let (conn_map_cmd_tx, conn_map_cmd_rx) = mpsc::unbounded_channel();

        (
            InboundPacketRouter {
                local_addr,
                socket_tx,
                socket_rx,
                conns: ConnectionMap::default(),
                incoming_packet_handler,
                shutdown_tx: Some(shutdown_tx),
                shutdown_rx,
                conn_map_cmd_tx,
                conn_map_cmd_rx,
                accept_sink,
                #[cfg(target_os = "linux")]
                udp_drop_count: 0,
                #[cfg(target_os = "linux")]
                // Specify CMSG space for GRO, timestamp, drop count, IP_RECVORIGDSTADDR, and
                // IPV6_RECVORIGDSTADDR. Even if they're not all currently used, the cmsg buffer
                // may have been configured by a previous version of Tokio-Quiche with the socket
                // re-used on graceful restart. As such, this vector should _only grow_, and care
                // should be taken when adding new cmsgs.
                reusable_cmsg_space: nix::cmsg_space!(u32, nix::sys::time::TimeSpec, u16, sockaddr_in, sockaddr_in6),
                config,

                current_buf: BufFactory::get_max_buf(),

                #[cfg(target_os = "linux")]
                metrics_handshake_time_seconds: metrics.handshake_time_seconds(labels::QuicHandshakeStage::QueueWaiting),
                #[cfg(target_os = "linux")]
                metrics_udp_drop_count: metrics.udp_drop_count(),

                metrics,

            },
            accept_stream,
        )
    }

    fn on_incoming(&mut self, mut incoming: Incoming) -> io::Result<()> {
        #[cfg(feature = "perf-quic-listener-metrics")]
        let start = std::time::Instant::now();

        if let Some(dcid) = short_dcid(&incoming.buf) {
            if let Some(ev_sender) = self.conns.get(&dcid) {
                let _ = ev_sender.try_send(incoming);
                return Ok(());
            }
        }

        let hdr = Header::from_slice(&mut incoming.buf, MAX_CONN_ID_LEN)
            .map_err(|e| match e {
                quiche::Error::BufferTooShort | quiche::Error::InvalidPacket =>
                    labels::QuicInvalidInitialPacketError::FailedToParse.into(),
                e => io::Error::other(e),
            })?;

        if let Some(ev_sender) = self.conns.get(&hdr.dcid) {
            let _ = ev_sender.try_send(incoming);
            return Ok(());
        }

        #[cfg(feature = "perf-quic-listener-metrics")]
        let _timer = listener_stage_timer::ListenerStageTimer::new(
            start,
            self.metrics.handshake_time_seconds(
                labels::QuicHandshakeStage::HandshakeProtocol,
            ),
        );

        if self.shutdown_tx.is_none() {
            return Ok(());
        }

        let local_addr = incoming.local_addr;
        let peer_addr = incoming.peer_addr;

        #[cfg(feature = "perf-quic-listener-metrics")]
        let init_rx_time = incoming.rx_time;

        let new_connection = self.incoming_packet_handler.handle_initials(
            incoming,
            hdr,
            self.config.as_mut(),
        )?;

        match new_connection {
            Some(new_connection) => self.spawn_new_connection(
                new_connection,
                local_addr,
                peer_addr,
                #[cfg(feature = "perf-quic-listener-metrics")]
                init_rx_time,
            ),
            None => Ok(()),
        }
    }

    /// Creates a new [`QuicConnection`](super::QuicConnection) and spawns an
    /// associated io worker.
    fn spawn_new_connection(
        &mut self, new_connection: NewConnection, local_addr: SocketAddr,
        peer_addr: SocketAddr,
        #[cfg(feature = "perf-quic-listener-metrics")] init_rx_time: Option<
            SystemTime,
        >,
    ) -> io::Result<()> {
        let NewConnection {
            conn,
            pending_cid,
            handshake_start_time,
            initial_pkt,
        } = new_connection;

        let Some(ref shutdown_tx) = self.shutdown_tx else {
            // don't create new connections if we're shutting down.
            return Ok(());
        };
        let Ok(send_permit) = self.accept_sink.try_reserve() else {
            // drop the connection if the backlog is full. the client will retry.
            return Err(
                labels::QuicInvalidInitialPacketError::AcceptQueueOverflow.into(),
            );
        };

        let scid = conn.source_id().into_owned();
        let writer_cfg = WriterConfig {
            peer_addr,
            pending_cid: pending_cid.clone(),
            with_gso: self.config.has_gso,
            pacing_offload: self.config.pacing_offload,
            with_pktinfo: if self.local_addr.is_ipv4() {
                self.config.has_ippktinfo
            } else {
                self.config.has_ipv6pktinfo
            },
        };

        let handshake_info = HandshakeInfo::new(
            handshake_start_time,
            self.config.handshake_timeout,
        );

        let conn = InitialQuicConnection::new(QuicConnectionParams {
            writer_cfg,
            initial_pkt,
            shutdown_tx: shutdown_tx.clone(),
            conn_map_cmd_tx: self.conn_map_cmd_tx.clone(),
            scid: scid.clone(),
            metrics: self.metrics.clone(),
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time,
            handshake_info,
            quiche_conn: conn,
            socket: Arc::clone(&self.socket_tx),
            local_addr,
            peer_addr,
        });

        conn.audit_log_stats
            .set_transport_handshake_start(instant_to_system(
                handshake_start_time,
            ));

        self.conns.insert(scid, &conn);

        // Add the client-generated "pending" connection ID to the map as well.
        //
        // This is only required when client address validation is disabled.
        // When validation is enabled, the client is already using the
        // server-generated connection ID by the time we get here.
        if let Some(pending_cid) = pending_cid {
            self.conns.map_cid(pending_cid, &conn);
        }

        self.metrics.accepted_initial_packet_count().inc();
        if self.config.enable_expensive_packet_count_metrics {
            if let Some(peer_ip) =
                quic_expensive_metrics_ip_reduce(conn.peer_addr().ip())
            {
                self.metrics
                    .expensive_accepted_initial_packet_count(peer_ip)
                    .inc();
            }
        }

        send_permit.send(Ok(conn));
        Ok(())
    }
}

impl<Tx, Rx, M, I> InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + Sync + 'static,
    Rx: DatagramSocketRecv,
    M: Metrics,
    I: InitialPacketHandler,
{
    /// [`InboundPacketRouter::poll_recv_from`] should be used if the underlying
    /// system or socket does not support rx_time nor GRO.
    fn poll_recv_from(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<io::Result<PollRecvData>> {
        let mut buf = tokio::io::ReadBuf::new(&mut self.current_buf);
        let addr = ready!(self.socket_rx.poll_recv_from(cx, &mut buf))?;
        Poll::Ready(Ok(PollRecvData {
            bytes: buf.filled().len(),
            src_addr: addr,
            rx_time: None,
            gro: None,
            dst_addr_override: None,
        }))
    }

    fn poll_recv_and_rx_time(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<io::Result<PollRecvData>> {
        #[cfg(not(target_os = "linux"))]
        {
            self.poll_recv_from(cx)
        }

        #[cfg(target_os = "linux")]
        {
            use nix::errno::Errno;
            use nix::sys::socket::*;
            use std::net::SocketAddrV4;
            use std::net::SocketAddrV6;
            use std::os::fd::AsRawFd;
            use tokio::io::Interest;

            let Some(udp_socket) = self.socket_rx.as_udp_socket() else {
                // the given socket is not a UDP socket, fall back to the
                // simple poll_recv_from.
                return self.poll_recv_from(cx);
            };

            self.reusable_cmsg_space.clear();

            loop {
                let iov_s = &mut [io::IoSliceMut::new(&mut self.current_buf)];
                match udp_socket.try_io(Interest::READABLE, || {
                    recvmsg::<SockaddrStorage>(
                        udp_socket.as_raw_fd(),
                        iov_s,
                        Some(&mut self.reusable_cmsg_space),
                        MsgFlags::empty(),
                    )
                    .map_err(|x| x.into())
                }) {
                    Ok(r) => {
                        let bytes = r.bytes;

                        let address = match r.address {
                            Some(inner) => inner,
                            _ => return Poll::Ready(Err(Errno::EINVAL.into())),
                        };

                        let peer_addr = match address.family() {
                            Some(AddressFamily::Inet) => SocketAddrV4::from(
                                *address.as_sockaddr_in().unwrap(),
                            )
                            .into(),
                            Some(AddressFamily::Inet6) => SocketAddrV6::from(
                                *address.as_sockaddr_in6().unwrap(),
                            )
                            .into(),
                            _ => {
                                return Poll::Ready(Err(Errno::EINVAL.into()));
                            },
                        };

                        let mut rx_time = None;
                        let mut gro = None;
                        let mut dst_addr_override = None;

                        for cmsg in r.cmsgs() {
                            match cmsg {
                                ControlMessageOwned::RxqOvfl(c) => {
                                    if c != self.udp_drop_count {
                                        self.metrics_udp_drop_count.inc_by(
                                            (c - self.udp_drop_count) as u64,
                                        );
                                        self.udp_drop_count = c;
                                    }
                                },
                                ControlMessageOwned::ScmTimestampns(val) => {
                                    rx_time = SystemTime::UNIX_EPOCH
                                        .checked_add(val.into());
                                    if let Some(delta) =
                                        rx_time.and_then(|rx_time| {
                                            rx_time.elapsed().ok()
                                        })
                                    {
                                        self.metrics_handshake_time_seconds
                                            .observe(delta.as_nanos() as u64);
                                    }
                                },
                                ControlMessageOwned::UdpGroSegments(val) =>
                                    gro = Some(val),
                                ControlMessageOwned::Ipv4OrigDstAddr(val) => {
                                    let source_addr = std::net::Ipv4Addr::from(
                                        u32::to_be(val.sin_addr.s_addr),
                                    );
                                    let source_port = u16::to_be(val.sin_port);

                                    let parsed_addr =
                                        SocketAddr::V4(SocketAddrV4::new(
                                            source_addr,
                                            source_port,
                                        ));

                                    dst_addr_override = resolve_dst_addr(
                                        &self.local_addr,
                                        &parsed_addr,
                                    );
                                },
                                ControlMessageOwned::Ipv6OrigDstAddr(val) => {
                                    // Don't have to flip IPv6 bytes since it's a
                                    // byte array, not a
                                    // series of bytes parsed as a u32 as in the
                                    // IPv4 case
                                    let source_addr = std::net::Ipv6Addr::from(
                                        val.sin6_addr.s6_addr,
                                    );
                                    let source_port = u16::to_be(val.sin6_port);
                                    let source_flowinfo =
                                        u32::to_be(val.sin6_flowinfo);
                                    let source_scope =
                                        u32::to_be(val.sin6_scope_id);

                                    let parsed_addr =
                                        SocketAddr::V6(SocketAddrV6::new(
                                            source_addr,
                                            source_port,
                                            source_flowinfo,
                                            source_scope,
                                        ));

                                    dst_addr_override = resolve_dst_addr(
                                        &self.local_addr,
                                        &parsed_addr,
                                    );
                                },
                                ControlMessageOwned::Ipv4PacketInfo(_) |
                                ControlMessageOwned::Ipv6PacketInfo(_) => {
                                    // We only want the destination address from
                                    // IP_RECVORIGDSTADDR, but we'll get these
                                    // messages because
                                    // we set IP_PKTINFO on the socket.
                                },
                                _ => {
                                    return Poll::Ready(
                                        Err(Errno::EINVAL.into()),
                                    );
                                },
                            };
                        }

                        return Poll::Ready(Ok(PollRecvData {
                            bytes,
                            src_addr: peer_addr,
                            dst_addr_override,
                            rx_time,
                            gro,
                        }));
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // NOTE: we manually poll the socket here to register
                        // interest in the socket to become
                        // writable for the given `cx`. Under the hood, tokio's
                        // implementation just checks for
                        // EWOULDBLOCK and if socket is busy registers provided
                        // waker to be invoked when the
                        // socket is free and consequently drive the event loop.
                        ready!(udp_socket.poll_recv_ready(cx))?
                    },
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
    }

    fn handle_conn_map_commands(&mut self) {
        while let Ok(req) = self.conn_map_cmd_rx.try_recv() {
            match req {
                ConnectionMapCommand::UnmapCid(cid) => self.conns.unmap_cid(&cid),
                ConnectionMapCommand::RemoveScid(scid) =>
                    self.conns.remove(&scid),
            }
        }
    }
}

// Quickly extract the connection id of a short quic packet without allocating
fn short_dcid(buf: &[u8]) -> Option<ConnectionId<'_>> {
    let is_short_dcid = buf.first()? >> 7 == 0;

    if is_short_dcid {
        buf.get(1..1 + MAX_CONN_ID_LEN).map(ConnectionId::from_ref)
    } else {
        None
    }
}

/// Converts an [`Instant`] to a [`SystemTime`], based on the current delta
/// between both clocks.
fn instant_to_system(ts: Instant) -> SystemTime {
    let now = Instant::now();
    let system_now = SystemTime::now();
    if let Some(delta) = now.checked_duration_since(ts) {
        return system_now - delta;
    }

    let delta = ts.checked_duration_since(now).expect("now < ts");
    system_now + delta
}

/// Determine if we should store the destination address for a packet, based on
/// an address parsed from a
/// [`ControlMessageOwned`](nix::sys::socket::ControlMessageOwned).
///
/// This is to prevent overriding the destination address if the packet was
/// originally addressed to `local`, as that would cause us to incorrectly
/// address packets when sending.
///
/// Returns the parsed address if it should be stored.
#[cfg(target_os = "linux")]
fn resolve_dst_addr(
    local: &SocketAddr, parsed: &SocketAddr,
) -> Option<SocketAddr> {
    if local != parsed {
        return Some(*parsed);
    }

    None
}

impl<Tx, Rx, M, I> Future for InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + Sync + 'static,
    Rx: DatagramSocketRecv + Unpin,
    M: Metrics,
    I: InitialPacketHandler + Unpin,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let server_addr = self.local_addr;

        loop {
            if let Err(error) = self.incoming_packet_handler.update(cx) {
                // This is so rare that it's easier to spawn a separate task
                let sender = self.accept_sink.clone();
                spawn_with_killswitch(async move {
                    let _ = sender.send(Err(error)).await;
                });
            }

            match self.poll_recv_and_rx_time(cx) {
                Poll::Ready(Ok(PollRecvData {
                    bytes,
                    src_addr: peer_addr,
                    dst_addr_override,
                    rx_time,
                    gro,
                })) => {
                    let mut buf = std::mem::replace(
                        &mut self.current_buf,
                        BufFactory::get_max_buf(),
                    );
                    buf.truncate(bytes);

                    let send_from = if let Some(dst_addr) = dst_addr_override {
                        log::trace!("overriding local address"; "actual_local" => format!("{:?}", dst_addr), "configured_local" => format!("{:?}", server_addr));
                        dst_addr
                    } else {
                        server_addr
                    };

                    let res = self.on_incoming(Incoming {
                        peer_addr,
                        local_addr: send_from,
                        buf,
                        rx_time,
                        gro,
                    });

                    if let Err(e) = res {
                        let err_type = initial_packet_error_type(&e);
                        self.metrics
                            .rejected_initial_packet_count(err_type.clone())
                            .inc();

                        if self.config.enable_expensive_packet_count_metrics {
                            if let Some(peer_ip) =
                                quic_expensive_metrics_ip_reduce(peer_addr.ip())
                            {
                                self.metrics
                                    .expensive_rejected_initial_packet_count(
                                        err_type.clone(),
                                        peer_ip,
                                    )
                                    .inc();
                            }
                        }

                        if matches!(
                            err_type,
                            labels::QuicInvalidInitialPacketError::Unexpected
                        ) {
                            // don't block packet routing on errors
                            let _ = self.accept_sink.try_send(Err(e));
                        }
                    }
                },

                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),

                Poll::Pending => {
                    // Check whether any connections are still active
                    if self.shutdown_tx.is_some() && self.accept_sink.is_closed()
                    {
                        self.shutdown_tx = None;
                    }

                    if self.shutdown_rx.poll_recv(cx).is_ready() {
                        return Poll::Ready(Ok(()));
                    }

                    // Process any incoming connection map signals and handle them
                    self.handle_conn_map_commands();

                    return Poll::Pending;
                },
            }
        }
    }
}

/// Categorizes errors that are returned when handling packets which are not
/// associated with an established connection. The purpose is to suppress
/// logging of 'expected' errors (e.g. junk data sent to the UDP socket) to
/// prevent DoS.
fn initial_packet_error_type(
    e: &io::Error,
) -> labels::QuicInvalidInitialPacketError {
    Some(e)
        .filter(|e| e.kind() == io::ErrorKind::Other)
        .and_then(io::Error::get_ref)
        .and_then(|e| e.downcast_ref())
        .map_or(
            labels::QuicInvalidInitialPacketError::Unexpected,
            Clone::clone,
        )
}

/// An [`InitialPacketHandler`] handles unknown quic initials and processes
/// them; generally accepting new connections (acting as a server), or
/// establishing a connection to a server (acting as a client). An
/// [`InboundPacketRouter`] holds an instance of this trait and routes
/// [`Incoming`] packets to it when it receives initials.
///
/// The handler produces [`quiche::Connection`]s which are then turned into
/// [`QuicConnection`](super::QuicConnection), IoWorker pair.
pub trait InitialPacketHandler {
    fn update(&mut self, _ctx: &mut Context<'_>) -> io::Result<()> {
        Ok(())
    }

    fn handle_initials(
        &mut self, incoming: Incoming, hdr: Header<'static>,
        quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>>;
}

/// A [`NewConnection`] describes a new [`quiche::Connection`] that can be
/// driven by an io worker.
pub struct NewConnection {
    conn: QuicheConnection,
    pending_cid: Option<ConnectionId<'static>>,
    initial_pkt: Option<Incoming>,
    /// When the handshake started. Should be called before [`quiche::accept`]
    /// or [`quiche::connect`].
    handshake_start_time: Instant,
}

// TODO: the router module is private so we can't move these to /tests
// TODO: Rewrite tests to be Windows compatible
#[cfg(all(test, unix))]
mod tests {
    use super::acceptor::ConnectionAcceptor;
    use super::acceptor::ConnectionAcceptorConfig;
    use super::*;

    use crate::http3::settings::Http3Settings;
    use crate::metrics::DefaultMetrics;
    use crate::quic::connection::SimpleConnectionIdGenerator;
    use crate::settings::Config;
    use crate::settings::Hooks;
    use crate::settings::QuicSettings;
    use crate::settings::TlsCertificatePaths;
    use crate::socket::SocketCapabilities;
    use crate::ConnectionParams;
    use crate::ServerH3Driver;

    use datagram_socket::MAX_DATAGRAM_SIZE;
    use h3i::actions::h3::Action;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time;

    #[cfg(not(feature = "__rustls"))]
    const TEST_CERT_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.crt"
    );
    #[cfg(feature = "__rustls")]
    const TEST_CERT_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert_rustls.crt"
    );
    const TEST_KEY_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.key"
    );

    fn test_connect(host_port: String) {
        let h3i_config = h3i::config::Config::new()
            .with_host_port("test.com".to_string())
            .with_idle_timeout(2000)
            .with_connect_to(host_port)
            .verify_peer(false)
            .build()
            .unwrap();

        let conn_close = h3i::quiche::ConnectionError {
            is_app: true,
            error_code: h3i::quiche::WireErrorCode::NoError as _,
            reason: Vec::new(),
        };
        let actions = [Action::ConnectionClose { error: conn_close }];

        let _ = h3i::client::sync_client::connect(h3i_config, &actions, None);
    }

    #[tokio::test]
    async fn test_timeout() {
        // Configure a short idle timeout to speed up connection reclamation as
        // quiche doesn't support time mocking
        let quic_settings = QuicSettings {
            max_idle_timeout: Some(Duration::from_millis(1)),
            max_recv_udp_payload_size: MAX_DATAGRAM_SIZE,
            max_send_udp_payload_size: MAX_DATAGRAM_SIZE,
            ..Default::default()
        };

        let tls_cert_settings = TlsCertificatePaths {
            cert: &TEST_CERT_FILE,
            private_key: &TEST_KEY_FILE,
            kind: crate::settings::CertificateKind::X509,
        };

        let params = ConnectionParams::new_server(
            quic_settings,
            tls_cert_settings,
            Hooks::default(),
        );
        let config = Config::new(&params, SocketCapabilities::default()).unwrap();

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let host_port = local_addr.to_string();
        let socket_tx = Arc::new(socket);
        let socket_rx = Arc::clone(&socket_tx);

        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                disable_client_ip_validation: config.disable_client_ip_validation,
                qlog_dir: config.qlog_dir.clone(),
                keylog_file: config
                    .keylog_file
                    .as_ref()
                    .and_then(|f| f.try_clone().ok()),
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            Arc::clone(&socket_tx),
            0,
            Default::default(),
            Box::new(SimpleConnectionIdGenerator),
            DefaultMetrics,
        );

        let (socket_driver, mut incoming) = InboundPacketRouter::new(
            config,
            socket_tx,
            socket_rx,
            local_addr,
            acceptor,
            DefaultMetrics,
        );
        tokio::spawn(socket_driver);

        // Start a request and drop it after connection establishment
        std::thread::spawn(move || test_connect(host_port));

        // Wait for a new connection
        time::pause();

        let (h3_driver, _) = ServerH3Driver::new(Http3Settings::default());
        let conn = incoming.recv().await.unwrap().unwrap();
        let drop_check = conn.incoming_ev_sender.clone();
        let _conn = conn.start(h3_driver);

        // Poll the incoming until the connection is dropped
        time::advance(Duration::new(30, 0)).await;
        time::resume();

        // NOTE: this is a smoke test - in case of issues `notified()` future will
        // never resolve hanging the test.
        drop_check.closed().await;
    }
}
