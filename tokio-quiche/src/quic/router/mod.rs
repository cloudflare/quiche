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
use crate::metrics::labels;
use crate::metrics::quic_expensive_metrics_ip_reduce;
use crate::metrics::Metrics;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::settings::Config;
use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;
use foundations::telemetry::log;
use hashlink::LinkedHashMap;
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
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use task_killswitch::spawn_with_killswitch;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use foundations::telemetry::metrics::Counter;
#[cfg(target_os = "linux")]
use foundations::telemetry::metrics::TimeHistogram;
#[cfg(target_os = "linux")]
use libc::sockaddr_in;
#[cfg(target_os = "linux")]
use libc::sockaddr_in6;

type ConnStream<Tx, M> = mpsc::Receiver<io::Result<InitialQuicConnection<Tx, M>>>;

/// How many incoming packets (GRO batches) to process before checking the
/// `ConnectionMapCommand` queue again. 30 means "check the command queue once
/// every 30 packets".
const PACKET_RX_YIELD_AFTER: usize = 30;
/// `ConnectionMapCommand` processing batch size to amortize receive operations.
const CONN_MAP_CMD_BATCH_SIZE: usize = 128;

const STATELESS_RESET_QUEUE_CAPACITY: usize = 64;
const STATELESS_RESET_EXPIRATION: Duration = Duration::from_millis(100);

struct StatelessReset {
    payload: Vec<u8>,
    to: SocketAddr,
    #[cfg(target_os = "linux")]
    from: Option<SocketAddr>,
}

/// Server-side stateless reset state. Present only when the router is a
/// server-side connection and a reset key is configured. Clients neither send
/// resets nor advertise key-derived tokens on SCIDs. Note that this isn't an
/// RFC requirement, but a design choice to reduce the attack surface.
///
/// We have a rate limit that limits the number of resets per 2-tuple to 1 per 100ms.
struct StatelessResetCtx {
    key: quiche::StatelessResetKey,
    tx: mpsc::Sender<StatelessReset>,
    /// Peers with a reset recently queued, ordered by reservation time for
    /// opportunistic expiration and capped at the reset queue capacity.
    recent_peers: LinkedHashMap<SocketAddr, Instant>,
}

impl StatelessResetCtx {
    fn try_reserve(&mut self, peer: SocketAddr) -> bool {
        try_reserve_stateless_reset(
            &mut self.recent_peers,
            peer,
            Instant::now(),
            STATELESS_RESET_QUEUE_CAPACITY,
            STATELESS_RESET_EXPIRATION,
        )
    }

    fn cancel_reservation(&mut self, peer: SocketAddr) {
        self.recent_peers.remove(&peer);
    }
}

fn try_reserve_stateless_reset(
    recent_peers: &mut LinkedHashMap<SocketAddr, Instant>, peer: SocketAddr,
    now: Instant, max: usize, expiration: Duration,
) -> bool {
    while recent_peers.front().is_some_and(|(_, sent_at)| {
        now.saturating_duration_since(*sent_at) >= expiration
    }) {
        recent_peers.pop_front();
    }

    if recent_peers.contains_key(&peer) || recent_peers.len() >= max {
        return false;
    }

    recent_peers.insert(peer, now);
    true
}

#[allow(unused_variables)]
fn start_stateless_reset_writer<Tx, M>(
    socket: Arc<Tx>, metrics: M,
) -> mpsc::Sender<StatelessReset>
where
    Tx: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    let (tx, mut rx) =
        mpsc::channel::<StatelessReset>(STATELESS_RESET_QUEUE_CAPACITY);

    spawn_with_killswitch(async move {
        #[cfg(target_os = "linux")]
        let would_block_metric =
            metrics.write_errors(labels::QuicWriteError::WouldBlock);
        #[cfg(target_os = "linux")]
        let send_to_wouldblock_duration_s =
            metrics.send_to_wouldblock_duration_s();
        while let Some(reset) = rx.recv().await {
            let sent = send_stateless_reset(
                &socket,
                &reset,
                #[cfg(target_os = "linux")]
                &would_block_metric,
                #[cfg(target_os = "linux")]
                &send_to_wouldblock_duration_s,
            )
            .await;
            if sent {
                crate::metrics::quic::stateless_reset_sent_count().inc();
            } else {
                crate::metrics::quic::stateless_reset_dropped_count().inc();
            }
        }
    });

    tx
}

async fn send_stateless_reset<Tx>(
    socket: &Arc<Tx>, reset: &StatelessReset,
    #[cfg(target_os = "linux")]
    would_block_metric: &foundations::telemetry::metrics::Counter,
    #[cfg(target_os = "linux")] send_to_wouldblock_duration_s: &foundations::telemetry::metrics::TimeHistogram,
) -> bool
where
    Tx: DatagramSocketSend + Send + 'static,
{
    let result = if let Some(_udp) = socket.as_udp_socket() {
        #[cfg(target_os = "linux")]
        {
            crate::quic::io::gso::send_to(
                _udp,
                reset.to,
                reset.from,
                &reset.payload,
                reset.payload.len(),
                None,
                would_block_metric.clone(),
                send_to_wouldblock_duration_s.clone(),
            )
            .await
        }

        #[cfg(not(target_os = "linux"))]
        socket.send_to(&reset.payload, reset.to).await
    } else {
        socket.send_to(&reset.payload, reset.to).await
    };

    if let Err(error) = result {
        log::debug!("Failed to send stateless reset"; "error" => ?error);
        false
    } else {
        true
    }
}

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
    buf: Vec<u8>,
    // The packet's source, e.g., the peer's address
    src_addr: SocketAddr,
    // The packet's original destination. If the original destination is
    // different from the local listening address, this will be `None`.
    dst_addr_override: Option<SocketAddr>,
    rx_time: Option<SystemTime>,
    gro: Option<i32>,
    #[cfg(target_os = "linux")]
    so_mark_data: Option<[u8; 4]>,
}

/// A message to the listener notifiying a mapping for a connection should be
/// removed.
pub enum ConnectionMapCommand {
    MapCid {
        existing_cid: ConnectionId<'static>,
        new_cid: ConnectionId<'static>,
    },
    UnmapCid(ConnectionId<'static>),
}

/// An `InboundPacketRouter` maintains a map of quic connections and routes
/// [`Incoming`] packets from the [recv half][rh] of a datagram socket to those
/// connections or some quic initials handler. There is only 1
/// `InboundPacketRouter` per socket.
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
    /// Reusable buffer to receive a batch of `ConnectionMapCommand`s in
    /// `poll_conn_map_commands`. Always fully drained after use, so its length
    /// should be 0 outside of `poll_conn_map_commands`.
    conn_map_cmd_buf: Vec<ConnectionMapCommand>,
    accept_sink: mpsc::Sender<io::Result<InitialQuicConnection<Tx, M>>>,
    stateless_reset: Option<StatelessResetCtx>,
    metrics: M,
    #[cfg(target_os = "linux")]
    udp_drop_count: u32,

    #[cfg(target_os = "linux")]
    reusable_cmsg_space: Vec<u8>,

    #[cfg(target_os = "linux")]
    buf: Vec<u8>,

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
        let stateless_reset = match (
            incoming_packet_handler.is_server(),
            config.stateless_reset_key,
        ) {
            (true, Some(key)) => Some(StatelessResetCtx {
                key,
                tx: start_stateless_reset_writer(
                    Arc::clone(&socket_tx),
                    metrics.clone(),
                ),
                recent_peers: LinkedHashMap::with_capacity(
                    STATELESS_RESET_QUEUE_CAPACITY,
                ),
            }),
            _ => None,
        };

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
                conn_map_cmd_buf: Vec::with_capacity(4),
                accept_sink,
                stateless_reset,
                #[cfg(target_os = "linux")]
                udp_drop_count: 0,
                #[cfg(target_os = "linux")]
                // Specify CMSG space. Even if they're not all currently used, the cmsg buffer may
                // have been configured by a previous version of Tokio-Quiche with the socket
                // re-used on graceful restart. As such, this vector should _only grow_, and care
                // should be taken when adding new cmsgs.
                reusable_cmsg_space: nix::cmsg_space!(
                    u32, // GRO
                    nix::sys::time::TimeSpec, // timestamp
                    u16, // drop count
                    sockaddr_in, // IP_RECVORIGDSTADDR
                    sockaddr_in6, // IPV6_RECVORIGDSTADDR
                    u32 // SO_MARK
                ),

                config,

                #[cfg(target_os = "linux")]
                buf: Vec::new(),
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

            // We only support receiving stateless reset packets for client
            // connections and sending stateless reset packets for server
            // connections.
            if self.incoming_packet_handler.is_server() {
                if has_quic_fixed_bit(&incoming.buf) &&
                    self.stateless_reset.is_some()
                {
                    self.enqueue_stateless_reset(&incoming, &dcid);
                }
            } else {
                // A client socket has a single connection,
                // so an unmatched DCID can be forwarded to it for token
                // validation.
                if let Some(ev_sender) = self.conns.get_any() {
                    let _ = ev_sender.try_send(incoming);
                    return Ok(());
                }
            }

            // No connection found for this DCID, drop the this short header
            // packet.
            return Ok(());
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
            cid_generator,
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
            local_addr,
            pending_cid: pending_cid.clone(),
            stateless_reset_key: self.stateless_reset.as_ref().map(|s| s.key),
            with_gso: self.config.has_gso,
            pacing_offload: self.config.pacing_offload,
            with_pktinfo: if self.local_addr.is_ipv4() {
                self.config.has_ippktinfo
            } else {
                self.config.has_ipv6pktinfo
            },
            pool_send_buffer: self.config.pool_send_buffer,
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
            cid_generator,
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

        self.conns.insert(&scid, &conn);

        // Add the client-generated "pending" connection ID to the map as well.
        // This is only required for QUIC servers, because clients can send
        // Initial packets with arbitrary DCIDs to servers.
        if let Some(pending_cid) = pending_cid {
            self.conns.map_cid(&scid, &pending_cid);
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

    fn enqueue_stateless_reset(
        &mut self, incoming: &Incoming, dcid: &ConnectionId,
    ) {
        let Some(ctx) = &mut self.stateless_reset else {
            return;
        };
        let peer = incoming.peer_addr;
        if !ctx.try_reserve(peer) {
            crate::metrics::quic::stateless_reset_dropped_count().inc();
            return;
        }
        let datagram_len = incoming
            .gro
            .and_then(|len| usize::try_from(len).ok())
            .unwrap_or(incoming.buf.len())
            .min(incoming.buf.len());
        let Some(payload) = quiche::build_stateless_reset_packet(
            &ctx.key,
            dcid.as_ref(),
            datagram_len,
        ) else {
            ctx.cancel_reservation(peer);
            crate::metrics::quic::stateless_reset_dropped_count().inc();
            return;
        };
        #[cfg(target_os = "linux")]
        let from = if incoming.local_addr.is_ipv4() {
            self.config.has_ippktinfo
        } else {
            self.config.has_ipv6pktinfo
        }
        .then_some(incoming.local_addr);

        if ctx
            .tx
            .try_send(StatelessReset {
                payload,
                to: peer,
                #[cfg(target_os = "linux")]
                from,
            })
            .is_err()
        {
            ctx.cancel_reservation(peer);
            crate::metrics::quic::stateless_reset_dropped_count().inc();
        }
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
        let mut buf = Vec::with_capacity(datagram_socket::MAX_DATAGRAM_SIZE);
        // We use ReadBuf's ability to write to uninitialized memory to avoid
        // the cost of having to initialize the Vec.
        let mut read_buf = tokio::io::ReadBuf::uninit(buf.spare_capacity_mut());
        let addr = ready!(self.socket_rx.poll_recv_from(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        unsafe {
            // Safety: ReadBuf has guaranteed that `n` initialized bytes have
            // been written to the buffer, so we can set the vec's length
            // accordingly
            buf.set_len(n);
        }
        Poll::Ready(Ok(PollRecvData {
            buf,
            src_addr: addr,
            rx_time: None,
            gro: None,
            dst_addr_override: None,
            #[cfg(target_os = "linux")]
            so_mark_data: None,
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
            use libc::SOL_SOCKET;
            use libc::SO_MARK;
            use nix::errno::Errno;
            use nix::sys::socket::*;
            use std::net::SocketAddrV4;
            use std::net::SocketAddrV6;
            use std::os::fd::AsRawFd;
            use tokio::io::Interest;

            use crate::buf_factory::BufFactory;

            let Some(udp_socket) = self.socket_rx.as_udp_socket() else {
                // the given socket is not a UDP socket, fall back to the
                // simple poll_recv_from.
                return self.poll_recv_from(cx);
            };

            // Note, the resize will be a no-op after the first call since
            // we never truncate the `self.buf`
            self.buf.resize(BufFactory::MAX_BUF_SIZE, 0u8);
            loop {
                let iov_s = &mut [io::IoSliceMut::new(&mut self.buf)];
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
                        let filled_buf =
                            r.iovs().next().map(Vec::from).unwrap_or_default();
                        // The slices returend by `nix::socket::recvmsg`'s result
                        // add up to `r.bytes`. This assert is just to make sure
                        // the code handles the result correctly.
                        debug_assert_eq!(r.bytes, filled_buf.len());

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
                        let mut mark_bytes: Option<[u8; 4]> = None;

                        let Ok(cmsgs) = r.cmsgs() else {
                            // Best-effort if we can't read cmsgs.
                            return Poll::Ready(Ok(PollRecvData {
                                buf: filled_buf,
                                src_addr: peer_addr,
                                dst_addr_override,
                                rx_time,
                                gro,
                                so_mark_data: mark_bytes,
                            }));
                        };

                        for cmsg in cmsgs {
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
                                    // messages because we set IP_PKTINFO on the
                                    // socket.
                                },
                                ControlMessageOwned::Unknown(raw_cmsg) => {
                                    let UnknownCmsg {
                                        cmsg_header,
                                        data_bytes,
                                    } = raw_cmsg;

                                    if cmsg_header.cmsg_level == SOL_SOCKET &&
                                        cmsg_header.cmsg_type == SO_MARK
                                    {
                                        let Ok(arr) =
                                            <[u8; 4]>::try_from(data_bytes)
                                        else {
                                            // Should be unreachable as SO_MARK is
                                            // a u32: https://elixir.bootlin.com/linux/v6.17/source/include/net/sock.h#L487
                                            continue;
                                        };

                                        let _ = mark_bytes.insert(arr);
                                    }
                                },
                                _ => {
                                    // Unrecognized cmsg received, just ignore
                                    // it.
                                },
                            };
                        }

                        return Poll::Ready(Ok(PollRecvData {
                            buf: filled_buf,
                            src_addr: peer_addr,
                            dst_addr_override,
                            rx_time,
                            gro,
                            so_mark_data: mark_bytes,
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

    fn poll_process_packet(&mut self, cx: &mut Context) -> Poll<()> {
        let pkt_data = match ready!(self.poll_recv_and_rx_time(cx)) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Incoming packet router encountered recvmsg error"; "error" => e);
                return Poll::Ready(());
            },
        };

        let PollRecvData {
            buf,
            src_addr: peer_addr,
            dst_addr_override,
            rx_time,
            gro,
            #[cfg(target_os = "linux")]
            so_mark_data,
        } = pkt_data;

        let send_from = if let Some(dst_addr) = dst_addr_override {
            log::trace!("overriding local address"; "actual_local" => dst_addr, "configured_local" => self.local_addr);
            dst_addr
        } else {
            self.local_addr
        };

        let res = self.on_incoming(Incoming {
            peer_addr,
            local_addr: send_from,
            buf,
            rx_time,
            gro,
            #[cfg(target_os = "linux")]
            so_mark_data,
        });

        // Only error handling below - if `on_incoming` was successful,
        // we return here
        let Err(e) = res else {
            return Poll::Ready(());
        };

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

        if matches!(err_type, labels::QuicInvalidInitialPacketError::Unexpected) {
            // don't block packet routing on errors
            let _ = self.accept_sink.try_send(Err(e));
        }

        Poll::Ready(())
    }

    fn poll_conn_map_commands(&mut self, cx: &mut Context) -> Poll<()> {
        let cmd_rx = &mut self.conn_map_cmd_rx;
        let buf = &mut self.conn_map_cmd_buf;
        debug_assert!(buf.is_empty());

        while ready!(cmd_rx.poll_recv_many(cx, buf, CONN_MAP_CMD_BATCH_SIZE)) > 0
        {
            for cmd in buf.drain(..) {
                match cmd {
                    ConnectionMapCommand::MapCid {
                        existing_cid,
                        new_cid,
                    } => self.conns.map_cid(&existing_cid, &new_cid),
                    ConnectionMapCommand::UnmapCid(cid) =>
                        self.conns.unmap_cid(&cid),
                }
            }
        }

        Poll::Ready(())
    }
}

fn has_quic_fixed_bit(buf: &[u8]) -> bool {
    buf.first().is_some_and(|first| first & 0x40 != 0)
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
        loop {
            // First, check whether the app stopped accepting connections.
            if self.shutdown_tx.is_some() && self.accept_sink.is_closed() {
                self.shutdown_tx = None;
            }

            // Second, check if all connections have shut down and we can exit.
            if self.shutdown_tx.is_none() &&
                self.shutdown_rx.poll_recv(cx).is_ready()
            {
                return Poll::Ready(Ok(()));
            }

            // Third, run the generic `InitialPacketHandler` update.
            if let Err(error) = self.incoming_packet_handler.update(cx) {
                // An error here is so rare that it's easier to spawn a separate
                // task
                let sender = self.accept_sink.clone();
                spawn_with_killswitch(async move {
                    let _ = sender.send(Err(error)).await;
                });
            }

            // Fourth, update ConnectionMap before receiving packets. This ensures
            // our SCID destinations are up-to-date (as of this moment).
            // If this returns pending, we have processed all available commands
            // and are registered for a wakeup on the next command.
            let _ = self.poll_conn_map_commands(cx);

            // Finally, process up to `PACKET_RX_YIELD_AFTER` packet (batches) at
            // once. If no more packets are available, we wait to be woken again.
            for _ in 0..PACKET_RX_YIELD_AFTER {
                ready!(self.poll_process_packet(cx));
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

    fn is_server(&self) -> bool {
        false
    }

    fn handle_initials(
        &mut self, incoming: Incoming, hdr: Header<'static>,
        quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>>;
}

/// A [`NewConnection`] describes a new [`quiche::Connection`] that can be
/// driven by an io worker.
pub struct NewConnection {
    /// See [`QuicConnectionParams::quiche_conn`].
    conn: Box<QuicheConnection>,
    pending_cid: Option<ConnectionId<'static>>,
    initial_pkt: Option<Incoming>,
    cid_generator: Option<SharedConnectionIdGenerator>,
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
    use crate::quic::connect_with_config;
    use crate::quic::connection::ApplicationOverQuic;
    use crate::quic::connection::SimpleConnectionIdGenerator;
    use crate::settings::Config;
    use crate::settings::Hooks;
    use crate::settings::QuicSettings;
    use crate::settings::TlsCertificatePaths;
    use crate::socket::Socket;
    use crate::socket::SocketCapabilities;
    use crate::ConnectionIdGenerator as _;
    use crate::ConnectionParams;
    use crate::QuicResult;
    use crate::ServerH3Driver;

    use datagram_socket::MAX_DATAGRAM_SIZE;
    use futures::FutureExt as _;
    use h3i::actions::h3::Action;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;
    use tokio::time;

    const STATELESS_RESET_KEY: u128 = u128::from_be_bytes([0xba; 16]);

    struct ResetTestApplication {
        established_tx: Option<oneshot::Sender<()>>,
        draining_tx: Option<oneshot::Sender<()>>,
        send_rx: mpsc::Receiver<()>,
        send_pending: bool,
    }

    impl ApplicationOverQuic for ResetTestApplication {
        fn on_conn_established(
            &mut self, _qconn: &mut QuicheConnection,
            _handshake_info: &HandshakeInfo,
        ) -> QuicResult<()> {
            if let Some(tx) = self.established_tx.take() {
                let _ = tx.send(());
            }
            Ok(())
        }

        fn should_act(&self) -> bool {
            true
        }

        async fn wait_for_data(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            if self.send_rx.recv().await.is_some() {
                self.send_pending = true;
                return Ok(());
            }
            std::future::pending().await
        }

        fn process_reads(
            &mut self, qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            if qconn.is_draining() {
                if let Some(tx) = self.draining_tx.take() {
                    let _ = tx.send(());
                }
            }
            Ok(())
        }

        fn process_writes(
            &mut self, qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            if self.send_pending {
                qconn.send_ack_eliciting()?;
                self.send_pending = false;
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct PendingSocket {
        send_polled: AtomicBool,
    }

    impl DatagramSocketSend for PendingSocket {
        fn poll_send(
            &self, _cx: &mut Context, _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.send_polled.store(true, Ordering::Relaxed);
            Poll::Pending
        }

        fn poll_send_to(
            &self, cx: &mut Context, buf: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            self.poll_send(cx, buf)
        }
    }

    const TEST_CERT_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.crt"
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
        let actions = vec![Action::ConnectionClose { error: conn_close }];

        let _ = h3i::client::sync_client::connect(h3i_config, actions, None);
    }

    #[test]
    fn stateless_reset_reservations_are_rate_limited_and_bounded() {
        let mut recent_peers = LinkedHashMap::new();
        let a: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let a2: SocketAddr = "1.1.1.1:444".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:443".parse().unwrap();
        let start = Instant::now();
        let expiration = Duration::from_millis(100);

        assert!(try_reserve_stateless_reset(
            &mut recent_peers,
            a,
            start,
            2,
            expiration,
        ));
        assert!(try_reserve_stateless_reset(
            &mut recent_peers,
            a2,
            start + Duration::from_millis(50),
            2,
            expiration,
        ));
        assert!(
            !try_reserve_stateless_reset(
                &mut recent_peers,
                a,
                start + Duration::from_millis(99),
                2,
                expiration,
            ),
            "same peer is limited until its reservation expires"
        );
        assert!(
            !try_reserve_stateless_reset(
                &mut recent_peers,
                b,
                start + Duration::from_millis(99),
                2,
                expiration,
            ),
            "capacity blocks a third peer"
        );
        assert!(try_reserve_stateless_reset(
            &mut recent_peers,
            a,
            start + expiration,
            2,
            expiration,
        ));
        assert!(try_reserve_stateless_reset(
            &mut recent_peers,
            b,
            start + Duration::from_millis(150),
            2,
            expiration,
        ));
    }

    #[tokio::test]
    async fn stateless_reset_writer_queue_is_bounded() {
        // This socket never completes a send, keeping the writer occupied with
        // the first reset while subsequent resets accumulate in the queue.
        let socket = Arc::new(PendingSocket::default());
        let stateless_reset_tx =
            start_stateless_reset_writer(Arc::clone(&socket), DefaultMetrics);
        let reset = || StatelessReset {
            payload: vec![0; quiche::MIN_STATELESS_RESET_LEN],
            to: "127.0.0.1:443".parse().unwrap(),
            #[cfg(target_os = "linux")]
            from: None,
        };

        stateless_reset_tx.try_send(reset()).unwrap();

        // Wait until the writer has removed the first reset from the queue and
        // is blocked trying to send it.
        time::timeout(Duration::from_secs(1), async {
            while !socket.send_polled.load(Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // Fill every queue slot.
        for _ in 0..STATELESS_RESET_QUEUE_CAPACITY {
            stateless_reset_tx.try_send(reset()).unwrap();
        }

        // The next reset should be rejected.
        assert!(matches!(
            stateless_reset_tx.try_send(reset()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }

    #[test]
    fn stateless_reset_packet_layout() {
        let dcid = ConnectionId::from_ref(&[0x42; MAX_CONN_ID_LEN]);
        let key = quiche::StatelessResetKey::from_u128(STATELESS_RESET_KEY);

        assert!(
            quiche::build_stateless_reset_packet(&key, dcid.as_ref(), 21)
                .is_none()
        );

        let reset = quiche::build_stateless_reset_packet(&key, dcid.as_ref(), 22)
            .unwrap();
        assert_eq!(reset.len(), 21);
        assert_eq!(reset[0] >> 6, 0b01);
        assert_eq!(
            &reset[reset.len() - quiche::STATELESS_RESET_TOKEN_LEN..],
            key.derive_token(dcid.as_ref()).unwrap().as_bytes(),
        );

        let reset =
            quiche::build_stateless_reset_packet(&key, dcid.as_ref(), 1200)
                .unwrap();
        assert!((quiche::RECOMMENDED_STATELESS_RESET_LEN..=
            quiche::MAX_STATELESS_RESET_LEN)
            .contains(&reset.len()));
        assert!(reset.len() < 1200);
        assert_eq!(reset[0] >> 6, 0b01);
        assert_eq!(
            &reset[reset.len() - quiche::STATELESS_RESET_TOKEN_LEN..],
            key.derive_token(dcid.as_ref()).unwrap().as_bytes(),
        );
    }

    #[tokio::test]
    async fn server_stateless_reset_drains_client_connection() {
        let quic_settings = QuicSettings {
            stateless_reset_key: Some(STATELESS_RESET_KEY),
            max_recv_udp_payload_size: MAX_DATAGRAM_SIZE,
            max_send_udp_payload_size: MAX_DATAGRAM_SIZE,
            ..Default::default()
        };
        let tls_cert_settings = TlsCertificatePaths {
            cert: TEST_CERT_FILE,
            private_key: TEST_KEY_FILE,
            kind: crate::settings::CertificateKind::X509,
        };
        let server_params = ConnectionParams::new_server(
            quic_settings,
            tls_cert_settings,
            Hooks::default(),
        );
        let config =
            Config::new(&server_params, SocketCapabilities::default()).unwrap();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server_socket_tx = Arc::new(server_socket);
        let server_socket_rx = Arc::clone(&server_socket_tx);
        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                disable_client_ip_validation: config.disable_client_ip_validation,
                qlog_dir: config.qlog_dir.clone(),
                qlog_compression: config.qlog_compression,
                keylog_file: None,
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            Arc::clone(&server_socket_tx),
            Default::default(),
            Arc::new(SimpleConnectionIdGenerator),
            DefaultMetrics,
        );
        let (server_router, mut incoming) = InboundPacketRouter::new(
            config,
            server_socket_tx,
            server_socket_rx,
            server_addr,
            acceptor,
            DefaultMetrics,
        );
        // Drive the router manually so the test can remove its CID mapping.
        tokio::pin!(server_router);

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket.connect(server_addr).await.unwrap();
        let client_socket =
            Socket::<Arc<UdpSocket>, Arc<UdpSocket>>::from_udp(client_socket)
                .unwrap();
        let client_params = ConnectionParams::new_client(
            QuicSettings::default(),
            None,
            Hooks::default(),
        );
        // The command channel triggers one client packet after server state loss.
        // The oneshot fires only when the client connection sees
        // draining.
        let (client_send_tx, client_send_rx) = mpsc::channel(1);
        let (draining_tx, draining_rx) = oneshot::channel();
        let client_app = ResetTestApplication {
            established_tx: None,
            draining_tx: Some(draining_tx),
            send_rx: client_send_rx,
            send_pending: false,
        };
        let client = tokio::spawn(async move {
            connect_with_config(
                client_socket,
                Some("test.com"),
                &client_params,
                client_app,
            )
            .await
        });

        // Poll the server router until it creates the server connection from
        // the client's Initial packet.
        let initial = time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut server_router =>
                    panic!("server router exited early: {result:?}"),
                initial = incoming.recv() => initial.unwrap().unwrap(),
            }
        })
        .await
        .unwrap();
        let (server_established_tx, server_established_rx) = oneshot::channel();
        let (server_send_tx, server_send_rx) = mpsc::channel(1);
        let server_app = ResetTestApplication {
            established_tx: Some(server_established_tx),
            draining_tx: None,
            send_rx: server_send_rx,
            send_pending: false,
        };
        let server_connection = initial.start(server_app);
        let server_scid = server_connection.scid().clone();

        // Continue polling the router while each worker completes its side of
        // the handshake.
        let mut server_established_rx = server_established_rx;
        time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut server_router =>
                    panic!("server router exited early: {result:?}"),
                established = &mut server_established_rx => established.unwrap(),
            }
        })
        .await
        .unwrap();

        let mut client = client;
        let client_connection = time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut server_router =>
                    panic!("server router exited early: {result:?}"),
                client = &mut client => client.unwrap().unwrap(),
            }
        })
        .await
        .unwrap();

        // Simulate silent server state loss: the client still uses this
        // server-issued CID, but the listener can no longer route it.
        server_router
            .as_mut()
            .get_mut()
            .conns
            .unmap_cid(&server_scid);
        client_send_tx.send(()).await.unwrap();

        // The resulting server reset must be routed to the client
        // connection, validated by quiche, and transition it to draining.
        let mut draining_rx = draining_rx;
        time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut server_router =>
                    panic!("server router exited early: {result:?}"),
                draining = &mut draining_rx => draining.unwrap(),
            }
        })
        .await
        .unwrap();

        drop(client_connection);
        drop(server_send_tx);
    }

    #[tokio::test]
    async fn unknown_short_header_triggers_stateless_reset() {
        let quic_settings = QuicSettings {
            stateless_reset_key: Some(STATELESS_RESET_KEY),
            max_recv_udp_payload_size: MAX_DATAGRAM_SIZE,
            max_send_udp_payload_size: MAX_DATAGRAM_SIZE,
            ..Default::default()
        };
        let tls_cert_settings = TlsCertificatePaths {
            cert: TEST_CERT_FILE,
            private_key: TEST_KEY_FILE,
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
        let socket_tx = Arc::new(socket);
        let socket_rx = Arc::clone(&socket_tx);
        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                disable_client_ip_validation: config.disable_client_ip_validation,
                qlog_dir: config.qlog_dir.clone(),
                qlog_compression: config.qlog_compression,
                keylog_file: None,
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            Arc::clone(&socket_tx),
            Default::default(),
            Arc::new(SimpleConnectionIdGenerator),
            DefaultMetrics,
        );
        let (router, _incoming) = InboundPacketRouter::new(
            config,
            socket_tx,
            socket_rx,
            local_addr,
            acceptor,
            DefaultMetrics,
        );
        let router = tokio::spawn(router);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dcid = [0x42; MAX_CONN_ID_LEN];
        let mut packet = [0; 1200];
        packet[0] = 0x40;
        packet[1..1 + MAX_CONN_ID_LEN].copy_from_slice(&dcid);

        client.send_to(&packet, local_addr).await.unwrap();

        let mut reset = [0; quiche::MAX_STATELESS_RESET_LEN];
        let (len, peer) =
            time::timeout(Duration::from_secs(1), client.recv_from(&mut reset))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(peer, local_addr);
        assert!((quiche::RECOMMENDED_STATELESS_RESET_LEN..=
            quiche::MAX_STATELESS_RESET_LEN)
            .contains(&len));
        assert_eq!(reset[0] >> 6, 0b01);
        assert_eq!(
            &reset[len - quiche::STATELESS_RESET_TOKEN_LEN..len],
            quiche::StatelessResetKey::from_u128(STATELESS_RESET_KEY)
                .derive_token(&dcid)
                .unwrap()
                .as_bytes(),
        );

        router.abort();
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
            cert: TEST_CERT_FILE,
            private_key: TEST_KEY_FILE,
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
                qlog_compression: config.qlog_compression,
                keylog_file: config
                    .keylog_file
                    .as_ref()
                    .and_then(|f| f.try_clone().ok()),
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            Arc::clone(&socket_tx),
            Default::default(),
            Arc::new(SimpleConnectionIdGenerator),
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

    struct NoopDatagramSender;
    impl DatagramSocketSend for NoopDatagramSender {
        fn poll_send(
            &self, _cx: &mut Context, buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_send_to(
            &self, _cx: &mut Context, buf: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
    }

    struct AlwaysReadyReceiver;
    impl DatagramSocketRecv for AlwaysReadyReceiver {
        fn poll_recv(
            &mut self, _cx: &mut Context, buf: &mut tokio::io::ReadBuf,
        ) -> Poll<io::Result<()>> {
            // Short header packet:
            // 1 byte descriptor + 20 byte DCID + 1 byte packet number + payload
            const DUMMY_QUIC_PACKET: &[u8] =
                b"\x40THIS_20_BYTE_CONN_ID\x06payload_payload_payload";
            buf.put_slice(DUMMY_QUIC_PACKET);
            Poll::Ready(Ok(()))
        }
    }

    struct NoopInitialHandler;
    impl InitialPacketHandler for NoopInitialHandler {
        fn handle_initials(
            &mut self, _incoming: Incoming, _hdr: Header<'static>,
            _quiche_config: &mut quiche::Config,
        ) -> io::Result<Option<NewConnection>> {
            Ok(None)
        }
    }

    #[test]
    fn test_poll_packet_always_ready() {
        let tls_cert_settings = TlsCertificatePaths {
            cert: TEST_CERT_FILE,
            private_key: TEST_KEY_FILE,
            kind: crate::settings::CertificateKind::X509,
        };
        let params = ConnectionParams::new_server(
            QuicSettings::default(),
            tls_cert_settings,
            Hooks::default(),
        );

        let config = Config::new(&params, SocketCapabilities::default()).unwrap();
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);

        let (mut ipr, accept_stream) = InboundPacketRouter::new(
            config,
            Arc::new(NoopDatagramSender),
            AlwaysReadyReceiver,
            local_addr,
            NoopInitialHandler,
            DefaultMetrics,
        );
        let conn_map_cmd_tx = ipr.conn_map_cmd_tx.clone();

        // Keep polling the IPR in a busy loop until it resolves
        let (ipr_notifier, ipr_done) = std::sync::mpsc::sync_channel::<()>(0);
        let ipr = std::thread::spawn(move || {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            while ipr.poll_unpin(&mut cx).is_pending() {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(ipr_notifier);
            ipr
        });

        // Fill the `conn_map_cmd` channel with some messages to process
        for _ in 0..20 {
            let random_cid = SimpleConnectionIdGenerator.new_connection_id();
            conn_map_cmd_tx
                .send(ConnectionMapCommand::UnmapCid(random_cid))
                .unwrap();
        }
        // Give the IPR some time to process the ConnectionMapCommands
        std::thread::sleep(Duration::from_secs(1));

        // Shut the IPR down by dropping the accept_stream receiver. We wait for
        // up to 10 seconds for IPR::poll to resolve. If it doesn't, it's not
        // checking the shutdown condition regularly.
        drop(accept_stream);
        let ipr_done_res = ipr_done.recv_timeout(Duration::from_secs(10));
        assert_eq!(
            ipr_done_res,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        );

        // Check that the ConnectionMapCommands we added above were actually
        // processed
        let ipr = ipr.join().unwrap();
        assert!(ipr.conn_map_cmd_rx.is_empty());
    }
}
