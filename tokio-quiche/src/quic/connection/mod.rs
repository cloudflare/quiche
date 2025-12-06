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

mod error;
mod id;
mod map;

pub use self::error::HandshakeError;
pub use self::id::ConnectionIdGenerator;
pub use self::id::SimpleConnectionIdGenerator;
pub(crate) use self::map::ConnectionMap;

use boring::ssl::SslRef;
use datagram_socket::AsSocketStats;
use datagram_socket::DatagramSocketSend;
use datagram_socket::MaybeConnectedSocket;
use datagram_socket::QuicAuditStats;
use datagram_socket::ShutdownConnection;
use datagram_socket::SocketStats;
use foundations::telemetry::log;
use futures::future::BoxFuture;
use futures::Future;
use quiche::ConnectionId;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use self::error::make_handshake_result;
use super::io::connection_stage::Close;
use super::io::connection_stage::ConnectionStageContext;
use super::io::connection_stage::Handshake;
use super::io::connection_stage::RunningApplication;
use super::io::worker::Closing;
use super::io::worker::IoWorkerParams;
use super::io::worker::Running;
use super::io::worker::RunningOrClosing;
use super::io::worker::WriteState;
use super::QuicheConnection;
use crate::buf_factory::PooledBuf;
use crate::metrics::Metrics;
use crate::quic::io::worker::IoWorker;
use crate::quic::io::worker::WriterConfig;
use crate::quic::io::worker::INCOMING_QUEUE_SIZE;
use crate::quic::router::ConnectionMapCommand;
use crate::QuicResult;

/// Wrapper for connection statistics recorded by [quiche].
#[derive(Debug)]
pub struct QuicConnectionStats {
    /// Aggregate connection statistics across all paths.
    pub stats: quiche::Stats,
    /// Specific statistics about the connection's active path.
    pub path_stats: Option<quiche::PathStats>,
}
pub(crate) type QuicConnectionStatsShared = Arc<Mutex<QuicConnectionStats>>;

impl QuicConnectionStats {
    pub(crate) fn from_conn(qconn: &QuicheConnection) -> Self {
        Self {
            stats: qconn.stats(),
            path_stats: qconn.path_stats().next(),
        }
    }

    fn startup_exit_to_socket_stats(
        value: quiche::StartupExit,
    ) -> datagram_socket::StartupExit {
        let reason = match value.reason {
            quiche::StartupExitReason::Loss =>
                datagram_socket::StartupExitReason::Loss,
            quiche::StartupExitReason::BandwidthPlateau =>
                datagram_socket::StartupExitReason::BandwidthPlateau,
            quiche::StartupExitReason::PersistentQueue =>
                datagram_socket::StartupExitReason::PersistentQueue,
        };

        datagram_socket::StartupExit {
            cwnd: value.cwnd,
            bandwidth: value.bandwidth,
            reason,
        }
    }
}

impl AsSocketStats for QuicConnectionStats {
    fn as_socket_stats(&self) -> SocketStats {
        SocketStats {
            pmtu: self
                .path_stats
                .as_ref()
                .map(|p| p.pmtu as u16)
                .unwrap_or_default(),
            rtt_us: self
                .path_stats
                .as_ref()
                .map(|p| p.rtt.as_micros() as i64)
                .unwrap_or_default(),
            min_rtt_us: self
                .path_stats
                .as_ref()
                .and_then(|p| p.min_rtt.map(|x| x.as_micros() as i64))
                .unwrap_or_default(),
            max_rtt_us: self
                .path_stats
                .as_ref()
                .and_then(|p| p.max_rtt.map(|x| x.as_micros() as i64))
                .unwrap_or_default(),
            rtt_var_us: self
                .path_stats
                .as_ref()
                .map(|p| p.rttvar.as_micros() as i64)
                .unwrap_or_default(),
            cwnd: self
                .path_stats
                .as_ref()
                .map(|p| p.cwnd as u64)
                .unwrap_or_default(),
            total_pto_count: self
                .path_stats
                .as_ref()
                .map(|p| p.total_pto_count as u64)
                .unwrap_or_default(),
            packets_sent: self.stats.sent as u64,
            packets_recvd: self.stats.recv as u64,
            packets_lost: self.stats.lost as u64,
            packets_lost_spurious: self.stats.spurious_lost as u64,
            packets_retrans: self.stats.retrans as u64,
            bytes_sent: self.stats.sent_bytes,
            bytes_recvd: self.stats.recv_bytes,
            bytes_lost: self.stats.lost_bytes,
            bytes_retrans: self.stats.stream_retrans_bytes,
            bytes_unsent: 0, /* not implemented yet, kept for compatibility
                              * with TCP */
            delivery_rate: self
                .path_stats
                .as_ref()
                .map(|p| p.delivery_rate)
                .unwrap_or_default(),
            max_bandwidth: self.path_stats.as_ref().and_then(|p| p.max_bandwidth),
            startup_exit: self
                .path_stats
                .as_ref()
                .and_then(|p| p.startup_exit)
                .map(QuicConnectionStats::startup_exit_to_socket_stats),
            data_blocked_sent_count: self.stats.data_blocked_sent_count,
            stream_data_blocked_sent_count: self
                .stats
                .stream_data_blocked_sent_count,
            data_blocked_recv_count: self.stats.data_blocked_recv_count,
            stream_data_blocked_recv_count: self
                .stats
                .stream_data_blocked_recv_count,
            bytes_in_flight_duration_us: self
                .stats
                .bytes_in_flight_duration
                .as_micros() as u64,
            reset_stream_count_local: self.stats.reset_stream_count_local,
            stopped_stream_count_local: self.stats.stopped_stream_count_local,
            reset_stream_count_remote: self.stats.reset_stream_count_remote,
            stopped_stream_count_remote: self.stats.stopped_stream_count_remote,
        }
    }
}

/// A received network packet with additional metadata.
#[derive(Debug)]
pub struct Incoming {
    /// The address that sent the inbound packet.
    pub peer_addr: SocketAddr,
    /// The address on which we received the inbound packet.
    pub local_addr: SocketAddr,
    /// The receive timestamp of the packet.
    ///
    /// Used for the `perf-quic-listener-metrics` feature.
    pub rx_time: Option<SystemTime>,
    /// The packet's contents.
    pub buf: PooledBuf,
    /// If set, then `buf` is a GRO buffer containing multiple packets.
    /// Each individual packet has a size of `gso` (except for the last one).
    pub gro: Option<i32>,
    /// [SO_MARK] control message value received from the socket.
    ///
    /// This will always be `None` after the connection has been spawned as
    /// the message is `take()`d before spawning.
    ///
    /// [SO_MARK]: https://man7.org/linux/man-pages/man7/socket.7.html
    #[cfg(target_os = "linux")]
    pub so_mark_data: Option<[u8; 4]>,
}

/// A QUIC connection that has not performed a handshake yet.
///
/// This type is currently only used for server-side connections. It is created
/// and added to the listener's connection stream after an initial packet from
/// a client has been received and (optionally) the client's IP address has been
/// validated.
///
/// To turn the initial connection into a fully established one, a QUIC
/// handshake must be performed. Users have multiple options to facilitate this:
/// - `start` is a simple entrypoint which spawns a task to handle the entire
///   lifetime of the QUIC connection. The caller can then only communicate with
///   the connection via their [`ApplicationOverQuic`].
/// - `handshake` spawns a task for the handshake and awaits its completion.
///   Afterwards, it pauses the connection and allows the caller to resume it
///   later via an opaque struct. We spawn a separate task to allow the tokio
///   scheduler free choice in where to run the handshake.
/// - `handshake_fut` returns a future to drive the handshake for maximum
///   flexibility.
#[must_use = "call InitialQuicConnection::start to establish the connection"]
pub struct InitialQuicConnection<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    /// An internal ID, to uniquely identify the connection across multiple QUIC
    /// connection IDs.
    pub(crate) id: u64,
    params: QuicConnectionParams<Tx, M>,
    pub(crate) audit_log_stats: Arc<QuicAuditStats>,
    stats: QuicConnectionStatsShared,
    pub(crate) incoming_ev_sender: mpsc::Sender<Incoming>,
    incoming_ev_receiver: mpsc::Receiver<Incoming>,
}

impl<Tx, M> InitialQuicConnection<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    #[inline]
    pub(crate) fn new(params: QuicConnectionParams<Tx, M>) -> Self {
        let (incoming_ev_sender, incoming_ev_receiver) =
            mpsc::channel(INCOMING_QUEUE_SIZE);
        let audit_log_stats = Arc::new(QuicAuditStats::new(params.scid.to_vec()));

        let stats = Arc::new(Mutex::new(QuicConnectionStats::from_conn(
            &params.quiche_conn,
        )));

        Self {
            id: Self::generate_id(),
            params,
            audit_log_stats,
            stats,
            incoming_ev_sender,
            incoming_ev_receiver,
        }
    }

    /// The local address this connection listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.params.local_addr
    }

    /// The remote address for this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.params.peer_addr
    }

    /// [boring]'s SSL object for this connection.
    #[doc(hidden)]
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.params.quiche_conn.as_mut()
    }

    /// A handle to the [`QuicAuditStats`] for this connection.
    ///
    /// # Note
    /// These stats are updated during the lifetime of the connection.
    /// The getter exists to grab a handle early on, which can then
    /// be stowed away and read out after the connection has closed.
    #[inline]
    pub fn audit_log_stats(&self) -> Arc<QuicAuditStats> {
        Arc::clone(&self.audit_log_stats)
    }

    /// A handle to the [`QuicConnectionStats`] for this connection.
    ///
    /// # Note
    /// Initially, these stats represent the state when the [quiche::Connection]
    /// was created. They are updated when the connection is closed, so this
    /// getter exists primarily to grab a handle early on.
    #[inline]
    pub fn stats(&self) -> &QuicConnectionStatsShared {
        &self.stats
    }

    /// Creates a future to drive the connection's handshake.
    ///
    /// This is a lower-level alternative to the `handshake` function which
    /// gives the caller more control over execution of the future. See
    /// `handshake` for details on the return values.
    #[allow(clippy::type_complexity)]
    pub fn handshake_fut<A: ApplicationOverQuic>(
        self, app: A,
    ) -> (
        QuicConnection,
        BoxFuture<'static, io::Result<Running<Arc<Tx>, M, A>>>,
    ) {
        self.params.metrics.connections_in_memory().inc();

        let conn = QuicConnection {
            local_addr: self.params.local_addr,
            peer_addr: self.params.peer_addr,
            audit_log_stats: Arc::clone(&self.audit_log_stats),
            stats: Arc::clone(&self.stats),
            scid: self.params.scid,
        };
        let context = ConnectionStageContext {
            in_pkt: self.params.initial_pkt,
            incoming_pkt_receiver: self.incoming_ev_receiver,
            application: app,
            stats: Arc::clone(&self.stats),
        };
        let conn_stage = Handshake {
            handshake_info: self.params.handshake_info,
        };
        let params = IoWorkerParams {
            socket: MaybeConnectedSocket::new(self.params.socket),
            shutdown_tx: self.params.shutdown_tx,
            cfg: self.params.writer_cfg,
            audit_log_stats: self.audit_log_stats,
            write_state: WriteState::default(),
            conn_map_cmd_tx: self.params.conn_map_cmd_tx,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: self.params.init_rx_time,
            metrics: self.params.metrics.clone(),
        };

        let handshake_fut = async move {
            let qconn = self.params.quiche_conn;
            let handshake_done =
                IoWorker::new(params, conn_stage).run(qconn, context).await;

            match handshake_done {
                RunningOrClosing::Running(r) => Ok(r),
                RunningOrClosing::Closing(Closing {
                    params,
                    work_loop_result,
                    mut context,
                    mut qconn,
                }) => {
                    let hs_result = make_handshake_result(&work_loop_result);
                    IoWorker::new(params, Close { work_loop_result })
                        .close(&mut qconn, &mut context)
                        .await;
                    hs_result
                },
            }
        };

        (conn, Box::pin(handshake_fut))
    }

    /// Performs the QUIC handshake in a separate tokio task and awaits its
    /// completion.
    ///
    /// The returned [`QuicConnection`] holds metadata about the established
    /// connection. The connection itself is paused after `handshake`
    /// returns and must be resumed by passing the opaque `Running` value to
    /// [`InitialQuicConnection::resume`]. This two-step process
    /// allows callers to collect telemetry and run code before serving their
    /// [`ApplicationOverQuic`].
    pub async fn handshake<A: ApplicationOverQuic>(
        self, app: A,
    ) -> io::Result<(QuicConnection, Running<Arc<Tx>, M, A>)> {
        let task_metrics = self.params.metrics.clone();
        let (conn, handshake_fut) = Self::handshake_fut(self, app);

        let handshake_handle = crate::metrics::tokio_task::spawn(
            "quic_handshake_worker",
            task_metrics,
            handshake_fut,
        );

        // `AbortOnDropHandle` simulates task-killswitch behavior without needing
        // to give up ownership of the `JoinHandle`.
        let handshake_abort_handle = AbortOnDropHandle::new(handshake_handle);

        let worker = handshake_abort_handle.await??;

        Ok((conn, worker))
    }

    /// Resumes a QUIC connection which was paused after a successful handshake.
    pub fn resume<A: ApplicationOverQuic>(pre_running: Running<Arc<Tx>, M, A>) {
        let task_metrics = pre_running.params.metrics.clone();
        let fut = async move {
            let Running {
                params,
                context,
                qconn,
            } = pre_running;
            let running_worker = IoWorker::new(params, RunningApplication);

            let Closing {
                params,
                mut context,
                work_loop_result,
                mut qconn,
            } = running_worker.run(qconn, context).await;

            IoWorker::new(params, Close { work_loop_result })
                .close(&mut qconn, &mut context)
                .await;
        };

        crate::metrics::tokio_task::spawn_with_killswitch(
            "quic_io_worker",
            task_metrics,
            fut,
        );
    }

    /// Drives a QUIC connection from handshake to close in separate tokio
    /// tasks.
    ///
    /// It combines [`InitialQuicConnection::handshake`] and
    /// [`InitialQuicConnection::resume`] into a single call.
    pub fn start<A: ApplicationOverQuic>(self, app: A) -> QuicConnection {
        let task_metrics = self.params.metrics.clone();
        let (conn, handshake_fut) = Self::handshake_fut(self, app);

        let fut = async move {
            match handshake_fut.await {
                Ok(running) => Self::resume(running),
                Err(e) => {
                    log::error!("QUIC handshake failed in IQC::start"; "error" => e)
                },
            }
        };

        crate::metrics::tokio_task::spawn_with_killswitch(
            "quic_handshake_worker",
            task_metrics,
            fut,
        );

        conn
    }

    /// Drives a QUIC connection from handshake to close in separate tokio
    /// tasks but returns a result by awaiting the [`InitialQuicConnection::handshake`] call.
    ///
    /// It combines [`InitialQuicConnection::handshake`] and
    /// [`InitialQuicConnection::resume`] into a single call.
    pub async fn start_with_result<A: ApplicationOverQuic>(self, app: A) -> io::Result<QuicConnection> {
        let task_metrics = self.params.metrics.clone();
        let result = self.handshake(app).await;

        match result {
            Ok((q_conn, handshake)) => {
                crate::metrics::tokio_task::spawn_with_killswitch(
                    "quic_handshake_worker",
                    task_metrics,
                    async move {
                        Self::resume(handshake)
                    }
                );

                Ok(q_conn)
            },
            Err(e) => {
                log::error!("QUIC handshake failed in IQC::start"; "error" => e);
                Err(e) // Pass it upward
            }
        }
    }

    fn generate_id() -> u64 {
        let mut buf = [0; 8];

        boring::rand::rand_bytes(&mut buf).unwrap();

        u64::from_ne_bytes(buf)
    }
}

pub(crate) struct QuicConnectionParams<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    pub writer_cfg: WriterConfig,
    pub initial_pkt: Option<Incoming>,
    pub shutdown_tx: mpsc::Sender<()>,
    pub conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>, /* channel that signals connection map changes */
    pub scid: ConnectionId<'static>,
    pub metrics: M,
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub init_rx_time: Option<SystemTime>,
    pub handshake_info: HandshakeInfo,
    pub quiche_conn: QuicheConnection,
    pub socket: Arc<Tx>,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

/// Metadata about an established QUIC connection.
///
/// While this struct allows access to some facets of a QUIC connection, it
/// notably does not represent the [quiche::Connection] itself. The crate
/// handles most interactions with [quiche] internally in a worker task. Users
/// can only access the connection directly via their [`ApplicationOverQuic`]
/// implementation.
///
/// See the [module-level docs](crate::quic) for an overview of how a QUIC
/// connection is handled internally.
pub struct QuicConnection {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    audit_log_stats: Arc<QuicAuditStats>,
    stats: QuicConnectionStatsShared,
    scid: ConnectionId<'static>,
}

impl QuicConnection {
    /// The local address this connection listens on.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The remote address for this connection.
    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// A handle to the [`QuicAuditStats`] for this connection.
    ///
    /// # Note
    /// These stats are updated during the lifetime of the connection.
    /// The getter exists to grab a handle early on, which can then
    /// be stowed away and read out after the connection has closed.
    #[inline]
    pub fn audit_log_stats(&self) -> &Arc<QuicAuditStats> {
        &self.audit_log_stats
    }

    /// A handle to the [`QuicConnectionStats`] for this connection.
    ///
    /// # Note
    /// Initially, these stats represent the state when the [quiche::Connection]
    /// was created. They are updated when the connection is closed, so this
    /// getter exists primarily to grab a handle early on.
    #[inline]
    pub fn stats(&self) -> &QuicConnectionStatsShared {
        &self.stats
    }

    /// The QUIC source connection ID used by this connection.
    #[inline]
    pub fn scid(&self) -> &ConnectionId<'static> {
        &self.scid
    }
}

impl AsSocketStats for QuicConnection {
    #[inline]
    fn as_socket_stats(&self) -> SocketStats {
        // It is important to note that those stats are only updated when
        // the connection stops, which is fine, since this is only used to
        // log after the connection is finished.
        self.stats.lock().unwrap().as_socket_stats()
    }

    #[inline]
    fn as_quic_stats(&self) -> Option<&Arc<QuicAuditStats>> {
        Some(&self.audit_log_stats)
    }
}

impl<Tx, M> AsSocketStats for InitialQuicConnection<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    #[inline]
    fn as_socket_stats(&self) -> SocketStats {
        // It is important to note that those stats are only updated when
        // the connection stops, which is fine, since this is only used to
        // log after the connection is finished.
        self.stats.lock().unwrap().as_socket_stats()
    }

    #[inline]
    fn as_quic_stats(&self) -> Option<&Arc<QuicAuditStats>> {
        Some(&self.audit_log_stats)
    }
}

impl<Tx, M> ShutdownConnection for InitialQuicConnection<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    #[inline]
    fn poll_shutdown(
        &mut self, _cx: &mut std::task::Context,
    ) -> std::task::Poll<io::Result<()>> {
        // TODO: Does nothing at the moment. We always call Self::start
        // anyway so it's not really important at this moment.
        Poll::Ready(Ok(()))
    }
}

impl ShutdownConnection for QuicConnection {
    #[inline]
    fn poll_shutdown(
        &mut self, _cx: &mut std::task::Context,
    ) -> std::task::Poll<io::Result<()>> {
        // TODO: does nothing at the moment
        Poll::Ready(Ok(()))
    }
}

/// Details about a connection's QUIC handshake.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    /// The time at which the connection was created.
    start_time: Instant,
    /// The timeout before which the handshake must complete.
    timeout: Option<Duration>,
    /// The real duration that the handshake took to complete.
    time_handshake: Option<Duration>,
}

impl HandshakeInfo {
    pub(crate) fn new(start_time: Instant, timeout: Option<Duration>) -> Self {
        Self {
            start_time,
            timeout,
            time_handshake: None,
        }
    }

    /// The time at which the connection was created.
    #[inline]
    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    /// How long the handshake took to complete.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.time_handshake.unwrap_or_default()
    }

    pub(crate) fn set_elapsed(&mut self) {
        let elapsed = self.start_time.elapsed();
        self.time_handshake = Some(elapsed)
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.timeout.map(|timeout| self.start_time + timeout)
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.timeout
            .is_some_and(|timeout| self.start_time.elapsed() >= timeout)
    }
}

/// A trait to implement an application served over QUIC.
///
/// The application is driven by an internal worker task, which also handles I/O
/// for the connection. The worker feeds inbound packets into the
/// [quiche::Connection], calls [`ApplicationOverQuic::process_reads`] followed
/// by [`ApplicationOverQuic::process_writes`], and then flushes any pending
/// outbound packets to the network. This repeats in a loop until either the
/// connection is closed or the [`ApplicationOverQuic`] returns an error.
///
/// In between loop iterations, the worker yields until a new packet arrives, a
/// timer expires, or [`ApplicationOverQuic::wait_for_data`] resolves.
/// Implementors can interact with the underlying connection via the mutable
/// reference passed to trait methods.
#[allow(unused_variables)] // for default functions
pub trait ApplicationOverQuic: Send + 'static {
    /// Callback to customize the [`ApplicationOverQuic`] after the QUIC
    /// handshake completed successfully.
    ///
    /// # Errors
    /// Returning an error from this method immediately stops the worker loop
    /// and transitions to the connection closing stage.
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection, handshake_info: &HandshakeInfo,
    ) -> QuicResult<()>;

    /// Determines whether the application's methods will be called by the
    /// worker.
    ///
    /// The function is checked in each iteration of the worker loop. Only
    /// `on_conn_established()` and `buffer()` bypass this check.
    fn should_act(&self) -> bool;

    /// A borrowed buffer for the worker to write outbound packets into.
    ///
    /// This method allows sharing a buffer between the worker and the
    /// application, efficiently using the allocated memory while the
    /// application is inactive. It can also be used to artificially
    /// restrict the size of outbound network packets.
    ///
    /// Any data in the buffer may be overwritten by the worker. If necessary,
    /// the application should save the contents when this method is called.
    fn buffer(&mut self) -> &mut [u8];

    /// Waits for an event to trigger the next iteration of the worker loop.
    ///
    /// The returned future is awaited in parallel to inbound packets and the
    /// connection's timers. Any one of those futures resolving triggers the
    /// next loop iteration, so implementations should not rely on
    /// `wait_for_data` for the bulk of their processing. Instead, after
    /// `wait_for_data` resolves, `process_writes` should be used to pull all
    /// available data out of the event source (for example, a channel).
    ///
    /// As for any future, it is **very important** that this method does not
    /// block the runtime. If it does, the other concurrent futures will be
    /// starved.
    ///
    /// # Errors
    /// Returning an error from this method immediately stops the worker loop
    /// and transitions to the connection closing stage.
    fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send;

    /// Processes data received on the connection.
    ///
    /// This method is only called if `should_act()` returns `true` and any
    /// packets were received since the last worker loop iteration. It
    /// should be used to read from the connection's open streams.
    ///
    /// # Errors
    /// Returning an error from this method immediately stops the worker loop
    /// and transitions to the connection closing stage.
    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()>;

    /// Adds data to be sent on the connection.
    ///
    /// Unlike `process_reads`, this method is called on every iteration of the
    /// worker loop (provided `should_act()` returns true). It is called
    /// after `process_reads` and immediately before packets are pushed to
    /// the socket. The main use case is providing already-buffered data to
    /// the [quiche::Connection].
    ///
    /// # Errors
    /// Returning an error from this method immediately stops the worker loop
    /// and transitions to the connection closing stage.
    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()>;

    /// Callback to inspect the result of the worker task, before a final packet
    /// with a `CONNECTION_CLOSE` frame is flushed to the network.
    ///
    /// `connection_result` is [`Ok`] only if the connection was closed without
    /// any local error. Otherwise, the state of `qconn` depends on the
    /// error type and application behavior.
    fn on_conn_close<M: Metrics>(
        &mut self, qconn: &mut QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
    }
}

/// A command to execute on a [quiche::Connection] in the context of an
/// [`ApplicationOverQuic`].
///
/// We expect most [`ApplicationOverQuic`] implementations (such as
/// [H3Driver](crate::http3::driver::H3Driver)) will provide some way to submit
/// actions for them to take, for example via a channel. This enum may be
/// accepted as part of those actions to inspect or alter the state of the
/// underlying connection.
pub enum QuicCommand {
    /// Close the connection with the given parameters.
    ///
    /// Some packets may still be sent after this command has been executed, so
    /// the worker task may continue running for a bit. See
    /// [`quiche::Connection::close`] for details.
    ConnectionClose(ConnectionShutdownBehaviour),
    /// Execute a custom callback on the connection.
    Custom(Box<dyn FnOnce(&mut QuicheConnection) + Send + 'static>),
    /// Collect the current [`SocketStats`] from the connection.
    ///
    /// Unlike [`QuicConnection::stats()`], these statistics are not cached and
    /// instead are retrieved right before the command is executed.
    Stats(Box<dyn FnOnce(datagram_socket::SocketStats) + Send + 'static>),
}

impl QuicCommand {
    /// Consume the command and perform its operation on `qconn`.
    ///
    /// This method should be called by [`ApplicationOverQuic`] implementations
    /// when they receive a [`QuicCommand`] to execute.
    pub fn execute(self, qconn: &mut QuicheConnection) {
        match self {
            Self::ConnectionClose(behavior) => {
                let ConnectionShutdownBehaviour {
                    send_application_close,
                    error_code,
                    reason,
                } = behavior;

                let _ = qconn.close(send_application_close, error_code, &reason);
            },
            Self::Custom(f) => {
                (f)(qconn);
            },
            Self::Stats(callback) => {
                let stats_pair = QuicConnectionStats::from_conn(qconn);
                (callback)(stats_pair.as_socket_stats());
            },
        }
    }
}

impl fmt::Debug for QuicCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ConnectionClose(b) =>
                f.debug_tuple("ConnectionClose").field(b).finish(),
            Self::Custom(_) => f.debug_tuple("Custom").finish_non_exhaustive(),
            Self::Stats(_) => f.debug_tuple("Stats").finish_non_exhaustive(),
        }
    }
}

/// Parameters to close a [quiche::Connection].
///
/// The connection will use these parameters for the `CONNECTION_CLOSE` frame
/// it sends to its peer.
#[derive(Debug, Clone)]
pub struct ConnectionShutdownBehaviour {
    /// Whether to send an application close or a regular close to the peer.
    ///
    /// If this is true but the connection is not in a state where it is safe to
    /// send an application error (not established nor in early data), in
    /// accordance with [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3-3), the
    /// error code is changed to `APPLICATION_ERROR` and the reason phrase is
    /// cleared.
    pub send_application_close: bool,
    /// The [QUIC][proto-err] or [application-level][app-err] error code to send
    /// to the peer.
    ///
    /// [proto-err]: https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
    /// [app-err]: https://www.rfc-editor.org/rfc/rfc9000.html#section-20.2
    pub error_code: u64,
    /// The reason phrase to send to the peer.
    pub reason: Vec<u8>,
}
