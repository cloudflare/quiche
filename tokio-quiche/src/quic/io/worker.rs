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

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;
#[cfg(feature = "perf-quic-listener-metrics")]
use std::time::SystemTime;

use super::connection_stage::Close;
use super::connection_stage::ConnectionStage;
use super::connection_stage::ConnectionStageContext;
use super::connection_stage::Handshake;
use super::connection_stage::RunningApplication;
use super::gso::*;
use super::utilization_estimator::BandwidthReporter;

use crate::metrics::labels;
use crate::metrics::Metrics;
use crate::quic::connection::ApplicationOverQuic;
use crate::quic::connection::HandshakeError;
use crate::quic::connection::Incoming;
use crate::quic::connection::QuicConnectionStats;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::quic::router::ConnectionMapCommand;
use crate::quic::QuicheConnection;
use crate::QuicResult;

use boring::ssl::SslRef;
use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;
use datagram_socket::MaybeConnectedSocket;
use datagram_socket::QuicAuditStats;
use foundations::telemetry::log;
use quiche::ConnectionId;
use quiche::Error as QuicheError;
use quiche::SendInfo;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time;

// Number of incoming packets to be buffered in the incoming channel.
pub(crate) const INCOMING_QUEUE_SIZE: usize = 2048;

// Check if there are any incoming packets while sending data every this number
// of sent packets
pub(crate) const CHECK_INCOMING_QUEUE_RATIO: usize = INCOMING_QUEUE_SIZE / 16;

const RELEASE_TIMER_THRESHOLD: Duration = Duration::from_micros(250);

/// Stop queuing GSO packets, if packet size is below this threshold.
const GSO_THRESHOLD: usize = 1_000;

/// Size of each full egress buffer borrowed for a send burst.
///
/// Matches the maximum quiche buffer size so GSO batching is unaffected while
/// a connection is actively sending. Unlike a persistent per-connection
/// buffer, this memory is returned to the per-worker [`SEND_BUF_POOL`] before
/// the worker sleeps. The free list retains it for reuse (rather than truly
/// freeing it) but no idle connection owns an egress buffer.
const SEND_BUFFER_SIZE: usize = crate::buf_factory::BufFactory::MAX_BUF_SIZE;

/// Size of a temporary egress buffer when pooling is disabled.
///
/// The cold handshake and connection-close paths generate a single datagram at
/// a time. When pooling is enabled, they borrow a full-size buffer from
/// [`SEND_BUF_POOL`]; otherwise a one-MTU buffer is enough.
const TRANSIENT_SEND_BUFFER_SIZE: usize = 1500;

/// Allocates a zero-initialized egress buffer on the heap.
///
/// This is the cold path that fills [`SEND_BUF_POOL`] on a miss; steady-state
/// bursts borrow a recycled buffer via [`PooledSendBuf::acquire`] and never
/// hit this. The buffer is boxed (never a stack array) so that holding it
/// across the `.await` in [`IoWorker::flush_buffer_to_socket`] keeps the
/// worker's futures small and avoids uncontrolled stack growth.
fn alloc_send_buffer() -> Box<[u8]> {
    vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice()
}

thread_local! {
    /// Per-runtime-worker free-list of egress scratch buffers.
    ///
    /// A buffer is borrowed for a single send burst and returned on drop, so
    /// its pages stay resident across bursts (no per-burst page fault or
    /// kernel zero-fill) while no idle connection retains a buffer: the pool
    /// holds at most [`SEND_BUF_POOL_CAP`] buffers per worker thread,
    /// independent of the connection count.
    static SEND_BUF_POOL: std::cell::RefCell<Vec<Box<[u8]>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Upper bound on egress buffers parked per worker thread. The natural
/// high-water mark is the number of connection tasks simultaneously suspended
/// at a flush `.await` on one runtime thread; returns beyond the cap are freed
/// so a burst spike cannot pin unbounded memory to a thread.
///
/// This is a fixed per-worker-thread reservation, independent of the
/// connection count: up to `SEND_BUF_POOL_CAP * SEND_BUFFER_SIZE`
/// (16 * 64 KiB = 1 MiB) per runtime worker thread. The pool is not shrunk
/// once grown, so after a burst it stays at its high-water mark for the
/// process lifetime.
const SEND_BUF_POOL_CAP: usize = 16;

/// Egress scratch buffer borrowed from the per-thread [`SEND_BUF_POOL`] and
/// returned to it on drop.
///
/// Behaves like the `Box<[u8]>` it replaces via `Deref`/`DerefMut`, so idle
/// connections still retain no egress buffer, but the backing pages are
/// recycled instead of re-faulted (and re-zeroed by the kernel) every burst.
struct PooledSendBuf(Box<[u8]>);

impl PooledSendBuf {
    fn acquire() -> Self {
        let buf = SEND_BUF_POOL
            .with(|pool| pool.borrow_mut().pop())
            .unwrap_or_else(|| {
                // Pool miss (cold path): allocate a fresh buffer and record it.
                // Re-using a parked buffer (the hot path) does not touch any
                // counter.
                crate::metrics::quic::send_buffer_pool_allocated().inc();
                alloc_send_buffer()
            });
        // No re-zeroing on reuse: quiche writes only the bytes it emits and
        // the flush path transmits solely `send_buf[..bytes_written]`, so any
        // stale bytes left by a previous burst are never sent.
        Self(buf)
    }
}

impl Drop for PooledSendBuf {
    fn drop(&mut self) {
        // Move the buffer out, leaving an empty (non-allocating) boxed slice
        // behind, so it can be returned to the pool. Storing a plain
        // `Box<[u8]>` rather than an `Option` keeps `Deref`/`DerefMut`
        // panic-free.
        let buf = std::mem::take(&mut self.0);
        // Returns to *this* thread's pool. With tokio work-stealing a task may
        // migrate across the flush `.await`, so a buffer can be acquired on one
        // worker and returned on another; this is benign, and the per-thread
        // cap keeps the total bounded by `cap * workers`.
        SEND_BUF_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < SEND_BUF_POOL_CAP {
                pool.push(buf);
            } else {
                // Pool already at capacity (cold path, only under burst
                // spikes): drop the buffer instead of parking it, and record
                // the discard. Returning to a non-full pool (the hot path)
                // does not touch any counter.
                crate::metrics::quic::send_buffer_pool_discarded().inc();
            }
        });
    }
}

impl std::ops::Deref for PooledSendBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for PooledSendBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Egress buffer used briefly outside the main write loop.
///
/// This preserves the runtime pooling switch for handshake and close paths:
/// pooling borrows a full-size recycled buffer, while disabling it allocates a
/// small one-off buffer.
enum TransientSendBuf {
    Pooled(PooledSendBuf),
    Unpooled(Box<[u8]>),
}

impl TransientSendBuf {
    fn acquire(pool_send_buffer: bool) -> Self {
        if pool_send_buffer {
            Self::Pooled(PooledSendBuf::acquire())
        } else {
            Self::Unpooled(
                vec![0u8; TRANSIENT_SEND_BUFFER_SIZE].into_boxed_slice(),
            )
        }
    }
}

impl AsRef<[u8]> for TransientSendBuf {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Pooled(buf) => &buf[..],
            Self::Unpooled(buf) => &buf[..],
        }
    }
}

impl AsMut<[u8]> for TransientSendBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Pooled(buf) => &mut buf[..],
            Self::Unpooled(buf) => &mut buf[..],
        }
    }
}

pub struct WriterConfig {
    pub pending_cid: Option<ConnectionId<'static>>,
    pub stateless_reset_key: Option<u128>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub with_gso: bool,
    pub pacing_offload: bool,
    pub with_pktinfo: bool,
    /// Whether the worker borrows its egress buffer from a per-worker-thread
    /// pool for each send burst. When `false`, the worker keeps a persistent
    /// per-connection buffer for its lifetime instead.
    pub pool_send_buffer: bool,
}

#[derive(Default)]
pub(crate) struct WriteState {
    conn_established: bool,
    bytes_written: usize,
    segment_size: usize,
    num_pkts: usize,
    tx_time: Option<Instant>,
    has_pending_data: bool,
    // If pacer schedules packets too far into the future, we want to pause
    // sending, until the future arrives
    next_release_time: Option<Instant>,
    // The selected source and destination addresses for the current write
    // cycle.
    selected_path: Option<(SocketAddr, SocketAddr)>,
    // Iterator over the network paths that haven't been flushed yet.
    pending_paths: quiche::SocketAddrIter,
}

pub(crate) struct IoWorkerParams<Tx, M> {
    pub(crate) socket: MaybeConnectedSocket<Tx>,
    pub(crate) shutdown_tx: mpsc::Sender<()>,
    pub(crate) cfg: WriterConfig,
    pub(crate) audit_log_stats: Arc<QuicAuditStats>,
    pub(crate) write_state: WriteState,
    pub(crate) conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
    pub(crate) cid_generator: Option<SharedConnectionIdGenerator>,
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub(crate) init_rx_time: Option<SystemTime>,
    pub(crate) metrics: M,
}

pub(crate) struct IoWorker<Tx, M, S> {
    socket: MaybeConnectedSocket<Tx>,
    /// A field that signals to the listener task that the connection has gone
    /// away (nothing is sent here, listener task just detects the sender
    /// has dropped)
    shutdown_tx: mpsc::Sender<()>,
    cfg: WriterConfig,
    audit_log_stats: Arc<QuicAuditStats>,
    write_state: WriteState,
    conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
    cid_generator: Option<SharedConnectionIdGenerator>,
    #[cfg(feature = "perf-quic-listener-metrics")]
    init_rx_time: Option<SystemTime>,
    metrics: M,
    conn_stage: S,
    bw_estimator: BandwidthReporter,
}

impl<Tx, M, S> IoWorker<Tx, M, S>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
    S: ConnectionStage,
{
    pub(crate) fn new(params: IoWorkerParams<Tx, M>, conn_stage: S) -> Self {
        let bw_estimator =
            BandwidthReporter::new(params.metrics.utilized_bandwidth());

        log::trace!("Creating IoWorker with stage: {conn_stage:?}");

        Self {
            socket: params.socket,
            shutdown_tx: params.shutdown_tx,
            cfg: params.cfg,
            audit_log_stats: params.audit_log_stats,
            write_state: params.write_state,
            conn_map_cmd_tx: params.conn_map_cmd_tx,
            cid_generator: params.cid_generator,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: params.init_rx_time,
            metrics: params.metrics,
            conn_stage,
            bw_estimator,
        }
    }

    fn fill_available_scids(&self, qconn: &mut QuicheConnection) {
        if qconn.scids_left() == 0 {
            return;
        }
        let Some(cid_generator) = self.cid_generator.as_deref() else {
            return;
        };

        let current_cid = qconn.source_id().into_owned();
        for _ in 0..qconn.scids_left() {
            let new_cid = cid_generator.new_connection_id();
            let reset_token =
                reset_token_for_cid(self.cfg.stateless_reset_key, &new_cid);

            if self
                .conn_map_cmd_tx
                .send(ConnectionMapCommand::MapCid {
                    existing_cid: current_cid.clone(),
                    new_cid: new_cid.clone(),
                })
                .is_err()
            {
                // Can't do anything if the connection map is gone
                return;
            }

            if qconn.new_scid(&new_cid, reset_token, false).is_err() {
                // This only fails if we have reached the CID limit already
                return;
            }
        }
    }

    fn unmap_cid(&self, cid: ConnectionId<'static>) {
        // If the connection map is gone, the ID is already "unmapped"
        let _ = self
            .conn_map_cmd_tx
            .send(ConnectionMapCommand::UnmapCid(cid));
    }

    fn refresh_connection_ids(&self, qconn: &mut QuicheConnection) {
        // Top up the connection's active CIDs
        self.fill_available_scids(qconn);

        // Remove retired CIDs from the ingress router
        while let Some(retired_cid) = qconn.retired_scid_next() {
            self.unmap_cid(retired_cid);
        }
    }

    async fn work_loop<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) -> QuicResult<()> {
        const DEFAULT_SLEEP: Duration = Duration::from_secs(60);
        let mut current_deadline: Option<Instant> = None;
        let sleep = time::sleep(DEFAULT_SLEEP);
        tokio::pin!(sleep);

        // When pooling is disabled we keep one persistent egress buffer for the
        // whole connection, owned here in the IO worker and held across the loop
        // below (including while the connection is idle) -- the pre-pooling
        // behavior. When pooling is enabled this stays `None` and each send
        // burst borrows a transient buffer from the per-worker pool instead.
        let mut persistent_send_buf: Option<Box<[u8]>> =
            (!self.cfg.pool_send_buffer).then(alloc_send_buffer);

        loop {
            let now = Instant::now();

            self.write_state.has_pending_data = true;

            // Transient egress buffer for this wakeup's send burst when pooling
            // is enabled. Borrowed from the per-worker pool on demand (see
            // below) and returned after the burst, before the worker sleeps in
            // the `select!` further down, so idle connections still hold no
            // egress buffer. Stays `None` when a persistent buffer is used.
            let mut pooled_send_buf: Option<PooledSendBuf> = None;

            while self.write_state.has_pending_data {
                let mut packets_sent = 0;

                // Try to clear all received packets every so often, because
                // incoming packets contain acks, and because the
                // receive queue has a very limited size, once it is full incoming
                // packets get stalled indefinitely
                let mut did_recv = false;
                while let Some(pkt) = ctx
                    .in_pkt
                    .take()
                    .or_else(|| ctx.incoming_pkt_receiver.try_recv().ok())
                {
                    self.process_incoming(qconn, pkt)?;
                    did_recv = true;
                }

                self.conn_stage.on_read(did_recv, qconn, ctx)?;
                self.refresh_connection_ids(qconn);

                let can_release = match self.write_state.next_release_time {
                    None => true,
                    Some(next_release) =>
                        next_release
                            .checked_duration_since(now)
                            .unwrap_or_default() <
                            RELEASE_TIMER_THRESHOLD,
                };

                self.write_state.has_pending_data &= can_release;

                while self.write_state.has_pending_data &&
                    packets_sent < CHECK_INCOMING_QUEUE_RATIO
                {
                    // Use the persistent per-connection buffer when pooling is
                    // disabled. Otherwise borrow a buffer from the per-worker
                    // pool on the first gather of this send burst and reuse it
                    // for the remainder of the burst; it is returned at the end
                    // of the enclosing block (below), before the worker sleeps,
                    // so idle connections hold no egress buffer.
                    let send_buf: &mut [u8] =
                        if let Some(buf) = persistent_send_buf.as_deref_mut() {
                            buf
                        } else {
                            &mut pooled_send_buf
                                .get_or_insert_with(PooledSendBuf::acquire)[..]
                        };

                    self.gather_data_from_quiche_conn(qconn, send_buf, false)?;

                    // Break if the connection is closed
                    if qconn.is_closed() {
                        return Ok(());
                    }

                    let mut flush_operation_token =
                        TrackMidHandshakeFlush::new(self.metrics.clone());

                    self.flush_buffer_to_socket(&send_buf[..]).await;

                    flush_operation_token.mark_complete();

                    packets_sent += self.write_state.num_pkts;

                    if let ControlFlow::Break(reason) =
                        self.conn_stage.on_flush(qconn, ctx)
                    {
                        return reason;
                    }
                }
            }

            // Return the borrowed egress buffer to the per-worker pool before
            // sleeping so it is not held while the connection is idle. The
            // persistent buffer (when pooling is disabled) is intentionally
            // kept across sleeps for the connection's lifetime.
            drop(pooled_send_buf);

            self.bw_estimator.update(qconn, now);

            self.audit_log_stats
                .set_max_bandwidth(self.bw_estimator.max_bandwidth);
            self.audit_log_stats.set_max_loss_pct(
                (self.bw_estimator.max_loss_pct * 100_f32).round() as u8,
            );

            let new_deadline = min_of_some(
                qconn.timeout_instant(),
                self.write_state.next_release_time,
            );
            let new_deadline =
                min_of_some(new_deadline, self.conn_stage.wait_deadline());

            if new_deadline != current_deadline {
                current_deadline = new_deadline;

                sleep
                    .as_mut()
                    .reset(new_deadline.unwrap_or(now + DEFAULT_SLEEP).into());
            }

            let incoming_recv = &mut ctx.incoming_pkt_receiver;
            let application = &mut ctx.application;

            select! {
                biased;
                () = &mut sleep => {
                    // It's very important that we keep the timeout arm at the top of this loop so
                    // that we poll it every time we need to. Since this is a biased `select!`, if
                    // we put this behind another arm, we could theoretically starve the sleep arm
                    // and hang connections.
                    //
                    // See https://docs.rs/tokio/latest/tokio/macro.select.html#fairness for more
                    qconn.on_timeout();

                    self.write_state.next_release_time = None;
                    current_deadline = None;
                    sleep.as_mut().reset((now + DEFAULT_SLEEP).into());
                }
                Some(pkt) = incoming_recv.recv() => ctx.in_pkt = Some(pkt),
                directive = self.wait_for_data_or_handshake(qconn, application) => {
                    match directive? {
                        WaitForDataOrHandshakeDirective::Flush(send_buf) => {
                            // The handshake data was gathered into this
                            // on-demand buffer; flush it here (outside the
                            // select! so the flush cannot be cancelled), then
                            // return it to the pool or drop it.
                            self.flush_buffer_to_socket(send_buf.as_ref()).await;
                        }
                        WaitForDataOrHandshakeDirective::Noop => {}
                    }
                },
            };

            if let ControlFlow::Break(reason) = self.conn_stage.post_wait(qconn) {
                return reason;
            }
        }
    }

    #[cfg(feature = "perf-quic-listener-metrics")]
    fn measure_complete_handshake_time(&mut self) {
        if let Some(init_rx_time) = self.init_rx_time.take() {
            if let Ok(delta) = init_rx_time.elapsed() {
                self.metrics
                    .handshake_time_seconds(
                        labels::QuicHandshakeStage::HandshakeResponse,
                    )
                    .observe(delta.as_nanos() as u64);
            }
        }
    }

    /// Gathers one or more packets from quiche into `send_buf`.
    ///
    /// A single-packet gather leaves a full buffer available for the next
    /// packet instead of generating a short packet in the remaining tail.
    fn gather_data_from_quiche_conn(
        &mut self, qconn: &mut QuicheConnection, send_buf: &mut [u8],
        single_packet: bool,
    ) -> QuicResult<usize> {
        let mut segment_size = None;
        let mut send_info = None;

        self.write_state.num_pkts = 0;
        self.write_state.bytes_written = 0;

        self.write_state.selected_path = None;

        let now = Instant::now();

        let send_buf = {
            let trunc = UDP_MAX_GSO_PACKET_SIZE.min(send_buf.len());
            &mut send_buf[..trunc]
        };

        #[cfg(feature = "gcongestion")]
        let gcongestion_enabled = true;

        #[cfg(not(feature = "gcongestion"))]
        let gcongestion_enabled = qconn.gcongestion_enabled().unwrap_or(false);

        let initial_release_decision = if gcongestion_enabled {
            let initial_release_decision = qconn
                .get_next_release_time()
                .filter(|_| self.pacing_enabled(qconn));

            if let Some(future_release_time) =
                initial_release_decision.as_ref().and_then(|v| v.time(now))
            {
                let max_into_fut = qconn.max_release_into_future();

                if future_release_time.duration_since(now) >= max_into_fut {
                    self.write_state.next_release_time =
                        Some(now + max_into_fut.mul_f32(0.8));
                    self.write_state.has_pending_data = false;
                    return Ok(0);
                }
            }

            initial_release_decision
        } else {
            None
        };

        let buffer_write_outcome = loop {
            let outcome = self.write_packet_to_buffer(
                qconn,
                send_buf,
                &mut send_info,
                segment_size,
            );

            let packet_size = match outcome {
                Ok(0) => break Ok(0),

                Ok(bytes_written) => bytes_written,

                Err(e) => break Err(e),
            };

            // Flush after one packet when GSO is disabled or the caller needs
            // each packet to start with a full buffer.
            if single_packet || !self.cfg.with_gso {
                break outcome;
            }

            #[cfg(not(feature = "gcongestion"))]
            let max_send_size = if !gcongestion_enabled {
                // Only call qconn.send_quantum when !gcongestion_enabled.
                tune_max_send_size(
                    segment_size,
                    qconn.send_quantum(),
                    send_buf.len(),
                )
            } else {
                usize::MAX
            };

            #[cfg(feature = "gcongestion")]
            let max_send_size = usize::MAX;

            // If segment_size is known, update the maximum of
            // GSO sender buffer size to the multiple of
            // segment_size.
            let buffer_is_full = self.write_state.num_pkts ==
                UDP_MAX_SEGMENT_COUNT ||
                self.write_state.bytes_written >= max_send_size;

            if buffer_is_full {
                break outcome;
            }

            // Flush to network when the newly generated packet size is
            // different from previously written packet, as GSO needs packets
            // to have the same size, except for the last one in the buffer.
            // The last packet may be smaller than the previous size.
            match segment_size {
                Some(size)
                    if packet_size != size || packet_size < GSO_THRESHOLD =>
                    break outcome,
                None => segment_size = Some(packet_size),
                _ => (),
            }

            if gcongestion_enabled {
                // If the release time of next packet is different, or it can't be
                // part of a burst, start the next batch
                if let Some(initial_release_decision) = initial_release_decision {
                    match qconn.get_next_release_time() {
                        Some(release)
                            if release.can_burst() ||
                                release.time_eq(
                                    &initial_release_decision,
                                    now,
                                ) => {},
                        _ => break outcome,
                    }
                }
            }
        };

        let tx_time = if gcongestion_enabled {
            initial_release_decision
                .filter(|_| self.pacing_enabled(qconn))
                // Return the time from the release decision if release_decision.time > now, else None.
                .and_then(|v| v.time(now))
        } else {
            send_info
                .filter(|_| self.pacing_enabled(qconn))
                .map(|v| v.at)
        };

        self.write_state.conn_established = qconn.is_established();
        self.write_state.tx_time = tx_time;
        self.write_state.segment_size =
            segment_size.unwrap_or(self.write_state.bytes_written);

        if !gcongestion_enabled {
            if let Some(time) = tx_time {
                const DEFAULT_MAX_INTO_FUTURE: Duration =
                    Duration::from_millis(1);
                if time
                    .checked_duration_since(now)
                    .map(|d| d > DEFAULT_MAX_INTO_FUTURE)
                    .unwrap_or(false)
                {
                    self.write_state.next_release_time =
                        Some(now + DEFAULT_MAX_INTO_FUTURE.mul_f32(0.8));
                    self.write_state.has_pending_data = false;
                    return Ok(0);
                }
            }
        }

        buffer_write_outcome
    }

    /// Selects a network path, if none already selected.
    ///
    /// This will return the first path available in the write state's
    /// `pending_paths` iterator. If that is empty a new iterator will be
    /// created by querying quiche itself.
    ///
    /// Note that the connection's statically configured local address will be
    /// used to query quiche for available paths, so this can't handle multiple
    /// local addresses currently.
    fn select_path(
        &mut self, qconn: &QuicheConnection,
    ) -> Option<(SocketAddr, SocketAddr)> {
        if self.write_state.selected_path.is_some() {
            return self.write_state.selected_path;
        }

        let from = self.cfg.local_addr;

        // Initialize paths iterator.
        if self.write_state.pending_paths.len() == 0 {
            self.write_state.pending_paths = qconn.paths_iter(from);
        }

        let to = self.write_state.pending_paths.next()?;

        Some((from, to))
    }

    #[cfg(not(feature = "gcongestion"))]
    fn pacing_enabled(&self, qconn: &QuicheConnection) -> bool {
        self.cfg.pacing_offload && qconn.pacing_enabled()
    }

    #[cfg(feature = "gcongestion")]
    fn pacing_enabled(&self, _qconn: &QuicheConnection) -> bool {
        self.cfg.pacing_offload
    }

    fn write_packet_to_buffer(
        &mut self, qconn: &mut QuicheConnection, send_buf: &mut [u8],
        send_info: &mut Option<SendInfo>, segment_size: Option<usize>,
    ) -> QuicResult<usize> {
        let mut send_buf = &mut send_buf[self.write_state.bytes_written..];
        if send_buf.len() > segment_size.unwrap_or(usize::MAX) {
            // Never let the buffer be longer than segment size, for GSO to
            // function properly.
            send_buf = &mut send_buf[..segment_size.unwrap_or(usize::MAX)];
        }

        // On the first call to `select_path()` a path will be chosen based on
        // the local address the connection initially landed on. Once a path is
        // selected following calls to `select_path()` will return it, until it
        // is reset at the start of the next write cycle.
        //
        // The path is then passed to `send_on_path()` which will only generate
        // packets meant for that path, this way a single GSO buffer will only
        // contain packets that belong to the same network path, which is
        // required because the from/to addresses for each `sendmsg()` call
        // apply to the whole GSO buffer.
        let (from, to) = self.select_path(qconn).unzip();

        match qconn.send_on_path(send_buf, from, to) {
            Ok((packet_size, info)) => {
                let _ = send_info.get_or_insert(info);

                self.write_state.bytes_written += packet_size;
                self.write_state.num_pkts += 1;

                let from = send_info.as_ref().map(|info| info.from);
                let to = send_info.as_ref().map(|info| info.to);

                self.write_state.selected_path = from.zip(to);

                self.write_state.has_pending_data = true;

                Ok(packet_size)
            },

            Err(QuicheError::Done) => {
                // Flush the current buffer to network. If no other path needs
                // to be flushed to the network also yield the work loop task.
                //
                // Otherwise the write loop will start again and the next path
                // will be selected.
                let has_pending_paths = self.write_state.pending_paths.len() > 0;

                // Keep writing if there are paths left to try.
                self.write_state.has_pending_data = has_pending_paths;

                Ok(0)
            },

            Err(e) => {
                let error_code = if let Some(local_error) = qconn.local_error() {
                    local_error.error_code
                } else {
                    let internal_error_code =
                        quiche::WireErrorCode::InternalError as u64;
                    let _ = qconn.close(false, internal_error_code, &[]);

                    internal_error_code
                };

                self.audit_log_stats
                    .set_sent_conn_close_transport_error_code(error_code as i64);

                Err(Box::new(e))
            },
        }
    }

    async fn flush_buffer_to_socket(&mut self, send_buf: &[u8]) {
        if self.write_state.bytes_written > 0 {
            let current_send_buf = &send_buf[..self.write_state.bytes_written];

            let (from, to) = self.write_state.selected_path.unzip();

            let to = to.unwrap_or(self.cfg.peer_addr);
            let from = from.filter(|_| self.cfg.with_pktinfo);

            let send_res = if let (Some(udp_socket), true) =
                (self.socket.as_udp_socket(), self.cfg.with_gso)
            {
                // Only UDP supports GSO.
                send_to(
                    udp_socket,
                    to,
                    from,
                    current_send_buf,
                    self.write_state.segment_size,
                    self.write_state.tx_time,
                    self.metrics
                        .write_errors(labels::QuicWriteError::WouldBlock),
                    self.metrics.send_to_wouldblock_duration_s(),
                )
                .await
            } else {
                self.socket.send_to(current_send_buf, to).await
            };

            #[cfg(feature = "perf-quic-listener-metrics")]
            self.measure_complete_handshake_time();

            match send_res {
                Ok(n) =>
                    if n < self.write_state.bytes_written {
                        self.metrics
                            .write_errors(labels::QuicWriteError::Partial)
                            .inc();
                    },

                Err(_) => {
                    self.metrics.write_errors(labels::QuicWriteError::Err).inc();
                },
            }
        }
    }

    /// Process the incoming packet
    fn process_incoming(
        &mut self, qconn: &mut QuicheConnection, mut pkt: Incoming,
    ) -> QuicResult<()> {
        let recv_info = quiche::RecvInfo {
            from: pkt.peer_addr,
            to: pkt.local_addr,
        };

        if let Some(gro) = pkt.gro {
            for dgram in pkt.buf.chunks_mut(gro as usize) {
                qconn.recv(dgram, recv_info)?;
            }
        } else {
            qconn.recv(&mut pkt.buf, recv_info)?;
        }

        Ok(())
    }

    // When a connection is established, process application data, if not the task
    // is probably polled following a wakeup from boring, so we check if quiche
    // has any handshake packets to send.
    //
    // TODO(erittenhouse): would be nice to decouple wait_for_data from the
    // application, but wait_for_quiche relies on IOW methods, so we can't write a
    // default implementation for ConnectionStage
    //
    // # Cancel safety
    //
    // This future is polled as an arm of the `select!` in [`Self::work_loop`],
    // so it MUST be cancel safe: it may be dropped at any `.await` point when
    // another arm completes first. It stays cancel safe because
    // [`ApplicationOverQuic::wait_for_data`] is itself required to be cancel
    // safe, and the handshake branch keeps no state across its `.await` beyond
    // the local `send_buf` (which is returned to the free list or freed if the
    // future is cancelled; any bytes gathered into it are re-gathered on the
    // next poll). Take care to preserve this property when modifying it.
    async fn wait_for_data_or_handshake<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection, quic_application: &mut A,
    ) -> QuicResult<WaitForDataOrHandshakeDirective> {
        if quic_application.should_act() {
            // Poll the application to make progress.
            //
            // Once the connection has been established (i.e. the handshake is
            // complete), we only poll the application.
            //
            // The exception is 0-RTT in TLS 1.3, where the full handshake is
            // still in progress but we have 0-RTT keys to process early data.
            // This means TLS callbacks might only be polled on the next timeout
            // or when a packet is received from the peer.
            quic_application.wait_for_data(qconn).await?;
            Ok(WaitForDataOrHandshakeDirective::Noop)
        } else {
            // Poll quiche to make progress on handshake callbacks, gathering
            // any handshake packets into an on-demand buffer that the caller
            // flushes. `wait_for_quiche()` returns it only after generating a
            // packet, so pending handshake waits do not retain a buffer.
            let send_buf = self.wait_for_quiche(qconn).await?;
            Ok(WaitForDataOrHandshakeDirective::Flush(send_buf))
        }
    }

    /// Check if Quiche has any packets to send
    ///
    /// If yes: fills buffer and updates self.write_state.bytes_written
    /// If no: Poll::Pending
    ///
    /// # Example
    ///
    /// This function can be used, for example, to drive an asynchronous TLS
    /// handshake. Each call to `gather_data_from_quiche_conn` attempts to
    /// progress the handshake via a call to `quiche::Connection.send()` -
    /// once one of the `gather_data_from_quiche_conn()` calls writes to the
    /// send buffer, we signal to the caller which has to take care of flushing
    ///
    /// # Cancel safety
    ///
    /// This future is awaited (indirectly) as an arm of the `select!` in
    /// [`Self::work_loop`], so it MUST be cancel safe. The `poll_fn` below
    /// holds no state across polls other than what lives in `self.write_state`,
    /// so dropping the future between polls loses nothing: the next call simply
    /// re-gathers. Take care to preserve this property when modifying it.
    async fn wait_for_quiche(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<TransientSendBuf> {
        let send_buf = std::future::poll_fn(|_| {
            // Allocate inside this closure so a pending poll immediately
            // returns its buffer to the pool instead of retaining it across
            // the select! wait.
            let mut send_buf =
                TransientSendBuf::acquire(self.cfg.pool_send_buffer);

            match self.gather_data_from_quiche_conn(
                qconn,
                send_buf.as_mut(),
                true,
            ) {
                Ok(bytes_written) => {
                    // We need to avoid consecutive calls to gather(), which write
                    // data to the buffer, without a flush().
                    // If we don't avoid those consecutive calls, we end
                    // up overwriting data in the buffer or unnecessarily waiting
                    // for more calls to drive_handshake()
                    // before calling the handshake complete.
                    if bytes_written == 0 && self.write_state.bytes_written == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(send_buf))
                    }
                },
                _ => Poll::Ready(Err(quiche::Error::TlsFail)),
            }
        })
        .await?;
        Ok(send_buf)
    }
}

/// Whether caller of [`wait_for_data_or_handshake`] is required to
/// call [`flush_buffer_to_socket`].
///
/// `Flush` carries the on-demand buffer the handshake data was gathered into so
/// the caller can flush it and then return it to the pool or drop it.
#[must_use]
enum WaitForDataOrHandshakeDirective {
    Noop,
    Flush(TransientSendBuf),
}

pub struct Running<Tx, M, A> {
    pub(crate) params: IoWorkerParams<Tx, M>,
    pub(crate) context: ConnectionStageContext<A>,
    /// See [`QuicConnectionParams::quiche_conn`].
    pub(crate) qconn: Box<QuicheConnection>,
}

impl<Tx, M, A> Running<Tx, M, A> {
    pub fn ssl(&mut self) -> &mut SslRef {
        // Deref to pick `Connection::as_mut` over `Box::as_mut`.
        (*self.qconn).as_mut()
    }
}

pub(crate) struct Closing<Tx, M, A> {
    pub(crate) params: IoWorkerParams<Tx, M>,
    pub(crate) context: ConnectionStageContext<A>,
    pub(crate) work_loop_result: QuicResult<()>,
    /// See [`QuicConnectionParams::quiche_conn`].
    pub(crate) qconn: Box<QuicheConnection>,
}

pub enum RunningOrClosing<Tx, M, A> {
    Running(Running<Tx, M, A>),
    Closing(Closing<Tx, M, A>),
}

impl<Tx, M> IoWorker<Tx, M, Handshake>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn run<A>(
        mut self, mut qconn: Box<QuicheConnection>,
        mut ctx: ConnectionStageContext<A>,
    ) -> RunningOrClosing<Tx, M, A>
    where
        A: ApplicationOverQuic,
    {
        // This makes an assumption that the waker being set in ex_data is stable
        // across the active task's lifetime. Moving a future that encompasses an
        // async callback from this task across a channel, for example, will
        // cause issues as this waker will then be stale and attempt to
        // wake the wrong task.
        std::future::poll_fn(|cx| {
            // Deref to pick `Connection::as_mut` over `Box::as_mut`.
            let ssl = (*qconn).as_mut();
            ssl.set_task_waker(Some(cx.waker().clone()));

            Poll::Ready(())
        })
        .await;

        #[cfg(target_os = "linux")]
        if let Some(incoming) = ctx.in_pkt.as_mut() {
            self.audit_log_stats
                .set_initial_so_mark_data(incoming.so_mark_data.take());
        }

        let mut work_loop_result = self.work_loop(&mut qconn, &mut ctx).await;
        if work_loop_result.is_ok() && qconn.is_closed() {
            work_loop_result = Err(HandshakeError::ConnectionClosed.into());
        }

        if let Err(err) = &work_loop_result {
            self.metrics.failed_handshakes(err.into()).inc();

            return RunningOrClosing::Closing(Closing {
                params: self.into(),
                context: ctx,
                work_loop_result,
                qconn,
            });
        };

        match self.on_conn_established(&mut qconn, &mut ctx.application) {
            Ok(()) => RunningOrClosing::Running(Running {
                params: self.into(),
                context: ctx,
                qconn,
            }),
            Err(e) => {
                foundations::telemetry::log::warn!(
                    "Handshake stage on_connection_established failed"; "error"=>%e
                );

                RunningOrClosing::Closing(Closing {
                    params: self.into(),
                    context: ctx,
                    work_loop_result,
                    qconn,
                })
            },
        }
    }

    fn on_conn_established<App: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection, driver: &mut App,
    ) -> QuicResult<()> {
        // Only calculate the QUIC handshake duration and call the driver's
        // on_conn_established hook if this is the first time
        // is_established == true.
        if self.audit_log_stats.transport_handshake_duration_us() == -1 {
            self.conn_stage.handshake_info.set_elapsed();
            let handshake_info = &self.conn_stage.handshake_info;

            self.audit_log_stats
                .set_transport_handshake_duration(handshake_info.elapsed());

            driver.on_conn_established(qconn, handshake_info)?;
        }

        if let Some(cid) = self.cfg.pending_cid.take() {
            self.unmap_cid(cid);
        }

        Ok(())
    }
}

impl<Tx, M, S> From<IoWorker<Tx, M, S>> for IoWorkerParams<Tx, M> {
    fn from(value: IoWorker<Tx, M, S>) -> Self {
        Self {
            socket: value.socket,
            shutdown_tx: value.shutdown_tx,
            cfg: value.cfg,
            audit_log_stats: value.audit_log_stats,
            write_state: value.write_state,
            conn_map_cmd_tx: value.conn_map_cmd_tx,
            cid_generator: value.cid_generator,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: value.init_rx_time,
            metrics: value.metrics,
        }
    }
}

impl<Tx, M> IoWorker<Tx, M, RunningApplication>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn run<A: ApplicationOverQuic>(
        mut self, mut qconn: Box<QuicheConnection>,
        mut ctx: ConnectionStageContext<A>,
    ) -> Closing<Tx, M, A> {
        // Perform a single call to process_reads()/process_writes(),
        // unconditionally, to ensure that any application data (e.g.
        // STREAM frames or datagrams) processed by the Handshake
        // stage are properly passed to the application.
        if let Err(e) = self.conn_stage.on_read(true, &mut qconn, &mut ctx) {
            return Closing {
                params: self.into(),
                context: ctx,
                work_loop_result: Err(e),
                qconn,
            };
        };

        let work_loop_result = self.work_loop(&mut qconn, &mut ctx).await;

        Closing {
            params: self.into(),
            context: ctx,
            work_loop_result,
            qconn,
        }
    }
}

impl<Tx, M> IoWorker<Tx, M, Close>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn close<A: ApplicationOverQuic>(
        mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) {
        if self.conn_stage.work_loop_result.is_ok() &&
            self.bw_estimator.max_bandwidth > 0
        {
            let metrics = &self.metrics;

            metrics
                .max_bandwidth_mbps()
                .observe(self.bw_estimator.max_bandwidth as f64 * 1e-6);

            metrics
                .max_loss_pct()
                .observe(self.bw_estimator.max_loss_pct as f64 * 100.);
        }

        if ctx.application.should_act() {
            ctx.application.on_conn_close(
                qconn,
                &self.metrics,
                &self.conn_stage.work_loop_result,
            );
        }

        // TODO: this assumes that the tidy_up operation can be completed in one
        // send (ignoring flow/congestion control constraints). We should
        // guarantee that it gets sent by doublechecking the
        // gathered/flushed byte totals and retry if they don't match.
        //
        // This runs once per connection at close and sends a single
        // CONNECTION_CLOSE datagram, so acquire a buffer only for this send.
        let mut send_buf = TransientSendBuf::acquire(self.cfg.pool_send_buffer);
        let _ =
            self.gather_data_from_quiche_conn(qconn, send_buf.as_mut(), false);
        self.flush_buffer_to_socket(send_buf.as_ref()).await;

        *ctx.stats.lock().unwrap() = QuicConnectionStats::from_conn(qconn);

        if let Some(err) = qconn.peer_error() {
            if err.is_app {
                self.audit_log_stats
                    .set_recvd_conn_close_application_error_code(
                        err.error_code as _,
                    );
            } else {
                self.audit_log_stats
                    .set_recvd_conn_close_transport_error_code(
                        err.error_code as _,
                    );
            }
        }

        if let Some(err) = qconn.local_error() {
            if err.is_app {
                self.audit_log_stats
                    .set_sent_conn_close_application_error_code(
                        err.error_code as _,
                    );
            } else {
                self.audit_log_stats
                    .set_sent_conn_close_transport_error_code(
                        err.error_code as _,
                    );
            }
        }

        self.close_connection(qconn);

        if let Err(work_loop_error) = self.conn_stage.work_loop_result {
            self.audit_log_stats
                .set_connection_close_reason(work_loop_error);
        }
    }

    fn close_connection(&mut self, qconn: &mut QuicheConnection) {
        if let Some(cid) = self.cfg.pending_cid.take() {
            self.unmap_cid(cid);
        }
        while let Some(retired_cid) = qconn.retired_scid_next() {
            self.unmap_cid(retired_cid);
        }
        for cid in qconn.source_ids().cloned() {
            self.unmap_cid(cid.into_owned());
        }

        self.metrics.connections_in_memory().dec();
    }
}

/// Returns the minimum of `v1` and `v2`, ignoring `None`s.
fn min_of_some<T: Ord>(v1: Option<T>, v2: Option<T>) -> Option<T> {
    match (v1, v2) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(v), _) | (_, Some(v)) => Some(v),
        (None, None) => None,
    }
}

/// A Token which increment the skipped_mid_handshake_flush_count metric on
/// `Drop` unless it is marked complete.
struct TrackMidHandshakeFlush<M: Metrics> {
    complete: bool,
    metrics: M,
}

impl<M: Metrics> TrackMidHandshakeFlush<M> {
    fn new(metrics: M) -> Self {
        Self {
            complete: false,
            metrics,
        }
    }

    fn mark_complete(&mut self) {
        self.complete = true;
    }
}

impl<M: Metrics> Drop for TrackMidHandshakeFlush<M> {
    fn drop(&mut self) {
        if !self.complete {
            self.metrics.skipped_mid_handshake_flush_count().inc();
        }
    }
}

fn reset_token_for_cid(static_key: Option<u128>, cid: &ConnectionId) -> u128 {
    let Some(static_key) = static_key else {
        return random_u128();
    };

    match quiche::derive_stateless_reset_wire_token(
        &static_key.to_be_bytes(),
        cid.as_ref(),
    ) {
        Ok(reset_token) => reset_token,
        Err(error) => {
            log::error!("failed to derive stateless reset token, using a random token"; "error" => ?error);
            random_u128()
        },
    }
}

fn random_u128() -> u128 {
    let mut buf = [0; 16];
    boring::rand::rand_bytes(&mut buf).expect("boring's RAND_bytes never fails");
    u128::from_ne_bytes(buf)
}

#[cfg(test)]
mod pooled_send_buf_tests {
    use super::*;

    // Each test runs on a freshly spawned thread so the thread-local
    // `SEND_BUF_POOL` starts empty (const-initialized) and cannot interfere
    // with other tests sharing the harness's worker threads.

    #[test]
    fn caps_retained_buffers() {
        std::thread::spawn(|| {
            // Acquire more than the cap at once (all misses, so all fresh
            // allocations), then drop them. Only `SEND_BUF_POOL_CAP` may be
            // parked; the remainder are freed.
            let bufs: Vec<PooledSendBuf> = (0..SEND_BUF_POOL_CAP + 4)
                .map(|_| PooledSendBuf::acquire())
                .collect();
            drop(bufs);

            let retained = SEND_BUF_POOL.with(|pool| pool.borrow().len());
            assert_eq!(retained, SEND_BUF_POOL_CAP);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn reuses_a_returned_buffer() {
        std::thread::spawn(|| {
            let first_ptr = {
                let buf = PooledSendBuf::acquire();
                assert_eq!(buf.len(), SEND_BUFFER_SIZE);
                buf.as_ptr()
            }; // returned to the pool here

            let reused = PooledSendBuf::acquire();
            assert_eq!(
                reused.as_ptr(),
                first_ptr,
                "acquire should hand back the pooled allocation"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn returns_to_the_dropping_thread() {
        // Acquire on one thread, drop on another: the buffer lands in the
        // dropping thread's pool (work-stealing migration across `.await` is
        // benign).
        let buf = std::thread::spawn(PooledSendBuf::acquire).join().unwrap();

        std::thread::spawn(move || {
            assert_eq!(SEND_BUF_POOL.with(|pool| pool.borrow().len()), 0);
            drop(buf);
            assert_eq!(SEND_BUF_POOL.with(|pool| pool.borrow().len()), 1);
        })
        .join()
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_token_for_cid_is_derived_when_key_is_configured() {
        let static_key = u128::from_be_bytes([0xba; 16]);
        let cid = ConnectionId::from_ref(b"cid");

        assert_eq!(
            reset_token_for_cid(Some(static_key), &cid),
            0x5c99_a18d_1775_d13b_f681_8a38_0867_604b,
        );
    }
}
