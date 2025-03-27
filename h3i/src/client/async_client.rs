use buffer_pool::ConsumeBuffer;
use buffer_pool::Pool;
use buffer_pool::Pooled;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep_until;
use tokio::time::Instant;

use log;

use tokio_quiche::http3::driver::H3ConnectionError;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quiche::Connection as QConnection;
use tokio_quiche::quiche::PathStats;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;

use crate::actions::h3::Action;
use crate::actions::h3::WaitType;
use crate::actions::h3::WaitingFor;
use crate::client::execute_action;
use crate::client::parse_args;
use crate::client::parse_streams;
use crate::client::ClientError;
use crate::client::CloseTriggerFrames;
use crate::client::ConnectionSummary;
use crate::client::ParsedArgs;
use crate::client::StreamMap;
use crate::config::Config as H3iConfig;

use super::Client;
use super::ConnectionCloseDetails;
use super::ConnectionRecord;
use super::StreamParserMap;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DATAGRAM_POOL_SIZE: usize = 64 * 1024;
const POOL_SIZE: usize = 16 * 1024;
const POOL_SHARDS: usize = 8;
pub const MAX_POOL_BUF_SIZE: usize = 64 * 1024;

/// A generic buffer pool used to pass data around.
pub static BUF_POOL: Pool<POOL_SHARDS, ConsumeBuffer> =
    Pool::<POOL_SHARDS, _>::new(POOL_SIZE, MAX_POOL_BUF_SIZE);
/// A datagram pool shared for both UDP streams, and incoming QUIC packets.
pub static DATAGRAM_POOL: Pool<POOL_SHARDS, ConsumeBuffer> =
    Pool::<POOL_SHARDS, _>::new(DATAGRAM_POOL_SIZE, MAX_DATAGRAM_SIZE);

/// Connect to the socket.
pub async fn connect(
    args: H3iConfig, frame_actions: Vec<Action>,
    close_trigger_frames: Option<CloseTriggerFrames>,
) -> std::result::Result<BuildingConnectionSummary, ClientError> {
    let ParsedArgs {
        local_addr,
        peer_addr,
        connect_url,
    } = parse_args(&args);

    let connection_params = ConnectionParams::new_client(
        QuicSettings {
            disable_client_ip_validation: true,
            // TODO(evanrittenhouse): make this configurable via CLI args, add
            // qlog_dir option
            handshake_timeout: Some(Duration::from_secs(args.idle_timeout)),
            ..Default::default()
        },
        None,
        Hooks::default(),
    );

    let socket = tokio::net::UdpSocket::bind(local_addr).await.unwrap();
    socket.connect(peer_addr).await.unwrap();

    log::info!(
        "connecting to {:} from {:}",
        peer_addr,
        socket.local_addr().unwrap()
    );

    let (h3i, conn_summary_fut) =
        H3iDriver::new(frame_actions, close_trigger_frames);
    match tokio_quiche::quic::connect_with_config(
        socket,
        connect_url.as_ref().map(String::as_str),
        &connection_params,
        h3i,
    )
    .await
    {
        Ok(_) => Ok(conn_summary_fut),
        Err(_) => Err(ClientError::HandshakeFail),
    }
}

#[must_use = "must await the connection summary"]
pub struct BuildingConnectionSummary {
    rx: mpsc::UnboundedReceiver<ConnectionRecord>,
    summary: Option<ConnectionSummary>,
    seen_all_close_trigger_frames: Option<mpsc::Sender<()>>,
}

impl BuildingConnectionSummary {
    pub fn new(
        rx: mpsc::UnboundedReceiver<ConnectionRecord>,
        close_trigger_frames: Option<CloseTriggerFrames>,
        trigger_frame_tx: mpsc::Sender<()>,
    ) -> Self {
        let summary = ConnectionSummary {
            stream_map: StreamMap::new(close_trigger_frames),
            ..Default::default()
        };

        Self {
            rx,
            summary: Some(summary),
            seen_all_close_trigger_frames: Some(trigger_frame_tx),
        }
    }
}

impl Future for BuildingConnectionSummary {
    type Output = ConnectionSummary;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        while let Poll::Ready(Some(record)) = self.rx.poll_recv(cx) {
            let summary = self.summary.as_mut().expect("summary already taken");

            match record {
                ConnectionRecord::StreamedFrame { stream_id, frame } => {
                    let stream_map = &mut summary.stream_map;
                    stream_map.insert(stream_id, frame);

                    if stream_map.all_close_trigger_frames_seen() {
                        // Signal the H3iDriver task to close the connection.
                        if let Some(expected_tx) =
                            self.seen_all_close_trigger_frames.take()
                        {
                            let _ = expected_tx.try_send(());
                        }
                    }
                },
                ConnectionRecord::ConnectionStats(s) => summary.stats = Some(s),
                ConnectionRecord::PathStats(ps) => summary.path_stats = ps,
                ConnectionRecord::Close(d) => summary.conn_close_details = d,
            };
        }

        if self.rx.is_closed() {
            // The sender drops when the Tokio-Quiche IOW finishes, so the
            // connection is done and we're safe to yield the summary.
            let summary = self.summary.take().expect("summary already taken");
            Poll::Ready(summary)
        } else {
            Poll::Pending
        }
    }
}

pub struct H3iDriver {
    buffer: Pooled<ConsumeBuffer>,
    actions: Vec<Action>,
    actions_executed: usize,
    /// The minimum time at which the next action should fire.
    next_fire_time: Instant,
    /// If the [QConnection] is established
    should_act: bool,
    waiting_for_responses: WaitingFor,

    record_tx: mpsc::UnboundedSender<ConnectionRecord>,
    stream_parsers: StreamParserMap,
    close_trigger_seen_rx: mpsc::Receiver<()>,
}

impl H3iDriver {
    fn new(
        actions: Vec<Action>, close_trigger_frames: Option<CloseTriggerFrames>,
    ) -> (Self, BuildingConnectionSummary) {
        let (record_tx, record_rx_chan) = mpsc::unbounded_channel();
        let (close_trigger_seen_tx, close_trigger_seen_rx) =
            mpsc::channel::<()>(1);
        let fut = BuildingConnectionSummary::new(
            record_rx_chan,
            close_trigger_frames,
            close_trigger_seen_tx,
        );

        (
            Self {
                buffer: BUF_POOL.get_with(|d| d.expand(MAX_POOL_BUF_SIZE)),
                actions,
                actions_executed: 0,
                next_fire_time: Instant::now(),
                should_act: false,
                waiting_for_responses: WaitingFor::default(),
                // Sends [StreamedFrame]s to the user-facing [FrameRx].
                record_tx,
                stream_parsers: StreamParserMap::default(),
                close_trigger_seen_rx,
            },
            fut,
        )
    }

    /// If all actions have been completed.
    fn actions_complete(&self) -> bool {
        self.actions_executed == self.actions.len()
    }

    /// If the next action should fire.
    fn should_fire(&self) -> bool {
        Instant::now() >= self.next_fire_time
    }

    /// Insert all waits into the waiting set.
    fn register_waits(&mut self) {
        while self.actions_executed < self.actions.len() {
            if let Action::Wait { wait_type } =
                &self.actions[self.actions_executed]
            {
                self.actions_executed += 1;

                match wait_type {
                    WaitType::WaitDuration(duration) => {
                        self.next_fire_time = Instant::now() + *duration;

                        log::debug!(
                            "won't fire an action due to waiting for responses: {:?}",
                            self.waiting_for_responses
                        );
                    },
                    WaitType::StreamEvent(event) => {
                        self.waiting_for_responses.add_wait(event);
                    },
                }
            } else {
                break;
            }
        }
    }
}

impl Client for H3iDriver {
    fn stream_parsers_mut(&mut self) -> &mut StreamParserMap {
        &mut self.stream_parsers
    }

    fn handle_response_frame(
        &mut self, stream_id: u64, frame: crate::frame::H3iFrame,
    ) {
        self.record_tx
            .send(ConnectionRecord::StreamedFrame { stream_id, frame })
            .expect("H3iDriver task dropped")
    }
}

impl ApplicationOverQuic for H3iDriver {
    fn on_conn_established(
        &mut self, _qconn: &mut QConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        log::info!("HTTP/3 connection established");
        self.should_act = true;

        Ok(())
    }

    fn should_act(&self) -> bool {
        self.should_act
    }

    fn process_reads(&mut self, qconn: &mut QConnection) -> QuicResult<()> {
        log::debug!("process_reads");

        // This is executed in process_reads, before reading any frames, so that
        // we can clear any waits resolved by the current read iteration.
        // If this was in process_writes, we'd potentially miss some and
        // hang the client.
        self.register_waits();

        let stream_events = parse_streams(qconn, self);
        for event in stream_events {
            self.waiting_for_responses.remove_wait(event);
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QConnection) -> QuicResult<()> {
        log::debug!("process_writes");

        if !self.waiting_for_responses.is_empty() {
            log::debug!(
                "awaiting responses on streams {:?}, skipping further action",
                self.waiting_for_responses
            );

            return Ok(());
        }

        // Re-create the iterator so we can mutably borrow the stream parser map
        let mut iter =
            self.actions.clone().into_iter().skip(self.actions_executed);
        while let Some(action) = iter.next() {
            match action {
                Action::SendFrame { .. }
                | Action::StreamBytes { .. }
                | Action::ResetStream { .. }
                | Action::StopSending { .. }
                | Action::OpenUniStream { .. }
                | Action::ConnectionClose { .. }
                | Action::SendHeadersFrame { .. } => {
                    if self.should_fire() {
                        // Reset the fire time such that the next action will
                        // still fire.
                        self.next_fire_time = Instant::now();

                        execute_action(&action, qconn, self.stream_parsers_mut());
                        self.actions_executed += 1;
                    } else {
                        break;
                    }
                },
                Action::Wait { .. } => {
                    // Break out of the write phase if we see a wait, since waits
                    // have to be registered in the read
                    // phase. The actions_executed pointer will be
                    // incremented there as well
                    break;
                },
                Action::FlushPackets => {
                    self.actions_executed += 1;
                    break;
                },
            }
        }

        Ok(())
    }

    async fn wait_for_data(&mut self, qconn: &mut QConnection) -> QuicResult<()> {
        log::debug!("wait for data");
        if !self.should_fire() {
            log::debug!("should fire");
            // We must have queued a Wait action, so let the timer expire
            sleep_until(self.next_fire_time).await;
            log::debug!("releasing Wait timer");
            return Ok(());
        }

        let actions_complete = self.actions_complete();
        // TODO(evanrittenhouse): clean this up
        let err = std::future::poll_fn(|_| {
            if qconn.is_closed() && actions_complete {
                let peer_error = qconn.peer_error();
                log::info!(
                    "connection closed with error={:?} did_idle_timeout={}",
                    peer_error,
                    qconn.is_timed_out()
                );

                return Poll::Ready(Box::new(
                    H3ConnectionError::ControllerWentAway,
                ));
            } else {
                return Poll::Pending;
            }
        });

        select! {
            rx = self.close_trigger_seen_rx.recv() => {
                if let Some(_) = rx {
                    // TODO: customizable close trigger frames
                    let _ = qconn.close(true, quiche::h3::WireErrorCode::NoError as u64, b"saw all expected frames");
                }

                return Ok(());
            }
            status = err => {
                log::error!("err: {}", status);
                Err(status)
            }
        }
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    fn on_conn_close<M: Metrics>(
        &mut self, qconn: &mut QConnection, _metrics: &M,
        _work_loop_result: &QuicResult<()>,
    ) {
        let _ = self
            .record_tx
            .send(ConnectionRecord::Close(ConnectionCloseDetails::new(&qconn)));

        let _ = self
            .record_tx
            .send(ConnectionRecord::ConnectionStats(qconn.stats()));

        let conn_path_stats = qconn.path_stats().collect::<Vec<PathStats>>();
        let _ = self
            .record_tx
            .send(ConnectionRecord::PathStats(conn_path_stats));
    }
}
