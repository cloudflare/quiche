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

//! Responsible for creating a [tokio_quiche::quic::QuicheConnection] and
//! yielding I/O to tokio-quiche.

use buffer_pool::ConsumeBuffer;
use buffer_pool::Pooled;
use log;
use quiche::PathStats;
use quiche::Stats;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::sleep_until;
use tokio::time::Instant;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::socket::Socket;
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
use crate::client::MAX_DATAGRAM_SIZE;
use crate::config::Config as H3iConfig;
use crate::frame::H3iFrame;
use crate::quiche;

use super::Client;
use super::ConnectionCloseDetails;
use super::StreamParserMap;

/// Connect to the socket.
pub async fn connect(
    args: &H3iConfig, frame_actions: Vec<Action>,
    close_trigger_frames: Option<CloseTriggerFrames>,
) -> std::result::Result<BuildingConnectionSummary, ClientError> {
    let quic_settings = create_config(args);
    let connection_params =
        ConnectionParams::new_client(quic_settings, None, Hooks::default());

    let ParsedArgs {
        connect_url,
        bind_addr,
        peer_addr,
    } = parse_args(args);

    let socket = tokio::net::UdpSocket::bind(bind_addr).await.unwrap();
    socket.connect(peer_addr).await.unwrap();

    log::info!(
        "connecting to {:} from {:}",
        peer_addr,
        socket.local_addr().unwrap()
    );

    let (h3i, conn_summary_fut) =
        H3iDriver::new(frame_actions, close_trigger_frames);
    match tokio_quiche::quic::connect_with_config(
        Socket::try_from(socket).unwrap(),
        connect_url,
        &connection_params,
        h3i,
    )
    .await
    {
        Ok(_) => Ok(conn_summary_fut),
        Err(_) => Err(ClientError::HandshakeFail),
    }
}

fn create_config(args: &H3iConfig) -> QuicSettings {
    let mut quic_settings = QuicSettings::default();

    quic_settings.verify_peer = args.verify_peer;
    quic_settings.max_idle_timeout =
        Some(Duration::from_millis(args.idle_timeout));
    quic_settings.max_recv_udp_payload_size = MAX_DATAGRAM_SIZE;
    quic_settings.max_send_udp_payload_size = MAX_DATAGRAM_SIZE;
    quic_settings.initial_max_data = 10_000_000;
    quic_settings.initial_max_stream_data_bidi_local =
        args.max_stream_data_bidi_local;
    quic_settings.initial_max_stream_data_bidi_remote =
        args.max_stream_data_bidi_remote;
    quic_settings.initial_max_stream_data_uni = args.max_stream_data_uni;
    quic_settings.initial_max_streams_bidi = args.max_streams_bidi;
    quic_settings.initial_max_streams_uni = args.max_streams_uni;
    quic_settings.disable_active_migration = true;
    quic_settings.active_connection_id_limit = 0;
    quic_settings.max_connection_window = args.max_window;
    quic_settings.max_stream_window = args.max_stream_window;
    quic_settings.grease = false;

    quic_settings.capture_quiche_logs = true;
    quic_settings.keylog_file = std::env::var_os("SSLKEYLOGFILE")
        .and_then(|os_str| os_str.into_string().ok());

    quic_settings
}

/// The [`Future`] used to build a [`ConnectionSummary`].
///
/// At a high level, [`H3iDriver`] will interact with the UDP socket directly,
/// sending and receiving data as necessary. As new data is received, it will
/// send [`ConnectionRecord`]s to this struct, which uses these records to
/// construct the [`ConnectionSummary`].
#[must_use = "must await to get a ConnectionSummary"]
pub struct BuildingConnectionSummary {
    rx: mpsc::UnboundedReceiver<ConnectionRecord>,
    summary: Option<ConnectionSummary>,
    seen_all_close_trigger_frames: Option<oneshot::Sender<()>>,
}

impl BuildingConnectionSummary {
    fn new(
        rx: mpsc::UnboundedReceiver<ConnectionRecord>,
        close_trigger_frames: Option<CloseTriggerFrames>,
        trigger_frame_tx: oneshot::Sender<()>,
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
            // Grab all records received from the current event loop iteration and
            // insert them into the in-progress summary
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
                            let _ = expected_tx.send(());
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
    next_fire_time: Instant,
    waiting_for_responses: WaitingFor,
    record_tx: mpsc::UnboundedSender<ConnectionRecord>,
    stream_parsers: StreamParserMap,
    close_trigger_seen_rx: oneshot::Receiver<()>,
}

impl H3iDriver {
    fn new(
        actions: Vec<Action>, close_trigger_frames: Option<CloseTriggerFrames>,
    ) -> (Self, BuildingConnectionSummary) {
        let (record_tx, record_rx) = mpsc::unbounded_channel();
        let (close_trigger_seen_tx, close_trigger_seen_rx) = oneshot::channel();
        let fut = BuildingConnectionSummary::new(
            record_rx,
            close_trigger_frames,
            close_trigger_seen_tx,
        );

        (
            Self {
                buffer: BufFactory::get_max_buf(),
                actions,
                actions_executed: 0,
                next_fire_time: Instant::now(),
                waiting_for_responses: WaitingFor::default(),
                record_tx,
                stream_parsers: StreamParserMap::default(),
                close_trigger_seen_rx,
            },
            fut,
        )
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
                            "h3i: waiting for responses: {:?}",
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
        &mut self, _qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        log::info!("h3i: HTTP/3 connection established");
        Ok(())
    }

    fn should_act(&self) -> bool {
        // Even if the connection wasn't established, we should still send
        // terminal records to the summary
        true
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        log::trace!("h3i: process_reads");

        // This is executed in process_reads so that work_loop can clear any waits
        // on the current event loop iteration - if it was in process_writes, we
        // could potentially miss waits and hang the client.
        self.register_waits();

        let stream_events = parse_streams(qconn, self);
        for event in stream_events {
            self.waiting_for_responses.remove_wait(event);
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        log::trace!("h3i: process_writes");

        if !self.waiting_for_responses.is_empty() {
            log::debug!(
                "awaiting responses on streams {:?}, skipping further action",
                self.waiting_for_responses
            );

            return Ok(());
        }

        // Re-create the iterator so we can mutably borrow the stream parser map
        let iter = self.actions.clone().into_iter().skip(self.actions_executed);

        for action in iter {
            match action {
                Action::SendFrame { .. } |
                Action::StreamBytes { .. } |
                Action::ResetStream { .. } |
                Action::StopSending { .. } |
                Action::OpenUniStream { .. } |
                Action::ConnectionClose { .. } |
                Action::SendHeadersFrame { .. } => {
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

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        log::trace!("h3i: wait_for_data");

        let waiting = !self.should_fire();
        select! {
            rx = &mut self.close_trigger_seen_rx, if !self.close_trigger_seen_rx.is_terminated() => {
                // NOTE: wait_for_data can be called again after all close triggers have been seen,
                // depending on how long it takes quiche to mark the connection as closed.
                // Therefore we can't re-poll the receiver or we'd panic.
                if rx.is_ok() {
                    // TODO: customizable close trigger frames
                    let _ = qconn.close(true, quiche::h3::WireErrorCode::NoError as u64, b"saw all expected frames");
                }
            }
            _ = sleep_until(self.next_fire_time), if waiting => {
                log::debug!("h3i: releasing wait timer");
            }
            else => {}
        }

        Ok(())
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    fn on_conn_close<M: Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        _work_loop_result: &QuicResult<()>,
    ) {
        let _ = self
            .record_tx
            .send(ConnectionRecord::Close(ConnectionCloseDetails::new(qconn)));

        let _ = self
            .record_tx
            .send(ConnectionRecord::ConnectionStats(qconn.stats()));

        let conn_path_stats = qconn.path_stats().collect::<Vec<PathStats>>();
        let _ = self
            .record_tx
            .send(ConnectionRecord::PathStats(conn_path_stats));
    }
}

pub enum ConnectionRecord {
    StreamedFrame { stream_id: u64, frame: H3iFrame },
    Close(ConnectionCloseDetails),
    PathStats(Vec<PathStats>),
    ConnectionStats(Stats),
}
