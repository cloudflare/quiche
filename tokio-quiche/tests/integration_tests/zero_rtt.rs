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

use crate::integration_tests::extract_host_ipv4;
use crate::integration_tests::h3i_fixtures;
use crate::integration_tests::start_server_with_settings;
use crate::integration_tests::Http3Settings;
use crate::integration_tests::QuicSettings;
use crate::integration_tests::TestConnectionHook;
use datagram_socket::QuicAuditStats;
use foundations::telemetry::with_test_telemetry;
use foundations::telemetry::TestTelemetryContext;
use futures::SinkExt;
use h3i;
use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::client::connection_summary::ConnectionSummary;
use quiche::h3::NameValue;
use quiche::ConnectionError;
use quiche::WireErrorCode;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::metrics::labels::HandshakeError as HandshakeErrorLabel;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::HandshakeError;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::ServerH3Connection;

#[derive(Debug, Default, Clone)]
struct TestContext {
    did_recv_early_data_request: bool,
    requests_handled_count: usize,
    hosts_seen: Vec<String>,
}

#[tokio::test]
async fn handle_0_rtt_request() {
    let context = Arc::new(Mutex::new(TestContext::default()));
    let early_stream_id = 0;
    let stream_id = 4;

    let context_clone = context.clone();
    let mut quic_settings = QuicSettings::default();
    quic_settings.enable_early_data = true;
    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        TestConnectionHook::new(),
        move |h3_conn| helper_server_handler(h3_conn, &context_clone),
    );

    let nst_data = {
        let summary = {
            let h3i_config = h3i_fixtures::h3i_config(&url);
            helper_connect_with_early_data(
                h3i_config,
                None,
                helper_frame_actions(stream_id),
            )
            .await
        };

        {
            let context = context.lock().unwrap();
            assert_eq!(context.hosts_seen.len(), 1);
            assert!(context.hosts_seen.contains(&"test.com".to_string()));
            assert_eq!(context.requests_handled_count, 1);
            assert!(!context.did_recv_early_data_request);
        }

        // Get Session data from this connection to resume the 0-RTT connection.
        summary.conn_close_details.session.unwrap()
    };

    helper_reset_test(&context);

    {
        let early_frame_actions = vec![
            send_headers_frame(
                early_stream_id,
                false,
                h3i_fixtures::default_headers_with_authority("early.test.com"),
            ),
            Action::FlushPackets,
        ];

        let mut h3i_config = h3i_fixtures::h3i_config(&url);
        // Provide session to the client to enable resumption.
        h3i_config.session = Some(nst_data);
        h3i_config.enable_early_data = true;
        let _summary = helper_connect_with_early_data(
            h3i_config,
            Some(early_frame_actions),
            helper_frame_actions(stream_id),
        )
        .await;

        {
            let context = context.lock().unwrap();
            assert_eq!(context.hosts_seen.len(), 2);
            assert_eq!(context.hosts_seen, vec!["early.test.com", "test.com"]);
            assert_eq!(context.requests_handled_count, 2);
            assert!(context.did_recv_early_data_request);
        }
    }
}

pub async fn helper_connect_with_early_data(
    h3i_config: h3i::config::Config, early_actions: Option<Vec<Action>>,
    actions: Vec<Action>,
) -> ConnectionSummary {
    tokio::task::spawn_blocking(move || {
        h3i::client::sync_client::connect_with_early_data(
            h3i_config,
            early_actions,
            actions,
            None,
        )
        .unwrap()
    })
    .await
    .unwrap()
}

fn helper_reset_test(context: &Arc<Mutex<TestContext>>) {
    let mut context = context.lock().unwrap();
    *context = TestContext::default();
}

fn helper_frame_actions(stream_id: u64) -> Vec<Action> {
    vec![
        send_headers_frame(stream_id, true, h3i_fixtures::default_headers()),
        Action::FlushPackets,
        Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id,
                event_type: StreamEventType::Finished,
            }),
        },
        Action::ConnectionClose {
            error: ConnectionError {
                is_app: true,
                error_code: WireErrorCode::NoError as _,
                reason: Vec::new(),
            },
        },
    ]
}

fn helper_server_handler(
    mut h3_conn: ServerH3Connection, context: &Arc<Mutex<TestContext>>,
) -> impl Future<Output = ()> {
    let context = context.clone();

    async move {
        let event_rx = h3_conn.h3_controller.event_receiver_mut();

        while let Some(event) = event_rx.recv().await {
            match event {
                ServerH3Event::Core(event) => {
                    if let H3Event::ConnectionShutdown(_) = event {
                        break;
                    }
                },

                ServerH3Event::Headers {
                    incoming_headers,
                    is_in_early_data,
                    ..
                } => {
                    let IncomingH3Headers {
                        mut send, headers, ..
                    } = incoming_headers;

                    let authority = headers
                        .iter()
                        .find(|v| v.name().eq(":authority".as_bytes()))
                        .unwrap();

                    {
                        let mut context = context.lock().unwrap();
                        context.requests_handled_count += 1;
                        context.did_recv_early_data_request |= *is_in_early_data;
                        let host = std::str::from_utf8(authority.value())
                            .unwrap()
                            .to_string();
                        context.hosts_seen.push(host);
                    }

                    // Send headers.
                    send.send(OutboundFrame::Headers(
                        vec![Header::new(b":status", b"200")],
                        None,
                    ))
                    .await
                    .unwrap();

                    send.send(OutboundFrame::Body(Default::default(), true))
                        .await
                        .unwrap();
                },
            }
        }
    }
}

/// A server accepting 0-RTT early data, with a session to resume with 0-RTT.
struct EarlyDataServer {
    url: String,
    audit_stats_rx: mpsc::UnboundedReceiver<Arc<QuicAuditStats>>,
    /// Set when the server application receives a request in early data,
    /// which proves that the server accepted 0-RTT and started the application
    /// before the handshake completed.
    recv_early_data_request: Arc<AtomicBool>,
    session: Vec<u8>,
}

impl EarlyDataServer {
    async fn start(handshake_timeout: Duration) -> Self {
        let mut quic_settings = QuicSettings::default();
        quic_settings.enable_early_data = true;
        quic_settings.disable_client_ip_validation = true;
        quic_settings.handshake_timeout = Some(handshake_timeout);
        // The client keeps sending packets, so the idle timeout never fires.
        quic_settings.max_idle_timeout = Some(Duration::from_secs(60));

        let recv_early_data_request = Arc::new(AtomicBool::new(false));

        let recv_early_data_request_clone = recv_early_data_request.clone();
        let (url, mut audit_stats_rx) = start_server_with_settings(
            quic_settings,
            Http3Settings::default(),
            TestConnectionHook::new(),
            move |mut h3_conn: ServerH3Connection| {
                let recv_early_data_request =
                    recv_early_data_request_clone.clone();

                async move {
                    // Keep the connection alive until it is closed by the
                    // server.
                    let event_rx = h3_conn.h3_controller.event_receiver_mut();
                    while let Some(event) = event_rx.recv().await {
                        if let ServerH3Event::Headers {
                            is_in_early_data, ..
                        } = event
                        {
                            if *is_in_early_data {
                                recv_early_data_request
                                    .store(true, Ordering::SeqCst);
                            }
                        }
                    }
                }
            },
        );

        // Get a session to resume with 0-RTT.
        let session = {
            let h3i_config = h3i_fixtures::h3i_config(&url);
            let summary = helper_connect_with_early_data(
                h3i_config,
                None,
                helper_frame_actions(4),
            )
            .await;

            summary.conn_close_details.session.unwrap()
        };

        // Wait for the first connection to be fully closed.
        timeout(Duration::from_secs(5), audit_stats_rx.recv())
            .await
            .unwrap()
            .unwrap();

        Self {
            url,
            audit_stats_rx,
            recv_early_data_request,
            session,
        }
    }

    /// Asserts that the connection resumed with 0-RTT was closed by the
    /// handshake timeout, after the application was started.
    fn assert_handshake_timeout(&self, audit_stats: &QuicAuditStats) {
        let close_reason = audit_stats.connection_close_reason();
        let close_reason = close_reason.as_ref().unwrap();
        assert!(matches!(
            close_reason.downcast_ref::<HandshakeError>(),
            Some(HandshakeError::Timeout)
        ));

        assert!(self.recv_early_data_request.load(Ordering::SeqCst));
    }
}

/// A client that resumes a session with 0-RTT, sends a request in early data,
/// and never processes the server's packets, so the handshake never completes.
struct EarlyDataClient {
    socket: std::net::UdpSocket,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    stream_id: u64,
}

impl EarlyDataClient {
    fn connect(server: &EarlyDataServer) -> Self {
        let peer_addr = extract_host_ipv4(&server.url);

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer_addr).unwrap();

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.verify_peer(false);
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.enable_early_data();

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut scid).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);

        let mut conn = quiche::connect(
            Some("test.com"),
            &scid,
            socket.local_addr().unwrap(),
            peer_addr,
            &mut config,
        )
        .unwrap();
        conn.set_session(&server.session).unwrap();

        // Send the Initial flight, after which the client can send 0-RTT data.
        let mut out = [0; 65535];
        let (len, _) = conn.send(&mut out).unwrap();
        socket.send(&out[..len]).unwrap();
        assert!(conn.is_in_early_data());

        let h3_config = quiche::h3::Config::new().unwrap();
        let mut h3_conn =
            quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .unwrap();
        let stream_id = h3_conn
            .send_request(&mut conn, &h3i_fixtures::default_headers(), false)
            .unwrap();

        Self {
            socket,
            conn,
            h3_conn,
            stream_id,
        }
    }

    /// Sends request body data in 0-RTT packets.
    fn send_body(&mut self, body: &[u8]) {
        assert!(self.conn.is_in_early_data());
        let _ =
            self.h3_conn
                .send_body(&mut self.conn, self.stream_id, body, false);

        let mut out = [0; 65535];
        while let Ok((len, _)) = self.conn.send(&mut out) {
            self.socket.send(&out[..len]).unwrap();
        }
    }
}

/// A client that resumes a session with 0-RTT, but never completes the
/// handshake while it keeps sending 0-RTT packets, must still be subject to
/// the handshake timeout, even though the application was already started.
#[with_test_telemetry(tokio::test)]
async fn handshake_timeout_after_0_rtt(cx: TestTelemetryContext) {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

    let mut server = EarlyDataServer::start(HANDSHAKE_TIMEOUT).await;

    // Metrics are global and shared with tests running concurrently, so only
    // check that the counter was incremented.
    let failed_handshake_timeouts = || {
        DefaultMetrics
            .failed_handshakes(HandshakeErrorLabel::Timeout)
            .get()
    };
    let failed_handshake_timeouts_before = failed_handshake_timeouts();

    let mut client = EarlyDataClient::connect(&server);

    let audit_stats = timeout(HANDSHAKE_TIMEOUT * 5, async {
        loop {
            client.send_body(b"a");

            tokio::select! {
                stats = server.audit_stats_rx.recv() => return stats.unwrap(),
                _ = tokio::time::sleep(Duration::from_millis(50)) => (),
            }
        }
    })
    .await
    .expect("connection wasn't closed by the server");

    server.assert_handshake_timeout(&audit_stats);
    assert!(failed_handshake_timeouts() > failed_handshake_timeouts_before);

    // A handshake timeout is an expected outcome, it must not be logged as an
    // error by the application.
    let error_logs: Vec<_> = cx
        .log_records()
        .iter()
        .filter(|record| record.level.as_str() == "ERROR")
        .map(|record| record.message.clone())
        .collect();
    assert!(
        error_logs.is_empty(),
        "unexpected error logs: {error_logs:?}"
    );
}
