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

use crate::integration_tests::h3i_fixtures;
use crate::integration_tests::start_server_with_settings;
use crate::integration_tests::Http3Settings;
use crate::integration_tests::QuicSettings;
use crate::integration_tests::TestConnectionHook;
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
use std::sync::Arc;
use std::sync::Mutex;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
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
    let url = start_server_with_settings(
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
            assert_eq!(context.did_recv_early_data_request, false);
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
            assert_eq!(context.did_recv_early_data_request, true);
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
                ServerH3Event::Core(event) => match event {
                    H3Event::ConnectionShutdown(_) => break,

                    _ => (),
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
                        let host = str::from_utf8(authority.value())
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

                    send.send(OutboundFrame::Body(
                        BufFactory::get_empty_buf(),
                        true,
                    ))
                    .await
                    .unwrap();
                },
            }
        }
    }
}
