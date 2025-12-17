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

use crate::fixtures::*;

use futures::SinkExt;

use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::CustomCallback;
use h3i::quiche::ConnectionError;
use h3i::quiche::WireErrorCode;
use h3i_fixtures::h3i_config;
use h3i_fixtures::url_headers;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::http3::H3AuditStats;
use tokio_quiche::quiche::h3::Header;
use url::Url;

#[tokio::test]
async fn test_additional_headers() {
    let hook = TestConnectionHook::new();

    let url = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook,
        move |mut h3_conn| async move {
            let event_rx = h3_conn.h3_controller.event_receiver_mut();

            while let Some(event) = event_rx.recv().await {
                match event {
                    ServerH3Event::Core(event) => match event {
                        H3Event::ConnectionShutdown(_) => break,

                        _ => (),
                    },

                    ServerH3Event::Headers {
                        incoming_headers, ..
                    } => {
                        let IncomingH3Headers { mut send, .. } = incoming_headers;

                        // Send initial headers.
                        send.send(OutboundFrame::Headers(
                            vec![Header::new(b":status", b"103")],
                            None,
                        ))
                        .await
                        .unwrap();

                        // Delay sending additional headers to the next cycle
                        // just to make sure things work properly if the frames
                        // aren't sent back to back.
                        tokio::task::yield_now().await;

                        // Send additional headers.
                        send.send(OutboundFrame::Headers(
                            vec![Header::new(b":status", b"200")],
                            None,
                        ))
                        .await
                        .unwrap();

                        // Send fin
                        send.send(OutboundFrame::Body(
                            BufFactory::get_empty_buf(),
                            true,
                        ))
                        .await
                        .unwrap();
                    },
                }
            }
        },
    );

    let summary = h3i_fixtures::request(&url, 1)
        .await
        .expect("request failed");

    let mut headers = summary.stream_map.headers_on_stream(0).into_iter();

    assert_eq!(
        headers.next().expect("initial headers").status_code(),
        Some(&Vec::from("103".as_bytes()))
    );
    assert_eq!(
        headers.next().expect("additional headers").status_code(),
        Some(&Vec::from("200".as_bytes()))
    );
    assert!(headers.next().is_none());
}

#[tokio::test]
async fn test_headers_flush_duration_updated_on_connection_drop() {
    let hook = TestConnectionHook::new();

    let audit_stats: Arc<RwLock<Option<Arc<H3AuditStats>>>> =
        Arc::new(RwLock::new(None));
    let clone = Arc::clone(&audit_stats);

    let url = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook,
        move |mut h3_conn| {
            let clone = clone.clone();
            async move {
                let event_rx = h3_conn.h3_controller.event_receiver_mut();

                while let Some(event) = event_rx.recv().await {
                    match event {
                        ServerH3Event::Core(event) => match event {
                            H3Event::ConnectionShutdown(_) => break,

                            _ => (),
                        },

                        ServerH3Event::Headers {
                            incoming_headers, ..
                        } => {
                            let IncomingH3Headers {
                                mut send,
                                h3_audit_stats,
                                ..
                            } = incoming_headers;
                            *clone.write().unwrap() = Some(h3_audit_stats);

                            // Send headers that don't fit in the congestion
                            // window and will
                            // block the connection.
                            send.send(OutboundFrame::Headers(
                                vec![
                                    Header::new(b":status", b"200"),
                                    Header::new(b"large", &b"a".repeat(30_000)),
                                ],
                                None,
                            ))
                            .await
                            .unwrap();
                        },
                    }
                }
            }
        },
    );

    let h3i = h3i_config(&url);
    let url = Url::parse(&url).expect("h3i request URL is invalid");
    let headers = url_headers(&url);

    let wait_until_headers_pending_flush = CustomCallback::new(Arc::new({
        let audit_stats = Arc::clone(&audit_stats);

        move || {
            let timeout = Duration::from_secs(5);
            let start = Instant::now();
            loop {
                if let Some(audit_stats) = audit_stats.read().unwrap().clone() {
                    if audit_stats.headers_pending_flush() {
                        // Done!
                        break;
                    }
                }

                assert!(Instant::now() - start < timeout, "timeout");
                sleep(Duration::from_millis(1));
            }
        }
    }));

    // Run actions:
    // 1. Send a request
    // 2. Wait for the server to attempt to send headers that are too large.
    // 3. Close the client connection to trigger implicit stream shutdown at the
    //    server.
    let actions = Vec::from([
        send_headers_frame(0, true, headers.clone()),
        Action::FlushPackets,
        Action::RunCallback {
            cb: wait_until_headers_pending_flush,
        },
        Action::ConnectionClose {
            error: ConnectionError {
                is_app: true,
                error_code: WireErrorCode::NoError as _,
                reason: Vec::new(),
            },
        },
    ]);

    let summary = tokio::task::spawn_blocking(move || {
        h3i::client::sync_client::connect(h3i, actions, None)
    })
    .await
    .unwrap()
    .unwrap();

    // Verify that the h3i client executed the full action list and the client
    // connection did not time out.
    assert!(!summary.conn_close_details.timed_out);
    assert!(summary.conn_close_details.local_error().is_some());
    assert_eq!(summary.conn_close_details.peer_error(), None);

    let mut headers = summary.stream_map.headers_on_stream(0).into_iter();
    assert!(headers.next().is_none());

    let audit_stats = audit_stats.read().unwrap().clone().unwrap();
    assert!(audit_stats.headers_pending_flush());
    // Verify that headers_flush_duration is updated on connection drop.
    assert!(audit_stats.headers_flush_duration() > Duration::ZERO);
}
