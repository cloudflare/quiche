// Copyright (C) 2026, Cloudflare, Inc.
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
use parking_lot::Mutex;
use rstest::rstest;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

use h3i::client::connection_summary::ConnectionSummary;
use h3i::frame::H3iFrame;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::quic::QuicCommand;
use tokio_quiche::quic::QuicConnectionStats;
use tokio_quiche::quiche::h3::Header;

// A response that slowly trickles to the client will always be
// app-limited.  The connection should not exit the BBR startup phase
// since has_bandwidth_growth ignores app-limited rounds.
#[rstest]
#[case::cubic("cubic", false)]
#[case::bbr2_app_limited_broken("bbr2", false)]
#[case::bbr2_app_limited_fixed("bbr2", true)]
#[tokio::test]
async fn test_app_limited_slow_upstream(
    #[case] cc_algorithm_name: &str, #[case] enable_bbr_app_limited_fix: bool,
) {
    let hook = TestConnectionHook::new();

    // The size of the response to trickle at 1 byte / msec.
    let response_size = 2000;

    let server_path_stats: Arc<Mutex<Option<quiche::PathStats>>> =
        Default::default();
    let server_path_stats_clone = server_path_stats.clone();
    let stats_notify: Arc<Notify> = Arc::new(Notify::new());
    let stats_notify_clone = stats_notify.clone();

    let capture_stats = Box::new(move |stats: QuicConnectionStats| {
        *server_path_stats_clone.lock() = stats.path_stats.clone();
        stats_notify_clone.notify_one();
    });

    let mut quic_settings = QuicSettings::default();
    quic_settings.cc_algorithm = cc_algorithm_name.to_string();
    quic_settings.enable_bbr_app_limited_fix = enable_bbr_app_limited_fix;

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        move |mut h3_conn| {
            let capture_stats = capture_stats.clone();
            async move {
                let cmd_sender = h3_conn.h3_controller.cmd_sender();
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
                            let IncomingH3Headers { mut send, .. } =
                                incoming_headers;

                            // Send additional headers.
                            send.send(OutboundFrame::Headers(
                                vec![Header::new(b":status", b"200")],
                                None,
                            ))
                            .await
                            .unwrap();

                            for _ in 0..response_size {
                                send.send(OutboundFrame::Body(
                                    BufFactory::buf_from_slice(&[23; 1]),
                                    false,
                                ))
                                .await
                                .unwrap();
                                tokio::time::sleep(Duration::from_millis(1))
                                    .await;
                            }

                            // Work around: send the stats gathering command
                            // before the fin to guarantee that the command will
                            // be accepted.
                            cmd_sender
                                .send(QuicCommand::ConnectionStats(
                                    capture_stats.clone(),
                                ))
                                .expect("driver is gone?");

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
            }
        },
    );

    let summary = h3i_fixtures::request(&url, 1)
        .await
        .expect("request failed");

    let mut headers = summary.stream_map.headers_on_stream(0).into_iter();

    assert_eq!(
        headers.next().expect("headers").status_code(),
        Some(&Vec::from("200".as_bytes()))
    );
    assert!(headers.next().is_none());

    let frame_bytes = body_bytes(&summary, 0);
    assert_eq!(frame_bytes, response_size);

    stats_notify.notified().await;

    // BBR shouldn't have exited startup because the full workflow was app-limited
    // and there was no loss.
    let server_path_stats = server_path_stats.lock().clone().unwrap();
    assert_eq!(server_path_stats.lost, 0);
    if cc_algorithm_name == "cubic" || enable_bbr_app_limited_fix {
        assert_eq!(server_path_stats.startup_exit, None);
    } else {
        // BBR incorrectly exits startup when enable_bbr_app_limited_fix is not
        // enabled.
        assert_ne!(server_path_stats.startup_exit, None);
    }
}

fn body_bytes(summary: &ConnectionSummary, stream_id: u64) -> usize {
    summary
        .stream_map
        .stream(stream_id)
        .into_iter()
        .map(|h3i_frame| {
            if let H3iFrame::QuicheH3(quiche::h3::frame::Frame::Data {
                payload,
            }) = h3i_frame
            {
                payload.len()
            } else {
                0
            }
        })
        .sum::<usize>()
}
