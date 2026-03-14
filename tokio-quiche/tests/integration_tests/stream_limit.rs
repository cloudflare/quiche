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

use std::sync::Arc;
use std::sync::Mutex;

use crate::fixtures::*;
use h3i_fixtures::default_headers;
use h3i_fixtures::h3i_config;
use h3i_fixtures::received_status_code_on_stream;
use h3i_fixtures::summarize_connection;
use tokio::sync::oneshot;
use tokio_quiche::quic::QuicConnectionStats;

use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::RequiredStreamsQuota;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;

/// The server advertises a limit of 2 concurrent bidirectional streams.
/// The client opens those 2 streams successfully, then attempts a third
/// using [`Action::StreamLimitReached`], which asserts that
/// [`quiche::Error::StreamLimit`] is returned. Sending
/// `STREAMS_BLOCKED` is enabled on the client so the server's
/// `streams_blocked_bidi_recv_count` stat is incremented.
#[tokio::test]
async fn test_bidi_stream_limit_reached() -> QuicResult<()> {
    const MAX_STREAMS: u64 = 2;

    let mut quic_settings = QuicSettings::default();
    quic_settings.initial_max_streams_bidi = MAX_STREAMS;

    let hook = TestConnectionHook::new();
    let (server_stats_tx, server_stats_rx) =
        oneshot::channel::<Arc<Mutex<QuicConnectionStats>>>();
    let server_stats_tx = Arc::new(Mutex::new(Some(server_stats_tx)));
    let (url, _audit_stats_rx) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        move |connection: ServerH3Connection| {
            let stats_handle = Arc::clone(connection.stats());
            let tx = Arc::clone(&server_stats_tx);
            async move {
                handle_connection(connection).await;
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send(stats_handle);
                }
            }
        },
    );

    // Build a config that enables STREAMS_BLOCKED frames so the server
    // increments its streams_blocked_bidi_recv_count stat.
    let h3i = h3i_config(&url).with_send_streams_blocked(true);

    let mut actions = vec![];

    // Open the two streams the server allows and wait for their responses.
    for i in 0..MAX_STREAMS {
        let stream_id = i * 4;
        actions.push(send_headers_frame(stream_id, true, default_headers()));
    }

    // Attempt to open a third stream. The server only allows MAX_STREAMS
    // concurrent bidirectional streams, so stream_send must return
    // Err(StreamLimit). The action logs an error if it does not.
    let blocked_stream_id = MAX_STREAMS * 4;
    actions.push(Action::StreamLimitReached {
        stream_id: blocked_stream_id,
    });
    actions.push(Action::FlushPackets);
    // Wait until the server has processed the responses for streams 0 and 4,
    // collected both streams (requiring ACKs from the client), and sent a
    // MAX_STREAMS_BIDI frame that the client has received and applied.
    // peer_streams_left_bidi >= 1 is only true after all of that has happened.
    actions.push(Action::Wait {
        wait_type: WaitType::CanOpenNumStreams(RequiredStreamsQuota {
            num: 1,
            bidi: true,
        }),
    });
    // Attempt to create the stream that previously blocked. It should succeed
    // since the server sent a MAX_STREAMS update after streams 0 and 4 closed.
    actions.push(send_headers_frame(
        blocked_stream_id,
        true,
        default_headers(),
    ));
    actions.push(Action::FlushPackets);
    // Wait for all streams to finish.
    for i in 0..(MAX_STREAMS + 1) {
        let stream_id = i * 4;
        actions.push(Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id,
                event_type: StreamEventType::Finished,
            }),
        });
    }
    actions.push(Action::ConnectionClose {
        error: quiche::ConnectionError {
            is_app: true,
            error_code: quiche::WireErrorCode::NoError as _,
            reason: Vec::new(),
        },
    });

    let summary = summarize_connection(h3i, actions).await;

    // All requests should have returned 200 responses, including the retried
    // blocked_stream_id (stream 8 succeeds on retry after the server sends a
    // MAX_STREAMS update once streams 0 and 4 complete).
    for i in 0..(MAX_STREAMS + 1) {
        assert!(
            received_status_code_on_stream(&summary, i * 4, 200),
            "stream {} should have received a 200 response",
            i * 4,
        );
    }

    // The client sent STREAMS_BLOCKED because we enabled
    // send_streams_blocked. Retrieve the server-side quiche::Stats and verify
    // that the server received exactly one STREAMS_BLOCKED (bidi) frame.
    let server_stats_handle = server_stats_rx
        .await
        .expect("server should have sent its stats handle");
    let server_stats = server_stats_handle.lock().unwrap();

    assert_eq!(
        server_stats.stats.streams_blocked_bidi_recv_count, 1,
        "server should have received exactly one STREAMS_BLOCKED (bidi) frame",
    );

    Ok(())
}
