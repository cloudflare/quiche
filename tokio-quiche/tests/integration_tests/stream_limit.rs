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
use h3i_fixtures::default_headers;
use h3i_fixtures::h3i_config;
use h3i_fixtures::received_status_code_on_stream;
use h3i_fixtures::summarize_connection;

use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::quiche::ConnectionError;
use h3i::quiche::WireErrorCode;

/// Verify that when the client hits the server-imposed stream limit, the
/// blocked request is automatically retried once a `MAX_STREAMS` update
/// arrives following the completion of a previous request.
///
/// Sequence:
/// 1. Server advertises `initial_max_streams_bidi = 3` so only streams 0, 4,
///    and 8 can be opened immediately.
/// 2. Three requests are sent back-to-back without waiting, then a fourth
///    request (stream 12) is attempted. That fourth `SendHeadersFrame` action
///    returns `quiche::Error::StreamLimit` and is held as a pending retry.
/// 3. The client flushes packets so the three in-flight requests reach the
///    server, then waits for stream 0 to finish. The server processes the
///    request, closes stream 0, reclaims the credit, and sends a
///    `MAX_STREAMS_BIDI(4)` frame back to the client.
/// 4. On the next `check_duration_and_do_actions` call (triggered by the
///    stream-finished event), the pending stream-12 action is retried
///    successfully.
/// 5. All four streams eventually receive a 200 response, and the connection is
///    closed cleanly.
#[tokio::test]
async fn test_stream_limit_retry_after_max_streams_update() -> QuicResult<()> {
    // The server tells the client it may open at most 3 bidi streams initially.
    const INITIAL_STREAMS: u64 = 3;

    let hook = TestConnectionHook::new();
    let mut quic_settings = QuicSettings::default();
    quic_settings.initial_max_streams_bidi = INITIAL_STREAMS;
    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        handle_connection,
    );

    let h3i = h3i_config(&url);

    // Send INITIAL_STREAMS requests without waiting so all slots are consumed
    // simultaneously, then immediately attempt a fourth request that will be
    // blocked by StreamLimit.  After the first stream completes the server
    // recredits one slot via MAX_STREAMS, which unblocks stream 12.
    let last_stream_id = INITIAL_STREAMS * 4;
    let mut actions = vec![];

    for i in 0..INITIAL_STREAMS {
        actions.push(send_headers_frame(i * 4, true, default_headers()));
    }

    // Flush so the server receives all three requests before we block on the
    // fourth.
    actions.push(Action::FlushPackets);

    // This will hit StreamLimit and be deferred until MAX_STREAMS arrives.
    actions.push(send_headers_frame(last_stream_id, true, default_headers()));

    // Wait for the first stream to complete.  The server will send a
    // MAX_STREAMS frame once it reclaims stream 0's credit, which lets h3i
    // retry the deferred stream-12 action.
    actions.push(Action::Wait {
        wait_type: WaitType::StreamEvent(StreamEvent {
            stream_id: 0,
            event_type: StreamEventType::Finished,
        }),
    });

    // Wait for the remaining three streams (4, 8, and the retried 12).
    for i in 1..=INITIAL_STREAMS {
        actions.push(Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id: i * 4,
                event_type: StreamEventType::Finished,
            }),
        });
    }

    actions.push(Action::ConnectionClose {
        error: ConnectionError {
            is_app: true,
            error_code: WireErrorCode::NoError as _,
            reason: Vec::new(),
        },
    });

    let summary = summarize_connection(h3i, actions).await;

    // All four streams must have received a successful response.
    for i in 0..=INITIAL_STREAMS {
        let stream_id = i * 4;
        assert!(
            received_status_code_on_stream(&summary, stream_id, 200),
            "stream {stream_id} did not receive a 200 response",
        );
    }

    // Connection should have closed cleanly with no error.
    assert!(
        summary.conn_close_details.no_err(),
        "expected clean connection close, got: {:?}",
        summary.conn_close_details,
    );

    Ok(())
}
