use h3i::actions::h3::Action;
use h3i::actions::h3::ExpectedStreamSendResult;
use h3i::client::sync_client;
use h3i::config::Config;
use h3i::HTTP3_CONTROL_STREAM_TYPE_ID;
use h3i::QPACK_DECODER_STREAM_TYPE_ID;
use h3i::QPACK_ENCODER_STREAM_TYPE_ID;

/// Test that opening too many unidirectional streams correctly triggers a
/// StreamLimit error. Most servers advertise a max_streams_uni of 3, so
/// attempting to open a 4th stream should fail.
fn main() {
    let config = Config::new()
        .with_host_port("cloudflare-quic.com".to_string())
        .with_idle_timeout(2000)
        .build()
        .unwrap();

    // Client-initiated unidirectional stream IDs: 2, 6, 10, 14, ...
    // With max_streams_uni=3 from server, streams 2, 6, 10 should succeed,
    // but stream 14 should fail with StreamLimit.
    let actions = vec![
        Action::OpenUniStream {
            stream_id: 2,
            fin_stream: false,
            stream_type: HTTP3_CONTROL_STREAM_TYPE_ID,
            expected_result: ExpectedStreamSendResult::OkExact(1),
        },
        Action::OpenUniStream {
            stream_id: 6,
            fin_stream: false,
            stream_type: QPACK_ENCODER_STREAM_TYPE_ID,
            expected_result: ExpectedStreamSendResult::OkExact(1),
        },
        Action::OpenUniStream {
            stream_id: 10,
            fin_stream: false,
            stream_type: QPACK_DECODER_STREAM_TYPE_ID,
            expected_result: ExpectedStreamSendResult::OkExact(1),
        },
        // This 4th stream should exceed the server's max_streams_uni limit
        Action::OpenUniStream {
            stream_id: 14,
            fin_stream: false,
            stream_type: 0x10,
            expected_result: ExpectedStreamSendResult::Error(
                h3i::quiche::Error::StreamLimit,
            ),
        },
        Action::ConnectionClose {
            error: h3i::quiche::ConnectionError {
                is_app: true,
                error_code: h3i::quiche::h3::WireErrorCode::NoError as u64,
                reason: vec![],
            },
        },
    ];

    let close_trigger_frames = None;

    let summary = sync_client::connect(config, actions, close_trigger_frames)
        .expect("connection failed");

    println!(
        "=== Stream limit test completed! ===\n\n{}",
        serde_json::to_string_pretty(&summary).unwrap_or_else(|e| e.to_string())
    );
}
