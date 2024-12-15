use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::client::sync_client;
use h3i::config::Config;
use quiche::h3::frame::Frame;
use quiche::h3::Header;
use quiche::h3::NameValue;

/// The QUIC stream to send the frames on. See
/// https://datatracker.ietf.org/doc/html/rfc9000#name-streams and
/// https://datatracker.ietf.org/doc/html/rfc9114#request-streams for more.
const STREAM_ID: u64 = 0;

/// Send a request with a Content-Length header that specifies 5 bytes, but a
/// body that is only 4 bytes long. This verifies https://datatracker.ietf.org/doc/html/rfc9114#section-4.1.2-3 for
/// cloudflare-quic.com.
fn main() {
    let config = Config::new()
        .with_host_port("cloudflare-quic.com".to_string())
        .with_idle_timeout(2000)
        .build()
        .unwrap();

    let headers = vec![
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"cloudflare-quic.com"),
        Header::new(b":path", b"/"),
        // We say that we're going to send a body with 5 bytes...
        Header::new(b"content-length", b"5"),
    ];

    let header_block = encode_header_block(&headers).unwrap();

    let actions = vec![
        Action::SendHeadersFrame {
            stream_id: STREAM_ID,
            fin_stream: false,
            headers,
            frame: Frame::Headers { header_block },
        },
        Action::SendFrame {
            stream_id: STREAM_ID,
            fin_stream: true,
            frame: Frame::Data {
                // ...but, in actuality, we only send 4 bytes. This should yield a
                // 400 Bad Request response from an RFC-compliant
                // server: https://datatracker.ietf.org/doc/html/rfc9114#section-4.1.2-3
                payload: b"test".to_vec(),
            },
        },
        Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id: STREAM_ID,
                event_type: StreamEventType::Headers,
            }),
        },
        Action::ConnectionClose {
            error: quiche::ConnectionError {
                is_app: true,
                error_code: quiche::h3::WireErrorCode::NoError as u64,
                reason: vec![],
            },
        },
    ];

    // This example doesn't use close trigger frames, since we manually close the
    // connection upon receiving a HEADERS frame on stream 0.
    let close_trigger_frames = None;

    let summary = sync_client::connect(config, &actions, close_trigger_frames)
        .expect("connection failed");

    println!(
        "=== received connection summary! ===\n\n{}",
        serde_json::to_string_pretty(&summary).unwrap_or_else(|e| e.to_string())
    );
}

// SendHeadersFrame requires a QPACK-encoded header block. h3i provides a
// `send_headers_frame` helper function to abstract this, but for clarity, we do
// it here.
fn encode_header_block(
    headers: &[quiche::h3::Header],
) -> std::result::Result<Vec<u8>, String> {
    let mut encoder = quiche::h3::qpack::Encoder::new();

    let headers_len = headers
        .iter()
        .fold(0, |acc, h| acc + h.value().len() + h.name().len() + 32);

    let mut header_block = vec![0; headers_len];
    let len = encoder
        .encode(headers, &mut header_block)
        .map_err(|_| "Internal Error")?;

    header_block.truncate(len);

    Ok(header_block)
}
