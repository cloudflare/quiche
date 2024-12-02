use h3i::actions::h3::Action;
use h3i::client::sync_client;
use h3i::config::Config;
use quiche::h3::frame::Frame;
use quiche::h3::Header;
use quiche::h3::NameValue;

fn main() {
    let config = Config::new()
        .with_host_port("blog.cloudflare.com".to_string())
        .with_idle_timeout(2000)
        .build()
        .unwrap();

    let headers = vec![
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", "blog.cloudflare.com".as_bytes()),
        Header::new(b":path", b"/"),
        // We say that we're going to send a body with 5 bytes...
        Header::new(b"content-length", b"5"),
    ];

    let header_block = encode_header_block(&headers).unwrap();

    let actions = vec![
        Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: false,
            headers,
            frame: Frame::Headers { header_block },
        },
        Action::SendFrame {
            stream_id: 0,
            fin_stream: true,
            frame: Frame::Data {
                // ...but, in actuality, we only send 4 bytes. This should yield a
                // 400 Bad Request response from an RFC-compliant
                // server: https://datatracker.ietf.org/doc/html/rfc9114#section-4.1.2-3
                payload: b"test".to_vec(),
            },
        },
    ];

    let summary =
        sync_client::connect(config, &actions).expect("connection failed");

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
