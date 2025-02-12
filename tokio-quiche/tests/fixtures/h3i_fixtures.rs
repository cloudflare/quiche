use h3i::actions::h3::{send_headers_frame, Action, StreamEvent, StreamEventType, WaitType};
use h3i::client::connection_summary::ConnectionSummary;
use h3i::client::ClientError;
use h3i::frame::H3iFrame;
use h3i::quiche::h3::{self, Header};
use h3i::quiche::{ConnectionError, WireErrorCode};
use url::Url;

/// Default h3i config, connects to "test.com"
pub fn h3i_config(url: &str) -> h3i::config::Config {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let final_url = url.split('/').next().unwrap_or(url);

    h3i::config::Config::new()
        .with_host_port("test.com".to_string())
        .with_idle_timeout(2000)
        .with_max_streams_bidi(100)
        .with_max_streams_uni(100)
        .with_max_data(1000000)
        .with_max_stream_data_bidi_local(1000000)
        .with_max_stream_data_bidi_remote(1000000)
        .with_max_stream_data_uni(100000)
        .with_connect_to(final_url.to_string())
        .verify_peer(false)
        .build()
        .unwrap()
}

pub fn default_headers() -> Vec<Header> {
    vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"test.com"),
        Header::new(b":path", b"/"),
    ]
}

pub fn url_headers(url: &Url) -> Vec<Header> {
    use url::Position::{AfterQuery, BeforeHost, BeforePath};
    let authority = &url[BeforeHost..BeforePath];
    let path = &url[BeforePath..AfterQuery];

    vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", url.scheme().as_bytes()),
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":path", path.as_bytes()),
    ]
}

pub async fn summarize_connection(
    h3i: h3i::config::Config,
    actions: Vec<Action>,
) -> ConnectionSummary {
    tokio::task::spawn_blocking(move || h3i::client::sync_client::connect(&h3i, &actions).unwrap())
        .await
        .unwrap()
}

pub async fn request(url: &str, count: u64) -> Result<ConnectionSummary, ClientError> {
    let h3i = h3i_config(url);
    let url = Url::parse(url).expect("h3i request URL is invalid");
    let headers = url_headers(&url);

    let mut actions = Vec::new();
    for req in 0..count {
        let stream_id = req * 4;
        actions.push(send_headers_frame(stream_id, true, headers.clone()));
        actions.push(Action::FlushPackets);
        actions.push(Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id,
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

    tokio::task::spawn_blocking(move || h3i::client::sync_client::connect(&h3i, &actions))
        .await
        .unwrap()
}

pub fn received_status_code_on_stream(summary: &ConnectionSummary, stream: u64, code: u16) -> bool {
    summary
        .stream_map
        .headers_on_stream(stream)
        .iter()
        .any(|e| {
            e.status_code()
                .expect("no status code")
                .expect("unparsable status code")
                == code
        })
}

pub fn stream_body(summary: &ConnectionSummary, stream: u64) -> Option<String> {
    let mut has_body = false;
    let body: String = summary
        .stream_map
        .stream(stream)
        .into_iter()
        .filter_map(|f| {
            if let H3iFrame::QuicheH3(h3::frame::Frame::Data { payload }) = f {
                has_body = true;
                return Some(String::from_utf8(payload).expect("response body not UTF-8"));
            }
            None
        })
        .collect();

    has_body.then_some(body)
}
