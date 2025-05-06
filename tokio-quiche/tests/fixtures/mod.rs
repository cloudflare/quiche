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

use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::InboundFrame;
use tokio_quiche::http3::driver::InboundFrameStream;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::quiche::h3::NameValue;
use tokio_quiche::quiche::h3::{
    self,
};
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Controller;

use futures::stream::FuturesUnordered;
use futures::Future;
use futures::SinkExt;
use futures::StreamExt;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::select;

// Re-export for convenience
pub use tokio_quiche::http3::settings::Http3Settings;
pub use tokio_quiche::quic::ConnectionShutdownBehaviour;
pub use tokio_quiche::settings::QuicSettings;
pub use tokio_quiche::QuicResult;
pub use tokio_quiche::QuicResultExt;
pub use tokio_quiche::ServerH3Connection;
pub use tokio_quiche::ServerH3Driver;

pub mod h3i_fixtures;

use h3i_fixtures::stream_body;

#[cfg(not(feature = "__rustls"))]
pub const TEST_CERT_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/",
    "../quiche/examples/cert.crt"
);
#[cfg(feature = "__rustls")]
pub const TEST_CERT_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/",
    "../quiche/examples/cert_rustls.crt"
);
pub const TEST_KEY_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/",
    "../quiche/examples/cert.key"
);

pub struct TestConnectionHook {
    was_called: Arc<AtomicBool>,
}

impl TestConnectionHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            was_called: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn was_called(&self) -> bool {
        self.was_called.load(Ordering::SeqCst)
    }
}

impl ConnectionHook for TestConnectionHook {
    #[cfg(not(feature = "__rustls"))]
    fn create_custom_ssl_context_builder(
        &self, _settings: TlsCertificatePaths<'_>,
    ) -> Option<boring::ssl::SslContextBuilder> {
        self.was_called.store(true, Ordering::SeqCst);
        None
    }
}

pub async fn request(
    url: String, count: u64,
) -> QuicResult<HashMap<u64, String>> {
    let summary = h3i_fixtures::request(&url, count)
        .await
        .expect("requests failed");
    let map = (0..count)
        .map(|req| {
            let stream_id = req * 4;
            let body =
                stream_body(&summary, stream_id).expect("missing response body");
            (stream_id, body)
        })
        .collect();
    Ok(map)
}

pub async fn serve_connection_details(
    h3_controller: &mut ServerH3Controller, request_counter: Arc<AtomicUsize>,
) -> QuicResult<()> {
    let event_rx = h3_controller.event_receiver_mut();
    let mut request_futs = FuturesUnordered::new();

    loop {
        select! {
            Some(frame) = event_rx.recv() => {
                let ServerH3Event::Core(frame) = frame;
                match frame {
                    H3Event::IncomingSettings {..} | H3Event::BodyBytesReceived { .. } | H3Event::StreamClosed { .. } => {},
                    H3Event::IncomingHeaders(headers) => {
                        let IncomingH3Headers {
                            stream_id, headers, send, recv, ..
                        } = headers;

                        request_counter.fetch_add(1, Ordering::SeqCst);
                        request_futs.push(handle_forwarded_headers_frame(stream_id, headers, send, recv));
                    }
                    H3Event::ConnectionError(err) => { break Err(err.into()); }
                    H3Event::ConnectionShutdown(Some(err)) => { break Err(err.into()); }
                    _ => unreachable!()
                }
            }
            Some(_) = request_futs.next() => {}
            else => { break Ok(()); }
        }
    }
}

pub async fn handle_connection(mut connection: ServerH3Connection) {
    let _ = serve_connection_details(
        &mut connection.h3_controller,
        Default::default(),
    )
    .await;
}

pub async fn handle_forwarded_headers_frame(
    stream_id: u64, list: Vec<Header>, mut send: OutboundFrameSender,
    mut recv: InboundFrameStream,
) {
    send.send(OutboundFrame::Headers(
        vec![h3::Header::new(b":status", b"200")],
        None,
    ))
    .await
    .unwrap();

    let path = list
        .iter()
        .find_map(|l| (l.name() == b":path").then(|| l.value().to_vec()))
        .unwrap();

    while let Some(frame) = recv.recv().await {
        match frame {
            InboundFrame::Body(_, fin) =>
                if fin {
                    let res = format!(
                        "{stream_id},GET {}|",
                        String::from_utf8(path).unwrap()
                    );
                    send.send(OutboundFrame::body(
                        BufFactory::buf_from_slice(res.as_bytes()),
                        true,
                    ))
                    .await
                    .unwrap();
                    return;
                },
            InboundFrame::Datagram(_) => unreachable!(),
        }
    }
}

pub fn start_server() -> (String, Arc<TestConnectionHook>) {
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_send_udp_payload_size = 1400;
    quic_settings.max_recv_udp_payload_size = 1400;

    let hook = TestConnectionHook::new();

    (
        start_server_with_settings(
            quic_settings,
            Http3Settings::default(),
            hook.clone(),
            handle_connection,
        ),
        hook,
    )
}

pub fn start_server_with_settings<F, Fut>(
    quic_settings: QuicSettings, http3_settings: Http3Settings,
    hook: Arc<impl ConnectionHook + Send + Sync + 'static>, hdl: F,
) -> String
where
    F: Fn(ServerH3Connection) -> Fut + Send + Clone + 'static,
    Fut: Future<Output = ()> + Send,
{
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", socket.local_addr().unwrap().port());

    let tls_cert_settings = TlsCertificatePaths {
        cert: &TEST_CERT_FILE,
        private_key: &TEST_KEY_FILE,
        kind: tokio_quiche::settings::CertificateKind::X509,
    };

    let hooks = Hooks {
        connection_hook: Some(hook),
    };

    let params =
        ConnectionParams::new_server(quic_settings, tls_cert_settings, hooks);
    let mut stream = listen(
        vec![socket],
        params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .unwrap()
    .remove(0);

    tokio::spawn(async move {
        loop {
            let (h3_driver, h3_controller) =
                ServerH3Driver::new(http3_settings.clone());
            let conn = stream.next().await.unwrap().unwrap().start(h3_driver);
            let h3_over_quic = ServerH3Connection::new(conn, h3_controller);

            let hdl = hdl.clone();
            tokio::spawn(async move {
                hdl(h3_over_quic).await;
            });
        }
    });

    url
}

pub fn map_responses(
    responses: Vec<HashMap<u64, String>>,
) -> HashMap<usize, HashSet<usize>> {
    let mut map = HashMap::<_, HashSet<_>>::default();
    let res_info_re =
        Regex::new(r"^(?P<stream_id>\d+),GET /(?P<conn_num>\d+)$").unwrap();

    for resp in responses {
        for (_, content) in resp {
            for res in content.split('|') {
                if res.is_empty() {
                    continue;
                }

                let caps = res_info_re.captures(res).unwrap();
                let conn_num =
                    caps.name("conn_num").unwrap().as_str().parse().unwrap();
                let stream_id =
                    caps.name("stream_id").unwrap().as_str().parse().unwrap();

                map.entry(conn_num).or_default().insert(stream_id);
            }
        }
    }

    map
}
