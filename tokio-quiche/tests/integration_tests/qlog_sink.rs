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

//! Integration tests for the tokio-quiche
//! [`ConnectionHook::create_qlog_sink`] path. Drives a real
//! handshake against a server whose `ConnectionHook` installs a
//! recording sink, then asserts the sink received the qlog header
//! and the initial local transport-parameters event.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use boring::ssl::SslContextBuilder;
use futures::stream::StreamExt;
use qlog::events::quic::QuicEventType;
use qlog::events::Event;
use qlog::events::EventType;
use qlog::events::JsonEvent;
use qlog::QlogSeq;
use qlog::QlogSink;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quic::QlogSinkContext;
use tokio_quiche::quic::QuicCommand;
use tokio_quiche::settings::CertificateKind;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;

use crate::fixtures::*;

/// Sink that records the qlog header title and the
/// `EventType` of every native event it receives. JSON events are
/// accepted but not recorded — this test only inspects native
/// quic-domain events.
#[derive(Clone, Default)]
struct RecordingSink {
    inner: Arc<Mutex<RecordingSinkInner>>,
}

#[derive(Default)]
struct RecordingSinkInner {
    header_title: Option<String>,
    event_types: Vec<EventType>,
}

impl QlogSink for RecordingSink {
    fn start_log(&mut self, qlog: &QlogSeq) -> qlog::Result<()> {
        self.inner.lock().unwrap().header_title = qlog.title.clone();
        Ok(())
    }

    fn add_event(&mut self, event: Event) -> qlog::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .event_types
            .push(EventType::from(&event.data));
        Ok(())
    }

    fn add_json_event(&mut self, _event: JsonEvent) -> qlog::Result<()> {
        Ok(())
    }

    fn finish_log(&mut self) -> qlog::Result<()> {
        Ok(())
    }
}

/// `ConnectionHook` that returns a clone of the wrapped
/// `RecordingSink` for every connection. Does not customize TLS.
struct QlogHook {
    sink: RecordingSink,
}

impl ConnectionHook for QlogHook {
    fn create_custom_ssl_context_builder(
        &self, _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        None
    }

    fn create_qlog_sink(
        &self, _ctx: QlogSinkContext<'_>,
    ) -> Option<Box<dyn QlogSink>> {
        Some(Box::new(self.sink.clone()))
    }
}

/// Short sleep used after the request completes but before we
/// inspect the recorded events, so the server-side connection's
/// drop path runs and the streamer's `finish_log` lands. Connection
/// teardown on localhost typically takes <10 ms; 200 ms is generous
/// and keeps the test fast. (Mirrors the convention in
/// `qlog_compression.rs`.)
const DRAIN_DELAY: Duration = Duration::from_millis(200);

#[tokio::test]
async fn hook_installed_sink_receives_initial_event() {
    let sink = RecordingSink::default();
    let hook = Arc::new(QlogHook { sink: sink.clone() });

    let (url, _audit_rx) = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook,
        handle_connection,
    );

    let url = format!("{url}/1");
    let _ = request(url, 1).await.expect("request failed");

    sleep(DRAIN_DELAY).await;

    let recorded = sink.inner.lock().unwrap();
    assert_eq!(recorded.header_title.as_deref(), Some("tokio-quiche qlog"));
    assert!(
        recorded
            .event_types
            .contains(&EventType::QuicEventType(QuicEventType::ParametersSet)),
        "expected ParametersSet event, got {:?}",
        recorded.event_types
    );
}

#[tokio::test]
async fn custom_command_switches_sinks_mid_connection() {
    /// `ConnectionHook` that records whether `create_qlog_sink` was called.
    ///
    /// Returns `None` so the connection starts with no qlog sink at all,
    /// then the test installs a `RecordingSink` via a
    /// `QuicCommand::Custom` closure.
    struct NoSinkHook {
        consulted: Arc<AtomicBool>,
    }

    impl ConnectionHook for NoSinkHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: TlsCertificatePaths<'_>,
        ) -> Option<SslContextBuilder> {
            None
        }

        fn create_qlog_sink(
            &self, _ctx: QlogSinkContext<'_>,
        ) -> Option<Box<dyn QlogSink>> {
            self.consulted.store(true, Ordering::SeqCst);
            None
        }
    }

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr: SocketAddr = socket.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", server_addr.port());

    let quic_settings = QuicSettings::default();

    let consulted = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(NoSinkHook {
        consulted: consulted.clone(),
    });

    let tls_cert_settings = TlsCertificatePaths {
        cert: TEST_CERT_FILE,
        private_key: TEST_KEY_FILE,
        kind: CertificateKind::X509,
    };

    let hooks = Hooks {
        connection_hook: Some(hook),
    };

    let params =
        ConnectionParams::new_server(quic_settings, tls_cert_settings, hooks);

    let mut stream = listen(vec![socket], params, DefaultMetrics)
        .unwrap()
        .remove(0);

    // Channel used to pass the per-connection `cmd_sender` from the
    // server-accept task to the test thread.
    type ServerCmdSender = tokio_quiche::http3::driver::RequestSender<
        tokio_quiche::http3::driver::ServerH3Command,
        QuicCommand,
    >;
    let (sender_tx, mut sender_rx) = mpsc::unbounded_channel::<ServerCmdSender>();

    tokio::spawn(async move {
        let (h3_driver, h3_controller) =
            ServerH3Driver::new(Http3Settings::default());
        let conn = stream
            .next()
            .await
            .expect("listener stream closed")
            .expect("listener error")
            .start(h3_driver);
        let h3_over_quic = ServerH3Connection::new(conn, h3_controller);
        // Hand the cmd_sender back to the test before we hand the
        // controller to `handle_connection`.
        let _ = sender_tx.send(h3_over_quic.h3_controller.cmd_sender());
        handle_connection(h3_over_quic).await;
    });

    // Build the sink we want to install on the live connection. Keep a
    // shared handle so the test thread can inspect what it recorded.
    let recording = RecordingSink::default();
    let recording_state = recording.inner.clone();

    // Drive the client in the background. We send the `Custom` command
    // as soon as the per-connection `cmd_sender` becomes available,
    // then await the request.
    let url_for_request = format!("{url}/1");
    let req_handle =
        tokio::spawn(async move { request(url_for_request, 1).await });

    // Wait for the accept loop to publish the per-connection cmd_sender.
    let cmd_sender =
        tokio::time::timeout(Duration::from_secs(2), sender_rx.recv())
            .await
            .expect("timed out waiting for connection")
            .expect("connection accept loop exited");

    let sink_for_cmd: Box<dyn QlogSink> = Box::new(recording.clone());
    cmd_sender
        .send(QuicCommand::Custom(Box::new(move |qconn| {
            qconn.set_qlog_sink_with_level(
                sink_for_cmd,
                "switched".to_string(),
                "switched mid-connection".to_string(),
                tokio_quiche::quiche::QlogLevel::Base,
            );
        })))
        .expect("send Custom command");

    let _ = req_handle.await.expect("request task panicked");

    sleep(DRAIN_DELAY).await;

    assert!(
        consulted.load(Ordering::SeqCst),
        "ConnectionHook::create_qlog_sink should have been consulted on accept"
    );

    let recorded = recording_state.lock().unwrap();
    assert_eq!(
        recorded.header_title.as_deref(),
        Some("switched"),
        "qlog header should reflect the title set via QuicCommand::Custom"
    );
    assert!(
        !recorded.event_types.is_empty(),
        "expected at least one event after sink swap"
    );
}

#[tokio::test]
async fn qlog_dir_still_writes_file_without_hook_sink() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut quic_settings = QuicSettings::default();
    quic_settings.qlog_dir = Some(dir.path().to_string_lossy().into_owned());

    let hook = TestConnectionHook::new();
    let (url, _audit_rx) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        handle_connection,
    );

    let url = format!("{url}/1");
    let _ = request(url, 1).await.expect("request failed");

    sleep(DRAIN_DELAY).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("qlog dir readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected qlog file under {:?}, got {entries:?}",
        dir.path()
    );
}
