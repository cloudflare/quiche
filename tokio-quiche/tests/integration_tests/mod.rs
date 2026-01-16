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
use h3i_fixtures::received_status_code_on_stream;

use foundations::telemetry::with_test_telemetry;
use foundations::telemetry::TestTelemetryContext;
use futures::StreamExt;
use futures_util::future::try_join_all;
use std::time::Duration;
use tokio::time::timeout;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;
use tokio_quiche::InitialQuicConnection;

pub mod async_callbacks;
pub mod connection_close;
pub mod headers;
pub mod migration;
pub mod timeouts;
pub mod zero_rtt;

#[tokio::test]
async fn echo() {
    const CONN_COUNT: usize = 5;

    let req_count = |conn_num| conn_num * 100;
    let (url, hook) = start_server();
    let mut reqs = vec![];

    for i in 1..=CONN_COUNT {
        let url = format!("{url}/{i}");

        reqs.push(request(url, req_count(i) as u64))
    }

    let res = try_join_all(reqs).await.unwrap();
    let res_map = map_responses(res);

    assert_eq!(res_map.len(), CONN_COUNT);

    for i in 1..=CONN_COUNT {
        let resps = res_map.get(&i).unwrap();

        assert_eq!(resps.len(), req_count(i));
    }

    assert!(hook.was_called());
}

#[tokio::test]
async fn e2e() {
    let (url, hook) = start_server();
    let url = format!("{url}/1");

    let res = request(url, 1).await.unwrap();
    let res_map = map_responses(vec![res]);

    assert_eq!(res_map.len(), 1);

    let resps = res_map.get(&1).unwrap();
    assert_eq!(resps.len(), 1);
    assert!(hook.was_called());
}

#[tokio::test]
async fn e2e_client_ip_validation_disabled() {
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_recv_udp_payload_size = 1400;
    quic_settings.max_send_udp_payload_size = 1400;
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));
    quic_settings.disable_client_ip_validation = true;

    let hook = TestConnectionHook::new();

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );
    let url = format!("{url}/1");
    let reqs = vec![request(url, 1)];

    let res = try_join_all(reqs).await.unwrap();
    let res_map = map_responses(res);

    assert_eq!(res_map.len(), 1);

    let resps = res_map.get(&1).unwrap();
    assert_eq!(resps.len(), 1);
    assert!(hook.was_called());
}

#[with_test_telemetry(tokio::test)]
async fn quiche_logs_forwarded_server_side(cx: TestTelemetryContext) {
    let mut quic_settings = QuicSettings::default();
    quic_settings.capture_quiche_logs = true;

    let hook = TestConnectionHook::new();

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        handle_connection,
    );
    let url = format!("{url}/1");
    let reqs = vec![request(url, 1)];

    let res = try_join_all(reqs).await.unwrap();
    let res_map = map_responses(res);

    assert_eq!(res_map.len(), 1);

    // Unfortunately, the Foundations `fields` struct is empty for some reason.
    // This is a bit of a hacky test, but it checks for a string that should
    // come from Quiche's Trace logs
    assert!(cx.log_records().iter().any(|record| (record
        .message
        .contains("rx pkt") ||
        record.message.contains("tx pkt")) &&
        record.level.as_str() == "TRACE"));
}

#[tokio::test]
async fn test_ioworker_state_machine_pause() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", socket.local_addr().unwrap().port());

    let tls_cert_settings = TlsCertificatePaths {
        cert: TEST_CERT_FILE,
        private_key: TEST_KEY_FILE,
        kind: tokio_quiche::settings::CertificateKind::X509,
    };

    let hooks = Hooks {
        connection_hook: Some(TestConnectionHook::new()),
    };

    let params = ConnectionParams::new_server(
        QuicSettings::default(),
        tls_cert_settings,
        hooks,
    );
    let mut stream = listen(vec![socket], params, DefaultMetrics)
        .unwrap()
        .remove(0);

    tokio::spawn(async move {
        loop {
            let (h3_driver, h3_controller) =
                ServerH3Driver::new(Http3Settings::default());
            let conn = stream.next().await.unwrap().unwrap();

            let (quic_connection, worker) =
                conn.handshake(h3_driver).await.expect("handshake failed");

            InitialQuicConnection::resume(worker);

            let h3_over_quic =
                ServerH3Connection::new(quic_connection, h3_controller);
            tokio::spawn(async move {
                handle_connection(h3_over_quic).await;
            });
        }
    });

    let url = format!("{url}/1");
    let summary = timeout(Duration::from_secs(2), h3i_fixtures::request(&url, 1))
        .await
        .expect("request timed out")
        .expect("request failed");

    assert!(received_status_code_on_stream(&summary, 0, 200));
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_so_mark_receieve_data() {
    use datagram_socket::QuicAuditStats;
    use std::sync::Arc;
    use std::sync::RwLock;

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", socket.local_addr().unwrap().port());

    let tls_cert_settings = TlsCertificatePaths {
        cert: TEST_CERT_FILE,
        private_key: TEST_KEY_FILE,
        kind: tokio_quiche::settings::CertificateKind::X509,
    };

    let hooks = Hooks {
        connection_hook: Some(TestConnectionHook::new()),
    };

    let params = ConnectionParams::new_server(
        QuicSettings::default(),
        tls_cert_settings,
        hooks,
    );
    let mut stream = listen(vec![socket], params, DefaultMetrics)
        .unwrap()
        .remove(0);

    let audit_log: Arc<RwLock<Option<Arc<QuicAuditStats>>>> =
        Arc::new(RwLock::new(None));
    let clone = Arc::clone(&audit_log);

    let _ = tokio::spawn(async move {
        let (h3_driver, h3_controller) =
            ServerH3Driver::new(Http3Settings::default());
        let conn = stream.next().await.unwrap().unwrap();

        let quic_connection = conn.start(h3_driver);
        let h3_over_quic =
            ServerH3Connection::new(quic_connection, h3_controller);

        let audit_stats = Arc::clone(h3_over_quic.audit_log_stats());
        *clone.write().unwrap() = Some(audit_stats);
        let _ = tokio::spawn(async move {
            handle_connection(h3_over_quic).await;
        })
        .await;
    });

    let url = format!("{url}/1");
    let summary = timeout(Duration::from_secs(2), h3i_fixtures::request(&url, 1))
        .await
        .expect("request timed out")
        .expect("request failed");

    assert!(received_status_code_on_stream(&summary, 0, 200));

    let audit_log = audit_log.read().unwrap();
    let so_mark_data = audit_log.as_ref().unwrap().initial_so_mark_data();
    // We don't actually set SO_MARK anywhere, so we just want to ensure that the
    // data is `Some`, indicating that we at least received the cmsg from the
    // socket.
    assert_eq!(so_mark_data.unwrap(), &[0, 0, 0, 0]);
}
