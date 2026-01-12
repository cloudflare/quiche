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

use std::time::Duration;

use crate::fixtures::*;
use h3i_fixtures::default_headers;
use h3i_fixtures::h3i_config;
use h3i_fixtures::received_status_code_on_stream;
use h3i_fixtures::summarize_connection;

use datagram_socket::QuicAuditStats;
use futures::StreamExt;
use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::quiche;
use h3i::quiche::h3::Header;
use quiche::h3::frame::Frame;
use quiche::h3::frame::DATA_FRAME_TYPE_ID;
use std::sync::Arc;
use std::sync::RwLock;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;
use tokio_quiche::TQError;

#[tokio::test]
async fn test_requests_per_connection_limit() -> QuicResult<()> {
    const MAX_REQS: u64 = 10;

    let hook = TestConnectionHook::new();
    let url = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings {
            max_requests_per_connection: Some(MAX_REQS),
            ..Default::default()
        },
        hook,
        handle_connection,
    );

    let h3i = h3i_config(&url);
    let mut actions = vec![];

    for i in 0..MAX_REQS {
        actions.push(send_headers_frame(i * 4, true, default_headers()));
        actions.push(Action::FlushPackets);
        actions.push(Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id: i * 4,
                event_type: StreamEventType::Headers,
            }),
        });
    }

    // This last action should fail due to request limits on the connection being
    // breached
    actions.push(send_headers_frame(MAX_REQS * 4, true, default_headers()));
    actions.push(Action::FlushPackets);

    let summary = summarize_connection(h3i, actions).await;

    for i in 0..MAX_REQS {
        assert!(
            received_status_code_on_stream(&summary, i * 4, 200),
            "request {i} didn't have a status code OK",
        );
    }
    assert!(summary.stream_map.stream(MAX_REQS * 4).is_empty());

    let error = summary
        .conn_close_details
        .peer_error()
        .expect("no error received");
    assert_eq!(error.error_code, quiche::h3::WireErrorCode::NoError as u64);

    Ok(())
}

#[tokio::test]
async fn test_max_header_list_size_limit() {
    let hook = TestConnectionHook::new();
    let url = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings {
            max_header_list_size: Some(5_000),
            ..Default::default()
        },
        hook,
        handle_connection,
    );

    let h3i = h3i_config(&url);

    let mut small_headers = default_headers();
    small_headers.push(Header::new(b"a", vec![b'0'; 4000].as_slice()));
    let mut big_headers = default_headers();
    big_headers.push(Header::new(b"a", vec![b'0'; 5000].as_slice()));

    let actions = vec![
        send_headers_frame(0, true, small_headers),
        Action::FlushPackets,
        Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id: 0,
                event_type: StreamEventType::Headers,
            }),
        },
        send_headers_frame(4, true, big_headers),
    ];

    let summary = summarize_connection(h3i, actions).await;

    assert!(received_status_code_on_stream(&summary, 0, 200));
    assert!(summary.stream_map.stream(4).is_empty());

    let error = summary
        .conn_close_details
        .peer_error()
        .expect("no error received");
    assert_eq!(
        error.error_code,
        quiche::h3::WireErrorCode::ExcessiveLoad as u64
    );
}

#[tokio::test]
async fn test_no_connection_close_frame_on_idle_timeout() -> QuicResult<()> {
    const IDLE_TIMEOUT: Duration = Duration::from_secs(1);

    let hook = TestConnectionHook::new();

    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(IDLE_TIMEOUT);

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        handle_connection,
    );

    let h3i = h3i_config(&url);
    let actions = vec![Action::Wait {
        wait_type: WaitType::WaitDuration(IDLE_TIMEOUT.mul_f32(1.5)),
    }];

    let summary = summarize_connection(h3i, actions).await;
    assert!(summary.conn_close_details.no_err());

    Ok(())
}

#[tokio::test]
async fn test_tokio_quiche_error_with_additional_context() {
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
    // Start the server.
    let mut stream = listen(
        vec![socket],
        params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .unwrap()
    .remove(0);

    let audit_log: Arc<RwLock<Option<Arc<QuicAuditStats>>>> =
        Arc::new(RwLock::new(None));
    let audit_logs_clone = Arc::clone(&audit_log);

    // Extract Audit logs from the H3 server.
    let _ = tokio::spawn(async move {
        let (h3_driver, h3_controller) = ServerH3Driver::new(Http3Settings {
            ..Default::default()
        });
        let conn = stream.next().await.unwrap().unwrap();

        let quic_connection = conn.start(h3_driver);
        let h3_over_quic =
            ServerH3Connection::new(quic_connection, h3_controller);

        let audit_stats = Arc::clone(h3_over_quic.audit_log_stats());
        *audit_logs_clone.write().unwrap() = Some(audit_stats);
        let _ = tokio::spawn(async move {
            handle_connection(h3_over_quic).await;
        })
        .await;
    });

    let actions = vec![
        Action::SendDatagram { payload: vec![] },
        Action::SendFrame {
            stream_id: 0,
            fin_stream: true,
            frame: Frame::from_bytes(DATA_FRAME_TYPE_ID, 0, &[0]).unwrap(),
        },
    ];
    let url = format!("{url}/1");
    let _summary = summarize_connection(h3i_config(&url), actions).await;

    // Close error is also exposed from the Audit Log.
    let audit_log = audit_log.read().unwrap();
    let connection_close_reason =
        audit_log.as_ref().unwrap().connection_close_reason();

    let tq_error = (*connection_close_reason).as_ref().unwrap();
    let tq_error = tq_error.downcast_ref::<TQError>().unwrap();
    // tokio-quiche specific context
    assert_eq!(
        tq_error.reason(),
        "Error processing packets. Opt: `AOQ::process_reads`"
    );
    assert_eq!(tq_error.handshake_complete(), true);
    assert_eq!(tq_error.did_idle_timeout(), false);
    assert!(tq_error.peer_err().is_none());
    // quiche local_err
    assert_eq!(
        tq_error.local_err().clone().unwrap().reason,
        format!("Unexpected frame type {}", DATA_FRAME_TYPE_ID).as_bytes()
    );
}
