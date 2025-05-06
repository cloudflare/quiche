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

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(feature = "__rustls"))]
mod boringssl {
    pub(super) use boring::ssl::BoxSelectCertFinish;
    pub(super) use boring::ssl::ClientHello;
    pub(super) use boring::ssl::SslContextBuilder;
    pub(super) use boring::ssl::SslFiletype;
    pub(super) use boring::ssl::SslMethod;
    pub(super) use std::sync::atomic::AtomicBool;
    pub(super) use tokio_quiche::quic::ConnectionHook;
    pub(super) use tokio_quiche::settings::TlsCertificatePaths;
}
#[cfg(not(feature = "__rustls"))]
use self::boringssl::*;

use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::WaitType;
use h3i::quiche::ConnectionError;
use h3i::quiche::{
    self,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_quiche::http3::driver::H3ConnectionError;
use url::Url;

use crate::fixtures::h3i_fixtures::*;
use crate::fixtures::*;

// TODO(erittenhouse): figure out a way to avoid all of this duplication
#[tokio::test]
#[cfg(not(feature = "__rustls"))]
async fn test_handshake_duration_ioworker() {
    use h3i::client::ClientError;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
    struct TestAsyncCallbackConnectionHook {
        was_called: Arc<AtomicBool>,
    }

    impl ConnectionHook for TestAsyncCallbackConnectionHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: TlsCertificatePaths<'_>,
        ) -> Option<SslContextBuilder> {
            let mut ssl_ctx_builder =
                SslContextBuilder::new(SslMethod::tls()).ok()?;
            let cloned_bool = Arc::clone(&self.was_called);

            ssl_ctx_builder.set_async_select_certificate_callback(move |_| {
                cloned_bool.store(true, Ordering::SeqCst);

                Ok(Box::pin(async {
                    // Pause during the handshake. Give some extra time to
                    // (hopefully) avoid flakiness.
                    tokio::time::sleep(HANDSHAKE_TIMEOUT.mul_f32(1.5)).await;
                    Ok(Box::new(|_: ClientHello<'_>| Ok(()))
                        as BoxSelectCertFinish)
                }))
            });

            ssl_ctx_builder
                .set_private_key_file(&TEST_KEY_FILE, SslFiletype::PEM)
                .unwrap();

            ssl_ctx_builder
                .set_certificate_chain_file(&TEST_CERT_FILE)
                .unwrap();

            Some(ssl_ctx_builder)
        }
    }

    let hook = Arc::new(TestAsyncCallbackConnectionHook {
        was_called: Arc::new(AtomicBool::new(false)),
    });

    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));
    quic_settings.handshake_timeout = Some(HANDSHAKE_TIMEOUT);

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings {
            post_accept_timeout: Some(HANDSHAKE_TIMEOUT),
            ..Default::default()
        },
        hook.clone(),
        handle_connection,
    );

    // TODO: migrate to h3i client to assert a CONNECTION_CLOSE was received. This
    // will have to be the sync version so as to isolate the tokio-quiche IO
    // loop.
    //
    // Unfortunately we can't PCAP this test since encryption keys don't seem to
    // get dumped.
    //
    // build() spawns the InboundPacketRouter and sends the Initial, which will
    // kick the handshake off on the server-side. If all goes well, the server
    // will close the connection and the router will time the connection out.
    let url = format!("{url}/1");
    let client_res = h3i_fixtures::request(&url, 1).await;

    assert!(matches!(client_res, Err(ClientError::HandshakeFail)));
    assert!(hook.was_called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_handshake_timeout_with_one_client_flight() {
    let hook = TestConnectionHook::new();

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
    let mut quic_settings = QuicSettings::default();
    quic_settings.handshake_timeout = Some(HANDSHAKE_TIMEOUT);

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );

    let peer_addr = Url::parse(&url)
        .expect("fixture should return a valid URL")
        .socket_addrs(|| None)
        .expect("URL should resolve to a SocketAddr")[0];

    let mut quiche_config = quiche::Config::new(1).unwrap();
    quiche_config.verify_peer(false);
    quiche_config.set_application_protos(&[b"h3"]).unwrap();
    quiche_config.set_max_recv_udp_payload_size(1350);
    quiche_config.set_max_send_udp_payload_size(1350);

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.connect(peer_addr).await.unwrap();

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();
    let mut quiche_conn = quiche::connect(
        Some("test.com"),
        &scid,
        local_addr,
        peer_addr,
        &mut quiche_config,
    )
    .unwrap();

    // Send first Initial packet
    let mut out = [0; 65535];
    let (write, _) = quiche_conn.send(&mut out).expect("initial send failed");
    socket.send(&out[..write]).await.unwrap();

    // Receive Retry packet
    let (len, from) = socket.recv_from(&mut out).await.unwrap();
    let recv_info = quiche::RecvInfo {
        from,
        to: socket.local_addr().unwrap(),
    };
    let _ = quiche_conn.recv(&mut out[..len], recv_info);

    // Send second Initial packet, which will spawn the TQ Handshake IOW
    let (written, _) = quiche_conn.send(&mut out).unwrap();
    socket.send(&out[..written]).await.unwrap();

    let err = timeout(
        // Give a small buffer for the handshake timeout to fire
        HANDSHAKE_TIMEOUT.mul_f32(1.5),
        async move {
            loop {
                let (len, from) = socket.recv_from(&mut out).await.unwrap();
                let recv_info = quiche::RecvInfo {
                    from,
                    to: socket.local_addr().unwrap(),
                };
                let _ = quiche_conn.recv(&mut out[..len], recv_info);

                if let Some(e) = quiche_conn.peer_error().cloned() {
                    return e;
                }
            }
        },
    )
    .await;

    assert_eq!(err.unwrap(), ConnectionError {
        is_app: false,
        error_code: quiche::WireErrorCode::ApplicationError as u64,
        reason: vec![]
    });
}

#[tokio::test]
async fn test_post_accept_timeout() {
    const POST_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

    // Absence of async callbacks should render the handshake portion of the
    // post-accept timeout (see test_handshake_duration_ioworker) calculation
    // negligble.
    let hook = TestConnectionHook::new();

    // Track if we've seen any requests over this connection.
    let request_counter = Arc::new(AtomicUsize::new(0));
    let clone = Arc::clone(&request_counter);

    let mut quic_settings = QuicSettings::default();
    // Since this is longer than the H3Driver's post-accept timeout, if
    // the connection fails we know that it's from the
    // post-accept timeout rather than Quiche's idle timeout.
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings {
            post_accept_timeout: Some(POST_ACCEPT_TIMEOUT),
            ..Default::default()
        },
        hook,
        move |mut h3_conn| {
            let counter = Arc::clone(&clone);
            async move {
                let err =
                    serve_connection_details(&mut h3_conn.h3_controller, counter)
                        .await
                        .expect_err("serve_connection didn't return an error");
                let h3_err: &H3ConnectionError = err
                    .downcast_ref()
                    .expect("Didn't receive an H3ConnectionError error");
                assert_eq!(h3_err, &H3ConnectionError::PostAcceptTimeout);
            }
        },
    );

    let h3i_config = h3i_config(&url);
    let actions = vec![Action::Wait {
        wait_type: WaitType::WaitDuration(POST_ACCEPT_TIMEOUT.mul_f32(1.5)),
    }];

    let summary = summarize_connection(h3i_config, actions).await;

    // Since the server's idle timeout is longer than the H3Driver's post-accept
    // timeout, the connection should have closed without any requests being
    // received.
    assert_eq!(request_counter.load(Ordering::SeqCst), 0);

    let err = summary
        .conn_close_details
        .peer_error()
        .expect("no error received");
    assert!(err.is_app);
    assert_eq!(err.error_code, quiche::h3::WireErrorCode::NoError as u64);
}

#[tokio::test]
async fn test_post_accept_timeout_is_reset() {
    const POST_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

    // Absence of async callbacks should render the handshake portion of the
    // post-accept timeout (see test_handshake_duration_ioworker) calculation
    // negligble.
    let hook = TestConnectionHook::new();

    let request_counter = Arc::new(AtomicUsize::new(0));
    let clone = Arc::clone(&request_counter);

    let mut quic_settings = QuicSettings::default();
    // Since this is longer than the H3Driver's post-accept timeout, if
    // the connection fails we know that it's from the
    // post-accept timeout rather than Quiche's idle timeout.
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings {
            post_accept_timeout: Some(POST_ACCEPT_TIMEOUT),
            ..Default::default()
        },
        hook,
        move |mut h3_conn| {
            let counter = Arc::clone(&clone);
            async move {
                serve_connection_details(&mut h3_conn.h3_controller, counter)
                    .await
                    .expect("serve_connection failed");
            }
        },
    );

    let h3i_config = h3i_config(&url);
    let actions = vec![
        // Just to ensure that normal waits don't accidentally trigger the
        // post-accept timeout
        Action::Wait {
            wait_type: WaitType::WaitDuration(POST_ACCEPT_TIMEOUT.mul_f32(0.50)),
        },
        send_headers_frame(0, true, default_headers()),
        Action::FlushPackets,
        // Post-accept timeout should be cancelled, so we can wait an arbitrary
        // period (less than the idle timeout of course) and the
        // post-accept timeout shouldn't fire
        Action::Wait {
            wait_type: WaitType::WaitDuration(POST_ACCEPT_TIMEOUT.mul_f32(1.1)),
        },
        send_headers_frame(4, true, default_headers()),
        Action::FlushPackets,
    ];

    let summary = summarize_connection(h3i_config, actions).await;
    assert!(summary.conn_close_details.no_err());

    for i in [0, 4] {
        assert!(received_status_code_on_stream(&summary, i, 200));
    }

    assert_eq!(request_counter.load(Ordering::SeqCst), 2);
}
