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
use boring::ssl::BoxSelectCertFinish;
use boring::ssl::ClientHello;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslFiletype;
use boring::ssl::SslMethod;
use h3i::client::ClientError;
use h3i_fixtures::received_status_code_on_stream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::task::yield_now;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::settings::TlsCertificatePaths;

#[tokio::test]
async fn test_hello_world_async_callbacks() {
    // TODO: migrate this to rxtx-h3, copied from examples/client as a simple
    // Hello World to sanity check that the client builder works.

    struct TestAsyncCallbackConnectionHook {
        was_called: Arc<AtomicBool>,
    }

    impl ConnectionHook for TestAsyncCallbackConnectionHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: TlsCertificatePaths<'_>,
        ) -> Option<SslContextBuilder> {
            let mut ssl_ctx_builder =
                SslContextBuilder::new(SslMethod::tls()).ok()?;
            ssl_ctx_builder.set_async_select_certificate_callback(|_| {
                Ok(Box::pin(async {
                    yield_now().await;
                    Ok(Box::new(|_: ClientHello<'_>| Ok(()))
                        as BoxSelectCertFinish)
                }))
            });

            ssl_ctx_builder
                .set_private_key_file(TEST_KEY_FILE, SslFiletype::PEM)
                .unwrap();

            ssl_ctx_builder
                .set_certificate_chain_file(TEST_CERT_FILE)
                .unwrap();

            self.was_called.store(true, Ordering::SeqCst);

            Some(ssl_ctx_builder)
        }
    }

    let hook = Arc::new(TestAsyncCallbackConnectionHook {
        was_called: Arc::new(AtomicBool::new(false)),
    });
    let url = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );

    let url = format!("{url}/1");
    let summary = h3i_fixtures::request(&url, 1)
        .await
        .expect("request failed");

    assert!(received_status_code_on_stream(&summary, 0, 200));
    assert!(hook.was_called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_async_callbacks_fail_after_initial_send() {
    struct TestAsyncCallbackConnectionHook {}

    impl ConnectionHook for TestAsyncCallbackConnectionHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: TlsCertificatePaths<'_>,
        ) -> Option<SslContextBuilder> {
            let mut ssl_ctx_builder =
                SslContextBuilder::new(SslMethod::tls()).ok()?;
            ssl_ctx_builder.set_async_select_certificate_callback(|_| {
                Ok(Box::pin(async {
                    // Async callbacks in tokio quiche are driven by calls to
                    // quiche's `send` and `recv` methods.
                    // `send` and `recv` will call SSL_do_handshake once
                    // per invocation. As such, at least 3 successful invocations
                    // to `send` and `recv` are needed to
                    // trigger a handshake failure in the `send`
                    // invocation that stems from the `wait_for_data_or_handshake`
                    // future in the select branch.
                    yield_now().await;
                    yield_now().await;
                    yield_now().await;
                    Err(boring::ssl::AsyncSelectCertError)
                }))
            });

            ssl_ctx_builder
                .set_private_key_file(TEST_KEY_FILE, SslFiletype::PEM)
                .unwrap();

            ssl_ctx_builder
                .set_certificate_chain_file(TEST_CERT_FILE)
                .unwrap();

            Some(ssl_ctx_builder)
        }
    }

    let hook = Arc::new(TestAsyncCallbackConnectionHook {});
    let url = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );

    let url = format!("{url}/1");
    let client_res = h3i_fixtures::request(&url, 1).await;
    assert!(matches!(client_res, Err(ClientError::HandshakeFail)));
}

#[tokio::test(flavor = "multi_thread")]
// #[cfg(target_os = "linux")]
async fn test_handshake_future_cancellation_is_a_problem() {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::SndBuf;
    use std::os::fd::AsFd;
    use tokio::task::JoinSet;

    const NUM_HANDSHAKES: u16 = 500;

    struct TestAsyncCallbackConnectionHook {}

    impl ConnectionHook for TestAsyncCallbackConnectionHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: TlsCertificatePaths<'_>,
        ) -> Option<SslContextBuilder> {
            let mut ssl_ctx_builder =
                SslContextBuilder::new(SslMethod::tls()).ok()?;
            ssl_ctx_builder.set_async_select_certificate_callback(|_| {
                Ok(Box::pin(async {
                    // Sleep during the callback. This should mean we end up waiting in the
                    // wait_for_data stage, which we then cancel by manually sending a packet with
                    // the client Quiche connection.
                    // tokio::task::yield_now().await;

                    // Allow the handshake to progress
                    Ok(Box::new(|_: ClientHello<'_>| Ok(()))
                        as BoxSelectCertFinish)
                }))
            });

            ssl_ctx_builder
                .set_private_key_file(TEST_KEY_FILE, SslFiletype::PEM)
                .unwrap();

            ssl_ctx_builder
                .set_certificate_chain_file(TEST_CERT_FILE)
                .unwrap();

            Some(ssl_ctx_builder)
        }
    }

    // Shrink the socket buffer so that it can only hold one packet. This will
    // force congestion on the listening socket.
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    setsockopt(&socket.as_fd(), SndBuf, &1200)
        .expect("can't set sndbuf on UDP socket");

    let hook = Arc::new(TestAsyncCallbackConnectionHook {});
    let url = start_server_with_socket_and_settings(
        socket,
        QuicSettings::default(),
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );

    let mut set = JoinSet::new();

    // The socket's send buffer can only fit one packet, so spawning 100 connections should cause
    // congestion and cause one of the handshakes to fail.
    for _ in 0..NUM_HANDSHAKES {
        let clone = url.clone();
        set.spawn(async move { h3i_fixtures::request(&clone, 1).await });
    }

    let results = set.join_all().await;
    let errors: Vec<_> = results
        .iter()
        .filter(|r| matches!(r, Err(ClientError::HandshakeFail)))
        .collect();
    let n_errors = errors.len();

    assert_eq!(n_errors, 0, "{} handshakes failed", n_errors,);
}
