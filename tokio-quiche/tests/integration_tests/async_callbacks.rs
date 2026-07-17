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

use boring::ssl::BoxSelectCertFinish;
use boring::ssl::ClientHello;
use boring::ssl::SslContextBuilder;
use boring::ssl::SslFiletype;
use boring::ssl::SslMethod;
use futures::StreamExt;
use std::future::poll_fn;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::timeout;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::socket::Socket;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;

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
    let (url, _) = start_server_with_settings(
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
    // TODO: migrate this to rxtx-h3, copied from examples/client as a simple
    // Hello World to sanity check that the client builder works.
    use h3i::client::ClientError;

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
    let (url, _) = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );

    let url = format!("{url}/1");
    let client_res = h3i_fixtures::request(&url, 1).await;
    assert!(matches!(client_res, Err(ClientError::HandshakeFail)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_eager_wait_for_data_does_not_starve_handshake() {
    struct TestApplication {
        buffer: [u8; 1500],
        eager_pre_handshake: bool,
        should_act: bool,
        established_tx: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl ApplicationOverQuic for TestApplication {
        fn on_conn_established(
            &mut self, _qconn: &mut QuicheConnection,
            _handshake_info: &tokio_quiche::quic::HandshakeInfo,
        ) -> QuicResult<()> {
            if let Some(established_tx) = self.established_tx.take() {
                let _ = established_tx.send(());
            }

            Ok(())
        }

        fn should_act(&self) -> bool {
            self.should_act
        }

        fn buffer(&mut self) -> &mut [u8] {
            &mut self.buffer
        }

        fn wait_for_data(
            &mut self, qconn: &mut QuicheConnection,
        ) -> impl Future<Output = QuicResult<()>> + Send {
            let should_resolve = self.eager_pre_handshake &&
                !qconn.is_established() &&
                !qconn.is_in_early_data();

            poll_fn(move |_| {
                if should_resolve {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
        }

        fn process_reads(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            Ok(())
        }

        fn process_writes(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            Ok(())
        }
    }

    struct TestAsyncCallbackConnectionHook {
        callback_completed: Arc<AtomicBool>,
    }

    impl ConnectionHook for TestAsyncCallbackConnectionHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: TlsCertificatePaths<'_>,
        ) -> Option<SslContextBuilder> {
            let callback_completed = Arc::clone(&self.callback_completed);
            let mut ssl_ctx_builder =
                SslContextBuilder::new(SslMethod::tls()).ok()?;
            ssl_ctx_builder.set_async_select_certificate_callback(move |_| {
                let callback_completed = Arc::clone(&callback_completed);

                Ok(Box::pin(async move {
                    yield_now().await;
                    callback_completed.store(true, Ordering::SeqCst);

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

    let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let tls_cert_settings = TlsCertificatePaths {
        cert: TEST_CERT_FILE,
        private_key: TEST_KEY_FILE,
        kind: tokio_quiche::settings::CertificateKind::X509,
    };

    let hook = Arc::new(TestAsyncCallbackConnectionHook {
        callback_completed: Arc::new(AtomicBool::new(false)),
    });
    let hooks = Hooks {
        connection_hook: Some(hook.clone()),
    };
    let mut quic_settings = QuicSettings::default();
    quic_settings.handshake_timeout = Some(Duration::from_secs(2));
    let params =
        ConnectionParams::new_server(quic_settings, tls_cert_settings, hooks);
    let mut stream = listen(vec![server_socket], params, DefaultMetrics)
        .unwrap()
        .remove(0);

    let (established_tx, established_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let conn = stream.next().await.unwrap().unwrap();
        let app = TestApplication {
            buffer: [0; 1500],
            eager_pre_handshake: true,
            should_act: true,
            established_tx: Some(established_tx),
        };

        let _ = conn.handshake(app).await.expect("handshake failed");
    });

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();
    let client_socket = Socket::try_from(client_socket).unwrap();
    let client_app = TestApplication {
        buffer: [0; 1500],
        eager_pre_handshake: false,
        should_act: false,
        established_tx: None,
    };

    timeout(
        Duration::from_secs(5),
        connect_with_config(
            client_socket,
            Some("127.0.0.1"),
            &ConnectionParams::default(),
            client_app,
        ),
    )
    .await
    .expect("client handshake timed out")
    .expect("client handshake failed");

    timeout(Duration::from_secs(5), established_rx)
        .await
        .expect("server handshake timed out")
        .expect("server app was dropped before establishment");

    server_task.await.unwrap();

    assert!(hook.callback_completed.load(Ordering::SeqCst));
}
