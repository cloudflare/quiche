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
