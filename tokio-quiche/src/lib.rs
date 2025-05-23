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

//! Bridging the gap between [quiche] and [tokio].
//!
//! tokio-quiche connects [quiche::Connection]s and [quiche::h3::Connection]s to
//! tokio's event loop. Users have the choice between implementing their own,
//! custom [`ApplicationOverQuic`] or using the ready-made
//! [H3Driver](crate::http3::driver::H3Driver) for HTTP/3 clients and servers.
//!
//! # Starting an HTTP/3 Server
//!
//! A server [`listen`]s on a UDP socket for QUIC connections and spawns a new
//! tokio task to handle each individual connection.
//!
//! ```
//! use futures::stream::StreamExt;
//! use tokio_quiche::http3::settings::Http3Settings;
//! use tokio_quiche::listen;
//! use tokio_quiche::metrics::DefaultMetrics;
//! use tokio_quiche::quic::SimpleConnectionIdGenerator;
//! use tokio_quiche::ConnectionParams;
//! use tokio_quiche::ServerH3Driver;
//!
//! # async fn example() -> tokio_quiche::QuicResult<()> {
//! let socket = tokio::net::UdpSocket::bind("0.0.0.0:443").await?;
//! let mut listeners = listen(
//!     [socket],
//!     ConnectionParams::default(),
//!     SimpleConnectionIdGenerator,
//!     DefaultMetrics,
//! )?;
//! let mut accept_stream = &mut listeners[0];
//!
//! while let Some(conn) = accept_stream.next().await {
//!     let (driver, mut controller) =
//!         ServerH3Driver::new(Http3Settings::default());
//!     conn?.start(driver);
//!
//!     tokio::spawn(async move {
//!         // `controller` is the handle to our established HTTP/3 connection.
//!         // For example, inbound requests are available as H3Events via:
//!         let event = controller.event_receiver_mut().recv().await;
//!     });
//! }
//! # Ok(())
//! # }
//! ```
//!
//! For client-side use cases, check out our [`connect`](crate::quic::connect)
//! API.
//!
//! # Feature Flags
//!
//! tokio-quiche supports a number of feature flags to enable experimental
//! features, performance enhancements, and additional telemetry. By default, no
//! feature flags are enabled.
//!
//! - `rpk`: Support for raw public keys (RPK) in QUIC handshakes (via
//!   [boring]).
//! - `gcongestion`: Replace quiche's original congestion control implementation
//!   with one adapted from google/quiche.
//! - `zero-copy`: Use zero-copy sends with quiche (implies `gcongestion`).
//! - `perf-quic-listener-metrics`: Extra telemetry for QUIC handshake
//!   durations, including protocol overhead and network delays.
//! - `tokio-task-metrics`: Scheduling & poll duration histograms for tokio
//!   tasks.
//!
//! Other parts of the crate are enabled by separate build flags instead, to be
//! controlled by the final binary:
//!
//! - `--cfg capture_keylogs`: Optional `SSLKEYLOGFILE` capturing for QUIC
//!   connections.

pub extern crate quiche;

pub mod buf_factory;
pub mod http3;
pub mod metrics;
pub mod quic;
mod result;
pub mod settings;
pub mod socket;

pub use buffer_pool;
pub use datagram_socket;

use foundations::telemetry::settings::LogVerbosity;
use std::io;
use std::sync::Arc;
use std::sync::Once;
use tokio::net::UdpSocket;
use tokio_stream::wrappers::ReceiverStream;

use crate::metrics::Metrics;
use crate::socket::QuicListener;

pub use crate::http3::driver::ClientH3Controller;
pub use crate::http3::driver::ClientH3Driver;
pub use crate::http3::driver::ServerH3Controller;
pub use crate::http3::driver::ServerH3Driver;
pub use crate::http3::ClientH3Connection;
pub use crate::http3::ServerH3Connection;
pub use crate::quic::connection::ApplicationOverQuic;
pub use crate::quic::connection::ConnectionIdGenerator;
pub use crate::quic::connection::InitialQuicConnection;
pub use crate::quic::connection::QuicConnection;
pub use crate::result::BoxError;
pub use crate::result::QuicResult;
pub use crate::settings::ConnectionParams;

#[doc(hidden)]
pub use crate::result::QuicResultExt;

/// A stream of accepted [`InitialQuicConnection`]s from a [`listen`] call.
///
/// Errors from processing the client's QUIC initials can also be emitted on
/// this stream. These do not indicate that the listener itself has failed.
pub type QuicConnectionStream<M> =
    ReceiverStream<io::Result<InitialQuicConnection<UdpSocket, M>>>;

/// Starts listening for inbound QUIC connections on the given
/// [`QuicListener`]s.
///
/// Each socket starts a separate tokio task to process and route inbound
/// packets. This task emits connections on the respective
/// [`QuicConnectionStream`] after receiving the client's QUIC initial and
/// (optionally) validating its IP address.
///
/// The task shuts down when the returned stream is closed (or dropped) and all
/// previously-yielded connections are closed.
pub fn listen_with_capabilities<M>(
    sockets: impl IntoIterator<Item = QuicListener>, params: ConnectionParams,
    cid_generator: impl ConnectionIdGenerator<'static> + Clone, metrics: M,
) -> io::Result<Vec<QuicConnectionStream<M>>>
where
    M: Metrics,
{
    if params.settings.capture_quiche_logs {
        capture_quiche_logs();
    }

    sockets
        .into_iter()
        .map(|s| {
            crate::quic::start_listener(
                s,
                &params,
                cid_generator.clone(),
                metrics.clone(),
            )
        })
        .collect()
}

/// Starts listening for inbound QUIC connections on the given `sockets`.
///
/// Each socket is converted into a [`QuicListener`] with defaulted socket
/// parameters. The listeners are then passed to [`listen_with_capabilities`].
pub fn listen<S, M>(
    sockets: impl IntoIterator<Item = S>, params: ConnectionParams,
    cid_generator: impl ConnectionIdGenerator<'static> + Clone, metrics: M,
) -> io::Result<Vec<QuicConnectionStream<M>>>
where
    S: TryInto<QuicListener, Error = io::Error>,
    M: Metrics,
{
    let quic_sockets: Vec<QuicListener> = sockets
        .into_iter()
        .map(|s| {
            #[cfg_attr(not(target_os = "linux"), expect(unused_mut))]
            let mut socket = s.try_into()?;
            #[cfg(target_os = "linux")]
            socket.apply_max_capabilities(
                params.settings.max_send_udp_payload_size,
            );
            Ok(socket)
        })
        .collect::<io::Result<_>>()?;

    listen_with_capabilities(quic_sockets, params, cid_generator, metrics)
}

static GLOBAL_LOGGER_ONCE: Once = Once::new();

/// Forward Quiche logs into the slog::Drain currently used by Foundations
///
/// # Warning
///
/// This should **only be used for local debugging**. Quiche can potentially
/// emit lots (and lots, and lots) of logs (the TRACE level emits a log record
/// on every packet and frame) and you can very easily overwhelm your logging
/// pipeline.
///
/// # Note
///
/// Quiche uses the `env_logger` crate, which uses `log` under the hood. `log`
/// requires that you only set the global logger once. That means that we have
/// to register the logger at `listen()` time for servers - for clients, we
/// should register loggers when the `quiche::Connection` is established.
pub(crate) fn capture_quiche_logs() {
    GLOBAL_LOGGER_ONCE.call_once(|| {
        use foundations::telemetry::log as foundations_log;
        use log::Level as std_level;

        let curr_logger =
            Arc::clone(&foundations_log::slog_logger()).read().clone();
        let scope_guard = slog_scope::set_global_logger(curr_logger);

        // Convert slog::Level from Foundations settings to log::Level
        let normalized_level = match foundations_log::verbosity() {
            LogVerbosity::Critical | LogVerbosity::Error => std_level::Error,
            LogVerbosity::Warning => std_level::Warn,
            LogVerbosity::Info => std_level::Info,
            LogVerbosity::Debug => std_level::Debug,
            LogVerbosity::Trace => std_level::Trace,
        };

        slog_stdlog::init_with_level(normalized_level).unwrap();

        // The slog Drain becomes `slog::Discard` when the scope_guard is dropped,
        // and you can't set the global logger again because of a mandate
        // in the `log` crate. We have to manually `forget` the scope
        // guard so that the logger remains registered for the duration of the
        // process.
        std::mem::forget(scope_guard)
    });
}
