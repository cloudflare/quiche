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

use std::net::SocketAddr;

use boring::ssl::SslContextBuilder;

use crate::settings::TlsCertificatePaths;

/// Context passed to [`ConnectionHook::create_qlog_sink`] when tokio-quiche
/// needs an initial qlog sink for a new connection.
#[derive(Debug)]
#[non_exhaustive]
pub struct QlogSinkContext<'a> {
    /// Trace id for this connection. Formatted from the local source
    /// connection id (`scid`) — i.e. the server's SCID on the server
    /// path and the client's SCID on the client path.
    pub id: &'a str,
    /// True if this connection was accepted as a server.
    pub is_server: bool,
    /// Local socket address of the connection.
    pub local_addr: SocketAddr,
    /// Peer socket address of the connection.
    pub peer_addr: SocketAddr,
}

/// A set of hooks executed at the level of a [quiche::Connection].
pub trait ConnectionHook {
    /// Constructs an optional [`SslContextBuilder`].
    ///
    /// This method allows full customization of quiche's SSL context, for
    /// example to specify async callbacks during the QUIC handshake. It is
    /// called once per socket during initial setup, and then reused across
    /// all connections on that socket.
    ///
    /// Only called if both the hook and [`TlsCertificatePaths`] are set in
    /// [`ConnectionParams`](crate::ConnectionParams).
    fn create_custom_ssl_context_builder(
        &self, settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder>;

    /// Returns an optional [`qlog::QlogSink`] for a new connection.
    ///
    /// Called once per accepted/connected `quiche::Connection`. If `Some` is
    /// returned, tokio-quiche installs it via
    /// `quiche::Connection::set_qlog_sink`. If `None` is returned,
    /// tokio-quiche falls back to the existing `qlog_dir` writer-backed path.
    fn create_qlog_sink(
        &self, _ctx: QlogSinkContext<'_>,
    ) -> Option<Box<dyn qlog::QlogSink>> {
        None
    }
}
