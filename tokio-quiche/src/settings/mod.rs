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

//! Configuration for QUIC connections.

mod config;
mod hooks;
mod quic;
mod tls;

pub(crate) use self::config::*;

pub use self::hooks::*;
pub use self::quic::*;
pub use self::tls::*;

/// Combined configuration parameters required to establish a QUIC connection.
///
/// [`ConnectionParams`] aggregates the parameters required for all QUIC
/// connections, regardless of whether it's a client- or server-side connection.
/// To construct them, either `ConnectionParams::new_server` or
/// `ConnectionParams::new_client` must be used. The parameters can be modified
/// freely after construction.
#[derive(Default)]
#[non_exhaustive] // force use of constructor functions
pub struct ConnectionParams<'a> {
    /// QUIC connection settings.
    pub settings: QuicSettings,
    /// Optional TLS credentials to authenticate with.
    pub tls_cert: Option<TlsCertificatePaths<'a>>,
    /// Hooks to use for the connection.
    pub hooks: Hooks,
    /// Set the session to attempt resumption.
    pub session: Option<Vec<u8>>,
}

impl core::fmt::Debug for ConnectionParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid printing 'session' since it contains connection secrets.
        f.debug_struct("ConnectionParams")
            .field("settings", &self.settings)
            .field("tls_cert", &self.tls_cert)
            .field("hooks", &self.hooks)
            .finish()
    }
}

impl<'a> ConnectionParams<'a> {
    /// Creates [`ConnectionParams`] for a QUIC server.
    /// Servers should always specify TLS credentials.
    #[inline]
    pub fn new_server(
        settings: QuicSettings, tls_cert: TlsCertificatePaths<'a>, hooks: Hooks,
    ) -> Self {
        Self {
            settings,
            tls_cert: Some(tls_cert),
            hooks,
            session: None,
        }
    }

    /// Creates [`ConnectionParams`] for a QUIC client.
    /// Clients may enable mTLS by specifying TLS credentials.
    #[inline]
    pub fn new_client(
        settings: QuicSettings, tls_cert: Option<TlsCertificatePaths<'a>>,
        hooks: Hooks,
    ) -> Self {
        Self {
            settings,
            tls_cert,
            hooks,
            session: None,
        }
    }
}
