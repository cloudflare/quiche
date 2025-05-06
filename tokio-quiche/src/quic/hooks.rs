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

#[cfg(not(feature = "__rustls"))]
use crate::settings::TlsCertificatePaths;
#[cfg(not(feature = "__rustls"))]
use boring::ssl::SslContextBuilder;

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
    #[cfg(not(feature = "__rustls"))]
    fn create_custom_ssl_context_builder(
        &self, settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder>;
}
