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

use crate::result::QuicResult;
use std::io;

/// Additional error types that can occur during a QUIC handshake.
///
/// Protocol errors are returned directly as [`quiche::Error`] values.
#[non_exhaustive]
#[derive(Debug, Clone, thiserror::Error)]
pub enum HandshakeError {
    /// The configured handshake timeout has expired.
    #[error("handshake timeout expired")]
    Timeout,
    /// The connection was closed while handshaking, for example by the peer.
    #[error("connection closed during Handshake stage")]
    ConnectionClosed,
}

// We use io::Result for `IQC::handshake` to provide a uniform interface with
// handshakes of other connection types, for example TLS. This is a best-effort
// mapping to match the existing io::ErrorKind values.
impl From<HandshakeError> for io::Error {
    fn from(err: HandshakeError) -> Self {
        match err {
            HandshakeError::Timeout => Self::new(io::ErrorKind::TimedOut, err),
            HandshakeError::ConnectionClosed =>
                Self::new(io::ErrorKind::NotConnected, err),
        }
    }
}

/// Derives a [`std::io::Result`] from `IoWorker::handshake`'s result without
/// taking ownership of the original [`Result`].
pub(crate) fn make_handshake_result<T>(res: &QuicResult<()>) -> io::Result<T> {
    let Err(err) = res else {
        return Err(io::Error::other(
            "Handshake transitioned to Closing without error",
        ));
    };

    // BoxError does not force its content to be Clone, so we need to check for
    // the types we expect manually & clone/copy them.
    if let Some(hs_err) = err.downcast_ref::<HandshakeError>() {
        Err(hs_err.clone().into())
    } else if let Some(quiche_err) = err.downcast_ref::<quiche::Error>() {
        Err(io::Error::other(*quiche_err))
    } else {
        let data_fmt = format!("unexpected handshake error: {err}");
        Err(io::Error::other(data_fmt))
    }
}
