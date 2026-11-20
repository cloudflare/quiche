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

use crate::quic::QuicheConnection;
use crate::result::QuicResult;
use std::fmt;
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

/// A client connection closed before its handshake completed.
///
/// A failed [`connect`](crate::quic::connect) or
/// [`connect_with_config`](crate::quic::connect_with_config) returns this
/// inside an [`io::Error`] of kind [`io::ErrorKind::TimedOut`]: downcast the
/// returned error to [`io::Error`], then downcast [`io::Error::get_ref`] to
/// `HandshakeClosed`.
///
/// It carries the `CONNECTION_CLOSE` details, so a caller can tell a handshake
/// its own TLS stack rejected (a local `CRYPTO_ERROR` carrying the TLS alert)
/// from one the peer closed or one that timed out.
///
/// A handshake that runs in the connection's worker, as a server's does,
/// reports a close as [`HandshakeError::ConnectionClosed`] instead. A client's
/// handshake runs before its worker starts, so a client connect reports this.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HandshakeClosed {
    /// The connection's source connection ID.
    pub scid: quiche::ConnectionId<'static>,
    /// The error this endpoint closed the connection with, if it closed it.
    pub local_error: Option<quiche::ConnectionError>,
    /// The error the peer closed the connection with, if it closed it.
    pub peer_error: Option<quiche::ConnectionError>,
    /// Whether the connection closed because its idle timeout expired.
    pub timed_out: bool,
}

impl HandshakeClosed {
    pub(crate) fn from_conn(conn: &QuicheConnection) -> Self {
        Self {
            scid: conn.source_id().into_owned(),
            local_error: conn.local_error().cloned(),
            peer_error: conn.peer_error().cloned(),
            timed_out: conn.is_timed_out(),
        }
    }

    /// Wraps this in the [`io::Error`] a failed client connect returns.
    pub(crate) fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, self)
    }
}

impl fmt::Display for HandshakeClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "connection {:?} closed during handshake", self.scid)?;

        if self.timed_out {
            write!(f, ", idle timeout expired")?;
        }

        for (side, err) in
            [("local", &self.local_error), ("peer", &self.peer_error)]
        {
            if let Some(err) = err {
                let layer = if err.is_app {
                    "application"
                } else {
                    "transport"
                };
                write!(f, ", {side} {layer} error {:#x}", err.error_code)?;
            }
        }

        Ok(())
    }
}

impl std::error::Error for HandshakeClosed {}

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
