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
use quiche::ConnectionError;
use std::error::Error;
use std::io;

/// Generic thread-safe boxed error.
///
/// From all our prior experience we've learned that there is very little
/// practical use in concrete error types. On the surface it seems appealing to
/// use such errors, because they have, ahem, concrete type. But the flip side
/// is that code in big projects quickly ends up being polluted with endless
/// adapter error types to combine different APIs together, or, even worse, an
/// Error god-object gets introduced to accommodate all possible error types.
///
/// On rare occasions concrete error types can be used, where handling of the
/// error depends on the error kind. But, in practice, such cases are quite
/// rare.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;
/// [Result] alias based on [`BoxError`] for this crate.
pub type QuicResult<T> = Result<T, BoxError>;

/// Extension trait to add methods to [Result].
pub trait QuicResultExt<T, E> {
    /// Turns the [Result] into an [`io::Result`] with
    /// [`ErrorKind::Other`](io::ErrorKind::Other).
    fn into_io(self) -> io::Result<T>
    where
        E: Into<BoxError>;
}

impl<T, E> QuicResultExt<T, E> for Result<T, E>
where
    E: Into<BoxError>,
{
    #[inline]
    fn into_io(self) -> io::Result<T> {
        self.map_err(io::Error::other)
    }
}

/// A local tokio-quiche error type that allows for capturing additional
/// context.
#[derive(Debug)]
pub struct TQError {
    /// Preserve the original error.
    parent: BoxError,

    /// Reason for this alert.
    reason: String,

    /// True if the handshake has completed.
    handshake_complete: bool,

    /// Connection was closed due to the idle timeout.
    did_idle_timeout: bool,

    /// Either the internal quiche error or the error `quiche::close()` was
    /// called with.
    local_err: Option<ConnectionError>,

    /// The error received from the peer.
    peer_err: Option<ConnectionError>,
}

impl TQError {
    pub(crate) fn with_context(
        parent: BoxError, reason: &str, qconn: &QuicheConnection,
    ) -> Self {
        let local_err = qconn.local_error().cloned();
        let peer_err = qconn.peer_error().cloned();

        TQError {
            parent,
            reason: reason.to_string(),
            handshake_complete: qconn.is_established(),
            did_idle_timeout: qconn.is_timed_out(),
            local_err,
            peer_err,
        }
    }

    pub fn parent(&self) -> &BoxError {
        &self.parent
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    pub fn did_idle_timeout(&self) -> bool {
        self.did_idle_timeout
    }

    pub fn local_err(&self) -> Option<&ConnectionError> {
        self.local_err.as_ref()
    }

    pub fn peer_err(&self) -> Option<&ConnectionError> {
        self.peer_err.as_ref()
    }
}

impl std::fmt::Display for TQError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TQError {}
