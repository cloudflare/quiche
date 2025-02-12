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

// We use io::Result for `IQC::handshake` to provide a uniform interface with handshakes
// of other connection types, for example TLS. This is a best-effort mapping to match the
// existing io::ErrorKind values.
impl From<HandshakeError> for io::Error {
    fn from(err: HandshakeError) -> Self {
        match err {
            HandshakeError::Timeout => Self::new(io::ErrorKind::TimedOut, err),
            HandshakeError::ConnectionClosed => Self::new(io::ErrorKind::NotConnected, err),
        }
    }
}

/// Derives a [`std::io::Result`] from `IoWorker::handshake`'s result without taking
/// ownership of the original [`Result`].
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
