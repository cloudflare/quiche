// Copyright (C) 2018-2019, Cloudflare, Inc.
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

/// A specialized [`Result`] type for quiche operations.
///
/// This type is used throughout quiche's public API for any operation that
/// can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A QUIC error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// There is no more work to do.
    Done,

    /// The provided buffer is too short.
    BufferTooShort,

    /// The provided packet cannot be parsed because its version is unknown.
    UnknownVersion,

    /// The provided packet cannot be parsed because it contains an invalid
    /// frame.
    InvalidFrame,

    /// The provided packet cannot be parsed.
    InvalidPacket,

    /// The operation cannot be completed because the connection is in an
    /// invalid state.
    InvalidState,

    /// The operation cannot be completed because the stream is in an
    /// invalid state.
    ///
    /// The stream ID is provided as associated data.
    InvalidStreamState(u64),

    /// The peer's transport params cannot be parsed.
    InvalidTransportParam,

    /// A cryptographic operation failed.
    CryptoFail,

    /// The TLS handshake failed.
    TlsFail,

    /// The peer violated the local flow control limits.
    FlowControl,

    /// The peer violated the local stream limits.
    StreamLimit,

    /// The specified stream was stopped by the peer.
    ///
    /// The error code sent as part of the `STOP_SENDING` frame is provided as
    /// associated data.
    StreamStopped(u64),

    /// The specified stream was reset by the peer.
    ///
    /// The error code sent as part of the `RESET_STREAM` frame is provided as
    /// associated data.
    StreamReset(u64),

    /// The received data exceeds the stream's final size.
    FinalSize,

    /// Error in congestion control.
    CongestionControl,

    /// Too many identifiers were provided.
    IdLimit,

    /// Not enough available identifiers.
    OutOfIdentifiers,

    /// Error in key update.
    KeyUpdate,

    /// The peer sent more data in CRYPTO frames than we can buffer.
    CryptoBufferExceeded,

    /// The peer sent an ACK frame with an invalid range.
    InvalidAckRange,

    /// The peer send an ACK frame for a skipped packet used for Optimistic ACK
    /// mitigation.
    OptimisticAckDetected,

    /// An invalid DCID was used when connecting to a remote peer.
    InvalidDcidInitialization,

    /// The operation cannot be completed because the connection has an invalid
    /// path state.
    InvalidPathState,

    /// The operation cannot be completed because the connection has an invalid
    /// CID state.
    InvalidCidState,
}

/// QUIC error codes sent on the wire.
///
/// As defined in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html#name-error-codes).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WireErrorCode {
    /// An endpoint uses this with CONNECTION_CLOSE to signal that the
    /// connection is being closed abruptly in the absence of any error.
    NoError              = 0x0,
    /// The endpoint encountered an internal error and cannot continue with the
    /// connection.
    InternalError        = 0x1,
    /// The server refused to accept a new connection.
    ConnectionRefused    = 0x2,
    /// An endpoint received more data than it permitted in its advertised data
    /// limits; see Section 4.
    FlowControlError     = 0x3,
    /// An endpoint received a frame for a stream identifier that exceeded its
    /// advertised stream limit for the corresponding stream type.
    StreamLimitError     = 0x4,
    /// An endpoint received a frame for a stream that was not in a state that
    /// permitted that frame.
    StreamStateError     = 0x5,
    /// (1) An endpoint received a STREAM frame containing data that exceeded
    /// the previously established final size, (2) an endpoint received a
    /// STREAM frame or a RESET_STREAM frame containing a final size that
    /// was lower than the size of stream data that was already received, or
    /// (3) an endpoint received a STREAM frame or a RESET_STREAM frame
    /// containing a different final size to the one already established.
    FinalSizeError       = 0x6,
    /// An endpoint received a frame that was badly formatted -- for instance, a
    /// frame of an unknown type or an ACK frame that has more
    /// acknowledgment ranges than the remainder of the packet could carry.
    FrameEncodingError   = 0x7,
    /// An endpoint received transport parameters that were badly formatted,
    /// included an invalid value, omitted a mandatory transport parameter,
    /// included a forbidden transport parameter, or were otherwise in
    /// error.
    TransportParameterError = 0x8,
    /// The number of connection IDs provided by the peer exceeds the advertised
    /// active_connection_id_limit.
    ConnectionIdLimitError = 0x9,
    /// An endpoint detected an error with protocol compliance that was not
    /// covered by more specific error codes.
    ProtocolViolation    = 0xa,
    /// A server received a client Initial that contained an invalid Token
    /// field.
    InvalidToken         = 0xb,
    /// The application or application protocol caused the connection to be
    /// closed.
    ApplicationError     = 0xc,
    /// An endpoint has received more data in CRYPTO frames than it can buffer.
    CryptoBufferExceeded = 0xd,
    /// An endpoint detected errors in performing key updates.
    KeyUpdateError       = 0xe,
    /// An endpoint has reached the confidentiality or integrity limit for the
    /// AEAD algorithm used by the given connection.
    AeadLimitReached     = 0xf,
    /// An endpoint has determined that the network path is incapable of
    /// supporting QUIC. An endpoint is unlikely to receive a
    /// CONNECTION_CLOSE frame carrying this code except when the path does
    /// not support a large enough MTU.
    NoViablePath         = 0x10,
}

impl Error {
    pub(crate) fn to_wire(self) -> u64 {
        match self {
            Error::Done => WireErrorCode::NoError as u64,
            Error::InvalidFrame => WireErrorCode::FrameEncodingError as u64,
            Error::InvalidStreamState(..) =>
                WireErrorCode::StreamStateError as u64,
            Error::InvalidTransportParam =>
                WireErrorCode::TransportParameterError as u64,
            Error::FlowControl => WireErrorCode::FlowControlError as u64,
            Error::StreamLimit => WireErrorCode::StreamLimitError as u64,
            Error::IdLimit => WireErrorCode::ConnectionIdLimitError as u64,
            Error::FinalSize => WireErrorCode::FinalSizeError as u64,
            Error::CryptoBufferExceeded =>
                WireErrorCode::CryptoBufferExceeded as u64,
            Error::KeyUpdate => WireErrorCode::KeyUpdateError as u64,
            _ => WireErrorCode::ProtocolViolation as u64,
        }
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn to_c(self) -> libc::ssize_t {
        match self {
            Error::Done => -1,
            Error::BufferTooShort => -2,
            Error::UnknownVersion => -3,
            Error::InvalidFrame => -4,
            Error::InvalidPacket => -5,
            Error::InvalidState => -6,
            Error::InvalidStreamState(_) => -7,
            Error::InvalidTransportParam => -8,
            Error::CryptoFail => -9,
            Error::TlsFail => -10,
            Error::FlowControl => -11,
            Error::StreamLimit => -12,
            Error::FinalSize => -13,
            Error::CongestionControl => -14,
            Error::StreamStopped { .. } => -15,
            Error::StreamReset { .. } => -16,
            Error::IdLimit => -17,
            Error::OutOfIdentifiers => -18,
            Error::KeyUpdate => -19,
            Error::CryptoBufferExceeded => -20,
            Error::InvalidAckRange => -21,
            Error::OptimisticAckDetected => -22,
            Error::InvalidDcidInitialization => -23,
            Error::InvalidPathState => -24,
            Error::InvalidCidState => -25,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

/// Represents information carried by `CONNECTION_CLOSE` frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionError {
    /// Whether the error came from the application or the transport layer.
    pub is_app: bool,

    /// The error code carried by the `CONNECTION_CLOSE` frame.
    pub error_code: u64,

    /// The reason carried by the `CONNECTION_CLOSE` frame.
    pub reason: Vec<u8>,
}
