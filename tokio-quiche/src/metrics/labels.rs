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

//! Labels for crate metrics.

use serde::Serialize;
use serde::Serializer;

use crate::quic;
use crate::BoxError;

/// Type of handshake latency that was measured by a metric.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuicHandshakeStage {
    // The time spent in kernel processing a packet plus the time waiting
    // for the QUIC handler to be polled by tokio worker.
    QueueWaiting,
    // Time spent on protocol processing of a single handshake packet (not
    // including queue waiting and scheduling delay of I/O worker to write
    // data out)
    HandshakeProtocol,
    // Time between receiving a handshake in the kernel and flushing its
    // response to the socket. Ideally we can ask kernel to report TX stamp,
    // but right now tx latency is not a major source of problem, so we omit
    // that.
    HandshakeResponse,
}

/// Type of UDP [`send(2)`](https://man7.org/linux/man-pages/man2/send.2.html) error observed.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuicWriteError {
    Err,
    Partial,
}

/// Category of error that caused the QUIC handshake to fail.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HandshakeError {
    CryptoFail,
    TlsFail,
    Timeout,
    Disconnect,
    Other,
}

impl From<&quiche::Error> for HandshakeError {
    fn from(err: &quiche::Error) -> Self {
        match err {
            quiche::Error::CryptoFail => Self::CryptoFail,
            quiche::Error::TlsFail => Self::TlsFail,
            _ => Self::Other,
        }
    }
}

impl From<&quic::HandshakeError> for HandshakeError {
    fn from(err: &quic::HandshakeError) -> Self {
        match err {
            quic::HandshakeError::Timeout => Self::Timeout,
            quic::HandshakeError::ConnectionClosed => Self::Disconnect,
        }
    }
}

impl From<&BoxError> for HandshakeError {
    fn from(err: &BoxError) -> Self {
        if let Some(e) = err.downcast_ref::<quic::HandshakeError>() {
            Self::from(e)
        } else if let Some(e) = err.downcast_ref::<quiche::Error>() {
            Self::from(e)
        } else {
            Self::Other
        }
    }
}

/// Reason why a QUIC Initial was discarded by the packet router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicInvalidInitialPacketError {
    TokenValidationFail,
    FailedToParse,
    WrongType(quiche::Type),
    AcceptQueueOverflow,
    Unexpected,
}

impl std::fmt::Display for QuicInvalidInitialPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::FailedToParse => f.write_str("failed to parse packet"),
            Self::TokenValidationFail => f.write_str("token validation fail"),
            Self::WrongType(ty) => write!(f, "wrong type: {ty:?}"),
            Self::AcceptQueueOverflow => f.write_str("accept queue overflow"),
            Self::Unexpected => f.write_str("unexpected error"),
        }
    }
}

impl Serialize for QuicInvalidInitialPacketError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl std::hash::Hash for QuicInvalidInitialPacketError {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        std::mem::discriminant(self).hash(state);
        if let Self::WrongType(ty) = self {
            std::mem::discriminant(ty).hash(state);
        }
    }
}

impl std::error::Error for QuicInvalidInitialPacketError {}

impl From<QuicInvalidInitialPacketError> for std::io::Error {
    fn from(e: QuicInvalidInitialPacketError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

/// HTTP/3 error code (from IANA registry).
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct H3Error(u64);

impl Serialize for H3Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let code = self.0;

        // https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml
        let v = if code > 0x21 && (code - 0x21) % 0x1f == 0 {
            "H3_GREASE"
        } else {
            match code {
                0x33 => "H3_DATAGRAM_ERROR",

                0x100 => "H3_NO_ERROR",
                0x101 => "H3_GENERAL_PROTOCOL_ERROR",
                0x102 => "H3_INTERNAL_ERROR",
                0x103 => "H3_STREAM_CREATION_ERROR",
                0x104 => "H3_CLOSED_CRITICAL_STREAM",
                0x105 => "H3_FRAME_UNEXPECTED",
                0x106 => "H3_FRAME_ERROR",
                0x107 => "H3_EXCESSIVE_LOAD",
                0x108 => "H3_ID_ERROR",
                0x109 => "H3_SETTINGS_ERROR",
                0x10a => "H3_MISSING_SETTINGS",
                0x10b => "H3_REQUEST_REJECTED",
                0x10c => "H3_REQUEST_CANCELLED",
                0x10d => "H3_REQUEST_INCOMPLETE",
                0x10e => "H3_MESSAGE_ERROR",
                0x10f => "H3_CONNECT_ERROR",
                0x110 => "H3_VERSION_FALLBACK",

                0x200 => "QPACK_DECOMPRESSION_FAILED",
                0x201 => "QPACK_ENCODER_STREAM_ERROR",
                0x202 => "QPACK_DECODER_STREAM_ERROR",

                _ => "H3_UNKNOWN",
            }
        };
        serializer.serialize_str(v)
    }
}

impl From<u64> for H3Error {
    fn from(code: u64) -> Self {
        Self(code)
    }
}

/// QUIC error code (from IANA registry).
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct QuicError(u64);

impl Serialize for QuicError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // https://www.iana.org/assignments/quic/quic.xhtml
        let v = match self.0 {
            0x0 => "NO_ERROR",
            0x1 => "INTERNAL_ERROR",
            0x2 => "CONNECTION_REFUSED",
            0x3 => "FLOW_CONTROL_ERROR",
            0x4 => "STREAM_LIMIT_ERROR",
            0x5 => "STREAM_STATE_ERROR",
            0x6 => "FINAL_SIZE_ERROR",
            0x7 => "FRAME_ENCODING_ERROR",
            0x8 => "TRANSPORT_PARAMETER_ERROR",
            0x9 => "CONNECTION_ID_LIMIT_ERROR",
            0xa => "PROTOCOL_VIOLATION",
            0xb => "INVALID_TOKEN",
            0xc => "APPLICATION_ERROR",
            0xd => "CRYPTO_BUFFER_EXCEEDED",
            0xe => "KEY_UPDATE_ERROR",
            0xf => "AEAD_LIMIT_REACHED",
            0x10 => "NO_VIABLE_PATH",
            0x11 => "VERSION_NEGOTIATION_ERROR",
            0x100..=0x1ff => "CRYPTO_ERROR",

            _ => "QUIC_UNKNOWN",
        };
        serializer.serialize_str(v)
    }
}

impl From<u64> for QuicError {
    fn from(code: u64) -> Self {
        Self(code)
    }
}
