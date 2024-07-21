// Copyright (C) 2024, Cloudflare, Inc.
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

//! Helpers for dealing with quiche stream events and HTTP/3 frames.

use std::cmp;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::Debug;

use http::status::InvalidStatusCode;
use http::HeaderMap;
use http::HeaderName;
use http::StatusCode;

use quiche;

use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Header;
use quiche::h3::NameValue;
use serde::ser::SerializeStruct;
use serde::ser::Serializer;
use serde::Serialize;

use crate::client::connection_summary::MAX_SERIALIZED_BUFFER_LEN;
use crate::encode_header_block;

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// An internal representation of a QUIC or HTTP/3 frame. This type exists so
/// that we can extend types defined in Quiche.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum H3iFrame {
    /// A wrapper around a quiche HTTP/3 frame.
    QuicheH3(QFrame),
    /// A wrapper around an [EnrichedHeaders] struct.
    Headers(EnrichedHeaders),
    /// A wrapper around a [ResetStream] struct
    ResetStream(ResetStream),
}

impl H3iFrame {
    /// Try to convert this `H3iFrame` to an [EnrichedHeaders].
    ///
    /// Returns `Some` if the operation succeeded.
    pub fn to_enriched_headers(&self) -> Option<EnrichedHeaders> {
        if let H3iFrame::Headers(header) = self {
            Some(header.clone())
        } else {
            None
        }
    }
}

impl Serialize for H3iFrame {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            H3iFrame::QuicheH3(frame) => {
                let mut state = s.serialize_struct("frame", 1)?;
                let name = frame_name(frame);
                state.serialize_field(name, &SerializableQFrame(frame))?;
                state.end()
            },
            H3iFrame::Headers(headers) => {
                let mut state = s.serialize_struct("enriched_headers", 1)?;
                state.serialize_field("enriched_headers", headers)?;
                state.end()
            },
            H3iFrame::ResetStream(reset) => {
                let mut state = s.serialize_struct("reset_stream", 1)?;
                state.serialize_field("reset_stream", reset)?;
                state.end()
            },
        }
    }
}

impl From<QFrame> for H3iFrame {
    fn from(value: QFrame) -> Self {
        Self::QuicheH3(value)
    }
}

impl From<Vec<Header>> for H3iFrame {
    fn from(value: Vec<Header>) -> Self {
        Self::Headers(EnrichedHeaders::from(value))
    }
}

/// An HTTP/3 HEADERS frame with decoded headers and a [HeaderMap].
#[derive(Clone, PartialEq, Eq)]
pub struct EnrichedHeaders {
    header_block: Vec<u8>,
    headers: Vec<Header>,
    header_map: HeaderMap<Vec<u8>>,
}

/// A wrapper to help serialize an quiche HTTP header.
pub struct SerializableHeader<'a>(&'a Header);

impl<'a> Serialize for SerializableHeader<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("header", 2)?;
        state.serialize_field("name", &String::from_utf8_lossy(self.0.name()))?;
        state
            .serialize_field("value", &String::from_utf8_lossy(self.0.value()))?;
        state.end()
    }
}

impl EnrichedHeaders {
    /// Return the array of headers in this frame.
    ///
    /// # Examples
    /// ```
    /// use h3i::frame::EnrichedHeaders;
    /// use quiche::h3::Header;
    ///
    /// let raw = vec![
    ///     Header::new(b"new jersey", b"devils"),
    ///     Header::new(b"new york", b"jets"),
    /// ];
    /// let headers = EnrichedHeaders::from(raw.clone());
    /// assert_eq!(headers.headers(), raw);
    /// ```
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Fetches the value of the `:status` pseudo-header.
    ///
    /// # Examples
    /// ```
    /// use h3i::frame::EnrichedHeaders;
    /// use quiche::h3::Header;
    ///
    /// let headers = EnrichedHeaders::from(vec![Header::new(b"hello", b"world")]);
    /// assert!(headers.status_code().is_none());
    ///
    /// let headers =
    ///     EnrichedHeaders::from(vec![Header::new(b":status", b"hello_world")]);
    /// assert!(headers.status_code().expect("code is Some").is_err());
    ///
    /// let headers = EnrichedHeaders::from(vec![Header::new(b":status", b"200")]);
    /// assert_eq!(
    ///     headers
    ///         .status_code()
    ///         .expect("status code is Some")
    ///         .expect("status code is Ok"),
    ///     200
    /// );
    /// ```
    pub fn status_code(&self) -> Option<Result<StatusCode, InvalidStatusCode>> {
        // Unfortunately can't use header_map since pseudo-headers aren't stored
        // in it
        self.headers
            .iter()
            .filter(|h| h.name() == b":status")
            .map(|header| StatusCode::from_bytes(header.value()))
            .next()
    }
}

impl Serialize for EnrichedHeaders {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("enriched_headers", 2)?;
        state.serialize_field("header_block_len", &self.header_block.len())?;
        let x: Vec<SerializableHeader> =
            self.headers.iter().map(SerializableHeader).collect();
        state.serialize_field("headers", &x)?;
        state.end()
    }
}

impl From<Vec<Header>> for EnrichedHeaders {
    fn from(headers: Vec<Header>) -> Self {
        let header_block = encode_header_block(&headers).unwrap();

        let mut header_map = HeaderMap::with_capacity(headers.len());
        for header in headers.iter() {
            let name = header.name();

            if let Some(b':') = name.first() {
                // Pseudo-headers can't be parsed into a `HeaderName` in the
                // `http` crate.
                //
                // See https://docs.rs/http/latest/src/http/header/name.rs.html#1115 for more.
                continue;
            }

            let header_name = if let Ok(s) = HeaderName::from_bytes(name) {
                s
            } else {
                continue;
            };

            header_map.insert(header_name, header.value().to_vec());
        }

        Self {
            header_block,
            headers,
            header_map,
        }
    }
}

impl TryFrom<QFrame> for EnrichedHeaders {
    type Error = BoxError;

    fn try_from(value: QFrame) -> Result<Self, Self::Error> {
        match value {
            QFrame::Headers { header_block } => {
                let mut qpack_decoder = quiche::h3::qpack::Decoder::new();
                let headers =
                    qpack_decoder.decode(&header_block, u64::MAX).unwrap();

                Ok(EnrichedHeaders::from(headers))
            },
            _ => Err("Cannot convert non-Headers frame into HeadersFrame".into()),
        }
    }
}

impl Debug for EnrichedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.headers)
    }
}

/// A `RESET_STREAM` frame.
///
/// See [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000#name-reset_stream-frames) for
/// more.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResetStream {
    /// The stream ID over which the RESET_STREAM frame was sent.
    pub stream_id: u64,
    /// The error code sent from the peer.
    pub error_code: u64,
}

fn frame_name(frame: &QFrame) -> &'static str {
    match frame {
        QFrame::Data { .. } => "DATA",
        QFrame::Headers { .. } => "HEADERS",
        QFrame::CancelPush { .. } => "CANCEL_PUSH",
        QFrame::Settings { .. } => "SETTINGS",
        QFrame::PushPromise { .. } => "PUSH_PROMISE",
        QFrame::GoAway { .. } => "GO_AWAY",
        QFrame::MaxPushId { .. } => "MAX_PUSH_ID",
        QFrame::PriorityUpdateRequest { .. } => "PRIORITY_UPDATE(REQUEST)",
        QFrame::PriorityUpdatePush { .. } => "PRIORITY_UPDATE(PUSH)",
        QFrame::Unknown { .. } => "UNKNOWN",
    }
}

/// A wrapper to help serialize a quiche HTTP/3 frame.
pub struct SerializableQFrame<'a>(&'a QFrame);

impl<'a> Serialize for SerializableQFrame<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let name = frame_name(self.0);
        match self.0 {
            QFrame::Data { payload } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field("payload_len", &payload.len())?;
                state.end()
            },

            QFrame::Headers { header_block } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field("header_block_len", &header_block.len())?;
                state.end()
            },

            QFrame::CancelPush { push_id } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field("push_id", &push_id)?;
                state.end()
            },

            QFrame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                h3_datagram,
                grease: _,
                additional_settings,
                raw: _,
            } => {
                let mut state = s.serialize_struct(name, 6)?;
                state.serialize_field(
                    "max_field_section_size",
                    &max_field_section_size,
                )?;
                state.serialize_field(
                    "qpack_max_table_capacity",
                    &qpack_max_table_capacity,
                )?;
                state.serialize_field(
                    "qpack_blocked_streams",
                    &qpack_blocked_streams,
                )?;
                state.serialize_field(
                    "connect_protocol_enabled",
                    &connect_protocol_enabled,
                )?;
                state.serialize_field("h3_datagram", &h3_datagram)?;
                state.serialize_field(
                    "additional_settings",
                    &additional_settings,
                )?;
                state.end()
            },

            QFrame::PushPromise {
                push_id,
                header_block,
            } => {
                let mut state = s.serialize_struct(name, 2)?;
                state.serialize_field("push_id", &push_id)?;
                state.serialize_field("header_block_len", &header_block.len())?;
                state.end()
            },

            QFrame::GoAway { id } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field("id", &id)?;
                state.end()
            },

            QFrame::MaxPushId { push_id } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field("push_id", &push_id)?;
                state.end()
            },

            QFrame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                let mut state = s.serialize_struct(name, 2)?;
                state.serialize_field(
                    "prioritized_element_id",
                    &prioritized_element_id,
                )?;

                let max = cmp::min(
                    priority_field_value.len(),
                    MAX_SERIALIZED_BUFFER_LEN,
                );
                state.serialize_field(
                    "priority_field_value",
                    &String::from_utf8_lossy(&priority_field_value[..max]),
                )?;
                state.end()
            },

            QFrame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field(
                    "prioritized_element_id",
                    &prioritized_element_id,
                )?;
                let max = cmp::min(
                    priority_field_value.len(),
                    MAX_SERIALIZED_BUFFER_LEN,
                );
                state.serialize_field(
                    "priority_field_value",
                    &String::from_utf8_lossy(&priority_field_value[..max]),
                )?;
                state.end()
            },

            QFrame::Unknown { raw_type, payload } => {
                let mut state = s.serialize_struct(name, 1)?;
                state.serialize_field("raw_type", &raw_type)?;
                let max = cmp::min(payload.len(), MAX_SERIALIZED_BUFFER_LEN);

                state.serialize_field(
                    "payload",
                    &qlog::HexSlice::maybe_string(Some(&payload[..max])),
                )?;
                state.end()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code() {
        let header_frame = vec![Header::new(b":status", b"200")];
        let enriched = H3iFrame::Headers(header_frame.into())
            .to_enriched_headers()
            .unwrap();

        let result = enriched.status_code().expect("no status code");
        assert_eq!(result.ok(), Some(StatusCode::OK));

        let header_frame = vec![Header::new(b"hello", b"super-earth")];
        let enriched = H3iFrame::Headers(header_frame.into())
            .to_enriched_headers()
            .unwrap();

        assert!(enriched.status_code().is_none());
    }
}
