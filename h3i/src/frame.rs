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
use std::sync::Arc;

use multimap::MultiMap;
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
#[derive(Debug, Eq, PartialEq, Clone)]
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

pub type HeaderMap = MultiMap<Vec<u8>, Vec<u8>>;

/// An HTTP/3 HEADERS frame with decoded headers and a [HeaderMap].
#[derive(Clone, PartialEq, Eq)]
pub struct EnrichedHeaders {
    header_block: Vec<u8>,
    headers: Vec<Header>,
    /// A multi-map of raw header names to values, similar to http's HeaderMap.
    header_map: HeaderMap,
}

/// A wrapper to help serialize an quiche HTTP header.
pub struct SerializableHeader<'a>(&'a Header);

impl Serialize for SerializableHeader<'_> {
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

    /// Returns a multi-map of header keys to values.
    ///
    /// If a single key contains multiple values, the values in the entry will
    /// be returned in the same order as they appear in the array of headers
    /// which backs the [`EnrichedHeaders`].
    ///
    /// # Examples
    /// ```
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use multimap::MultiMap;
    /// use quiche::h3::Header;
    /// use std::iter::FromIterator;
    ///
    /// let header_frame = vec![
    ///     Header::new(b":status", b"200"),
    ///     Header::new(b"hello", b"world"),
    ///     Header::new(b"hello", b"super-earth"),
    /// ];
    ///
    /// let enriched = H3iFrame::Headers(header_frame.into())
    ///     .to_enriched_headers()
    ///     .unwrap();
    ///
    /// let expected = MultiMap::from_iter([
    ///     (b":status".to_vec(), vec![b"200".to_vec()]),
    ///     (b"hello".to_vec(), vec![
    ///         b"world".to_vec(),
    ///         b"super-earth".to_vec(),
    ///     ]),
    /// ]);
    ///
    /// assert_eq!(*enriched.header_map(), expected);
    /// ```
    pub fn header_map(&self) -> &HeaderMap {
        &self.header_map
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
    /// let headers = EnrichedHeaders::from(vec![Header::new(b":status", b"200")]);
    /// assert_eq!(headers.status_code().expect("status code is Some"), b"200");
    /// ```
    pub fn status_code(&self) -> Option<&Vec<u8>> {
        self.header_map.get(b":status".as_slice())
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

        let mut header_map: HeaderMap = MultiMap::with_capacity(headers.len());
        for header in headers.iter() {
            header_map.insert(header.name().to_vec(), header.value().to_vec());
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

impl Serialize for SerializableQFrame<'_> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let name = frame_name(self.0);
        match self.0 {
            QFrame::Data { payload } => {
                let mut state = s.serialize_struct(name, 2)?;
                let max = cmp::min(payload.len(), MAX_SERIALIZED_BUFFER_LEN);
                state.serialize_field("payload_len", &payload.len())?;
                state.serialize_field(
                    "payload",
                    &qlog::HexSlice::maybe_string(Some(&payload[..max])),
                )?;
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
                let mut state = s.serialize_struct(name, 3)?;
                state.serialize_field(
                    "prioritized_element_id",
                    &prioritized_element_id,
                )?;

                let max = cmp::min(
                    priority_field_value.len(),
                    MAX_SERIALIZED_BUFFER_LEN,
                );
                state.serialize_field(
                    "priority_field_value_len",
                    &priority_field_value.len(),
                )?;
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
                let mut state = s.serialize_struct(name, 3)?;
                state.serialize_field(
                    "prioritized_element_id",
                    &prioritized_element_id,
                )?;
                let max = cmp::min(
                    priority_field_value.len(),
                    MAX_SERIALIZED_BUFFER_LEN,
                );
                state.serialize_field(
                    "priority_field_value_len",
                    &priority_field_value.len(),
                )?;
                state.serialize_field(
                    "priority_field_value",
                    &String::from_utf8_lossy(&priority_field_value[..max]),
                )?;
                state.end()
            },

            QFrame::Unknown { raw_type, payload } => {
                let mut state = s.serialize_struct(name, 3)?;
                state.serialize_field("raw_type", &raw_type)?;
                let max = cmp::min(payload.len(), MAX_SERIALIZED_BUFFER_LEN);
                state.serialize_field("payload_len", &payload.len())?;
                state.serialize_field(
                    "payload",
                    &qlog::HexSlice::maybe_string(Some(&payload[..max])),
                )?;
                state.end()
            },
        }
    }
}

type CustomEquivalenceHandler =
    Box<dyn for<'f> Fn(&'f H3iFrame) -> bool + Send + Sync + 'static>;

#[derive(Clone)]
enum Comparator {
    Frame(H3iFrame),
    /// Specifies how to compare an incoming [`H3iFrame`] with this
    /// [`CloseTriggerFrame`]. Typically, the validation attempts to fuzzy-match
    /// the [`CloseTriggerFrame`] against the incoming [`H3iFrame`], but there
    /// are times where other behavior is desired (for example, checking
    /// deserialized JSON payloads in a headers frame, or ensuring a random
    /// value matches a regex).
    ///
    /// See [`CloseTriggerFrame::is_equivalent`] for more on how frames are
    /// compared.
    Fn(Arc<CustomEquivalenceHandler>),
}

impl Serialize for Comparator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Fn(_) => serializer.serialize_str("<comparator_fn>"),
            Self::Frame(f) => {
                let mut frame_ser = serializer.serialize_struct("frame", 1)?;
                frame_ser.serialize_field("frame", f)?;
                frame_ser.end()
            },
        }
    }
}

/// Instructs h3i to watch for certain incoming [`H3iFrame`]s. The incoming
/// frames can either be supplied directly via [`CloseTriggerFrame::new`], or
/// via a verification callback  passed to
/// [`CloseTriggerFrame::new_with_comparator`].
#[derive(Serialize, Clone)]
pub struct CloseTriggerFrame {
    stream_id: u64,
    comparator: Comparator,
}

impl CloseTriggerFrame {
    /// Create a new [`CloseTriggerFrame`] which should watch for the provided
    /// [`H3iFrame`].
    ///
    /// # Note
    ///
    /// For [QuicheH3] and [ResetStream] variants, equivalence is the same as
    /// equality.
    ///
    /// For Headers variants, this [`CloseTriggerFrame`] is equivalent to the
    /// incoming [`H3iFrame`] if the [`H3iFrame`] contains all [`Header`]s
    /// in _this_ frame. In other words, `this` can be considered equivalent
    /// to `other` if `other` contains a superset of `this`'s [`Header`]s.
    ///
    /// This allows users for fuzzy-matching on header frames without needing to
    /// supply every individual header on the frame.
    ///
    /// [ResetStream]: H3iFrame::ResetStream
    /// [QuicheH3]: H3iFrame::QuicheH3
    pub fn new(stream_id: u64, frame: impl Into<H3iFrame>) -> Self {
        Self {
            stream_id,
            comparator: Comparator::Frame(frame.into()),
        }
    }

    /// Create a new [`CloseTriggerFrame`] which will match incoming
    /// [`H3iFrame`]s according to the passed `comparator_fn`.
    ///
    /// The `comparator_fn` will be called with every incoming [`H3iFrame`]. It
    /// should return `true` if the incoming frame is expected, and `false`
    /// if it is not.
    pub fn new_with_comparator<F>(stream_id: u64, comparator_fn: F) -> Self
    where
        F: Fn(&H3iFrame) -> bool + Send + Sync + 'static,
    {
        Self {
            stream_id,
            comparator: Comparator::Fn(Arc::new(Box::new(comparator_fn))),
        }
    }

    pub(crate) fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub(crate) fn is_equivalent(&self, other: &H3iFrame) -> bool {
        let frame = match &self.comparator {
            Comparator::Fn(compare) => return compare(other),
            Comparator::Frame(frame) => frame,
        };

        match frame {
            H3iFrame::Headers(me) => {
                let H3iFrame::Headers(other) = other else {
                    return false;
                };

                // TODO(evanrittenhouse): we could theoretically hand-roll a
                // MultiMap which uses a HashSet as the
                // multi-value collection, but in practice we don't expect very
                // many headers on an CloseTriggerFrame
                //
                // ref: https://docs.rs/multimap/latest/src/multimap/lib.rs.html#89
                me.headers().iter().all(|m| other.headers().contains(m))
            },
            H3iFrame::QuicheH3(me) => match other {
                H3iFrame::QuicheH3(other) => me == other,
                _ => false,
            },
            H3iFrame::ResetStream(me) => match other {
                H3iFrame::ResetStream(rs) => me == rs,
                _ => false,
            },
        }
    }
}

impl Debug for CloseTriggerFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match &self.comparator {
            Comparator::Frame(frame) => format!("{frame:?}"),
            Comparator::Fn(_) => "closure".to_string(),
        };

        write!(
            f,
            "CloseTriggerFrame {{ stream_id: {}, comparator: {repr} }}",
            self.stream_id
        )
    }
}

impl PartialEq for CloseTriggerFrame {
    fn eq(&self, other: &Self) -> bool {
        match (&self.comparator, &other.comparator) {
            (Comparator::Frame(this_frame), Comparator::Frame(other_frame)) =>
                self.stream_id == other.stream_id && this_frame == other_frame,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::frame::Frame;

    #[test]
    fn test_header_equivalence() {
        let this = CloseTriggerFrame::new(0, vec![
            Header::new(b"hello", b"world"),
            Header::new(b"go", b"jets"),
        ]);
        let other: H3iFrame = vec![
            Header::new(b"hello", b"world"),
            Header::new(b"go", b"jets"),
            Header::new(b"go", b"devils"),
        ]
        .into();

        assert!(this.is_equivalent(&other));
    }

    #[test]
    fn test_header_non_equivalence() {
        let this = CloseTriggerFrame::new(0, vec![
            Header::new(b"hello", b"world"),
            Header::new(b"go", b"jets"),
            Header::new(b"go", b"devils"),
        ]);
        let other: H3iFrame =
            vec![Header::new(b"hello", b"world"), Header::new(b"go", b"jets")]
                .into();

        // `other` does not contain the `go: devils` header, so it's not
        // equivalent to `this.
        assert!(!this.is_equivalent(&other));
    }

    #[test]
    fn test_rst_stream_equivalence() {
        let mut rs = ResetStream {
            stream_id: 0,
            error_code: 57,
        };

        let this = CloseTriggerFrame::new(0, H3iFrame::ResetStream(rs.clone()));
        let incoming = H3iFrame::ResetStream(rs.clone());
        assert!(this.is_equivalent(&incoming));

        rs.stream_id = 57;
        let incoming = H3iFrame::ResetStream(rs);
        assert!(!this.is_equivalent(&incoming));
    }

    #[test]
    fn test_frame_equivalence() {
        let mut d = Frame::Data {
            payload: b"57".to_vec(),
        };

        let this = CloseTriggerFrame::new(0, H3iFrame::QuicheH3(d.clone()));
        let incoming = H3iFrame::QuicheH3(d.clone());
        assert!(this.is_equivalent(&incoming));

        d = Frame::Data {
            payload: b"go jets".to_vec(),
        };
        let incoming = H3iFrame::QuicheH3(d.clone());
        assert!(!this.is_equivalent(&incoming));
    }

    #[test]
    fn test_comparator() {
        let this = CloseTriggerFrame::new_with_comparator(0, |frame| {
            if let H3iFrame::Headers(..) = frame {
                frame
                    .to_enriched_headers()
                    .unwrap()
                    .header_map()
                    .get(&b"cookie".to_vec())
                    .is_some_and(|v| {
                        std::str::from_utf8(v)
                            .map(|s| s.to_lowercase())
                            .unwrap()
                            .contains("cookie")
                    })
            } else {
                false
            }
        });

        let incoming: H3iFrame =
            vec![Header::new(b"cookie", b"SomeRandomCookie1234")].into();

        assert!(this.is_equivalent(&incoming));
    }
}
