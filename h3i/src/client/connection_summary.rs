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

//! Summarizes events that occurred during a connection.

use quiche;
use quiche::Connection;
use quiche::ConnectionError;
use quiche::PathStats;
use quiche::Stats;
use serde::ser::SerializeStruct;
use serde::ser::Serializer;
use serde::Serialize;
use std::cmp;
use std::collections::HashMap;

use crate::frame::EnrichedHeaders;
use crate::frame::H3iFrame;

/// Maximum length of any serialized element's unstructured data such as reason
/// phrase.
pub const MAX_SERIALIZED_BUFFER_LEN: usize = 16384;

/// A summary of all frames received on a connection. There are some extra
/// fields included to provide additional context into the connection's
/// behavior.
#[derive(Default, Debug)]
pub struct ConnectionSummary {
    pub stream_map: StreamMap,
    /// L4 statistics received from the connection.
    pub stats: Option<Stats>,
    /// Statistics about all paths of the connection.
    pub path_stats: Vec<PathStats>,
    /// Details about why the connection closed.
    pub conn_close_details: ConnectionCloseDetails,
}

impl Serialize for ConnectionSummary {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("path_stats", 4)?;
        state.serialize_field("stream_map", &self.stream_map)?;
        state.serialize_field(
            "stats",
            &self.stats.as_ref().map(SerializableStats),
        )?;
        let p: Vec<SerializablePathStats> =
            self.path_stats.iter().map(SerializablePathStats).collect();
        state.serialize_field("path_stats", &p)?;
        state.serialize_field("error", &self.conn_close_details)?;
        state.end()
    }
}

/// An aggregation of frames received over a connection, mapped to the stream ID
/// over which they were received.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StreamMap(HashMap<u64, Vec<H3iFrame>>);

impl From<HashMap<u64, Vec<H3iFrame>>> for StreamMap {
    fn from(value: HashMap<u64, Vec<H3iFrame>>) -> Self {
        Self(value)
    }
}

impl StreamMap {
    /// Flatten all received frames into a single vector. The ordering is
    /// non-deterministic.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    /// stream_map.insert(0, headers.clone());
    ///
    /// assert_eq!(stream_map.all_frames(), vec![headers]);
    /// ```
    pub fn all_frames(&self) -> Vec<H3iFrame> {
        self.0
            .values()
            .flatten()
            .map(Clone::clone)
            .collect::<Vec<H3iFrame>>()
    }

    /// Get all frames on a given `stream_id`.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    /// stream_map.insert(0, headers.clone());
    ///
    /// assert_eq!(stream_map.stream(0), vec![headers]);
    /// ```
    pub fn stream(&self, stream_id: u64) -> Vec<H3iFrame> {
        self.0.get(&stream_id).cloned().unwrap_or_default()
    }

    /// Insert a new [`H3iFrame`] into the stream map on a given stream.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// use std::collections::HashMap;
    /// use std::iter::FromIterator;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    /// stream_map.insert(0, headers.clone());
    ///
    /// assert_eq!(stream_map.stream(0), vec![headers]);
    /// ```
    pub fn insert(&mut self, k: u64, v: H3iFrame) {
        self.0.entry(k).or_default().push(v)
    }

    /// Check if a provided [`H3iFrame`] was received, regardless of what stream
    /// it was received on.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    /// stream_map.insert(0, headers.clone());
    ///
    /// assert!(stream_map.received_frame(&headers));
    /// ```
    pub fn received_frame(&self, frame: &H3iFrame) -> bool {
        self.all_frames().contains(frame)
    }

    /// Check if a provided [`H3iFrame`] was received over a specified stream.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    /// stream_map.insert(0, headers.clone());
    ///
    /// assert!(stream_map.received_frame_on_stream(0, &headers));
    /// ```
    pub fn received_frame_on_stream(
        &self, stream: u64, frame: &H3iFrame,
    ) -> bool {
        self.0.get(&stream).map(|v| v.contains(frame)).is_some()
    }

    /// Check if the stream map is empty, e.g., no frames were received.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// let mut stream_map = StreamMap::default();
    /// assert!(stream_map.is_empty());
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    /// stream_map.insert(0, headers.clone());
    ///
    /// assert!(!stream_map.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// See all HEADERS received on a given stream.
    ///
    /// # Example
    ///
    /// ```
    /// use h3i::client::connection_summary::StreamMap;
    /// use h3i::frame::EnrichedHeaders;
    /// use h3i::frame::H3iFrame;
    /// use quiche::h3::Header;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let enriched = EnrichedHeaders::from(vec![h]);
    /// let headers = H3iFrame::Headers(enriched.clone());
    /// let data = H3iFrame::QuicheH3(quiche::h3::frame::Frame::Data {
    ///     payload: b"hello world".to_vec(),
    /// });
    /// stream_map.insert(0, headers.clone());
    /// stream_map.insert(0, data);
    ///
    /// assert_eq!(stream_map.headers_on_stream(0), vec![enriched]);
    /// ```
    pub fn headers_on_stream(&self, stream_id: u64) -> Vec<EnrichedHeaders> {
        self.stream(stream_id)
            .into_iter()
            .filter_map(|h3i_frame| h3i_frame.to_enriched_headers())
            .collect()
    }
}

/// Denotes why the connection was closed.
#[derive(Debug, Default)]
pub struct ConnectionCloseDetails {
    peer_error: Option<ConnectionError>,
    local_error: Option<ConnectionError>,
    /// If the connection timed out.
    pub timed_out: bool,
}

impl ConnectionCloseDetails {
    pub fn new(qconn: &Connection) -> Self {
        Self {
            peer_error: qconn.peer_error().cloned(),
            local_error: qconn.local_error().cloned(),
            timed_out: qconn.is_timed_out(),
        }
    }

    /// The error sent from the peer, if any.
    pub fn peer_error(&self) -> Option<&ConnectionError> {
        self.peer_error.as_ref()
    }

    /// The error generated locally, if any.
    pub fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    /// If the connection didn't see an error, either one from the peer or
    /// generated locally.
    pub fn no_err(&self) -> bool {
        self.peer_error.is_none() && self.local_error.is_none()
    }
}

impl Serialize for ConnectionCloseDetails {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state: <S as Serializer>::SerializeStruct =
            s.serialize_struct("enriched_connection_error", 3)?;
        if let Some(pe) = &self.peer_error {
            state.serialize_field(
                "peer_error",
                &SerializableConnectionError(pe),
            )?;
        }

        if let Some(le) = &self.local_error {
            state.serialize_field(
                "local_error",
                &SerializableConnectionError(le),
            )?;
        }

        state.serialize_field("timed_out", &self.timed_out)?;
        state.end()
    }
}

// Only applicable to async client
#[doc(hidden)]
/// A record that will be inserted into the [ConnectionSummary].
pub enum ConnectionRecord {
    StreamedFrame { stream_id: u64, frame: H3iFrame },
    ConnectionStats(Stats),
    PathStats(Vec<PathStats>),
    Close(ConnectionCloseDetails),
}

/// A wrapper to help serialize [quiche::PathStats]
pub struct SerializablePathStats<'a>(&'a quiche::PathStats);

impl<'a> Serialize for SerializablePathStats<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("path_stats", 17)?;
        state.serialize_field("local_addr", &self.0.local_addr)?;
        state.serialize_field("peer_addr", &self.0.peer_addr)?;
        state.serialize_field("active", &self.0.active)?;
        state.serialize_field("recv", &self.0.recv)?;
        state.serialize_field("sent", &self.0.sent)?;
        state.serialize_field("lost", &self.0.lost)?;
        state.serialize_field("retrans", &self.0.retrans)?;
        state.serialize_field("rtt", &self.0.rtt.as_secs_f64())?;
        state.serialize_field(
            "min_rtt",
            &self.0.min_rtt.map(|x| x.as_secs_f64()),
        )?;
        state.serialize_field("rttvar", &self.0.rttvar.as_secs_f64())?;
        state.serialize_field("cwnd", &self.0.cwnd)?;
        state.serialize_field("sent_bytes", &self.0.sent_bytes)?;
        state.serialize_field("recv_bytes", &self.0.recv_bytes)?;
        state.serialize_field("lost_bytes", &self.0.lost_bytes)?;
        state.serialize_field(
            "stream_retrans_bytes",
            &self.0.stream_retrans_bytes,
        )?;
        state.serialize_field("pmtu", &self.0.pmtu)?;
        state.serialize_field("delivery_rate", &self.0.delivery_rate)?;
        state.end()
    }
}

/// A wrapper to help serialize [quiche::Stats]
pub struct SerializableStats<'a>(&'a quiche::Stats);

impl<'a> Serialize for SerializableStats<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("path_stats", 14)?;
        state.serialize_field("recv", &self.0.recv)?;
        state.serialize_field("sent", &self.0.sent)?;
        state.serialize_field("lost", &self.0.lost)?;
        state.serialize_field("retrans", &self.0.retrans)?;
        state.serialize_field("sent_bytes", &self.0.sent_bytes)?;
        state.serialize_field("recv_bytes", &self.0.recv_bytes)?;
        state.serialize_field("lost_bytes", &self.0.lost_bytes)?;
        state.serialize_field(
            "stream_retrans_bytes",
            &self.0.stream_retrans_bytes,
        )?;
        state.serialize_field("paths_count", &self.0.paths_count)?;
        state.serialize_field(
            "reset_stream_count_local",
            &self.0.reset_stream_count_local,
        )?;
        state.serialize_field(
            "stopped_stream_count_local",
            &self.0.stopped_stream_count_local,
        )?;
        state.serialize_field(
            "reset_stream_count_remote",
            &self.0.reset_stream_count_remote,
        )?;
        state.serialize_field(
            "stopped_stream_count_remote",
            &self.0.stopped_stream_count_remote,
        )?;
        state.serialize_field(
            "path_challenge_rx_count",
            &self.0.path_challenge_rx_count,
        )?;
        state.end()
    }
}

/// A wrapper to help serialize a [quiche::ConnectionError]
pub struct SerializableConnectionError<'a>(&'a quiche::ConnectionError);

impl<'a> Serialize for SerializableConnectionError<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("path_stats", 3)?;
        state.serialize_field("is_app", &self.0.is_app)?;
        state.serialize_field("error_code", &self.0.error_code)?;
        let max = cmp::min(self.0.reason.len(), MAX_SERIALIZED_BUFFER_LEN);
        state.serialize_field(
            "reason",
            &String::from_utf8_lossy(&self.0.reason[..max]),
        )?;
        state.end()
    }
}
