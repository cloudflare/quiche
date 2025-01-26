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
use std::iter::FromIterator;

use crate::frame::CloseTriggerFrame;
use crate::frame::EnrichedHeaders;
use crate::frame::H3iFrame;

/// Maximum length of any serialized element's unstructured data such as reason
/// phrase.
pub const MAX_SERIALIZED_BUFFER_LEN: usize = 16384;

/// A summary of all frames received on a connection. There are some extra
/// fields included to provide additional context into the connection's
/// behavior.
///
/// ConnectionSummary implements [Serialize]. HTTP/3 frames that contain binary
/// payload are serialized using the qlog
/// [hexstring](https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-10.html#section-1.2)
/// format - "an even-length lowercase string of hexadecimally encoded bytes
/// examples: 82dc, 027339, 4cdbfd9bf0"
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
        state.serialize_field(
            "missed_close_trigger_frames",
            &self.stream_map.missing_close_trigger_frames(),
        )?;
        state.end()
    }
}

/// A read-only aggregation of frames received over a connection, mapped to the
/// stream ID over which they were received.
///
/// [`StreamMap`] also contains the [`CloseTriggerFrames`] for the connection so
/// that its state can be updated as new frames are received.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StreamMap {
    stream_frame_map: HashMap<u64, Vec<H3iFrame>>,
    close_trigger_frames: Option<CloseTriggerFrames>,
}

impl<T> From<T> for StreamMap
where
    T: IntoIterator<Item = (u64, Vec<H3iFrame>)>,
{
    fn from(value: T) -> Self {
        let stream_frame_map = HashMap::from_iter(value);

        Self {
            stream_frame_map,
            close_trigger_frames: None,
        }
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
    /// use std::iter::FromIterator;
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    ///
    /// let stream_map: StreamMap = [(0, vec![headers.clone()])].into();
    /// assert_eq!(stream_map.all_frames(), vec![headers]);
    /// ```
    pub fn all_frames(&self) -> Vec<H3iFrame> {
        self.stream_frame_map
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
    /// use std::iter::FromIterator;
    ///
    /// let mut stream_map = StreamMap::default();
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    ///
    /// let stream_map: StreamMap = [(0, vec![headers.clone()])].into();
    /// assert_eq!(stream_map.stream(0), vec![headers]);
    /// ```
    pub fn stream(&self, stream_id: u64) -> Vec<H3iFrame> {
        self.stream_frame_map
            .get(&stream_id)
            .cloned()
            .unwrap_or_default()
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
    /// use std::iter::FromIterator;
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    ///
    /// let stream_map: StreamMap = [(0, vec![headers.clone()])].into();
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
    /// use std::iter::FromIterator;
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    ///
    /// let stream_map: StreamMap = [(0, vec![headers.clone()])].into();
    /// assert!(stream_map.received_frame_on_stream(0, &headers));
    /// ```
    pub fn received_frame_on_stream(
        &self, stream: u64, frame: &H3iFrame,
    ) -> bool {
        self.stream_frame_map
            .get(&stream)
            .map(|v| v.contains(frame))
            .is_some()
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
    /// use std::iter::FromIterator;
    ///
    /// let mut stream_map = StreamMap::default();
    /// assert!(stream_map.is_empty());
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let headers = H3iFrame::Headers(EnrichedHeaders::from(vec![h]));
    ///
    /// let stream_map: StreamMap = [(0, vec![headers.clone()])].into();
    /// assert!(!stream_map.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.stream_frame_map.is_empty()
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
    /// use std::iter::FromIterator;
    ///
    /// let h = Header::new(b"hello", b"world");
    /// let enriched = EnrichedHeaders::from(vec![h]);
    /// let headers = H3iFrame::Headers(enriched.clone());
    /// let data = H3iFrame::QuicheH3(quiche::h3::frame::Frame::Data {
    ///     payload: b"hello world".to_vec(),
    /// });
    ///
    /// let stream_map: StreamMap = [(0, vec![headers.clone(), data.clone()])].into();
    /// assert_eq!(stream_map.headers_on_stream(0), vec![enriched]);
    /// ```
    pub fn headers_on_stream(&self, stream_id: u64) -> Vec<EnrichedHeaders> {
        self.stream(stream_id)
            .into_iter()
            .filter_map(|h3i_frame| h3i_frame.to_enriched_headers())
            .collect()
    }

    /// If all [`CloseTriggerFrame`]s were seen. If no triggers were expected,
    /// this will return `false`.
    pub fn all_close_trigger_frames_seen(&self) -> bool {
        if let Some(triggers) = self.close_trigger_frames.as_ref() {
            triggers.saw_all_trigger_frames()
        } else {
            false
        }
    }

    /// The set of all [`CloseTriggerFrame`]s that were _not_ seen on the
    /// connection. Returns `None` if
    pub fn missing_close_trigger_frames(&self) -> Option<Vec<CloseTriggerFrame>> {
        self.close_trigger_frames
            .as_ref()
            .map(|e| e.missing_triggers())
    }

    ///  Not `pub` as users aren't expected to build their own [`StreamMap`]s.
    pub(crate) fn new(close_trigger_frames: Option<CloseTriggerFrames>) -> Self {
        Self {
            close_trigger_frames,
            ..Default::default()
        }
    }

    pub(crate) fn insert(&mut self, stream_id: u64, frame: H3iFrame) {
        if let Some(expected) = self.close_trigger_frames.as_mut() {
            expected.receive_frame(stream_id, &frame);
        }

        self.stream_frame_map
            .entry(stream_id)
            .or_default()
            .push(frame);
    }

    /// Close a [`quiche::Connection`] with the CONNECTION_CLOSE frame specified
    /// by [`CloseTriggerFrames`]. If no [`CloseTriggerFrames`] exist, this is a
    /// no-op.
    pub(crate) fn close_due_to_trigger_frames(
        &self, qconn: &mut quiche::Connection,
    ) {
        if let Some(ConnectionError {
            is_app,
            error_code,
            reason,
        }) = self.close_trigger_frames.as_ref().map(|tf| &tf.close_with)
        {
            let _ = qconn.close(*is_app, *error_code, reason);
        }
    }
}

/// A container for frames that h3i expects to see over a given connection. If
/// h3i receives all the frames it expects, it will send a CONNECTION_CLOSE
/// frame to the server. This bypasses the idle timeout and vastly quickens test
/// suites which depend heavily on h3i.
///
/// The specific CONNECTION_CLOSE frame can be customized by passing a
/// [`ConnectionError`] to [`Self::new_with_connection_close`]. h3i will send an
/// application CONNECTION_CLOSE frame with error code 0x100 if this struct is
/// constructed with the [`Self::new`] constructor.
#[derive(Clone, Serialize, Debug)]
pub struct CloseTriggerFrames {
    missing: Vec<CloseTriggerFrame>,
    #[serde(skip)]
    close_with: ConnectionError,
}

impl CloseTriggerFrames {
    /// Create a new [`CloseTriggerFrames`]. If all expected frames are
    /// received, h3i will close the connection with an application-level
    /// CONNECTION_CLOSE frame with error code 0x100.
    pub fn new(frames: Vec<CloseTriggerFrame>) -> Self {
        Self::new_with_connection_close(frames, ConnectionError {
            is_app: true,
            error_code: quiche::h3::WireErrorCode::NoError as u64,
            reason: b"saw all close trigger frames".to_vec(),
        })
    }

    /// Create a new [`CloseTriggerFrames`] with a custom close frame. When all
    /// close trigger frames are received, h3i will close the connection with
    /// the level, error code, and reason from `close_with`.
    pub fn new_with_connection_close(
        frames: Vec<CloseTriggerFrame>, close_with: ConnectionError,
    ) -> Self {
        Self {
            missing: frames,
            close_with,
        }
    }

    fn receive_frame(&mut self, stream_id: u64, frame: &H3iFrame) {
        for (i, trigger) in self.missing.iter_mut().enumerate() {
            if trigger.is_equivalent(frame) && trigger.stream_id() == stream_id {
                self.missing.remove(i);
                break;
            }
        }
    }

    fn saw_all_trigger_frames(&self) -> bool {
        self.missing.is_empty()
    }

    fn missing_triggers(&self) -> Vec<CloseTriggerFrame> {
        self.missing.clone()
    }
}

impl From<Vec<CloseTriggerFrame>> for CloseTriggerFrames {
    fn from(value: Vec<CloseTriggerFrame>) -> Self {
        Self::new(value)
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

impl Serialize for SerializablePathStats<'_> {
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

impl Serialize for SerializableStats<'_> {
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
#[derive(Clone, Debug)]
pub struct SerializableConnectionError<'a>(&'a quiche::ConnectionError);

impl Serialize for SerializableConnectionError<'_> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::EnrichedHeaders;
    use quiche::h3::Header;

    fn h3i_frame() -> H3iFrame {
        vec![Header::new(b"hello", b"world")].into()
    }

    #[test]
    fn close_trigger_frame() {
        let frame = h3i_frame();
        let mut triggers = CloseTriggerFrames::new(vec![CloseTriggerFrame::new(
            0,
            frame.clone(),
        )]);

        triggers.receive_frame(0, &frame);

        assert!(triggers.saw_all_trigger_frames());
    }

    #[test]
    fn trigger_frame_missing() {
        let frame = h3i_frame();
        let expected_frames = vec![
            CloseTriggerFrame::new(0, frame.clone()),
            CloseTriggerFrame::new(4, frame.clone()),
            CloseTriggerFrame::new(8, vec![Header::new(b"go", b"jets")]),
        ];
        let mut expected = CloseTriggerFrames::new(expected_frames.clone());

        expected.receive_frame(0, &frame);

        assert!(!expected.saw_all_trigger_frames());
        assert_eq!(expected.missing_triggers(), expected_frames[1..].to_vec());
    }

    fn stream_map_data() -> Vec<H3iFrame> {
        let headers =
            H3iFrame::Headers(EnrichedHeaders::from(vec![Header::new(
                b"hello", b"world",
            )]));
        let data = H3iFrame::QuicheH3(quiche::h3::frame::Frame::Data {
            payload: b"hello world".to_vec(),
        });

        vec![headers, data]
    }

    #[test]
    fn test_stream_map_trigger_frames_with_none() {
        let stream_map: StreamMap = vec![(0, stream_map_data())].into();
        assert!(!stream_map.all_close_trigger_frames_seen());
    }

    #[test]
    fn test_stream_map_trigger_frames() {
        let data = stream_map_data();
        let mut stream_map = StreamMap::new(Some(
            vec![
                CloseTriggerFrame::new(0, data[0].clone()),
                CloseTriggerFrame::new(0, data[1].clone()),
            ]
            .into(),
        ));

        stream_map.insert(0, data[0].clone());
        assert!(!stream_map.all_close_trigger_frames_seen());
        assert_eq!(stream_map.missing_close_trigger_frames().unwrap(), vec![
            CloseTriggerFrame::new(0, data[1].clone())
        ]);
    }
}
