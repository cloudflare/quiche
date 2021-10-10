// Copyright (C) 2019, Cloudflare, Inc.
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

//! The qlog crate is an implementation of the qlog [main logging schema],
//! [QUIC event definitions], and [HTTP/3 and QPACK event definitions].
//! The crate provides a qlog data model that can be used for traces with
//! events. It supports serialization and deserialization but defers logging IO
//! choices to applications.
//!
//! The crate uses Serde for conversion between Rust and JSON.
//!
//! [main logging schema]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema
//! [QUIC event definitions]:
//! https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events.html
//! [HTTP/3 and QPACK event definitions]:
//! https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-h3-events.html
//!
//! Overview
//! ---------------
//! qlog is a hierarchical logging format, with a rough structure of:
//!
//! * Log
//!   * Trace(s)
//!     * Event(s)
//!
//! In practice, a single QUIC connection maps to a single Trace file with one
//! or more Events. Applications can decide whether to combine Traces from
//! different connections into the same Log.
//!
//! ## Traces
//!
//! A [`Trace`] contains metadata such as the [`VantagePoint`] of capture and
//! the [`Configuration`], and protocol event data in the [`Event`] array.
//!
//! ## Writing out logs
//! As events occur during the connection, the application appends them to the
//! trace. The qlog crate supports two modes of writing logs: the buffered mode
//! stores everything in memory and requires the application to serialize and
//! write the output, the streaming mode progressively writes serialized JSON
//! output to a writer designated by the application.
//!
//! ### Creating a Trace
//!
//! A typical application needs a single qlog [`Trace`] that it appends QUIC
//! and/or HTTP/3 events to:
//!
//! ```
//! let mut trace = qlog::Trace::new(
//!     qlog::VantagePoint {
//!         name: Some("Example client".to_string()),
//!         ty: qlog::VantagePointType::Client,
//!         flow: None,
//!     },
//!     Some("Example qlog trace".to_string()),
//!     Some("Example qlog trace description".to_string()),
//!     Some(qlog::Configuration {
//!         time_offset: Some(0.0),
//!         original_uris: None,
//!     }),
//!     None,
//! );
//! ```
//!
//! ## Adding events
//!
//! Qlog [`Event`] objects are added to [`qlog::Trace.events`].
//!
//! The following example demonstrates how to log a qlog QUIC `packet_sent`
//! event containing a single Crypto frame. It constructs the necessary elements
//! of the [`Event`], then appends it to the trace with [`push_event()`].
//!
//! ```
//! # let mut trace = qlog::Trace::new (
//! #     qlog::VantagePoint {
//! #         name: Some("Example client".to_string()),
//! #         ty: qlog::VantagePointType::Client,
//! #         flow: None,
//! #     },
//! #     Some("Example qlog trace".to_string()),
//! #     Some("Example qlog trace description".to_string()),
//! #     Some(qlog::Configuration {
//! #         time_offset: Some(0.0),
//! #         original_uris: None,
//! #     }),
//! #     None
//! # );
//!
//! let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
//! let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
//!
//! let pkt_hdr = qlog::events::quic::PacketHeader::new(
//!     qlog::events::quic::PacketType::Initial,
//!     0,                         // packet_number
//!     None,                      // flags
//!     None,                      // token
//!     None,                      // length
//!     Some(0x00000001),          // version
//!     Some(b"7e37e4dcc6682da8"), // scid
//!     Some(&dcid),
//! );
//!
//! let frames = vec![qlog::events::quic::QuicFrame::Crypto {
//!     offset: 0,
//!     length: 0,
//! }];
//!
//! let raw = qlog::events::RawInfo {
//!     length: Some(1251),
//!     payload_length: Some(1224),
//!     data: None,
//! };
//!
//! let event_data =
//!     qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
//!         header: pkt_hdr,
//!         frames: Some(frames),
//!         is_coalesced: None,
//!         retry_token: None,
//!         stateless_reset_token: None,
//!         supported_versions: None,
//!         raw: Some(raw),
//!         datagram_id: None,
//!     });
//!
//! trace.push_event(qlog::events::Event::with_time(0.0, event_data));
//! ```
//!
//! ### Serializing
//!
//! The qlog crate has only been tested with `serde_json`, however
//! other serializer targets might work.
//!
//! For example, serializing the trace created above:
//!
//! ```
//! # let mut trace = qlog::Trace::new (
//! #     qlog::VantagePoint {
//! #         name: Some("Example client".to_string()),
//! #         ty: qlog::VantagePointType::Client,
//! #         flow: None,
//! #     },
//! #     Some("Example qlog trace".to_string()),
//! #     Some("Example qlog trace description".to_string()),
//! #     Some(qlog::Configuration {
//! #         time_offset: Some(0.0),
//! #         original_uris: None,
//! #     }),
//! #     None
//! # );
//! serde_json::to_string_pretty(&trace).unwrap();
//! ```
//!
//! which would generate the following:
//!
//! ```ignore
//! {
//!   "vantage_point": {
//!     "name": "Example client",
//!     "type": "client"
//!   },
//!   "title": "Example qlog trace",
//!   "description": "Example qlog trace description",
//!   "configuration": {
//!     "time_offset": 0.0
//!   },
//!   "events": [
//!     [
//!       0,
//!       "transport",
//!       "packet_sent",
//!       {
//!         "header": {
//!           "packet_type": "initial",
//!           "packet_number": 0,
//!           "version": "1",
//!           "scil": 8,
//!           "dcil": 8,
//!           "scid": "7e37e4dcc6682da8",
//!           "dcid": "36ce104eee50101c"
//!         },
//!         "raw": {
//!             "length": 1251,
//!             "payload_length": 1224
//!         },
//!         "frames": [
//!           {
//!             "frame_type": "crypto",
//!             "offset": 0,
//!             "length": 100,
//!           }
//!         ]
//!       }
//!     ]
//!   ]
//! }
//! ```
//!
//! Streaming Mode
//! --------------
//!
//! Create the trace:
//!
//! ```
//! let mut trace = qlog::Trace::new(
//!     qlog::VantagePoint {
//!         name: Some("Example client".to_string()),
//!         ty: qlog::VantagePointType::Client,
//!         flow: None,
//!     },
//!     Some("Example qlog trace".to_string()),
//!     Some("Example qlog trace description".to_string()),
//!     Some(qlog::Configuration {
//!         time_offset: Some(0.0),
//!         original_uris: None,
//!     }),
//!     None,
//! );
//! ```
//! Create an object with the [`Write`] trait:
//!
//! ```
//! let mut file = std::fs::File::create("foo.qlog").unwrap();
//! ```
//!
//! Create a [`QlogStreamer`] and start serialization to foo.qlog
//! using [`start_log()`]:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some(0.0),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! let mut streamer = qlog::streamer::QlogStreamer::new(
//!     qlog::QLOG_VERSION.to_string(),
//!     Some("Example qlog".to_string()),
//!     Some("Example qlog description".to_string()),
//!     None,
//!     std::time::Instant::now(),
//!     trace,
//!     qlog::events::EventImportance::Base,
//!     Box::new(file),
//! );
//!
//! streamer.start_log().ok();
//! ```
//!
//! ### Adding simple events
//!
//! Once logging has started you can stream events. Simple events
//! can be written in one step using [`add_event()`]:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some(0.0),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::streamer::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     qlog::events::EventImportance::Base,
//! #     Box::new(file),
//! # );
//! let event_data = qlog::events::EventData::MetricsUpdated(
//!     qlog::events::quic::MetricsUpdated {
//!         min_rtt: Some(1.0),
//!         smoothed_rtt: Some(1.0),
//!         latest_rtt: Some(1.0),
//!         rtt_variance: Some(1.0),
//!         pto_count: Some(1),
//!         congestion_window: Some(1234),
//!         bytes_in_flight: Some(5678),
//!         ssthresh: None,
//!         packets_in_flight: None,
//!         pacing_rate: None,
//!     },
//! );
//!
//! let event = qlog::events::Event::with_time(0.0, event_data);
//! streamer.add_event(event).ok();
//! ```
//!
//! ### Adding events with frames
//! Some events contain optional arrays of QUIC frames. If the
//! event has `Some(Vec<QuicFrame>)`, even if it is empty, the
//! streamer enters a frame serializing mode that must be
//! finalized before other events can be logged.
//!
//! In this example, a `PacketSent` event is created with an
//! empty frame array and frames are written out later:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some(0.0),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::streamer::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     qlog::events::EventImportance::Base,
//! #     Box::new(file),
//! # );
//! let pkt_hdr = qlog::events::quic::PacketHeader::with_type(
//!     qlog::events::quic::PacketType::OneRtt,
//!     0,
//!     Some(0x00000001),
//!     Some(b"7e37e4dcc6682da8"),
//!     Some(b"36ce104eee50101c"),
//! );
//!
//! let event_data =
//!     qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
//!         header: pkt_hdr,
//!         frames: Some(vec![]),
//!         is_coalesced: None,
//!         retry_token: None,
//!         stateless_reset_token: None,
//!         supported_versions: None,
//!         raw: None,
//!         datagram_id: None,
//!     });
//!
//! let event = qlog::events::Event::with_time(0.0, event_data);
//!
//! streamer.add_event(event).ok();
//! ```
//!
//! In this example, the frames contained in the QUIC packet
//! are PING and PADDING. Each frame is written using the
//! [`add_frame()`] method. Frame writing is concluded with
//! [`finish_frames()`].
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some(0.0),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::streamer::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     qlog::events::EventImportance::Base,
//! #     Box::new(file),
//! # );
//!
//! let ping = qlog::events::quic::QuicFrame::Ping;
//! let padding = qlog::events::quic::QuicFrame::Padding;
//!
//! streamer.add_frame(ping, false).ok();
//! streamer.add_frame(padding, false).ok();
//!
//! streamer.finish_frames().ok();
//! ```
//!
//! Once all events have have been written, the log
//! can be finalized with [`finish_log()`]:
//!
//! ```
//! # let mut trace = qlog::Trace::new(
//! #    qlog::VantagePoint {
//! #        name: Some("Example client".to_string()),
//! #        ty: qlog::VantagePointType::Client,
//! #        flow: None,
//! #    },
//! #    Some("Example qlog trace".to_string()),
//! #    Some("Example qlog trace description".to_string()),
//! #    Some(qlog::Configuration {
//! #        time_offset: Some(0.0),
//! #        original_uris: None,
//! #    }),
//! #    None,
//! # );
//! # let mut file = std::fs::File::create("foo.qlog").unwrap();
//! # let mut streamer = qlog::streamer::QlogStreamer::new(
//! #     qlog::QLOG_VERSION.to_string(),
//! #     Some("Example qlog".to_string()),
//! #     Some("Example qlog description".to_string()),
//! #     None,
//! #     std::time::Instant::now(),
//! #     trace,
//! #     qlog::events::EventImportance::Base,
//! #     Box::new(file),
//! # );
//! streamer.finish_log().ok();
//! ```
//!
//! ### Serializing
//!
//! Serialization to JSON occurs as methods on the [`QlogStreamer`]
//! are called. No additional steps are required.
//!
//! [`Trace`]: struct.Trace.html
//! [`VantagePoint`]: struct.VantagePoint.html
//! [`Configuration`]: struct.Configuration.html
//! [`qlog::Trace.events`]: struct.Trace.html#structfield.events
//! [`push_event()`]: struct.Trace.html#method.push_event
//! [`packet_sent_min()`]: event/struct.Event.html#method.packet_sent_min
//! [`QuicFrame::crypto()`]: enum.QuicFrame.html#variant.Crypto
//! [`QlogStreamer`]: struct.QlogStreamer.html
//! [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
//! [`start_log()`]: struct.QlogStreamer.html#method.start_log
//! [`add_event()`]: struct.QlogStreamer.html#method.add_event
//! [`add_event_with_instant()`]: struct.QlogStreamer.html#method.add_event
//! [`add_frame()`]: struct.QlogStreamer.html#method.add_frame
//! [`finish_frames()`]: struct.QlogStreamer.html#method.finish_frames
//! [`finish_log()`]: struct.QlogStreamer.html#method.finish_log

use crate::events::quic::PacketHeader;
use crate::events::Event;

use serde::Deserialize;
use serde::Serialize;

/// A quiche qlog error.
#[derive(Debug)]
pub enum Error {
    /// There is no more work to do.
    Done,

    /// The operation cannot be completed because it was attempted
    /// in an invalid state.
    InvalidState,

    /// I/O error.
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

pub const QLOG_VERSION: &str = "draft-02";

/// A specialized [`Result`] type for quiche qlog operations.
///
/// This type is used throughout the public API for any operation that
/// can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
pub struct Qlog {
    pub qlog_version: String,
    pub qlog_format: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub summary: Option<String>,

    pub traces: Vec<Trace>,
}

impl Default for Qlog {
    fn default() -> Self {
        Qlog {
            qlog_version: QLOG_VERSION.to_string(),
            qlog_format: "JSON".to_string(),
            title: Some("Default qlog title".to_string()),
            description: Some("Default qlog description".to_string()),
            summary: Some("Default qlog title".to_string()),
            traces: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum ImportanceLogLevel {
    Core  = 0,
    Base  = 1,
    Extra = 2,
}

// We now commence data definitions heavily styled on the QLOG
// schema definition. Data is serialized using serde.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Trace {
    pub vantage_point: VantagePoint,
    pub title: Option<String>,
    pub description: Option<String>,

    pub configuration: Option<Configuration>,

    pub common_fields: Option<CommonFields>,

    pub events: Vec<Event>,
}

/// Helper functions for using a qlog trace.
impl Trace {
    /// Creates a new qlog trace
    pub fn new(
        vantage_point: VantagePoint, title: Option<String>,
        description: Option<String>, configuration: Option<Configuration>,
        common_fields: Option<CommonFields>,
    ) -> Self {
        Trace {
            vantage_point,
            title,
            description,
            configuration,
            common_fields,
            events: Vec::new(),
        }
    }

    pub fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }
}

pub type Bytes = String;

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct VantagePoint {
    pub name: Option<String>,

    #[serde(rename = "type")]
    pub ty: VantagePointType,

    pub flow: Option<VantagePointType>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum VantagePointType {
    Client,
    Server,
    Network,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Configuration {
    pub time_offset: Option<f64>,

    pub original_uris: Option<Vec<String>>,
    /* TODO
     * additionalUserSpecifiedProperty */
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct CommonFields {
    pub group_id: Option<String>,
    pub protocol_type: Option<String>,

    pub reference_time: Option<String>,
    /* TODO
     * additionalUserSpecifiedProperty */
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Retry,
    Resumption,
    StatelessReset,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Token {
    #[serde(rename(serialize = "type"))]
    pub ty: Option<TokenType>,

    pub length: Option<u32>,
    pub data: Option<Bytes>,

    pub details: Option<String>,
}

pub struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    pub fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }

    pub fn maybe_string<T>(data: Option<&'a T>) -> Option<String>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        data.map(|d| format!("{}", HexSlice::new(d)))
    }
}

impl<'a> std::fmt::Display for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[doc(hidden)]
pub mod testing {
    use super::*;
    use crate::events::quic::PacketType;

    pub fn make_pkt_hdr(packet_type: PacketType) -> PacketHeader {
        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];

        // Some(1251),
        // Some(1224),

        PacketHeader::new(
            packet_type,
            0,
            None,
            None,
            None,
            Some(0x0000_0001),
            Some(&scid),
            Some(&dcid),
        )
    }

    pub fn make_trace() -> Trace {
        Trace::new(
            VantagePoint {
                name: None,
                ty: VantagePointType::Server,
                flow: None,
            },
            Some("Quiche qlog trace".to_string()),
            Some("Quiche qlog trace description".to_string()),
            Some(Configuration {
                time_offset: Some(0.0),
                original_uris: None,
            }),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::quic::PacketSent;
    use crate::events::quic::PacketType;
    use crate::events::quic::QuicFrame;
    use crate::events::EventData;
    use crate::events::RawInfo;
    use testing::*;

    #[test]
    fn packet_sent_event_no_frames() {
        let log_string = r#"{
  "time": 0.0,
  "name": "transport:packet_sent",
  "data": {
    "header": {
      "packet_type": "initial",
      "packet_number": 0,
      "version": "1",
      "scil": 8,
      "dcil": 8,
      "scid": "7e37e4dcc6682da8",
      "dcid": "36ce104eee50101c"
    },
    "raw": {
      "length": 1251,
      "payload_length": 1224
    }
  }
}"#;

        let pkt_hdr = make_pkt_hdr(PacketType::Initial);
        let ev_data = EventData::PacketSent(PacketSent {
            header: pkt_hdr.clone(),
            frames: None,
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(RawInfo {
                length: Some(1251),
                payload_length: Some(1224),
                data: None,
            }),
            datagram_id: None,
        });

        let ev = Event::with_time(0.0, ev_data);

        assert_eq!(serde_json::to_string_pretty(&ev).unwrap(), log_string);
    }

    #[test]
    fn packet_sent_event_some_frames() {
        let log_string = r#"{
  "time": 0.0,
  "name": "transport:packet_sent",
  "data": {
    "header": {
      "packet_type": "initial",
      "packet_number": 0,
      "version": "1",
      "scil": 8,
      "dcil": 8,
      "scid": "7e37e4dcc6682da8",
      "dcid": "36ce104eee50101c"
    },
    "raw": {
      "length": 1251,
      "payload_length": 1224
    },
    "frames": [
      {
        "frame_type": "padding"
      },
      {
        "frame_type": "ping"
      },
      {
        "frame_type": "stream",
        "stream_id": 0,
        "offset": 0,
        "length": 100,
        "fin": true
      }
    ]
  }
}"#;

        let pkt_hdr = make_pkt_hdr(PacketType::Initial);

        let mut frames = Vec::new();
        frames.push(QuicFrame::Padding);
        frames.push(QuicFrame::Ping);
        frames.push(QuicFrame::Stream {
            stream_id: 0,
            offset: 0,
            length: 100,
            fin: true,
            raw: None,
        });

        let ev_data = EventData::PacketSent(PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(frames),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(RawInfo {
                length: Some(1251),
                payload_length: Some(1224),
                data: None,
            }),
            datagram_id: None,
        });

        let ev = Event::with_time(0.0, ev_data);
        assert_eq!(serde_json::to_string_pretty(&ev).unwrap(), log_string);
    }

    #[test]
    fn trace_no_events() {
        let log_string = r#"{
  "vantage_point": {
    "type": "server"
  },
  "title": "Quiche qlog trace",
  "description": "Quiche qlog trace description",
  "configuration": {
    "time_offset": 0.0
  },
  "events": []
}"#;

        let trace = make_trace();

        let serialized = serde_json::to_string_pretty(&trace).unwrap();
        assert_eq!(serialized, log_string);

        let deserialized: Trace = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, trace);
    }

    #[test]
    fn trace_single_transport_event() {
        let log_string = r#"{
  "vantage_point": {
    "type": "server"
  },
  "title": "Quiche qlog trace",
  "description": "Quiche qlog trace description",
  "configuration": {
    "time_offset": 0.0
  },
  "events": [
    {
      "time": 0.0,
      "name": "transport:packet_sent",
      "data": {
        "header": {
          "packet_type": "initial",
          "packet_number": 0,
          "version": "1",
          "scil": 8,
          "dcil": 8,
          "scid": "7e37e4dcc6682da8",
          "dcid": "36ce104eee50101c"
        },
        "raw": {
          "length": 1251,
          "payload_length": 1224
        },
        "frames": [
          {
            "frame_type": "stream",
            "stream_id": 0,
            "offset": 0,
            "length": 100,
            "fin": true
          }
        ]
      }
    }
  ]
}"#;

        let mut trace = make_trace();

        let pkt_hdr = make_pkt_hdr(PacketType::Initial);

        let frames = vec![QuicFrame::Stream {
            stream_id: 0,
            offset: 0,
            length: 100,
            fin: true,
            raw: None,
        }];
        let event_data = EventData::PacketSent(PacketSent {
            header: pkt_hdr,
            frames: Some(frames),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(RawInfo {
                length: Some(1251),
                payload_length: Some(1224),
                data: None,
            }),
            datagram_id: None,
        });

        let ev = Event::with_time(0.0, event_data);

        trace.push_event(ev);

        let serialized = serde_json::to_string_pretty(&trace).unwrap();
        assert_eq!(serialized, log_string);

        let deserialized: Trace = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, trace);
    }
}

pub mod events;
pub mod streamer;
