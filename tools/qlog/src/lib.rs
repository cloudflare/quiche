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
//! let pkt_hdr = qlog::PacketHeader::new(
//!     qlog::PacketType::Initial,
//!     0,                         // packet_number
//!     None,                      // flags
//!     None,                      // token
//!     None,                      // length
//!     Some(0x00000001),          // version
//!     Some(b"7e37e4dcc6682da8"), // scid
//!     Some(&dcid),
//! );
//!
//! let frames = vec![qlog::QuicFrame::Crypto {
//!     offset: 0,
//!     length: 0,
//! }];
//!
//! let raw = qlog::RawInfo {
//!     length: Some(1251),
//!     payload_length: Some(1224),
//!     data: None,
//! };
//!
//! let event_data = qlog::EventData::PacketSent {
//!     header: pkt_hdr,
//!     frames: Some(frames),
//!     is_coalesced: None,
//!     retry_token: None,
//!     stateless_reset_token: None,
//!     supported_versions: None,
//!     raw: Some(raw),
//!     datagram_id: None,
//! };
//!
//! trace.push_event(qlog::Event::with_time(0.0, event_data));
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
//!     qlog::EventImportance::Base,
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
//! #     qlog::EventImportance::Base,
//! #     Box::new(file),
//! # );
//! let event_data = qlog::EventData::MetricsUpdated {
//!     min_rtt: Some(1.0),
//!     smoothed_rtt: Some(1.0),
//!     latest_rtt: Some(1.0),
//!     rtt_variance: Some(1.0),
//!     pto_count: Some(1),
//!     congestion_window: Some(1234),
//!     bytes_in_flight: Some(5678),
//!     ssthresh: None,
//!     packets_in_flight: None,
//!     pacing_rate: None,
//! };
//!
//! let event = qlog::Event::with_time(0.0, event_data);
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
//! #     qlog::EventImportance::Base,
//! #     Box::new(file),
//! # );
//! let pkt_hdr = qlog::PacketHeader::with_type(
//!     qlog::PacketType::OneRtt,
//!     0,
//!     Some(0x00000001),
//!     Some(b"7e37e4dcc6682da8"),
//!     Some(b"36ce104eee50101c"),
//! );
//!
//! let event_data = qlog::EventData::PacketSent {
//!     header: pkt_hdr,
//!     frames: Some(vec![]),
//!     is_coalesced: None,
//!     retry_token: None,
//!     stateless_reset_token: None,
//!     supported_versions: None,
//!     raw: None,
//!     datagram_id: None,
//! };
//!
//! let event = qlog::Event::with_time(0.0, event_data);
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
//! #     qlog::EventImportance::Base,
//! #     Box::new(file),
//! # );
//!
//! let ping = qlog::QuicFrame::Ping;
//! let padding = qlog::QuicFrame::Padding;
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
//! #     qlog::EventImportance::Base,
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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(untagged)]
pub enum EventType {
    ConnectivityEventType(ConnectivityEventType),

    TransportEventType(TransportEventType),

    SecurityEventType(SecurityEventType),

    RecoveryEventType(RecoveryEventType),

    Http3EventType(Http3EventType),

    QpackEventType(QpackEventType),

    GenericEventType(GenericEventType),

    None,
}

impl Default for EventType {
    fn default() -> Self {
        EventType::None
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum TimeFormat {
    Absolute,
    Delta,
    Relative,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub time: f32,

    // Strictly, the qlog 02 spec says we should have a name field in the
    // `Event` structure. However, serde's autogenerated Deserialize code
    // struggles to read Events properly because the `EventData` types often
    // alias. In order to work around that, we use can use a trick that will
    // give serde autogen all the information that it needs while also produced
    // a legal qlog. Specifically, strongly linking an EventData enum variant
    // with the wire-format name.
    //
    // The trick is to use Adjacent Tagging
    // (https://serde.rs/enum-representations.html#adjacently-tagged) with
    // Struct flattening (https://serde.rs/attr-flatten.html). At a high level
    // this first creates an `EventData` JSON object:
    //
    // {name: <enum variant name>, data: enum variant data }
    //
    // and then flattens those fields into the `Event` object.
    #[serde(flatten)]
    pub data: EventData,

    pub protocol_type: Option<String>,
    pub group_id: Option<String>,

    pub time_format: Option<TimeFormat>,

    #[serde(skip)]
    ty: EventType,
}

impl Event {
    /// Returns a new `Event` object with the provided time and data.
    pub fn with_time(time: f32, data: EventData) -> Self {
        let ty = EventType::from(&data);
        Event {
            time,
            data,
            protocol_type: Default::default(),
            group_id: Default::default(),
            time_format: Default::default(),
            ty,
        }
    }

    fn importance(&self) -> EventImportance {
        self.ty.into()
    }
}

impl PartialEq for Event {
    // custom comparison to skip over the `ty` field
    fn eq(&self, other: &Event) -> bool {
        self.time == other.time &&
            self.data == other.data &&
            self.protocol_type == other.protocol_type &&
            self.group_id == other.group_id &&
            self.time_format == other.time_format
    }
}

#[derive(Clone)]
pub enum EventImportance {
    Core,
    Base,
    Extra,
}

impl EventImportance {
    /// Returns true if this importance level is included by `other`.
    pub fn is_contained_in(&self, other: &EventImportance) -> bool {
        match (other, self) {
            (EventImportance::Core, EventImportance::Core) => true,

            (EventImportance::Base, EventImportance::Core) |
            (EventImportance::Base, EventImportance::Base) => true,

            (EventImportance::Extra, EventImportance::Core) |
            (EventImportance::Extra, EventImportance::Base) |
            (EventImportance::Extra, EventImportance::Extra) => true,

            (..) => false,
        }
    }
}

impl From<EventType> for EventImportance {
    fn from(ty: EventType) -> Self {
        match ty {
            EventType::ConnectivityEventType(
                ConnectivityEventType::ServerListening,
            ) => EventImportance::Extra,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionStarted,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionIdUpdated,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::SpinBitUpdated,
            ) => EventImportance::Base,
            EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionStateUpdated,
            ) => EventImportance::Base,

            EventType::SecurityEventType(SecurityEventType::KeyUpdated) =>
                EventImportance::Base,
            EventType::SecurityEventType(SecurityEventType::KeyRetired) =>
                EventImportance::Base,

            EventType::TransportEventType(TransportEventType::ParametersSet) =>
                EventImportance::Core,
            EventType::TransportEventType(
                TransportEventType::DatagramsReceived,
            ) => EventImportance::Extra,
            EventType::TransportEventType(TransportEventType::DatagramsSent) =>
                EventImportance::Extra,
            EventType::TransportEventType(
                TransportEventType::DatagramDropped,
            ) => EventImportance::Extra,
            EventType::TransportEventType(TransportEventType::PacketReceived) =>
                EventImportance::Core,
            EventType::TransportEventType(TransportEventType::PacketSent) =>
                EventImportance::Core,
            EventType::TransportEventType(TransportEventType::PacketDropped) =>
                EventImportance::Base,
            EventType::TransportEventType(TransportEventType::PacketBuffered) =>
                EventImportance::Base,
            EventType::TransportEventType(
                TransportEventType::StreamStateUpdated,
            ) => EventImportance::Base,
            EventType::TransportEventType(
                TransportEventType::FramesProcessed,
            ) => EventImportance::Extra,
            EventType::TransportEventType(TransportEventType::DataMoved) =>
                EventImportance::Base,

            EventType::RecoveryEventType(RecoveryEventType::ParametersSet) =>
                EventImportance::Base,
            EventType::RecoveryEventType(RecoveryEventType::MetricsUpdated) =>
                EventImportance::Core,
            EventType::RecoveryEventType(
                RecoveryEventType::CongestionStateUpdated,
            ) => EventImportance::Base,
            EventType::RecoveryEventType(RecoveryEventType::LossTimerUpdated) =>
                EventImportance::Extra,
            EventType::RecoveryEventType(RecoveryEventType::PacketLost) =>
                EventImportance::Core,
            EventType::RecoveryEventType(
                RecoveryEventType::MarkedForRetransmit,
            ) => EventImportance::Extra,

            EventType::Http3EventType(Http3EventType::ParametersSet) =>
                EventImportance::Base,
            EventType::Http3EventType(Http3EventType::StreamTypeSet) =>
                EventImportance::Base,
            EventType::Http3EventType(Http3EventType::FrameCreated) =>
                EventImportance::Core,
            EventType::Http3EventType(Http3EventType::FrameParsed) =>
                EventImportance::Core,
            EventType::Http3EventType(Http3EventType::PushResolved) =>
                EventImportance::Extra,

            EventType::QpackEventType(QpackEventType::StateUpdated) =>
                EventImportance::Base,
            EventType::QpackEventType(QpackEventType::StreamStateUpdated) =>
                EventImportance::Base,
            EventType::QpackEventType(QpackEventType::DynamicTableUpdated) =>
                EventImportance::Extra,
            EventType::QpackEventType(QpackEventType::HeadersEncoded) =>
                EventImportance::Base,
            EventType::QpackEventType(QpackEventType::HeadersDecoded) =>
                EventImportance::Base,
            EventType::QpackEventType(QpackEventType::InstructionCreated) =>
                EventImportance::Base,
            EventType::QpackEventType(QpackEventType::InstructionParsed) =>
                EventImportance::Base,

            _ => unimplemented!(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Connectivity,
    Security,
    Transport,
    Recovery,
    Http,
    Qpack,

    Error,
    Warning,
    Info,
    Debug,
    Verbose,
    Simulation,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let v = match self {
            EventCategory::Connectivity => "connectivity",
            EventCategory::Security => "security",
            EventCategory::Transport => "transport",
            EventCategory::Recovery => "recovery",
            EventCategory::Http => "http",
            EventCategory::Qpack => "qpack",
            EventCategory::Error => "error",
            EventCategory::Warning => "warning",
            EventCategory::Info => "info",
            EventCategory::Debug => "debug",
            EventCategory::Verbose => "verbose",
            EventCategory::Simulation => "simulation",
        };

        write!(f, "{}", v)
    }
}

impl From<EventType> for EventCategory {
    fn from(ty: EventType) -> Self {
        match ty {
            EventType::ConnectivityEventType(_) => EventCategory::Connectivity,
            EventType::SecurityEventType(_) => EventCategory::Security,
            EventType::TransportEventType(_) => EventCategory::Transport,
            EventType::RecoveryEventType(_) => EventCategory::Recovery,
            EventType::Http3EventType(_) => EventCategory::Http,
            EventType::QpackEventType(_) => EventCategory::Qpack,

            _ => unimplemented!(),
        }
    }
}

impl From<&EventData> for EventType {
    fn from(event_data: &EventData) -> Self {
        match event_data {
            EventData::ServerListening { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ServerListening,
                ),
            EventData::ConnectionStarted { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionStarted,
                ),
            EventData::ConnectionClosed { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionClosed,
                ),
            EventData::ConnectionIdUpdated { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionIdUpdated,
                ),
            EventData::SpinBitUpdated { .. } => EventType::ConnectivityEventType(
                ConnectivityEventType::SpinBitUpdated,
            ),
            EventData::ConnectionStateUpdated { .. } =>
                EventType::ConnectivityEventType(
                    ConnectivityEventType::ConnectionStateUpdated,
                ),

            EventData::KeyUpdated { .. } =>
                EventType::SecurityEventType(SecurityEventType::KeyUpdated),
            EventData::KeyRetired { .. } =>
                EventType::SecurityEventType(SecurityEventType::KeyRetired),

            EventData::VersionInformation { .. } =>
                EventType::TransportEventType(
                    TransportEventType::VersionInformation,
                ),
            EventData::AlpnInformation { .. } =>
                EventType::TransportEventType(TransportEventType::AlpnInformation),
            EventData::TransportParametersSet { .. } =>
                EventType::TransportEventType(TransportEventType::ParametersSet),
            EventData::TransportParametersRestored { .. } =>
                EventType::TransportEventType(
                    TransportEventType::ParametersRestored,
                ),
            EventData::DatagramsReceived { .. } => EventType::TransportEventType(
                TransportEventType::DatagramsReceived,
            ),
            EventData::DatagramsSent { .. } =>
                EventType::TransportEventType(TransportEventType::DatagramsSent),
            EventData::DatagramDropped { .. } =>
                EventType::TransportEventType(TransportEventType::DatagramDropped),
            EventData::PacketReceived { .. } =>
                EventType::TransportEventType(TransportEventType::PacketReceived),
            EventData::PacketSent { .. } =>
                EventType::TransportEventType(TransportEventType::PacketSent),
            EventData::PacketDropped { .. } =>
                EventType::TransportEventType(TransportEventType::PacketDropped),
            EventData::PacketBuffered { .. } =>
                EventType::TransportEventType(TransportEventType::PacketBuffered),
            EventData::PacketsAcked { .. } =>
                EventType::TransportEventType(TransportEventType::PacketsAcked),
            EventData::StreamStateUpdated { .. } =>
                EventType::TransportEventType(
                    TransportEventType::StreamStateUpdated,
                ),
            EventData::FramesProcessed { .. } =>
                EventType::TransportEventType(TransportEventType::FramesProcessed),
            EventData::DataMoved { .. } =>
                EventType::TransportEventType(TransportEventType::DataMoved),

            EventData::RecoveryParametersSet { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::ParametersSet),
            EventData::MetricsUpdated { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::MetricsUpdated),
            EventData::CongestionStateUpdated { .. } =>
                EventType::RecoveryEventType(
                    RecoveryEventType::CongestionStateUpdated,
                ),
            EventData::LossTimerUpdated { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::LossTimerUpdated),
            EventData::PacketLost { .. } =>
                EventType::RecoveryEventType(RecoveryEventType::PacketLost),
            EventData::MarkedForRetransmit { .. } =>
                EventType::RecoveryEventType(
                    RecoveryEventType::MarkedForRetransmit,
                ),

            EventData::H3ParametersSet { .. } =>
                EventType::Http3EventType(Http3EventType::ParametersSet),
            EventData::H3ParametersRestored { .. } =>
                EventType::Http3EventType(Http3EventType::ParametersRestored),
            EventData::H3StreamTypeSet { .. } =>
                EventType::Http3EventType(Http3EventType::StreamTypeSet),
            EventData::H3FrameCreated { .. } =>
                EventType::Http3EventType(Http3EventType::FrameCreated),
            EventData::H3FrameParsed { .. } =>
                EventType::Http3EventType(Http3EventType::FrameParsed),
            EventData::H3PushResolved { .. } =>
                EventType::Http3EventType(Http3EventType::PushResolved),

            EventData::QpackStateUpdated { .. } =>
                EventType::QpackEventType(QpackEventType::StateUpdated),
            EventData::QpackStreamStateUpdated { .. } =>
                EventType::QpackEventType(QpackEventType::StreamStateUpdated),
            EventData::QpackDynamicTableUpdated { .. } =>
                EventType::QpackEventType(QpackEventType::DynamicTableUpdated),
            EventData::QpackHeadersEncoded { .. } =>
                EventType::QpackEventType(QpackEventType::HeadersEncoded),
            EventData::QpackHeadersDecoded { .. } =>
                EventType::QpackEventType(QpackEventType::HeadersDecoded),
            EventData::QpackInstructionCreated { .. } =>
                EventType::QpackEventType(QpackEventType::InstructionCreated),
            EventData::QpackInstructionParsed { .. } =>
                EventType::QpackEventType(QpackEventType::InstructionParsed),

            EventData::ConnectionError { .. } =>
                EventType::GenericEventType(GenericEventType::ConnectionError),
            EventData::ApplicationError { .. } =>
                EventType::GenericEventType(GenericEventType::ApplicationError),
            EventData::InternalError { .. } =>
                EventType::GenericEventType(GenericEventType::InternalError),
            EventData::InternalWarning { .. } =>
                EventType::GenericEventType(GenericEventType::InternalError),
            EventData::Message { .. } =>
                EventType::GenericEventType(GenericEventType::Message),
            EventData::Marker { .. } =>
                EventType::GenericEventType(GenericEventType::Marker),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityEventType {
    ServerListening,
    ConnectionStarted,
    ConnectionClosed,
    ConnectionIdUpdated,
    SpinBitUpdated,
    ConnectionStateUpdated,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventType {
    VersionInformation,
    AlpnInformation,

    ParametersSet,
    ParametersRestored,

    DatagramsSent,
    DatagramsReceived,
    DatagramDropped,

    PacketSent,
    PacketReceived,
    PacketDropped,
    PacketBuffered,
    PacketsAcked,

    FramesProcessed,

    StreamStateUpdated,

    DataMoved,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventTrigger {
    Line,
    Retransmit,
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    KeyUpdated,
    KeyRetired,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventTrigger {
    Tls,
    Implicit,
    RemoteUpdate,
    LocalUpdate,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventType {
    ParametersSet,
    MetricsUpdated,
    CongestionStateUpdated,
    LossTimerUpdated,
    PacketLost,
    MarkedForRetransmit,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventTrigger {
    AckReceived,
    PacketSent,
    Alarm,
    Unknown,
}

// ================================================================== //

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,

    ServerHandshakeSecret,
    ClientHandshakeSecret,

    Server0RttSecret,
    Client0RttSecret,

    Server1RttSecret,
    Client1RttSecret,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Attempted,
    Reset,
    Handshake,
    Active,
    Keepalive,
    Draining,
    Closed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PreferredAddress {
    pub ip_v4: String,
    pub ip_v6: String,

    pub port_v4: u16,
    pub port_v6: u16,

    pub connection_id: Bytes,
    pub stateless_reset_token: Token,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum LossTimerEventType {
    Set,
    Expired,
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    // bidirectional stream states, draft-23 3.4.
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,

    // sending-side stream states, draft-23 3.1.
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,

    // receive-side stream states, draft-23 3.2.
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,

    // both-side states
    DataReceived,

    // qlog-defined
    Destroyed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DataRecipient {
    User,
    Application,
    Transport,
    Network,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum H3Owner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum H3StreamType {
    Data,
    Control,
    Push,
    Reserved,
    QpackEncode,
    QpackDecode,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum H3PushDecision {
    Claimed,
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackStreamState {
    Blocked,
    Unblocked,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackUpdateType {
    Added,
    Evicted,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct QpackDynamicTableEntry {
    pub index: u64,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct QpackHeaderBlockPrefix {
    pub required_insert_count: u64,
    pub sign_bit: bool,
    pub delta_base: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct RawInfo {
    pub length: Option<u64>,
    pub payload_length: Option<u64>,

    pub data: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "name", content = "data")]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    // ================================================================== //
    // CONNECTIVITY
    #[serde(rename = "connectivity:server_listening")]
    ServerListening {
        ip_v4: Option<String>, // human-readable or bytes
        ip_v6: Option<String>, // human-readable or bytes
        port_v4: u32,
        port_v6: u32,

        retry_required: Option<bool>,
    },

    #[serde(rename = "connectivity:connection_started")]
    ConnectionStarted {
        ip_version: String, // "v4" or "v6"
        src_ip: String,     // human-readable or bytes
        dst_ip: String,     // human-readable or bytes

        protocol: Option<String>,
        src_port: u32,
        dst_port: u32,

        src_cid: Option<Bytes>,
        dst_cid: Option<Bytes>,
    },

    #[serde(rename = "connectivity:connection_closed")]
    ConnectionClosed {
        owner: Option<TransportOwner>,

        connection_code: Option<ConnectionErrorCode>,
        application_code: Option<ApplicationErrorCode>,
        internal_code: Option<u32>,

        reason: Option<String>,
    },

    #[serde(rename = "connectivity:connection_id_updated")]
    ConnectionIdUpdated {
        owner: Option<TransportOwner>,

        old: Option<Bytes>,
        new: Option<Bytes>,
    },

    #[serde(rename = "connectivity:spin_bit_updated")]
    SpinBitUpdated { state: bool },

    #[serde(rename = "connectivity:connection_state_updated")]
    ConnectionStateUpdated {
        old: Option<ConnectionState>,
        new: ConnectionState,
    },

    // ================================================================== //
    // SECURITY
    #[serde(rename = "security:connection_state_updated")]
    KeyUpdated {
        key_type: KeyType,
        old: Option<Bytes>,
        new: Bytes,
        generation: Option<u32>,
    },

    #[serde(rename = "security:connection_state_updated")]
    KeyRetired {
        key_type: KeyType,
        key: Option<Bytes>,
        generation: Option<u32>,
    },

    // ================================================================== //
    // TRANSPORT
    #[serde(rename = "transport:version_information")]
    VersionInformation {
        server_versions: Option<Vec<Bytes>>,
        client_versions: Option<Vec<Bytes>>,
        chosen_version: Option<Bytes>,
    },

    #[serde(rename = "transport:version_information")]
    AlpnInformation {
        server_alpns: Option<Vec<Bytes>>,
        client_alpns: Option<Vec<Bytes>>,
        chosen_alpn: Option<Bytes>,
    },

    #[serde(rename = "transport:parameters_set")]
    TransportParametersSet {
        owner: Option<TransportOwner>,

        resumption_allowed: Option<bool>,
        early_data_enabled: Option<bool>,
        tls_cipher: Option<String>,
        aead_tag_length: Option<u8>,

        original_destination_connection_id: Option<Bytes>,
        initial_source_connection_id: Option<Bytes>,
        retry_source_connection_id: Option<Bytes>,
        stateless_reset_token: Option<Token>,
        disable_active_migration: Option<bool>,

        max_idle_timeout: Option<u64>,
        max_udp_payload_size: Option<u32>,
        ack_delay_exponent: Option<u16>,
        max_ack_delay: Option<u16>,
        active_connection_id_limit: Option<u32>,

        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,

        preferred_address: Option<PreferredAddress>,
    },

    #[serde(rename = "transport:parameters_restored")]
    TransportParametersRestored {
        disable_active_migration: Option<bool>,

        max_idle_timeout: Option<u64>,
        max_udp_payload_size: Option<u32>,
        active_connection_id_limit: Option<u32>,

        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
    },

    #[serde(rename = "transport:datagrams_received")]
    DatagramsReceived {
        count: Option<u16>,

        raw: Option<Vec<RawInfo>>,

        datagram_ids: Option<Vec<u32>>,
    },

    #[serde(rename = "transport:datagrams_sent")]
    DatagramsSent {
        count: Option<u16>,

        raw: Option<Vec<RawInfo>>,

        datagram_ids: Option<Vec<u32>>,
    },

    #[serde(rename = "transport:datagram_dropped")]
    DatagramDropped { raw: Option<RawInfo> },

    #[serde(rename = "transport:packet_received")]
    PacketReceived {
        header: PacketHeader,
        // `frames` is defined here in the QLog schema specification. However,
        // our streaming serializer requires serde to put the object at the end,
        // so we define it there and depend on serde's preserve_order feature.
        is_coalesced: Option<bool>,

        retry_token: Option<Token>,

        stateless_reset_token: Option<Bytes>,

        supported_versions: Option<Vec<Bytes>>,

        raw: Option<RawInfo>,
        datagram_id: Option<u32>,

        frames: Option<Vec<QuicFrame>>,
    },

    #[serde(rename = "transport:packet_sent")]
    PacketSent {
        header: PacketHeader,
        // `frames` is defined here in the QLog schema specification. However,
        // our streaming serializer requires serde to put the object at the end,
        // so we define it there and depend on serde's preserve_order feature.
        is_coalesced: Option<bool>,

        retry_token: Option<Token>,

        stateless_reset_token: Option<Bytes>,

        supported_versions: Option<Vec<Bytes>>,

        raw: Option<RawInfo>,
        datagram_id: Option<u32>,

        frames: Option<Vec<QuicFrame>>,
    },

    #[serde(rename = "transport:packet_dropped")]
    PacketDropped {
        header: Option<PacketHeader>,

        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
    },

    #[serde(rename = "transport:packet_buffered")]
    PacketBuffered {
        header: Option<PacketHeader>,

        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
    },

    #[serde(rename = "transport:version_information")]
    PacketsAcked {
        packet_number_space: Option<PacketNumberSpace>,
        packet_numbers: Option<Vec<u64>>,
    },

    #[serde(rename = "transport:stream_state_updated")]
    StreamStateUpdated {
        stream_id: u64,
        stream_type: Option<StreamType>,

        old: Option<StreamState>,
        new: StreamState,

        stream_side: Option<StreamSide>,
    },

    #[serde(rename = "transport:frames_processed")]
    FramesProcessed {
        frames: Vec<QuicFrame>,

        packet_number: Option<u64>,
    },

    #[serde(rename = "transport:data_moved")]
    DataMoved {
        stream_id: Option<u64>,
        offset: Option<u64>,
        length: Option<u64>,

        from: Option<DataRecipient>,
        to: Option<DataRecipient>,

        data: Option<Bytes>,
    },

    // ================================================================== //
    // RECOVERY
    #[serde(rename = "recovery:parameters_set")]
    RecoveryParametersSet {
        reordering_threshold: Option<u16>,
        time_threshold: Option<f32>,
        timer_granularity: Option<u16>,
        initial_rtt: Option<f32>,

        max_datagram_size: Option<u32>,
        initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u32>,
        loss_reduction_factor: Option<f32>,
        persistent_congestion_threshold: Option<u16>,
    },

    #[serde(rename = "recovery:metrics_updated")]
    MetricsUpdated {
        min_rtt: Option<f32>,
        smoothed_rtt: Option<f32>,
        latest_rtt: Option<f32>,
        rtt_variance: Option<f32>,

        pto_count: Option<u16>,

        congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>,

        ssthresh: Option<u64>,

        // qlog defined
        packets_in_flight: Option<u64>,

        pacing_rate: Option<u64>,
    },

    #[serde(rename = "recovery:congestion_state_updated")]
    CongestionStateUpdated { old: Option<String>, new: String },

    #[serde(rename = "recovery:loss_timer_updated")]
    LossTimerUpdated {
        timer_type: Option<TimerType>,
        packet_number_space: Option<PacketNumberSpace>,

        event_type: LossTimerEventType,

        delta: Option<f32>,
    },

    #[serde(rename = "recovery:packet_lost")]
    PacketLost {
        header: Option<PacketHeader>,

        frames: Option<Vec<QuicFrame>>,
    },

    #[serde(rename = "recovery:marked_for_retransmit")]
    MarkedForRetransmit { frames: Vec<QuicFrame> },

    // ================================================================== //
    // HTTP/3
    #[serde(rename = "http:parameters_set")]
    H3ParametersSet {
        owner: Option<H3Owner>,

        max_header_list_size: Option<u64>,
        max_table_capacity: Option<u64>,
        blocked_streams_count: Option<u64>,

        // qlog-defined
        waits_for_settings: Option<bool>,
    },

    #[serde(rename = "http:parameters_restored")]
    H3ParametersRestored {
        max_header_list_size: Option<u64>,
        max_table_capacity: Option<u64>,
        blocked_streams_count: Option<u64>,
    },

    #[serde(rename = "http:stream_type_set")]
    H3StreamTypeSet {
        stream_id: u64,
        owner: Option<H3Owner>,

        old: Option<H3StreamType>,
        new: H3StreamType,

        associated_push_id: Option<u64>,
    },

    #[serde(rename = "http:frame_created")]
    H3FrameCreated {
        stream_id: u64,
        length: Option<u64>,
        frame: Http3Frame,

        raw: Option<RawInfo>,
    },

    #[serde(rename = "http:frame_parsed")]
    H3FrameParsed {
        stream_id: u64,
        length: Option<u64>,
        frame: Http3Frame,

        raw: Option<RawInfo>,
    },

    #[serde(rename = "http:push_resolved")]
    H3PushResolved {
        push_id: Option<u64>,
        stream_id: Option<u64>,

        decision: Option<H3PushDecision>,
    },

    // ================================================================== //
    // QPACK
    #[serde(rename = "qpack:state_updated")]
    QpackStateUpdated {
        owner: Option<QpackOwner>,

        dynamic_table_capacity: Option<u64>,
        dynamic_table_size: Option<u64>,

        known_received_count: Option<u64>,
        current_insert_count: Option<u64>,
    },

    #[serde(rename = "qpack:stream_state_updated")]
    QpackStreamStateUpdated {
        stream_id: u64,

        state: QpackStreamState,
    },

    #[serde(rename = "qpack:dynamic_table_updated")]
    QpackDynamicTableUpdated {
        update_type: QpackUpdateType,

        entries: Vec<QpackDynamicTableEntry>,
    },

    #[serde(rename = "qpack:headers_encoded")]
    QpackHeadersEncoded {
        stream_id: Option<u64>,

        headers: Option<HttpHeader>,

        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,

        length: Option<u32>,
        raw: Option<Bytes>,
    },

    #[serde(rename = "qpack:headers_decoded")]
    QpackHeadersDecoded {
        stream_id: Option<u64>,

        headers: Option<HttpHeader>,

        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,

        length: Option<u32>,
        raw: Option<Bytes>,
    },

    #[serde(rename = "qpack:instruction_created")]
    QpackInstructionCreated {
        instruction: QPackInstruction,

        length: Option<u32>,
        raw: Option<Bytes>,
    },

    #[serde(rename = "qpack:instruction_parsed")]
    QpackInstructionParsed {
        instruction: QPackInstruction,

        length: Option<u32>,
        raw: Option<Bytes>,
    },

    // ================================================================== //
    // Generic
    #[serde(rename = "generic:connection_error")]
    ConnectionError {
        code: Option<ConnectionErrorCode>,
        description: Option<String>,
    },

    #[serde(rename = "generic:application_error")]
    ApplicationError {
        code: Option<ApplicationErrorCode>,
        description: Option<String>,
    },

    #[serde(rename = "generic:internal_error")]
    InternalError {
        code: Option<u64>,
        description: Option<String>,
    },

    #[serde(rename = "generic:internal_warning")]
    InternalWarning {
        code: Option<u64>,
        description: Option<String>,
    },

    #[serde(rename = "generic:message")]
    Message { message: String },

    #[serde(rename = "generic:marker")]
    Marker {
        marker_type: String,
        message: Option<String>,
    },
}

impl EventData {
    /// Returns size of `EventData` array of `QuicFrame`s if it exists.
    pub fn contains_quic_frames(&self) -> Option<usize> {
        // For some EventData variants, the frame array is optional
        // but for others it is mandatory.
        match self {
            EventData::PacketSent { frames, .. } |
            EventData::PacketReceived { frames, .. } |
            EventData::PacketLost { frames, .. } =>
                frames.as_ref().map(|f| f.len()),

            EventData::MarkedForRetransmit { frames } |
            EventData::FramesProcessed { frames, .. } => Some(frames.len()),

            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,

    #[serde(rename = "0RTT")]
    ZeroRtt,

    #[serde(rename = "1RTT")]
    OneRtt,

    Retry,
    VersionNegotiation,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3EventType {
    ParametersSet,
    ParametersRestored,
    StreamTypeSet,
    FrameCreated,
    FrameParsed,
    PushResolved,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackEventType {
    StateUpdated,
    StreamStateUpdated,
    DynamicTableUpdated,
    HeadersEncoded,
    HeadersDecoded,
    InstructionCreated,
    InstructionParsed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QuicFrameTypeName {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    ApplicationClose,
    HandshakeDone,
    Datagram,
    Unknown,
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

// TODO: search for pub enum Error { to see how best to encode errors in qlog.
#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub packet_number: u64,

    pub flags: Option<u8>,
    pub token: Option<Token>,

    pub length: Option<u16>,

    pub version: Option<Bytes>,

    pub scil: Option<u8>,
    pub dcil: Option<u8>,
    pub scid: Option<Bytes>,
    pub dcid: Option<Bytes>,
}

impl PacketHeader {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new PacketHeader.
    pub fn new(
        packet_type: PacketType, packet_number: u64, flags: Option<u8>,
        token: Option<Token>, length: Option<u16>, version: Option<u32>,
        scid: Option<&[u8]>, dcid: Option<&[u8]>,
    ) -> Self {
        let (scil, scid) = match scid {
            Some(cid) => (
                Some(cid.len() as u8),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let (dcil, dcid) = match dcid {
            Some(cid) => (
                Some(cid.len() as u8),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let version = version.map(|v| format!("{:x?}", v));

        PacketHeader {
            packet_type,
            packet_number,
            flags,
            token,
            length,
            version,
            scil,
            dcil,
            scid,
            dcid,
        }
    }

    /// Creates a new PacketHeader.
    ///
    /// Once a QUIC connection has formed, version, dcid and scid are stable, so
    /// there are space benefits to not logging them in every packet, especially
    /// PacketType::OneRtt.
    pub fn with_type(
        ty: PacketType, packet_number: u64, version: Option<u32>,
        scid: Option<&[u8]>, dcid: Option<&[u8]>,
    ) -> Self {
        match ty {
            PacketType::OneRtt => PacketHeader::new(
                ty,
                packet_number,
                None,
                None,
                None,
                None,
                None,
                None,
            ),

            _ => PacketHeader::new(
                ty,
                packet_number,
                None,
                None,
                None,
                version,
                scid,
                dcid,
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    TransportError,
    ApplicationError,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GenericEventType {
    ConnectionError,
    ApplicationError,
    InternalError,
    InternalWarning,

    Message,
    Marker,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum ConnectionErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum ApplicationErrorCode {
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ServerBusy,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ProtocolViolation,
    InvalidMigration,
    CryptoBufferExceeded,
    Unknown,
}

// TODO
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CryptoError {
    Prefix,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationError {
    HttpNoError,
    HttpGeneralProtocolError,
    HttpInternalError,
    HttpRequestCancelled,
    HttpIncompleteRequest,
    HttpConnectError,
    HttpFrameError,
    HttpExcessiveLoad,
    HttpVersionFallback,
    HttpIdError,
    HttpStreamCreationError,
    HttpClosedCriticalStream,
    HttpEarlyResponse,
    HttpMissingSettings,
    HttpUnexpectedFrame,
    HttpRequestRejection,
    HttpSettingsError,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these frame types have a frame_type
// field. But instead of making that a rust object property, just use serde to
// ensure it goes out on the wire. This means that deserialization of frames
// also works automatically.
pub enum QuicFrame {
    Padding,

    Ping,

    Ack {
        ack_delay: Option<f32>,
        acked_ranges: Option<Vec<(u64, u64)>>,

        ect1: Option<u64>,

        ect0: Option<u64>,

        ce: Option<u64>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        offset: u64,
        length: u64,
    },

    NewToken {
        length: String,
        token: String,
    },

    Stream {
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: bool,

        raw: Option<Bytes>,
    },

    MaxData {
        maximum: u64,
    },

    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },

    MaxStreams {
        stream_type: StreamType,
        maximum: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlocked {
        stream_type: StreamType,
        limit: u64,
    },

    NewConnectionId {
        sequence_number: u32,
        retire_prior_to: u32,
        length: u64,
        connection_id: String,
        reset_token: String,
    },

    RetireConnectionId {
        sequence_number: u32,
    },

    PathChallenge {
        data: Option<Bytes>,
    },

    PathResponse {
        data: Option<Bytes>,
    },

    ConnectionClose {
        error_space: ErrorSpace,
        error_code: u64,
        raw_error_code: Option<u64>,
        reason: Option<String>,

        trigger_frame_type: Option<u64>,
    },

    HandshakeDone,

    Datagram {
        length: u64,

        raw: Option<Bytes>,
    },

    Unknown {
        raw_frame_type: u64,
    },
}

// ================================================================== //
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3FrameTypeName {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    DuplicatePush,
    Reserved,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Setting {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Http3Frame {
    Data {
        frame_type: Http3FrameTypeName,

        raw: Option<Bytes>,
    },

    Headers {
        frame_type: Http3FrameTypeName,
        headers: Vec<HttpHeader>,
    },

    CancelPush {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    Settings {
        frame_type: Http3FrameTypeName,
        settings: Vec<Setting>,
    },

    PushPromise {
        frame_type: Http3FrameTypeName,
        push_id: String,
        headers: Vec<HttpHeader>,
    },

    Goaway {
        frame_type: Http3FrameTypeName,
        stream_id: String,
    },

    MaxPushId {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    DuplicatePush {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    Reserved {
        frame_type: Http3FrameTypeName,
    },

    Unknown {
        frame_type: Http3FrameTypeName,
    },
}

impl Http3Frame {
    pub fn data(raw: Option<Bytes>) -> Self {
        Http3Frame::Data {
            frame_type: Http3FrameTypeName::Data,
            raw,
        }
    }

    pub fn headers(headers: Vec<HttpHeader>) -> Self {
        Http3Frame::Headers {
            frame_type: Http3FrameTypeName::Headers,
            headers,
        }
    }

    pub fn cancel_push(push_id: String) -> Self {
        Http3Frame::CancelPush {
            frame_type: Http3FrameTypeName::CancelPush,
            push_id,
        }
    }

    pub fn settings(settings: Vec<Setting>) -> Self {
        Http3Frame::Settings {
            frame_type: Http3FrameTypeName::Settings,
            settings,
        }
    }

    pub fn push_promise(push_id: String, headers: Vec<HttpHeader>) -> Self {
        Http3Frame::PushPromise {
            frame_type: Http3FrameTypeName::PushPromise,
            push_id,
            headers,
        }
    }

    pub fn goaway(stream_id: String) -> Self {
        Http3Frame::Goaway {
            frame_type: Http3FrameTypeName::Goaway,
            stream_id,
        }
    }

    pub fn max_push_id(push_id: String) -> Self {
        Http3Frame::MaxPushId {
            frame_type: Http3FrameTypeName::MaxPushId,
            push_id,
        }
    }

    pub fn duplicate_push(push_id: String) -> Self {
        Http3Frame::DuplicatePush {
            frame_type: Http3FrameTypeName::DuplicatePush,
            push_id,
        }
    }

    pub fn reserved() -> Self {
        Http3Frame::Reserved {
            frame_type: Http3FrameTypeName::Reserved,
        }
    }

    pub fn unknown() -> Self {
        Http3Frame::Unknown {
            frame_type: Http3FrameTypeName::Unknown,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackInstructionTypeName {
    SetDynamicTableCapacityInstruction,
    InsertWithNameReferenceInstruction,
    InsertWithoutNameReferenceInstruction,
    DuplicateInstruction,
    HeaderAcknowledgementInstruction,
    StreamCancellationInstruction,
    InsertCountIncrementInstruction,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackTableType {
    Static,
    Dynamic,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum QPackInstruction {
    SetDynamicTableCapacityInstruction {
        instruction_type: QpackInstructionTypeName,

        capacity: u64,
    },

    InsertWithNameReferenceInstruction {
        instruction_type: QpackInstructionTypeName,

        table_type: QpackTableType,

        name_index: u64,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,
    },

    InsertWithoutNameReferenceInstruction {
        instruction_type: QpackInstructionTypeName,

        huffman_encoded_name: bool,
        name_length: u64,
        name: String,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,
    },

    DuplicateInstruction {
        instruction_type: QpackInstructionTypeName,

        index: u64,
    },

    HeaderAcknowledgementInstruction {
        instruction_type: QpackInstructionTypeName,

        stream_id: String,
    },

    StreamCancellationInstruction {
        instruction_type: QpackInstructionTypeName,

        stream_id: String,
    },

    InsertCountIncrementInstruction {
        instruction_type: QpackInstructionTypeName,

        increment: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackHeaderBlockRepresentationTypeName {
    IndexedHeaderField,
    LiteralHeaderFieldWithName,
    LiteralHeaderFieldWithoutName,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum QpackHeaderBlockRepresentation {
    IndexedHeaderField {
        header_field_type: QpackHeaderBlockRepresentationTypeName,

        table_type: QpackTableType,
        index: u64,

        is_post_base: Option<bool>,
    },

    LiteralHeaderFieldWithName {
        header_field_type: QpackHeaderBlockRepresentationTypeName,

        preserve_literal: bool,
        table_type: QpackTableType,
        name_index: u64,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,

        is_post_base: Option<bool>,
    },

    LiteralHeaderFieldWithoutName {
        header_field_type: QpackHeaderBlockRepresentationTypeName,

        preserve_literal: bool,
        table_type: QpackTableType,
        name_index: u64,

        huffman_encoded_name: bool,
        name_length: u64,
        name: String,

        huffman_encoded_value: bool,
        value_length: u64,
        value: String,

        is_post_base: Option<bool>,
    },
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
    use testing::*;

    #[test]
    fn packet_header() {
        let pkt_hdr = make_pkt_hdr(PacketType::Initial);

        let log_string = r#"{
  "packet_type": "initial",
  "packet_number": 0,
  "version": "1",
  "scil": 8,
  "dcil": 8,
  "scid": "7e37e4dcc6682da8",
  "dcid": "36ce104eee50101c"
}"#;

        assert_eq!(serde_json::to_string_pretty(&pkt_hdr).unwrap(), log_string);
    }

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
        let ev_data = EventData::PacketSent {
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
        };

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

        let ev_data = EventData::PacketSent {
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
        };

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
        let event_data = EventData::PacketSent {
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
        };

        let ev = Event::with_time(0.0, event_data);

        trace.push_event(ev);

        let serialized = serde_json::to_string_pretty(&trace).unwrap();
        assert_eq!(serialized, log_string);

        let deserialized: Trace = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, trace);
    }
}

pub mod streamer;
