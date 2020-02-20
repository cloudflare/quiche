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

//! The qlog crate is an implementation of the [qlog main schema] and [qlog QUIC
//! and HTTP/3 events] that attempts to closely follow the format of the qlog
//! [TypeScript schema]. This is just a data model and no support is provided
//! for logging IO, applications can decide themselves the most appropriate
//! method.
//!
//! The crate uses Serde for conversion between Rust and JSON.
//!
//! [qlog main schema]: https://tools.ietf.org/html/draft-marx-qlog-main-schema
//! [qlog QUIC and HTTP/3 events]:
//! https://quiclog.github.io/internet-drafts/draft-marx-qlog-event-definitions-quic-h3
//! [TypeScript schema]:
//! https://github.com/quiclog/qlog/blob/master/TypeScript/draft-01/QLog.ts
//!
//! Getting Started
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
//! the [`Configuration`] of the `Trace`.
//!
//! A very important part of the `Trace` is the definition of `event_fields`. A
//! qlog Event is a vector of [`EventField`]; this provides great flexibility to
//! log events with any number of `EventFields` in any order. The `event_fields`
//! property describes the format of event logging and it is important that
//! events comply with that format. Failing to do so it going to cause problems
//! for qlog analysis tools. For information is available at
//! https://tools.ietf.org/html/draft-marx-qlog-main-schema-01#section-3.3.4
//!
//! In order to make using qlog a bit easier, this crate expects a qlog Event to
//! consist of the following EventFields in the following order:
//! [`EventField::RelativeTime`], [`EventField::Category`],
//! [`EventField::Event`] and [`EventField::Data`]. A set of methods are
//! provided to assist in creating a Trace and appending events to it in this
//! format.
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
//!         time_offset: Some("0".to_string()),
//!         time_units: Some(qlog::TimeUnits::Ms),
//!         original_uris: None,
//!     }),
//!     None,
//! );
//! ```
//!
//! ## Adding events
//!
//! Qlog Events are added to [`qlog::Trace.events`].
//!
//! It is recommended to use the provided utility methods to append semantically
//! valid events to a trace. However, there is nothing preventing you from
//! creating the events manually.
//!
//! The following example demonstrates how to log a QUIC packet
//! containing a single Crypto frame. It uses the [`QuicFrame::crypto()`],
//! [`packet_sent_min()`] and [`push_event()`] methods to create and log a
//! PacketSent event and its EventData.
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
//! #         time_offset: Some("0".to_string()),
//! #         time_units: Some(qlog::TimeUnits::Ms),
//! #         original_uris: None,
//! #     }),
//! #     None
//! # );
//!
//! let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
//! let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
//! let pkt_hdr = qlog::PacketHeader::new(
//!     0,
//!     Some(1251),
//!     Some(1224),
//!     Some(0xff000018),
//!     Some(&scid),
//!     Some(&dcid),
//! );
//! let frames =
//!     vec![qlog::QuicFrame::crypto("0".to_string(), "1000".to_string())];
//! let event = qlog::event::Event::packet_sent_min(
//!     qlog::PacketType::Initial,
//!     pkt_hdr,
//!     Some(frames),
//! );
//!
//! trace.push_event(std::time::Duration::new(0, 0), event);
//! ```
//!
//! ### Serializing
//!
//! Simply:
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
//! #         time_offset: Some("0".to_string()),
//! #         time_units: Some(qlog::TimeUnits::Ms),
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
//!     "time_units": "ms",
//!     "time_offset": "0"
//!   },
//!   "event_fields": [
//!     "relative_time",
//!     "category",
//!     "event",
//!     "data"
//!   ],
//!   "events": [
//!     [
//!       "0",
//!       "transport",
//!       "packet_sent",
//!       {
//!         "packet_type": "initial",
//!         "header": {
//!           "packet_number": "0",
//!           "packet_size": 1251,
//!           "payload_length": 1224,
//!           "version": "ff000018",
//!           "scil": "8",
//!           "dcil": "8",
//!           "scid": "7e37e4dcc6682da8",
//!           "dcid": "36ce104eee50101c"
//!         },
//!         "frames": [
//!           {
//!             "frame_type": "crypto",
//!             "offset": "0",
//!             "length": "100",
//!           }
//!         ]
//!       }
//!     ]
//!   ]
//! }
//! ```
//! [`Trace`]: struct.Trace.html
//! [`VantagePoint`]: struct.VantagePoint.html
//! [`Configuration`]: struct.Configuration.html
//! [`EventField`]: enum.EventField.html
//! [`EventField::RelativeTime`]: enum.EventField.html#variant.RelativeTime
//! [`EventField::Category`]: enum.EventField.html#variant.Category
//! [`EventField::Type`]: enum.EventField.html#variant.Type
//! [`EventField::Data`]: enum.EventField.html#variant.Data
//! [`qlog::Trace.events`]: struct.Trace.html#structfield.events
//! [`push_event()`]: struct.Trace.html#method.push_event
//! [`packet_sent_min()`]: event/struct.Event.html#method.packet_sent_min
//! [`QuicFrame::crypto()`]: enum.QuicFrame.html#variant.Crypto
use serde::{
    Deserialize,
    Serialize,
};

pub const QLOG_VERSION: &str = "draft-01";

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
pub struct Qlog {
    pub qlog_version: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub summary: Option<String>,

    pub traces: Vec<Trace>,
}

impl Default for Qlog {
    fn default() -> Self {
        Qlog {
            qlog_version: QLOG_VERSION.to_string(),
            title: Some("Default qlog title".to_string()),
            description: Some("Default qlog description".to_string()),
            summary: Some("Default qlog title".to_string()),
            traces: Vec::new(),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
pub struct Trace {
    pub vantage_point: VantagePoint,
    pub title: Option<String>,
    pub description: Option<String>,

    pub configuration: Option<Configuration>,

    pub common_fields: Option<CommonFields>,
    pub event_fields: Vec<String>,

    pub events: Vec<Vec<EventField>>,
}

/// Helper functions for using a qlog trace.
impl Trace {
    /// Creates a new qlog trace with the hard-coded event_fields
    /// ["relative_time", "category", "event", "data"]
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
            event_fields: vec![
                "relative_time".to_string(),
                "category".to_string(),
                "event".to_string(),
                "data".to_string(),
            ],
            events: Vec::new(),
        }
    }

    pub fn push_event(
        &mut self, relative_time: std::time::Duration, event: crate::event::Event,
    ) {
        let rel = match &self.configuration {
            Some(conf) => match conf.time_units {
                Some(TimeUnits::Ms) => relative_time.as_millis().to_string(),

                Some(TimeUnits::Us) => relative_time.as_micros().to_string(),

                None => String::from(""),
            },

            None => String::from(""),
        };

        self.events.push(vec![
            EventField::RelativeTime(rel),
            EventField::Category(event.category),
            EventField::Event(event.ty),
            EventField::Data(event.data),
        ]);
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
pub struct VantagePoint {
    pub name: Option<String>,

    #[serde(rename = "type")]
    pub ty: VantagePointType,

    pub flow: Option<VantagePointType>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum VantagePointType {
    Client,
    Server,
    Network,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TimeUnits {
    Ms,
    Us,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub time_units: Option<TimeUnits>,
    pub time_offset: Option<String>,

    pub original_uris: Option<Vec<String>>,
    /* TODO
     * additionalUserSpecifiedProperty */
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            time_units: Some(TimeUnits::Ms),
            time_offset: Some("0".to_string()),
            original_uris: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CommonFields {
    pub group_id: Option<String>,
    pub protocol_type: Option<String>,

    pub reference_time: Option<String>,
    /* TODO
     * additionalUserSpecifiedProperty */
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum EventType {
    ConnectivityEventType(ConnectivityEventType),

    TransportEventType(TransportEventType),

    SecurityEventType(SecurityEventType),

    RecoveryEventType(RecoveryEventType),

    Http3EventType(Http3EventType),

    QpackEventType(QpackEventType),

    GenericEventType(GenericEventType),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventField {
    RelativeTime(String),

    Category(EventCategory),

    Event(EventType),

    Data(EventData),
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityEventType {
    ServerListening,
    ConnectionStarted,
    ConnectionIdUpdated,
    SpinBitUpdated,
    ConnectionStateUpdated,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventType {
    ParametersSet,

    DatagramsSent,
    DatagramsReceived,
    DatagramDropped,

    PacketSent,
    PacketReceived,
    PacketDropped,
    PacketBuffered,

    FramesProcessed,

    StreamStateUpdated,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventTrigger {
    Line,
    Retransmit,
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    KeyUpdated,
    KeyRetired,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventTrigger {
    Tls,
    Implicit,
    RemoteUpdate,
    LocalUpdate,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventType {
    ParametersSet,
    MetricsUpdated,
    CongestionStateUpdated,
    LossTimerSet,
    LossTimerTriggered,
    PacketLost,
    MarkedForRetransmit,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventTrigger {
    AckReceived,
    PacketSent,
    Alarm,
    Unknown,
}

// ================================================================== //

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransportOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreferredAddress {
    pub ip_v4: String,
    pub ip_v6: String,

    pub port_v4: u64,
    pub port_v6: u64,

    pub connection_id: String,
    pub stateless_reset_token: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3Owner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3StreamType {
    Data,
    Control,
    Push,
    Reserved,
    QpackEncode,
    QpackDecode,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3DataRecipient {
    Application,
    Transport,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum H3PushDecision {
    Claimed,
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackStreamState {
    Blocked,
    Unblocked,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackUpdateType {
    Added,
    Evicted,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QpackDynamicTableEntry {
    pub index: u64,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QpackHeaderBlockPrefix {
    pub required_insert_count: u64,
    pub sign_bit: bool,
    pub delta_base: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    // ================================================================== //
    // CONNECTIVITY
    ServerListening {
        ip_v4: Option<String>,
        ip_v6: Option<String>,
        port_v4: u64,
        port_v6: u64,

        quic_versions: Option<Vec<String>>,
        alpn_values: Option<Vec<String>>,

        stateless_reset_required: Option<bool>,
    },

    ConnectionStarted {
        ip_version: String,
        src_ip: String,
        dst_ip: String,

        protocol: Option<String>,
        src_port: u64,
        dst_port: u64,

        quic_version: Option<String>,
        src_cid: Option<String>,
        dst_cid: Option<String>,
    },

    ConnectionIdUpdated {
        src_old: Option<String>,
        src_new: Option<String>,

        dst_old: Option<String>,
        dst_new: Option<String>,
    },

    SpinBitUpdated {
        state: bool,
    },

    ConnectionStateUpdated {
        old: Option<ConnectionState>,
        new: ConnectionState,
    },

    // ================================================================== //
    // SECURITY
    KeyUpdated {
        key_type: KeyType,
        old: Option<String>,
        new: String,
        generation: Option<u64>,
    },

    KeyRetired {
        key_type: KeyType,
        key: Option<String>,
        generation: Option<u64>,
    },

    // ================================================================== //
    // TRANSPORT
    TransportParametersSet {
        owner: Option<TransportOwner>,

        resumption_allowed: Option<bool>,
        early_data_enabled: Option<bool>,
        alpn: Option<String>,
        version: Option<String>,
        tls_cipher: Option<String>,

        original_connection_id: Option<String>,
        stateless_reset_token: Option<String>,
        disable_active_migration: Option<bool>,

        idle_timeout: Option<u64>,
        max_packet_size: Option<u64>,
        ack_delay_exponent: Option<u64>,
        max_ack_delay: Option<u64>,
        active_connection_id_limit: Option<u64>,

        initial_max_data: Option<String>,
        initial_max_stream_data_bidi_local: Option<String>,
        initial_max_stream_data_bidi_remote: Option<String>,
        initial_max_stream_data_uni: Option<String>,
        initial_max_streams_bidi: Option<String>,
        initial_max_streams_uni: Option<String>,

        preferred_address: Option<PreferredAddress>,
    },

    DatagramsReceived {
        count: Option<u64>,
        byte_length: Option<u64>,
    },

    DatagramsSent {
        count: Option<u64>,
        byte_length: Option<u64>,
    },

    DatagramDropped {
        byte_length: Option<u64>,
    },

    PacketReceived {
        packet_type: PacketType,
        header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,

        is_coalesced: Option<bool>,

        raw_encrypted: Option<String>,
        raw_decrypted: Option<String>,
    },

    PacketSent {
        packet_type: PacketType,
        header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,

        is_coalesced: Option<bool>,

        raw_encrypted: Option<String>,
        raw_decrypted: Option<String>,
    },

    PacketDropped {
        packet_type: Option<PacketType>,
        packet_size: Option<u64>,

        raw: Option<String>,
    },

    PacketBuffered {
        packet_type: PacketType,
        packet_number: String,
    },

    StreamStateUpdated {
        stream_id: String,
        stream_type: Option<StreamType>,

        old: Option<StreamState>,
        new: StreamState,

        stream_side: Option<StreamSide>,
    },

    FramesProcessed {
        frames: Vec<QuicFrame>,
    },

    // ================================================================== //
    // RECOVERY
    RecoveryParametersSet {
        reordering_threshold: Option<u64>,
        time_threshold: Option<u64>,
        timer_granularity: Option<u64>,
        initial_rtt: Option<u64>,

        max_datagram_size: Option<u64>,
        initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u64>,
        loss_reduction_factor: Option<u64>,
        persistent_congestion_threshold: Option<u64>,
    },

    MetricsUpdated {
        min_rtt: Option<u64>,
        smoothed_rtt: Option<u64>,
        latest_rtt: Option<u64>,
        rtt_variance: Option<u64>,

        max_ack_delay: Option<u64>,
        pto_count: Option<u64>,

        congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>,

        ssthresh: Option<u64>,

        // qlog defined
        packets_in_flight: Option<u64>,
        in_recovery: Option<bool>,

        pacing_rate: Option<u64>,
    },

    CongestionStateUpdated {
        old: Option<String>,
        new: String,
    },

    LossTimerSet {
        timer_type: Option<TimerType>,
        timeout: Option<String>,
    },

    PacketLost {
        packet_type: PacketType,
        packet_number: String,

        header: Option<PacketHeader>,
        frames: Vec<QuicFrame>,
    },

    MarkedForRetransmit {
        frames: Vec<QuicFrame>,
    },

    // ================================================================== //
    // HTTP/3
    H3ParametersSet {
        owner: Option<H3Owner>,

        max_header_list_size: Option<u64>,
        max_table_capacity: Option<u64>,
        blocked_streams_count: Option<u64>,

        push_allowed: Option<bool>,

        waits_for_settings: Option<bool>,
    },

    H3StreamTypeSet {
        stream_id: String,
        owner: Option<H3Owner>,

        old: Option<H3StreamType>,
        new: H3StreamType,
    },

    H3FrameCreated {
        stream_id: String,
        frame: Http3Frame,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    H3FrameParsed {
        stream_id: String,
        frame: Http3Frame,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    H3DataMoved {
        stream_id: String,
        offset: Option<String>,

        from: Option<H3DataRecipient>,
        to: Option<H3DataRecipient>,

        raw: Option<String>,
    },

    H3PushResolved {
        push_id: Option<String>,
        stream_id: Option<String>,

        decision: Option<H3PushDecision>,
    },

    // ================================================================== //
    // QPACK
    QpackStateUpdated {
        owner: Option<QpackOwner>,

        dynamic_table_capacity: Option<u64>,
        dynamic_table_size: Option<u64>,

        known_received_count: Option<u64>,
        current_insert_count: Option<u64>,
    },

    QpackStreamStateUpdated {
        stream_id: String,

        state: QpackStreamState,
    },

    QpackDynamicTableUpdated {
        update_type: QpackUpdateType,

        entries: Vec<QpackDynamicTableEntry>,
    },

    QpackHeadersEncoded {
        stream_id: Option<String>,

        headers: Option<HttpHeader>,

        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,

        raw: Option<String>,
    },

    QpackHeadersDecoded {
        stream_id: Option<String>,

        headers: Option<HttpHeader>,

        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,

        raw: Option<String>,
    },

    QpackInstructionSent {
        instruction: QPackInstruction,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    QpackInstructionReceived {
        instruction: QPackInstruction,
        byte_length: Option<String>,

        raw: Option<String>,
    },

    // ================================================================== //
    // Generic
    ConnectionError {
        code: Option<ConnectionErrorCode>,
        description: Option<String>,
    },

    ApplicationError {
        code: Option<ApplicationErrorCode>,
        description: Option<String>,
    },

    InternalError {
        code: Option<u64>,
        description: Option<String>,
    },

    InternalWarning {
        code: Option<u64>,
        description: Option<String>,
    },

    Message {
        message: String,
    },

    Marker {
        marker_type: String,
        message: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Http3EventType {
    ParametersSet,
    StreamTypeSet,
    FrameCreated,
    FrameParsed,
    DataMoved,
    PushResolved,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackEventType {
    StateUpdated,
    StreamStateUpdated,
    DynamicTableUpdated,
    HeadersEncoded,
    HeadersDecoded,
    InstructionSent,
    InstructionReceived,
}

#[derive(Serialize, Deserialize, Clone)]
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
    Unknown,
}

// TODO: search for pub enum Error { to see how best to encode errors in qlog.
#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub packet_number: String,
    pub packet_size: Option<u64>,
    pub payload_length: Option<u64>,
    pub version: Option<String>,
    pub scil: Option<String>,
    pub dcil: Option<String>,
    pub scid: Option<String>,
    pub dcid: Option<String>,
}

impl PacketHeader {
    pub fn new(
        packet_number: u64, packet_size: Option<u64>,
        payload_length: Option<u64>, version: Option<u32>, scid: Option<&[u8]>,
        dcid: Option<&[u8]>,
    ) -> Self {
        let (scil, scid) = match scid {
            Some(cid) => (
                Some(cid.len().to_string()),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let (dcil, dcid) = match dcid {
            Some(cid) => (
                Some(cid.len().to_string()),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let version = match version {
            Some(v) => Some(format!("{:x?}", v)),

            None => None,
        };

        PacketHeader {
            packet_number: packet_number.to_string(),
            packet_size,
            payload_length,
            version,
            scil,
            dcil,
            scid,
            dcid,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    TransportError,
    ApplicationError,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GenericEventType {
    ConnectionError,
    ApplicationError,
    InternalError,
    InternalWarning,

    Message,
    Marker,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ConnectionErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ApplicationErrorCode {
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CryptoError {
    Prefix,
}

#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum QuicFrame {
    Padding {
        frame_type: QuicFrameTypeName,
    },

    Ping {
        frame_type: QuicFrameTypeName,
    },

    Ack {
        frame_type: QuicFrameTypeName,
        ack_delay: Option<String>,
        acked_ranges: Option<Vec<(u64, u64)>>,

        ect1: Option<String>,

        ect0: Option<String>,

        ce: Option<String>,
    },

    ResetStream {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        error_code: u64,
        final_size: String,
    },

    StopSending {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        error_code: u64,
    },

    Crypto {
        frame_type: QuicFrameTypeName,
        offset: String,
        length: String,
    },

    NewToken {
        frame_type: QuicFrameTypeName,
        length: String,
        token: String,
    },

    Stream {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        offset: String,
        length: String,
        fin: bool,

        raw: Option<String>,
    },

    MaxData {
        frame_type: QuicFrameTypeName,
        maximum: String,
    },

    MaxStreamData {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        maximum: String,
    },

    MaxStreams {
        frame_type: QuicFrameTypeName,
        stream_type: StreamType,
        maximum: String,
    },

    DataBlocked {
        frame_type: QuicFrameTypeName,
        limit: String,
    },

    StreamDataBlocked {
        frame_type: QuicFrameTypeName,
        stream_id: String,
        limit: String,
    },

    StreamsBlocked {
        frame_type: QuicFrameTypeName,
        stream_type: StreamType,
        limit: String,
    },

    NewConnectionId {
        frame_type: QuicFrameTypeName,
        sequence_number: String,
        retire_prior_to: String,
        length: u64,
        connection_id: String,
        reset_token: String,
    },

    RetireConnectionId {
        frame_type: QuicFrameTypeName,
        sequence_number: String,
    },

    PathChallenge {
        frame_type: QuicFrameTypeName,

        data: Option<String>,
    },

    PathResponse {
        frame_type: QuicFrameTypeName,

        data: Option<String>,
    },

    ConnectionClose {
        frame_type: QuicFrameTypeName,
        error_space: ErrorSpace,
        error_code: u64,
        raw_error_code: u64,
        reason: String,

        trigger_frame_type: Option<String>,
    },

    Unknown {
        frame_type: QuicFrameTypeName,
        raw_frame_type: u64,
    },
}

impl QuicFrame {
    pub fn padding() -> Self {
        QuicFrame::Padding {
            frame_type: QuicFrameTypeName::Padding,
        }
    }

    pub fn ping() -> Self {
        QuicFrame::Ping {
            frame_type: QuicFrameTypeName::Ping,
        }
    }

    pub fn ack(
        ack_delay: Option<String>, acked_ranges: Option<Vec<(u64, u64)>>,
        ect1: Option<String>, ect0: Option<String>, ce: Option<String>,
    ) -> Self {
        QuicFrame::Ack {
            frame_type: QuicFrameTypeName::Ack,
            ack_delay,
            acked_ranges,
            ect1,
            ect0,
            ce,
        }
    }

    pub fn reset_stream(
        stream_id: String, error_code: u64, final_size: String,
    ) -> Self {
        QuicFrame::ResetStream {
            frame_type: QuicFrameTypeName::ResetStream,
            stream_id,
            error_code,
            final_size,
        }
    }

    pub fn stop_sending(stream_id: String, error_code: u64) -> Self {
        QuicFrame::StopSending {
            frame_type: QuicFrameTypeName::StopSending,
            stream_id,
            error_code,
        }
    }

    pub fn crypto(offset: String, length: String) -> Self {
        QuicFrame::Crypto {
            frame_type: QuicFrameTypeName::Crypto,
            offset,
            length,
        }
    }

    pub fn new_token(length: String, token: String) -> Self {
        QuicFrame::NewToken {
            frame_type: QuicFrameTypeName::NewToken,
            length,
            token,
        }
    }

    pub fn stream(
        stream_id: String, offset: String, length: String, fin: bool,
        raw: Option<String>,
    ) -> Self {
        QuicFrame::Stream {
            frame_type: QuicFrameTypeName::Stream,
            stream_id,
            offset,
            length,
            fin,
            raw,
        }
    }

    pub fn max_data(maximum: String) -> Self {
        QuicFrame::MaxData {
            frame_type: QuicFrameTypeName::MaxData,
            maximum,
        }
    }

    pub fn max_stream_data(stream_id: String, maximum: String) -> Self {
        QuicFrame::MaxStreamData {
            frame_type: QuicFrameTypeName::MaxStreamData,
            stream_id,
            maximum,
        }
    }

    pub fn max_streams(stream_type: StreamType, maximum: String) -> Self {
        QuicFrame::MaxStreams {
            frame_type: QuicFrameTypeName::MaxStreams,
            stream_type,
            maximum,
        }
    }

    pub fn data_blocked(limit: String) -> Self {
        QuicFrame::DataBlocked {
            frame_type: QuicFrameTypeName::DataBlocked,
            limit,
        }
    }

    pub fn stream_data_blocked(stream_id: String, limit: String) -> Self {
        QuicFrame::StreamDataBlocked {
            frame_type: QuicFrameTypeName::StreamDataBlocked,
            stream_id,
            limit,
        }
    }

    pub fn streams_blocked(stream_type: StreamType, limit: String) -> Self {
        QuicFrame::StreamsBlocked {
            frame_type: QuicFrameTypeName::StreamsBlocked,
            stream_type,
            limit,
        }
    }

    pub fn new_connection_id(
        sequence_number: String, retire_prior_to: String, length: u64,
        connection_id: String, reset_token: String,
    ) -> Self {
        QuicFrame::NewConnectionId {
            frame_type: QuicFrameTypeName::NewConnectionId,
            sequence_number,
            retire_prior_to,
            length,
            connection_id,
            reset_token,
        }
    }

    pub fn retire_connection_id(sequence_number: String) -> Self {
        QuicFrame::RetireConnectionId {
            frame_type: QuicFrameTypeName::RetireConnectionId,
            sequence_number,
        }
    }

    pub fn path_challenge(data: Option<String>) -> Self {
        QuicFrame::PathChallenge {
            frame_type: QuicFrameTypeName::PathChallenge,
            data,
        }
    }

    pub fn path_response(data: Option<String>) -> Self {
        QuicFrame::PathResponse {
            frame_type: QuicFrameTypeName::PathResponse,
            data,
        }
    }

    pub fn connection_close(
        error_space: ErrorSpace, error_code: u64, raw_error_code: u64,
        reason: String, trigger_frame_type: Option<String>,
    ) -> Self {
        QuicFrame::ConnectionClose {
            frame_type: QuicFrameTypeName::ConnectionClose,
            error_space,
            error_code,
            raw_error_code,
            reason,
            trigger_frame_type,
        }
    }

    pub fn unknown(raw_frame_type: u64) -> Self {
        QuicFrame::Unknown {
            frame_type: QuicFrameTypeName::Unknown,
            raw_frame_type,
        }
    }
}

// ================================================================== //
#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Setting {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Http3Frame {
    Data {
        frame_type: Http3FrameTypeName,

        raw: Option<String>,
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
    pub fn data(raw: Option<String>) -> Self {
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

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackTableType {
    Static,
    Dynamic,
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum QpackHeaderBlockRepresentationTypeName {
    IndexedHeaderField,
    LiteralHeaderFieldWithName,
    LiteralHeaderFieldWithoutName,
}

#[derive(Serialize, Deserialize, Clone)]
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
        match data {
            Some(d) => Some(format!("{}", HexSlice::new(d))),

            None => None,
        }
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
pub mod testing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_header() {
        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
        let pkt_hdr = PacketHeader::new(
            0,
            Some(1251),
            Some(1224),
            Some(0xff000018),
            Some(&scid),
            Some(&dcid),
        );

        let log_string = r#"{
  "packet_number": "0",
  "packet_size": 1251,
  "payload_length": 1224,
  "version": "ff000018",
  "scil": "8",
  "dcil": "8",
  "scid": "7e37e4dcc6682da8",
  "dcid": "36ce104eee50101c"
}"#;

        assert_eq!(serde_json::to_string_pretty(&pkt_hdr).unwrap(), log_string);
    }

    #[test]
    fn packet_sent_event_no_frames() {
        let log_string = r#"{
  "packet_type": "initial",
  "header": {
    "packet_number": "0",
    "packet_size": 1251,
    "payload_length": 1224,
    "version": "ff000018",
    "scil": "8",
    "dcil": "8",
    "scid": "7e37e4dcc6682da8",
    "dcid": "36ce104eee50101c"
  }
}"#;

        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
        let pkt_hdr = PacketHeader::new(
            0,
            Some(1251),
            Some(1224),
            Some(0xff000018),
            Some(&scid),
            Some(&dcid),
        );

        let pkt_sent_evt = EventData::PacketSent {
            raw_encrypted: None,
            raw_decrypted: None,
            packet_type: PacketType::Initial,
            header: pkt_hdr.clone(),
            frames: None,
            is_coalesced: None,
        };

        assert_eq!(
            serde_json::to_string_pretty(&pkt_sent_evt).unwrap(),
            log_string
        );
    }

    #[test]
    fn packet_sent_event_some_frames() {
        let log_string = r#"{
  "packet_type": "initial",
  "header": {
    "packet_number": "0",
    "packet_size": 1251,
    "payload_length": 1224,
    "version": "ff000018",
    "scil": "8",
    "dcil": "8",
    "scid": "7e37e4dcc6682da8",
    "dcid": "36ce104eee50101c"
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
      "stream_id": "0",
      "offset": "0",
      "length": "100",
      "fin": true
    }
  ]
}"#;

        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
        let pkt_hdr = PacketHeader::new(
            0,
            Some(1251),
            Some(1224),
            Some(0xff000018),
            Some(&scid),
            Some(&dcid),
        );

        let mut frames = Vec::new();
        frames.push(QuicFrame::padding());

        frames.push(QuicFrame::ping());

        frames.push(QuicFrame::stream(
            "0".to_string(),
            "0".to_string(),
            "100".to_string(),
            true,
            None,
        ));

        let pkt_sent_evt = EventData::PacketSent {
            raw_encrypted: None,
            raw_decrypted: None,
            packet_type: PacketType::Initial,
            header: pkt_hdr.clone(),
            frames: Some(frames),
            is_coalesced: None,
        };

        assert_eq!(
            serde_json::to_string_pretty(&pkt_sent_evt).unwrap(),
            log_string
        );
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
    "time_units": "ms",
    "time_offset": "0"
  },
  "event_fields": [
    "relative_time",
    "category",
    "event",
    "data"
  ],
  "events": []
}"#;

        let trace = Trace::new(
            VantagePoint {
                name: None,
                ty: VantagePointType::Server,
                flow: None,
            },
            Some("Quiche qlog trace".to_string()),
            Some("Quiche qlog trace description".to_string()),
            Some(Configuration {
                time_offset: Some("0".to_string()),
                time_units: Some(TimeUnits::Ms),
                original_uris: None,
            }),
            None,
        );

        assert_eq!(serde_json::to_string_pretty(&trace).unwrap(), log_string);
    }
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
    "time_units": "ms",
    "time_offset": "0"
  },
  "event_fields": [
    "relative_time",
    "category",
    "event",
    "data"
  ],
  "events": [
    [
      "0",
      "transport",
      "packet_sent",
      {
        "packet_type": "initial",
        "header": {
          "packet_number": "0",
          "packet_size": 1251,
          "payload_length": 1224,
          "version": "ff000018",
          "scil": "8",
          "dcil": "8",
          "scid": "7e37e4dcc6682da8",
          "dcid": "36ce104eee50101c"
        },
        "frames": [
          {
            "frame_type": "stream",
            "stream_id": "0",
            "offset": "0",
            "length": "100",
            "fin": true
          }
        ]
      }
    ]
  ]
}"#;

    let mut trace = Trace::new(
        VantagePoint {
            name: None,
            ty: VantagePointType::Server,
            flow: None,
        },
        Some("Quiche qlog trace".to_string()),
        Some("Quiche qlog trace description".to_string()),
        Some(Configuration {
            time_offset: Some("0".to_string()),
            time_units: Some(TimeUnits::Ms),
            original_uris: None,
        }),
        None,
    );

    let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
    let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
    let pkt_hdr = PacketHeader::new(
        0,
        Some(1251),
        Some(1224),
        Some(0xff000018),
        Some(&scid),
        Some(&dcid),
    );
    let frames = vec![QuicFrame::stream(
        "0".to_string(),
        "0".to_string(),
        "100".to_string(),
        true,
        None,
    )];
    let event =
        event::Event::packet_sent_min(PacketType::Initial, pkt_hdr, Some(frames));

    trace.push_event(std::time::Duration::new(0, 0), event);

    assert_eq!(serde_json::to_string_pretty(&trace).unwrap(), log_string);
}

#[test]
fn test_event_validity() {
    // Test a single event in each category

    let ev = event::Event::server_listening_min(443, 443);
    assert!(ev.is_valid());

    let ev = event::Event::transport_parameters_set_min();
    assert!(ev.is_valid());

    let ev = event::Event::recovery_parameters_set_min();
    assert!(ev.is_valid());

    let ev = event::Event::h3_parameters_set_min();
    assert!(ev.is_valid());

    let ev = event::Event::qpack_state_updated_min();
    assert!(ev.is_valid());

    let ev = event::Event {
        category: EventCategory::Error,
        ty: EventType::GenericEventType(GenericEventType::ConnectionError),
        data: EventData::ConnectionError {
            code: None,
            description: None,
        },
    };

    assert!(ev.is_valid());
}

#[test]
fn test_bogus_event_validity() {
    // Test a single event in each category

    let mut ev = event::Event::server_listening_min(443, 443);
    ev.category = EventCategory::Simulation;
    assert!(!ev.is_valid());

    let mut ev = event::Event::transport_parameters_set_min();
    ev.category = EventCategory::Simulation;
    assert!(!ev.is_valid());

    let mut ev = event::Event::recovery_parameters_set_min();
    ev.category = EventCategory::Simulation;
    assert!(!ev.is_valid());

    let mut ev = event::Event::h3_parameters_set_min();
    ev.category = EventCategory::Simulation;
    assert!(!ev.is_valid());

    let mut ev = event::Event::qpack_state_updated_min();
    ev.category = EventCategory::Simulation;
    assert!(!ev.is_valid());

    let ev = event::Event {
        category: EventCategory::Error,
        ty: EventType::GenericEventType(GenericEventType::ConnectionError),
        data: EventData::FramesProcessed { frames: Vec::new() },
    };

    assert!(!ev.is_valid());
}

pub mod event;
