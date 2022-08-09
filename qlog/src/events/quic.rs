// Copyright (C) 2021, Cloudflare, Inc.
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

use serde::Deserialize;
use serde::Serialize;

use super::connectivity::TransportOwner;
use super::Bytes;
use super::DataRecipient;
use super::RawInfo;
use super::Token;
use crate::HexSlice;
use crate::StatelessResetToken;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    TransportError,
    ApplicationError,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionError,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketSentTrigger {
    RetransmitReordered,
    RetransmitTimeout,
    PtoProbe,
    RetransmitCrypto,
    CcBandwidthProbe,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketReceivedTrigger {
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketDroppedTrigger {
    KeysUnavailable,
    UnknownConnectionId,
    HeaderParserError,
    PayloadDecryptError,
    ProtocolViolation,
    DosPrevention,
    UnsupportedVersion,
    UnexpectedPacket,
    UnexpectedSourceConnectionId,
    UnexpectedVersion,
    Duplicate,
    InvalidInitial,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    Backpressure,
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    KeyUpdated,
    KeyRetired,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEventType {
    ParametersSet,
    MetricsUpdated,
    CongestionStateUpdated,
    LossTimerUpdated,
    PacketLost,
    MarkedForRetransmit,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CongestionStateUpdatedTrigger {
    PersistentCongestion,
    Ecn,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    PtoExpired,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LossTimerEventType {
    Set,
    Expired,
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum AckedRanges {
    Single(Vec<Vec<u64>>),
    Double(Vec<(u64, u64)>),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
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
        acked_ranges: Option<AckedRanges>,

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
        token: Token,
    },

    Stream {
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: Option<bool>,

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
        connection_id_length: Option<u8>,
        connection_id: Bytes,
        stateless_reset_token: Option<StatelessResetToken>,
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
        error_space: Option<ErrorSpace>,
        error_code: Option<u64>,
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
        raw_length: Option<u32>,
        raw: Option<Bytes>,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PreferredAddress {
    pub ip_v4: String,
    pub ip_v6: String,

    pub port_v4: u16,
    pub port_v6: u16,

    pub connection_id: Bytes,
    pub stateless_reset_token: StatelessResetToken,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct VersionInformation {
    pub server_versions: Option<Vec<Bytes>>,
    pub client_versions: Option<Vec<Bytes>>,
    pub chosen_version: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AlpnInformation {
    pub server_alpns: Option<Vec<Bytes>>,
    pub client_alpns: Option<Vec<Bytes>>,
    pub chosen_alpn: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TransportParametersSet {
    pub owner: Option<TransportOwner>,

    pub resumption_allowed: Option<bool>,
    pub early_data_enabled: Option<bool>,
    pub tls_cipher: Option<String>,
    pub aead_tag_length: Option<u8>,

    pub original_destination_connection_id: Option<Bytes>,
    pub initial_source_connection_id: Option<Bytes>,
    pub retry_source_connection_id: Option<Bytes>,
    pub stateless_reset_token: Option<StatelessResetToken>,
    pub disable_active_migration: Option<bool>,

    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u32>,
    pub ack_delay_exponent: Option<u16>,
    pub max_ack_delay: Option<u16>,
    pub active_connection_id_limit: Option<u32>,

    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,

    pub preferred_address: Option<PreferredAddress>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TransportParametersRestored {
    pub disable_active_migration: Option<bool>,

    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u32>,
    pub active_connection_id_limit: Option<u32>,

    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DatagramsReceived {
    pub count: Option<u16>,

    pub raw: Option<Vec<RawInfo>>,

    pub datagram_ids: Option<Vec<u32>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DatagramsSent {
    pub count: Option<u16>,

    pub raw: Option<Vec<RawInfo>>,

    pub datagram_ids: Option<Vec<u32>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DatagramDropped {
    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PacketReceived {
    pub header: PacketHeader,
    // `frames` is defined here in the QLog schema specification. However,
    // our streaming serializer requires serde to put the object at the end,
    // so we define it there and depend on serde's preserve_order feature.
    pub is_coalesced: Option<bool>,

    pub retry_token: Option<Token>,

    pub stateless_reset_token: Option<StatelessResetToken>,

    pub supported_versions: Option<Vec<Bytes>>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketReceivedTrigger>,

    pub frames: Option<Vec<QuicFrame>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PacketSent {
    pub header: PacketHeader,
    // `frames` is defined here in the QLog schema specification. However,
    // our streaming serializer requires serde to put the object at the end,
    // so we define it there and depend on serde's preserve_order feature.
    pub is_coalesced: Option<bool>,

    pub retry_token: Option<Token>,

    pub stateless_reset_token: Option<StatelessResetToken>,

    pub supported_versions: Option<Vec<Bytes>>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketSentTrigger>,

    pub frames: Option<Vec<QuicFrame>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PacketDropped {
    pub header: Option<PacketHeader>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketDroppedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PacketBuffered {
    pub header: Option<PacketHeader>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketBufferedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PacketsAcked {
    pub packet_number_space: Option<PacketNumberSpace>,
    pub packet_numbers: Option<Vec<u64>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct StreamStateUpdated {
    pub stream_id: u64,
    pub stream_type: Option<StreamType>,

    pub old: Option<StreamState>,
    pub new: StreamState,

    pub stream_side: Option<StreamSide>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FramesProcessed {
    pub frames: Vec<QuicFrame>,

    pub packet_number: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DataMoved {
    pub stream_id: Option<u64>,
    pub offset: Option<u64>,
    pub length: Option<u64>,

    pub from: Option<DataRecipient>,
    pub to: Option<DataRecipient>,

    pub data: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct RecoveryParametersSet {
    pub reordering_threshold: Option<u16>,
    pub time_threshold: Option<f32>,
    pub timer_granularity: Option<u16>,
    pub initial_rtt: Option<f32>,

    pub max_datagram_size: Option<u32>,
    pub initial_congestion_window: Option<u64>,
    pub minimum_congestion_window: Option<u32>,
    pub loss_reduction_factor: Option<f32>,
    pub persistent_congestion_threshold: Option<u16>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MetricsUpdated {
    pub min_rtt: Option<f32>,
    pub smoothed_rtt: Option<f32>,
    pub latest_rtt: Option<f32>,
    pub rtt_variance: Option<f32>,

    pub pto_count: Option<u16>,

    pub congestion_window: Option<u64>,
    pub bytes_in_flight: Option<u64>,

    pub ssthresh: Option<u64>,

    // qlog defined
    pub packets_in_flight: Option<u64>,

    pub pacing_rate: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct CongestionStateUpdated {
    pub old: Option<String>,
    pub new: String,

    pub trigger: Option<CongestionStateUpdatedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LossTimerUpdated {
    pub timer_type: Option<TimerType>,
    pub packet_number_space: Option<PacketNumberSpace>,

    pub event_type: LossTimerEventType,

    pub delta: Option<f32>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PacketLost {
    pub header: Option<PacketHeader>,

    pub frames: Option<Vec<QuicFrame>>,

    pub trigger: Option<PacketLostTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MarkedForRetransmit {
    pub frames: Vec<QuicFrame>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

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
}
