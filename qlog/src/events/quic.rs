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

use smallvec::SmallVec;

use crate::HexSlice;

use crate::events::ApplicationError;
use crate::events::ConnectionClosedEventError;
use crate::events::ConnectionClosedFrameError;
use crate::events::DataRecipient;
use crate::events::RawInfo;
use crate::events::Token;
use crate::events::TupleEndpointInfo;
use crate::Bytes;
use crate::StatelessResetToken;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
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
    #[default]
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub packet_type_bytes: Option<u64>,
    pub spin_bit: Option<bool>,
    pub key_phase: Option<u64>,
    pub key_phase_bit: Option<bool>,
    pub packet_number_length: Option<u8>,
    pub packet_number: Option<u64>,

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
        packet_type: PacketType, packet_number: Option<u64>,
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

        let version = version.map(|v| format!("{v:x?}"));

        PacketHeader {
            packet_type,
            packet_number,
            token,
            length,
            version,
            scil,
            dcil,
            scid,
            dcid,
            ..Default::default()
        }
    }

    /// Creates a new PacketHeader.
    ///
    /// Once a QUIC connection has formed, version, dcid and scid are stable, so
    /// there are space benefits to not logging them in every packet, especially
    /// PacketType::OneRtt.
    pub fn with_type(
        ty: PacketType, packet_number: Option<u64>, version: Option<u32>,
        scid: Option<&[u8]>, dcid: Option<&[u8]>,
    ) -> Self {
        match ty {
            PacketType::OneRtt =>
                PacketHeader::new(ty, packet_number, None, None, None, None, None),

            _ => PacketHeader::new(
                ty,
                packet_number,
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
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamTrigger {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Idle,
    Open,
    Closed,

    HalfClosedLocal,
    HalfClosedRemote,
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,
    DataReceived,
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
    ConnectionRefused,
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
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QuicEventType {
    ServerListening,
    ConnectionStarted,
    ConnectionClosed,
    ConnectionIdUpdated,
    SpinBitUpdated,
    ConnectionStateUpdated,
    TupleAssigned,
    MtuUpdated,

    VersionInformation,
    AlpnInformation,
    ParametersSet,
    ParametersRestored,
    PacketSent,
    PacketReceived,
    PacketDropped,
    PacketBuffered,
    PacketsAcked,
    UdpDatagramsSent,
    UdpDatagramsReceived,
    UdpDatagramDropped,
    StreamStateUpdated,
    FramesProcessed,
    StreamDataMoved,
    DatagramDataMoved,
    ConnectionDataBlockedUpdated,
    StreamDataBlockedUpdated,
    DatagramDataBlockedUpdated,
    MigrationStateUpdated,

    KeyUpdated,
    KeyDiscarded,

    RecoveryParametersSet,
    RecoveryMetricsUpdated,
    CongestionStateUpdated,
    TimerUpdated,
    PacketLost,
    MarkedForRetransmit,
    EcnStateUpdated,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportInitiator {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Attempted,
    PeerValidated,
    HandshakeStarted,
    EarlyWrite,
    HandshakeCompleted,
    HandshakeConfirmed,
    Closing,
    Draining,
    Closed,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionClosedTrigger {
    Clean,
    HandshakeTimeout,
    IdleTimeout,
    Error,
    StatelessReset,
    VersionMismatch,
    Application,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ServerListening {
    pub ip_v4: Option<String>, // human-readable or bytes
    pub port_v4: Option<u16>,
    pub ip_v6: Option<String>, // human-readable or bytes
    pub port_v6: Option<u16>,

    pub retry_required: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConnectionStarted {
    pub local: TupleEndpointInfo,
    pub remote: TupleEndpointInfo,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConnectionClosed {
    pub owner: Option<TransportInitiator>,

    pub connection_error: Option<ConnectionClosedEventError>,
    pub application_code: Option<ApplicationError>,
    pub error_code: Option<u64>,
    pub internal_code: Option<u64>,

    pub reason: Option<String>,

    pub trigger: Option<ConnectionClosedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConnectionIdUpdated {
    pub owner: Option<TransportInitiator>,

    pub old: Option<Bytes>,
    pub new: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SpinBitUpdated {
    pub state: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConnectionStateUpdated {
    pub old: Option<ConnectionState>,
    pub new: ConnectionState,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TupleAssigned {
    pub tuple_id: String,
    pub tuple_remote: Option<TupleEndpointInfo>,
    pub tuple_local: Option<TupleEndpointInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MtuUpdated {
    pub old: Option<u32>,
    pub new: u32,
    pub done: Option<bool>,
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
    InternalError,
    Rejected,
    Unsupported,
    Invalid,
    ConnectionUnknown,
    DecryptionFailure,
    General,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    Backpressure,
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum AckedRanges {
    Single(Vec<Vec<u64>>),
    Double(Vec<(u64, u64)>),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
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
    #[default]
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
    Padding {
        raw: Option<RawInfo>,
    },

    Ping {
        raw: Option<RawInfo>,
    },

    Ack {
        ack_delay: Option<f32>,
        acked_ranges: Option<AckedRanges>,

        ect1: Option<u64>,
        ect0: Option<u64>,
        ce: Option<u64>,

        raw: Option<RawInfo>,
    },

    ResetStream {
        stream_id: u64,
        error: ApplicationError,
        error_code: Option<u64>,
        final_size: u64,

        raw: Option<RawInfo>,
    },

    StopSending {
        stream_id: u64,
        error: ApplicationError,
        error_code: Option<u64>,

        raw: Option<RawInfo>,
    },

    Crypto {
        offset: u64,
        raw: Option<RawInfo>,
    },

    NewToken {
        token: Token,
        raw: Option<RawInfo>,
    },

    Stream {
        stream_id: u64,
        offset: Option<u64>,
        fin: Option<bool>,

        raw: Option<RawInfo>,
    },

    MaxData {
        maximum: u64,
        raw: Option<RawInfo>,
    },

    MaxStreamData {
        stream_id: u64,
        maximum: u64,
        raw: Option<RawInfo>,
    },

    MaxStreams {
        stream_type: StreamType,
        maximum: u64,
        raw: Option<RawInfo>,
    },

    DataBlocked {
        limit: u64,
        raw: Option<RawInfo>,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
        raw: Option<RawInfo>,
    },

    StreamsBlocked {
        stream_type: StreamType,
        limit: u64,
        raw: Option<RawInfo>,
    },

    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id_length: Option<u8>,
        connection_id: Bytes,
        stateless_reset_token: Option<StatelessResetToken>,
        raw: Option<RawInfo>,
    },

    RetireConnectionId {
        sequence_number: u64,
        raw: Option<RawInfo>,
    },

    PathChallenge {
        data: Option<Bytes>,
        raw: Option<RawInfo>,
    },

    PathResponse {
        data: Option<Bytes>,
        raw: Option<RawInfo>,
    },

    ConnectionClose {
        error_space: Option<ErrorSpace>,
        error: Option<ConnectionClosedFrameError>,
        error_code: Option<u64>,
        reason: Option<String>,
        reason_bytes: Option<Bytes>,

        trigger_frame_type: Option<u64>,
    },

    HandshakeDone {
        raw: Option<RawInfo>,
    },

    Datagram {
        raw: Option<RawInfo>,
    },

    Unknown {
        frame_type_bytes: Option<u64>,
        raw: Option<RawInfo>,
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
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct AlpnIdentifier {
    pub byte_value: Option<Bytes>,
    pub string_value: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct QuicVersionInformation {
    pub server_versions: Option<Vec<Bytes>>,
    pub client_versions: Option<Vec<Bytes>>,
    pub chosen_version: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct AlpnInformation {
    pub server_alpns: Option<Vec<AlpnIdentifier>>,
    pub client_alpns: Option<Vec<AlpnIdentifier>>,
    pub chosen_alpn: Option<AlpnIdentifier>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ParametersSet {
    pub initiator: Option<TransportInitiator>,

    pub resumption_allowed: Option<bool>,
    pub early_data_enabled: Option<bool>,
    pub tls_cipher: Option<String>,

    pub original_destination_connection_id: Option<Bytes>,
    pub initial_source_connection_id: Option<Bytes>,
    pub retry_source_connection_id: Option<Bytes>,
    pub stateless_reset_token: Option<StatelessResetToken>,
    pub disable_active_migration: Option<bool>,

    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u64>,
    pub ack_delay_exponent: Option<u64>,
    pub max_ack_delay: Option<u64>,
    pub active_connection_id_limit: Option<u64>,

    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,

    pub preferred_address: Option<PreferredAddress>,

    pub unknown_parameters: Vec<UnknownTransportParameter>,

    pub max_datagram_frame_size: Option<u64>,
    pub grease_quic_bit: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct UnknownTransportParameter {
    pub id: u64,
    pub value: Bytes,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ParametersRestored {
    pub disable_active_migration: Option<bool>,

    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u64>,
    pub active_connection_id_limit: Option<u64>,

    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,

    pub max_datagram_frame_size: Option<u64>,
    pub grease_quic_bit: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Ecn {
    #[serde(rename = "Not-ECT")]
    NotEct,
    #[serde(rename = "ECT(1)")]
    Ect1,
    #[serde(rename = "ECT(0)")]
    Ect0,
    #[serde(rename = "CE")]
    CE,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct UdpDatagramsReceived {
    pub count: Option<u16>,
    pub raw: Option<Vec<RawInfo>>,
    pub ecn: Option<Ecn>,
    pub datagram_ids: Option<Vec<u32>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct UdpDatagramsSent {
    pub count: Option<u16>,
    pub raw: Option<Vec<RawInfo>>,
    pub ecn: Option<Ecn>,
    pub datagram_ids: Option<Vec<u32>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct UdpDatagramDropped {
    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct PacketReceived {
    pub header: PacketHeader,
    // `frames` is defined here in the QLog schema specification. However,
    // our streaming serializer requires serde to put the object at the end,
    // so we define it there and depend on serde's preserve_order feature.
    pub stateless_reset_token: Option<StatelessResetToken>,

    pub supported_versions: Option<Vec<Bytes>>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketReceivedTrigger>,

    pub frames: Option<Vec<QuicFrame>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct PacketSent {
    pub header: PacketHeader,
    // `frames` is defined here in the QLog schema specification. However,
    // our streaming serializer requires serde to put the object at the end,
    // so we define it there and depend on serde's preserve_order feature.
    pub stateless_reset_token: Option<StatelessResetToken>,

    pub supported_versions: Option<Vec<Bytes>>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,
    pub is_mtu_probe_packet: Option<bool>,

    pub trigger: Option<PacketSentTrigger>,

    pub send_at_time: Option<f32>,

    pub frames: Option<SmallVec<[QuicFrame; 1]>>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct PacketDropped {
    pub header: Option<PacketHeader>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub details: Option<String>,

    pub trigger: Option<PacketDroppedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct PacketBuffered {
    pub header: Option<PacketHeader>,

    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketBufferedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
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

    pub trigger: Option<StreamTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct FramesProcessed {
    pub frames: Vec<QuicFrame>,

    pub packet_numbers: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DataMovedAdditionalInfo {
    FinSet,
    StreamReset,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct StreamDataMoved {
    pub stream_id: Option<u64>,
    pub offset: Option<u64>,
    pub from: Option<DataRecipient>,
    pub to: Option<DataRecipient>,
    pub additional_info: Option<DataMovedAdditionalInfo>,
    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct DatagramDataMoved {
    pub from: Option<DataRecipient>,
    pub to: Option<DataRecipient>,
    pub raw: Option<RawInfo>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockedState {
    Blocked,
    Unidirectionalblocked,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReason {
    Scheduled,
    Pacing,
    AmplificationProtection,
    CongestionControl,
    ConnectionFlowControl,
    StreamFlowControl,
    StreamId,
    Application,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ConnectionDataBlockedUpdated {
    old: Option<BlockedState>,
    new: BlockedState,
    reason: Option<BlockedReason>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct StreamDataBlockedUpdated {
    old: Option<BlockedState>,
    new: BlockedState,
    stream_id: u64,
    reason: Option<BlockedReason>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct DatagramDataBlockedUpdated {
    old: Option<BlockedState>,
    new: BlockedState,
    reason: Option<BlockedReason>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    ProbingStarted,
    ProbingAbandoned,
    ProbingSuccessful,
    MigrationStarted,
    MigrationAbandoned,
    MigrationComplete,
    #[default]
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MigrationStateUpdated {
    pub old: Option<MigrationState>,
    pub new: MigrationState,

    pub tuple_id: Option<String>,

    pub tuple_remote: Option<TupleEndpointInfo>,
    pub tuple_local: Option<TupleEndpointInfo>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum CongestionStateUpdatedTrigger {
    PersistentCongestion,
    Ecn,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
    LossTimeout,
    PathValidation,
    HandshakeTimeout,
    IdleTimeout,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    PtoExpired,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TimerEventType {
    Set,
    Expired,
    Cancelled,
    #[default]
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
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
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct RecoveryMetricsUpdated {
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
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct CongestionStateUpdated {
    pub old: Option<String>,
    pub new: String,

    pub trigger: Option<CongestionStateUpdatedTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TimerUpdated {
    pub timer_type: Option<TimerType>,
    pub timer_id: Option<u64>,
    pub packet_number_space: Option<PacketNumberSpace>,
    pub event_type: TimerEventType,
    pub delta: Option<f32>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct PacketLost {
    pub header: Option<PacketHeader>,

    pub frames: Option<Vec<QuicFrame>>,
    pub is_mtu_probe_packet: Option<bool>,

    pub trigger: Option<PacketLostTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct MarkedForRetransmit {
    pub frames: Vec<QuicFrame>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum EcnState {
    Testing,
    #[default]
    Unknown,
    Failed,
    Capable,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct EcnStateUpdated {
    pub old: Option<EcnState>,
    pub new: EcnState,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,

    ServerHandshakeSecret,
    ClientHandshakeSecret,

    #[serde(rename = "server_0rtt_secret")]
    Server0RttSecret,
    #[serde(rename = "client_0rtt_secret")]
    Client0RttSecret,
    #[serde(rename = "server_1rtt_secret")]
    Server1RttSecret,
    #[serde(rename = "client_1rtt_secret")]
    Client1RttSecret,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KeyUpdateOrRetiredTrigger {
    Tls,
    RemoteUpdate,
    LocalUpdate,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct KeyUpdated {
    pub key_type: KeyType,

    pub old: Option<Bytes>,
    pub new: Option<Bytes>,

    pub key_phase: Option<u64>,

    pub trigger: Option<KeyUpdateOrRetiredTrigger>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyDiscarded {
    pub key_type: KeyType,
    pub key: Option<Bytes>,

    pub key_phase: Option<u64>,

    pub trigger: Option<KeyUpdateOrRetiredTrigger>,
}

#[cfg(test)]
mod tests {

    use crate::events::quic::PacketType;
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
