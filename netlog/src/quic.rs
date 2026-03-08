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

use serde::Deserialize;
use serde::Serialize;

use super::EventHeader;

#[derive(Debug)]
pub enum Event {
    QuicSession(QuicSessionEvent),
    QuicSessionTransportParametersSent(QuicSessionTransportParametersSentEvent),
    QuicSessionTransportParametersReceived(
        QuicSessionTransportParametersReceivedEvent,
    ),
    QuicSessionUnauthenticatedPacketHeaderReceived(
        QuicSessionUnauthenticatedPacketHeaderReceived,
    ),
    QuicSessionPacketSent(QuicSessionPacketSent),
    QuicSessionAckFrameSent(QuicSessionAckFrameSent),
    QuicSessionAckFrameReceived(QuicSessionAckFrameReceived),
    QuicSessionStreamFrameReceived(QuicSessionStreamFrameReceivedEvent),
    QuicSessionStopSendingFrameSent(QuicSessionStopSendingFrameSentEvent),
    QuicSessionRstStreamFrameSent(QuicSessionRstStreamFrameSentEvent),
    QuicSessionRstStreamFrameReceived(QuicSessionRstStreamFrameReceivedEvent),
    QuicSessionBlockedFrameReceived(QuicSessionBlockedFrameReceivedEvent),
    QuicSessionWindowUpdateFrameSent(QuicSessionWindowUpdateFrameSentEvent),
    QuicSessionClosed(QuicSessionClosedEvent),
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionParams {
    pub cert_verify_flags: u64,
    pub connection_id: String,
    pub host: String,
    pub port: u16,
    #[serde(alias = "network_anonymization_key")]
    pub network_isolation_key: String,
    pub privacy_mode: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionEvent {
    pub params: QuicSessionParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionTransportParametersSentParams {
    pub quic_transport_parameters: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionTransportParametersSentEvent {
    pub params: QuicSessionTransportParametersSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionTransportParametersReceivedParams {
    pub quic_transport_parameters: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionTransportParametersReceivedEvent {
    pub params: QuicSessionTransportParametersReceivedParams,
}

// TODO: this should really be done using serde, not hacked like this. What
// makes it difficult is netlogs concats all these fields into one string.
#[derive(Debug, Default)]
pub struct TransportParameters {
    pub versions: String,
    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub initial_source_connection_id: Option<String>,
    pub max_datagram_frame_size: Option<u64>,
}

impl From<String> for TransportParameters {
    // Example string:
    // [Client legacy[version 00000001] [chosen_version 00000001 other_versions
    // 00000001] max_idle_timeout 30000 max_udp_payload_size 1472 initial_max_data
    // 15728640 initial_max_stream_data_bidi_local 6291456
    // initial_max_stream_data_bidi_remote 6291456 initial_max_stream_data_uni
    // 6291456 initial_max_streams_bidi 100 initial_max_streams_uni 103
    // initial_source_connection_id 0 max_datagram_frame_size 65536]
    fn from(value: String) -> Self {
        if value.len() < 3 {
            // String is probably bogus, so just return defaults
            return Default::default();
        }

        let mut tp = TransportParameters::default();

        // The format is quite gnarly, potentially this could be parsed using
        // regex but doing something very simple for now.
        let inner = &value[1..value.len() - 1];
        let last_version_pos = inner.rfind(']').unwrap_or_default();
        tp.versions = inner[0..last_version_pos + 1].to_string();
        let rest = &inner[last_version_pos + 2..inner.len()];

        let mut split = rest.split(' ').peekable();

        while let Some(item) = split.next() {
            if split.peek().is_none() {
                break;
            }

            match item {
                "max_idle_timeout" =>
                    tp.max_idle_timeout = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "max_udp_payload_size" =>
                    tp.max_udp_payload_size = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_max_data" =>
                    tp.initial_max_data = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_max_stream_data_bidi_local" =>
                    tp.initial_max_stream_data_bidi_local = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_max_stream_data_bidi_remote" =>
                    tp.initial_max_stream_data_bidi_remote = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_max_stream_data_uni" =>
                    tp.initial_max_stream_data_uni = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_max_streams_bidi" =>
                    tp.initial_max_streams_bidi = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_max_streams_uni" =>
                    tp.initial_max_streams_uni = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                "initial_source_connection_id" =>
                    tp.initial_source_connection_id =
                        split.peek().map(|v| (*v).to_string()),
                "max_datagram_frame_size" =>
                    tp.max_datagram_frame_size = split
                        .peek()
                        .map(|v| (*v).parse::<u64>().unwrap_or_default()),
                _ => (),
            }
        }

        tp
    }
}

impl From<QuicSessionTransportParametersReceivedParams> for TransportParameters {
    fn from(value: QuicSessionTransportParametersReceivedParams) -> Self {
        value.quic_transport_parameters.into()
    }
}

impl From<QuicSessionTransportParametersSentParams> for TransportParameters {
    fn from(value: QuicSessionTransportParametersSentParams) -> Self {
        value.quic_transport_parameters.into()
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionUnauthenticatedPacketHeaderReceivedParams {
    pub connection_id: String,
    pub header_format: String,
    pub long_header_type: Option<String>,
    pub packet_number: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionUnauthenticatedPacketHeaderReceived {
    pub params: QuicSessionUnauthenticatedPacketHeaderReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionPacketSentParams {
    pub encryption_level: String,
    pub packet_number: u64,
    pub sent_time_us: u64,
    transmission_type: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionPacketSent {
    pub params: QuicSessionPacketSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionAckFrameSentParams {
    pub delta_time_largest_observed_us: u64,
    pub largest_observed: u64,
    pub missing_packets: Vec<u64>,
    pub received_packet_times: Vec<u64>,
    pub smallest_observed: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionAckFrameSent {
    pub params: QuicSessionAckFrameSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionAckFrameReceivedParams {
    pub delta_time_largest_observed_us: u64,
    pub largest_observed: u64,
    pub missing_packets: Vec<u64>,
    pub received_packet_times: Vec<u64>,
    pub smallest_observed: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionAckFrameReceived {
    pub params: QuicSessionAckFrameReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStreamFrameReceivedParams {
    pub stream_id: u64,
    pub fin: bool,
    pub offset: u64,
    pub length: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStreamFrameReceivedEvent {
    pub params: QuicSessionStreamFrameReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStopSendingFrameSentParams {
    pub stream_id: u64,
    pub quic_rst_stream_error: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStopSendingFrameSentEvent {
    pub params: QuicSessionStopSendingFrameSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionRstStreamFrameSentParams {
    pub stream_id: u64,
    pub quic_rst_stream_error: u64,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionRstStreamFrameSentEvent {
    pub params: QuicSessionRstStreamFrameSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionRstStreamFrameReceivedParams {
    pub stream_id: u64,
    pub quic_rst_stream_error: u64,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionRstStreamFrameReceivedEvent {
    pub params: QuicSessionRstStreamFrameReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionBlockedFrameReceivedParams {
    pub stream_id: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionBlockedFrameReceivedEvent {
    pub params: QuicSessionBlockedFrameReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionWindowUpdateFrameSentParams {
    pub byte_offset: u64,
    pub stream_id: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionWindowUpdateFrameSentEvent {
    pub params: QuicSessionWindowUpdateFrameSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionClosedParams {
    pub details: String,
    pub from_peer: bool,
    pub quic_error: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionClosedEvent {
    pub params: QuicSessionClosedParams,
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
pub fn parse_event(
    event_hdr: &EventHeader, event: &[u8],
) -> Option<super::Event> {
    match event_hdr.ty_string.as_str() {
        "QUIC_SESSION" =>
            if event_hdr.phase_string == "PHASE_BEGIN" {
                let ev: QuicSessionEvent = serde_json::from_slice(event).unwrap();
                return Some(super::Event::Quic(Event::QuicSession(ev)));
            },

        "QUIC_SESSION_TRANSPORT_PARAMETERS_SENT" => {
            let ev: QuicSessionTransportParametersSentEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionTransportParametersSent(ev),
            ));
        },

        "QUIC_SESSION_TRANSPORT_PARAMETERS_RECEIVED" => {
            let ev: QuicSessionTransportParametersReceivedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionTransportParametersReceived(ev),
            ));
        },

        "QUIC_SESSION_STREAM_FRAME_RECEIVED" => {
            let ev: QuicSessionStreamFrameReceivedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionStreamFrameReceived(ev),
            ));
        },

        "QUIC_SESSION_STOP_SENDING_FRAME_SENT" => {
            let ev: QuicSessionStopSendingFrameSentEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionStopSendingFrameSent(ev),
            ));
        },

        "QUIC_SESSION_STOP_SENDING_FRAME_RECEIVED" => {
            // TODO
        },

        "QUIC_SESSION_RST_STREAM_FRAME_SENT" => {
            let ev: QuicSessionRstStreamFrameSentEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionRstStreamFrameSent(ev),
            ));
        },

        "QUIC_SESSION_RST_STREAM_FRAME_RECEIVED" => {
            let ev: QuicSessionRstStreamFrameReceivedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionRstStreamFrameReceived(ev),
            ));
        },

        "QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED" => {
            let ev: QuicSessionUnauthenticatedPacketHeaderReceived =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::Quic(
                Event::QuicSessionUnauthenticatedPacketHeaderReceived(ev),
            ));
        },

        "QUIC_SESSION_PACKET_SENT" => {
            let ev: QuicSessionPacketSent =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::Quic(Event::QuicSessionPacketSent(ev)));
        },

        "QUIC_SESSION_PACKET_RETRANSMITTED" => {
            // TODO
        },

        "QUIC_SESSION_ACK_FRAME_SENT" => {
            let ev: QuicSessionAckFrameSent =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::Quic(Event::QuicSessionAckFrameSent(ev)));
        },

        "QUIC_SESSION_ACK_FRAME_RECEIVED" => {
            let ev: QuicSessionAckFrameReceived =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::Quic(Event::QuicSessionAckFrameReceived(
                ev,
            )));
        },

        "QUIC_SESSION_PACKET_LOST" => {
            // TODO
        },

        "QUIC_SESSION_CLOSED" => {
            let ev: QuicSessionClosedEvent =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::Quic(Event::QuicSessionClosed(ev)));
        },

        "QUIC_SESSION_BLOCKED_FRAME_RECEIVED" => {
            let ev: QuicSessionBlockedFrameReceivedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionBlockedFrameReceived(ev),
            ));
        },

        "QUIC_SESSION_STREAMS_BLOCKED_FRAME_RECEIVED" => {
            // TODO
        },

        "QUIC_SESSION_WINDOW_UPDATE_FRAME_SENT" => {
            let ev: QuicSessionWindowUpdateFrameSentEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Quic(
                Event::QuicSessionWindowUpdateFrameSent(ev),
            ));
        },

        // Other events observed in netlogs but not currently supported.
        "QUIC_ACCEPT_CH_FRAME_RECEIVED" |
        "QUIC_CHROMIUM_CLIENT_STREAM_READ_EARLY_HINTS_RESPONSE_HEADERS" |
        "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS" |
        "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_TRAILERS" |
        "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS" |
        "QUIC_CONNECTION_MIGRATION_FAILURE" |
        "QUIC_CONNECTION_MIGRATION_FAILURE_AFTER_PROBING" |
        "QUIC_CONNECTION_MIGRATION_ON_MIGRATE_BACK" |
        "QUIC_CONNECTION_MIGRATION_ON_NETWORK_CONNECTED" |
        "QUIC_CONNECTION_MIGRATION_ON_NETWORK_DISCONNECTED" |
        "QUIC_CONNECTION_MIGRATION_ON_NETWORK_MADE_DEFAULT" |
        "QUIC_CONNECTION_MIGRATION_ON_PATH_DEGRADING" |
        "QUIC_CONNECTION_MIGRATION_ON_WRITE_ERROR" |
        "QUIC_CONNECTION_MIGRATION_PLATFORM_NOTIFICATION" |
        "QUIC_CONNECTION_MIGRATION_SUCCESS" |
        "QUIC_CONNECTION_MIGRATION_SUCCESS_AFTER_PROBING" |
        "QUIC_CONNECTION_MIGRATION_TRIGGERED" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_CANCEL_PROBING" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_PROBE_RECEIVED" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_PROBE_SENT" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_START_PROBING" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_STATELESS_RESET_RECEIVED" |
        "QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM" |
        "QUIC_HTTP_STREAM_PUSH_PROMISE_RENDEZVOUS" |
        "QUIC_PORT_MIGRATION_FAILURE" |
        "QUIC_PORT_MIGRATION_SUCCESS" |
        "QUIC_PORT_MIGRATION_TRIGGERED" |
        "QUIC_READ_ERROR" |
        "QUIC_SESSION_ATTEMPTING_TO_PROCESS_UNDECRYPTABLE_PACKET" |
        "QUIC_SESSION_BLOCKED_FRAME_SENT" |
        "QUIC_SESSION_BUFFERED_UNDECRYPTABLE_PACKET" |
        "QUIC_SESSION_CLIENT_GOAWAY_ON_PATH_DEGRADING" |
        "QUIC_SESSION_CLOSE_ON_ERROR" |
        "QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED" |
        "QUIC_SESSION_CONNECTION_CLOSE_FRAME_SENT" |
        "QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED" |
        "QUIC_SESSION_DROPPED_UNDECRYPTABLE_PACKET" |
        "QUIC_SESSION_DUPLICATE_PACKET_RECEIVED" |
        "QUIC_SESSION_GOAWAY_FRAME_RECEIVED" |
        "QUIC_SESSION_GOAWAY_FRAME_SENT" |
        "QUIC_SESSION_KEY_UPDATE" |
        "QUIC_SESSION_MAX_STREAMS_FRAME_RECEIVED" |
        "QUIC_SESSION_MAX_STREAMS_FRAME_SENT" |
        "QUIC_SESSION_MESSAGE_FRAME_RECEIVED" |
        "QUIC_SESSION_MESSAGE_FRAME_SENT" |
        "QUIC_SESSION_MTU_DISCOVERY_FRAME_SENT" |
        "QUIC_SESSION_NEW_CONNECTION_ID_FRAME_RECEIVED" |
        "QUIC_SESSION_NEW_CONNECTION_ID_FRAME_SENT" |
        "QUIC_SESSION_NEW_TOKEN_FRAME_RECEIVED" |
        "QUIC_SESSION_NEW_TOKEN_FRAME_SENT" |
        "QUIC_SESSION_PATH_CHALLENGE_FRAME_RECEIVED" |
        "QUIC_SESSION_PATH_CHALLENGE_FRAME_SENT" |
        "QUIC_SESSION_PATH_RESPONSE_FRAME_RECEIVED" |
        "QUIC_SESSION_PATH_RESPONSE_FRAME_SENT" |
        "QUIC_SESSION_PING_FRAME_RECEIVED" |
        "QUIC_SESSION_PING_FRAME_SENT" |
        "QUIC_SESSION_PUBLIC_RESET_PACKET_RECEIVED" |
        "QUIC_SESSION_PUSH_PROMISE_RECEIVED" |
        "QUIC_SESSION_RETIRE_CONNECTION_ID_FRAME_RECEIVED" |
        "QUIC_SESSION_RETIRE_CONNECTION_ID_FRAME_SENT" |
        "QUIC_SESSION_STOP_WAITING_FRAME_RECEIVED" |
        "QUIC_SESSION_STOP_WAITING_FRAME_SENT" |
        "QUIC_SESSION_TRANSPORT_PARAMETERS_RESUMED" |
        "QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE" |
        "QUIC_SESSION_WEBTRANSPORT_CLIENT_STATE_CHANGED" |
        "QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED" |
        "QUIC_SESSION_ZERO_RTT_REJECTED" |
        "QUIC_SESSION_CERTIFICATE_VERIFIED" |
        "QUIC_SESSION_CERTIFICATE_VERIFY_FAILED" |
        "QUIC_SESSION_COALESCED_PACKET_SENT" |
        "QUIC_SESSION_CRYPTO_FRAME_RECEIVED" |
        "QUIC_SESSION_CRYPTO_FRAME_SENT" |
        "QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_RECEIVED" |
        "QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_SENT" |
        "QUIC_SESSION_HANDSHAKE_DONE_FRAME_RECEIVED" |
        "QUIC_SESSION_PACKET_HEADER_REVIVED" |
        "QUIC_SESSION_PADDING_FRAME_RECEIVED" |
        "QUIC_SESSION_PADDING_FRAME_SENT" |
        "QUIC_SESSION_STREAMS_BLOCKED_FRAME_SENT" |
        "QUIC_SESSION_STREAM_FRAME_COALESCED" |
        "QUIC_SESSION_STREAM_FRAME_SENT" |
        "QUIC_SESSION_VERSION_NEGOTIATED" |
        "QUIC_SESSION_VERSION_NEGOTIATION_PACKET_RECEIVED" => (),

        // Most likely uninteresting events
        "QUIC_SESSION_PACKET_RECEIVED" |
        "QUIC_CONNECTION_MIGRATION_MODE" |
        "QUIC_STREAM_FACTORY_JOB" |
        "QUIC_STREAM_FACTORY_JOB_BOUND_TO_HTTP_STREAM_JOB" |
        "QUIC_STREAM_FACTORY_JOB_CONNECT" |
        "QUIC_STREAM_FACTORY_JOB_RETRY_ON_ALTERNATE_NETWORK" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_NOT_USED_ON_CONNECTION" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_RESOLUTION_MATCHED" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_RESOLUTION_NO_MATCH" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_TRIED_ON_CONNECTION" => (),

        // Ignored since it contains no extra params
        "QUIC_SESSION_PACKET_AUTHENTICATED" => (),

        // The netlog format is continually evolving, log any unknown types
        // in case they are interesting.
        _ => log::trace!("skipping unknown QUIC type....{}", event_hdr.ty_string),
    }

    None
}
