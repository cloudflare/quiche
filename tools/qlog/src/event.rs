// Copyright (C) 2020, Cloudflare, Inc.
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

//! Module-defined Event and functions to work with qlog data structures.
//!
//! The Qlog data structures are very flexible, which makes working with them
//! liable to simple semantic errors. This module provides some helper functions
//! that focus on creating valid types, while also reducing some of the
//! verbosity of using the raw data structures.

use super::*;

/// A representation of qlog events that couple EventCategory, EventType and
/// EventData.
///
/// Functions are provided to help construct valid events. Most events consist
/// of several optional fields, so minimal versions of these functions are
/// provided, which accept only mandatory qlog parameters. Minimal functions are
/// identified by a `_min` suffix.
#[derive(Clone)]
pub struct Event {
    pub category: EventCategory,
    pub ty: EventType,
    pub data: EventData,
}

#[allow(clippy::too_many_arguments)]
impl Event {
    // Connectivity events.

    /// Returns:
    /// * `EventCategory`=`Connectivity`
    /// * `EventType`=`ConnectivityEventType::ServerListening`
    /// * `EventData`=`ServerListening`.
    pub fn server_listening(
        ip_v4: Option<String>, ip_v6: Option<String>, port_v4: u64, port_v6: u64,
        quic_versions: Option<Vec<String>>, alpn_values: Option<Vec<String>>,
        stateless_reset_required: Option<bool>,
    ) -> Self {
        Event {
            category: EventCategory::Connectivity,
            ty: EventType::ConnectivityEventType(
                ConnectivityEventType::ServerListening,
            ),
            data: EventData::ServerListening {
                ip_v4,
                ip_v6,
                port_v4,
                port_v6,
                quic_versions,
                alpn_values,
                stateless_reset_required,
            },
        }
    }

    pub fn server_listening_min(port_v4: u64, port_v6: u64) -> Self {
        Event::server_listening(None, None, port_v4, port_v6, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Connectivity`
    /// * `EventType`=`ConnectivityEventType::ConnectionStarted`
    /// * `EventData`=`ConnectionStarted`.
    pub fn connection_started(
        ip_version: String, src_ip: String, dst_ip: String,
        protocol: Option<String>, src_port: u64, dst_port: u64,
        quic_version: Option<String>, src_cid: Option<String>,
        dst_cid: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Connectivity,
            ty: EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionStarted,
            ),
            data: EventData::ConnectionStarted {
                ip_version,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                quic_version,
                src_cid,
                dst_cid,
            },
        }
    }

    pub fn connection_started_min(
        ip_version: String, src_ip: String, dst_ip: String, src_port: u64,
        dst_port: u64,
    ) -> Self {
        Event::connection_started(
            ip_version, src_ip, dst_ip, None, src_port, dst_port, None, None,
            None,
        )
    }

    /// Returns:
    /// * `EventCategory`=`Connectivity`
    /// * `EventType`=`ConnectivityEventType::ConnectionIdUpdated`
    /// * `EventData`=`ConnectionIdUpdated`.
    pub fn connection_id_updated(
        src_old: Option<String>, src_new: Option<String>,
        dst_old: Option<String>, dst_new: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Connectivity,
            ty: EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionIdUpdated,
            ),
            data: EventData::ConnectionIdUpdated {
                src_old,
                src_new,
                dst_old,
                dst_new,
            },
        }
    }

    pub fn connection_id_updated_min() -> Self {
        Event::connection_id_updated(None, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Connectivity`
    /// * `EventType`=`ConnectivityEventType::SpinBitUpdated`
    /// * `EventData`=`SpinBitUpdated`.
    pub fn spinbit_updated(state: bool) -> Self {
        Event {
            category: EventCategory::Connectivity,
            ty: EventType::ConnectivityEventType(
                ConnectivityEventType::SpinBitUpdated,
            ),
            data: EventData::SpinBitUpdated { state },
        }
    }

    /// Returns:
    /// * `EventCategory`=`Connectivity`
    /// * `EventType`=`ConnectivityEventType::ConnectionState`
    /// * `EventData`=`ConnectionState`.
    pub fn connection_state_updated(
        old: Option<ConnectionState>, new: ConnectionState,
    ) -> Self {
        Event {
            category: EventCategory::Connectivity,
            ty: EventType::ConnectivityEventType(
                ConnectivityEventType::ConnectionStateUpdated,
            ),
            data: EventData::ConnectionStateUpdated { old, new },
        }
    }

    pub fn connection_state_updated_min(new: ConnectionState) -> Self {
        Event::connection_state_updated(None, new)
    }

    // Transport events.

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::ParametersSet`
    /// * `EventData`=`ParametersSet`.
    pub fn transport_parameters_set(
        owner: Option<TransportOwner>, resumption_allowed: Option<bool>,
        early_data_enabled: Option<bool>, alpn: Option<String>,
        version: Option<String>, tls_cipher: Option<String>,
        original_connection_id: Option<String>,
        stateless_reset_token: Option<String>,
        disable_active_migration: Option<bool>, idle_timeout: Option<u64>,
        max_packet_size: Option<u64>, ack_delay_exponent: Option<u64>,
        max_ack_delay: Option<u64>, active_connection_id_limit: Option<u64>,
        initial_max_data: Option<String>,
        initial_max_stream_data_bidi_local: Option<String>,
        initial_max_stream_data_bidi_remote: Option<String>,
        initial_max_stream_data_uni: Option<String>,
        initial_max_streams_bidi: Option<String>,
        initial_max_streams_uni: Option<String>,
        preferred_address: Option<PreferredAddress>,
    ) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(TransportEventType::ParametersSet),
            data: EventData::TransportParametersSet {
                owner,

                resumption_allowed,
                early_data_enabled,
                alpn,
                version,
                tls_cipher,

                original_connection_id,
                stateless_reset_token,
                disable_active_migration,

                idle_timeout,
                max_packet_size,
                ack_delay_exponent,
                max_ack_delay,
                active_connection_id_limit,

                initial_max_data,
                initial_max_stream_data_bidi_local,
                initial_max_stream_data_bidi_remote,
                initial_max_stream_data_uni,
                initial_max_streams_bidi,
                initial_max_streams_uni,

                preferred_address,
            },
        }
    }

    pub fn transport_parameters_set_min() -> Self {
        Event::transport_parameters_set(
            None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None,
        )
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::DatagramsReceived`
    /// * `EventData`=`DatagramsReceived`.
    pub fn datagrams_received(
        count: Option<u64>, byte_length: Option<u64>,
    ) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(
                TransportEventType::DatagramsReceived,
            ),
            data: EventData::DatagramsReceived { count, byte_length },
        }
    }

    pub fn datagrams_received_min() -> Self {
        Event::datagrams_received(None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::DatagramsSent`
    /// * `EventData`=`DatagramsSent`.
    pub fn datagrams_sent(count: Option<u64>, byte_length: Option<u64>) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(TransportEventType::DatagramsSent),
            data: EventData::DatagramsSent { count, byte_length },
        }
    }

    pub fn datagrams_sent_min() -> Self {
        Event::datagrams_sent(None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::DatagramDropped`
    /// * `EventData`=`DatagramDropped`.
    pub fn datagram_dropped(byte_length: Option<u64>) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(
                TransportEventType::DatagramDropped,
            ),
            data: EventData::DatagramDropped { byte_length },
        }
    }

    pub fn datagram_dropped_min() -> Self {
        Event::datagram_dropped(None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::PacketReceived`
    /// * `EventData`=`PacketReceived`.
    pub fn packet_received(
        packet_type: PacketType, header: PacketHeader,
        frames: Option<Vec<QuicFrame>>, is_coalesced: Option<bool>,
        raw_encrypted: Option<String>, raw_decrypted: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(TransportEventType::PacketReceived),
            data: EventData::PacketReceived {
                packet_type,
                header,
                frames,

                is_coalesced,

                raw_encrypted,
                raw_decrypted,
            },
        }
    }

    pub fn packet_received_min(
        packet_type: PacketType, header: PacketHeader,
    ) -> Self {
        Event::packet_received(packet_type, header, None, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::PacketSent`
    /// * `EventData`=`PacketSent`.
    pub fn packet_sent(
        packet_type: PacketType, header: PacketHeader,
        frames: Option<Vec<QuicFrame>>, is_coalesced: Option<bool>,
        raw_encrypted: Option<String>, raw_decrypted: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(TransportEventType::PacketSent),
            data: EventData::PacketSent {
                packet_type,
                header,
                frames,

                is_coalesced,

                raw_encrypted,
                raw_decrypted,
            },
        }
    }

    pub fn packet_sent_min(
        packet_type: PacketType, header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,
    ) -> Self {
        Event::packet_sent(packet_type, header, frames, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::PacketDropped`
    /// * `EventData`=`PacketDropped`.
    pub fn packet_dropped(
        packet_type: Option<PacketType>, packet_size: Option<u64>,
        raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(TransportEventType::PacketDropped),
            data: EventData::PacketDropped {
                packet_type,
                packet_size,
                raw,
            },
        }
    }

    pub fn packet_dropped_min() -> Self {
        Event::packet_dropped(None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::PacketBuffered`
    /// * `EventData`=`PacketBuffered`.
    pub fn packet_buffered(
        packet_type: PacketType, packet_number: String,
    ) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(TransportEventType::PacketBuffered),
            data: EventData::PacketBuffered {
                packet_type,
                packet_number,
            },
        }
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::StreamStateUpdated`
    /// * `EventData`=`StreamStateUpdated`.
    pub fn stream_state_updated(
        stream_id: String, stream_type: Option<StreamType>,
        old: Option<StreamState>, new: StreamState,
        stream_side: Option<StreamSide>,
    ) -> Self {
        Event {
            category: EventCategory::Connectivity,
            ty: EventType::TransportEventType(
                TransportEventType::StreamStateUpdated,
            ),
            data: EventData::StreamStateUpdated {
                stream_id,
                stream_type,
                old,
                new,
                stream_side,
            },
        }
    }

    pub fn stream_state_updated_min(stream_id: String, new: StreamState) -> Self {
        Event::stream_state_updated(stream_id, None, None, new, None)
    }

    /// Returns:
    /// * `EventCategory`=`Transport`
    /// * `EventType`=`TransportEventType::FramesProcessed`
    /// * `EventData`=`FramesProcessed`.
    pub fn frames_processed(frames: Vec<QuicFrame>) -> Self {
        Event {
            category: EventCategory::Transport,
            ty: EventType::TransportEventType(
                TransportEventType::FramesProcessed,
            ),
            data: EventData::FramesProcessed { frames },
        }
    }

    // Recovery events.

    /// Returns:
    /// * `EventCategory`=`Recovery`
    /// * `EventType`=`RecoveryEventType::ParametersSet`
    /// * `EventData`=`RecoveryParametersSet`.
    pub fn recovery_parameters_set(
        reordering_threshold: Option<u64>, time_threshold: Option<u64>,
        timer_granularity: Option<u64>, initial_rtt: Option<u64>,
        max_datagram_size: Option<u64>, initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u64>,
        loss_reduction_factor: Option<u64>,
        persistent_congestion_threshold: Option<u64>,
    ) -> Self {
        Event {
            category: EventCategory::Recovery,
            ty: EventType::RecoveryEventType(RecoveryEventType::ParametersSet),
            data: EventData::RecoveryParametersSet {
                reordering_threshold,
                time_threshold,
                timer_granularity,
                initial_rtt,
                max_datagram_size,
                initial_congestion_window,
                minimum_congestion_window,
                loss_reduction_factor,
                persistent_congestion_threshold,
            },
        }
    }

    pub fn recovery_parameters_set_min() -> Self {
        Event::recovery_parameters_set(
            None, None, None, None, None, None, None, None, None,
        )
    }

    /// Returns:
    /// * `EventCategory`=`Recovery`
    /// * `EventType`=`RecoveryEventType::MetricsUpdated`
    /// * `EventData`=`MetricsUpdated`.
    pub fn metrics_updated(
        min_rtt: Option<u64>, smoothed_rtt: Option<u64>, latest_rtt: Option<u64>,
        rtt_variance: Option<u64>, max_ack_delay: Option<u64>,
        pto_count: Option<u64>, congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>, ssthresh: Option<u64>,
        packets_in_flight: Option<u64>, in_recovery: Option<bool>,
        pacing_rate: Option<u64>,
    ) -> Self {
        Event {
            category: EventCategory::Recovery,
            ty: EventType::RecoveryEventType(RecoveryEventType::MetricsUpdated),
            data: EventData::MetricsUpdated {
                min_rtt,
                smoothed_rtt,
                latest_rtt,
                rtt_variance,
                max_ack_delay,
                pto_count,
                congestion_window,
                bytes_in_flight,
                ssthresh,
                packets_in_flight,
                in_recovery,
                pacing_rate,
            },
        }
    }

    pub fn metrics_updated_min() -> Self {
        Event::metrics_updated(
            None, None, None, None, None, None, None, None, None, None, None,
            None,
        )
    }

    /// Returns:
    /// * `EventCategory`=`Recovery`
    /// * `EventType`=`RecoveryEventType::CongestionStateUpdated`
    /// * `EventData`=`CongestionStateUpdated`.
    pub fn congestion_state_updated(old: Option<String>, new: String) -> Self {
        Event {
            category: EventCategory::Recovery,
            ty: EventType::RecoveryEventType(
                RecoveryEventType::CongestionStateUpdated,
            ),
            data: EventData::CongestionStateUpdated { old, new },
        }
    }

    pub fn congestion_state_updated_min(new: String) -> Self {
        Event::congestion_state_updated(None, new)
    }

    /// Returns:
    /// * `EventCategory`=`Recovery`
    /// * `EventType`=`RecoveryEventType::LossTimerSet`
    /// * `EventData`=`LossTimerSet`.
    pub fn loss_timer_set(
        timer_type: Option<TimerType>, timeout: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Recovery,
            ty: EventType::RecoveryEventType(RecoveryEventType::LossTimerSet),
            data: EventData::LossTimerSet {
                timer_type,
                timeout,
            },
        }
    }

    pub fn loss_timer_set_min() -> Self {
        Event::loss_timer_set(None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Recovery`
    /// * `EventType`=`RecoveryEventType::PacketLost`
    /// * `EventData`=`PacketLost`.
    pub fn packet_lost(
        packet_type: PacketType, packet_number: String,
        header: Option<PacketHeader>, frames: Vec<QuicFrame>,
    ) -> Self {
        Event {
            category: EventCategory::Recovery,
            ty: EventType::RecoveryEventType(RecoveryEventType::PacketLost),
            data: EventData::PacketLost {
                packet_type,
                packet_number,
                header,
                frames,
            },
        }
    }

    pub fn packet_lost_min(
        packet_type: PacketType, packet_number: String, frames: Vec<QuicFrame>,
    ) -> Self {
        Event::packet_lost(packet_type, packet_number, None, frames)
    }

    /// Returns:
    /// * `EventCategory`=`Recovery`
    /// * `EventType`=`RecoveryEventType::MarkedForRetransmit`
    /// * `EventData`=`MarkedForRetransmit`.
    pub fn marked_for_retransmit(frames: Vec<QuicFrame>) -> Self {
        Event {
            category: EventCategory::Recovery,
            ty: EventType::RecoveryEventType(
                RecoveryEventType::MarkedForRetransmit,
            ),
            data: EventData::MarkedForRetransmit { frames },
        }
    }

    // HTTP/3 events.

    /// Returns:
    /// * `EventCategory`=`Http`
    /// * `EventType`=`Http3EventType::ParametersSet`
    /// * `EventData`=`H3ParametersSet`.
    pub fn h3_parameters_set(
        owner: Option<H3Owner>, max_header_list_size: Option<u64>,
        max_table_capacity: Option<u64>, blocked_streams_count: Option<u64>,
        push_allowed: Option<bool>, waits_for_settings: Option<bool>,
    ) -> Self {
        Event {
            category: EventCategory::Http,
            ty: EventType::Http3EventType(Http3EventType::ParametersSet),
            data: EventData::H3ParametersSet {
                owner,
                max_header_list_size,
                max_table_capacity,
                blocked_streams_count,
                push_allowed,
                waits_for_settings,
            },
        }
    }

    pub fn h3_parameters_set_min() -> Self {
        Event::h3_parameters_set(None, None, None, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Http`
    /// * `EventType`=`Http3EventType::StreamTypeSet`
    /// * `EventData`=`H3StreamTypeSet`.
    pub fn h3_stream_type_set(
        stream_id: String, owner: Option<H3Owner>, old: Option<H3StreamType>,
        new: H3StreamType,
    ) -> Self {
        Event {
            category: EventCategory::Http,
            ty: EventType::Http3EventType(Http3EventType::StreamTypeSet),
            data: EventData::H3StreamTypeSet {
                stream_id,
                owner,
                old,
                new,
            },
        }
    }

    pub fn h3_stream_type_set_min(stream_id: String, new: H3StreamType) -> Self {
        Event::h3_stream_type_set(stream_id, None, None, new)
    }

    /// Returns:
    /// * `EventCategory`=`Http`
    /// * `EventType`=`Http3EventType::FrameCreated`
    /// * `EventData`=`H3FrameCreated`.
    pub fn h3_frame_created(
        stream_id: String, frame: Http3Frame, byte_length: Option<String>,
        raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Http,
            ty: EventType::Http3EventType(Http3EventType::FrameCreated),
            data: EventData::H3FrameCreated {
                stream_id,
                frame,
                byte_length,
                raw,
            },
        }
    }

    pub fn h3_frame_created_min(stream_id: String, frame: Http3Frame) -> Self {
        Event::h3_frame_created(stream_id, frame, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Http`
    /// * `EventType`=`Http3EventType::FrameParsed`
    /// * `EventData`=`H3FrameParsed`.
    pub fn h3_frame_parsed(
        stream_id: String, frame: Http3Frame, byte_length: Option<String>,
        raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Http,
            ty: EventType::Http3EventType(Http3EventType::FrameParsed),
            data: EventData::H3FrameParsed {
                stream_id,
                frame,
                byte_length,
                raw,
            },
        }
    }

    pub fn h3_frame_parsed_min(stream_id: String, frame: Http3Frame) -> Self {
        Event::h3_frame_parsed(stream_id, frame, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Http`
    /// * `EventType`=`Http3EventType::DataMoved`
    /// * `EventData`=`H3DataMoved`.
    pub fn h3_data_moved(
        stream_id: String, offset: Option<String>, length: Option<u64>,
        from: Option<H3DataRecipient>, to: Option<H3DataRecipient>,
        raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Http,
            ty: EventType::Http3EventType(Http3EventType::DataMoved),
            data: EventData::H3DataMoved {
                stream_id,
                offset,
                length,
                from,
                to,
                raw,
            },
        }
    }

    pub fn h3_data_moved_min(stream_id: String) -> Self {
        Event::h3_data_moved(stream_id, None, None, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Http`
    /// * `EventType`=`Http3EventType::PushResolved`
    /// * `EventData`=`H3PushResolved`.
    pub fn h3_push_resolved(
        push_id: Option<String>, stream_id: Option<String>,
        decision: Option<H3PushDecision>,
    ) -> Self {
        Event {
            category: EventCategory::Http,
            ty: EventType::Http3EventType(Http3EventType::PushResolved),
            data: EventData::H3PushResolved {
                push_id,
                stream_id,
                decision,
            },
        }
    }

    pub fn h3_push_resolved_min() -> Self {
        Event::h3_push_resolved(None, None, None)
    }

    // QPACK events.

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::StateUpdated`
    /// * `EventData`=`QpackStateUpdated`.
    pub fn qpack_state_updated(
        owner: Option<QpackOwner>, dynamic_table_capacity: Option<u64>,
        dynamic_table_size: Option<u64>, known_received_count: Option<u64>,
        current_insert_count: Option<u64>,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::StateUpdated),
            data: EventData::QpackStateUpdated {
                owner,
                dynamic_table_capacity,
                dynamic_table_size,
                known_received_count,
                current_insert_count,
            },
        }
    }

    pub fn qpack_state_updated_min() -> Self {
        Event::qpack_state_updated(None, None, None, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::StreamStateUpdated`
    /// * `EventData`=`QpackStreamStateUpdated`.
    pub fn qpack_stream_state_updated(
        stream_id: String, state: QpackStreamState,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::StreamStateUpdated),
            data: EventData::QpackStreamStateUpdated { stream_id, state },
        }
    }

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::DynamicTableUpdated`
    /// * `EventData`=`QpackDynamicTableUpdated`.
    pub fn qpack_dynamic_table_updated(
        update_type: QpackUpdateType, entries: Vec<QpackDynamicTableEntry>,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::DynamicTableUpdated),
            data: EventData::QpackDynamicTableUpdated {
                update_type,
                entries,
            },
        }
    }

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::HeadersEncoded`
    /// * `EventData`=`QpackHeadersEncoded`.
    pub fn qpack_headers_encoded(
        stream_id: Option<String>, headers: Option<HttpHeader>,
        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>, raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::HeadersEncoded),
            data: EventData::QpackHeadersEncoded {
                stream_id,
                headers,
                block_prefix,
                header_block,
                raw,
            },
        }
    }

    pub fn qpack_headers_encoded_min(
        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,
    ) -> Self {
        Event::qpack_headers_encoded(None, None, block_prefix, header_block, None)
    }

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::HeadersDecoded`
    /// * `EventData`=`QpackHeadersDecoded`.
    pub fn qpack_headers_decoded(
        stream_id: Option<String>, headers: Option<HttpHeader>,
        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>, raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::HeadersDecoded),
            data: EventData::QpackHeadersDecoded {
                stream_id,
                headers,
                block_prefix,
                header_block,
                raw,
            },
        }
    }

    pub fn qpack_headers_decoded_min(
        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,
    ) -> Self {
        Event::qpack_headers_decoded(None, None, block_prefix, header_block, None)
    }

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::InstructionSent`
    /// * `EventData`=`QpackInstructionSent`.
    pub fn qpack_instruction_sent(
        instruction: QPackInstruction, byte_length: Option<String>,
        raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::InstructionSent),
            data: EventData::QpackInstructionSent {
                instruction,
                byte_length,
                raw,
            },
        }
    }

    pub fn qpack_instruction_sent_min(instruction: QPackInstruction) -> Self {
        Event::qpack_instruction_sent(instruction, None, None)
    }

    /// Returns:
    /// * `EventCategory`=`Qpack`
    /// * `EventType`=`QpackEventType::InstructionReceived`
    /// * `EventData`=`QpackInstructionReceived`.
    pub fn qpack_instruction_received(
        instruction: QPackInstruction, byte_length: Option<String>,
        raw: Option<String>,
    ) -> Self {
        Event {
            category: EventCategory::Qpack,
            ty: EventType::QpackEventType(QpackEventType::InstructionReceived),
            data: EventData::QpackInstructionReceived {
                instruction,
                byte_length,
                raw,
            },
        }
    }

    pub fn qpack_instruction_received_min(instruction: QPackInstruction) -> Self {
        Event::qpack_instruction_received(instruction, None, None)
    }

    /// Checks if the the combination of `EventCategory`, `EventType` and
    /// `EventData` is valid.
    pub fn is_valid(&self) -> bool {
        match (&self.category, &self.ty) {
            (
                EventCategory::Connectivity,
                EventType::ConnectivityEventType(_),
            ) => matches!(
                &self.data,
                EventData::ServerListening { .. } |
                    EventData::ConnectionStarted { .. } |
                    EventData::ConnectionIdUpdated { .. } |
                    EventData::SpinBitUpdated { .. } |
                    EventData::ConnectionStateUpdated { .. }
            ),

            (EventCategory::Transport, EventType::TransportEventType(_)) =>
                matches!(
                    &self.data,
                    EventData::TransportParametersSet { .. } |
                        EventData::DatagramsReceived { .. } |
                        EventData::DatagramsSent { .. } |
                        EventData::DatagramDropped { .. } |
                        EventData::PacketReceived { .. } |
                        EventData::PacketSent { .. } |
                        EventData::PacketDropped { .. } |
                        EventData::PacketBuffered { .. } |
                        EventData::StreamStateUpdated { .. } |
                        EventData::FramesProcessed { .. }
                ),

            (EventCategory::Security, EventType::SecurityEventType(_)) =>
                matches!(
                    &self.data,
                    EventData::KeyUpdated { .. } | EventData::KeyRetired { .. }
                ),

            (EventCategory::Recovery, EventType::RecoveryEventType(_)) =>
                matches!(
                    &self.data,
                    EventData::RecoveryParametersSet { .. } |
                        EventData::MetricsUpdated { .. } |
                        EventData::CongestionStateUpdated { .. } |
                        EventData::LossTimerSet { .. } |
                        EventData::PacketLost { .. } |
                        EventData::MarkedForRetransmit { .. }
                ),

            (EventCategory::Http, EventType::Http3EventType(_)) => matches!(
                &self.data,
                EventData::H3ParametersSet { .. } |
                    EventData::H3StreamTypeSet { .. } |
                    EventData::H3FrameCreated { .. } |
                    EventData::H3FrameParsed { .. } |
                    EventData::H3DataMoved { .. } |
                    EventData::H3PushResolved { .. }
            ),

            (EventCategory::Qpack, EventType::QpackEventType(_)) => matches!(
                &self.data,
                EventData::QpackStateUpdated { .. } |
                    EventData::QpackStreamStateUpdated { .. } |
                    EventData::QpackDynamicTableUpdated { .. } |
                    EventData::QpackHeadersEncoded { .. } |
                    EventData::QpackHeadersDecoded { .. } |
                    EventData::QpackInstructionSent { .. } |
                    EventData::QpackInstructionReceived { .. }
            ),

            // TODO: in qlog-01 there is no sane default category defined for
            // GenericEventType
            (_, EventType::GenericEventType(_)) => matches!(
                &self.data,
                EventData::ConnectionError { .. } |
                    EventData::ApplicationError { .. } |
                    EventData::InternalError { .. } |
                    EventData::InternalWarning { .. } |
                    EventData::Message { .. } |
                    EventData::Marker { .. }
            ),

            _ => false,
        }
    }
}
