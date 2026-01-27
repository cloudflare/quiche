// Copyright (C) 2018-2019, Cloudflare, Inc.
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

//! Qlog logging support for QUIC connections.

use std::io::Write;
use std::time::Instant;

use smallvec::SmallVec;

use crate::ConnectionError;
use crate::TransportParams;

use crate::crypto;
use crate::packet;
use crate::recovery;

use qlog::events::connectivity::ConnectivityEventType;
use qlog::events::connectivity::TransportOwner;
use qlog::events::quic::QuicFrame;
use qlog::events::DataRecipient;
use qlog::events::EventData;
use qlog::events::EventImportance;
use qlog::events::EventType;
use qlog::events::RawInfo;

/// Qlog logging level.
///
/// Controls which qlog events are collected. Variants are defined in terms
/// of qlog importance levels, where a level includes all events from levels
/// below it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum Level {
    /// Logs any events of Core importance.
    Core  = 0,

    /// Logs any events of Core and Base importance.
    Base  = 1,

    /// Logs any events of Core, Base and Extra importance.
    Extra = 2,
}

// Event type constants for filtering.
const PARAMS_SET: EventType = EventType::TransportEventType(
    qlog::events::quic::TransportEventType::ParametersSet,
);
pub(crate) const PACKET_RX: EventType = EventType::TransportEventType(
    qlog::events::quic::TransportEventType::PacketReceived,
);
pub(crate) const PACKET_TX: EventType = EventType::TransportEventType(
    qlog::events::quic::TransportEventType::PacketSent,
);
const DATA_MV: EventType = EventType::TransportEventType(
    qlog::events::quic::TransportEventType::DataMoved,
);
const METRICS: EventType = EventType::RecoveryEventType(
    qlog::events::quic::RecoveryEventType::MetricsUpdated,
);
const CONNECTION_CLOSED: EventType =
    EventType::ConnectivityEventType(ConnectivityEventType::ConnectionClosed);

/// Internal qlog state for a connection.
pub(crate) struct Info {
    /// The qlog streamer instance.
    pub streamer: Option<qlog::streamer::QlogStreamer>,

    /// Whether peer transport parameters have been logged.
    pub logged_peer_params: bool,

    /// The configured logging level (event importance filter).
    pub level: EventImportance,
}

impl Default for Info {
    fn default() -> Self {
        Info {
            streamer: None,
            logged_peer_params: false,
            level: EventImportance::Base,
        }
    }
}

impl Info {
    /// Returns the start time of the qlog streamer, if available.
    #[allow(dead_code)]
    pub fn start_time(&self) -> Option<Instant> {
        self.streamer.as_ref().map(|s| s.start_time())
    }
}

/// Executes the provided body if the qlog event type importance is at or below
/// the configured level.
macro_rules! with_type {
    ($ty:expr, $qlog:expr, $qlog_streamer_ref:ident, $body:block) => {
        if ::qlog::events::EventImportance::from($ty)
            .is_contained_in(&$qlog.level)
        {
            if let Some(ref mut $qlog_streamer_ref) = $qlog.streamer {
                $body
            }
        }
    };
}
pub(crate) use with_type;

/// Initialize qlog streaming with the given writer and parameters.
#[allow(clippy::too_many_arguments)]
pub(crate) fn init_streamer(
    writer: Box<dyn Write + Send + Sync>, title: String, description: String,
    level: Level, is_server: bool, scid: &crate::ConnectionId,
    local_transport_params: &TransportParams, cipher: Option<crypto::Algorithm>,
) -> Info {
    let vantage_point = if is_server {
        qlog::VantagePoint {
            name: None,
            ty: qlog::VantagePointType::Server,
            flow: None,
        }
    } else {
        qlog::VantagePoint {
            name: None,
            ty: qlog::VantagePointType::Client,
            flow: None,
        }
    };

    let level = match level {
        Level::Core => EventImportance::Core,
        Level::Base => EventImportance::Base,
        Level::Extra => EventImportance::Extra,
    };

    let trace = qlog::TraceSeq::new(
        vantage_point,
        Some(title.clone()),
        Some(description.clone()),
        Some(qlog::Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        None,
    );

    let mut streamer = qlog::streamer::QlogStreamer::new(
        qlog::QLOG_VERSION.to_string(),
        Some(title),
        Some(description),
        None,
        Instant::now(),
        trace,
        level,
        writer,
    );

    if streamer.start_log().is_err() {
        return Info::default();
    }

    let ev_data = local_transport_params.to_qlog(TransportOwner::Local, cipher);

    if streamer.add_event_data_now(ev_data).is_err() {
        return Info::default();
    }

    // Log SCID chosen by the application.
    let scid_ev_data = EventData::ConnectionIdUpdated(
        qlog::events::connectivity::ConnectionIdUpdated {
            owner: Some(TransportOwner::Local),
            old: None,
            new: Some(format!("{}", qlog::HexSlice::new(&scid))),
        },
    );

    if streamer.add_event_data_now(scid_ev_data).is_err() {
        return Info::default();
    }

    Info {
        streamer: Some(streamer),
        logged_peer_params: false,
        level,
    }
}

/// Convert TransportParams to a qlog EventData.
pub fn transport_params_to_qlog(
    params: &TransportParams, owner: TransportOwner,
    cipher: Option<crypto::Algorithm>,
) -> EventData {
    let original_destination_connection_id = qlog::HexSlice::maybe_string(
        params.original_destination_connection_id.as_ref(),
    );

    let stateless_reset_token = qlog::HexSlice::maybe_string(
        params
            .stateless_reset_token
            .map(|s| s.to_be_bytes())
            .as_ref(),
    );

    let tls_cipher: Option<String> = cipher.map(|f| format!("{f:?}"));

    EventData::TransportParametersSet(
        qlog::events::quic::TransportParametersSet {
            owner: Some(owner),
            tls_cipher,
            original_destination_connection_id,
            stateless_reset_token,
            disable_active_migration: Some(params.disable_active_migration),
            max_idle_timeout: Some(params.max_idle_timeout),
            max_udp_payload_size: Some(params.max_udp_payload_size as u32),
            ack_delay_exponent: Some(params.ack_delay_exponent as u16),
            max_ack_delay: Some(params.max_ack_delay as u16),
            active_connection_id_limit: Some(params.active_conn_id_limit as u32),

            initial_max_data: Some(params.initial_max_data),
            initial_max_stream_data_bidi_local: Some(
                params.initial_max_stream_data_bidi_local,
            ),
            initial_max_stream_data_bidi_remote: Some(
                params.initial_max_stream_data_bidi_remote,
            ),
            initial_max_stream_data_uni: Some(params.initial_max_stream_data_uni),
            initial_max_streams_bidi: Some(params.initial_max_streams_bidi),
            initial_max_streams_uni: Some(params.initial_max_streams_uni),

            unknown_parameters: params
                .unknown_params
                .as_ref()
                .map(|unknown_params| {
                    unknown_params
                            .into_iter()
                            .cloned()
                            .map(
                                Into::<
                                    qlog::events::quic::UnknownTransportParameter,
                                >::into,
                            )
                            .collect()
                })
                .unwrap_or_default(),

            ..Default::default()
        },
    )
}

/// Logs a packet received event.
pub(crate) fn log_packet_received(
    info: &mut Info, hdr: &packet::Header, pn: u64, packet_size: usize,
    payload_len: usize, frames: SmallVec<[QuicFrame; 1]>, now: Instant,
) {
    with_type!(PACKET_RX, info, q, {
        let qlog_pkt_hdr = qlog::events::quic::PacketHeader::with_type(
            hdr.ty.to_qlog(),
            Some(pn),
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );

        let qlog_raw_info = RawInfo {
            length: Some(packet_size as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };

        let ev_data =
            EventData::PacketReceived(qlog::events::quic::PacketReceived {
                header: qlog_pkt_hdr,
                frames: Some(frames.to_vec()),
                raw: Some(qlog_raw_info),
                ..Default::default()
            });

        q.add_event_data_with_instant(ev_data, now).ok();
    });
}

/// Logs a packet sent event.
pub(crate) fn log_packet_sent(
    info: &mut Info, pkt_hdr: Option<qlog::events::quic::PacketHeader>,
    frames: SmallVec<[QuicFrame; 1]>, payload_len: usize, payload_offset: usize,
    crypto_overhead: usize, now: Instant,
) {
    let Some(header) = pkt_hdr else {
        return;
    };

    with_type!(PACKET_TX, info, q, {
        // Qlog packet raw info described at
        // https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-00#section-5.1
        //
        // `length` includes packet headers and trailers (AEAD tag).
        let length = payload_len + payload_offset + crypto_overhead;
        let qlog_raw_info = RawInfo {
            length: Some(length as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };

        let send_at_time =
            now.duration_since(q.start_time()).as_secs_f32() * 1000.0;

        let ev_data = EventData::PacketSent(qlog::events::quic::PacketSent {
            header,
            frames: Some(frames),
            raw: Some(qlog_raw_info),
            send_at_time: Some(send_at_time),
            ..Default::default()
        });

        q.add_event_data_with_instant(ev_data, now).ok();
    });
}

/// Logs a data moved event (stream data movement between layers).
pub(crate) fn log_data_moved(
    info: &mut Info, stream_id: u64, offset: u64, length: u64,
    from: DataRecipient, to: DataRecipient, now: Instant,
) {
    with_type!(DATA_MV, info, q, {
        let ev_data = EventData::DataMoved(qlog::events::quic::DataMoved {
            stream_id: Some(stream_id),
            offset: Some(offset),
            length: Some(length),
            from: Some(from),
            to: Some(to),
            ..Default::default()
        });

        q.add_event_data_with_instant(ev_data, now).ok();
    });
}

/// Logs peer transport parameters.
pub(crate) fn log_peer_params(
    info: &mut Info, peer_params: &TransportParams,
    cipher: Option<crypto::Algorithm>, now: Instant,
) {
    with_type!(PARAMS_SET, info, q, {
        if !info.logged_peer_params {
            let ev_data = peer_params.to_qlog(TransportOwner::Remote, cipher);

            q.add_event_data_with_instant(ev_data, now).ok();

            info.logged_peer_params = true;
        }
    });
}

/// Logs recovery metrics (gated by METRICS event type).
pub(crate) fn log_metrics(
    info: &mut Info, recovery: &mut recovery::Recovery, now: Instant,
) {
    with_type!(METRICS, info, q, {
        recovery.maybe_qlog(q, now);
    });
}

/// Logs recovery metrics after packet receive (gated by PACKET_RX event type).
pub(crate) fn log_metrics_on_rx(
    info: &mut Info, recovery: &mut recovery::Recovery, now: Instant,
) {
    with_type!(PACKET_RX, info, q, {
        recovery.maybe_qlog(q, now);
    });
}

/// Logs a key updated event.
pub(crate) fn log_key_updated(
    info: &mut Info, trigger: qlog::events::security::KeyUpdateOrRetiredTrigger,
    now: Instant,
) {
    with_type!(PACKET_RX, info, q, {
        let ev_data_client =
            EventData::KeyUpdated(qlog::events::security::KeyUpdated {
                key_type: qlog::events::security::KeyType::Client1RttSecret,
                trigger: Some(trigger.clone()),
                ..Default::default()
            });

        q.add_event_data_with_instant(ev_data_client, now).ok();

        let ev_data_server =
            EventData::KeyUpdated(qlog::events::security::KeyUpdated {
                key_type: qlog::events::security::KeyType::Server1RttSecret,
                trigger: Some(trigger),
                ..Default::default()
            });

        q.add_event_data_with_instant(ev_data_server, now).ok();
    });
}

/// Logs an MTU updated event.
pub(crate) fn log_mtu_updated(
    info: &mut Info, old: u16, new: u16, done: bool, now: Instant,
) {
    let event_type =
        EventType::ConnectivityEventType(ConnectivityEventType::MtuUpdated);

    with_type!(event_type, info, q, {
        let ev_data =
            EventData::MtuUpdated(qlog::events::connectivity::MtuUpdated {
                old: Some(old),
                new,
                done: Some(done),
            });

        q.add_event_data_with_instant(ev_data, now).ok();
    });
}

/// Logs a connection closed event.
pub(crate) fn log_connection_closed(
    info: &mut Info, is_established: bool, timed_out: bool,
    peer_error: Option<&ConnectionError>, local_error: Option<&ConnectionError>,
) {
    let cc = match (is_established, timed_out, peer_error, local_error) {
        (false, _, _, _) => qlog::events::connectivity::ConnectionClosed {
            owner: Some(TransportOwner::Local),
            connection_code: None,
            application_code: None,
            internal_code: None,
            reason: Some("Failed to establish connection".to_string()),
            trigger: Some(
                qlog::events::connectivity::ConnectionClosedTrigger::HandshakeTimeout,
            ),
        },

        (true, true, _, _) => qlog::events::connectivity::ConnectionClosed {
            owner: Some(TransportOwner::Local),
            connection_code: None,
            application_code: None,
            internal_code: None,
            reason: Some("Idle timeout".to_string()),
            trigger: Some(
                qlog::events::connectivity::ConnectionClosedTrigger::IdleTimeout,
            ),
        },

        (true, false, Some(peer_error), None) => {
            let (connection_code, application_code, trigger) = if peer_error.is_app
            {
                (
                    None,
                    Some(qlog::events::ApplicationErrorCode::Value(
                        peer_error.error_code,
                    )),
                    None,
                )
            } else {
                let trigger =
                    if peer_error.error_code == crate::WireErrorCode::NoError as u64
                    {
                        Some(
                            qlog::events::connectivity::ConnectionClosedTrigger::Clean,
                        )
                    } else {
                        Some(
                            qlog::events::connectivity::ConnectionClosedTrigger::Error,
                        )
                    };

                (
                    Some(qlog::events::ConnectionErrorCode::Value(
                        peer_error.error_code,
                    )),
                    None,
                    trigger,
                )
            };

            qlog::events::connectivity::ConnectionClosed {
                owner: Some(TransportOwner::Remote),
                connection_code,
                application_code,
                internal_code: None,
                reason: Some(
                    String::from_utf8_lossy(&peer_error.reason).to_string(),
                ),
                trigger,
            }
        },

        (true, false, None, Some(local_error)) => {
            let (connection_code, application_code, trigger) = if local_error.is_app
            {
                (
                    None,
                    Some(qlog::events::ApplicationErrorCode::Value(
                        local_error.error_code,
                    )),
                    None,
                )
            } else {
                let trigger =
                    if local_error.error_code == crate::WireErrorCode::NoError as u64
                    {
                        Some(
                            qlog::events::connectivity::ConnectionClosedTrigger::Clean,
                        )
                    } else {
                        Some(
                            qlog::events::connectivity::ConnectionClosedTrigger::Error,
                        )
                    };

                (
                    Some(qlog::events::ConnectionErrorCode::Value(
                        local_error.error_code,
                    )),
                    None,
                    trigger,
                )
            };

            qlog::events::connectivity::ConnectionClosed {
                owner: Some(TransportOwner::Local),
                connection_code,
                application_code,
                internal_code: None,
                reason: Some(
                    String::from_utf8_lossy(&local_error.reason).to_string(),
                ),
                trigger,
            }
        },

        _ => qlog::events::connectivity::ConnectionClosed {
            owner: None,
            connection_code: None,
            application_code: None,
            internal_code: None,
            reason: None,
            trigger: None,
        },
    };

    with_type!(CONNECTION_CLOSED, info, q, {
        let ev_data = EventData::ConnectionClosed(cc);

        q.add_event_data_now(ev_data).ok();
    });

    info.streamer = None;
}
