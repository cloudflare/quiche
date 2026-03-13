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

use qlog::events::http3::Http3Frame;
use qlog::events::quic::AckedRanges;
use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use tabled::Table;
use tabled::Tabled;

use crate::category_and_type_from_event;
use crate::category_and_type_from_name;

macro_rules! printy {
    ($k:expr, $value:expr, $s:expr) => {{
        $s += &format!("{}={}, ", $k, $value);
    }};
}

macro_rules! printyo {
    ($k:expr, $value:expr, $s:expr) => {{
        if let Some(v) = $value {
            $s += &format!("{}={}, ", $k, v);
        }
    }};
}

macro_rules! printy_json {
    ($k:expr, $value:expr, $s:expr) => {{
        $s += &format!(
            "{}={}, ",
            $k,
            &serde_json::to_string(&$value).unwrap().replace("\"", "")
        );
    }};
}

macro_rules! printyo_json {
    ($k:expr, $value:expr, $s:expr) => {{
        if let Some(v) = $value {
            $s += &format!(
                "{}={}, ",
                $k,
                &serde_json::to_string(&v).unwrap().replace("\"", "")
            );
        }
    }};
}

#[derive(Debug, Default, Tabled)]
struct PrintableEvent {
    pub time: f64,
    pub category: String,
    #[tabled(rename = "Type")]
    pub ty: String,
    pub details: String,
}

pub fn frames_to_string(frames: &[QuicFrame]) -> String {
    let mut s = String::new();
    for f in frames {
        match f {
            qlog::events::quic::QuicFrame::Padding { raw, .. } => {
                s += &format!(" PADDING {{raw={raw:?}}}");
            },
            qlog::events::quic::QuicFrame::Ping { .. } => {
                s += " PING";
            },
            qlog::events::quic::QuicFrame::Ack { acked_ranges, .. } => {
                s += " ACK {";
                if let Some(ar) = acked_ranges {
                    match ar {
                        AckedRanges::Single(items) => {
                            for a in items {
                                for b in a {
                                    s += &format!{"{b}, "};
                                }
                            }
                        },
                        AckedRanges::Double(items) => {
                            for a in items {
                                s += &format!{"{}-{}, ", a.0, a.1};
                            }
                        },
                    }
                }
                s += "}";
            },
            qlog::events::quic::QuicFrame::ResetStream { stream_id, error, error_code, final_size, .. } => {
                s += &format!(" RESET_STREAM {{id={stream_id}, error={error:?}, error_code={error_code:?}, final_size={final_size}}}");
            },
            qlog::events::quic::QuicFrame::StopSending { stream_id, error, error_code, ..} => {
                s += &format!(" STOP_SENDING {{id={stream_id}, error={error:?}, error_code={error_code:?}}}");
            },
            qlog::events::quic::QuicFrame::Crypto { offset, raw } => {
                s += &format!(" CRYPTO {{off={offset}, raw={raw:?}}}");
            },
            qlog::events::quic::QuicFrame::NewToken { token , ..} => {
               s += " NEW_TOKEN ";
               if let Some(ty) = &token.ty {
                    s += &format!("{{ty={ty:?}}}");
               }
            },
            qlog::events::quic::QuicFrame::Stream { stream_id, offset, fin, raw } => {
                s += &format!(" STREAM {{id={stream_id}, off={offset:?}, raw={raw:?}");
                if let Some(f) = fin {
                    s += &format!(", fin={f}")
                }
                s += "}";
            },
            qlog::events::quic::QuicFrame::MaxData { maximum, .. } => {
                s += &format!(" MAX_DATA {{max={maximum}}}");
            },
            qlog::events::quic::QuicFrame::MaxStreamData { stream_id, maximum, .. } => {
                s += &format!(" MAX_STREAM_DATA {{id={stream_id}, max={maximum}}}");
            },
            qlog::events::quic::QuicFrame::MaxStreams { stream_type, maximum, .. } => {
                s += &format!(" MAX_STREAMS {{ty={stream_type:?}, max={maximum}}}");
            },
            qlog::events::quic::QuicFrame::DataBlocked { limit, .. } => {
                s += &format!(" DATA_BLOCKED {{limit={limit}}}");
            },
            qlog::events::quic::QuicFrame::StreamDataBlocked { stream_id, limit, .. } => {
                s += &format!(" STREAM_DATA_BLOCKED {{id={stream_id}, limit={limit}}}");
            },
            qlog::events::quic::QuicFrame::StreamsBlocked { stream_type, limit , ..} => {
                s += &format!(" STREAMS_BLOCKED {{ty={stream_type:?}, limit={limit}}}");
            },
            qlog::events::quic::QuicFrame::NewConnectionId { /*sequence_number, retire_prior_to, connection_id_length, connection_id, stateless_reset_token*/ .. } => {
                s += " NEW_CONNECTION_ID {{todo='todo'}}";
            },
            qlog::events::quic::QuicFrame::RetireConnectionId { sequence_number , ..} => {
                s += &format!(" RETIRE_CONNECION_ID {{sn={sequence_number}}}");
            },
            qlog::events::quic::QuicFrame::PathChallenge { /*data*/ .. } => {
                s += " PATH_CHALLENGE {{todo='todo'}}";
            },
            qlog::events::quic::QuicFrame::PathResponse { /*data*/ .. } => {
                s += " PATH_RESPONSE {{todo='todo'}}";
            },
            qlog::events::quic::QuicFrame::ConnectionClose { error_space, error_code, reason, .. } => {
               s += " CONNECTION_CLOSE {";
               if let Some(es) = error_space {
                    s += &format!(" ty={es:?},");
               }
               printyo!(" code", error_code, s);
               printyo!(" reason", reason, s);
               s += "}";
            },
            qlog::events::quic::QuicFrame::HandshakeDone { .. } => {
                s += " HANDSHAKE_DONE";
            },
            qlog::events::quic::QuicFrame::Datagram { raw, .. } => {
               s += &format!(" DATAGRAM {{raw={raw:?}}}");
            },
            qlog::events::quic::QuicFrame::Unknown { frame_type_bytes, .. } => {
               s += &format!(" UNKNOWN {{frame_type_bytes={frame_type_bytes:?}}}");
            },
        }
    }

    s
}

fn http_frame_to_string(frame: &Http3Frame) -> String {
    let mut s = String::new();

    match frame {
        Http3Frame::Data { raw } =>{
            s += " DATA";
            if let Some(r) = raw {
                printyo!("len", r.length, s);
            }
        },
        Http3Frame::Headers { headers } => {
            s += " HEADERS {";

            for header in headers {
                let name = header.name.as_deref().unwrap_or("<binary>");
                let value = header.value.as_deref().unwrap_or("<binary>");
                s += &format!("{}: {}, ", name, value);
            }

            s += "}";
        },
        Http3Frame::CancelPush { push_id } => {
            s += &format!(" CANCEL_PUSH {{id={push_id}}}");
        },
        Http3Frame::Settings { /* settings */ ..} => {
            s += " SETTINGS {{todo}}";
        }
        Http3Frame::PushPromise { /*push_id, headers */ ..} => {
            s += " PUSH_PROMISE {{todo}}";
        }
        Http3Frame::Goaway { id } => {
            s += &format!(" GOAWAY {{id={id}}}");
        }
        Http3Frame::MaxPushId { push_id } => {
            s += &format!(" MAX_PUSH_ID {{id={push_id}}}");
        }
        Http3Frame::PriorityUpdate { /*target_stream_type, prioritized_element_id, priority_field_value*/ .. } => {
            s += " PRIORITY_UPDATE {{todo}}";
        },
        Http3Frame::Reserved { /*length*/ .. } => {
            s += " GREASE {{todo}}";
        },
        Http3Frame::Unknown { frame_type_value, .. } => {
            s += &format!(" UNKNOWN {{ty={frame_type_value}}}");
        }
    }

    s
}

pub fn sqlog_event_list(
    events: &[qlog::reader::Event],
) -> tabled::builder::Builder {
    let mut pp = vec![];

    for event in events {
        match event {
            qlog::reader::Event::Qlog(ev) => {
                let (cat, ty) = category_and_type_from_event(ev);

                let mut p = PrintableEvent {
                    time: ev.time,
                    ty,
                    category: cat,
                    ..Default::default()
                };

                match &ev.data {
                    EventData::ConnectionStarted(v) => {
                        printyo!("local_ip_v4", &v.local.ip_v4, p.details);
                        printyo!("local_port_v4", &v.local.port_v4, p.details);
                        printyo!("local_ip_v6", &v.local.ip_v6, p.details);
                        printyo!("local_port_v6", &v.local.port_v6, p.details);
                        printy!(
                            "local_cids",
                            format!("{:?}", &v.local.connection_ids),
                            p.details
                        );
                        printyo!("remote_ip_v4", &v.remote.ip_v4, p.details);
                        printyo!("remote_port_v4", &v.remote.port_v4, p.details);
                        printyo!("remote_ip_v6", &v.remote.ip_v6, p.details);
                        printyo!("remote_port_v6", &v.remote.port_v6, p.details);
                        printy!(
                            "remote_cid",
                            format!("{:?}", &v.local.connection_ids),
                            p.details
                        );
                    },
                    EventData::ConnectionClosed(v) => {
                        printyo_json!("initiator", &v.initiator, p.details);
                        printyo_json!(
                            "connection_code",
                            &v.connection_error,
                            p.details
                        );
                        printyo_json!(
                            "application_error",
                            &v.application_error,
                            p.details
                        );
                        printyo!("internal_code", &v.internal_code, p.details);
                        printyo!("reason", &v.reason, p.details);
                        printyo_json!("trigger", &v.trigger, p.details);
                    },
                    EventData::ParametersSet(v) => {
                        printyo_json!("initiator", &v.initiator, p.details);
                        printyo!(
                            "resumption_allowed",
                            &v.resumption_allowed,
                            p.details
                        );
                        printyo!(
                            "early_data_enabled",
                            &v.early_data_enabled,
                            p.details
                        );
                        printyo!("tls_cipher", &v.tls_cipher, p.details);
                        printyo!(
                            "odcid",
                            &v.original_destination_connection_id,
                            p.details
                        );
                        printyo!(
                            "initial_scid",
                            &v.initial_source_connection_id,
                            p.details
                        );
                        printyo!(
                            "retry_scid",
                            &v.retry_source_connection_id,
                            p.details
                        );
                        printyo!(
                            "stateless_reset_token",
                            &v.stateless_reset_token,
                            p.details
                        );
                        printyo!(
                            "disable_active_migration",
                            &v.disable_active_migration,
                            p.details
                        );
                        printyo!(
                            "max_idle_timeout",
                            &v.max_idle_timeout,
                            p.details
                        );
                        printyo!(
                            "max_udp_payload_size",
                            &v.max_udp_payload_size,
                            p.details
                        );
                        printyo!("max_ack_delay", &v.max_ack_delay, p.details);
                        printyo!(
                            "active_connection_id_limit",
                            &v.active_connection_id_limit,
                            p.details
                        );
                        printyo!(
                            "initial_max_data",
                            &v.initial_max_data,
                            p.details
                        );
                        printyo!(
                            "initial_max_stream_data_bidi_local",
                            &v.initial_max_stream_data_bidi_local,
                            p.details
                        );
                        printyo!(
                            "initial_max_stream_data_bidi_remote",
                            &v.initial_max_stream_data_bidi_remote,
                            p.details
                        );
                        printyo!(
                            "initial_max_stream_data_uni",
                            &v.initial_max_stream_data_uni,
                            p.details
                        );
                        printyo!(
                            "initial_max_streams_bidi",
                            &v.initial_max_streams_bidi,
                            p.details
                        );
                        printyo!(
                            "initial_max_streams_uni",
                            &v.initial_max_streams_uni,
                            p.details
                        );
                        printyo_json!(
                            "preferred_address",
                            &v.preferred_address,
                            p.details
                        );
                        // TODO: v.unknown_parameters
                    },
                    EventData::PacketSent(v) => {
                        p.details +=
                            &serde_json::to_string(&v.header.packet_type)
                                .unwrap()
                                .replace("\"", "");
                        printyo!(" pn", v.header.packet_number, p.details);

                        if let Some(frames) = &v.frames {
                            p.details += &frames_to_string(frames);
                        }
                    },
                    EventData::PacketReceived(v) => {
                        p.details +=
                            &serde_json::to_string(&v.header.packet_type)
                                .unwrap()
                                .replace("\"", "");
                        printyo!(" pn", v.header.packet_number, p.details);

                        if let Some(frames) = &v.frames {
                            p.details += &frames_to_string(frames);
                        }
                    },
                    EventData::StreamDataMoved(v) => {
                        printyo!("id", v.stream_id, p.details);
                        printyo!("off", v.offset, p.details);
                        if let Some(raw) = &v.raw {
                            printyo!("len", raw.length, p.details);
                        }
                        printyo_json!("from", &v.from, p.details);
                        printyo_json!("to", &v.to, p.details);
                    },
                    EventData::MetricsUpdated(v) => {
                        printyo!("min_rtt", v.min_rtt, p.details);
                        printyo!("smoothed_rtt", v.smoothed_rtt, p.details);
                        printyo!("latest_rtt", v.latest_rtt, p.details);
                        printyo!("rtt_variance", v.rtt_variance, p.details);
                        printyo!("pto_count", v.pto_count, p.details);
                        printyo!("cwnd", v.congestion_window, p.details);
                        printyo!("bytes_in_flight", v.bytes_in_flight, p.details);
                        printyo!("ssthresh", v.ssthresh, p.details);
                        printyo!(
                            "packets_in_flight",
                            v.packets_in_flight,
                            p.details
                        );
                        printyo!("pacing_rate", v.pacing_rate, p.details);
                    },
                    EventData::H3StreamTypeSet(ev) => {
                        printy!("id", &ev.stream_id, p.details);
                        printyo_json!("initiator", &ev.initiator, p.details);
                        printy_json!("ty", &ev.stream_type, p.details);
                    },
                    EventData::H3FrameCreated(v) => {
                        printy!("id", v.stream_id, p.details);
                        printyo!("len", v.length, p.details);
                        p.details += &http_frame_to_string(&v.frame);
                    },
                    EventData::H3FrameParsed(v) => {
                        printy!("id", v.stream_id, p.details);
                        printyo!("len", v.length, p.details);
                        p.details += &http_frame_to_string(&v.frame);
                    },

                    _ => {
                        p.details += &serde_json::to_string(&ev.data).unwrap();
                    },
                }

                pp.push(p);
            },

            qlog::reader::Event::Json(ev) => {
                let (cat, ty) = category_and_type_from_name(&ev.name);

                let p = PrintableEvent {
                    time: ev.time,
                    ty,
                    category: cat,
                    details: serde_json::to_string(&ev.data).unwrap(),
                };

                pp.push(p);
            },
        }
    }

    Table::builder(pp)
}
