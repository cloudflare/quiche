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
use qlog::events::moqt::MOQTByteString;
use qlog::events::moqt::MOQTControlMessage;
use qlog::events::moqt::MOQTParameter;
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
            QuicFrame::Padding { raw, .. } => {
                s += &format!(" PADDING {{raw={raw:?}}}");
            },
            QuicFrame::Ping { .. } => {
                s += " PING";
            },
            QuicFrame::Ack { acked_ranges, .. } => {
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
            QuicFrame::ResetStream { stream_id, error, error_code, final_size, .. } => {
                s += &format!(" RESET_STREAM {{id={stream_id}, error={error:?}, error_code={error_code:?}, final_size={final_size}}}");
            },
            QuicFrame::StopSending { stream_id, error, error_code, ..} => {
                s += &format!(" STOP_SENDING {{id={stream_id}, error={error:?}, error_code={error_code:?}}}");
            },
            QuicFrame::Crypto { offset, raw } => {
                s += &format!(" CRYPTO {{off={offset}, raw={raw:?}}}");
            },
            QuicFrame::NewToken { token , ..} => {
               s += " NEW_TOKEN ";
               if let Some(ty) = &token.ty {
                    s += &format!("{{ty={ty:?}}}");
               }
            },
            QuicFrame::Stream { stream_id, offset, fin, raw } => {
                s += &format!(" STREAM {{id={stream_id}, off={offset:?}, raw={raw:?}");
                if let Some(f) = fin {
                    s += &format!(", fin={f}")
                }
                s += "}";
            },
            QuicFrame::MaxData { maximum, .. } => {
                s += &format!(" MAX_DATA {{max={maximum}}}");
            },
            QuicFrame::MaxStreamData { stream_id, maximum, .. } => {
                s += &format!(" MAX_STREAM_DATA {{id={stream_id}, max={maximum}}}");
            },
            QuicFrame::MaxStreams { stream_type, maximum, .. } => {
                s += &format!(" MAX_STREAMS {{ty={stream_type:?}, max={maximum}}}");
            },
            QuicFrame::DataBlocked { limit, .. } => {
                s += &format!(" DATA_BLOCKED {{limit={limit}}}");
            },
            QuicFrame::StreamDataBlocked { stream_id, limit, .. } => {
                s += &format!(" STREAM_DATA_BLOCKED {{id={stream_id}, limit={limit}}}");
            },
            QuicFrame::StreamsBlocked { stream_type, limit , ..} => {
                s += &format!(" STREAMS_BLOCKED {{ty={stream_type:?}, limit={limit}}}");
            },
            QuicFrame::NewConnectionId { /*sequence_number, retire_prior_to, connection_id_length, connection_id, stateless_reset_token*/ .. } => {
                s += " NEW_CONNECTION_ID {{todo='todo'}}";
            },
            QuicFrame::RetireConnectionId { sequence_number , ..} => {
                s += &format!(" RETIRE_CONNECION_ID {{sn={sequence_number}}}");
            },
            QuicFrame::PathChallenge { /*data*/ .. } => {
                s += " PATH_CHALLENGE {{todo='todo'}}";
            },
            QuicFrame::PathResponse { /*data*/ .. } => {
                s += " PATH_RESPONSE {{todo='todo'}}";
            },
            QuicFrame::ConnectionClose { error_space, error_code, reason, .. } => {
               s += " CONNECTION_CLOSE {";
               if let Some(es) = error_space {
                    s += &format!(" ty={es:?},");
               }
               printyo!(" code", error_code, s);
               printyo!(" reason", reason, s);
               s += "}";
            },
            QuicFrame::HandshakeDone { .. } => {
                s += " HANDSHAKE_DONE";
            },
            QuicFrame::Datagram { raw, .. } => {
               s += &format!(" DATAGRAM {{raw={raw:?}}}");
            },
            QuicFrame::Unknown { frame_type_bytes, .. } => {
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

fn params_to_string(parameters: &Option<Vec<MOQTParameter>>) -> String {
    let mut s = String::new();
    if let Some(params) = parameters {
        for p in params {
            match p {
                MOQTParameter::AuthorizationToken {
                    alias_type,
                    token_alias,
                    token_type,
                    token_value,
                } => {
                    printy!("alias_type", alias_type, s);
                    printyo!("token_alias", token_alias, s);
                    printyo!("token_type", token_type, s);
                    printyo_json!("token_value", token_value, s);
                },
                MOQTParameter::DeliveryTimeout { value } => {
                    printy!("delivery_timeout", value, s)
                },
                MOQTParameter::MaxCacheDuration { value } => {
                    printy!("max_cache_duration", value, s)
                },
                MOQTParameter::PublisherPriority { value } => {
                    printy!("publisher_priority", value, s)
                },
                MOQTParameter::SubscriberPriority { value } => {
                    printy!("subscriber_priority", value, s)
                },
                MOQTParameter::GroupOrder { value } => {
                    printy!("group_order", value, s)
                },
                MOQTParameter::SubscriptionFilter { value } => {
                    printy_json!("subscription_filter", value, s)
                },
                MOQTParameter::Expires { value } => printy!("expires", value, s),
                MOQTParameter::LargestObject { value } => {
                    printy_json!("largest_object", value, s)
                },
                MOQTParameter::Forward { value } => printy!("forward", value, s),
                MOQTParameter::DynamicGroups { value } => {
                    printy!("dynamic_groups", value, s)
                },
                MOQTParameter::NewGroupRequest { value } => {
                    printy!("new_group_request", value, s)
                },
                MOQTParameter::Unknown {
                    name_bytes,
                    length,
                    value,
                    value_bytes,
                } => {
                    printy!("name_bytes", name_bytes, s);
                    printyo!("len", length, s);
                    printyo!("value", value, s);
                    printyo_json!("value_bytes", value_bytes, s);
                },
            }
        }
    }
    s
}

fn moqt_track_namespace_to_string(track_namespace: &[MOQTByteString]) -> String {
    let mut s = String::new();
    s += "track_namespace=[";
    for tn in track_namespace {
        printyo!("value", &tn.value, s);
        printyo!("value_bytes", &tn.value_bytes, s);
    }
    s += "], ";
    s
}

fn setup_params_to_string(
    setup_parameters: &Option<Vec<qlog::events::moqt::MOQTSetupParameter>>,
) -> String {
    use qlog::events::moqt::MOQTSetupParameter;
    let mut s = String::new();
    if let Some(params) = setup_parameters {
        for p in params {
            match p {
                MOQTSetupParameter::Path { value } => printy!("path", value, s),
                MOQTSetupParameter::MaxRequestId { value } => {
                    printy!("max_request_id", value, s)
                },
                MOQTSetupParameter::Authority { value } => {
                    printy!("authority", value, s)
                },
                MOQTSetupParameter::MaxAuthTokenCacheSize { value } => {
                    printy!("max_auth_token_cache_size", value, s)
                },
                MOQTSetupParameter::AuthorizationToken {
                    alias_type,
                    token_alias,
                    token_type,
                    token_value,
                } => {
                    printy_json!("alias_type", alias_type, s);
                    printyo!("token_alias", token_alias, s);
                    printyo!("token_type", token_type, s);
                    printyo_json!("token_value", token_value, s);
                },
                MOQTSetupParameter::Implementation { value } => {
                    printy!("implementation", value, s)
                },
                MOQTSetupParameter::Unknown {
                    name_bytes,
                    length,
                    value,
                    value_bytes,
                } => {
                    printy!("name_bytes", name_bytes, s);
                    printyo!("len", length, s);
                    printyo!("value", value, s);
                    printyo_json!("value_bytes", value_bytes, s);
                },
            }
        }
    }
    s
}

fn moq_control_message_to_string(message: &MOQTControlMessage) -> String {
    let mut s = String::new();

    match message {
        MOQTControlMessage::ClientSetup {
            number_of_parameters,
            setup_parameters,
        } => {
            s += "CLIENT_SETUP {";
            printy!("number_of_parameters", number_of_parameters, s);
            s += "setup_parameters=[";
            s += &setup_params_to_string(setup_parameters);
            s += "]}";
        },
        MOQTControlMessage::ServerSetup {
            number_of_parameters,
            setup_parameters,
        } => {
            s += "SERVER_SETUP {";
            printy!("number_of_parameters", number_of_parameters, s);
            s += "setup_parameters=[";
            s += &setup_params_to_string(setup_parameters);
            s += "]}";
        },
        MOQTControlMessage::Goaway { new_session_uri } => {
            s += "GOAWAY {";
            printy_json!("new_session_uri", new_session_uri, s);
            s += "}";
        },
        MOQTControlMessage::Subscribe {
            request_id,
            track_alias,
            track_namespace,
            track_name,
            number_of_parameters,
            parameters,
        } => {
            s += "SUBSCRIBE {";
            printy!("request_id", request_id, s);
            printy!("track_alias", track_alias, s);
            s += &moqt_track_namespace_to_string(track_namespace);
            printyo!("track_name", &track_name.value, s);
            printyo!("track_name_bytes", &track_name.value_bytes, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::RequestUpdate {
            request_id,
            number_of_parameters,
            parameters,
        } => {
            s += "REQUEST_UPDATE {";
            printy!("request_id", request_id, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::Unsubscribe { request_id } => {
            s += &format!("UNSUBSCRIBE {{request_id={request_id}}}");
        },
        MOQTControlMessage::Fetch {
            request_id,
            track_namespace,
            track_name,
            fetch_type,
            start_location,
            end_location,
            joining_request_id,
            number_of_parameters,
            parameters,
        } => {
            s += "FETCH {";
            printy!("request_id", request_id, s);
            s += &moqt_track_namespace_to_string(track_namespace);
            printyo!("track_name", &track_name.value, s);
            printyo!("track_name_bytes", &track_name.value_bytes, s);
            printyo_json!("fetch_type", fetch_type, s);
            printyo_json!("start_location", start_location, s);
            printyo_json!("end_location", end_location, s);
            printyo!("joining_request_id", joining_request_id, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::FetchCancel { request_id } => {
            s += &format!("FETCH_CANCEL {{request_id={request_id}}}");
        },
        MOQTControlMessage::SubscribeNamespace {
            track_namespace_prefix,
            number_of_parameters,
            parameters,
        } => {
            s += "SUBSCRIBE_NAMESPACE {";
            s += "track_namespace_prefix=[";
            for tn in track_namespace_prefix {
                printyo!("value", &tn.value, s);
                printyo!("value_bytes", &tn.value_bytes, s);
            }
            s += "], ";
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::SubscribeOk {
            request_id,
            track_alias,
            number_of_parameters,
            parameters,
        } => {
            s += "SUBSCRIBE_OK {";
            printy!("request_id", request_id, s);
            printy!("track_alias", track_alias, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::RequestError {
            request_id,
            error_code,
            reason,
        } => {
            s += "REQUEST_ERROR {";
            printy!("request_id", request_id, s);
            printy!("error_code", error_code, s);
            if let Some(r) = reason {
                printyo!("reason", &r.value, s);
                printyo!("reason_bytes", &r.value_bytes, s);
            }
            s += "}";
        },
        MOQTControlMessage::FetchOk {
            request_id,
            end_location,
            number_of_parameters,
            parameters,
        } => {
            s += "FETCH_OK {";
            printy!("request_id", request_id, s);
            printyo_json!("end_location", end_location, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::PublishDone {
            track_alias,
            status_code,
            reason,
        } => {
            s += "PUBLISH_DONE {";
            printy!("track_alias", track_alias, s);
            printy!("status_code", status_code, s);
            if let Some(r) = reason {
                printyo!("reason", &r.value, s);
                printyo!("reason_bytes", &r.value_bytes, s);
            }
            s += "}";
        },
        MOQTControlMessage::MaxRequestId { request_id } => {
            s += &format!("MAX_REQUEST_ID {{request_id={request_id}}}");
        },
        MOQTControlMessage::RequestsBlocked { maximum_request_id } => {
            s += &format!(
                "REQUESTS_BLOCKED {{maximum_request_id={maximum_request_id}}}"
            );
        },
        MOQTControlMessage::Publish {
            track_namespace,
            track_name,
            track_alias,
            number_of_parameters,
            parameters,
        } => {
            s += "PUBLISH {";
            s += &moqt_track_namespace_to_string(track_namespace);
            printyo!("track_name", &track_name.value, s);
            printyo!("track_name_bytes", &track_name.value_bytes, s);
            printy!("track_alias", track_alias, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::PublishOk {
            track_namespace,
            track_name,
            track_alias,
        } => {
            s += "PUBLISH_OK {";
            s += &moqt_track_namespace_to_string(track_namespace);
            printyo!("track_name", &track_name.value, s);
            printyo!("track_name_bytes", &track_name.value_bytes, s);
            printy!("track_alias", track_alias, s);
            s += "}";
        },
        MOQTControlMessage::PublishNamespace {
            track_namespace_prefix,
            number_of_parameters,
            parameters,
        } => {
            s += "PUBLISH_NAMESPACE {";
            s += "track_namespace_prefix=[";
            for tn in track_namespace_prefix {
                printyo!("value", &tn.value, s);
                printyo!("value_bytes", &tn.value_bytes, s);
            }
            s += "], ";
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::Namespace {
            track_namespace_suffix,
            track_name,
            track_alias,
            number_of_parameters,
            parameters,
        } => {
            s += "NAMESPACE {";
            s += "track_namespace_suffix=[";
            for tn in track_namespace_suffix {
                printyo!("value", &tn.value, s);
                printyo!("value_bytes", &tn.value_bytes, s);
            }
            s += "], ";
            printyo!("track_name", &track_name.value, s);
            printyo!("track_name_bytes", &track_name.value_bytes, s);
            printy!("track_alias", track_alias, s);
            printy!("number_of_parameters", number_of_parameters, s);
            s += "parameters=[";
            s += &params_to_string(parameters);
            s += "]}";
        },
        MOQTControlMessage::PublishNamespaceDone {
            track_namespace_prefix,
            status_code,
            reason,
        } => {
            s += "PUBLISH_NAMESPACE_DONE {";
            s += "track_namespace_prefix=[";
            for tn in track_namespace_prefix {
                printyo!("value", &tn.value, s);
                printyo!("value_bytes", &tn.value_bytes, s);
            }
            s += "], ";
            printy!("status_code", status_code, s);
            if let Some(r) = reason {
                printyo!("reason", &r.value, s);
                printyo!("reason_bytes", &r.value_bytes, s);
            }
            s += "}";
        },
        MOQTControlMessage::NamespaceDone => {
            s += "NAMESPACE_DONE";
        },
        MOQTControlMessage::PublishNamespaceCancel {
            track_namespace_prefix,
            error_code,
            reason,
        } => {
            s += "PUBLISH_NAMESPACE_CANCEL {";
            s += "track_namespace_prefix=[";
            for tn in track_namespace_prefix {
                printyo!("value", &tn.value, s);
                printyo!("value_bytes", &tn.value_bytes, s);
            }
            s += "], ";
            printy!("error_code", error_code, s);
            if let Some(r) = reason {
                printyo!("reason", &r.value, s);
                printyo!("reason_bytes", &r.value_bytes, s);
            }
            s += "}";
        },
        MOQTControlMessage::TrackStatus {
            track_namespace,
            track_name,
            status_code,
            last_location,
        } => {
            s += "TRACK_STATUS {";
            s += &moqt_track_namespace_to_string(track_namespace);
            printyo!("track_name", &track_name.value, s);
            printyo!("track_name_bytes", &track_name.value_bytes, s);
            printy!("status_code", status_code, s);
            printyo_json!("last_location", last_location, s);
            s += "}";
        },
        MOQTControlMessage::Unknown => s += "UNKNOWN",
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
                    EventData::QuicConnectionStarted(v) => {
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
                    EventData::QuicConnectionClosed(v) => {
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
                    EventData::QuicParametersSet(v) => {
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
                    EventData::QuicPacketSent(v) => {
                        p.details +=
                            &serde_json::to_string(&v.header.packet_type)
                                .unwrap()
                                .replace("\"", "");
                        printyo!(" pn", v.header.packet_number, p.details);

                        if let Some(frames) = &v.frames {
                            p.details += &frames_to_string(frames);
                        }
                    },
                    EventData::QuicPacketReceived(v) => {
                        p.details +=
                            &serde_json::to_string(&v.header.packet_type)
                                .unwrap()
                                .replace("\"", "");
                        printyo!(" pn", v.header.packet_number, p.details);

                        if let Some(frames) = &v.frames {
                            p.details += &frames_to_string(frames);
                        }
                    },
                    EventData::QuicStreamDataMoved(v) => {
                        printyo!("id", v.stream_id, p.details);
                        printyo!("off", v.offset, p.details);
                        if let Some(raw) = &v.raw {
                            printyo!("len", raw.length, p.details);
                        }
                        printyo_json!("from", &v.from, p.details);
                        printyo_json!("to", &v.to, p.details);
                    },
                    EventData::QuicMetricsUpdated(v) => {
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
                    EventData::Http3StreamTypeSet(ev) => {
                        printy!("id", &ev.stream_id, p.details);
                        printyo_json!("initiator", &ev.initiator, p.details);
                        printy_json!("ty", &ev.stream_type, p.details);
                    },
                    EventData::Http3FrameCreated(v) => {
                        printy!("id", v.stream_id, p.details);
                        printyo!("len", v.length, p.details);
                        p.details += &http_frame_to_string(&v.frame);
                    },
                    EventData::Http3FrameParsed(v) => {
                        printy!("id", v.stream_id, p.details);
                        printyo!("len", v.length, p.details);
                        p.details += &http_frame_to_string(&v.frame);
                    },
                    EventData::MOQTControlMessageCreated(v) => {
                        printy!("id", v.stream_id, p.details);
                        p.details += &moq_control_message_to_string(&v.message);
                        printyo_json!("raw", &v.raw, p.details);
                    },
                    EventData::MOQTControlMessageParsed(v) => {
                        printy!("id", v.stream_id, p.details);
                        p.details += &moq_control_message_to_string(&v.message);
                        printyo_json!("raw", &v.raw, p.details);
                    },
                    EventData::MOQTStreamTypeSet(v) => {
                        printyo_json!("owner", &v.owner, p.details);
                        printy!("id", v.stream_id, p.details);
                        printy_json!("ty", &v.stream_type, p.details);
                    },
                    EventData::MOQTSubgroupHeaderCreated(v) => {
                        printy!("stream_id", v.stream_id, p.details);
                        printy!("track_alias", v.track_alias, p.details);
                        printy!("group_id", v.group_id, p.details);
                        printy!(
                            "subgroup_id_mode",
                            v.subgroup_id_mode,
                            p.details
                        );
                        printyo!("subgroup_id", v.subgroup_id, p.details);
                        printyo!(
                            "publisher_priority",
                            v.publisher_priority,
                            p.details
                        );
                        printy!(
                            "contains_end_of_group",
                            v.contains_end_of_group,
                            p.details
                        );
                        printy!(
                            "extensions_present",
                            v.extensions_present,
                            p.details
                        );
                    },
                    EventData::MOQTSubgroupHeaderParsed(v) => {
                        printy!("stream_id", v.stream_id, p.details);
                        printy!("track_alias", v.track_alias, p.details);
                        printy!("group_id", v.group_id, p.details);
                        printy!(
                            "subgroup_id_mode",
                            v.subgroup_id_mode,
                            p.details
                        );
                        printyo!("subgroup_id", v.subgroup_id, p.details);
                        printyo!(
                            "publisher_priority",
                            v.publisher_priority,
                            p.details
                        );
                        printy!(
                            "contains_end_of_group",
                            v.contains_end_of_group,
                            p.details
                        );
                        printy!(
                            "extensions_present",
                            v.extensions_present,
                            p.details
                        );
                    },
                    EventData::MOQTSubgroupObjectCreated(v) => {
                        printy!("stream_id", v.stream_id, p.details);
                        printy!("object_id_delta", v.object_id_delta, p.details);
                        printyo_json!(
                            "extension_headers",
                            &v.extension_headers,
                            p.details
                        );
                        printy!(
                            "object_payload_length",
                            v.object_payload_length,
                            p.details
                        );
                        printyo!("object_status", v.object_status, p.details);
                        printyo_json!(
                            "object_payload",
                            &v.object_payload,
                            p.details
                        );
                    },
                    EventData::MOQTSubgroupObjectParsed(v) => {
                        printy!("stream_id", v.stream_id, p.details);
                        printy!("object_id_delta", v.object_id_delta, p.details);
                        printyo_json!(
                            "extension_headers",
                            &v.extension_headers,
                            p.details
                        );
                        printy!(
                            "object_payload_length",
                            v.object_payload_length,
                            p.details
                        );
                        printyo!("object_status", v.object_status, p.details);
                        printyo_json!(
                            "object_payload",
                            &v.object_payload,
                            p.details
                        );
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
