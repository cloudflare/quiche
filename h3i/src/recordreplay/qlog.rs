// Copyright (C) 2024, Cloudflare, Inc.
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

use std::collections::BTreeMap;

use crate::quiche;
use qlog::events::h3::H3FrameCreated;
use qlog::events::h3::H3Owner;
use qlog::events::h3::H3StreamTypeSet;
use qlog::events::h3::Http3Frame;
use qlog::events::h3::HttpHeader;
use qlog::events::quic::ErrorSpace;
use qlog::events::quic::PacketSent;
use qlog::events::quic::QuicFrame;
use qlog::events::Event;
use qlog::events::EventData;
use qlog::events::ExData;
use qlog::events::JsonEvent;
use qlog::events::RawInfo;
use quiche::h3::frame::Frame;
use quiche::h3::NameValue;

use serde_json::json;

use smallvec::smallvec;

use crate::actions::h3::Action;
use crate::actions::h3::WaitType;
use crate::encode_header_block;
use crate::encode_header_block_literal;
use crate::fake_packet_sent;
use crate::HTTP3_CONTROL_STREAM_TYPE_ID;
use crate::HTTP3_PUSH_STREAM_TYPE_ID;
use crate::QPACK_DECODER_STREAM_TYPE_ID;
use crate::QPACK_ENCODER_STREAM_TYPE_ID;

/// A qlog event representation using either the official RFC format or the
/// catch-al JSON event.
pub enum QlogEvent {
    Event {
        data: Box<EventData>,
        ex_data: ExData,
    },
    JsonEvent(JsonEvent),
}

/// A collection of [QlogEvent]s.
pub type QlogEvents = Vec<QlogEvent>;

/// A collection of [Action]s.
pub struct H3Actions(pub Vec<Action>);

/// A qlog [H3FrameCreated] event, with [ExData].
pub struct H3FrameCreatedEx {
    frame_created: H3FrameCreated,
    ex_data: ExData,
}

impl From<&Action> for QlogEvents {
    fn from(action: &Action) -> Self {
        match action {
            Action::SendFrame {
                stream_id,
                fin_stream,
                frame,
            } => {
                let frame_ev = EventData::H3FrameCreated(H3FrameCreated {
                    stream_id: *stream_id,
                    frame: frame.to_qlog(),
                    ..Default::default()
                });

                let mut ex = BTreeMap::new();

                if *fin_stream {
                    ex.insert("fin_stream".to_string(), json!(true));
                }

                vec![QlogEvent::Event {
                    data: Box::new(frame_ev),
                    ex_data: ex,
                }]
            },

            Action::SendHeadersFrame {
                stream_id,
                fin_stream,
                headers,
                literal_headers,
                ..
            } => {
                let qlog_headers = headers
                    .iter()
                    .map(|h| qlog::events::h3::HttpHeader {
                        name: String::from_utf8_lossy(h.name()).into_owned(),
                        value: String::from_utf8_lossy(h.value()).into_owned(),
                    })
                    .collect();

                let frame = Http3Frame::Headers {
                    headers: qlog_headers,
                };

                let frame_ev = EventData::H3FrameCreated(H3FrameCreated {
                    stream_id: *stream_id,
                    frame,
                    ..Default::default()
                });

                let mut ex = BTreeMap::new();

                if *fin_stream {
                    ex.insert("fin_stream".to_string(), json!(true));
                }

                if *literal_headers {
                    ex.insert("literal_headers".to_string(), json!(true));
                }

                vec![QlogEvent::Event {
                    data: Box::new(frame_ev),
                    ex_data: ex,
                }]
            },

            Action::OpenUniStream {
                stream_id,
                fin_stream,
                stream_type,
            } => {
                let ty = match *stream_type {
                    HTTP3_CONTROL_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::Control,
                    HTTP3_PUSH_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::Push,
                    QPACK_ENCODER_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::QpackEncode,
                    QPACK_DECODER_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::QpackDecode,

                    _ => qlog::events::h3::H3StreamType::Unknown,
                };
                let ty_val =
                    if matches!(ty, qlog::events::h3::H3StreamType::Unknown) {
                        Some(*stream_type)
                    } else {
                        None
                    };

                let stream_ev = EventData::H3StreamTypeSet(H3StreamTypeSet {
                    owner: Some(H3Owner::Local),
                    stream_id: *stream_id,
                    stream_type: ty,
                    stream_type_value: ty_val,
                    ..Default::default()
                });
                let mut ex = BTreeMap::new();

                if *fin_stream {
                    ex.insert("fin_stream".to_string(), json!(true));
                }

                vec![QlogEvent::Event {
                    data: Box::new(stream_ev),
                    ex_data: ex,
                }]
            },

            Action::StreamBytes {
                stream_id,
                fin_stream,
                bytes,
            } => {
                let len = bytes.len() as u64;
                let ev = fake_packet_sent(Some(smallvec![QuicFrame::Stream {
                    stream_id: *stream_id,
                    fin: Some(*fin_stream),
                    // ignore offset
                    offset: 0,
                    length: len,
                    raw: Some(RawInfo {
                        length: Some(len),
                        payload_length: Some(len),
                        data: String::from_utf8(bytes.clone()).ok()
                    })
                }]));

                vec![QlogEvent::Event {
                    data: Box::new(ev),
                    ex_data: BTreeMap::new(),
                }]
            },

            Action::SendDatagram { payload } => {
                let len = payload.len() as u64;
                let ev = fake_packet_sent(Some(smallvec![QuicFrame::Datagram {
                    length: len,
                    raw: String::from_utf8(payload.clone()).ok()
                }]));

                vec![QlogEvent::Event {
                    data: Box::new(ev),
                    ex_data: BTreeMap::new(),
                }]
            },

            Action::ResetStream {
                stream_id,
                error_code,
            } => {
                let ev =
                    fake_packet_sent(Some(smallvec![QuicFrame::ResetStream {
                        stream_id: *stream_id,
                        error_code: *error_code,
                        final_size: 0,
                        length: None,
                        payload_length: None
                    }]));
                vec![QlogEvent::Event {
                    data: Box::new(ev),
                    ex_data: BTreeMap::new(),
                }]
            },

            Action::StopSending {
                stream_id,
                error_code,
            } => {
                let ev =
                    fake_packet_sent(Some(smallvec![QuicFrame::StopSending {
                        stream_id: *stream_id,
                        error_code: *error_code,
                        length: None,
                        payload_length: None
                    }]));
                vec![QlogEvent::Event {
                    data: Box::new(ev),
                    ex_data: BTreeMap::new(),
                }]
            },

            Action::Wait { wait_type } => {
                let name = "h3i:wait".into();

                let data = match wait_type {
                    d @ WaitType::WaitDuration(_) =>
                        serde_json::to_value(d).unwrap(),
                    WaitType::StreamEvent(event) =>
                        serde_json::to_value(event).unwrap(),
                };

                vec![QlogEvent::JsonEvent(qlog::events::JsonEvent {
                    time: 0.0,
                    importance: qlog::events::EventImportance::Core,
                    name,
                    data,
                })]
            },

            Action::ConnectionClose { error } => {
                let error_space = if error.is_app {
                    ErrorSpace::Application
                } else {
                    ErrorSpace::Transport
                };

                let reason = if error.reason.is_empty() {
                    None
                } else {
                    Some(String::from_utf8(error.reason.clone()).unwrap())
                };

                let ev = fake_packet_sent(Some(smallvec![
                    QuicFrame::ConnectionClose {
                        error_space: Some(error_space),
                        error_code: Some(error.error_code),
                        // https://github.com/cloudflare/quiche/issues/1731
                        error_code_value: None,
                        reason,
                        trigger_frame_type: None
                    }
                ]));

                vec![QlogEvent::Event {
                    data: Box::new(ev),
                    ex_data: BTreeMap::new(),
                }]
            },

            Action::FlushPackets => {
                vec![]
            },
        }
    }
}

pub fn actions_from_qlog(event: Event, host_override: Option<&str>) -> H3Actions {
    let mut actions = vec![];
    match &event.data {
        EventData::PacketSent(ps) => {
            let packet_actions: H3Actions = ps.into();
            actions.extend(packet_actions.0);
        },

        EventData::H3FrameCreated(fc) => {
            let mut frame_created = H3FrameCreatedEx {
                frame_created: fc.clone(),
                ex_data: event.ex_data.clone(),
            };

            // Insert custom data so that conversion of frames to Actions can
            // use it.
            if let Some(host) = host_override {
                frame_created
                    .ex_data
                    .insert("host_override".into(), host.into());
            }

            actions.push(frame_created.into());
        },

        EventData::H3StreamTypeSet(st) => {
            let stream_actions = from_qlog_stream_type_set(st, &event.ex_data);
            actions.extend(stream_actions);
        },

        _ => (),
    }

    H3Actions(actions)
}

impl From<JsonEvent> for H3Actions {
    fn from(event: JsonEvent) -> Self {
        let mut actions = vec![];
        match event.name.as_ref() {
            "h3i:wait" => {
                let wait_type =
                    serde_json::from_value::<WaitType>(event.clone().data);

                if let Ok(wt) = wait_type {
                    actions.push(Action::Wait { wait_type: wt });
                } else {
                    log::debug!("couldn't create action from event: {event:?}");
                }
            },
            _ => unimplemented!(),
        }

        Self(actions)
    }
}

impl From<&PacketSent> for H3Actions {
    fn from(ps: &PacketSent) -> Self {
        let mut actions = vec![];
        if let Some(frames) = &ps.frames {
            for frame in frames {
                match &frame {
                    // TODO add these
                    QuicFrame::ResetStream {
                        stream_id,
                        error_code,
                        ..
                    } => actions.push(Action::ResetStream {
                        stream_id: *stream_id,
                        error_code: *error_code,
                    }),

                    QuicFrame::StopSending {
                        stream_id,
                        error_code,
                        ..
                    } => actions.push(Action::StopSending {
                        stream_id: *stream_id,
                        error_code: *error_code,
                    }),

                    QuicFrame::ConnectionClose {
                        error_space,
                        error_code,
                        reason,
                        ..
                    } => {
                        let is_app = matches!(
                            error_space.as_ref().expect(
                                "invalid CC frame in qlog input, no error space"
                            ),
                            ErrorSpace::Application
                        );

                        actions.push(Action::ConnectionClose {
                            error: quiche::ConnectionError {
                                is_app,
                                // TODO: remove unwrap when https://github.com/cloudflare/quiche/issues/1731
                                // is done
                                error_code: error_code.expect("invalid CC frame in qlog input, no error code"),
                                reason: reason
                                    .as_ref()
                                    .map(|s| s.as_bytes().to_vec())
                                    .unwrap_or_default(),
                            },
                        })
                    },

                    QuicFrame::Stream { stream_id, fin, .. } => {
                        let fin = fin.unwrap_or_default();

                        if fin {
                            actions.push(Action::StreamBytes {
                                stream_id: *stream_id,
                                fin_stream: true,
                                bytes: vec![],
                            });
                        }
                    },

                    QuicFrame::Datagram { raw, .. } => {
                        actions.push(Action::SendDatagram {
                            payload: raw.clone().unwrap_or_default().into(),
                        });
                    },
                    _ => (),
                }
            }
        }

        Self(actions)
    }
}

fn map_header(
    hdr: &HttpHeader, host_override: Option<&str>,
) -> quiche::h3::Header {
    if hdr.name.eq_ignore_ascii_case(":authority") ||
        hdr.name.eq_ignore_ascii_case("host")
    {
        if let Some(host) = host_override {
            return quiche::h3::Header::new(hdr.name.as_bytes(), host.as_bytes());
        }
    }

    quiche::h3::Header::new(hdr.name.as_bytes(), hdr.value.as_bytes())
}

impl From<H3FrameCreatedEx> for Action {
    fn from(value: H3FrameCreatedEx) -> Self {
        let stream_id = value.frame_created.stream_id;
        let fin_stream = value
            .ex_data
            .get("fin_stream")
            .unwrap_or(&serde_json::Value::Null)
            .as_bool()
            .unwrap_or_default();
        let host_override = value
            .ex_data
            .get("host_override")
            .unwrap_or(&serde_json::Value::Null)
            .as_str();

        let ret = match &value.frame_created.frame {
            Http3Frame::Settings { settings } => {
                let mut raw_settings = vec![];
                let mut additional_settings = vec![];
                // This is ugly but it reflects ambiguity in the qlog
                // specs.
                for s in settings {
                    match s.name.as_str() {
                        "MAX_FIELD_SECTION_SIZE" =>
                            raw_settings.push((0x6, s.value)),
                        "QPACK_MAX_TABLE_CAPACITY" =>
                            raw_settings.push((0x1, s.value)),
                        "QPACK_BLOCKED_STREAMS" =>
                            raw_settings.push((0x7, s.value)),
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL" =>
                            raw_settings.push((0x8, s.value)),
                        "H3_DATAGRAM" => raw_settings.push((0x33, s.value)),

                        _ =>
                            if let Ok(ty) = s.name.parse::<u64>() {
                                raw_settings.push((ty, s.value));
                                additional_settings.push((ty, s.value));
                            },
                    }
                }

                Action::SendFrame {
                    stream_id,
                    fin_stream,
                    frame: Frame::Settings {
                        max_field_section_size: None,
                        qpack_max_table_capacity: None,
                        qpack_blocked_streams: None,
                        connect_protocol_enabled: None,
                        h3_datagram: None,
                        grease: None,
                        raw: Some(raw_settings),
                        additional_settings: Some(additional_settings),
                    },
                }
            },

            Http3Frame::Headers { headers } => {
                let hdrs: Vec<quiche::h3::Header> = headers
                    .iter()
                    .map(|h| map_header(h, host_override))
                    .collect();

                let literal_headers = value
                    .ex_data
                    .get("literal_headers")
                    .unwrap_or(&serde_json::Value::Null)
                    .as_bool()
                    .unwrap_or_default();

                let header_block = if literal_headers {
                    encode_header_block_literal(&hdrs).unwrap()
                } else {
                    encode_header_block(&hdrs).unwrap()
                };

                Action::SendHeadersFrame {
                    stream_id,
                    fin_stream,
                    literal_headers,
                    headers: hdrs,
                    frame: Frame::Headers { header_block },
                }
            },

            Http3Frame::Data { raw } => {
                let mut payload = vec![];
                if let Some(r) = raw {
                    payload = r
                        .data
                        .clone()
                        .unwrap_or("".to_string())
                        .as_bytes()
                        .to_vec();
                }

                Action::SendFrame {
                    stream_id,
                    fin_stream,
                    frame: Frame::Data { payload },
                }
            },

            Http3Frame::Goaway { id } => Action::SendFrame {
                stream_id,
                fin_stream,
                frame: Frame::GoAway { id: *id },
            },

            _ => unimplemented!(),
        };

        ret
    }
}

fn from_qlog_stream_type_set(
    st: &H3StreamTypeSet, ex_data: &ExData,
) -> Vec<Action> {
    let mut actions = vec![];
    let fin_stream = parse_ex_data(ex_data);
    let stream_type = match st.stream_type {
        qlog::events::h3::H3StreamType::Control => Some(0x0),
        qlog::events::h3::H3StreamType::Push => Some(0x1),
        qlog::events::h3::H3StreamType::QpackEncode => Some(0x2),
        qlog::events::h3::H3StreamType::QpackDecode => Some(0x3),
        qlog::events::h3::H3StreamType::Reserved |
        qlog::events::h3::H3StreamType::Unknown => st.stream_type_value,
        _ => None,
    };

    if let Some(ty) = stream_type {
        actions.push(Action::OpenUniStream {
            stream_id: st.stream_id,
            fin_stream,
            stream_type: ty,
        })
    }

    actions
}

fn parse_ex_data(ex_data: &ExData) -> bool {
    ex_data
        .get("fin_stream")
        .unwrap_or(&serde_json::Value::Null)
        .as_bool()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::actions::h3::StreamEvent;
    use crate::actions::h3::StreamEventType;
    use crate::encode_header_block_literal;
    use std::time::Duration;

    use super::*;
    use quiche::h3::Header;
    use serde_json;

    const NOW: f32 = 123.0;
    const H3I_WAIT: &str = "h3i:wait";

    #[test]
    fn ser_duration_wait() {
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(WaitType::WaitDuration(
                Duration::from_millis(12345),
            ))
            .unwrap(),
        };
        let serialized = serde_json::to_string(&ev);

        let expected =
            r#"{"time":123.0,"name":"h3i:wait","data":{"duration":12345.0}}"#;
        assert_eq!(&serialized.unwrap(), expected);
    }

    #[test]
    fn deser_duration_wait() {
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(WaitType::WaitDuration(
                Duration::from_millis(12345),
            ))
            .unwrap(),
        };

        let expected =
            r#"{"time":123.0,"name":"h3i:wait","data":{"duration":12345.0}}"#;
        let deser = serde_json::from_str::<JsonEvent>(expected).unwrap();
        assert_eq!(deser.data, ev.data);
    }

    #[test]
    fn ser_stream_wait() {
        let expected = r#"{"time":123.0,"name":"h3i:wait","data":{"stream_id":0,"type":"data"}}"#;
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(StreamEvent {
                stream_id: 0,
                event_type: StreamEventType::Data,
            })
            .unwrap(),
        };

        let serialized = serde_json::to_string(&ev);
        assert_eq!(&serialized.unwrap(), expected);
    }

    #[test]
    fn deser_stream_wait() {
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(StreamEvent {
                stream_id: 0,
                event_type: StreamEventType::Data,
            })
            .unwrap(),
        };

        let expected = r#"{"time":123.0,"name":"h3i:wait","data":{"stream_id":0,"type":"data"}}"#;
        let deser = serde_json::from_str::<JsonEvent>(expected).unwrap();
        assert_eq!(deser.data, ev.data);
    }

    #[test]
    fn deser_http_headers_to_action() {
        let serialized = r#"{"time":0.074725,"name":"http:frame_created","data":{"stream_id":0,"frame":{"frame_type":"headers","headers":[{"name":":method","value":"GET"},{"name":":authority","value":"example.net"},{"name":":path","value":"/"},{"name":":scheme","value":"https"}]}},"fin_stream":true}"#;
        let deserialized = serde_json::from_str::<Event>(serialized).unwrap();
        let actions = actions_from_qlog(deserialized, None);
        assert!(actions.0.len() == 1);

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"example.net"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
        ];
        let header_block = encode_header_block(&headers).unwrap();
        let frame = Frame::Headers { header_block };
        let expected = Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: true,
            literal_headers: false,
            headers,
            frame,
        };

        assert_eq!(actions.0[0], expected);
    }

    #[test]
    fn deser_http_headers_host_overrid_to_action() {
        let serialized = r#"{"time":0.074725,"name":"http:frame_created","data":{"stream_id":0,"frame":{"frame_type":"headers","headers":[{"name":":method","value":"GET"},{"name":":authority","value":"bla.com"},{"name":":path","value":"/"},{"name":":scheme","value":"https"}]}},"fin_stream":true}"#;
        let deserialized = serde_json::from_str::<Event>(serialized).unwrap();
        let actions = actions_from_qlog(deserialized, Some("example.org"));
        assert!(actions.0.len() == 1);

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"example.org"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
        ];
        let header_block = encode_header_block(&headers).unwrap();
        let frame = Frame::Headers { header_block };
        let expected = Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: true,
            literal_headers: false,
            headers,
            frame,
        };

        assert_eq!(actions.0[0], expected);
    }

    #[test]
    fn deser_http_headers_literal_to_action() {
        let serialized = r#"{"time":0.074725,"name":"http:frame_created","data":{"stream_id":0,"frame":{"frame_type":"headers","headers":[{"name":":method","value":"GET"},{"name":":authority","value":"bla.com"},{"name":":path","value":"/"},{"name":":scheme","value":"https"},{"name":"Foo","value":"bar"}]}},"fin_stream":true,"literal_headers":true}"#;
        let deserialized = serde_json::from_str::<Event>(serialized).unwrap();
        let actions = actions_from_qlog(deserialized, None);
        assert!(actions.0.len() == 1);

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"bla.com"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
            Header::new(b"Foo", b"bar"),
        ];
        let header_block = encode_header_block_literal(&headers).unwrap();
        let frame = Frame::Headers { header_block };
        let expected = Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: true,
            literal_headers: true,
            headers,
            frame,
        };

        assert_eq!(actions.0[0], expected);
    }
}
