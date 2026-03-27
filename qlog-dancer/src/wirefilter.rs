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

use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use qlog::reader::Event;
use std::iter::FromIterator;
use std::vec;
use wirefilter::ExecutionContext;
use wirefilter::Scheme;
use wirefilter::TypedArray;

use crate::category_and_type_from_event;

fn stream_ids(event: &Event) -> TypedArray<'_, i64> {
    let mut ids: TypedArray<i64> = TypedArray::new();

    match event {
        Event::Qlog(event) => match &event.data {
            EventData::QuicStreamDataMoved(v) =>
                if let Some(id) = v.stream_id {
                    ids.push(id as i64);
                },
            EventData::QuicPacketSent(v) => {
                if let Some(frames) = &v.frames {
                    for frame in frames {
                        match frame {
                            QuicFrame::ResetStream { stream_id, .. } =>
                                ids.push(*stream_id as i64),
                            QuicFrame::StopSending { stream_id, .. } =>
                                ids.push(*stream_id as i64),
                            QuicFrame::Stream { stream_id, .. } =>
                                ids.push(*stream_id as i64),
                            QuicFrame::MaxStreamData { stream_id, .. } =>
                                ids.push(*stream_id as i64),
                            QuicFrame::StreamDataBlocked {
                                stream_id, ..
                            } => ids.push(*stream_id as i64),

                            // other frames are not related to streams
                            _ => (),
                        }
                    }
                }
            },
            EventData::Http3StreamTypeSet(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::Http3FrameCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::Http3FrameParsed(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTControlMessageCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTControlMessageParsed(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTStreamTypeSet(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTSubgroupHeaderCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTSubgroupHeaderParsed(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTSubgroupObjectCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTSubgroupObjectParsed(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTFetchHeaderCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTFetchHeaderParsed(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTFetchObjectCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::MOQTFetchObjectParsed(v) => {
                ids.push(v.stream_id as i64);
            },

            // other events are not related to streams
            _ => (),
        },

        // TODO: try and fuzzy extract stream id
        Event::Json(_event) => {},
    }

    ids
}

#[derive(Default)]
struct MOQTFilterFields<'a> {
    pub group_ids: TypedArray<'a, i64>,
    pub object_ids: TypedArray<'a, i64>,
    pub object_payload_length: TypedArray<'a, i64>,
}

impl From<&Event> for MOQTFilterFields<'_> {
    fn from(value: &Event) -> Self {
        let mut group_ids: TypedArray<i64> = TypedArray::new();
        let mut object_ids: TypedArray<i64> = TypedArray::new();
        let mut object_payload_length: TypedArray<i64> = TypedArray::new();

        match value {
            Event::Qlog(event) => match &event.data {
                EventData::MOQTObjectDatagramCreated(v) => {
                    group_ids.push(v.group_id as i64);
                    if let Some(id) = v.object_id {
                        object_ids.push(id as i64);
                    }
                },
                EventData::MOQTObjectDatagramParsed(v) => {
                    group_ids.push(v.group_id as i64);
                    if let Some(id) = v.object_id {
                        object_ids.push(id as i64);
                    }
                },
                EventData::MOQTSubgroupHeaderCreated(v) => {
                    group_ids.push(v.group_id as i64);
                },
                EventData::MOQTSubgroupHeaderParsed(v) => {
                    group_ids.push(v.group_id as i64);
                },
                EventData::MOQTSubgroupObjectCreated(v) => {
                    object_payload_length.push(v.object_payload_length as i64);
                },
                EventData::MOQTSubgroupObjectParsed(v) => {
                    object_payload_length.push(v.object_payload_length as i64);
                },
                EventData::MOQTFetchObjectCreated(v) => {
                    if let Some(id) = v.group_id {
                        group_ids.push(id as i64);
                    }
                    if let Some(id) = v.object_id {
                        object_ids.push(id as i64);
                    }
                    object_payload_length.push(v.object_payload_length as i64);
                },
                EventData::MOQTFetchObjectParsed(v) => {
                    if let Some(id) = v.group_id {
                        group_ids.push(id as i64);
                    }
                    if let Some(id) = v.object_id {
                        object_ids.push(id as i64);
                    }
                    object_payload_length.push(v.object_payload_length as i64);
                },

                // other events don't have MOQT fields we care about
                _ => (),
            },

            Event::Json(_event) => {},
        }

        Self {
            group_ids,
            object_ids,
            object_payload_length,
        }
    }
}

pub fn filter_sqlog_events(mut events: Vec<Event>, filter: &str) -> Vec<Event> {
    let mut ret = vec![];

    let mut builder = Scheme! {
        category: Bytes,
        name: Bytes,
        stream_id: Array(Int),
        moqt.group_id: Array(Int),
        moqt.object_id: Array(Int),
        moqt.object_payload_length: Array(Int),
    };

    builder
        .add_function("any", wirefilter::AnyFunction {})
        .unwrap();

    let scheme = builder.build();
    let ast = scheme.parse(filter).unwrap();
    let filter = ast.compile();

    // TODO: smarter filtering rather then drain / recreate
    for event in events.drain(..) {
        // Recreate context each time to appease borrow checker
        let mut ctx = ExecutionContext::new(&scheme);

        let moqt_filter_fields = MOQTFilterFields::from(&event);

        let filter_match = match &event {
            Event::Qlog(ev) => {
                let (cat, ty) = category_and_type_from_event(&ev);

                ctx.set_field_value(
                    scheme.get_field("category").unwrap(),
                    cat.clone(),
                )
                .unwrap();
                ctx.set_field_value(
                    scheme.get_field("name").unwrap(),
                    ty.clone(),
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("stream_id").unwrap(),
                    stream_ids(&event),
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("moqt.group_id").unwrap(),
                    moqt_filter_fields.group_ids,
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("moqt.object_id").unwrap(),
                    moqt_filter_fields.object_ids,
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("moqt.object_payload_length").unwrap(),
                    moqt_filter_fields.object_payload_length,
                )
                .unwrap();

                filter.execute(&ctx).unwrap()
            },
            Event::Json(ev) => {
                let (cat, ty) = category_and_type_from_event(&ev);
                ctx.set_field_value(
                    scheme.get_field("category").unwrap(),
                    cat.clone(),
                )
                .unwrap();
                ctx.set_field_value(
                    scheme.get_field("name").unwrap(),
                    ty.clone(),
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("stream_id").unwrap(),
                    stream_ids(&event),
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("moqt.group_id").unwrap(),
                    moqt_filter_fields.group_ids,
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("moqt.object_id").unwrap(),
                    moqt_filter_fields.object_ids,
                )
                .unwrap();

                ctx.set_field_value(
                    scheme.get_field("moqt.object_payload_length").unwrap(),
                    moqt_filter_fields.object_payload_length,
                )
                .unwrap();

                filter.execute(&ctx).unwrap()
            },
        };

        if filter_match {
            ret.push(event);
        }
    }

    ret
}

#[cfg(test)]
mod tests {
    use crate::wirefilter::filter_sqlog_events;
    use qlog::events::quic::PacketHeader;
    use qlog::events::quic::PacketSent;
    use qlog::events::quic::PacketType::Initial;
    use qlog::events::quic::QuicFrame;
    use qlog::events::EventData::QuicPacketSent;
    use qlog::events::RawInfo;
    use qlog::reader::Event;

    fn stream_frame(stream_id: u64) -> QuicFrame {
        QuicFrame::Stream {
            stream_id,
            offset: Some(0),
            fin: Some(true),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(10),
                data: None,
            })),
        }
    }

    // Events aren't clonable in the version of qlog we have, so lazy solution for
    // now
    fn events() -> Vec<Event> {
        let mut events = vec![];
        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
        let pkt_hdr = PacketHeader::new(
            Initial,
            Some(0),
            None,
            None,
            Some(1),
            Some(&scid),
            Some(&dcid),
        );
        let raw = RawInfo {
            length: None,
            payload_length: Some(0),
            data: None,
        };

        let frames = vec![
            QuicFrame::Crypto {
                offset: 0,
                raw: Some(Box::new(raw)),
            },
            stream_frame(1),
            stream_frame(2),
            stream_frame(3),
            stream_frame(4),
            stream_frame(5),
        ];

        let raw = RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        };

        let event_data = QuicPacketSent(PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(frames.into()),
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(raw.clone()),
            datagram_id: None,
            is_mtu_probe_packet: None,
            send_at_time: None,
            trigger: None,
        });

        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        let frames = vec![
            stream_frame(0),
            stream_frame(100),
            stream_frame(200),
            stream_frame(300),
            stream_frame(400),
        ];

        let event_data = QuicPacketSent(PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(frames.into()),
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(raw.clone()),
            datagram_id: None,
            is_mtu_probe_packet: None,
            send_at_time: None,
            trigger: None,
        });

        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        let frames = vec![
            stream_frame(1),
            stream_frame(100),
            stream_frame(2),
            stream_frame(200),
        ];

        let event_data = QuicPacketSent(PacketSent {
            header: pkt_hdr,
            frames: Some(frames.into()),
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(raw),
            datagram_id: None,
            is_mtu_probe_packet: None,
            send_at_time: None,
            trigger: None,
        });

        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        events
    }

    #[test]
    fn test_stream_id_filter_no_match() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==13)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert!(filtered_events.is_empty());
    }

    #[test]
    fn test_stream_id_filter_stream0() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==0)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 1);

        let ev = &filtered_events[0];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                stream_frame(0),
                                stream_frame(100),
                                stream_frame(200),
                                stream_frame(300),
                                stream_frame(400),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_stream_id_filter_stream1() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==1)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 2);

        let ev = &filtered_events[0];

        let raw = RawInfo {
            length: None,
            payload_length: Some(0),
            data: None,
        };

        match ev {
            Event::Qlog(event) => match &event.data {
                QuicPacketSent(packet_sent) => {
                    assert_eq!(
                        packet_sent.frames,
                        Some(vec![
                            QuicFrame::Crypto {
                                offset: 0,
                                raw: Some(Box::new(raw)),
                            },
                            stream_frame(1),
                            stream_frame(2),
                            stream_frame(3),
                            stream_frame(4),
                            stream_frame(5),
                        ])
                    );
                },
                _ => panic!("unexpected event data"),
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }

        let ev = &filtered_events[1];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                stream_frame(1),
                                stream_frame(100),
                                stream_frame(2),
                                stream_frame(200),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_stream_id_filter_stream0_and_stream3() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==0) || any(stream_id[*]==3)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 2);

        let raw = RawInfo {
            length: None,
            payload_length: Some(0),
            data: None,
        };

        let ev = &filtered_events[0];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                QuicFrame::Crypto {
                                    offset: 0,
                                    raw: Some(Box::new(raw)),
                                },
                                stream_frame(1),
                                stream_frame(2),
                                stream_frame(3),
                                stream_frame(4),
                                stream_frame(5),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }

        let ev = &filtered_events[1];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                stream_frame(0),
                                stream_frame(100),
                                stream_frame(200),
                                stream_frame(300),
                                stream_frame(400),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }
    }

    // MOQT test helpers and tests

    use qlog::events::moqt::MOQTObjectDatagramCreated;
    use qlog::events::moqt::MOQTSubgroupHeaderCreated;
    use qlog::events::moqt::MOQTSubgroupObjectCreated;
    use qlog::events::EventData::MOQTObjectDatagramCreated as MOQTObjectDatagramCreatedData;
    use qlog::events::EventData::MOQTSubgroupHeaderCreated as MOQTSubgroupHeaderCreatedData;
    use qlog::events::EventData::MOQTSubgroupObjectCreated as MOQTSubgroupObjectCreatedData;

    fn moqt_events() -> Vec<Event> {
        let mut events = vec![];

        // Event with group_id=1, object_id=10
        let event_data =
            MOQTObjectDatagramCreatedData(MOQTObjectDatagramCreated {
                track_alias: 100,
                group_id: 1,
                object_id: Some(10),
                publisher_priority: None,
                extension_headers_length: None,
                extension_headers: None,
                object_status: None,
                object_payload: None,
                end_of_group: false,
            });
        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        // Event with group_id=2, object_id=20
        let event_data =
            MOQTObjectDatagramCreatedData(MOQTObjectDatagramCreated {
                track_alias: 100,
                group_id: 2,
                object_id: Some(20),
                publisher_priority: None,
                extension_headers_length: None,
                extension_headers: None,
                object_status: None,
                object_payload: None,
                end_of_group: false,
            });
        events.push(Event::Qlog(qlog::events::Event::with_time(1.0, event_data)));

        // Subgroup header with stream_id=5, group_id=3
        let event_data =
            MOQTSubgroupHeaderCreatedData(MOQTSubgroupHeaderCreated {
                stream_id: 5,
                track_alias: 100,
                group_id: 3,
                subgroup_id_mode: 0,
                subgroup_id: Some(0),
                publisher_priority: Some(1),
                contains_end_of_group: false,
                extensions_present: false,
            });
        events.push(Event::Qlog(qlog::events::Event::with_time(2.0, event_data)));

        // Subgroup object with stream_id=5, object_payload_length=1000
        let event_data =
            MOQTSubgroupObjectCreatedData(MOQTSubgroupObjectCreated {
                stream_id: 5,
                object_id_delta: 0,
                extension_headers: None,
                object_payload_length: 1000,
                object_status: None,
                object_payload: None,
            });
        events.push(Event::Qlog(qlog::events::Event::with_time(3.0, event_data)));

        // Another subgroup object with object_payload_length=500
        let event_data =
            MOQTSubgroupObjectCreatedData(MOQTSubgroupObjectCreated {
                stream_id: 6,
                object_id_delta: 1,
                extension_headers: None,
                object_payload_length: 500,
                object_status: None,
                object_payload: None,
            });
        events.push(Event::Qlog(qlog::events::Event::with_time(4.0, event_data)));

        events
    }

    #[test]
    fn test_moqt_stream_id_filter() {
        let events = moqt_events();
        assert_eq!(events.len(), 5);

        let filter = "any(stream_id[*]==5)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 2);
    }

    #[test]
    fn test_moqt_group_id_filter() {
        let events = moqt_events();
        assert_eq!(events.len(), 5);

        let filter = "any(moqt.group_id[*]==2)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 1);

        match &filtered_events[0] {
            Event::Qlog(event) => match &event.data {
                MOQTObjectDatagramCreatedData(v) => {
                    assert_eq!(v.group_id, 2);
                    assert_eq!(v.object_id, Some(20));
                },
                _ => panic!("unexpected event data"),
            },
            Event::Json(_) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_moqt_object_id_filter() {
        let events = moqt_events();
        assert_eq!(events.len(), 5);

        let filter = "any(moqt.object_id[*]==10)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 1);

        match &filtered_events[0] {
            Event::Qlog(event) => match &event.data {
                MOQTObjectDatagramCreatedData(v) => {
                    assert_eq!(v.group_id, 1);
                    assert_eq!(v.object_id, Some(10));
                },
                _ => panic!("unexpected event data"),
            },
            Event::Json(_) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_moqt_object_payload_length_filter() {
        let events = moqt_events();
        assert_eq!(events.len(), 5);

        let filter = "any(moqt.object_payload_length[*]==1000)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert_eq!(filtered_events.len(), 1);

        match &filtered_events[0] {
            Event::Qlog(event) => match &event.data {
                MOQTSubgroupObjectCreatedData(v) => {
                    assert_eq!(v.stream_id, 5);
                    assert_eq!(v.object_payload_length, 1000);
                },
                _ => panic!("unexpected event data"),
            },
            Event::Json(_) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_moqt_filter_no_match() {
        let events = moqt_events();
        assert_eq!(events.len(), 5);

        let filter = "any(moqt.group_id[*]==999)";
        let filtered_events = filter_sqlog_events(events, filter);
        assert!(filtered_events.is_empty());
    }
}
