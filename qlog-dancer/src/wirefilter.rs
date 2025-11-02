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
            EventData::DataMoved(v) =>
                if let Some(id) = v.stream_id {
                    ids.push(id as i64);
                },
            EventData::PacketSent(v) => {
                if let Some(frames) = &v.frames {
                    for frame in frames {
                        match frame {
                            qlog::events::quic::QuicFrame::ResetStream { stream_id, .. } => ids.push(*stream_id as i64),
                            qlog::events::quic::QuicFrame::StopSending { stream_id , .. } => ids.push(*stream_id as i64),
                            qlog::events::quic::QuicFrame::Stream { stream_id, .. } => ids.push(*stream_id as i64),
                            qlog::events::quic::QuicFrame::MaxStreamData { stream_id, .. } => ids.push(*stream_id as i64),
                            qlog::events::quic::QuicFrame::StreamDataBlocked { stream_id, .. } => ids.push(*stream_id as i64),

                            // other frames are not related to streams
                            _ => (),
                        }
                    }
                }
            },
            EventData::H3StreamTypeSet(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::H3FrameCreated(v) => {
                ids.push(v.stream_id as i64);
            },
            EventData::H3FrameParsed(v) => {
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

pub fn filter_sqlog_events(mut events: Vec<Event>, filter: &str) -> Vec<Event> {
    let mut ret = vec![];

    let mut builder = Scheme! {
        category: Bytes,
        name: Bytes,
        stream_id: Array(Int),
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
    use qlog::events::quic::PacketHeader;
    use qlog::events::quic::PacketType::Initial;
    use qlog::events::quic::QuicFrame;
    use qlog::reader::Event;
    use smallvec::smallvec;

    use crate::wirefilter::filter_sqlog_events;

    fn stream_frame(stream_id: u64) -> QuicFrame {
        QuicFrame::Stream {
            stream_id,
            offset: 0,
            length: 10,
            fin: Some(true),
            raw: None,
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
            None,
            Some(1),
            Some(&scid),
            Some(&dcid),
        );
        let raw = qlog::events::RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        };

        let frames = vec![
            QuicFrame::Crypto {
                offset: 0,
                length: 0,
            },
            stream_frame(1),
            stream_frame(2),
            stream_frame(3),
            stream_frame(4),
            stream_frame(5),
        ];

        let event_data =
            qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
                header: pkt_hdr.clone(),
                frames: Some(frames.into()),
                is_coalesced: None,
                retry_token: None,
                stateless_reset_token: None,
                supported_versions: None,
                raw: Some(raw.clone()),
                datagram_id: None,
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

        let event_data =
            qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
                header: pkt_hdr.clone(),
                frames: Some(frames.into()),
                is_coalesced: None,
                retry_token: None,
                stateless_reset_token: None,
                supported_versions: None,
                raw: Some(raw.clone()),
                datagram_id: None,
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

        let event_data =
            qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
                header: pkt_hdr,
                frames: Some(frames.into()),
                is_coalesced: None,
                retry_token: None,
                stateless_reset_token: None,
                supported_versions: None,
                raw: Some(raw),
                datagram_id: None,
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
                    qlog::events::EventData::PacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(smallvec![
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
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    qlog::events::EventData::PacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(smallvec![
                                QuicFrame::Crypto {
                                    offset: 0,
                                    length: 0,
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
                    qlog::events::EventData::PacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(smallvec![
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

        let ev = &filtered_events[0];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    qlog::events::EventData::PacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(smallvec![
                                QuicFrame::Crypto {
                                    offset: 0,
                                    length: 0,
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
                    qlog::events::EventData::PacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(smallvec![
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
}
