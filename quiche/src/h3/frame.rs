// Copyright (C) 2019, Cloudflare, Inc.
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

use super::Result;

#[cfg(feature = "qlog")]
use qlog::events::h3::Http3Frame;

pub const DATA_FRAME_TYPE_ID: u64 = 0x0;
pub const HEADERS_FRAME_TYPE_ID: u64 = 0x1;
pub const CANCEL_PUSH_FRAME_TYPE_ID: u64 = 0x3;
pub const SETTINGS_FRAME_TYPE_ID: u64 = 0x4;
pub const PUSH_PROMISE_FRAME_TYPE_ID: u64 = 0x5;
pub const GOAWAY_FRAME_TYPE_ID: u64 = 0x6;
pub const MAX_PUSH_FRAME_TYPE_ID: u64 = 0xD;
pub const PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID: u64 = 0xF0700;
pub const PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID: u64 = 0xF0701;

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
pub const SETTINGS_H3_DATAGRAM: u64 = 0x276;

// Permit between 16 maximally-encoded and 128 minimally-encoded SETTINGS.
const MAX_SETTINGS_PAYLOAD_SIZE: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        payload: Vec<u8>,
    },

    Headers {
        header_block: Vec<u8>,
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        connect_protocol_enabled: Option<u64>,
        h3_datagram: Option<u64>,
        grease: Option<(u64, u64)>,
        raw: Option<Vec<(u64, u64)>>,
    },

    PushPromise {
        push_id: u64,
        header_block: Vec<u8>,
    },

    GoAway {
        id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    PriorityUpdateRequest {
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    },

    PriorityUpdatePush {
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    },

    Unknown {
        raw_type: u64,
        payload_length: u64,
    },
}

impl Frame {
    pub fn from_bytes(
        frame_type: u64, payload_length: u64, bytes: &[u8],
    ) -> Result<Frame> {
        let mut b = octets::Octets::with_slice(bytes);

        // TODO: handling of 0-length frames
        let frame = match frame_type {
            DATA_FRAME_TYPE_ID => Frame::Data {
                payload: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            HEADERS_FRAME_TYPE_ID => Frame::Headers {
                header_block: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            CANCEL_PUSH_FRAME_TYPE_ID => Frame::CancelPush {
                push_id: b.get_varint()?,
            },

            SETTINGS_FRAME_TYPE_ID =>
                parse_settings_frame(&mut b, payload_length as usize)?,

            PUSH_PROMISE_FRAME_TYPE_ID =>
                parse_push_promise(payload_length, &mut b)?,

            GOAWAY_FRAME_TYPE_ID => Frame::GoAway {
                id: b.get_varint()?,
            },

            MAX_PUSH_FRAME_TYPE_ID => Frame::MaxPushId {
                push_id: b.get_varint()?,
            },

            PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID |
            PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID =>
                parse_priority_update(frame_type, payload_length, &mut b)?,

            _ => Frame::Unknown {
                raw_type: frame_type,
                payload_length,
            },
        };

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<usize> {
        let before = b.cap();

        match self {
            Frame::Data { payload } => {
                b.put_varint(DATA_FRAME_TYPE_ID)?;
                b.put_varint(payload.len() as u64)?;

                b.put_bytes(payload.as_ref())?;
            },

            Frame::Headers { header_block } => {
                b.put_varint(HEADERS_FRAME_TYPE_ID)?;
                b.put_varint(header_block.len() as u64)?;

                b.put_bytes(header_block.as_ref())?;
            },

            Frame::CancelPush { push_id } => {
                b.put_varint(CANCEL_PUSH_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*push_id) as u64)?;

                b.put_varint(*push_id)?;
            },

            Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                h3_datagram,
                grease,
                ..
            } => {
                let mut len = 0;

                if let Some(val) = max_field_section_size {
                    len += octets::varint_len(SETTINGS_MAX_FIELD_SECTION_SIZE);
                    len += octets::varint_len(*val);
                }

                if let Some(val) = qpack_max_table_capacity {
                    len += octets::varint_len(SETTINGS_QPACK_MAX_TABLE_CAPACITY);
                    len += octets::varint_len(*val);
                }

                if let Some(val) = qpack_blocked_streams {
                    len += octets::varint_len(SETTINGS_QPACK_BLOCKED_STREAMS);
                    len += octets::varint_len(*val);
                }

                if let Some(val) = connect_protocol_enabled {
                    len += octets::varint_len(SETTINGS_ENABLE_CONNECT_PROTOCOL);
                    len += octets::varint_len(*val);
                }

                if let Some(val) = h3_datagram {
                    len += octets::varint_len(SETTINGS_H3_DATAGRAM);
                    len += octets::varint_len(*val);
                }

                if let Some(val) = grease {
                    len += octets::varint_len(val.0);
                    len += octets::varint_len(val.1);
                }

                b.put_varint(SETTINGS_FRAME_TYPE_ID)?;
                b.put_varint(len as u64)?;

                if let Some(val) = max_field_section_size {
                    b.put_varint(SETTINGS_MAX_FIELD_SECTION_SIZE)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = qpack_max_table_capacity {
                    b.put_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = qpack_blocked_streams {
                    b.put_varint(SETTINGS_QPACK_BLOCKED_STREAMS)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = connect_protocol_enabled {
                    b.put_varint(SETTINGS_ENABLE_CONNECT_PROTOCOL)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = h3_datagram {
                    b.put_varint(SETTINGS_H3_DATAGRAM)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = grease {
                    b.put_varint(val.0)?;
                    b.put_varint(val.1)?;
                }
            },

            Frame::PushPromise {
                push_id,
                header_block,
            } => {
                let len = octets::varint_len(*push_id) + header_block.len();
                b.put_varint(PUSH_PROMISE_FRAME_TYPE_ID)?;
                b.put_varint(len as u64)?;

                b.put_varint(*push_id)?;
                b.put_bytes(header_block.as_ref())?;
            },

            Frame::GoAway { id } => {
                b.put_varint(GOAWAY_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*id) as u64)?;

                b.put_varint(*id)?;
            },

            Frame::MaxPushId { push_id } => {
                b.put_varint(MAX_PUSH_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*push_id) as u64)?;

                b.put_varint(*push_id)?;
            },

            Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                let len = octets::varint_len(*prioritized_element_id) +
                    priority_field_value.len();

                b.put_varint(PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID)?;
                b.put_varint(len as u64)?;

                b.put_varint(*prioritized_element_id as u64)?;
                b.put_bytes(priority_field_value)?;
            },

            Frame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                let len = octets::varint_len(*prioritized_element_id) +
                    priority_field_value.len();

                b.put_varint(PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID)?;
                b.put_varint(len as u64)?;

                b.put_varint(*prioritized_element_id as u64)?;
                b.put_bytes(priority_field_value)?;
            },

            Frame::Unknown { .. } => unreachable!(),
        }

        Ok(before - b.cap())
    }

    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self) -> Http3Frame {
        match self {
            Frame::Data { .. } => Http3Frame::Data { raw: None },

            // Qlog expects the `headers` to be represented as an array of
            // name:value pairs. At this stage, we only have the qpack block, so
            // populate the field with an empty vec.
            Frame::Headers { .. } => Http3Frame::Headers { headers: vec![] },

            Frame::CancelPush { push_id } =>
                Http3Frame::CancelPush { push_id: *push_id },

            Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                h3_datagram,
                grease,
                ..
            } => {
                let mut settings = vec![];

                if let Some(v) = max_field_section_size {
                    settings.push(qlog::events::h3::Setting {
                        name: "MAX_FIELD_SECTION_SIZE".to_string(),
                        value: *v,
                    });
                }

                if let Some(v) = qpack_max_table_capacity {
                    settings.push(qlog::events::h3::Setting {
                        name: "QPACK_MAX_TABLE_CAPACITY".to_string(),
                        value: *v,
                    });
                }

                if let Some(v) = qpack_blocked_streams {
                    settings.push(qlog::events::h3::Setting {
                        name: "QPACK_BLOCKED_STREAMS".to_string(),
                        value: *v,
                    });
                }

                if let Some(v) = connect_protocol_enabled {
                    settings.push(qlog::events::h3::Setting {
                        name: "SETTINGS_ENABLE_CONNECT_PROTOCOL".to_string(),
                        value: *v,
                    });
                }

                if let Some(v) = h3_datagram {
                    settings.push(qlog::events::h3::Setting {
                        name: "H3_DATAGRAM".to_string(),
                        value: *v,
                    });
                }

                if let Some((k, v)) = grease {
                    settings.push(qlog::events::h3::Setting {
                        name: k.to_string(),
                        value: *v,
                    });
                }

                qlog::events::h3::Http3Frame::Settings { settings }
            },

            // Qlog expects the `headers` to be represented as an array of
            // name:value pairs. At this stage, we only have the qpack block, so
            // populate the field with an empty vec.
            Frame::PushPromise { push_id, .. } => Http3Frame::PushPromise {
                push_id: *push_id,
                headers: vec![],
            },

            Frame::GoAway { id } => Http3Frame::Goaway { id: *id },

            Frame::MaxPushId { push_id } =>
                Http3Frame::MaxPushId { push_id: *push_id },

            Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => Http3Frame::PriorityUpdate {
                target_stream_type:
                    qlog::events::h3::H3PriorityTargetStreamType::Request,
                prioritized_element_id: *prioritized_element_id,
                priority_field_value: String::from_utf8_lossy(
                    priority_field_value,
                )
                .into_owned(),
            },

            Frame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => Http3Frame::PriorityUpdate {
                target_stream_type:
                    qlog::events::h3::H3PriorityTargetStreamType::Request,
                prioritized_element_id: *prioritized_element_id,
                priority_field_value: String::from_utf8_lossy(
                    priority_field_value,
                )
                .into_owned(),
            },

            Frame::Unknown {
                raw_type,
                payload_length,
            } => Http3Frame::Unknown {
                raw_frame_type: *raw_type,
                raw_length: Some(*payload_length as u32),
                raw: None,
            },
        }
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Data { .. } => {
                write!(f, "DATA")?;
            },

            Frame::Headers { .. } => {
                write!(f, "HEADERS")?;
            },

            Frame::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push_id={}", push_id)?;
            },

            Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                raw,
                ..
            } => {
                write!(f, "SETTINGS max_field_section={:?}, qpack_max_table={:?}, qpack_blocked={:?} raw={:?}", max_field_section_size, qpack_max_table_capacity, qpack_blocked_streams, raw)?;
            },

            Frame::PushPromise {
                push_id,
                header_block,
            } => {
                write!(
                    f,
                    "PUSH_PROMISE push_id={} len={}",
                    push_id,
                    header_block.len()
                )?;
            },

            Frame::GoAway { id } => {
                write!(f, "GOAWAY id={}", id)?;
            },

            Frame::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID push_id={}", push_id)?;
            },

            Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                write!(
                    f,
                    "PRIORITY_UPDATE request_stream_id={}, priority_field_len={}",
                    prioritized_element_id,
                    priority_field_value.len()
                )?;
            },

            Frame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                write!(
                    f,
                    "PRIORITY_UPDATE push_id={}, priority_field_len={}",
                    prioritized_element_id,
                    priority_field_value.len()
                )?;
            },

            Frame::Unknown { raw_type, .. } => {
                write!(f, "UNKNOWN raw_type={}", raw_type,)?;
            },
        }

        Ok(())
    }
}

fn parse_settings_frame(
    b: &mut octets::Octets, settings_length: usize,
) -> Result<Frame> {
    let mut max_field_section_size = None;
    let mut qpack_max_table_capacity = None;
    let mut qpack_blocked_streams = None;
    let mut connect_protocol_enabled = None;
    let mut h3_datagram = None;
    let mut raw = Vec::new();

    // Reject SETTINGS frames that are too long.
    if settings_length > MAX_SETTINGS_PAYLOAD_SIZE {
        return Err(super::Error::ExcessiveLoad);
    }

    while b.off() < settings_length {
        let identifier = b.get_varint()?;
        let value = b.get_varint()?;

        // MAX_SETTINGS_PAYLOAD_SIZE protects us from storing too many raw
        // settings.
        raw.push((identifier, value));

        match identifier {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                qpack_max_table_capacity = Some(value);
            },

            SETTINGS_MAX_FIELD_SECTION_SIZE => {
                max_field_section_size = Some(value);
            },

            SETTINGS_QPACK_BLOCKED_STREAMS => {
                qpack_blocked_streams = Some(value);
            },

            SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                if value > 1 {
                    return Err(super::Error::SettingsError);
                }

                connect_protocol_enabled = Some(value);
            },

            SETTINGS_H3_DATAGRAM => {
                if value > 1 {
                    return Err(super::Error::SettingsError);
                }

                h3_datagram = Some(value);
            },

            // Reserved values overlap with HTTP/2 and MUST be rejected
            0x0 | 0x2 | 0x3 | 0x4 | 0x5 =>
                return Err(super::Error::SettingsError),

            // Unknown Settings parameters must be ignored.
            _ => (),
        }
    }

    Ok(Frame::Settings {
        max_field_section_size,
        qpack_max_table_capacity,
        qpack_blocked_streams,
        connect_protocol_enabled,
        h3_datagram,
        grease: None,
        raw: Some(raw),
    })
}

fn parse_push_promise(
    payload_length: u64, b: &mut octets::Octets,
) -> Result<Frame> {
    let push_id = b.get_varint()?;
    let header_block_length = payload_length - octets::varint_len(push_id) as u64;
    let header_block = b.get_bytes(header_block_length as usize)?.to_vec();

    Ok(Frame::PushPromise {
        push_id,
        header_block,
    })
}

fn parse_priority_update(
    frame_type: u64, payload_length: u64, b: &mut octets::Octets,
) -> Result<Frame> {
    let prioritized_element_id = b.get_varint()?;
    let priority_field_value_length =
        payload_length - octets::varint_len(prioritized_element_id) as u64;
    let priority_field_value =
        b.get_bytes(priority_field_value_length as usize)?.to_vec();

    match frame_type {
        PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID =>
            Ok(Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            }),

        PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID => Ok(Frame::PriorityUpdatePush {
            prioritized_element_id,
            priority_field_value,
        }),

        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data() {
        let mut d = [42; 128];

        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let frame_payload_len = payload.len();
        let frame_header_len = 2;

        let frame = Frame::Data { payload };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                DATA_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn headers() {
        let mut d = [42; 128];

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let frame_payload_len = header_block.len();
        let frame_header_len = 2;

        let frame = Frame::Headers { header_block };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                HEADERS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn cancel_push() {
        let mut d = [42; 128];

        let frame = Frame::CancelPush { push_id: 0 };

        let frame_payload_len = 1;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                CANCEL_PUSH_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_all_no_grease() {
        let mut d = [42; 128];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
            (SETTINGS_H3_DATAGRAM, 0),
        ];

        let frame = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(0),
            h3_datagram: Some(0),
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 11;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_all_grease() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(0),
            h3_datagram: Some(0),
            grease: Some((33, 33)),
            raw: Default::default(),
        };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
            (SETTINGS_H3_DATAGRAM, 0),
            (33, 33),
        ];

        // Frame parsing will not populate GREASE property but will be in the
        // raw info.
        let frame_parsed = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(0),
            h3_datagram: Some(0),
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 13;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame_parsed
        );
    }

    #[test]
    fn settings_h3_only() {
        let mut d = [42; 128];

        let raw_settings = vec![(SETTINGS_MAX_FIELD_SECTION_SIZE, 1024)];

        let frame = Frame::Settings {
            max_field_section_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 3;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_h3_connect_protocol_enabled() {
        let mut d = [42; 128];

        let raw_settings = vec![(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: Some(1),
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_h3_connect_protocol_enabled_bad() {
        let mut d = [42; 128];

        let raw_settings = vec![(SETTINGS_ENABLE_CONNECT_PROTOCOL, 9)];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: Some(9),
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );
    }

    #[test]
    fn settings_h3_dgram_only() {
        let mut d = [42; 128];

        let raw_settings = vec![(SETTINGS_H3_DATAGRAM, 1)];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: Some(1),
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 3;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_h3_dgram_bad() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: Some(5),
            grease: None,
            raw: Default::default(),
        };

        let frame_payload_len = 3;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );
    }

    #[test]
    fn settings_qpack_only() {
        let mut d = [42; 128];

        let raw_settings = vec![
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let frame_payload_len = 4;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_h2_prohibited() {
        // We need to test the prohibited values (0x0 | 0x2 | 0x3 | 0x4 | 0x5)
        // but the quiche API doesn't support that, so use a manually created
        // frame data buffer where d[frame_header_len] is the SETTING type field.
        let frame_payload_len = 2u64;
        let frame_header_len = 2;
        let mut d = [
            SETTINGS_FRAME_TYPE_ID as u8,
            frame_payload_len as u8,
            0x0,
            1,
        ];

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );

        d[frame_header_len] = 0x2;

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );

        d[frame_header_len] = 0x3;

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );

        d[frame_header_len] = 0x4;

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );

        d[frame_header_len] = 0x5;

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::SettingsError)
        );
    }

    #[test]
    fn settings_too_big() {
        // We need to test a SETTINGS frame that exceeds
        // MAX_SETTINGS_PAYLOAD_SIZE, so just craft a special buffer that look
        // likes the frame. The payload content doesn't matter since quiche
        // should abort before then.
        let frame_payload_len = MAX_SETTINGS_PAYLOAD_SIZE + 1;
        let frame_header_len = 2;
        let d = [
            SETTINGS_FRAME_TYPE_ID as u8,
            frame_payload_len as u8,
            0x1,
            1,
        ];

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            ),
            Err(crate::h3::Error::ExcessiveLoad)
        );
    }

    #[test]
    fn push_promise() {
        let mut d = [42; 128];

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let frame_payload_len = 1 + header_block.len();
        let frame_header_len = 2;

        let frame = Frame::PushPromise {
            push_id: 0,
            header_block,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PUSH_PROMISE_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn goaway() {
        let mut d = [42; 128];

        let frame = Frame::GoAway { id: 32 };

        let frame_payload_len = 1;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                GOAWAY_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn max_push_id() {
        let mut d = [42; 128];

        let frame = Frame::MaxPushId { push_id: 128 };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                MAX_PUSH_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn priority_update_request() {
        let mut d = [42; 128];

        let prioritized_element_id = 4;
        let priority_field_value = b"abcdefghijklm".to_vec();
        let frame_payload_len = 1 + priority_field_value.len();
        let frame_header_len = 5;

        let frame = Frame::PriorityUpdateRequest {
            prioritized_element_id,
            priority_field_value,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn priority_update_push() {
        let mut d = [42; 128];

        let prioritized_element_id = 6;
        let priority_field_value = b"abcdefghijklm".to_vec();
        let frame_payload_len = 1 + priority_field_value.len();
        let frame_header_len = 5;

        let frame = Frame::PriorityUpdatePush {
            prioritized_element_id,
            priority_field_value,
        };

        let wire_len = {
            let mut b = octets::OctetsMut::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
                frame_payload_len as u64,
                &d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn unknown_type() {
        let d = [42; 12];

        assert_eq!(
            Frame::from_bytes(255, 12345, &d[..]),
            Ok(Frame::Unknown {
                raw_type: 255,
                payload_length: 12345
            })
        );
    }
}
