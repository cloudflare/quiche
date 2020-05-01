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

use crate::octets;

pub const DATA_FRAME_TYPE_ID: u64 = 0x0;
pub const HEADERS_FRAME_TYPE_ID: u64 = 0x1;
pub const CANCEL_PUSH_FRAME_TYPE_ID: u64 = 0x3;
pub const SETTINGS_FRAME_TYPE_ID: u64 = 0x4;
pub const PUSH_PROMISE_FRAME_TYPE_ID: u64 = 0x5;
pub const GOAWAY_FRAME_TYPE_ID: u64 = 0x6;
pub const MAX_PUSH_FRAME_TYPE_ID: u64 = 0xD;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_HEADER_LIST_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;

#[derive(Clone, PartialEq)]
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
        max_header_list_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        grease: Option<(u64, u64)>,
    },

    PushPromise {
        push_id: u64,
        header_block: Vec<u8>,
    },

    GoAway {
        stream_id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    Unknown,
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
                stream_id: b.get_varint()?,
            },

            MAX_PUSH_FRAME_TYPE_ID => Frame::MaxPushId {
                push_id: b.get_varint()?,
            },

            _ => Frame::Unknown,
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
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                grease,
            } => {
                let mut len = 0;

                if let Some(val) = max_header_list_size {
                    len += octets::varint_len(SETTINGS_MAX_HEADER_LIST_SIZE);
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

                if let Some(val) = grease {
                    len += octets::varint_len(val.0);
                    len += octets::varint_len(val.1);
                }

                b.put_varint(SETTINGS_FRAME_TYPE_ID)?;
                b.put_varint(len as u64)?;

                if let Some(val) = max_header_list_size {
                    b.put_varint(SETTINGS_MAX_HEADER_LIST_SIZE)?;
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

            Frame::GoAway { stream_id } => {
                b.put_varint(GOAWAY_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*stream_id) as u64)?;

                b.put_varint(*stream_id)?;
            },

            Frame::MaxPushId { push_id } => {
                b.put_varint(MAX_PUSH_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*push_id) as u64)?;

                b.put_varint(*push_id)?;
            },

            Frame::Unknown => unreachable!(),
        }

        Ok(before - b.cap())
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Data { payload } => {
                write!(f, "DATA len={}", payload.len())?;
            },

            Frame::Headers { header_block } => {
                write!(f, "HEADERS len={}", header_block.len())?;
            },

            Frame::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push_id={}", push_id)?;
            },

            Frame::Settings {
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                ..
            } => {
                write!(f, "SETTINGS max_headers={:?}, qpack_max_table={:?}, qpack_blocked={:?} ", max_header_list_size, qpack_max_table_capacity, qpack_blocked_streams)?;
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

            Frame::GoAway { stream_id } => {
                write!(f, "GOAWAY stream_id={}", stream_id)?;
            },

            Frame::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID push_id={}", push_id)?;
            },

            Frame::Unknown => {
                write!(f, "UNKNOWN")?;
            },
        }

        Ok(())
    }
}

fn parse_settings_frame(
    b: &mut octets::Octets, settings_length: usize,
) -> Result<Frame> {
    let mut max_header_list_size = None;
    let mut qpack_max_table_capacity = None;
    let mut qpack_blocked_streams = None;

    while b.off() < settings_length {
        let setting_ty = b.get_varint()?;
        let settings_val = b.get_varint()?;

        match setting_ty {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                qpack_max_table_capacity = Some(settings_val);
            },

            SETTINGS_MAX_HEADER_LIST_SIZE => {
                max_header_list_size = Some(settings_val);
            },

            SETTINGS_QPACK_BLOCKED_STREAMS => {
                qpack_blocked_streams = Some(settings_val);
            },

            // Unknown Settings parameters must be ignored.
            _ => (),
        }
    }

    Ok(Frame::Settings {
        max_header_list_size,
        qpack_max_table_capacity,
        qpack_blocked_streams,
        grease: None,
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

        let frame = Frame::Settings {
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        let frame_payload_len = 6;
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
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: Some((33, 33)),
        };

        // Frame parsing will always ignore GREASE values.
        let frame_parsed = Frame::Settings {
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        let frame_payload_len = 8;
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

        let frame = Frame::Settings {
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            grease: None,
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
    fn settings_qpack_only() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            max_header_list_size: None,
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
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

        let frame = Frame::GoAway { stream_id: 32 };

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
    fn unknown_type() {
        let d = [42; 12];

        assert_eq!(Frame::from_bytes(255, 12345, &d[..]), Ok(Frame::Unknown));
    }
}
