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

use std::mem;

use super::Error;
use super::Result;

use crate::octets;

pub const DATA_FRAME_TYPE_ID: u8 = 0x0;
pub const HEADERS_FRAME_TYPE_ID: u8 = 0x1;
pub const _PRIORITY_FRAME_TYPE_ID: u8 = 0x2;
pub const CANCEL_PUSH_FRAME_TYPE_ID: u8 = 0x3;
pub const SETTINGS_FRAME_TYPE_ID: u8 = 0x4;
pub const PUSH_PROMISE_FRAME_TYPE_ID: u8 = 0x5;
pub const GOAWAY_FRAME_TYPE_ID: u8 = 0x6;
pub const MAX_PUSH_FRAME_TYPE_ID: u8 = 0xD;
pub const DUPLICATE_PUSH_FRAME_TYPE_ID: u8 = 0xE;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u16 = 0x1;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u16 = 0x7;
const SETTINGS_NUM_PLACEHOLDERS: u16 = 0x8;

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
        num_placeholders: Option<u64>,
        max_header_list_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
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

    DuplicatePush {
        push_id: u64,
    },
}

impl Frame {
    pub fn from_bytes(
        frame_type: u8, payload_length: u64, bytes: &mut [u8],
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

            DUPLICATE_PUSH_FRAME_TYPE_ID => Frame::DuplicatePush {
                push_id: b.get_varint()?,
            },

            _ => return Err(Error::Done),
        };

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::Octets) -> Result<usize> {
        let before = b.cap();

        match self {
            Frame::Data { payload } => {
                b.put_varint(payload.len() as u64)?;
                b.put_u8(DATA_FRAME_TYPE_ID)?;

                b.put_bytes(payload.as_ref())?;
            },

            Frame::Headers { header_block } => {
                b.put_varint(header_block.len() as u64)?;
                b.put_u8(HEADERS_FRAME_TYPE_ID)?;

                b.put_bytes(header_block.as_ref())?;
            },

            Frame::CancelPush { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_u8(CANCEL_PUSH_FRAME_TYPE_ID)?;

                b.put_varint(*push_id)?;
            },

            Frame::Settings {
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            } => {
                let mut len = 0;

                if let Some(val) = num_placeholders {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                if let Some(val) = max_header_list_size {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                if let Some(val) = qpack_max_table_capacity {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                if let Some(val) = qpack_blocked_streams {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                b.put_varint(len as u64)?;
                b.put_u8(SETTINGS_FRAME_TYPE_ID)?;

                if let Some(val) = num_placeholders {
                    b.put_u16(0x8)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = max_header_list_size {
                    b.put_u16(0x6)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = qpack_max_table_capacity {
                    b.put_u16(0x1)?;
                    b.put_varint(*val as u64)?;
                }

                if let Some(val) = qpack_blocked_streams {
                    b.put_u16(0x7)?;
                    b.put_varint(*val as u64)?;
                }
            },

            Frame::PushPromise {
                push_id,
                header_block,
            } => {
                let len = octets::varint_len(*push_id) + header_block.len();
                b.put_varint(len as u64)?;
                b.put_u8(PUSH_PROMISE_FRAME_TYPE_ID)?;

                b.put_varint(*push_id)?;
                b.put_bytes(header_block.as_ref())?;
            },

            Frame::GoAway { stream_id } => {
                b.put_varint(octets::varint_len(*stream_id) as u64)?;
                b.put_u8(GOAWAY_FRAME_TYPE_ID)?;

                b.put_varint(*stream_id)?;
            },

            Frame::MaxPushId { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_u8(MAX_PUSH_FRAME_TYPE_ID)?;

                b.put_varint(*push_id)?;
            },

            Frame::DuplicatePush { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_u8(DUPLICATE_PUSH_FRAME_TYPE_ID)?;

                b.put_varint(*push_id)?;
            },
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
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            } => {
                write!(f, "SETTINGS placeholders={:?}, max_headers={:?}, qpack_max_table={:?}, qpack_blocked={:?} ", num_placeholders, max_header_list_size, qpack_max_table_capacity, qpack_blocked_streams)?;
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

            Frame::DuplicatePush { push_id } => {
                write!(f, "DUPLICATE_PUSH push_id={}", push_id)?;
            },
        }

        Ok(())
    }
}

fn parse_settings_frame(
    b: &mut octets::Octets, settings_length: usize,
) -> Result<Frame> {
    let mut num_placeholders = None;
    let mut max_header_list_size = None;
    let mut qpack_max_table_capacity = None;
    let mut qpack_blocked_streams = None;

    while b.off() < settings_length {
        let setting = b.get_u16()?;

        match setting {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                qpack_max_table_capacity = Some(b.get_varint()?);
            },

            SETTINGS_MAX_HEADER_LIST_SIZE => {
                max_header_list_size = Some(b.get_varint()?);
            },

            SETTINGS_QPACK_BLOCKED_STREAMS => {
                qpack_blocked_streams = Some(b.get_varint()?);
            },

            SETTINGS_NUM_PLACEHOLDERS => {
                num_placeholders = Some(b.get_varint()?);
            },

            // Unknown Settings parameters must be ignored.
            _ => (),
        }
    }

    Ok(Frame::Settings {
        num_placeholders,
        max_header_list_size,
        qpack_max_table_capacity,
        qpack_blocked_streams,
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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                DATA_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                HEADERS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                CANCEL_PUSH_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_all() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        };

        let frame_payload_len = 12;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_h3_only() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: Some(16),
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        };

        let frame_payload_len = 7;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn settings_qpack_only() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: None,
            max_header_list_size: None,
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        };

        let frame_payload_len = 6;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PUSH_PROMISE_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                GOAWAY_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                MAX_PUSH_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn duplicate_push() {
        let mut d = [42; 128];

        let frame = Frame::DuplicatePush { push_id: 0 };

        let frame_payload_len = 1;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                DUPLICATE_PUSH_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn unknown_type() {
        let mut d = [42; 12];

        assert_eq!(Frame::from_bytes(255, 12345, &mut d[..]), Err(Error::Done));
    }
}
