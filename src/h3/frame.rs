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

use super::Error;
use super::Result;

use crate::octets;

pub const DATA_FRAME_TYPE_ID: u64 = 0x0;
pub const HEADERS_FRAME_TYPE_ID: u64 = 0x1;
pub const PRIORITY_FRAME_TYPE_ID: u64 = 0x2;
pub const CANCEL_PUSH_FRAME_TYPE_ID: u64 = 0x3;
pub const SETTINGS_FRAME_TYPE_ID: u64 = 0x4;
pub const PUSH_PROMISE_FRAME_TYPE_ID: u64 = 0x5;
pub const GOAWAY_FRAME_TYPE_ID: u64 = 0x6;
pub const MAX_PUSH_FRAME_TYPE_ID: u64 = 0xD;
pub const DUPLICATE_PUSH_FRAME_TYPE_ID: u64 = 0xE;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_HEADER_LIST_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
const SETTINGS_NUM_PLACEHOLDERS: u64 = 0x9;

const ELEM_DEPENDENCY_TYPE_MASK: u8 = 0x30;

/// HTTP/3 Prioritized Element type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrioritizedElemType {
    RequestStream,
    PushStream,
    Placeholder,
    CurrentStream,
}

impl PrioritizedElemType {
    fn is_peid_absent(self) -> bool {
        match self {
            PrioritizedElemType::CurrentStream => true,
            _ => false,
        }
    }

    fn to_bits(self) -> Result<u8> {
        match self {
            PrioritizedElemType::RequestStream => Ok(0x00),

            PrioritizedElemType::PushStream => Ok(0x01),

            PrioritizedElemType::Placeholder => Ok(0x02),

            PrioritizedElemType::CurrentStream => Ok(0x03),
        }
    }

    fn from_bits(bits: u8) -> Result<PrioritizedElemType> {
        match bits {
            0x00 => Ok(PrioritizedElemType::RequestStream),

            0x01 => Ok(PrioritizedElemType::PushStream),

            0x02 => Ok(PrioritizedElemType::Placeholder),

            0x03 => Ok(PrioritizedElemType::CurrentStream),

            _ => Err(Error::InternalError),
        }
    }
}

/// HTTP/3 Element Dependency type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ElemDependencyType {
    RequestStream,
    PushStream,
    Placeholder,
    RootOfTree,
}

impl ElemDependencyType {
    fn is_edid_absent(self) -> bool {
        match self {
            ElemDependencyType::RootOfTree => true,
            _ => false,
        }
    }

    fn to_bits(self) -> Result<u8> {
        match self {
            ElemDependencyType::RequestStream => Ok(0x00),

            ElemDependencyType::PushStream => Ok(0x01),

            ElemDependencyType::Placeholder => Ok(0x02),

            ElemDependencyType::RootOfTree => Ok(0x03),
        }
    }

    fn from_bits(bits: u8) -> Result<ElemDependencyType> {
        match bits {
            0x00 => Ok(ElemDependencyType::RequestStream),

            0x01 => Ok(ElemDependencyType::PushStream),

            0x02 => Ok(ElemDependencyType::Placeholder),

            0x03 => Ok(ElemDependencyType::RootOfTree),

            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum Frame {
    Data {
        payload: Vec<u8>,
    },

    Headers {
        header_block: Vec<u8>,
    },

    Priority {
        priority_elem: PrioritizedElemType,
        elem_dependency: ElemDependencyType,
        prioritized_element_id: Option<u64>,
        element_dependency_id: Option<u64>,
        weight: u8,
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        num_placeholders: Option<u64>,
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

    DuplicatePush {
        push_id: u64,
    },
}

impl Frame {
    pub fn from_bytes(
        frame_type: u64, payload_length: u64, bytes: &mut [u8],
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

            PRIORITY_FRAME_TYPE_ID => parse_priority_frame(&mut b)?,

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
                b.put_varint(DATA_FRAME_TYPE_ID)?;
                b.put_varint(payload.len() as u64)?;

                b.put_bytes(payload.as_ref())?;
            },

            Frame::Headers { header_block } => {
                b.put_varint(HEADERS_FRAME_TYPE_ID)?;
                b.put_varint(header_block.len() as u64)?;

                b.put_bytes(header_block.as_ref())?;
            },

            Frame::Priority {
                priority_elem,
                elem_dependency,
                prioritized_element_id,
                element_dependency_id,
                weight,
            } => {
                b.put_varint(PRIORITY_FRAME_TYPE_ID)?;

                let mut length = 2; // 2 u8s = (PT+DT+Empty) + Weight
                if let Some(peid) = prioritized_element_id {
                    length += octets::varint_len(*peid);
                }

                if let Some(edid) = element_dependency_id {
                    length += octets::varint_len(*edid);
                }

                b.put_varint(length as u64)?;

                let mut bitfield = priority_elem.to_bits()? << 6;
                bitfield |= elem_dependency.to_bits()? << 4;

                b.put_u8(bitfield)?;

                if let Some(peid) = prioritized_element_id {
                    b.put_varint(*peid)?;
                }

                if let Some(edid) = element_dependency_id {
                    b.put_varint(*edid)?;
                }

                b.put_u8(*weight)?;
            },

            Frame::CancelPush { push_id } => {
                b.put_varint(CANCEL_PUSH_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*push_id) as u64)?;

                b.put_varint(*push_id)?;
            },

            Frame::Settings {
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                grease,
            } => {
                let mut len = 0;

                if let Some(val) = num_placeholders {
                    len += octets::varint_len(SETTINGS_NUM_PLACEHOLDERS);
                    len += octets::varint_len(*val);
                }

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

                if let Some(val) = num_placeholders {
                    b.put_varint(SETTINGS_NUM_PLACEHOLDERS)?;
                    b.put_varint(*val as u64)?;
                }

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

            Frame::DuplicatePush { push_id } => {
                b.put_varint(DUPLICATE_PUSH_FRAME_TYPE_ID)?;
                b.put_varint(octets::varint_len(*push_id) as u64)?;

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

            Frame::Priority {
                priority_elem,
                elem_dependency,
                prioritized_element_id,
                element_dependency_id,
                weight,
            } => {
                write!(f, "PRIORITY pri_type={:?} dep_type={:?} pri_id={:?} dep_id={:?} weight={:?}", priority_elem, elem_dependency, prioritized_element_id, element_dependency_id, weight)?;
            },

            Frame::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push_id={}", push_id)?;
            },

            Frame::Settings {
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                ..
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

            SETTINGS_NUM_PLACEHOLDERS => {
                num_placeholders = Some(settings_val);
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

fn parse_priority_frame(b: &mut octets::Octets) -> Result<Frame> {
    let bitfield = b.get_u8()?;
    let mut prioritized_element_id = None;
    let mut element_dependency_id = None;

    let priority_elem = PrioritizedElemType::from_bits(bitfield >> 6)?;

    let elem_dependency = ElemDependencyType::from_bits(
        (bitfield & ELEM_DEPENDENCY_TYPE_MASK) >> 4,
    )?;

    if !priority_elem.is_peid_absent() {
        prioritized_element_id = Some(b.get_varint()?);
    }

    if !elem_dependency.is_edid_absent() {
        element_dependency_id = Some(b.get_varint()?);
    }

    Ok(Frame::Priority {
        priority_elem,
        elem_dependency,
        prioritized_element_id,
        element_dependency_id,
        weight: b.get_u8()?,
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
    fn data_zero_length() {
        let mut d = [42; 128];

        let payload = vec![];
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
    fn settings_all_no_grease() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        let frame_payload_len = 8;
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
    fn settings_all_grease() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: Some((33, 33)),
        };

        // Frame parsing will always ignore GREASE values.
        let frame_parsed = Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        let frame_payload_len = 10;
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
            frame_parsed
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
            grease: None,
        };

        let frame_payload_len = 5;
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
            grease: None,
        };

        let frame_payload_len = 4;
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
    fn priority_current_stream_to_root() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::CurrentStream,
            elem_dependency: ElemDependencyType::RootOfTree,
            prioritized_element_id: None,
            element_dependency_id: None,
            weight: 16,
        };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PRIORITY_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn priority_placeholder_to_root() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::Placeholder,
            elem_dependency: ElemDependencyType::RootOfTree,
            prioritized_element_id: Some(0),
            element_dependency_id: None,
            weight: 16,
        };

        let frame_payload_len = 3;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PRIORITY_FRAME_TYPE_ID,
                frame_payload_len as u64,
                &mut d[frame_header_len..]
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn priority_current_stream_to_placeholder() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::CurrentStream,
            elem_dependency: ElemDependencyType::Placeholder,
            prioritized_element_id: None,
            element_dependency_id: Some(0),
            weight: 16,
        };

        let frame_payload_len = 3;
        let frame_header_len = 2;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, frame_header_len + frame_payload_len);

        assert_eq!(
            Frame::from_bytes(
                PRIORITY_FRAME_TYPE_ID,
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
