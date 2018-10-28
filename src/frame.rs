// Copyright (c) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

use std::fmt;

use ::Result;
use ::Error;

use octets;
use ranges;
use stream;

pub const MAX_CRYPTO_OVERHEAD: usize = 8;
pub const MAX_STREAM_OVERHEAD: usize = 12;

#[derive(PartialEq)]
pub enum Frame {
    Padding {
        len: usize,
    },

    ConnectionClose {
        error_code: u16,
        frame_type: u64,
        reason: Vec<u8>,
    },

    ApplicationClose {
        error_code: u16,
        reason: Vec<u8>,
    },

    MaxData {
        max: u64,
    },

    MaxStreamData {
        stream_id: u64,
        max: u64,
    },

    MaxStreamId {
        max: u64,
    },

    Ping,

    NewConnectionId {
        seq_num: u64,
        conn_id: Vec<u8>,
        reset_token: Vec<u8>,
    },

    RetireConnectionId {
        seq_num: u64,
    },

    ACK {
        ack_delay: u64,
        ranges: ranges::RangeSet,
    },

    NewToken {
        token: Vec<u8>,
    },

    Crypto {
        data: stream::RangeBuf,
    },

    Stream {
        stream_id: u64,
        data: stream::RangeBuf,
    },
}

impl Frame {
    pub fn from_bytes(b: &mut octets::Bytes) -> Result<Frame> {
        let frame_type = b.get_varint()?;

        // println!("GOT FRAME {:x}", frame_type);

        let frame = match frame_type {
            0x00 => {
                let mut len = 1;

                while b.peek_u8() == Ok(0x00) {
                    b.get_u8()?;

                    len += 1;
                }

                Frame::Padding {
                    len,
                }
            },

            0x02 => {
                Frame::ConnectionClose {
                    error_code: b.get_u16()?,
                    frame_type: b.get_varint()?,
                    reason: b.get_bytes_with_varint_length()?.to_vec(),
                }
            },

            0x03 => {
                Frame::ApplicationClose {
                    error_code: b.get_u16()?,
                    reason: b.get_bytes_with_varint_length()?.to_vec(),
                }
            },

            0x04 => {
                Frame::MaxData {
                    max: b.get_varint()?,
                }
            },

            0x05 => {
                Frame::MaxStreamData {
                    stream_id: b.get_varint()?,
                    max: b.get_varint()?,
                }
            },

            0x06 => {
                Frame::MaxStreamId {
                    max: b.get_varint()?,
                }
            },

            0x07 => Frame::Ping,

            0x0b => {
                Frame::NewConnectionId {
                    seq_num: b.get_varint()?,
                    conn_id: b.get_bytes_with_u8_length()?.to_vec(),
                    reset_token: b.get_bytes(16)?.to_vec(),
                }
            },

            0x0d => {
                Frame::RetireConnectionId {
                    seq_num: b.get_varint()?,
                }
            },

            0x1a => parse_ack_frame(frame_type, b)?,

            0x18 => {
                let offset = b.get_varint()?;
                let data = b.get_bytes_with_varint_length()?;

                Frame::Crypto {
                    data: stream::RangeBuf::from(data.as_ref(),
                                                 offset as usize,
                                                 false),
                }
            },

            0x19 => {
                Frame::NewToken {
                    token: b.get_bytes_with_varint_length()?.to_vec(),
                }
            },

            0x10 => parse_stream_frame(frame_type, b)?,
            0x11 => parse_stream_frame(frame_type, b)?,
            0x12 => parse_stream_frame(frame_type, b)?,
            0x13 => parse_stream_frame(frame_type, b)?,
            0x14 => parse_stream_frame(frame_type, b)?,
            0x15 => parse_stream_frame(frame_type, b)?,
            0x16 => parse_stream_frame(frame_type, b)?,
            0x17 => parse_stream_frame(frame_type, b)?,

            _    => return Err(Error::UnknownFrame),
        };

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::Bytes) -> Result<usize> {
        let before = b.cap();

        match self {
            Frame::Padding { len } => {
                let mut left = *len;

                while left > 0 {
                    b.put_varint(0x00)?;

                    left -= 1;
                }
            },

            Frame::ConnectionClose { error_code, frame_type, reason } => {
                b.put_varint(0x02)?;

                b.put_u16(*error_code)?;
                b.put_varint(*frame_type)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                b.put_varint(0x03)?;

                b.put_u16(*error_code)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::MaxData { max } => {
                b.put_varint(0x04)?;

                b.put_varint(*max)?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                b.put_varint(0x05)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*max)?;
            },

            Frame::MaxStreamId { max } => {
                b.put_varint(0x06)?;

                b.put_varint(*max)?;
            },

            Frame::Ping => {
                b.put_varint(0x07)?;
            },

            Frame::NewConnectionId { seq_num, conn_id, reset_token } => {
                b.put_varint(0x0b)?;

                b.put_varint(*seq_num)?;
                b.put_u8(conn_id.len() as u8)?;
                b.put_bytes(conn_id.as_ref())?;
                b.put_bytes(reset_token.as_ref())?;
            },

            Frame::RetireConnectionId { seq_num } => {
                b.put_varint(0x0d)?;

                b.put_varint(*seq_num)?;
            },

            Frame::ACK { ack_delay, ranges } => {
                b.put_varint(0x1a)?;

                let mut it = ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                b.put_varint(first.end - 1)?;
                b.put_varint(*ack_delay)?;
                b.put_varint(it.len() as u64)?;
                b.put_varint(ack_block)?;

                let mut smallest_ack = first.start;

                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;

                    b.put_varint(gap)?;
                    b.put_varint(ack_block)?;

                    smallest_ack = block.start;
                }
            },

            Frame::NewToken { token } => {
                b.put_varint(0x19)?;

                b.put_varint(token.len() as u64)?;
                b.put_bytes(&token)?;
            },

            Frame::Crypto { data } => {
                b.put_varint(0x18)?;

                b.put_varint(data.off() as u64)?;
                b.put_varint(data.len() as u64)?;
                b.put_bytes(&data)?;
            }

            Frame::Stream { stream_id, data } => {
                let mut ty: u8 = 0x10;

                // Always encode offset
                ty |= 0x04;

                // Always encode length
                ty |= 0x02;

                if data.fin() {
                    ty |= 0x01;
                }

                b.put_varint(u64::from(ty))?;

                b.put_varint(*stream_id)?;
                b.put_varint(data.off() as u64)?;
                b.put_varint(data.len() as u64)?;
                b.put_bytes(data.as_ref())?;
            }
        }

        Ok(before - b.cap())
    }

    pub fn wire_len(&self) -> usize {
        match self {
            Frame::Padding { len } => {
                *len
            },

            Frame::ConnectionClose { frame_type, reason, .. } => {
                1 +                                // frame type
                2 +                                // error_code
                octets::varint_len(*frame_type) +  // frame_type
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len()                       // reason
            },

            Frame::ApplicationClose { reason, .. } => {
                1 +                                // frame type
                2 +                                // error_code
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len()                       // reason
            },

            Frame::MaxData { max } => {
                1 +                                // frame type
                octets::varint_len(*max)           // max
            },

            Frame::MaxStreamData { stream_id, max } => {
                1 +                                // frame type
                octets::varint_len(*stream_id) +   // stream_id
                octets::varint_len(*max)           // max
            },

            Frame::MaxStreamId { max } => {
                1 +                                // frame type
                octets::varint_len(*max)           // max
            },

            Frame::Ping => 1, // type

            Frame::NewConnectionId { seq_num, conn_id, reset_token } => {
                1 +                                // frame type
                octets::varint_len(*seq_num) +     // seq_num
                1 +                                // conn_id length
                conn_id.len() +                    // conn_id
                reset_token.len()                  // reset_token
            },

            Frame::RetireConnectionId { seq_num } => {
                1 +                                // frame type
                octets::varint_len(*seq_num)       // seq_num
            },

            Frame::ACK { ack_delay, ranges } => {
                let mut it = ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                let mut len =
                    1 +                                   // frame type
                    octets::varint_len(first.end - 1) +   // largest_ack
                    octets::varint_len(*ack_delay) +      // ack_delay
                    octets::varint_len(it.len() as u64) + // block_count
                    octets::varint_len(ack_block);        // first_block

                let mut smallest_ack = first.start;

                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;

                    len += octets::varint_len(gap as u64) + // gap
                           octets::varint_len(ack_block);   // ack_block

                    smallest_ack = block.start;
                }

                len
            },

            Frame::NewToken { token } =>  {
                1 +                              // frame type
                octets::varint_len(token.len() as u64) + // token length
                token.len()                      // token
            },

            Frame::Crypto { data } => {
                1 +                              // frame type
                octets::varint_len(data.off() as u64) + // offset
                octets::varint_len(data.len() as u64) + // length
                data.len()                       // data
            },

            Frame::Stream { stream_id, data } => {
                1 +                              // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(data.off() as u64) + // offset
                octets::varint_len(data.len() as u64) + // length
                data.len()                       // data
            },
        }
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Frame::Padding { len } => {
                write!(f, "PADDING len={}", len)?;
            },

            Frame::ConnectionClose { error_code, frame_type, reason } => {
                write!(f, "CONNECTION_CLOSE err={:x} frame={:x} reason={:x?}",
                       error_code, frame_type, reason)?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                write!(f, "APPLICATION_CLOSE err={:x} reason={:x?}",
                       error_code, reason)?;
            },

            Frame::MaxData { max } => {
                write!(f, "MAX_DATA max={}", max)?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                write!(f, "MAX_STREAM_DATA stream={} max={}", stream_id, max)?;
            },

            Frame::MaxStreamId { max } => {
                write!(f, "MAX_STREAM_ID max={}", max)?;
            },

            Frame::Ping => {
                write!(f, "PING")?;
            },

            Frame::NewConnectionId { .. } => {
                write!(f, "NEW_CONNECTION_ID (TODO)")?;
            },

            Frame::RetireConnectionId { .. } => {
                write!(f, "RETIRE_CONNECTION_ID (TODO)")?;
            },

            Frame::ACK { ack_delay, ranges } => {
                write!(f, "ACK delay={} blocks={:?}", ack_delay, ranges)?;
            },

            Frame::NewToken { .. } => {
                write!(f, "NEW_TOKEN (TODO)")?;
            },

            Frame::Crypto { data } => {
                write!(f, "CRYPTO off={} len={}", data.off(), data.len())?;
            },

            Frame::Stream { stream_id, data } => {
                write!(f, "STREAM id={} off={} len={} fin={}",
                       stream_id, data.off(), data.len(), data.fin())?;
            },
        }

        Ok(())
    }
}

fn parse_ack_frame(_ty: u64, b: &mut octets::Bytes) -> Result<Frame> {
    let largest_ack = b.get_varint()?;
    let ack_delay = b.get_varint()?;
    let block_count = b.get_varint()?;
    let ack_block = b.get_varint()?;

    let mut smallest_ack = largest_ack - ack_block;

    let mut ranges = ranges::RangeSet::default();
    ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..block_count {
        let gap = b.get_varint()?;
        let largest_ack = (smallest_ack - gap) - 2;
        let ack_block = b.get_varint()?;

        smallest_ack = largest_ack - ack_block;
        ranges.insert(smallest_ack..largest_ack + 1);
    }

    Ok(Frame::ACK {
        ack_delay,
        ranges,
    })
}

fn parse_stream_frame(ty: u64, b: &mut octets::Bytes) -> Result<Frame> {
    let first = ty as u8;

    let stream_id = b.get_varint()?;

    let offset = if first & 0x04 != 0 {
        b.get_varint()?
    } else {
        0
    };

    let len = if first & 0x02 != 0 {
        b.get_varint()? as usize
    } else {
        b.cap()
    };

    let fin = first & 0x01 != 0;

    let data = b.get_bytes(len)?;

    Ok(Frame::Stream {
        stream_id,
        data: stream::RangeBuf::from(data.as_ref(), offset as usize, fin),
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::Padding {
            len: 128,
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 128);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn connection_close() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::ConnectionClose {
            error_code: 0xbeef,
            frame_type: 523_423,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 20);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn application_close() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::ApplicationClose {
            error_code: 0xbeef,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 16);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn max_data() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::MaxData {
            max: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn max_stream_data() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::MaxStreamData {
            stream_id: 12_321,
            max: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn max_stream_id() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::MaxStreamId {
            max: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn ping() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::Ping;

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 1);
        assert_eq!(&d[..wire_len], [0x07 as u8]);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn new_connection_id() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::NewConnectionId {
            seq_num: 123_213,
            conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            reset_token: vec![0x42; 16],
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 37);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn retire_connection_id() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::RetireConnectionId {
            seq_num: 123_213,
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn ack() {
        let mut d: [u8; 128] = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let frame = Frame::ACK {
            ack_delay: 874_656_534,
            ranges,
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn new_token() {
        let mut d: [u8; 128] = [42; 128];

        let frame = Frame::NewToken {
            token: Vec::from("this is a token"),
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn crypto() {
        let mut d: [u8; 128] = [42; 128];

        let data: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Crypto {
            data: stream::RangeBuf::from(&data, 1230976, false),
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 18);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn stream() {
        let mut d: [u8; 128] = [42; 128];

        let data: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: stream::RangeBuf::from(&data, 1230976, true),
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 19);

        {
            let mut b = octets::Bytes::new(&mut d);
            assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }
}
