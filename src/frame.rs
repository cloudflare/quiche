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

use ::Result;
use ::Error;

use octets;
use stream;

#[derive(PartialEq, Debug)]
pub enum Frame {
    Padding,

    ConnectionClose {
        error_code: u16,
        frame_type: u64,
        reason: Vec<u8>,
    },

    ApplicationClose {
        error_code: u16,
        reason: Vec<u8>,
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
        largest_ack: u64,
        ack_delay: u64,
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
            0x00 => Frame::Padding,

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

            0x07 => Frame::Ping,

            0x0b => {
                Frame::NewConnectionId {
                    seq_num: b.get_varint()?,
                    conn_id: b.get_bytes_with_u8_length()?.to_vec(),
                    reset_token: b.get_bytes(16)?.to_vec(),
                }
            }

            0x0d => {
                Frame::RetireConnectionId {
                    seq_num: b.get_varint()?,
                }
            }

            0x1a => parse_ack_frame(frame_type, b)?,

            0x18 => {
                let offset = b.get_varint()?;
                let data = b.get_bytes_with_varint_length()?;

                Frame::Crypto {
                    data: stream::RangeBuf::from(data.as_ref(),
                                                 offset as usize,
                                                 false),
                }
            }

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
            Frame::Padding => {
                b.put_varint(0x00)?;

                ()
            },

            Frame::ConnectionClose { error_code, frame_type, reason } => {
                b.put_varint(0x02)?;

                b.put_u16(*error_code)?;
                b.put_varint(*frame_type)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;

                ()
            },

            Frame::ApplicationClose { error_code, reason } => {
                b.put_varint(0x03)?;

                b.put_u16(*error_code)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;

                ()
            },

            Frame::Ping => {
                b.put_varint(0x07)?;

                ()
            },

            Frame::NewConnectionId { seq_num, conn_id, reset_token } => {
                b.put_varint(0x0b)?;

                b.put_varint(*seq_num)?;
                b.put_u8(conn_id.len() as u8)?;
                b.put_bytes(conn_id.as_ref())?;
                b.put_bytes(reset_token.as_ref())?;

                ()
            },

            Frame::RetireConnectionId { seq_num } => {
                b.put_varint(0x0d)?;

                b.put_varint(*seq_num)?;

                ()
            },

            Frame::ACK { largest_ack, ack_delay } => {
                b.put_varint(0x1a)?;

                b.put_varint(*largest_ack)?;
                b.put_varint(*ack_delay)?;
                b.put_varint(0)?;
                b.put_varint(0)?;

                ()
            },

            Frame::Crypto { data } => {
                b.put_varint(0x18)?;

                b.put_varint(data.off() as u64)?;
                b.put_varint(data.len() as u64)?;
                b.put_bytes(&data)?;

                ()
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

                ()
            }
        }

        Ok(before - b.cap())
    }

    pub fn wire_len(&self) -> usize {
        match self {
            Frame::Padding => 1, // type

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

            Frame::ACK { largest_ack, ack_delay } => {
                1 +                                // frame type
                octets::varint_len(*largest_ack) + // largest_ack
                octets::varint_len(*ack_delay) +   // ack_delay
                1 +                                // block_count
                1                                  // first_block
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

fn parse_ack_frame(_ty: u64, b: &mut octets::Bytes) -> Result<Frame> {
    let largest_ack = b.get_varint()?;
    let ack_delay = b.get_varint()?;
    let block_count = b.get_varint()?;
    let _first_block = b.get_varint()?;

    // TODO: properly store ACK blocks
    for _i in 0..block_count {
        let _gap = b.get_varint()?;
        let _ack = b.get_varint()?;
    }

    Ok(Frame::ACK {
        largest_ack,
        ack_delay,
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

        let frame = Frame::Padding;

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 1);
        assert_eq!(&d[..wire_len], [0 as u8]);

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
            frame_type: 523423,
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
            seq_num: 123213,
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
            seq_num: 123213,
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

        let frame = Frame::ACK {
            largest_ack: 2163721632,
            ack_delay: 874656534
        };

        let wire_len = {
            let mut b = octets::Bytes::new(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 15);

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
