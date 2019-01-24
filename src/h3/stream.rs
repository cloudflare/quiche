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

use std::collections::VecDeque;

use crate::octets;

use super::frame::Frame;
use super::Error;
use super::Result;

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u8 = 0x43;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u8 = 0x50;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u8 = 0x48;
pub const QPACK_DECODER_STREAM_TYPE_ID: u8 = 0x68;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type {
    Control,
    Request,
    Push,
    QpackEncoder,
    QpackDecoder,
    // Grease, // TODO: enable GREASE streams
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    StreamTypeLen,
    StreamType,
    FrameTypeLen,
    FrameType,
    FramePayloadLenLen,
    FramePayloadLen,
    FramePayload,
    PushIdLen,
    PushId,
    QpackInstruction,
    Invalid,
}

impl Type {
    // TODO: draft 18+ with require true varints
    pub fn deserialize(v: u8) -> Option<Type> {
        match v {
            HTTP3_CONTROL_STREAM_TYPE_ID => Some(Type::Control),
            HTTP3_PUSH_STREAM_TYPE_ID => Some(Type::Push),
            QPACK_ENCODER_STREAM_TYPE_ID => Some(Type::QpackEncoder),
            QPACK_DECODER_STREAM_TYPE_ID => Some(Type::QpackDecoder),
            // TODO: parse grease stream
            _ => {
                trace!("Stream type value {:x} is unknown", v);
                None
            },
        }
    }
}

/// An HTTP/3 Stream
#[derive(Debug)]
pub struct Stream {
    id: u64,
    ty: Option<Type>,
    is_local: bool,
    initialised: bool,
    ty_len: u8,
    state: State,
    stream_offset: u64,
    buf: Vec<u8>,
    buf_read_off: u64,
    buf_end_pos: u64,
    next_varint_len: usize,
    frame_payload_len: u64,
    frame_type: Option<u8>,
    frames: VecDeque<Frame>,
}

impl Stream {
    pub fn new(id: u64, is_local: bool) -> Stream {
        let mut ty = None;
        let mut initialised = false;
        let mut state = State::StreamTypeLen;

        if crate::stream::is_bidi(id) {
            ty = Some(Type::Request);
            initialised = true;
            // TODO draft 18+ will mean first state is not FramePayloadLenLen
            state = State::FramePayloadLenLen;
        };

        trace!(
            "Stream id {} is new and is starting in {:?} state",
            id,
            state
        );

        Stream {
            id,
            ty,
            is_local,
            initialised,
            ty_len: 0,
            state,
            stream_offset: 0,
            buf: Vec::new(), /* TODO: need a more elegant
                              * approach to buffer management */
            buf_read_off: 0,
            buf_end_pos: 0,
            next_varint_len: 0,
            frame_payload_len: 0,
            frame_type: None,
            frames: VecDeque::new(),
        }
    }

    pub fn state(&mut self) -> &State {
        &self.state
    }

    pub fn get_frame(&mut self) -> Option<Frame> {
        self.frames.pop_front()
    }

    pub fn buf_bytes(&mut self, size: usize) -> Result<&mut [u8]> {
        // check there are enough meaningful bytes to read

        let desired_end_index = self.buf_read_off as usize + size;
        if desired_end_index < self.buf_end_pos as usize + 1 {
            return Ok(
                &mut self.buf[self.buf_read_off as usize..desired_end_index]
            );
        }

        trace!("Tried to read {} bytes but we don't have that many.", size);
        Err(Error::BufferTooShort)
    }

    // TODO: this function needs improvement (e.g. avoid copies)
    pub fn add_data(&mut self, d: &mut Vec<u8>) -> Result<()> {
        // TODO: use of unstable library feature 'try_reserve': new API (see issue
        // #48043) self.buf.try_reserve(d.len())?;
        trace!(
            "Stream id {}: adding {} bytes of data buffer",
            self.id,
            d.len()
        );
        self.buf_end_pos += d.len() as u64;
        self.buf.append(d);

        Ok(())
    }

    pub fn set_stream_type_len(&mut self, len: u8) -> Result<()> {
        if self.state == State::StreamTypeLen {
            self.ty_len = len;
            self.do_state_transition(State::StreamType);
            return Ok(());
        }

        Err(Error::InternalError)
    }

    pub fn set_stream_type(&mut self, ty: Option<Type>) -> Result<()> {
        if self.state == State::StreamType {
            self.ty = ty;
            self.stream_offset += u64::from(self.ty_len);
            self.buf_read_off += u64::from(self.ty_len);

            match ty {
                Some(Type::Request) => {
                    // TODO: draft18+ will not start in FramePayloadLenLen
                    self.do_state_transition(State::FramePayloadLenLen);
                },
                Some(Type::Control) => {
                    // TODO: draft18+ will not start in FramePayloadLenLen
                    self.do_state_transition(State::FramePayloadLenLen);
                },
                Some(Type::Push) => {
                    self.do_state_transition(State::PushIdLen);
                },
                Some(Type::QpackEncoder) | Some(Type::QpackDecoder) => {
                    self.do_state_transition(State::QpackInstruction);
                    self.initialised = true;
                },
                // TODO: enable GREASE streams
                // Some(Type::Grease) => {
                // self.state = State::Done;
                // },
                None => {
                    self.do_state_transition(State::Invalid);
                },
            };

            return Ok(());
        }

        Err(Error::InternalError)
    }

    pub fn set_next_varint_len(&mut self, len: usize) -> Result<()> {
        self.next_varint_len = len;

        match self.state {
            State::FramePayloadLenLen =>
                self.do_state_transition(State::FramePayloadLen),
            State::FrameTypeLen => self.do_state_transition(State::FrameType),
            State::PushIdLen => self.do_state_transition(State::PushId),
            _ => { /*TODO*/ },
        }

        Ok(())
    }

    pub fn get_varint(&mut self) -> Result<(u64)> {
        if self.buf.len() - self.buf_read_off as usize >=
            self.next_varint_len as usize
        {
            let n = self.buf_read_off as usize + self.next_varint_len;
            let varint = octets::Octets::with_slice(
                &mut self.buf[self.buf_read_off as usize..n],
            )
            .get_varint()?;

            self.stream_offset += self.next_varint_len as u64;
            self.buf_read_off += self.next_varint_len as u64;

            return Ok(varint);
        }

        Err(Error::Done)
    }

    // TODO: we probably don't need this in draft 18+
    pub fn get_u8(&mut self) -> Result<(u8)> {
        let ret = self.buf_bytes(1)?[0];

        self.stream_offset += 1;
        self.buf_read_off += 1;

        Ok(ret)
    }

    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        // Only expect frames on Control, Request and Push streams
        if self.ty == Some(Type::Control) ||
            self.ty == Some(Type::Request) ||
            self.ty == Some(Type::Push)
        {
            self.frame_payload_len = len;
            self.do_state_transition(State::FrameTypeLen);

            return Ok(());
        }

        Err(Error::UnexpectedFrame)
    }

    fn do_state_transition(&mut self, s: State) {
        self.state = s;

        trace!(
            "Stream id {} transitioned to {:?} state",
            self.id,
            self.state
        );
    }

    pub fn set_frame_type(&mut self, ty: u8) -> Result<()> {
        // Only expect frames on Control, Request and Push streams

        match self.ty {
            Some(Type::Control) => {
                // Control stream starts uninitialised and only SETTINGS is
                // accepted in that state. Other frames cause an
                // error. Once initialised, no more SETTINGS are
                // permitted.
                if !self.initialised {
                    match ty {
                        super::frame::SETTINGS_FRAME_TYPE_ID => {
                            self.frame_type = Some(ty);
                            self.do_state_transition(State::FramePayload);

                            self.initialised = true;
                        },
                        _ => {
                            trace!("Stream {} not intialised and attempt to process a {:?} was made, this is an error.", self.id, ty);
                            return Err(Error::MissingSettings);
                        },
                    }
                } else {
                    match ty {
                        super::frame::SETTINGS_FRAME_TYPE_ID => {
                            trace!("Stream {} was intialised and attempt to process  {:?} was made, this is an error.", self.id, ty);
                            return Err(Error::UnexpectedFrame);
                        },
                        _ => {
                            self.frame_type = Some(ty);
                            self.do_state_transition(State::FramePayload);
                        },
                    }
                }
            },
            Some(Type::Request) => {
                match ty {
                    super::frame::HEADERS_FRAME_TYPE_ID |
                    super::frame::DATA_FRAME_TYPE_ID |
                    super::frame::PRIORITY_FRAME_TYPE_ID |
                    super::frame::PUSH_PROMISE_FRAME_TYPE_ID => {
                        self.frame_type = Some(ty);
                        self.do_state_transition(State::FramePayload);
                    },
                    _ => {
                        error!(
                            "Unexpected frame type {} on request stream {}",
                            ty, self.id
                        );
                        return Err(Error::UnexpectedFrame);
                    },
                }
                self.frame_type = Some(ty);
            },
            Some(Type::Push) => {
                self.frame_type = Some(ty);
                // TODO: draft18+
                self.do_state_transition(State::FramePayloadLenLen);
            },
            _ => {
                error!("Unexpected frame type {} on stream {}", ty, self.id);
                return Err(Error::UnexpectedFrame);
            },
        }

        Ok(())
    }

    pub fn parse_frame(&mut self) -> Result<()> {
        // Now we want to parse the whole frame payload but only if
        // there is enough data in our stream buffer.
        // stream.buf_bytes() should return an error if we don't have
        // enuough.
        let frame = Frame::from_bytes(
            self.frame_type.unwrap(),
            self.frame_payload_len,
            self.buf_bytes(self.frame_payload_len as usize)?,
        )?;

        debug!("Parse {:?} on stream ID {}", frame, self.id);

        // TODO: bytes in the buffer are no longer needed, so we can remove them
        // and set the offset back to 0?
        self.buf_read_off += self.frame_payload_len;

        // Stream offset always increases, so we can track how many total bytes
        // was seen by the application layer
        self.stream_offset += self.frame_payload_len;

        // TODO: draft18+ will not got back to FramePayloadLenLen
        self.do_state_transition(State::FramePayloadLenLen);

        self.frames.push_back(frame);
        Ok(())
    }

    pub fn more(&self) -> bool {
        let rem_bytes = self.buf_end_pos - self.buf_read_off; //- 1;
        trace!(
            "Stream id {}: {} bytes remaining in buffer",
            self.id,
            rem_bytes
        );
        rem_bytes > 0
    }
}
