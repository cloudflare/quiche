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

use super::Error;
use super::Result;

use crate::octets;

use super::frame;

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
    // TODO: enable GREASE streams
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
}

impl Type {
    pub fn deserialize(v: u8) -> Result<Type> {
        match v {
            HTTP3_CONTROL_STREAM_TYPE_ID => Ok(Type::Control),
            HTTP3_PUSH_STREAM_TYPE_ID => Ok(Type::Push),
            QPACK_ENCODER_STREAM_TYPE_ID => Ok(Type::QpackEncoder),
            QPACK_DECODER_STREAM_TYPE_ID => Ok(Type::QpackDecoder),

            // TODO: parse grease stream
            _ => Err(Error::UnknownStreamType),
        }
    }
}

/// An HTTP/3 Stream
#[derive(Debug)]
pub struct Stream {
    id: u64,
    ty: Option<Type>,
    is_local: bool,
    initialized: bool,
    ty_len: u8,
    state: State,
    stream_offset: u64,
    buf: Vec<u8>,
    buf_read_off: u64,
    buf_end_pos: u64,
    next_varint_len: usize,
    frame_payload_len: u64,
    frame_type: Option<u8>,
    frames: VecDeque<frame::Frame>,
}

impl Stream {
    pub fn new(id: u64, is_local: bool) -> Stream {
        let mut ty = None;
        let mut initialized = false;
        let mut state = State::StreamTypeLen;

        if crate::stream::is_bidi(id) {
            ty = Some(Type::Request);
            initialized = true;
            state = State::FramePayloadLenLen;
        };

        Stream {
            id,
            ty,
            is_local,
            initialized,
            ty_len: 0,
            state,
            stream_offset: 0,
            // TODO: need a more elegant approach to buffer management.
            buf: Vec::new(),
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

    pub fn get_frame(&mut self) -> Option<frame::Frame> {
        self.frames.pop_front()
    }

    pub fn buf_bytes(&mut self, size: usize) -> Result<&mut [u8]> {
        let desired_end_index = self.buf_read_off as usize + size;

        // Check there are enough meaningful bytes to read.
        if desired_end_index < self.buf_end_pos as usize + 1 {
            return Ok(
                &mut self.buf[self.buf_read_off as usize..desired_end_index]
            );
        }

        Err(Error::BufferTooShort)
    }

    // TODO: this function needs improvement (e.g. avoid copies)
    pub fn push(&mut self, d: &[u8]) -> Result<()> {
        self.buf_end_pos += d.len() as u64;
        self.buf.extend_from_slice(d);

        Ok(())
    }

    pub fn set_stream_type_len(&mut self, len: u8) -> Result<()> {
        if self.state != State::StreamTypeLen {
            return Err(Error::InternalError);
        }

        self.ty_len = len;
        self.state = State::StreamType;

        Ok(())
    }

    pub fn set_stream_type(&mut self, ty: Type) -> Result<()> {
        if self.state != State::StreamType {
            return Err(Error::InternalError);
        }

        self.ty = Some(ty);

        self.stream_offset += u64::from(self.ty_len);
        self.buf_read_off += u64::from(self.ty_len);

        match ty {
            Type::Request => self.state = State::FramePayloadLenLen,

            Type::Control => self.state = State::FramePayloadLenLen,

            Type::Push => self.state = State::PushIdLen,

            Type::QpackEncoder | Type::QpackDecoder => {
                self.state = State::QpackInstruction;
                self.initialized = true;
            },
        }

        Ok(())
    }

    pub fn set_next_varint_len(&mut self, len: usize) -> Result<()> {
        self.next_varint_len = len;

        match self.state {
            State::FramePayloadLenLen => self.state = State::FramePayloadLen,

            State::FrameTypeLen => self.state = State::FrameType,

            State::PushIdLen => self.state = State::PushId,

            _ => (),
        }

        Ok(())
    }

    pub fn get_varint(&mut self) -> Result<u64> {
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

    pub fn get_u8(&mut self) -> Result<(u8)> {
        let ret = self.buf_bytes(1)?[0];

        self.stream_offset += 1;
        self.buf_read_off += 1;

        Ok(ret)
    }

    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        // Only expect frames on Control, Request and Push streams.
        if self.ty == Some(Type::Control) ||
            self.ty == Some(Type::Request) ||
            self.ty == Some(Type::Push)
        {
            self.frame_payload_len = len;
            self.state = State::FrameTypeLen;

            return Ok(());
        }

        Err(Error::UnexpectedFrame)
    }

    pub fn set_frame_type(&mut self, ty: u8) -> Result<()> {
        // Only expect frames on Control, Request and Push streams.
        match self.ty {
            Some(Type::Control) => {
                // Control stream starts uninitialized and only SETTINGS is
                // accepted in that state. Other frames cause an error. Once
                // initialized, no more SETTINGS are permitted.
                match (ty, self.initialized) {
                    // Initialize control stream.
                    (frame::SETTINGS_FRAME_TYPE_ID, false) =>
                        self.initialized = true,

                    // Duplicate SETTINGS frame.
                    (frame::SETTINGS_FRAME_TYPE_ID, true) =>
                        return Err(Error::UnexpectedFrame),

                    (_, false) => return Err(Error::MissingSettings),

                    (_, true) => return Err(Error::UnexpectedFrame),
                }

                self.state = State::FramePayload;
            },

            Some(Type::Request) => self.state = State::FramePayload,

            Some(Type::Push) => self.state = State::FramePayloadLenLen,

            _ => return Err(Error::UnexpectedFrame),
        }

        self.frame_type = Some(ty);

        Ok(())
    }

    pub fn parse_frame(&mut self) -> Result<()> {
        // Parse the whole frame payload but only if there is enough data in
        // the stream buffer. stream.buf_bytes() returns an error if we don't
        // have enough.
        assert!(self.frame_type.is_some());

        if let Ok(frame) = frame::Frame::from_bytes(
            self.frame_type.unwrap(),
            self.frame_payload_len,
            self.buf_bytes(self.frame_payload_len as usize)?,
        ) {
            self.frames.push_back(frame);
        }

        // TODO: bytes in the buffer are no longer needed, so we can remove
        // them and set the offset back to 0?
        self.buf_read_off += self.frame_payload_len;

        // Stream offset always increases, so we can track how many total
        // bytes were seen by the application layer.
        self.stream_offset += self.frame_payload_len;

        self.state = State::FramePayloadLenLen;

        Ok(())
    }

    pub fn more(&self) -> bool {
        let rem_bytes = self.buf_end_pos - self.buf_read_off;
        rem_bytes > 0
    }
}
