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

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u64 = 0x0;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u64 = 0x1;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u64 = 0x2;
pub const QPACK_DECODER_STREAM_TYPE_ID: u64 = 0x3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type {
    Control,
    Request,
    Push,
    QpackEncoder,
    QpackDecoder,
    Unknown,
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
    Done,
}

impl Type {
    pub fn deserialize(v: u64) -> Result<Type> {
        match v {
            HTTP3_CONTROL_STREAM_TYPE_ID => Ok(Type::Control),
            HTTP3_PUSH_STREAM_TYPE_ID => Ok(Type::Push),
            QPACK_ENCODER_STREAM_TYPE_ID => Ok(Type::QpackEncoder),
            QPACK_DECODER_STREAM_TYPE_ID => Ok(Type::QpackDecoder),

            _ => Ok(Type::Unknown),
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
    is_peer_fin: bool,
    state: State,
    stream_offset: u64,
    buf: Vec<u8>,
    buf_read_off: u64,
    buf_end_pos: u64,
    next_varint_len: usize,
    frame_payload_len: u64,
    frame_type: Option<u64>,
    frames: VecDeque<frame::Frame>,
}

impl Stream {
    pub fn new(id: u64, is_local: bool) -> Stream {
        let mut ty = None;
        let mut state = State::StreamTypeLen;

        if crate::stream::is_bidi(id) {
            ty = Some(Type::Request);
            state = State::FrameTypeLen;
        };

        Stream {
            id,
            ty,
            is_local,
            initialized: false,
            is_peer_fin: false,
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

    pub fn peer_fin(&self) -> bool {
        self.is_peer_fin
    }

    pub fn set_peer_fin(&mut self, fin: bool) {
        self.is_peer_fin = fin;
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

    pub fn set_ty(&mut self, ty: Type) -> Result<()> {
        if self.state != State::StreamType {
            return Err(Error::InternalError);
        }

        self.ty = Some(ty);

        match ty {
            Type::Request => self.state = State::FrameTypeLen,

            Type::Control => self.state = State::FrameTypeLen,

            Type::Push => self.state = State::PushIdLen,

            Type::QpackEncoder | Type::QpackDecoder => {
                self.state = State::QpackInstruction;
                self.initialized = true;
            },

            Type::Unknown => {
                self.state = State::Done;
            },
        }

        Ok(())
    }

    pub fn ty(&mut self) -> Option<Type> {
        self.ty
    }

    pub fn set_next_varint_len(&mut self, len: usize) -> Result<()> {
        match self.state {
            State::StreamTypeLen => self.state = State::StreamType,

            State::FramePayloadLenLen => self.state = State::FramePayloadLen,

            State::FrameTypeLen => self.state = State::FrameType,

            State::PushIdLen => self.state = State::PushId,

            State::PushId => self.state = State::FrameTypeLen,

            _ => return Err(Error::InternalError),
        }

        self.next_varint_len = len;

        Ok(())
    }

    pub fn get_varint(&mut self) -> Result<u64> {
        if self.next_varint_len == 0 {
            return Err(Error::Done);
        }

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

            // Reset next_varint_len so we avoid incorrect multiple calls.
            self.next_varint_len = 0;

            // If processing push, progress the state machine appropriately.
            if self.state == State::PushId {
                self.state = State::FrameTypeLen;
            }

            return Ok(varint);
        }

        Err(Error::Done)
    }

    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        if self.state != State::FramePayloadLen {
            return Err(Error::InternalError);
        }

        // Only expect frames on Control, Request and Push streams.
        if self.ty == Some(Type::Control) ||
            self.ty == Some(Type::Request) ||
            self.ty == Some(Type::Push)
        {
            self.frame_payload_len = len;
            self.state = State::FramePayload;

            return Ok(());
        }

        Err(Error::InternalError)
    }

    pub fn set_frame_type(&mut self, ty: u64) -> Result<()> {
        if self.state != State::FrameType {
            return Err(Error::InternalError);
        }

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

                    // Additional SETTINGS frame.
                    (frame::SETTINGS_FRAME_TYPE_ID, true) =>
                        return Err(Error::UnexpectedFrame),

                    // Frames that can never be received on control streams.
                    (frame::DATA_FRAME_TYPE_ID, _) =>
                        return Err(Error::WrongStream),

                    (frame::HEADERS_FRAME_TYPE_ID, _) =>
                        return Err(Error::WrongStream),

                    (frame::PUSH_PROMISE_FRAME_TYPE_ID, _) =>
                        return Err(Error::WrongStream),

                    (frame::DUPLICATE_PUSH_FRAME_TYPE_ID, _) =>
                        return Err(Error::WrongStream),

                    (_, false) => return Err(Error::MissingSettings),

                    (_, true) => (),
                }

                self.state = State::FramePayloadLenLen;
            },

            Some(Type::Request) => {
                // Request stream starts uninitialized and only HEADERS or
                // PRIORITY is accepted in that state. Other
                // frames cause an error. Once initialized, no
                // more PRIORITY frames are permitted.
                if !self.is_local {
                    match (ty, self.initialized) {
                        (frame::HEADERS_FRAME_TYPE_ID, false) =>
                            self.initialized = true,

                        (frame::PRIORITY_FRAME_TYPE_ID, false) =>
                            self.initialized = true,

                        // Additional PRIORITY frame is error.
                        (frame::PRIORITY_FRAME_TYPE_ID, true) =>
                            return Err(Error::UnexpectedFrame),

                        // Frames that can never be received on request streams.
                        (frame::CANCEL_PUSH_FRAME_TYPE_ID, _) =>
                            return Err(Error::WrongStream),

                        (frame::SETTINGS_FRAME_TYPE_ID, _) =>
                            return Err(Error::WrongStream),

                        (frame::GOAWAY_FRAME_TYPE_ID, _) =>
                            return Err(Error::WrongStream),

                        (frame::MAX_PUSH_FRAME_TYPE_ID, _) =>
                            return Err(Error::WrongStream),

                        // All other frames can be ignored regardless of stream
                        // state.
                        (_, false) => (),

                        (_, true) => (),
                    }
                }

                self.state = State::FramePayloadLenLen;
            },

            Some(Type::Push) => {
                match ty {
                    // Frames that can never be received on request streams.
                    frame::PRIORITY_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    frame::CANCEL_PUSH_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    frame::SETTINGS_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    frame::PUSH_PROMISE_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    frame::GOAWAY_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    frame::MAX_PUSH_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    frame::DUPLICATE_PUSH_FRAME_TYPE_ID =>
                        return Err(Error::WrongStream),

                    _ => (),
                }

                self.state = State::FramePayloadLenLen;
            },

            _ => return Err(Error::UnexpectedFrame),
        }

        self.frame_type = Some(ty);

        Ok(())
    }

    pub fn parse_frame(&mut self) -> Result<()> {
        // Parse the whole frame payload but only if there is enough data in
        // the stream buffer. stream.buf_bytes() returns an error if we don't
        // have enough.
        if self.frame_type.is_none() {
            return Err(Error::InternalError);
        }

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

        // Set state to parse next frame
        self.state = State::FrameTypeLen;

        Ok(())
    }

    pub fn more(&self) -> bool {
        let rem_bytes = self.buf_end_pos - self.buf_read_off;
        rem_bytes > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_good() {
        let mut stream = Stream::new(3, false);
        assert_eq!(*stream.state(), State::StreamTypeLen);

        let mut d = [42; 40];
        let mut b = octets::Octets::with_slice(&mut d);

        let frame = frame::Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // Parse stream type.
        assert_eq!(stream.more(), true);
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(stream_ty_len, 1);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        assert_eq!(*stream.state(), State::StreamType);

        let stream_ty = stream.get_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_CONTROL_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(*stream.state(), State::FrameTypeLen);

        // Parse the SETTINGS frame.
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);

        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::SETTINGS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 8);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(frame));

        assert_eq!(stream.more(), false);
    }

    #[test]
    fn control_bad_multiple_settings() {
        let mut stream = Stream::new(3, false);
        assert_eq!(*stream.state(), State::StreamTypeLen);

        let mut d = [42; 40];
        let mut b = octets::Octets::with_slice(&mut d);

        let frame = frame::Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();
        frame.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // Parse stream type.
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        let stream_ty = stream.get_varint().unwrap();
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();

        // Parse first SETTINGS frame.
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_ty_len).unwrap();

        let frame_ty = stream.get_varint().unwrap();
        stream.set_frame_type(frame_ty).unwrap();

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();

        let frame_payload_len = stream.get_varint().unwrap();
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.parse_frame(), Ok(()));
        stream.get_frame();

        assert_eq!(stream.more(), true);

        // Parse second SETTINGS frame.
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_ty_len).unwrap();

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::UnexpectedFrame));
    }

    #[test]
    fn control_bad_late_settings() {
        let mut stream = Stream::new(3, false);
        assert_eq!(*stream.state(), State::StreamTypeLen);

        let mut d = [42; 40];
        let mut b = octets::Octets::with_slice(&mut d);

        let goaway = frame::Frame::GoAway { stream_id: 0 };

        let settings = frame::Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        goaway.to_bytes(&mut b).unwrap();
        settings.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // Parse stream type.
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        let stream_ty = stream.get_varint().unwrap();
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();

        // Parse GOAWAY.
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_ty_len).unwrap();

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::MissingSettings));
    }

    #[test]
    fn control_bad_frame() {
        let mut stream = Stream::new(3, false);
        assert_eq!(*stream.state(), State::StreamTypeLen);

        let mut d = [42; 40];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };

        let settings = frame::Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        settings.to_bytes(&mut b).unwrap();
        hdrs.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // Parse stream type.
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        let stream_ty = stream.get_varint().unwrap();
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();

        // Parse first SETTINGS frame.
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_ty_len).unwrap();

        let frame_ty = stream.get_varint().unwrap();
        stream.set_frame_type(frame_ty).unwrap();

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();

        let frame_payload_len = stream.get_varint().unwrap();
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.parse_frame(), Ok(()));
        stream.get_frame();

        // Parse HEADERS.
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(frame_ty_len).unwrap();

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::WrongStream));
    }

    #[test]
    fn request_no_data() {
        let mut stream = Stream::new(0, false);

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.set_ty(Type::Request), Err(Error::InternalError));

        assert_eq!(stream.more(), false);
        assert_eq!(stream.get_varint(), Err(Error::Done));
        assert_eq!(stream.set_frame_payload_len(100), Err(Error::InternalError));
        assert_eq!(stream.get_frame(), None);
        assert_eq!(stream.parse_frame(), Err(Error::InternalError));

        assert_eq!(stream.set_frame_type(1), Err(Error::InternalError));
    }

    #[test]
    fn request_good() {
        let mut stream = Stream::new(0, false);

        let mut d = [42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data { payload };

        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // parse the HEADERS frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::HEADERS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 12);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(hdrs));

        // parse the DATA frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);

        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::DATA_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 12);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(data));

        assert_eq!(stream.more(), false);
    }

    #[test]
    fn priority_request_good() {
        let mut stream = Stream::new(0, false);

        let mut d = [42; 1280];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data { payload };

        // Create an approximate PRIORITY frame in the buffer
        b.put_varint(frame::PRIORITY_FRAME_TYPE_ID).unwrap();
        b.put_varint(2).unwrap(); // 2 u8s = Bitfield + Weight
        b.put_u8(0).unwrap(); // bitfield
        b.put_u8(16).unwrap(); // weight

        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // parse the PRIORITY frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::PRIORITY_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 2);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        // TODO: if/when PRIRORITY frame is fully implemented, test it
        // e.g. `assert_eq!(stream.get_frame(), Some(priority));`

        // parse the HEADERS frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::HEADERS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 12);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(hdrs));

        // parse the DATA frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);

        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::DATA_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 12);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(data));

        assert_eq!(stream.more(), false);
    }

    #[test]
    fn priority_control_good() {
        let mut stream = Stream::new(2, false);

        let mut d = [42; 1280];
        let mut b = octets::Octets::with_slice(&mut d);

        let settings = frame::Frame::Settings {
            num_placeholders: Some(0),
            max_header_list_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            grease: None,
        };

        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        settings.to_bytes(&mut b).unwrap();

        // Create an approximate PRIORITY frame in the buffer
        b.put_varint(frame::PRIORITY_FRAME_TYPE_ID).unwrap();
        b.put_varint(1 + octets::varint_parse_len(1) as u64 + 1)
            .unwrap(); // 2 u8s = Bitfield + varint + Weight
        b.put_u8(128).unwrap(); // bitfield
        b.put_varint(1).unwrap();
        b.put_u8(16).unwrap(); // weight

        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // Parse stream type.
        assert_eq!(stream.more(), true);
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(stream_ty_len, 1);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        assert_eq!(*stream.state(), State::StreamType);

        let stream_ty = stream.get_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_CONTROL_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(*stream.state(), State::FrameTypeLen);

        // Parse the SETTINGS frame.
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);

        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::SETTINGS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 8);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(settings));

        // parse the PRIORITY frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::PRIORITY_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 3);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        // TODO: if/when PRIRORITY frame is fully implemented, test it
        // e.g. `assert_eq!(stream.get_frame(), Some(priority));`

        assert_eq!(stream.more(), false);
    }

    #[test]
    fn push_good() {
        let mut stream = Stream::new(2, false);

        let mut d = [42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data { payload };

        b.put_varint(HTTP3_PUSH_STREAM_TYPE_ID).unwrap();
        b.put_varint(1).unwrap();
        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();
        let off = b.off();

        stream.push(&mut d[..off]).unwrap();

        // parse stream type
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        let stream_ty = stream.get_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_PUSH_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(*stream.state(), State::PushIdLen);

        // parse push ID
        let push_id_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        stream.set_next_varint_len(push_id_len).unwrap();
        assert_eq!(*stream.state(), State::PushId);
        let push_id = stream.get_varint().unwrap();
        assert_eq!(push_id, 1);

        // parse the HEADERS frame
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::HEADERS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_payload_len_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 12);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(hdrs));

        // parse the DATA frame
        assert_eq!(stream.more(), true);
        let frame_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_ty_len, 1);

        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FrameType);

        let frame_ty = stream.get_varint().unwrap();
        assert_eq!(frame_ty, frame::DATA_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLenLen);

        let frame_payload_len_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(frame_payload_len_len, 1);
        stream.set_next_varint_len(frame_ty_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayloadLen);

        let frame_payload_len = stream.get_varint().unwrap();
        assert_eq!(frame_payload_len, 12);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(*stream.state(), State::FramePayload);

        assert_eq!(stream.parse_frame(), Ok(()));
        assert_eq!(*stream.state(), State::FrameTypeLen);

        assert_eq!(stream.get_frame(), Some(data));

        assert_eq!(stream.more(), false);
    }

    #[test]
    fn grease() {
        let mut stream = Stream::new(2, false);

        let mut d = [42; 20];
        let mut b = octets::Octets::with_slice(&mut d);

        b.put_varint(33).unwrap();

        stream.push(&mut d).unwrap();

        // parse stream type
        assert_eq!(stream.more(), true);
        let stream_ty_len =
            octets::varint_parse_len(stream.buf_bytes(1).unwrap()[0]);
        assert_eq!(stream_ty_len, 1);
        stream.set_next_varint_len(stream_ty_len).unwrap();
        assert_eq!(*stream.state(), State::StreamType);

        let stream_ty = stream.get_varint().unwrap();
        assert_eq!(stream_ty, 33);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(*stream.state(), State::Done);
    }
}
