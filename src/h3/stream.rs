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
    /// Reading the stream's type.
    StreamType,

    /// Reading the stream's current frame's type.
    FrameType,

    /// Reading the stream's current frame's payload length.
    FramePayloadLen,

    /// Reading the stream's current frame's payload.
    FramePayload,

    /// Reading DATA payload.
    Data,

    /// Reading the push ID.
    PushId,

    /// Reading a QPACK instruction.
    QpackInstruction,

    /// Reading and discarding data.
    Drain,
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

/// An HTTP/3 stream.
///
/// This maintains the HTTP/3 state for streams of any type (control, request,
/// QPACK, ...).
///
/// A number of bytes, depending on the current stream's state, is read from the
/// transport stream into the HTTP/3 stream's "state buffer". This intermediate
/// buffering is required due to the fact that data read from the transport
/// might not be complete (e.g. a varint might be split across multiple QUIC
/// packets).
///
/// When enough data to complete the current state has been buffered, it is
/// consumed from the state buffer and the stream is transitioned to the next
/// state (see `State` for a list of possible states).
#[derive(Debug)]
pub struct Stream {
    /// The corresponding transport stream's ID.
    id: u64,

    /// The stream's type (if known).
    ty: Option<Type>,

    /// The current stream state.
    state: State,

    /// The buffer holding partial data for the current state.
    state_buf: Vec<u8>,

    /// The expected amount of bytes required to complete the state.
    state_len: usize,

    /// The write offset in the state buffer, that is, how many bytes have
    /// already been read from the transport for the current state. When
    /// it reaches `stream_len` the state can be completed.
    state_off: usize,

    /// The type of the frame currently being parsed.
    frame_type: Option<u64>,

    /// List of frames that have already been parsed, but not yet processed.
    frames: VecDeque<frame::Frame>,

    /// Whether the stream was created locally, or by the peer.
    is_local: bool,

    /// Whether the stream has been initialized.
    initialized: bool,

    /// Whether the peer has finished sending data on this stream.
    is_peer_fin: bool,

    /// Whether we have DATA frame data buffered and ready to be read.
    has_incoming_data: bool,
}

impl Stream {
    /// Creates a new HTTP/3 stream.
    ///
    /// The `is_local` parameter indicates whether the stream was created by the
    /// local endpoint, or by the peer.
    pub fn new(id: u64, is_local: bool) -> Stream {
        let (ty, state) = if crate::stream::is_bidi(id) {
            // All bidirectional streams are "request" streams, so we don't
            // need to read the stream type.
            (Some(Type::Request), State::FrameType)
        } else {
            // The stream's type is yet to be determined.
            (None, State::StreamType)
        };

        Stream {
            id,
            ty,

            state,

            // Pre-allocate a buffer to avoid multiple tiny early allocations.
            state_buf: vec![0; 16],

            // Expect one byte for the initial state, to parse the initial
            // varint length.
            state_len: 1,
            state_off: 0,

            frame_type: None,
            frames: VecDeque::new(),

            is_local,
            initialized: false,
            is_peer_fin: false,
            has_incoming_data: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn ty(&self) -> Option<Type> {
        self.ty
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

    /// Sets the stream's type and transitions to the next state.
    pub fn set_ty(&mut self, ty: Type) -> Result<()> {
        assert_eq!(self.state, State::StreamType);

        self.ty = Some(ty);

        let state = match ty {
            Type::Control | Type::Request => State::FrameType,

            Type::Push => State::PushId,

            Type::QpackEncoder | Type::QpackDecoder => {
                self.initialized = true;

                State::QpackInstruction
            },

            Type::Unknown => State::Drain,
        };

        self.state_transition(state, 1, true);

        Ok(())
    }

    /// Sets the push ID and transitions to the next state.
    pub fn set_push_id(&mut self, _id: u64) -> Result<()> {
        assert_eq!(self.state, State::PushId);

        // TODO: implement push ID.

        self.state_transition(State::FrameType, 1, true);

        Ok(())
    }

    /// Sets the frame type and transitions to the next state.
    pub fn set_frame_type(&mut self, ty: u64) -> Result<()> {
        assert_eq!(self.state, State::FrameType);

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
            },

            Some(Type::Request) => {
                // Request stream starts uninitialized and only HEADERS
                // is accepted. Other frames cause an error.
                if !self.is_local {
                    match (ty, self.initialized) {
                        (frame::HEADERS_FRAME_TYPE_ID, false) =>
                            self.initialized = true,

                        // Frames that can never be received on request streams.
                        (frame::PRIORITY_FRAME_TYPE_ID, _) =>
                            return Err(Error::WrongStream),

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
            },

            _ => return Err(Error::UnexpectedFrame),
        }

        self.frame_type = Some(ty);

        self.state_transition(State::FramePayloadLen, 1, true);

        Ok(())
    }

    /// Sets the frame's payload length and transitions to the next state.
    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        assert_eq!(self.state, State::FramePayloadLen);

        // Only expect frames on Control, Request and Push streams.
        if self.ty == Some(Type::Control) ||
            self.ty == Some(Type::Request) ||
            self.ty == Some(Type::Push)
        {
            let (state, resize) = match self.frame_type {
                Some(frame::DATA_FRAME_TYPE_ID) => (State::Data, false),

                _ => (State::FramePayload, true),
            };

            self.state_transition(state, len as usize, resize);

            return Ok(());
        }

        Err(Error::InternalError)
    }

    /// Tries to fill the state buffer by reading data from the corresponding
    /// transport stream.
    ///
    /// When not enough data can be read to complete the state, this returns
    /// `Error::Done`.
    pub fn try_fill_buffer(
        &mut self, conn: &mut crate::Connection,
    ) -> Result<()> {
        let buf = &mut self.state_buf[self.state_off..self.state_len];

        let (read, _) = conn.stream_recv(self.id, buf)?;

        trace!(
            "{} read {} bytes on stream {}",
            conn.trace_id(),
            read,
            self.id,
        );

        self.state_off += read;

        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }

        Ok(())
    }

    /// Tries to fill the state buffer by reading data from the given cursor.
    ///
    /// This is intended to replace `try_fill_buffer()` in tests, in order to
    /// avoid having to setup a transport connection.
    #[cfg(test)]
    fn try_fill_buffer_for_tests(
        &mut self, stream: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        let buf = &mut self.state_buf[self.state_off..self.state_len];

        let read = std::io::Read::read(stream, buf).unwrap();

        self.state_off += read;

        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }

        Ok(())
    }

    /// Tries to parse a varint (including length) from the state buffer.
    pub fn try_consume_varint(&mut self) -> Result<u64> {
        if self.state_off == 1 {
            self.state_len = octets::varint_parse_len(self.state_buf[0]);
            self.state_buf.resize(self.state_len, 0);
        }

        // Return early if we don't have enough data in the state buffer to
        // parse the whole varint.
        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }

        let varint =
            octets::Octets::with_slice(&mut self.state_buf).get_varint()?;

        Ok(varint)
    }

    /// Tries to parse a frame from the state buffer.
    pub fn try_consume_frame(&mut self) -> Result<()> {
        // TODO: properly propagate frame parsing errors.
        if let Ok(frame) = frame::Frame::from_bytes(
            self.frame_type.unwrap(),
            self.state_len as u64,
            &mut self.state_buf,
        ) {
            self.frames.push_back(frame);
        }

        self.state_transition(State::FrameType, 1, true);

        Ok(())
    }

    /// Tries to read DATA payload from the transport stream.
    pub fn try_consume_data(
        &mut self, conn: &mut crate::Connection, out: &mut [u8],
    ) -> Result<usize> {
        let left = std::cmp::min(out.len(), self.state_len - self.state_off);

        let (len, _) = conn.stream_recv(self.id, &mut out[..left])?;

        self.state_off += len;

        if self.state_buffer_complete() {
            self.state_transition(State::FrameType, 1, true);
        }

        Ok(len)
    }

    /// Tries to read DATA payload from the given cursor.
    ///
    /// This is intended to replace `try_consume_data()` in tests, in order to
    /// avoid having to setup a transport connection.
    #[cfg(test)]
    fn try_consume_data_for_tests(
        &mut self, stream: &mut std::io::Cursor<Vec<u8>>, out: &mut [u8],
    ) -> Result<usize> {
        let left = std::cmp::min(out.len(), self.state_len - self.state_off);

        let len = std::io::Read::read(stream, &mut out[..left]).unwrap();

        self.state_off += len;

        if self.state_buffer_complete() {
            self.state_transition(State::FrameType, 1, true);
        }

        Ok(len)
    }

    pub fn notify_incoming_data(&mut self, has_data: bool) {
        self.has_incoming_data = has_data;
    }

    pub fn has_incoming_data(&self) -> bool {
        self.has_incoming_data
    }

    /// Returns true if the state buffer has enough data to complete the state.
    fn state_buffer_complete(&self) -> bool {
        self.state_off == self.state_len
    }

    /// Transitions the stream to a new state, and optionally resets the state
    /// buffer.
    fn state_transition(
        &mut self, new_state: State, expected_len: usize, resize: bool,
    ) {
        self.state = new_state;
        self.state_off = 0;
        self.state_len = expected_len;

        // Some states don't need the state buffer, so don't resize it if not
        // necessary.
        if resize {
            self.state_buf.resize(self.state_len, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Process incoming SETTINGS frame on control stream.
    fn control_good() {
        let mut stream = Stream::new(3, false);
        assert_eq!(stream.state, State::StreamType);

        let mut d = vec![42; 40];
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

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_CONTROL_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(stream.state, State::FrameType);

        // Parse the SETTINGS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::SETTINGS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the SETTINGS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 8);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the SETTINGS frame payload.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.get_frame(), Some(frame));
    }

    #[test]
    /// Process duplicate SETTINGS frame on control stream.
    fn control_bad_multiple_settings() {
        let mut stream = Stream::new(3, false);
        assert_eq!(stream.state, State::StreamType);

        let mut d = vec![42; 40];
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

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_CONTROL_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(stream.state, State::FrameType);

        // Parse the SETTINGS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::SETTINGS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the SETTINGS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 8);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the SETTINGS frame payload.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.get_frame(), Some(frame));

        // Parse the second SETTINGS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::UnexpectedFrame));
    }

    #[test]
    /// Process other frame before SETTINGS frame on control stream.
    fn control_bad_late_settings() {
        let mut stream = Stream::new(3, false);
        assert_eq!(stream.state, State::StreamType);

        let mut d = vec![42; 40];
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

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_CONTROL_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(stream.state, State::FrameType);

        // Parse GOAWAY.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::MissingSettings));
    }

    #[test]
    /// Process not-allowed frame on control stream.
    fn control_bad_frame() {
        let mut stream = Stream::new(3, false);
        assert_eq!(stream.state, State::StreamType);

        let mut d = vec![42; 40];
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

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();

        // Parse first SETTINGS frame.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        stream.set_frame_type(frame_ty).unwrap();

        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        stream.set_frame_payload_len(frame_payload_len).unwrap();

        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        stream.get_frame();

        // Parse HEADERS.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::WrongStream));
    }

    #[test]
    fn request_no_data() {
        let mut stream = Stream::new(0, false);

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        assert_eq!(stream.get_frame(), None);
    }

    #[test]
    fn request_good() {
        let mut stream = Stream::new(0, false);

        let mut d = vec![42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data {
            payload: payload.clone(),
        };

        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::HEADERS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the HEADERS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 12);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the HEADERS frame.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.get_frame(), Some(hdrs));

        // Parse the DATA frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::DATA_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the DATA frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 12);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::Data);

        // Parse the DATA payload.
        let mut recv_buf = vec![0; payload.len()];
        assert_eq!(
            stream.try_consume_data_for_tests(&mut cursor, &mut recv_buf),
            Ok(payload.len())
        );
        assert_eq!(payload, recv_buf);

        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    fn priority_request_bad() {
        let mut stream = Stream::new(0, false);

        let mut d = vec![42; 1280];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data {
            payload: payload.clone(),
        };

        // Create an approximate PRIORITY frame in the buffer.
        b.put_varint(frame::PRIORITY_FRAME_TYPE_ID).unwrap();
        b.put_varint(2).unwrap(); // 2 u8s = Bitfield + Weight
        b.put_u8(0).unwrap(); // bitfield
        b.put_u8(16).unwrap(); // weight

        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the PRIORITY frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();

        // PRIORITY frame not allowed on request stream, so ensure
        // error is returned.
        assert_eq!(frame_ty, frame::PRIORITY_FRAME_TYPE_ID);

        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::WrongStream));
        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    fn priority_control_good() {
        let mut stream = Stream::new(2, false);

        let mut d = vec![42; 1280];
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

        // Create an approximate PRIORITY frame in the buffer.
        b.put_varint(frame::PRIORITY_FRAME_TYPE_ID).unwrap();
        b.put_varint(1 + octets::varint_parse_len(1) as u64 + 1)
            .unwrap(); // 2 u8s = Bitfield + varint + Weight
        b.put_u8(128).unwrap(); // bitfield
        b.put_varint(1).unwrap();
        b.put_u8(16).unwrap(); // weight

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_CONTROL_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(stream.state, State::FrameType);

        // Parse the SETTINGS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::SETTINGS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the SETTINGS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 8);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the SETTINGS frame payload.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        assert_eq!(stream.state, State::FrameType);

        // Parse the PRIORITY frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::PRIORITY_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the PRIORITY frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 3);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the PRIORITY frame.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        assert_eq!(stream.state, State::FrameType);

        // TODO: if/when PRIRORITY frame is fully implemented, test it
        // e.g. `assert_eq!(stream.get_frame(), Some(priority));`
    }

    #[test]
    fn push_good() {
        let mut stream = Stream::new(2, false);

        let mut d = vec![42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data {
            payload: payload.clone(),
        };

        b.put_varint(HTTP3_PUSH_STREAM_TYPE_ID).unwrap();
        b.put_varint(1).unwrap();
        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream_ty, HTTP3_PUSH_STREAM_TYPE_ID);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(stream.state, State::PushId);

        // Parse push ID.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let push_id = stream.try_consume_varint().unwrap();
        assert_eq!(push_id, 1);

        stream.set_push_id(push_id).unwrap();
        assert_eq!(stream.state, State::FrameType);

        // Parse the HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::HEADERS_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the HEADERS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 12);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the HEADERS frame.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok(()));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.get_frame(), Some(hdrs));

        // Parse the DATA frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::DATA_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the DATA frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 12);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::Data);

        // Parse the DATA payload.
        let mut recv_buf = vec![0; payload.len()];
        assert_eq!(
            stream.try_consume_data_for_tests(&mut cursor, &mut recv_buf),
            Ok(payload.len())
        );
        assert_eq!(payload, recv_buf);

        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    fn grease() {
        let mut stream = Stream::new(2, false);

        let mut d = vec![42; 20];
        let mut b = octets::Octets::with_slice(&mut d);

        b.put_varint(33).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let stream_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream_ty, 33);
        stream
            .set_ty(Type::deserialize(stream_ty).unwrap())
            .unwrap();
        assert_eq!(stream.state, State::Drain);
    }
}
