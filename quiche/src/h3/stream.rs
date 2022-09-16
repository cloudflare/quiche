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

use super::frame;

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u64 = 0x0;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u64 = 0x1;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u64 = 0x2;
pub const QPACK_DECODER_STREAM_TYPE_ID: u64 = 0x3;

const MAX_STATE_BUF_SIZE: usize = (1 << 24) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Control,
    Request,
    Push,
    QpackEncoder,
    QpackDecoder,
    Unknown,
}

impl Type {
    #[cfg(feature = "qlog")]
    pub fn to_qlog(self) -> qlog::events::h3::H3StreamType {
        match self {
            Type::Control => qlog::events::h3::H3StreamType::Control,
            Type::Request => qlog::events::h3::H3StreamType::Data,
            Type::Push => qlog::events::h3::H3StreamType::Push,
            Type::QpackEncoder => qlog::events::h3::H3StreamType::QpackEncode,
            Type::QpackDecoder => qlog::events::h3::H3StreamType::QpackDecode,
            Type::Unknown => qlog::events::h3::H3StreamType::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

    /// All data has been read.
    Finished,
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

    /// Whether the stream was created locally, or by the peer.
    is_local: bool,

    /// Whether the stream has been remotely initialized.
    remote_initialized: bool,

    /// Whether the stream has been locally initialized.
    local_initialized: bool,

    /// Whether a `Data` event has been triggered for this stream.
    data_event_triggered: bool,

    /// The last `PRIORITY_UPDATE` frame encoded field value, if any.
    last_priority_update: Option<Vec<u8>>,
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

            is_local,
            remote_initialized: false,
            local_initialized: false,

            data_event_triggered: false,

            last_priority_update: None,
        }
    }

    pub fn ty(&self) -> Option<Type> {
        self.ty
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Sets the stream's type and transitions to the next state.
    pub fn set_ty(&mut self, ty: Type) -> Result<()> {
        assert_eq!(self.state, State::StreamType);

        self.ty = Some(ty);

        let state = match ty {
            Type::Control | Type::Request => State::FrameType,

            Type::Push => State::PushId,

            Type::QpackEncoder | Type::QpackDecoder => {
                self.remote_initialized = true;

                State::QpackInstruction
            },

            Type::Unknown => State::Drain,
        };

        self.state_transition(state, 1, true)?;

        Ok(())
    }

    /// Sets the push ID and transitions to the next state.
    pub fn set_push_id(&mut self, _id: u64) -> Result<()> {
        assert_eq!(self.state, State::PushId);

        // TODO: implement push ID.

        self.state_transition(State::FrameType, 1, true)?;

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
                match (ty, self.remote_initialized) {
                    // Initialize control stream.
                    (frame::SETTINGS_FRAME_TYPE_ID, false) =>
                        self.remote_initialized = true,

                    // Non-SETTINGS frames not allowed on control stream
                    // before initialization.
                    (_, false) => return Err(Error::MissingSettings),

                    // Additional SETTINGS frame.
                    (frame::SETTINGS_FRAME_TYPE_ID, true) =>
                        return Err(Error::FrameUnexpected),

                    // Frames that can't be received on control stream
                    // after initialization.
                    (frame::DATA_FRAME_TYPE_ID, true) =>
                        return Err(Error::FrameUnexpected),

                    (frame::HEADERS_FRAME_TYPE_ID, true) =>
                        return Err(Error::FrameUnexpected),

                    (frame::PUSH_PROMISE_FRAME_TYPE_ID, true) =>
                        return Err(Error::FrameUnexpected),

                    // All other frames are ignored after initialization.
                    (_, true) => (),
                }
            },

            Some(Type::Request) => {
                // Request stream starts uninitialized and only HEADERS
                // is accepted. Other frames cause an error.
                if !self.is_local {
                    match (ty, self.remote_initialized) {
                        (frame::HEADERS_FRAME_TYPE_ID, false) =>
                            self.remote_initialized = true,

                        (frame::DATA_FRAME_TYPE_ID, false) =>
                            return Err(Error::FrameUnexpected),

                        (frame::CANCEL_PUSH_FRAME_TYPE_ID, _) =>
                            return Err(Error::FrameUnexpected),

                        (frame::SETTINGS_FRAME_TYPE_ID, _) =>
                            return Err(Error::FrameUnexpected),

                        (frame::GOAWAY_FRAME_TYPE_ID, _) =>
                            return Err(Error::FrameUnexpected),

                        (frame::MAX_PUSH_FRAME_TYPE_ID, _) =>
                            return Err(Error::FrameUnexpected),

                        // All other frames can be ignored regardless of stream
                        // state.
                        _ => (),
                    }
                }
            },

            Some(Type::Push) => {
                match ty {
                    // Frames that can never be received on request streams.
                    frame::CANCEL_PUSH_FRAME_TYPE_ID =>
                        return Err(Error::FrameUnexpected),

                    frame::SETTINGS_FRAME_TYPE_ID =>
                        return Err(Error::FrameUnexpected),

                    frame::PUSH_PROMISE_FRAME_TYPE_ID =>
                        return Err(Error::FrameUnexpected),

                    frame::GOAWAY_FRAME_TYPE_ID =>
                        return Err(Error::FrameUnexpected),

                    frame::MAX_PUSH_FRAME_TYPE_ID =>
                        return Err(Error::FrameUnexpected),

                    _ => (),
                }
            },

            _ => return Err(Error::FrameUnexpected),
        }

        self.frame_type = Some(ty);

        self.state_transition(State::FramePayloadLen, 1, true)?;

        Ok(())
    }

    // Returns the stream's current frame type, if any
    pub fn frame_type(&self) -> Option<u64> {
        self.frame_type
    }

    /// Sets the frame's payload length and transitions to the next state.
    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        assert_eq!(self.state, State::FramePayloadLen);

        // Only expect frames on Control, Request and Push streams.
        if matches!(self.ty, Some(Type::Control | Type::Request | Type::Push)) {
            let (state, resize) = match self.frame_type {
                Some(frame::DATA_FRAME_TYPE_ID) => (State::Data, false),

                // These frame types can never have 0 payload length because
                // they always have fields that must be populated.
                Some(
                    frame::GOAWAY_FRAME_TYPE_ID |
                    frame::PUSH_PROMISE_FRAME_TYPE_ID |
                    frame::CANCEL_PUSH_FRAME_TYPE_ID |
                    frame::MAX_PUSH_FRAME_TYPE_ID,
                ) => {
                    if len == 0 {
                        return Err(Error::FrameError);
                    }

                    (State::FramePayload, true)
                },

                _ => (State::FramePayload, true),
            };

            self.state_transition(state, len as usize, resize)?;

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
        // If no bytes are required to be read, return early.
        if self.state_buffer_complete() {
            return Ok(());
        }

        let buf = &mut self.state_buf[self.state_off..self.state_len];

        let read = match conn.stream_recv(self.id, buf) {
            Ok((len, _)) => len,

            Err(e) => {
                // The stream is not readable anymore, so re-arm the Data event.
                if e == crate::Error::Done {
                    self.reset_data_event();
                }

                return Err(e.into());
            },
        };

        trace!(
            "{} read {} bytes on stream {}",
            conn.trace_id(),
            read,
            self.id,
        );

        self.state_off += read;

        if !self.state_buffer_complete() {
            self.reset_data_event();

            return Err(Error::Done);
        }

        Ok(())
    }

    /// Initialize the local part of the stream.
    pub fn initialize_local(&mut self) {
        self.local_initialized = true
    }

    /// Whether the stream has been locally initialized.
    pub fn local_initialized(&self) -> bool {
        self.local_initialized
    }

    /// Tries to fill the state buffer by reading data from the given cursor.
    ///
    /// This is intended to replace `try_fill_buffer()` in tests, in order to
    /// avoid having to setup a transport connection.
    #[cfg(test)]
    fn try_fill_buffer_for_tests(
        &mut self, stream: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        // If no bytes are required to be read, return early
        if self.state_buffer_complete() {
            return Ok(());
        }

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

        let varint = octets::Octets::with_slice(&self.state_buf).get_varint()?;

        Ok(varint)
    }

    /// Tries to parse a frame from the state buffer.
    ///
    /// If successful, returns the `frame::Frame` and the payload length.
    pub fn try_consume_frame(&mut self) -> Result<(frame::Frame, u64)> {
        // Processing a frame other than DATA, so re-arm the Data event.
        self.reset_data_event();

        let payload_len = self.state_len as u64;

        // TODO: properly propagate frame parsing errors.
        let frame = frame::Frame::from_bytes(
            self.frame_type.unwrap(),
            payload_len,
            &self.state_buf,
        )?;

        self.state_transition(State::FrameType, 1, true)?;

        Ok((frame, payload_len))
    }

    /// Tries to read DATA payload from the transport stream.
    pub fn try_consume_data(
        &mut self, conn: &mut crate::Connection, out: &mut [u8],
    ) -> Result<(usize, bool)> {
        let left = std::cmp::min(out.len(), self.state_len - self.state_off);

        let (len, fin) = match conn.stream_recv(self.id, &mut out[..left]) {
            Ok(v) => v,

            Err(e) => {
                // The stream is not readable anymore, so re-arm the Data event.
                if e == crate::Error::Done {
                    self.reset_data_event();
                }

                return Err(e.into());
            },
        };

        self.state_off += len;

        // The stream is not readable anymore, so re-arm the Data event.
        if !conn.stream_readable(self.id) {
            self.reset_data_event();
        }

        if self.state_buffer_complete() {
            self.state_transition(State::FrameType, 1, true)?;
        }

        Ok((len, fin))
    }

    /// Marks the stream as finished.
    pub fn finished(&mut self) {
        let _ = self.state_transition(State::Finished, 0, false);
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
            self.state_transition(State::FrameType, 1, true)?;
        }

        Ok(len)
    }

    /// Tries to update the data triggered state for the stream.
    ///
    /// This returns `true` if a Data event was not already triggered before
    /// the last reset, and updates the state. Returns `false` otherwise.
    pub fn try_trigger_data_event(&mut self) -> bool {
        if self.data_event_triggered {
            return false;
        }

        self.data_event_triggered = true;

        true
    }

    /// Resets the data triggered state.
    fn reset_data_event(&mut self) {
        self.data_event_triggered = false;
    }

    /// Set the last priority update for the stream.
    pub fn set_last_priority_update(&mut self, priority_update: Option<Vec<u8>>) {
        self.last_priority_update = priority_update;
    }

    /// Take the last priority update and leave `None` in its place.
    pub fn take_last_priority_update(&mut self) -> Option<Vec<u8>> {
        self.last_priority_update.take()
    }

    /// Returns `true` if there is a priority update.
    pub fn has_last_priority_update(&self) -> bool {
        self.last_priority_update.is_some()
    }

    /// Returns true if the state buffer has enough data to complete the state.
    fn state_buffer_complete(&self) -> bool {
        self.state_off == self.state_len
    }

    /// Transitions the stream to a new state, and optionally resets the state
    /// buffer.
    fn state_transition(
        &mut self, new_state: State, expected_len: usize, resize: bool,
    ) -> Result<()> {
        // Some states don't need the state buffer, so don't resize it if not
        // necessary.
        if resize {
            // A peer can influence the size of the state buffer (e.g. with the
            // payload size of a GREASE frame), so we need to limit the maximum
            // size to avoid DoS.
            if expected_len > MAX_STATE_BUF_SIZE {
                return Err(Error::ExcessiveLoad);
            }

            self.state_buf.resize(expected_len, 0);
        }

        self.state = new_state;
        self.state_off = 0;
        self.state_len = expected_len;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::h3::frame::*;

    use super::*;

    fn open_uni(b: &mut octets::OctetsMut, ty: u64) -> Result<Stream> {
        let stream = Stream::new(2, false);
        assert_eq!(stream.state, State::StreamType);

        b.put_varint(ty)?;

        Ok(stream)
    }

    fn parse_uni(
        stream: &mut Stream, ty: u64, cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        stream.try_fill_buffer_for_tests(cursor)?;

        let stream_ty = stream.try_consume_varint()?;
        assert_eq!(stream_ty, ty);
        stream.set_ty(Type::deserialize(stream_ty).unwrap())?;

        Ok(())
    }

    fn parse_skip_frame(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        // Parse the frame type.
        stream.try_fill_buffer_for_tests(cursor)?;

        let frame_ty = stream.try_consume_varint()?;

        stream.set_frame_type(frame_ty)?;
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the frame payload length.
        stream.try_fill_buffer_for_tests(cursor)?;

        let frame_payload_len = stream.try_consume_varint()?;
        stream.set_frame_payload_len(frame_payload_len)?;
        assert_eq!(stream.state, State::FramePayload);

        // Parse the frame payload.
        stream.try_fill_buffer_for_tests(cursor)?;

        stream.try_consume_frame()?;
        assert_eq!(stream.state, State::FrameType);

        Ok(())
    }

    #[test]
    /// Process incoming SETTINGS frame on control stream.
    fn control_good() {
        let mut d = vec![42; 40];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let frame = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
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
        assert_eq!(frame_payload_len, 6);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the SETTINGS frame payload.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok((frame, 6)));
        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    /// Process incoming empty SETTINGS frame on control stream.
    fn control_empty_settings() {
        let mut d = vec![42; 40];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(vec![]),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
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
        assert_eq!(frame_payload_len, 0);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the SETTINGS frame payload.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok((frame, 0)));
        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    /// Process duplicate SETTINGS frame on control stream.
    fn control_bad_multiple_settings() {
        let mut d = vec![42; 40];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let frame = frame::Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();
        frame.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
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
        assert_eq!(frame_payload_len, 6);
        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the SETTINGS frame payload.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok((frame, 6)));
        assert_eq!(stream.state, State::FrameType);

        // Parse the second SETTINGS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Process other frame before SETTINGS frame on control stream.
    fn control_bad_late_settings() {
        let mut d = vec![42; 40];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let goaway = frame::Frame::GoAway { id: 0 };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        goaway.to_bytes(&mut b).unwrap();
        settings.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
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
        let mut d = vec![42; 40];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (33, 33),
        ];

        let settings = frame::Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        settings.to_bytes(&mut b).unwrap();
        hdrs.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
            .unwrap();
        assert_eq!(stream.state, State::FrameType);

        // Parse first SETTINGS frame.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        stream.set_frame_type(frame_ty).unwrap();

        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        stream.set_frame_payload_len(frame_payload_len).unwrap();

        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert!(stream.try_consume_frame().is_ok());

        // Parse HEADERS.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::FrameUnexpected));
    }

    #[test]
    fn request_no_data() {
        let mut stream = Stream::new(0, false);

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
    }

    #[test]
    fn request_good() {
        let mut stream = Stream::new(0, false);

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

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

        assert_eq!(stream.try_consume_frame(), Ok((hdrs, 12)));
        assert_eq!(stream.state, State::FrameType);

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
    fn push_good() {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = frame::Frame::Headers { header_block };
        let data = frame::Frame::Data {
            payload: payload.clone(),
        };

        let mut stream = open_uni(&mut b, HTTP3_PUSH_STREAM_TYPE_ID).unwrap();
        b.put_varint(1).unwrap();
        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_PUSH_STREAM_TYPE_ID, &mut cursor).unwrap();
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

        assert_eq!(stream.try_consume_frame(), Ok((hdrs, 12)));
        assert_eq!(stream.state, State::FrameType);

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
        let mut d = vec![42; 20];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let mut stream = open_uni(&mut b, 33).unwrap();

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

    #[test]
    fn data_before_headers() {
        let mut stream = Stream::new(0, false);

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let data = frame::Frame::Data {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the DATA frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::DATA_FRAME_TYPE_ID);

        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::FrameUnexpected));
    }

    #[test]
    fn zero_length_goaway() {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(vec![]),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();

        // Write a 0-length payload frame.
        b.put_varint(frame::GOAWAY_FRAME_TYPE_ID).unwrap();
        b.put_varint(0).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
            .unwrap();

        // Skip SETTINGS frame type.
        parse_skip_frame(&mut stream, &mut cursor).unwrap();

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::GOAWAY_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(
            Err(Error::FrameError),
            stream.set_frame_payload_len(frame_payload_len)
        );
    }

    #[test]
    fn zero_length_push_promise() {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let mut stream = Stream::new(0, false);

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        // Write a 0-length payload frame.
        b.put_varint(frame::PUSH_PROMISE_FRAME_TYPE_ID).unwrap();
        b.put_varint(0).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::PUSH_PROMISE_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(
            Err(Error::FrameError),
            stream.set_frame_payload_len(frame_payload_len)
        );
    }

    #[test]
    fn zero_length_cancel_push() {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(vec![]),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();

        // Write a 0-length payload frame.
        b.put_varint(frame::CANCEL_PUSH_FRAME_TYPE_ID).unwrap();
        b.put_varint(0).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
            .unwrap();

        // Skip SETTINGS frame type.
        parse_skip_frame(&mut stream, &mut cursor).unwrap();

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::CANCEL_PUSH_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(
            Err(Error::FrameError),
            stream.set_frame_payload_len(frame_payload_len)
        );
    }

    #[test]
    fn zero_length_max_push_id() {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(vec![]),
        };

        let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        frame.to_bytes(&mut b).unwrap();

        // Write a 0-length payload frame.
        b.put_varint(frame::MAX_PUSH_FRAME_TYPE_ID).unwrap();
        b.put_varint(0).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
            .unwrap();

        // Skip SETTINGS frame type.
        parse_skip_frame(&mut stream, &mut cursor).unwrap();

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, frame::MAX_PUSH_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(
            Err(Error::FrameError),
            stream.set_frame_payload_len(frame_payload_len)
        );
    }
}
