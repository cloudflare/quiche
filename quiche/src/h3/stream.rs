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

use std::mem::MaybeUninit;

use crate::buffers::BufFactory;

use super::Error;
use super::Result;

use super::frame;

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u64 = 0x0;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u64 = 0x1;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u64 = 0x2;
pub const QPACK_DECODER_STREAM_TYPE_ID: u64 = 0x3;

const MAX_STATE_BUF_SIZE: usize = (1 << 24) - 1;
const MAX_STATE_BUF_ALLOC_SIZE: usize = 4096;
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
    pub fn to_qlog(self) -> qlog::events::http3::StreamType {
        match self {
            Type::Control => qlog::events::http3::StreamType::Control,
            Type::Request => qlog::events::http3::StreamType::Request,
            Type::Push => qlog::events::http3::StreamType::Push,
            Type::QpackEncoder => qlog::events::http3::StreamType::QpackEncode,
            Type::QpackDecoder => qlog::events::http3::StreamType::QpackDecode,
            Type::Unknown => qlog::events::http3::StreamType::Unknown,
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

    /// Reading the stream's current frame's payload without buffering the data.
    SkipFramePayload,

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

    /// Whether the local send-side of the stream has finished.
    local_finished: bool,

    /// Whether a `Data` event has been triggered for this stream.
    data_event_triggered: bool,

    /// The last `PRIORITY_UPDATE` frame encoded field value, if any.
    last_priority_update: Option<Vec<u8>>,

    /// The count of HEADERS frames that have been received.
    headers_received_count: usize,

    /// Whether a DATA frame has been received.
    data_received: bool,

    /// Whether a trailing HEADER field has been sent.
    trailers_sent: bool,

    /// Whether a trailing HEADER field has been received.
    trailers_received: bool,

    /// Max size of QPACK encoded headers carried in HEADERS or PUSH_PROMISE
    /// frames. Related to SETTINGS_MAX_FIELD_LIST_SIZE; see
    /// <https://datatracker.ietf.org/doc/html/rfc9114#section-7.2.4.1>
    max_encoded_headers_payload_size: u64,

    /// Max PRIORITY_UPDATE frame payload size; see
    /// <https://datatracker.ietf.org/doc/html/rfc9218#section-7.2>
    max_priority_update_size: u64,
}

impl Stream {
    /// Creates a new HTTP/3 stream.
    ///
    /// The `is_local` parameter indicates whether the stream was created by the
    /// local endpoint, or by the peer.
    pub fn new(
        id: u64, is_local: bool, max_field_section_size: u64,
        max_priority_update_size: u64,
    ) -> Stream {
        let (ty, state) = if crate::stream::is_bidi(id) {
            // All bidirectional streams are "request" streams, so we don't
            // need to read the stream type.
            (Some(Type::Request), State::FrameType)
        } else {
            // The stream's type is yet to be determined.
            (None, State::StreamType)
        };

        // Huffman encoding might inflate the size of encoded headers
        // when transferred in HEADERS or PUSH_PROMISE frames. Scale up
        // the limit by 50% to accommodate this.
        let max_encoded_headers_payload_size =
            max_field_section_size.saturating_add(max_field_section_size / 2);

        Stream {
            id,
            ty,

            state,

            // Pre-allocate a buffer to avoid multiple tiny early allocations.
            state_buf: Vec::with_capacity(16),

            // Expect one byte for the initial state, to parse the initial
            // varint length.
            state_len: 1,
            state_off: 0,

            frame_type: None,

            is_local,

            remote_initialized: false,

            local_initialized: false,
            local_finished: false,

            data_event_triggered: false,

            last_priority_update: None,

            headers_received_count: 0,

            data_received: false,

            trailers_sent: false,
            trailers_received: false,

            max_encoded_headers_payload_size,
            max_priority_update_size,
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
                self.validate_request_frame_type(ty)?;
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

    /// Validates a frame type received on a request stream and advances the
    /// request-stream HTTP message phase tracking accordingly.
    ///
    /// Request streams start uninitialized and only HEADERS is accepted. After
    /// initialization, DATA and HEADERS frames may be acceptable, depending on
    /// the HTTP message phase (informational/final headers, body, trailers).
    /// Receiving any other known frame type on a request stream is always an
    /// error per RFC 9114, regardless of which endpoint opened the stream.
    ///
    /// HTTP message phase bookkeeping (`remote_initialized`, `data_received`,
    /// `trailers_received`) only applies to peer-initiated streams, since it
    /// tracks the receive direction.
    fn validate_request_frame_type(&mut self, ty: u64) -> Result<()> {
        // Frames that are never valid on a request stream, regardless of which
        // endpoint opened it.
        if matches!(
            ty,
            frame::CANCEL_PUSH_FRAME_TYPE_ID |
                frame::SETTINGS_FRAME_TYPE_ID |
                frame::GOAWAY_FRAME_TYPE_ID |
                frame::MAX_PUSH_FRAME_TYPE_ID |
                frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID |
                frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID
        ) {
            return Err(Error::FrameUnexpected);
        }

        // HTTP message phase bookkeeping only applies to peer-initiated
        // streams, since it tracks the receive direction.
        if self.is_local {
            return Ok(());
        }

        match (ty, self.remote_initialized) {
            (frame::HEADERS_FRAME_TYPE_ID, false) => {
                self.remote_initialized = true;
            },

            (frame::DATA_FRAME_TYPE_ID, false) =>
                return Err(Error::FrameUnexpected),

            (frame::HEADERS_FRAME_TYPE_ID, true) => {
                if self.trailers_received {
                    return Err(Error::FrameUnexpected);
                }

                if self.data_received {
                    self.trailers_received = true;
                }
            },

            (frame::DATA_FRAME_TYPE_ID, true) => {
                if self.trailers_received {
                    return Err(Error::FrameUnexpected);
                }

                self.data_received = true;
            },

            // All other frames can be ignored regardless of stream state.
            _ => (),
        }

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
        if !matches!(self.ty, Some(Type::Control | Type::Request | Type::Push)) {
            return Err(Error::InternalError);
        }

        let (state, resize) = match self.frame_type {
            Some(frame::DATA_FRAME_TYPE_ID) => (State::Data, false),

            Some(frame::HEADERS_FRAME_TYPE_ID) => {
                if len > self.max_encoded_headers_payload_size {
                    return Err(Error::ExcessiveLoad);
                }

                (State::FramePayload, true)
            },

            // These frames carry a mandatory single varint, so their payload
            // size has to be at least 1 byte and at most 8 bytes.
            Some(frame::CANCEL_PUSH_FRAME_TYPE_ID) |
            Some(frame::GOAWAY_FRAME_TYPE_ID) |
            Some(frame::MAX_PUSH_FRAME_TYPE_ID) => {
                if !(1..=8).contains(&len) {
                    return Err(Error::FrameError);
                }

                (State::FramePayload, true)
            },

            Some(frame::SETTINGS_FRAME_TYPE_ID) => {
                if len > frame::MAX_SETTINGS_PAYLOAD_SIZE as u64 {
                    return Err(Error::FrameError);
                }

                (State::FramePayload, true)
            },

            Some(frame::PUSH_PROMISE_FRAME_TYPE_ID) => {
                // A push promise payload includes a varint and a field section.
                let max_push_promise_size =
                    self.max_encoded_headers_payload_size.saturating_add(8);

                if len == 0 {
                    return Err(Error::FrameError);
                }

                if len > max_push_promise_size {
                    return Err(Error::ExcessiveLoad);
                }

                (State::FramePayload, true)
            },

            Some(frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID) |
            Some(frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID) => {
                if len == 0 {
                    return Err(Error::FrameError);
                }

                if len > self.max_priority_update_size {
                    return Err(Error::ExcessiveLoad);
                }

                (State::FramePayload, true)
            },

            // Ignore unknown frames' payloads.
            _ => {
                if len > MAX_STATE_BUF_SIZE as u64 {
                    return Err(Error::ExcessiveLoad);
                }

                (State::SkipFramePayload, false)
            },
        };

        self.state_transition(state, len as usize, resize)?;

        Ok(())
    }

    /// Returns a mutable slice over the state buffer's spare capacity,
    /// reserving additional space if needed.
    ///
    /// Callers must initialize the returned bytes and call
    /// [`commit_state_buf_read()`] with the number of bytes written.
    fn spare_state_buf(&mut self) -> &mut [u8] {
        let need = self.state_len - self.state_off;
        let spare = self
            .state_buf
            .capacity()
            .saturating_sub(self.state_buf.len());

        if spare == 0 {
            let additional = std::cmp::min(MAX_STATE_BUF_ALLOC_SIZE, need);
            self.state_buf.reserve(additional);
        }

        let buf = self.state_buf.spare_capacity_mut();
        let usable = std::cmp::min(need, buf.len());

        // SAFETY: MaybeUninit<u8> has the same layout as u8. The caller
        // contract requires initializing all returned bytes before calling
        // commit_state_buf_read(), so no uninitialized memory is read.
        unsafe {
            std::mem::transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(
                &mut buf[..usable],
            )
        }
    }

    /// Advances the state buffer's initialized length and offset by `read`
    /// bytes. The caller must have written `read` bytes into the slice
    /// previously returned by [`spare_state_buf()`].
    fn commit_state_buf_read(&mut self, read: usize) {
        let buf_len = self.state_buf.len();
        debug_assert!(buf_len + read <= self.state_buf.capacity());
        // SAFETY: `read` bytes were written to spare capacity by the I/O
        // layer. read <= spare_buf.len() <= spare_capacity, so
        // buf_len + read <= capacity.
        unsafe { self.state_buf.set_len(buf_len + read) };

        self.state_off += read;
    }

    /// Tries to fill the state buffer by reading data from the corresponding
    /// transport stream.
    ///
    /// When not enough data can be read to complete the state, this returns
    /// `Error::Done`.
    pub fn try_fill_buffer<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<()> {
        // If no bytes are required to be read, return early.
        if self.state_buffer_complete() {
            return Ok(());
        }

        loop {
            let stream_id = self.id;

            let spare_buf = self.spare_state_buf();
            let spare_len = spare_buf.len();

            match conn.stream_recv(stream_id, spare_buf) {
                Ok((read, fin)) => {
                    self.commit_state_buf_read(read);

                    if self.critical_stream_closed(fin) {
                        super::close_conn_critical_stream(conn)?;
                    }

                    trace!(
                        "{} read {} bytes on stream {}",
                        conn.trace_id(),
                        read,
                        self.id,
                    );

                    if read < spare_len {
                        break;
                    }

                    if self.state_buffer_complete() {
                        return Ok(());
                    }
                },

                Err(e @ crate::Error::StreamReset(_)) => {
                    if self.critical_stream_closed(true) {
                        super::close_conn_critical_stream(conn)?;
                    }

                    return Err(e.into());
                },

                Err(e) => {
                    // The stream is not readable anymore, so re-arm the Data
                    // event.
                    if e == crate::Error::Done {
                        self.reset_data_event();
                    }

                    return Err(e.into());
                },
            };
        }

        if !self.state_buffer_complete() {
            self.reset_data_event();

            return Err(Error::Done);
        }

        Ok(())
    }

    /// Tries to read data from the corresponding transport stream up to the
    /// state's size, without storing the data in the state buffer.
    ///
    /// When not enough data can be read to complete the state, this returns
    /// `Error::Done`.
    pub fn try_skip_data<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<()> {
        // If no bytes are required to be read, return early.
        if self.state_buffer_complete() {
            return Ok(());
        }

        let len = self.state_len - self.state_off;

        let read = match conn.stream_discard(self.id, len) {
            Ok((len, fin)) => {
                if self.critical_stream_closed(fin) {
                    super::close_conn_critical_stream(conn)?;
                }

                len
            },

            Err(e @ crate::Error::StreamReset(_)) => {
                if self.critical_stream_closed(true) {
                    super::close_conn_critical_stream(conn)?;
                }

                return Err(e.into());
            },

            Err(e) => {
                // The stream is not readable anymore, so re-arm the Data
                // event.
                if e == crate::Error::Done {
                    self.reset_data_event();
                }

                return Err(e.into());
            },
        };

        trace!(
            "{} discarded {} bytes on stream {}",
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

    /// Finish the local part of the stream.
    pub fn finish_local(&mut self) {
        self.local_finished = true
    }

    /// Whether the local send-side of the stream has finished.
    pub fn local_finished(&self) -> bool {
        self.local_finished
    }

    pub fn increment_headers_received(&mut self) {
        self.headers_received_count =
            self.headers_received_count.saturating_add(1);
    }

    pub fn headers_received_count(&self) -> usize {
        self.headers_received_count
    }

    pub fn mark_trailers_sent(&mut self) {
        self.trailers_sent = true;
    }

    pub fn trailers_sent(&self) -> bool {
        self.trailers_sent
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

        loop {
            let spare_buf = self.spare_state_buf();
            let spare_len = spare_buf.len();

            let read = match std::io::Read::read(stream, spare_buf) {
                Ok(0) => {
                    // end of stream, stop
                    break;
                },

                Ok(v) => v,

                Err(_) => {
                    panic!("Test buffer reading should never fail");
                },
            };

            self.commit_state_buf_read(read);

            if read < spare_len {
                break;
            }

            if self.state_buffer_complete() {
                break;
            }
        }

        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }

        Ok(())
    }

    /// Tries to parse a varint (including length) from the state buffer.
    pub fn try_consume_varint(&mut self) -> Result<u64> {
        if self.state_off == 1 {
            self.state_len = octets::varint_parse_len(self.state_buf[0]);
            self.state_buf.reserve(self.state_len);
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
        debug_assert_eq!(self.state, State::FramePayload);
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

    /// Tries to skip the current frame's payload.
    pub fn try_skip_frame<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<()> {
        self.try_skip_data(conn)?;

        // Processing a frame other than DATA, so re-arm the Data event.
        self.reset_data_event();

        self.state_transition(State::FrameType, 1, true)?;

        Ok(())
    }

    /// Tries to read DATA payload from the transport stream.
    pub fn try_consume_data<F: BufFactory, OUT: bytes::BufMut>(
        &mut self, conn: &mut crate::Connection<F>, out: OUT,
    ) -> Result<(usize, bool)> {
        debug_assert_eq!(self.state, State::Data);
        let out = out.limit(self.state_len - self.state_off);

        let (len, fin) = match conn.stream_recv_buf(self.id, out) {
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
        debug_assert!(self.state_len >= self.state_off);

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

    /// Checks whether one of the critical streams was closed.
    fn critical_stream_closed(&self, fin: bool) -> bool {
        fin && matches!(
            self.ty,
            Some(Type::Control) |
                Some(Type::QpackEncoder) |
                Some(Type::QpackDecoder)
        )
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
        self.state_buf.clear();

        // Some states don't need the state buffer, so don't resize it if not
        // necessary.
        if resize {
            // A peer can influence the size of the state buffer (e.g. with the
            // payload size of a GREASE frame), so we need to limit the maximum
            // size to avoid DoS.
            if expected_len > MAX_STATE_BUF_SIZE {
                return Err(Error::ExcessiveLoad);
            }

            let reserve_len =
                std::cmp::min(expected_len, MAX_STATE_BUF_ALLOC_SIZE);
            self.state_buf.reserve(reserve_len);
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
    use crate::h3::PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT;
    use crate::h3::SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT;

    use super::*;

    fn open_uni(b: &mut octets::OctetsMut, ty: u64) -> Result<Stream> {
        let stream = <Stream>::new(
            2,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        assert_eq!(stream.state, State::StreamType);

        b.put_varint(ty)?;

        Ok(stream)
    }

    fn open_remote_request_stream() -> Stream {
        Stream::new(
            0,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        )
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

    /// Fill the buffer and parse a multi-byte varint that requires two
    /// fills (the first read gets the length prefix, the second gets the
    /// remaining bytes).
    fn parse_multibyte_varint(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<u64> {
        stream.try_fill_buffer_for_tests(cursor)?;
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(cursor)?;
        stream.try_consume_varint()
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
            additional_settings: None,
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
        assert_eq!(frame_ty, SETTINGS_FRAME_TYPE_ID);

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
            additional_settings: None,
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
        assert_eq!(frame_ty, SETTINGS_FRAME_TYPE_ID);

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

        let frame = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
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
        assert_eq!(frame_ty, SETTINGS_FRAME_TYPE_ID);

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

        let goaway = Frame::GoAway { id: 0 };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
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
        let hdrs = Frame::Headers { header_block };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (33, 33),
        ];

        let settings = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
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
        let mut stream = open_remote_request_stream();

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
    }

    #[test]
    fn request_good() {
        let mut stream = open_remote_request_stream();

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdrs = Frame::Headers { header_block };
        let data = Frame::Data {
            payload: payload.clone(),
        };

        hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);

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
        assert_eq!(frame_ty, DATA_FRAME_TYPE_ID);

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
        let hdrs = Frame::Headers { header_block };
        let data = Frame::Data {
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
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);

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
        assert_eq!(frame_ty, DATA_FRAME_TYPE_ID);

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
        let mut stream = open_remote_request_stream();

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let data = Frame::Data {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        data.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the DATA frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, DATA_FRAME_TYPE_ID);

        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::FrameUnexpected));
    }

    #[test]
    fn additional_headers() {
        let mut stream = open_remote_request_stream();

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info_hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };
        let non_info_hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };
        let trailers = Frame::Headers { header_block };
        let data = Frame::Data {
            payload: payload.clone(),
        };

        info_hdrs.to_bytes(&mut b).unwrap();
        non_info_hdrs.to_bytes(&mut b).unwrap();
        data.to_bytes(&mut b).unwrap();
        trailers.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);

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

        assert_eq!(stream.try_consume_frame(), Ok((info_hdrs, 12)));
        assert_eq!(stream.state, State::FrameType);

        // Parse the non-info HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);

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

        assert_eq!(stream.try_consume_frame(), Ok((non_info_hdrs, 12)));
        assert_eq!(stream.state, State::FrameType);

        // Parse the DATA frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, DATA_FRAME_TYPE_ID);

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

        // Parse the trailing HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);

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

        assert_eq!(stream.try_consume_frame(), Ok((trailers, 12)));
        assert_eq!(stream.state, State::FrameType);
    }

    /// Returns the frame type ID for a given frame variant.
    fn frame_type_id(frame: &Frame) -> u64 {
        match frame {
            Frame::Data { .. } => DATA_FRAME_TYPE_ID,
            Frame::Headers { .. } => HEADERS_FRAME_TYPE_ID,
            Frame::CancelPush { .. } => CANCEL_PUSH_FRAME_TYPE_ID,
            Frame::Settings { .. } => SETTINGS_FRAME_TYPE_ID,
            Frame::PushPromise { .. } => PUSH_PROMISE_FRAME_TYPE_ID,
            Frame::GoAway { .. } => GOAWAY_FRAME_TYPE_ID,
            Frame::MaxPushId { .. } => MAX_PUSH_FRAME_TYPE_ID,
            Frame::PriorityUpdateRequest { .. } =>
                PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
            Frame::PriorityUpdatePush { .. } =>
                PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
            Frame::Unknown { .. } => unreachable!(),
        }
    }

    /// Parse a large frame and check the size limit behavior.
    ///
    /// Writes the frame to a buffer, parses the frame type and payload
    /// length (handling multi-byte varint retry), then checks whether
    /// `set_frame_payload_len` accepts or rejects the frame. If accepted,
    /// also parses the payload and verifies `try_consume_frame` output.
    ///
    /// - `stream`: the H3 stream to parse the frame on.
    /// - `frame`: the frame to encode and parse back.
    /// - `expected_payload_len`: the expected encoded payload length.
    /// - `expect_accept`: if true, the frame should be accepted and fully
    ///   parsed; if false, `set_frame_payload_len` should reject it with
    ///   `Error::ExcessiveLoad`.
    fn check_large_frame_size_limit(
        stream: &mut Stream, frame: Frame, expected_payload_len: u64,
        expect_accept: bool,
    ) {
        let expected_type_id = frame_type_id(&frame);

        let mut d = vec![42; 20000];
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b).unwrap();
        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, expected_type_id);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        let frame_payload_len =
            parse_multibyte_varint(stream, &mut cursor).unwrap();
        assert_eq!(frame_payload_len, expected_payload_len);

        if expect_accept {
            stream.set_frame_payload_len(frame_payload_len).unwrap();
            assert_eq!(stream.state, State::FramePayload);

            stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

            assert_eq!(
                stream.try_consume_frame(),
                Ok((frame, expected_payload_len))
            );
            assert_eq!(stream.state, State::FrameType);
        } else {
            assert_eq!(
                stream.set_frame_payload_len(frame_payload_len),
                Err(Error::ExcessiveLoad)
            );
        }
    }

    #[test]
    fn large_headers_default_limit() {
        let mut stream = open_remote_request_stream();
        let header_block = vec![0; 16384];
        let frame = Frame::Headers {
            header_block: header_block.clone(),
        };

        check_large_frame_size_limit(&mut stream, frame, 16384, true);
    }

    #[test]
    fn large_headers_limit_with_huffman() {
        // Create stream with a max_field_section_size limit of 4k.
        let mut stream = Stream::new(
            0,
            false,
            4196,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );

        // Size the header block so it will fit within the Huffman margin.
        // On this branch the margin is x + x/2 = 4196 + 2098 = 6294.
        let header_block = vec![0; 6294];
        let frame = Frame::Headers {
            header_block: header_block.clone(),
        };

        check_large_frame_size_limit(&mut stream, frame, 6294, true);
    }

    #[test]
    fn large_headers_small_limit() {
        // Create stream with a max_field_section_size limit of 4k.
        // Encoded headers at 16k are larger than the 4k limit.
        let mut stream = Stream::new(
            0,
            false,
            4196,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        let header_block = vec![0; 16384];
        let frame = Frame::Headers {
            header_block: header_block.clone(),
        };

        check_large_frame_size_limit(&mut stream, frame, 16384, false);
    }

    #[test]
    fn large_push_promise_default_limit() {
        let mut stream = open_remote_request_stream();
        let header_block = vec![0; 16384];
        let frame = Frame::PushPromise {
            push_id: 0,
            header_block: header_block.clone(),
        };

        check_large_frame_size_limit(&mut stream, frame, 1 + 16384, true);
    }

    #[test]
    fn large_push_promise_limit_with_huffman() {
        // Create stream with a max_field_section_size limit of 4k.
        let mut stream = Stream::new(
            0,
            false,
            4196,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );

        // Size the header block so it will fit within the Huffman margin.
        // On this branch the margin is x + x/2 = 4196 + 2098 = 6294.
        let header_block = vec![0; 6294];
        let frame = Frame::PushPromise {
            push_id: 0,
            header_block: header_block.clone(),
        };

        check_large_frame_size_limit(&mut stream, frame, 1 + 6294, true);
    }

    #[test]
    fn large_push_promise_small_limit() {
        // Create stream with a max_field_section_size limit of 4k.
        // Encoded push promise at 16k is larger than the 4k limit.
        let mut stream = Stream::new(
            0,
            false,
            4196,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        let header_block = vec![0; 16384];
        let frame = Frame::PushPromise {
            push_id: 0,
            header_block: header_block.clone(),
        };

        check_large_frame_size_limit(&mut stream, frame, 1 + 16384, false);
    }

    #[test]
    fn large_priority_update_large_limit() {
        let settings = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: Some(vec![]),
        };

        let mut d = vec![42; 20000];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Control stream needs a SETTINGS frame to transition it into
        // being able to parse other frame types.
        let mut stream = <Stream>::new(
            2,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            20000,
        );
        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
        settings.to_bytes(&mut b).unwrap();

        let priority_field_value = vec![0; 16384];
        let pu = Frame::PriorityUpdateRequest {
            prioritized_element_id: 0,
            priority_field_value,
        };

        pu.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
            .unwrap();

        // Skip SETTINGS frame type.
        parse_skip_frame(&mut stream, &mut cursor).unwrap();

        // Parse the frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 1 + 16384);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // Parse the frame.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        assert_eq!(stream.try_consume_frame(), Ok((pu, 1 + 16384)));
        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    fn large_priority_update_small_limit() {
        let settings = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: Some(vec![]),
        };

        let mut d = vec![42; 20000];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Control stream needs a SETTINGS frame to transition it into
        // being able to parse other frame types.
        let mut stream =
            <Stream>::new(2, false, SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT, 123);
        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();

        settings.to_bytes(&mut b).unwrap();

        let priority_field_value = vec![0; 16384];
        let pu = Frame::PriorityUpdateRequest {
            prioritized_element_id: 0,
            priority_field_value,
        };

        pu.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
            .unwrap();

        // Skip SETTINGS frame type.
        parse_skip_frame(&mut stream, &mut cursor).unwrap();

        // Parse the frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, 1 + 16384);

        assert_eq!(
            stream.set_frame_payload_len(frame_payload_len),
            Err(Error::ExcessiveLoad)
        );
    }

    #[test]
    fn finite_sized_frame_limits() {
        let settings = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: Some(vec![]),
        };

        for ty in [
            CANCEL_PUSH_FRAME_TYPE_ID,
            GOAWAY_FRAME_TYPE_ID,
            MAX_PUSH_FRAME_TYPE_ID,
        ] {
            // These frames must have a size between 1 and 8 bytes inclusive.
            for size in [0, 9] {
                let mut d = vec![42; 128];
                let mut b = octets::OctetsMut::with_slice(&mut d);

                // Control stream needs a SETTINGS frame to transition it into
                // being able to parse other frame types.
                let mut stream =
                    open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID).unwrap();
                settings.to_bytes(&mut b).unwrap();

                // Write bytes as far as frame length.
                b.put_varint(ty).unwrap();
                b.put_varint(size).unwrap();

                let mut cursor = std::io::Cursor::new(d);

                parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)
                    .unwrap();

                // Skip SETTINGS frame type.
                parse_skip_frame(&mut stream, &mut cursor).unwrap();

                // Parse frame type.
                stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
                let frame_ty = stream.try_consume_varint().unwrap();
                assert_eq!(frame_ty, ty);

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
    }

    #[test]
    fn zero_length_push_promise() {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let mut stream = open_remote_request_stream();

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        // Write a 0-length payload frame.
        b.put_varint(PUSH_PROMISE_FRAME_TYPE_ID).unwrap();
        b.put_varint(0).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, PUSH_PROMISE_FRAME_TYPE_ID);

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
    /// Drip feed data in chunks that exactly match spare capacity, forcing
    /// spare to hit 0 on every re-entry to try_fill_buffer_for_tests.
    fn large_state_buf_exact_spare_drip_feed() {
        const LARGE_HEADER_LEN: usize = 16384;
        let mut stream = Stream::new(
            0,
            false,
            LARGE_HEADER_LEN as u64,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );

        let mut d = vec![42; 20000];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Use nonzero fill to catch off-by-one errors in payload offset.
        let header_block = vec![0xAB; LARGE_HEADER_LEN];
        let hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };

        hdrs.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);
        stream.set_frame_type(frame_ty).unwrap();

        // Parse frame payload length.
        let frame_payload_len =
            parse_multibyte_varint(&mut stream, &mut cursor).unwrap();
        assert_eq!(frame_payload_len, LARGE_HEADER_LEN as u64);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);

        // After state transition, initial reserve gives us
        // MAX_STATE_BUF_ALLOC_SIZE of spare capacity.
        assert_eq!(stream.state_buf.capacity(), MAX_STATE_BUF_ALLOC_SIZE);
        assert_eq!(stream.state_buf.len(), 0);

        // Save the full cursor data then replace with an empty one so we
        // can drip feed exact amounts.
        let full_data = cursor.into_inner();
        let pos = 5; // 1 byte frame type + 4 byte varint (16384 >= 2^14)
        let payload_data = &full_data[pos..pos + LARGE_HEADER_LEN];

        // Drip feed in chunks that exactly match MAX_STATE_BUF_ALLOC_SIZE.
        // Each chunk fully consumes spare, so on re-entry spare is exactly 0
        // and spare_state_buf must reserve.
        let mut fed = 0;
        while fed + MAX_STATE_BUF_ALLOC_SIZE <= LARGE_HEADER_LEN {
            let chunk = &payload_data[fed..fed + MAX_STATE_BUF_ALLOC_SIZE];
            let mut chunk_cursor = std::io::Cursor::new(chunk.to_vec());

            let result = stream.try_fill_buffer_for_tests(&mut chunk_cursor);

            fed += MAX_STATE_BUF_ALLOC_SIZE;

            if fed < LARGE_HEADER_LEN {
                assert_eq!(result, Err(Error::Done));
                assert_eq!(stream.state_off, fed);
                // spare_state_buf should have reserved on each re-entry
                // since previous chunk consumed all spare.
                assert!(stream.state_buf.capacity() >= fed);
            } else {
                assert_eq!(result, Ok(()));
                assert_eq!(stream.state_off, LARGE_HEADER_LEN);
            }
        }

        assert_eq!(
            stream.try_consume_frame(),
            Ok((hdrs, LARGE_HEADER_LEN as u64))
        );
        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    /// Drip feed data in chunks smaller than spare capacity, so spare is
    /// small but nonzero on re-entry. Verifies that the buffer eventually
    /// grows when spare is fully consumed across multiple small reads.
    fn large_state_buf_small_leftover_spare() {
        const LARGE_HEADER_LEN: usize = 260000;
        let mut stream = Stream::new(
            0,
            false,
            LARGE_HEADER_LEN as u64,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );

        let mut d = vec![42; LARGE_HEADER_LEN + 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let header_block = vec![0; LARGE_HEADER_LEN];
        let hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };

        hdrs.to_bytes(&mut b).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);
        stream.set_frame_type(frame_ty).unwrap();

        // Parse frame payload length.
        let frame_payload_len =
            parse_multibyte_varint(&mut stream, &mut cursor).unwrap();
        assert_eq!(frame_payload_len, LARGE_HEADER_LEN as u64);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state, State::FramePayload);
        assert_eq!(stream.state_buf.capacity(), MAX_STATE_BUF_ALLOC_SIZE);

        let full_data = cursor.into_inner();
        let pos = 5; // 1 byte frame type + 4 byte varint length
        let payload_data = &full_data[pos..pos + LARGE_HEADER_LEN];

        // Drip feed 1000-byte chunks. These don't align with the 4096 spare
        // capacity, so spare will be nonzero but shrinking on each re-entry
        // until it hits 0 and forces a reserve.
        let chunk_size = 1000;
        let mut fed = 0;
        while fed < LARGE_HEADER_LEN {
            let end = std::cmp::min(fed + chunk_size, LARGE_HEADER_LEN);
            let chunk = &payload_data[fed..end];
            let mut chunk_cursor = std::io::Cursor::new(chunk.to_vec());

            let result = stream.try_fill_buffer_for_tests(&mut chunk_cursor);

            fed = end;

            if fed < LARGE_HEADER_LEN {
                assert_eq!(result, Err(Error::Done));
                assert_eq!(stream.state_off, fed);
                // Capacity must always be at least as large as what we've
                // buffered.
                assert!(stream.state_buf.capacity() >= stream.state_buf.len());
                // Capacity should grow incrementally. The allocator may
                // over-allocate (typically doubling), so we allow up to
                // 2x (bytes_read + reserve_size) to account for that.
                // The key property: capacity never jumps to the full
                // frame size before we've read a proportional amount.
                assert!(
                    stream.state_buf.capacity() <=
                        (fed + MAX_STATE_BUF_ALLOC_SIZE) * 2,
                    "capacity {} grew too far ahead of bytes read {} \
                     (max alloc size {})",
                    stream.state_buf.capacity(),
                    fed,
                    MAX_STATE_BUF_ALLOC_SIZE,
                );
            } else {
                assert_eq!(result, Ok(()));
            }
        }

        assert_eq!(
            stream.try_consume_frame(),
            Ok((hdrs, LARGE_HEADER_LEN as u64))
        );
        assert_eq!(stream.state, State::FrameType);
    }

    #[test]
    fn large_state_buf_allocation() {
        const LARGE_HEADER_LEN: usize = 260000;
        let mut stream = Stream::new(
            0,
            false,
            LARGE_HEADER_LEN as u64,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        assert_eq!(stream.state_buf.capacity(), 16);

        let mut d = vec![42; 5];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Drip feed a large HEADERS frame into the "stream"
        b.put_varint(HEADERS_FRAME_TYPE_ID).unwrap();
        b.put_varint(LARGE_HEADER_LEN as u64).unwrap();

        let mut cursor = std::io::Cursor::new(d);

        // Parse the HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        assert_eq!(stream.state_buf.capacity(), 16);

        let frame_ty = stream.try_consume_varint().unwrap();
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);
        assert_eq!(stream.state_buf.capacity(), 16);

        stream.set_frame_type(frame_ty).unwrap();
        assert_eq!(stream.state_buf.capacity(), 16);

        // Parse the HEADERS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        assert_eq!(stream.state_buf.capacity(), 16);

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor).unwrap();
        assert_eq!(stream.state_buf.capacity(), 16);

        let frame_payload_len = stream.try_consume_varint().unwrap();
        assert_eq!(frame_payload_len, LARGE_HEADER_LEN as u64);
        assert_eq!(stream.state_buf.capacity(), 16);

        stream.set_frame_payload_len(frame_payload_len).unwrap();
        assert_eq!(stream.state_buf.capacity(), MAX_STATE_BUF_ALLOC_SIZE);

        /// Assert state_len, state_off, and state_buf.capacity() in one
        /// call, with labeled messages on failure.
        fn assert_state_buf_props(
            stream: &Stream, len: usize, off: usize, capacity: usize,
        ) {
            assert_eq!(stream.state_len, len, "state_len");
            assert_eq!(stream.state_off, off, "state_off");
            assert_eq!(stream.state_buf.capacity(), capacity, "capacity");
        }

        // Start consuming HEADERS frame payload. It fails because the cursor
        // doesn't have the target size of data in it.
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            0,
            MAX_STATE_BUF_ALLOC_SIZE,
        );

        // Drip feed data into the cursor to emulate a series of transport
        // reads. After set_frame_payload_len, the initial reserve gives us
        // MAX_STATE_BUF_ALLOC_SIZE (4096) bytes of spare capacity.

        // Feed 2048 bytes: fits within the 4096 spare, no growth needed.
        cursor.get_mut().extend_from_slice(&[123; 2048]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            2048,
            MAX_STATE_BUF_ALLOC_SIZE,
        );

        // Feed 1024 bytes: still fits in the remaining 2048 spare.
        cursor.get_mut().extend_from_slice(&[123; 1024]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            3072,
            MAX_STATE_BUF_ALLOC_SIZE,
        );

        // Feed 512 bytes: fits in the remaining 1024 spare. Capacity
        // between state_off 4096 and 6144 stays stable because spare
        // doesn't hit 0.
        cursor.get_mut().extend_from_slice(&[123; 512]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            3584,
            MAX_STATE_BUF_ALLOC_SIZE,
        );

        // Feed 4096 bytes: exceeds the remaining 512 spare. The loop reads
        // 512 to fill spare, then spare hits 0, triggers a reserve of
        // MAX_STATE_BUF_ALLOC_SIZE (4096), and reads the remaining 3584.
        // The allocator doubles capacity from 4096 to 8192.
        cursor.get_mut().extend_from_slice(&[123; 4096]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            7680,
            MAX_STATE_BUF_ALLOC_SIZE * 2,
        );

        // Each subsequent feed exceeds spare (512 after the previous
        // reserve+read), so the loop drains the leftover spare, hits 0,
        // reserves MAX_STATE_BUF_ALLOC_SIZE, and the allocator doubles.
        cursor.get_mut().extend_from_slice(&[123; 8192]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            15872,
            MAX_STATE_BUF_ALLOC_SIZE * 4,
        );

        cursor.get_mut().extend_from_slice(&[123; 16384]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            32256,
            MAX_STATE_BUF_ALLOC_SIZE * 8,
        );

        cursor.get_mut().extend_from_slice(&[123; 32768]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            65024,
            MAX_STATE_BUF_ALLOC_SIZE * 16,
        );

        cursor.get_mut().extend_from_slice(&[123; 65536]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            130560,
            MAX_STATE_BUF_ALLOC_SIZE * 32,
        );

        // Feed the remaining bytes to complete the frame.
        let remaining = LARGE_HEADER_LEN - 130560;
        cursor.get_mut().extend_from_slice(&vec![123; remaining]);
        assert_eq!(stream.try_fill_buffer_for_tests(&mut cursor), Ok(()));
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            LARGE_HEADER_LEN,
            MAX_STATE_BUF_ALLOC_SIZE * 64,
        );

        let header_block = vec![123; LARGE_HEADER_LEN];
        let hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };
        assert_eq!(
            stream.try_consume_frame(),
            Ok((hdrs, LARGE_HEADER_LEN as u64))
        );
        assert_eq!(stream.state, State::FrameType);

        assert_state_buf_props(&stream, 1, 0, MAX_STATE_BUF_ALLOC_SIZE * 64);
    }
}
