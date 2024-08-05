// Copyright (C) 2024, Cloudflare, Inc.
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

//! Stateful parsing of QUIC streams into HTTP/3 frames.

use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Error as H3Error;
use quiche::h3::Result;
use quiche::Connection;

use crate::frame::H3iFrame;

/// Max stream state size in bytes (2MB).
const MAX_STREAM_STATE_SIZE: usize = 2_000_000;

#[derive(Debug, Default, PartialEq, Eq)]
enum FrameState {
    #[default]
    Type,
    Len,
    Val,
}

#[derive(Debug, Eq, PartialEq)]
/// The reason that frame parsing was interrupted.
pub enum InterruptCause {
    FinBit,
    ResetStream(u64),
}

#[derive(Debug, Eq, PartialEq)]
/// Represents different frame parsing outcomes.
pub enum FrameParseResult {
    /// The frame was unable to be parsed at the current moment. This signifies
    /// that the stream is retryable without another I/O cycle. If another
    /// I/O cycle is needed, a [`quiche::h3::Error::TransportError`]
    /// containing [`quiche::Error::Done`] will be returned.
    Retry,
    /// A frame has been successfully parsed. `fin` denotes if the FIN bit was
    /// set.
    FrameParsed { h3i_frame: H3iFrame, fin: bool },
    /// A frame is in the middle of being parsed, but either a FIN bit or a
    /// RESET_STREAM was received.
    Interrupted(InterruptCause),
}

/// Parses [`H3iFrame`]s from a QUIC stream.
///
/// Each `FrameParser` instance is bound to a single stream when created.
/// [`FrameParser::try_parse_frame()`] will attempt to pull stream data from a
/// [`quiche::Connection`] and build a complete frame.
///
/// There are various success and failure criteria, see `try_parse_frame()` for
/// specific guidance.
pub(crate) struct FrameParser {
    ty: Option<u64>,
    len: Option<u64>,

    stream_id: u64,

    curr_state: FrameState,
    state_buf: Vec<u8>,
    state_offset: usize,
    state_len: usize,
}

impl FrameParser {
    pub(crate) fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            ..Default::default()
        }
    }

    /// Attempt to pull stream data from a [`quiche::Connection`] and build a
    /// complete frame.
    ///
    /// On success, [FrameParseResult::FrameParsed] is returned. The caller
    /// should keep calling try_parse_frame() to read a series of frames
    /// from the stream.
    ///
    /// [FrameParseResult::Retry] signifies that the parser's internal state
    /// requires another attempt to read stream data, but the stream is
    /// still readable. `try_parse_frame()` should be retried without
    /// executing another I/O cycle.
    ///
    /// If the available stream data does not provide a complete frame, a
    /// [`quiche::h3::Error::TransportError`] containing [`quiche::Error::Done`]
    /// is returned. Callers should execute an I/O cycle before calling
    /// try_parse_frame() again.
    ///
    /// If the stream is terminated, either by FIN or reset,
    /// [FrameParseResult::Interrupted] is returned. The caller should cease
    /// calling methods on the stream since the stream is closed.
    pub(crate) fn try_parse_frame(
        &mut self, qconn: &mut Connection,
    ) -> Result<FrameParseResult> {
        loop {
            let (len, fin) = match self.try_fill_buffer(qconn, self.stream_id) {
                Ok((l, f)) => (l, f),
                Err(H3Error::TransportError(quiche::Error::StreamReset(err))) =>
                    return Ok(FrameParseResult::Interrupted(
                        InterruptCause::ResetStream(err),
                    )),
                Err(e) => return Err(e),
            };

            log::trace!(
                "{} stream={} read bytes={len:?}",
                qconn.trace_id(),
                self.stream_id
            );

            if fin && self.frame_incomplete() {
                return Ok(FrameParseResult::Interrupted(InterruptCause::FinBit));
            };

            match self.curr_state {
                FrameState::Type => {
                    let Ok(varint) = self.try_consume_varint() else {
                        // Map Error::Done's to Retry's because state_buf must be
                        // resized to fit a larger varint
                        return Ok(FrameParseResult::Retry);
                    };

                    self.set_frame_type(varint)?;
                    self.state_transition(FrameState::Len, 1)?;
                },
                FrameState::Len => {
                    let Ok(varint) = self.try_consume_varint() else {
                        // Map Error::Done's to Retry's because state_buf must be
                        // resized to fit a larger varint
                        return Ok(FrameParseResult::Retry);
                    };

                    self.set_frame_len(varint)?;
                    self.state_transition(
                        FrameState::Val,
                        self.len.expect("frame len is not set") as usize,
                    )?;
                },
                FrameState::Val => {
                    if self.state_buffer_complete() {
                        let h3i_frame = self.build_h3i_frame()?;
                        // unwraps are safe now
                        let ty = match self.ty.unwrap() {
                            0x0 => "DATA".to_string(),
                            0x1 => "HEADERS".to_string(),
                            0x3 => "CANCEL_PUSH".to_string(),
                            0x4 => "SETTINGS".to_string(),
                            0x5 => "PUSH_PROMISE".to_string(),
                            0x7 => "GOAWAY".to_string(),
                            0xd => "MAX_PUSH_AWAY".to_string(),
                            _ => format!("UNKNOWN val={}", self.ty.unwrap()),
                        };
                        log::info!(
                            "{} stream={} frame rx ty={} len={}",
                            qconn.trace_id(),
                            self.stream_id,
                            ty,
                            self.len.unwrap()
                        );

                        // Reset the states for the next frame
                        *self = Self::new(self.stream_id);
                        return Ok(FrameParseResult::FrameParsed {
                            h3i_frame,
                            fin,
                        });
                    };

                    // No need to map to Retry here since we've exhausted the
                    // received bytes and must try another I/O
                    // cycle
                    return Err(H3Error::TransportError(quiche::Error::Done));
                },
            }
        }
    }

    fn frame_incomplete(&self) -> bool {
        !self.state_buf.is_empty() && !self.state_buffer_complete()
    }

    fn try_fill_buffer(
        &mut self, qconn: &mut Connection, stream_id: u64,
    ) -> Result<(usize, bool)> {
        if self.state_buffer_complete() {
            return Ok((0, qconn.stream_finished(stream_id)));
        }

        let buf = &mut self.state_buf[self.state_offset..self.state_len];
        match qconn.stream_recv(stream_id, buf) {
            Ok((len, fin)) => {
                self.state_offset += len;
                Ok((len, fin))
            },
            Err(e) => Err(H3Error::TransportError(e)),
        }
    }

    fn try_consume_varint(&mut self) -> Result<u64> {
        if self.state_offset == 1 {
            self.state_len = octets::varint_parse_len(self.state_buf[0]);
            self.state_buf.resize(self.state_len, 0);
        }

        if !self.state_buffer_complete() {
            return Err(H3Error::TransportError(quiche::Error::Done));
        }

        let varint = octets::Octets::with_slice(&self.state_buf).get_varint()?;
        Ok(varint)
    }

    fn state_buffer_complete(&self) -> bool {
        self.state_offset == self.state_len
    }

    fn state_transition(
        &mut self, new_state: FrameState, expected_len: usize,
    ) -> Result<()> {
        // A peer can influence the size of the state buffer (e.g. with the
        // payload size of a GREASE frame), so we need to limit the maximum
        // size to avoid DoS.
        if expected_len > MAX_STREAM_STATE_SIZE {
            return Err(quiche::h3::Error::ExcessiveLoad);
        }

        self.state_buf.resize(expected_len, 0);
        self.curr_state = new_state;
        self.state_offset = 0;
        self.state_len = expected_len;

        Ok(())
    }

    fn set_frame_type(&mut self, ty: u64) -> Result<()> {
        self.ty = Some(ty);
        self.state_transition(FrameState::Len, 1)?;

        Ok(())
    }

    fn set_frame_len(&mut self, len: u64) -> Result<()> {
        self.len = Some(len);
        self.state_transition(FrameState::Val, len as usize)?;

        Ok(())
    }

    fn build_h3i_frame(&mut self) -> Result<H3iFrame> {
        let qframe = QFrame::from_bytes(
            self.ty.expect("frame ty not set"),
            self.len.expect("frame len not set"),
            &self.state_buf,
        )?;

        match qframe {
            QFrame::Headers { ref header_block } => {
                let mut qpack_decoder = quiche::h3::qpack::Decoder::new();
                let headers =
                    qpack_decoder.decode(header_block, u64::MAX).unwrap();

                Ok(H3iFrame::Headers(headers.into()))
            },
            _ => Ok(qframe.into()),
        }
    }
}

impl std::fmt::Debug for FrameParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!(
            "FrameParser {{ stream: {}, type: {:?}, length: {:?} }}",
            self.stream_id, self.ty, self.len,
        );

        write!(f, "{}", s)
    }
}

impl Default for FrameParser {
    fn default() -> Self {
        Self {
            ty: None,
            len: None,
            curr_state: FrameState::default(),
            stream_id: 0,
            state_buf: vec![0],
            state_offset: 0,
            state_len: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::frame::Frame;
    use quiche::h3::testing::*;

    pub fn path_relative_to_manifest_dir(
        path: impl AsRef<std::path::Path>,
    ) -> String {
        std::fs::canonicalize(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path),
        )
        .unwrap()
        .to_string_lossy()
        .into_owned()
    }

    // TODO: remove this and use Session::new() when https://github.com/cloudflare/quiche/pull/1805
    // lands
    fn session() -> Result<Session> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file(&path_relative_to_manifest_dir(
            "../quiche/examples/cert.crt",
        ))?;
        config.load_priv_key_from_pem_file(&path_relative_to_manifest_dir(
            "../quiche/examples/cert.key",
        ))?;
        config.set_application_protos(&[b"h3"])?;
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.enable_dgram(true, 3, 3);
        config.set_ack_delay_exponent(8);

        let h3_config = quiche::h3::Config::new()?;
        Session::with_configs(&mut config, &h3_config)
    }

    // See https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc for
    // encoding scheme. 64 is the lowest number that can be parsed with a 2-byte
    // varint, so it's used in all tests so they're easier to reason about
    #[test]
    fn simple_case() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::new(0);
        let expected = Frame::Data {
            payload: vec![1, 2, 3, 4, 5],
        };
        s.send_frame_client(expected.clone(), 0, true)
            .expect("first");

        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn type_precedes_split() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::new(0);
        let expected = Frame::Data {
            payload: vec![10; 10],
        };
        s.send_arbitrary_stream_data_client(&[0], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[10; 11], 0, true)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn type_multiple_bytes() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::new(0);
        let expected = Frame::Unknown {
            raw_type: 64,
            payload: vec![1, 2, 3, 4, 5],
        };
        s.send_arbitrary_stream_data_client(&[64, 64, 5, 1, 2, 3, 4, 5], 0, true)
            .expect("first");

        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn type_multiple_buffers() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::new(0);
        let expected = Frame::Unknown {
            raw_type: 64,
            payload: vec![1, 2, 3, 4, 5],
        };

        s.send_arbitrary_stream_data_client(&[64], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[64, 5, 1, 2, 3, 4, 5], 0, true)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn type_multiple_buffers_precedes_split() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Unknown {
            raw_type: 64,
            payload: vec![1, 2, 3, 4, 5],
        };

        s.send_arbitrary_stream_data_client(&[64, 64], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[5, 1, 2, 3, 4, 5], 0, false)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: false
        });
    }

    #[test]
    fn len_precedes_split() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: vec![57; 10],
        };

        s.send_arbitrary_stream_data_client(&[0, 10], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[57; 10], 0, true)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn len_multiple_bytes() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut b = vec![0, 64, 64];
        let mut payload = vec![0; 64];
        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: payload.clone(),
        };
        b.append(&mut payload);

        s.send_arbitrary_stream_data_client(&b, 0, true)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn len_multiple_buffers() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: vec![64; 64],
        };

        s.send_arbitrary_stream_data_client(&[0, 64], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[64; 65], 0, true)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn len_multiple_buffers_precedes_split() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: vec![0; 64],
        };

        s.send_arbitrary_stream_data_client(&[0, 64, 64], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[0; 64], 0, true)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: true
        });
    }

    #[test]
    fn no_val() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let first = Frame::Unknown {
            raw_type: 64,
            payload: vec![],
        };
        let second = Frame::Data {
            payload: vec![1, 2, 3],
        };

        s.send_arbitrary_stream_data_client(&[64, 64, 0, 0, 3, 1, 2, 3], 0, true)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::Retry);

        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(first),
            fin: false
        });

        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(second),
            fin: true
        });
    }

    #[test]
    fn val_multiple_buffers() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: vec![1, 2, 3, 4, 5],
        };

        s.send_arbitrary_stream_data_client(&[0, 5, 1], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));

        s.send_arbitrary_stream_data_client(&[2, 3, 4, 5], 0, false)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: false
        });
    }

    #[test]
    fn val_doesnt_extend_to_buffer_end() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: vec![1, 2, 3, 4, 5],
        };

        s.send_arbitrary_stream_data_client(&[0, 5, 1, 2, 3, 4, 5, 0], 0, true)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: false
        });

        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));
        assert_eq!(parser.ty, Some(0));
        assert_eq!(parser.curr_state, FrameState::Len);
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let first = Frame::Data {
            payload: vec![1, 2, 3],
        };
        let second = Frame::Data {
            payload: vec![1, 2, 3, 4],
        };

        s.send_arbitrary_stream_data_client(
            &[0, 3, 1, 2, 3, 0, 4, 1, 2, 3, 4],
            0,
            true,
        )
        .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(first),
            fin: false
        });
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(second),
            fin: true
        });
    }

    #[test]
    fn multiple_frames_multiple_buffers() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let first = Frame::Data {
            payload: vec![1, 2, 3],
        };
        let second = Frame::Data {
            payload: vec![1, 2, 3, 4],
        };
        let third = Frame::Data {
            payload: vec![1, 2, 3],
        };

        s.send_arbitrary_stream_data_client(
            &[0, 3, 1, 2, 3, 0, 4, 1, 2, 3, 4, 0, 3, 1],
            0,
            false,
        )
        .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(first),
            fin: false
        });
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(second),
            fin: false
        });

        let res = parser.try_parse_frame(&mut s.pipe.server);
        assert_eq!(res, Err(H3Error::TransportError(quiche::Error::Done)));
        assert_eq!(parser.ty, Some(0));
        assert_eq!(parser.len, Some(3));
        assert_eq!(parser.state_buf, vec![1, 0, 0]);

        s.send_arbitrary_stream_data_client(&[2, 3], 0, true)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(third),
            fin: true
        });
    }

    #[test]
    fn multiple_frames_nonzero_stream() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let first = Frame::Data {
            payload: vec![1, 2, 3],
        };
        let second = Frame::Data {
            payload: vec![1, 2, 3, 4, 5],
        };

        s.send_arbitrary_stream_data_client(&[0, 3, 1, 2, 3], 0, true)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(first.clone()),
            fin: true
        });

        parser = FrameParser::new(4);
        s.send_arbitrary_stream_data_client(&[0, 5, 1, 2, 3, 4, 5], 4, false)
            .expect("second");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(second),
            fin: false
        });

        s.send_arbitrary_stream_data_client(&[0, 3, 1, 2, 3], 4, true)
            .expect("third");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(first),
            fin: true
        });
    }

    #[test]
    fn interrupted() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        s.send_arbitrary_stream_data_client(&[0, 3, 1, 2], 0, true)
            .expect("send");

        assert_eq!(
            parser.try_parse_frame(&mut s.pipe.server),
            Ok(FrameParseResult::Interrupted(InterruptCause::FinBit))
        );
    }

    #[test]
    fn stream_reset() {
        let mut s = session().unwrap();
        s.handshake().unwrap();

        let mut parser = FrameParser::default();
        let expected = Frame::Data {
            payload: vec![1, 2, 3, 4, 5],
        };

        s.send_arbitrary_stream_data_client(&[0, 5, 1, 2, 3, 4, 5], 0, false)
            .expect("first");
        let res = parser.try_parse_frame(&mut s.pipe.server).unwrap();
        assert_eq!(res, FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(expected),
            fin: false
        });

        s.pipe
            .client
            .stream_shutdown(0, quiche::Shutdown::Write, 0)
            .expect("shutdown");
        s.pipe.advance().expect("advance");
        assert_eq!(
            parser.try_parse_frame(&mut s.pipe.server),
            Ok(FrameParseResult::Interrupted(InterruptCause::ResetStream(
                0
            )))
        );
    }
}
