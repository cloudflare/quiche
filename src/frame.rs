// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use crate::Error;
use crate::Result;

use crate::octets;
use crate::packet;
use crate::ranges;
use crate::stream;

pub const MAX_CRYPTO_OVERHEAD: usize = 8;
pub const MAX_STREAM_OVERHEAD: usize = 12;
pub const MAX_STREAM_SIZE: u64 = 1 << 62;

#[derive(Clone, PartialEq)]
pub enum Frame {
    Padding {
        len: usize,
    },

    Ping,

    ACK {
        ack_delay: u64,
        ranges: ranges::RangeSet,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        data: stream::RangeBuf,
    },

    NewToken {
        token: Vec<u8>,
    },

    Stream {
        stream_id: u64,
        data: stream::RangeBuf,
    },

    MaxData {
        max: u64,
    },

    MaxStreamData {
        stream_id: u64,
        max: u64,
    },

    MaxStreamsBidi {
        max: u64,
    },

    MaxStreamsUni {
        max: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlockedBidi {
        limit: u64,
    },

    StreamsBlockedUni {
        limit: u64,
    },

    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: Vec<u8>,
        reset_token: Vec<u8>,
    },

    RetireConnectionId {
        seq_num: u64,
    },

    PathChallenge {
        data: Vec<u8>,
    },

    PathResponse {
        data: Vec<u8>,
    },

    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },

    ApplicationClose {
        error_code: u64,
        reason: Vec<u8>,
    },

    HandshakeDone,
}

impl Frame {
    pub fn from_bytes(
        b: &mut octets::Octets, pkt: packet::Type,
    ) -> Result<Frame> {
        let frame_type = b.get_varint()?;

        // println!("GOT FRAME {:x}", frame_type);

        let frame = match frame_type {
            0x00 => {
                let mut len = 1;

                while b.peek_u8() == Ok(0x00) {
                    b.get_u8()?;

                    len += 1;
                }

                Frame::Padding { len }
            },

            0x01 => Frame::Ping,

            0x02 => parse_ack_frame(frame_type, b)?,

            0x04 => Frame::ResetStream {
                stream_id: b.get_varint()?,
                error_code: b.get_varint()?,
                final_size: b.get_varint()?,
            },

            0x05 => Frame::StopSending {
                stream_id: b.get_varint()?,
                error_code: b.get_varint()?,
            },

            0x06 => {
                let offset = b.get_varint()?;
                let data = b.get_bytes_with_varint_length()?;
                let data = stream::RangeBuf::from(data.as_ref(), offset, false);

                Frame::Crypto { data }
            },

            0x07 => Frame::NewToken {
                token: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x08..=0x0f => parse_stream_frame(frame_type, b)?,

            0x10 => Frame::MaxData {
                max: b.get_varint()?,
            },

            0x11 => Frame::MaxStreamData {
                stream_id: b.get_varint()?,
                max: b.get_varint()?,
            },

            0x12 => Frame::MaxStreamsBidi {
                max: b.get_varint()?,
            },

            0x13 => Frame::MaxStreamsUni {
                max: b.get_varint()?,
            },

            0x14 => Frame::DataBlocked {
                limit: b.get_varint()?,
            },

            0x15 => Frame::StreamDataBlocked {
                stream_id: b.get_varint()?,
                limit: b.get_varint()?,
            },

            0x16 => Frame::StreamsBlockedBidi {
                limit: b.get_varint()?,
            },

            0x17 => Frame::StreamsBlockedUni {
                limit: b.get_varint()?,
            },

            0x18 => Frame::NewConnectionId {
                seq_num: b.get_varint()?,
                retire_prior_to: b.get_varint()?,
                conn_id: b.get_bytes_with_u8_length()?.to_vec(),
                reset_token: b.get_bytes(16)?.to_vec(),
            },

            0x19 => Frame::RetireConnectionId {
                seq_num: b.get_varint()?,
            },

            0x1a => Frame::PathChallenge {
                data: b.get_bytes(8)?.to_vec(),
            },

            0x1b => Frame::PathResponse {
                data: b.get_bytes(8)?.to_vec(),
            },

            0x1c => Frame::ConnectionClose {
                error_code: b.get_varint()?,
                frame_type: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x1d => Frame::ApplicationClose {
                error_code: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x1e => Frame::HandshakeDone,

            _ => return Err(Error::InvalidFrame),
        };

        let allowed = match (pkt, &frame) {
            // PADDING and PING are allowed on all packet types.
            (_, Frame::Padding { .. }) | (_, Frame::Ping { .. }) => true,

            // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and
            // RETIRE_CONNECTION_ID can't be sent on 0-RTT packets.
            (packet::Type::ZeroRTT, Frame::ACK { .. }) => false,
            (packet::Type::ZeroRTT, Frame::Crypto { .. }) => false,
            (packet::Type::ZeroRTT, Frame::HandshakeDone) => false,
            (packet::Type::ZeroRTT, Frame::NewToken { .. }) => false,
            (packet::Type::ZeroRTT, Frame::PathResponse { .. }) => false,
            (packet::Type::ZeroRTT, Frame::RetireConnectionId { .. }) => false,
            (packet::Type::ZeroRTT, Frame::ConnectionClose { .. }) => false,

            // ACK, CRYPTO and CONNECTION_CLOSE can be sent on all other packet
            // types.
            (_, Frame::ACK { .. }) => true,
            (_, Frame::Crypto { .. }) => true,
            (_, Frame::ConnectionClose { .. }) => true,

            // All frames are allowed on 0-RTT and 1-RTT packets.
            (packet::Type::Short, _) => true,
            (packet::Type::ZeroRTT, _) => true,

            // All other cases are forbidden.
            (..) => false,
        };

        if !allowed {
            return Err(Error::InvalidPacket);
        }

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::Octets) -> Result<usize> {
        let before = b.cap();

        match self {
            Frame::Padding { len } => {
                let mut left = *len;

                while left > 0 {
                    b.put_varint(0x00)?;

                    left -= 1;
                }
            },

            Frame::Ping => {
                b.put_varint(0x01)?;
            },

            Frame::ACK { ack_delay, ranges } => {
                b.put_varint(0x02)?;

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

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                b.put_varint(0x04)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*error_code)?;
                b.put_varint(*final_size)?;
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                b.put_varint(0x05)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*error_code)?;
            },

            Frame::Crypto { data } => {
                b.put_varint(0x06)?;

                b.put_varint(data.off() as u64)?;
                b.put_varint(data.len() as u64)?;
                b.put_bytes(&data)?;
            },

            Frame::NewToken { token } => {
                b.put_varint(0x07)?;

                b.put_varint(token.len() as u64)?;
                b.put_bytes(&token)?;
            },

            Frame::Stream { stream_id, data } => {
                let mut ty: u8 = 0x08;

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
            },

            Frame::MaxData { max } => {
                b.put_varint(0x10)?;

                b.put_varint(*max)?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                b.put_varint(0x11)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*max)?;
            },

            Frame::MaxStreamsBidi { max } => {
                b.put_varint(0x12)?;

                b.put_varint(*max)?;
            },

            Frame::MaxStreamsUni { max } => {
                b.put_varint(0x13)?;

                b.put_varint(*max)?;
            },

            Frame::DataBlocked { limit } => {
                b.put_varint(0x14)?;

                b.put_varint(*limit)?;
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                b.put_varint(0x15)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*limit)?;
            },

            Frame::StreamsBlockedBidi { limit } => {
                b.put_varint(0x16)?;

                b.put_varint(*limit)?;
            },

            Frame::StreamsBlockedUni { limit } => {
                b.put_varint(0x17)?;

                b.put_varint(*limit)?;
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                b.put_varint(0x18)?;

                b.put_varint(*seq_num)?;
                b.put_varint(*retire_prior_to)?;
                b.put_u8(conn_id.len() as u8)?;
                b.put_bytes(conn_id.as_ref())?;
                b.put_bytes(reset_token.as_ref())?;
            },

            Frame::RetireConnectionId { seq_num } => {
                b.put_varint(0x19)?;

                b.put_varint(*seq_num)?;
            },

            Frame::PathChallenge { data } => {
                b.put_varint(0x1a)?;

                b.put_bytes(data.as_ref())?;
            },

            Frame::PathResponse { data } => {
                b.put_varint(0x1b)?;

                b.put_bytes(data.as_ref())?;
            },

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                b.put_varint(0x1c)?;

                b.put_varint(*error_code)?;
                b.put_varint(*frame_type)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                b.put_varint(0x1d)?;

                b.put_varint(*error_code)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Frame::HandshakeDone => {
                b.put_varint(0x1e)?;
            },
        }

        Ok(before - b.cap())
    }

    pub fn wire_len(&self) -> usize {
        match self {
            Frame::Padding { len } => *len,

            Frame::Ping => 1,

            Frame::ACK { ack_delay, ranges } => {
                let mut it = ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                let mut len = 1 + // frame type
                    octets::varint_len(first.end - 1) + // largest_ack
                    octets::varint_len(*ack_delay) + // ack_delay
                    octets::varint_len(it.len() as u64) + // block_count
                    octets::varint_len(ack_block); // first_block

                let mut smallest_ack = first.start;

                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;

                    len += octets::varint_len(gap) + // gap
                           octets::varint_len(ack_block); // ack_block

                    smallest_ack = block.start;
                }

                len
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*error_code) + // error_code
                octets::varint_len(*final_size) // final_size
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*error_code) // error_code
            },

            Frame::Crypto { data } => {
                1 + // frame type
                octets::varint_len(data.off() as u64) + // offset
                octets::varint_len(data.len() as u64) + // length
                data.len() // data
            },

            Frame::NewToken { token } => {
                1 + // frame type
                octets::varint_len(token.len() as u64) + // token length
                token.len() // token
            },

            Frame::Stream { stream_id, data } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(data.off() as u64) + // offset
                octets::varint_len(data.len() as u64) + // length
                data.len() // data
            },

            Frame::MaxData { max } => {
                1 + // frame type
                octets::varint_len(*max) // max
            },

            Frame::MaxStreamData { stream_id, max } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*max) // max
            },

            Frame::MaxStreamsBidi { max } => {
                1 + // frame type
                octets::varint_len(*max) // max
            },

            Frame::MaxStreamsUni { max } => {
                1 + // frame type
                octets::varint_len(*max) // max
            },

            Frame::DataBlocked { limit } => {
                1 + // frame type
                octets::varint_len(*limit) // limit
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                1 + // frame type
                octets::varint_len(*stream_id) + // stream_id
                octets::varint_len(*limit) // limit
            },

            Frame::StreamsBlockedBidi { limit } => {
                1 + // frame type
                octets::varint_len(*limit) // limit
            },

            Frame::StreamsBlockedUni { limit } => {
                1 + // frame type
                octets::varint_len(*limit) // limit
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                1 + // frame type
                octets::varint_len(*seq_num) + // seq_num
                octets::varint_len(*retire_prior_to) + // retire_prior_to
                1 + // conn_id length
                conn_id.len() + // conn_id
                reset_token.len() // reset_token
            },

            Frame::RetireConnectionId { seq_num } => {
                1 + // frame type
                octets::varint_len(*seq_num) // seq_num
            },

            Frame::PathChallenge { .. } => {
                1 + // frame type
                8 // data
            },

            Frame::PathResponse { .. } => {
                1 + // frame type
                8 // data
            },

            Frame::ConnectionClose {
                frame_type,
                error_code,
                reason,
                ..
            } => {
                1 + // frame type
                octets::varint_len(*error_code) + // error_code
                octets::varint_len(*frame_type) + // frame_type
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len() // reason
            },

            Frame::ApplicationClose { reason, error_code } => {
                1 + // frame type
                octets::varint_len(*error_code) + // error_code
                octets::varint_len(reason.len() as u64) + // reason_len
                reason.len() // reason
            },

            Frame::HandshakeDone => {
                1 // frame type
            },
        }
    }

    pub fn ack_eliciting(&self) -> bool {
        match self {
            Frame::Padding { .. } |
            Frame::ACK { .. } |
            Frame::ApplicationClose { .. } |
            Frame::ConnectionClose { .. } => false,

            _ => true,
        }
    }

    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self) -> qlog::QuicFrame {
        match self {
            Frame::Padding { .. } => qlog::QuicFrame::padding(),

            Frame::Ping { .. } => qlog::QuicFrame::ping(),

            Frame::ACK { ack_delay, ranges } => {
                let ack_ranges =
                    ranges.iter().map(|r| (r.start, r.end - 1)).collect();
                qlog::QuicFrame::ack(
                    Some(ack_delay.to_string()),
                    Some(ack_ranges),
                    None,
                    None,
                    None,
                )
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => qlog::QuicFrame::reset_stream(
                stream_id.to_string(),
                *error_code,
                final_size.to_string(),
            ),

            Frame::StopSending {
                stream_id,
                error_code,
            } =>
                qlog::QuicFrame::stop_sending(stream_id.to_string(), *error_code),

            Frame::Crypto { data } => qlog::QuicFrame::crypto(
                data.off().to_string(),
                data.len().to_string(),
            ),

            Frame::NewToken { token } => qlog::QuicFrame::new_token(
                token.len().to_string(),
                "TODO: https://github.com/quiclog/internet-drafts/issues/36"
                    .to_string(),
            ),

            Frame::Stream { stream_id, data } => qlog::QuicFrame::stream(
                stream_id.to_string(),
                data.off().to_string(),
                data.len().to_string(),
                data.fin(),
                None,
            ),

            Frame::MaxData { max } => qlog::QuicFrame::max_data(max.to_string()),

            Frame::MaxStreamData { stream_id, max } =>
                qlog::QuicFrame::max_stream_data(
                    stream_id.to_string(),
                    max.to_string(),
                ),

            Frame::MaxStreamsBidi { max } => qlog::QuicFrame::max_streams(
                qlog::StreamType::Bidirectional,
                max.to_string(),
            ),

            Frame::MaxStreamsUni { max } => qlog::QuicFrame::max_streams(
                qlog::StreamType::Unidirectional,
                max.to_string(),
            ),

            Frame::DataBlocked { limit } =>
                qlog::QuicFrame::data_blocked(limit.to_string()),

            Frame::StreamDataBlocked { stream_id, limit } =>
                qlog::QuicFrame::stream_data_blocked(
                    stream_id.to_string(),
                    limit.to_string(),
                ),

            Frame::StreamsBlockedBidi { limit } =>
                qlog::QuicFrame::streams_blocked(
                    qlog::StreamType::Bidirectional,
                    limit.to_string(),
                ),

            Frame::StreamsBlockedUni { limit } =>
                qlog::QuicFrame::streams_blocked(
                    qlog::StreamType::Unidirectional,
                    limit.to_string(),
                ),

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                ..
            } => qlog::QuicFrame::new_connection_id(
                seq_num.to_string(),
                retire_prior_to.to_string(),
                conn_id.len() as u64,
                "TODO: https://github.com/quiclog/internet-drafts/issues/36"
                    .to_string(),
                "TODO: https://github.com/quiclog/internet-drafts/issues/36"
                    .to_string(),
            ),

            Frame::RetireConnectionId { seq_num } =>
                qlog::QuicFrame::retire_connection_id(seq_num.to_string()),

            Frame::PathChallenge { .. } => qlog::QuicFrame::path_challenge(Some(
                "TODO: https://github.com/quiclog/internet-drafts/issues/36"
                    .to_string(),
            )),

            Frame::PathResponse { .. } => qlog::QuicFrame::path_response(Some(
                "TODO: https://github.com/quiclog/internet-drafts/issues/36"
                    .to_string(),
            )),

            Frame::ConnectionClose {
                error_code, reason, ..
            } => qlog::QuicFrame::connection_close(
                qlog::ErrorSpace::TransportError,
                *error_code,
                *error_code,
                String::from_utf8(reason.clone()).unwrap(),
                Some(
                    "TODO: https://github.com/quiclog/internet-drafts/issues/36"
                        .to_string(),
                ),
            ),

            Frame::ApplicationClose { error_code, reason } =>
                qlog::QuicFrame::connection_close(
                    qlog::ErrorSpace::ApplicationError,
                    *error_code,
                    *error_code,
                    String::from_utf8(reason.clone()).unwrap(),
                    None, /* Application variant of the frame has no trigger
                           * frame type */
                ),

            _ => qlog::QuicFrame::unknown(std::u64::MAX),
        }
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Padding { len } => {
                write!(f, "PADDING len={}", len)?;
            },

            Frame::Ping => {
                write!(f, "PING")?;
            },

            Frame::ACK { ack_delay, ranges } => {
                write!(f, "ACK delay={} blocks={:?}", ack_delay, ranges)?;
            },

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                write!(
                    f,
                    "RESET_STREAM stream={} err={:x} size={}",
                    stream_id, error_code, final_size
                )?;
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                write!(
                    f,
                    "STOP_SENDING stream={} err={:x}",
                    stream_id, error_code
                )?;
            },

            Frame::Crypto { data } => {
                write!(f, "CRYPTO off={} len={}", data.off(), data.len())?;
            },

            Frame::NewToken { .. } => {
                write!(f, "NEW_TOKEN (TODO)")?;
            },

            Frame::Stream { stream_id, data } => {
                write!(
                    f,
                    "STREAM id={} off={} len={} fin={}",
                    stream_id,
                    data.off(),
                    data.len(),
                    data.fin()
                )?;
            },

            Frame::MaxData { max } => {
                write!(f, "MAX_DATA max={}", max)?;
            },

            Frame::MaxStreamData { stream_id, max } => {
                write!(f, "MAX_STREAM_DATA stream={} max={}", stream_id, max)?;
            },

            Frame::MaxStreamsBidi { max } => {
                write!(f, "MAX_STREAMS type=bidi max={}", max)?;
            },

            Frame::MaxStreamsUni { max } => {
                write!(f, "MAX_STREAMS type=uni max={}", max)?;
            },

            Frame::DataBlocked { limit } => {
                write!(f, "DATA_BLOCKED limit={}", limit)?;
            },

            Frame::StreamDataBlocked { stream_id, limit } => {
                write!(
                    f,
                    "STREAM_DATA_BLOCKED stream={} limit={}",
                    stream_id, limit
                )?;
            },

            Frame::StreamsBlockedBidi { limit } => {
                write!(f, "STREAMS_BLOCKED type=bidi limit={}", limit)?;
            },

            Frame::StreamsBlockedUni { limit } => {
                write!(f, "STREAMS_BLOCKED type=uni limit={}", limit)?;
            },

            Frame::NewConnectionId { .. } => {
                write!(f, "NEW_CONNECTION_ID (TODO)")?;
            },

            Frame::RetireConnectionId { .. } => {
                write!(f, "RETIRE_CONNECTION_ID (TODO)")?;
            },

            Frame::PathChallenge { data } => {
                write!(f, "PATH_CHALLENGE data={:02x?}", data)?;
            },

            Frame::PathResponse { data } => {
                write!(f, "PATH_RESPONSE data={:02x?}", data)?;
            },

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                write!(
                    f,
                    "CONNECTION_CLOSE err={:x} frame={:x} reason={:x?}",
                    error_code, frame_type, reason
                )?;
            },

            Frame::ApplicationClose { error_code, reason } => {
                write!(
                    f,
                    "APPLICATION_CLOSE err={:x} reason={:x?}",
                    error_code, reason
                )?;
            },

            Frame::HandshakeDone => {
                write!(f, "HANDSHAKE_DONE")?;
            },
        }

        Ok(())
    }
}

fn parse_ack_frame(_ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let largest_ack = b.get_varint()?;
    let ack_delay = b.get_varint()?;
    let block_count = b.get_varint()?;
    let ack_block = b.get_varint()?;

    if largest_ack < ack_block {
        return Err(Error::InvalidFrame);
    }

    let mut smallest_ack = largest_ack - ack_block;

    let mut ranges = ranges::RangeSet::default();

    #[allow(clippy::range_plus_one)]
    ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..block_count {
        let gap = b.get_varint()?;

        if smallest_ack < 2 + gap {
            return Err(Error::InvalidFrame);
        }

        let largest_ack = (smallest_ack - gap) - 2;
        let ack_block = b.get_varint()?;

        if largest_ack < ack_block {
            return Err(Error::InvalidFrame);
        }

        smallest_ack = largest_ack - ack_block;

        #[allow(clippy::range_plus_one)]
        ranges.insert(smallest_ack..largest_ack + 1);
    }

    Ok(Frame::ACK { ack_delay, ranges })
}

fn parse_stream_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
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

    if offset + len as u64 >= MAX_STREAM_SIZE {
        return Err(Error::InvalidFrame);
    }

    let fin = first & 0x01 != 0;

    let data = b.get_bytes(len)?;
    let data = stream::RangeBuf::from(data.as_ref(), offset, fin);

    Ok(Frame::Stream { stream_id, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        let mut d = [42; 128];

        let frame = Frame::Padding { len: 128 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 128);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_ok());
    }

    #[test]
    fn ping() {
        let mut d = [42; 128];

        let frame = Frame::Ping;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 1);
        assert_eq!(&d[..wire_len], [0x01 as u8]);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_ok());
    }

    #[test]
    fn ack() {
        let mut d = [42; 128];

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
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_ok());
    }

    #[test]
    fn reset_stream() {
        let mut d = [42; 128];

        let frame = Frame::ResetStream {
            stream_id: 123_213,
            error_code: 21_123_767,
            final_size: 21_123_767,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 13);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn stop_sending() {
        let mut d = [42; 128];

        let frame = Frame::StopSending {
            stream_id: 123_213,
            error_code: 15_352,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn crypto() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Crypto {
            data: stream::RangeBuf::from(&data, 1230976, false),
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 18);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_ok());
    }

    #[test]
    fn new_token() {
        let mut d = [42; 128];

        let frame = Frame::NewToken {
            token: Vec::from("this is a token"),
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn stream() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: stream::RangeBuf::from(&data, 1230976, true),
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 19);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn stream_too_big() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: stream::RangeBuf::from(&data, MAX_STREAM_SIZE - 11, true),
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 23);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short),
            Err(Error::InvalidFrame)
        );
    }

    #[test]
    fn max_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxData { max: 128_318_273 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn max_stream_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamData {
            stream_id: 12_321,
            max: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn max_streams_bidi() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsBidi { max: 128_318_273 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn max_streams_uni() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsUni { max: 128_318_273 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::DataBlocked { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn stream_data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::StreamDataBlocked {
            stream_id: 12_321,
            limit: 128_318_273,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn streams_blocked_bidi() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedBidi { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn streams_blocked_uni() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedUni { limit: 128_318_273 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn new_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::NewConnectionId {
            seq_num: 123_213,
            retire_prior_to: 122_211,
            conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            reset_token: vec![0x42; 16],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 41);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn retire_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::RetireConnectionId { seq_num: 123_213 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn path_challenge() {
        let mut d = [42; 128];

        let frame = Frame::PathChallenge {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn path_response() {
        let mut d = [42; 128];

        let frame = Frame::PathResponse {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn connection_close() {
        let mut d = [42; 128];

        let frame = Frame::ConnectionClose {
            error_code: 0xbeef,
            frame_type: 523_423,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 22);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_ok());
    }

    #[test]
    fn application_close() {
        let mut d = [42; 128];

        let frame = Frame::ApplicationClose {
            error_code: 0xbeef,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 18);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }

    #[test]
    fn handshake_done() {
        let mut d = [42; 128];

        let frame = Frame::HandshakeDone;

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 1);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_err());

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());
    }
}
