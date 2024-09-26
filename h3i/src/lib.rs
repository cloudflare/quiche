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

//! h3i - low-level HTTP/3 debug and testing
//!
//! HTTP/3 ([RFC 9114]) is the wire format for HTTP semantics ([RFC 9110]). The
//! RFCs contain a range of requirements about how Request or Response messages
//! are generated, serialized, sent, received, parsed, and consumed. QUIC ([RFC
//! 9000]) streams are used for these messages along with other control and
//! QPACK ([RFC 9204]) header compression instructions.
//!
//! h3i provides a highly configurable HTTP/3 client that can bend RFC rules in
//! order to test the behavior of servers. QUIC streams can be opened, fin'd,
//! stopped or reset at any point in time. HTTP/3 frames can be sent on any
//! stream, in any order, containing user-controlled content (both legal and
//! illegal).
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110.html
//! [RFC 9114]: https://www.rfc-editor.org/rfc/rfc9114.html
//! [RFC 9204]: https://www.rfc-editor.org/rfc/rfc9204.html

use qlog::events::quic::PacketHeader;
use qlog::events::quic::PacketSent;
use qlog::events::quic::PacketType;
use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
pub use quiche;
use quiche::h3::NameValue;

use smallvec::SmallVec;

/// The ID for an HTTP/3 control stream type.
///
/// See https://datatracker.ietf.org/doc/html/rfc9114#name-control-streams.
pub const HTTP3_CONTROL_STREAM_TYPE_ID: u64 = 0x0;

/// The ID for an HTTP/3 push stream type.
///
/// See https://datatracker.ietf.org/doc/html/rfc9114#name-push-streams.
pub const HTTP3_PUSH_STREAM_TYPE_ID: u64 = 0x1;

/// The ID for a QPACK encoder stream type.
///
/// See https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.1.
pub const QPACK_ENCODER_STREAM_TYPE_ID: u64 = 0x2;

/// The ID for a QPACK decoder stream type.
///
/// See https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.2.
pub const QPACK_DECODER_STREAM_TYPE_ID: u64 = 0x3;

#[derive(Default)]
struct StreamIdAllocator {
    id: u64,
}

impl StreamIdAllocator {
    pub fn take_next_id(&mut self) -> u64 {
        let old = self.id;
        self.id += 4;

        old
    }

    pub fn peek_next_id(&mut self) -> u64 {
        self.id
    }
}

fn encode_header_block(
    headers: &[quiche::h3::Header],
) -> std::result::Result<Vec<u8>, String> {
    let mut encoder = quiche::h3::qpack::Encoder::new();

    let headers_len = headers
        .iter()
        .fold(0, |acc, h| acc + h.value().len() + h.name().len() + 32);

    let mut header_block = vec![0; headers_len];
    let len = encoder
        .encode(headers, &mut header_block)
        .map_err(|_| "Internal Error")?;

    header_block.truncate(len);

    Ok(header_block)
}

fn fake_packet_header() -> PacketHeader {
    PacketHeader {
        packet_type: PacketType::OneRtt,
        packet_number: None,
        flags: None,
        token: None,
        length: None,
        version: None,
        scil: None,
        dcil: None,
        scid: None,
        dcid: None,
    }
}

fn fake_packet_sent(frames: Option<SmallVec<[QuicFrame; 1]>>) -> EventData {
    EventData::PacketSent(PacketSent {
        header: fake_packet_header(),
        is_coalesced: None,
        retry_token: None,
        stateless_reset_token: None,
        supported_versions: None,
        raw: None,
        datagram_id: None,
        trigger: None,
        send_at_time: None,
        frames,
    })
}

pub mod actions;
pub mod client;
pub mod config;
pub mod frame;
pub mod frame_parser;
pub mod prompts;
pub mod recordreplay;
