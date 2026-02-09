// Copyright (C) 2026, Cloudflare, Inc.
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

//! Testing utilities for qlog.

use crate::events::quic::PacketType;
use crate::Configuration;
use crate::PacketHeader;
use crate::Trace;
use crate::TraceSeq;
use crate::VantagePoint;
use crate::VantagePointType;

pub fn make_pkt_hdr(packet_type: PacketType) -> PacketHeader {
    let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
    let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];

    // Some(1251),
    // Some(1224),

    PacketHeader::new(
        packet_type,
        Some(0),
        None,
        None,
        None,
        Some(0x0000_0001),
        Some(&scid),
        Some(&dcid),
    )
}

pub fn make_trace() -> Trace {
    Trace::new(
        VantagePoint {
            name: None,
            ty: VantagePointType::Server,
            flow: None,
        },
        Some("Quiche qlog trace".to_string()),
        Some("Quiche qlog trace description".to_string()),
        Some(Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        None,
    )
}

pub fn make_trace_seq() -> TraceSeq {
    TraceSeq::new(
        VantagePoint {
            name: None,
            ty: VantagePointType::Server,
            flow: None,
        },
        Some("Quiche qlog trace".to_string()),
        Some("Quiche qlog trace description".to_string()),
        Some(Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        None,
    )
}

#[cfg(test)]
mod event_tests;
#[cfg(test)]
mod trace_tests;
