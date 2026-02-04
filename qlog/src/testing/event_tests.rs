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

use super::*;
use crate::events::quic::PacketSent;
use crate::events::quic::PacketType;
use crate::events::quic::QuicFrame;
use crate::events::EventData;
use crate::events::RawInfo;
use crate::Event;

#[test]
fn packet_sent_event_no_frames() {
    let log_string = r#"{
  "time": 0.0,
  "name": "transport:packet_sent",
  "data": {
    "header": {
      "packet_type": "initial",
      "packet_number": 0,
      "version": "1",
      "scil": 8,
      "dcil": 8,
      "scid": "7e37e4dcc6682da8",
      "dcid": "36ce104eee50101c"
    },
    "raw": {
      "length": 1251,
      "payload_length": 1224
    }
  }
}"#;

    let pkt_hdr = make_pkt_hdr(PacketType::Initial);
    let ev_data = EventData::PacketSent(PacketSent {
        header: pkt_hdr,
        raw: Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        }),
        ..Default::default()
    });

    let ev = Event::with_time(0.0, ev_data);

    assert_eq!(serde_json::to_string_pretty(&ev).unwrap(), log_string);
}

#[test]
fn packet_sent_event_some_frames() {
    let log_string = r#"{
  "time": 0.0,
  "name": "transport:packet_sent",
  "data": {
    "header": {
      "packet_type": "initial",
      "packet_number": 0,
      "version": "1",
      "scil": 8,
      "dcil": 8,
      "scid": "7e37e4dcc6682da8",
      "dcid": "36ce104eee50101c"
    },
    "raw": {
      "length": 1251,
      "payload_length": 1224
    },
    "frames": [
      {
        "frame_type": "padding",
        "payload_length": 1234
      },
      {
        "frame_type": "ping"
      },
      {
        "frame_type": "stream",
        "stream_id": 0,
        "offset": 0,
        "length": 100,
        "fin": true
      }
    ]
  }
}"#;

    let pkt_hdr = make_pkt_hdr(PacketType::Initial);

    let frames = vec![
        QuicFrame::Padding {
            payload_length: 1234,
            length: None,
        },
        QuicFrame::Ping {
            payload_length: None,
            length: None,
        },
        QuicFrame::Stream {
            stream_id: 0,
            offset: 0,
            length: 100,
            fin: Some(true),
            raw: None,
        },
    ];

    let ev_data = EventData::PacketSent(PacketSent {
        header: pkt_hdr,
        frames: Some(frames.into()),
        raw: Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        }),
        ..Default::default()
    });

    let ev = Event::with_time(0.0, ev_data);
    assert_eq!(serde_json::to_string_pretty(&ev).unwrap(), log_string);
}
