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
use crate::events::quic::MetricsUpdated;
use crate::events::quic::PacketSent;
use crate::events::quic::PacketType;
use crate::events::quic::QuicFrame;
use crate::events::EventData;
use crate::events::ExData;
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

// Test constants for MetricsUpdated tests
const MIN_RTT: f32 = 10.0;
const SMOOTHED_RTT: f32 = 15.0;
const CONGESTION_WINDOW: u64 = 12000;
const PACING_RATE: u64 = 500000;
const DELIVERY_RATE: u64 = 1000000;
const SEND_RATE: u64 = 500000;
const COLLISION_VALUE: f32 = 999.0;

#[test]
fn packet_header() {
    let pkt_hdr = make_pkt_hdr(PacketType::Initial);

    let log_string = r#"{
  "packet_type": "initial",
  "packet_number": 0,
  "version": "1",
  "scil": 8,
  "dcil": 8,
  "scid": "7e37e4dcc6682da8",
  "dcid": "36ce104eee50101c"
}"#;

    assert_eq!(serde_json::to_string_pretty(&pkt_hdr).unwrap(), log_string);
}

#[test]
fn metrics_updated_with_ex_data() {
    // Test that ex_data fields are flattened into the same object
    let mut ex_data = ExData::new();
    ex_data.insert(
        "delivery_rate".to_string(),
        serde_json::json!(DELIVERY_RATE),
    );
    ex_data.insert("send_rate".to_string(), serde_json::json!(SEND_RATE));

    let metrics = MetricsUpdated {
        min_rtt: Some(MIN_RTT),
        congestion_window: Some(CONGESTION_WINDOW),
        ex_data,
        ..Default::default()
    };

    let json = serde_json::to_value(&metrics).unwrap();

    // Verify standard fields are present
    assert_eq!(json["min_rtt"], MIN_RTT);
    assert_eq!(json["congestion_window"], CONGESTION_WINDOW);

    // Verify ex_data fields are flattened (not nested under "ex_data")
    assert_eq!(json["delivery_rate"], DELIVERY_RATE);
    assert_eq!(json["send_rate"], SEND_RATE);
    assert!(json.get("ex_data").is_none(), "ex_data should be flattened");
}

#[test]
fn metrics_updated_ex_data_collision() {
    // Test collision: same field set via struct AND ex_data.
    // With serde's preserve_order feature and ex_data at the top of the
    // struct, standard fields are serialized last and take precedence.
    //
    // NOTE: This test documents serde's silent overwrite behavior.
    // serde does NOT error or panic on duplicate keys - it just overwrites.
    // This test exists to warn users: avoid ex_data keys matching struct
    // fields!
    let mut ex_data = ExData::new();
    ex_data.insert("min_rtt".to_string(), serde_json::json!(COLLISION_VALUE));

    let metrics = MetricsUpdated {
        min_rtt: Some(MIN_RTT), // struct field value
        ex_data,                // ex_data also has min_rtt
        ..Default::default()
    };

    let json = serde_json::to_value(&metrics).unwrap();

    // Standard field wins in collision - ex_data cannot overwrite standard
    // fields, which prevents accidental data corruption.
    assert_eq!(json["min_rtt"], MIN_RTT);
}

#[test]
fn metrics_updated_round_trip() {
    // Test serialization -> deserialization round-trip
    let mut ex_data = ExData::new();
    ex_data.insert(
        "delivery_rate".to_string(),
        serde_json::json!(DELIVERY_RATE),
    );

    let original = MetricsUpdated {
        min_rtt: Some(MIN_RTT),
        smoothed_rtt: Some(SMOOTHED_RTT),
        congestion_window: Some(CONGESTION_WINDOW),
        pacing_rate: Some(PACING_RATE),
        ex_data,
        ..Default::default()
    };

    let json_str = serde_json::to_string(&original).unwrap();
    let deserialized: MetricsUpdated = serde_json::from_str(&json_str).unwrap();

    // Standard fields round-trip correctly
    assert_eq!(deserialized.min_rtt, original.min_rtt);
    assert_eq!(deserialized.smoothed_rtt, original.smoothed_rtt);
    assert_eq!(deserialized.congestion_window, original.congestion_window);
    assert_eq!(deserialized.pacing_rate, original.pacing_rate);

    // ex_data fields round-trip correctly
    assert_eq!(
        deserialized.ex_data.get("delivery_rate"),
        Some(&serde_json::json!(DELIVERY_RATE))
    );
}

#[test]
fn metrics_updated_no_ex_data() {
    // Test that ex_data is not present when not used
    let metrics = MetricsUpdated {
        min_rtt: Some(MIN_RTT),
        congestion_window: Some(CONGESTION_WINDOW),
        ..Default::default()
    };

    let json = serde_json::to_value(&metrics).unwrap();

    // Verify standard fields are present
    assert_eq!(json["min_rtt"], MIN_RTT);
    assert_eq!(json["congestion_window"], CONGESTION_WINDOW);

    // Verify ex_data is not present
    assert!(
        json.get("ex_data").is_none(),
        "ex_data should not be present"
    );
}
