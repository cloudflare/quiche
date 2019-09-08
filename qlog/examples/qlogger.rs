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

use qlog::*;

fn main() {

    let ty = PacketType::Initial;

    println!("{}", serde_json::to_string(&ty).unwrap());

    let pkt_hdr_1 = PacketHeader {
        packet_number: "0".to_string(),
        packet_size: Some(1251),
        payload_length: Some(1224),
        version: Some("0xff000016".to_string()),
        scil: Some("8".to_string()),
        dcil: Some("8".to_string()),
        scid: Some("7e37e4dcc6682da8".to_string()),
        dcid: Some("36ce104eee50101c".to_string()),
    };

     println!(
        "packet header: {}",
        serde_json::to_string(&pkt_hdr_1).unwrap()
    );

    let pkt_sent_evt_0 = EventData::PacketSent {
        raw_encrypted: None,
        raw_decrypted: None,
        packet_type: PacketType::Initial,
        header: pkt_hdr_1.clone(),
        frames: None,
        is_coalesced: None
    };

    println!(
        "packet 0: {}",
        serde_json::to_string(&pkt_sent_evt_0).unwrap()
    );

    let mut frames = Vec::new();
    frames.push(QuicFrame::padding());

    frames.push(QuicFrame::ping());

    frames.push(QuicFrame::stream(
        "0".to_string(),
        "0".to_string(),
        "100".to_string(),
        true,
        None,
    ));

    let pkt_sent_evt_1 = EventData::PacketSent {
        raw_encrypted: None,
        raw_decrypted: None,
        packet_type: PacketType::Initial,
        header: pkt_hdr_1.clone(),
        frames: Some(frames),
        is_coalesced: None
    };
    println!(
        "packet 1: {}",
        serde_json::to_string(&pkt_sent_evt_1).unwrap()
    );

    let pkt_hdr_2 = PacketHeader {
        packet_number: "0".to_string(),
        packet_size: Some(1251),
        payload_length: Some(1224),
        version: Some("0xff000016".to_string()),
        scil: None,
        dcil: None,
        scid: None,
        dcid: None,
    };

    let pkt_sent_evt_2 = EventData::PacketSent {
        raw_encrypted: None,
        raw_decrypted: None,
        packet_type: PacketType::Initial,
        header: pkt_hdr_2,
        frames: None,
        is_coalesced: None
    };
    println!(
        "packet 2: {}",
        serde_json::to_string(&pkt_sent_evt_2).unwrap()
    );

    let vantage_point = VantagePoint {
        name: None,
        ty: VantagePointType::Client,
        flow: None,
    };

    let mut trace = Trace {
        vantage_point,
        title: Some("Test trace".to_string()),
        description: Some("Test trace description".to_string()),
        configuration: Some(Configuration {
            time_offset: Some("0".to_string()),
            time_units: Some(TimeUnits::Ms),
            original_uris: None,
        }),
        common_fields: None,
        event_fields: vec![
            "relative_time".to_string(),
            "category".to_string(),
            "event".to_string(),
            "trigger".to_string(),
            "data".to_string(),
        ], // TODO: hack
        events: Vec::new(), // vec![vec![rt, cat, ev, trigger, data]],
    };

    trace.push_transport_event(
        "0".to_string(),
        TransportEventType::PacketSent,
        TransportEventTrigger::Line,
        pkt_sent_evt_1,
    );

    println!("trace {}", serde_json::to_string(&trace).unwrap());

    let qlog = Qlog {
        qlog_version: "WIP".to_string(),
        title: Some("Test log".to_string()),
        description: Some("Test log description".to_string()),
        summary: None,
        traces: vec![trace],
    };

    println!("log {}", serde_json::to_string(&qlog).unwrap());
}
