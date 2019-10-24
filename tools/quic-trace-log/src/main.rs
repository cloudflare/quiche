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

use std::io::BufRead;

use regex::Regex;

use protobuf::Message;

fn main() {
    let mut args = std::env::args();
    args.next();

    let log_file = args.next().unwrap();
    let trace_file = args.next().unwrap();

    let inp = std::fs::File::open(log_file).unwrap();
    let mut out = std::fs::File::create(trace_file).unwrap();

    let mut trace = quic_trace::Trace::new();

    trace.set_protocol_version(b"AAAA".to_vec());

    // Log prefix.
    let prefix_re = Regex::new(r"^\[(.*) TRACE quiche.*\]").unwrap();

    // Packet events.
    let pkt_re = Regex::new(
        r"(rx|tx) pkt (Initial|Handshake|Application) .* len=(\d+) pn=(\d+)",
    )
    .unwrap();
    let lost_re = Regex::new(r"packet (\d+) lost on epoch (\d)").unwrap();

    let rec_re =
        Regex::new(r"timer=(.*) crypto=(.*) inflight=(.*) cwnd=(.*) latest_rtt=(.*) srtt=(.*) min_rtt=(.*) rttvar=(.*) probes=(\d+)").unwrap();

    // Frame events.
    let stream_frm_re = Regex::new(
        r"(rx|tx) frm STREAM id=(\d+) off=(\d+) len=(\d+) fin=(true|false)",
    )
    .unwrap();
    let ack_frm_re =
        Regex::new(r"(rx|tx) frm ACK delay=(.*) blocks=\[(.*)\]").unwrap();
    let close_frm_re = Regex::new(
        r"(rx|tx) frm (APPLICATION|CONNECTION)_CLOSE err=(\d+) reason=",
    )
    .unwrap();

    let mut start_time = None;

    let mut events = Vec::new();

    let mut event: Option<quic_trace::Event> = None;

    let file = std::io::BufReader::new(&inp);
    for (_, line) in file.lines().enumerate() {
        let l = line.unwrap();

        let time = match prefix_re.captures(&l) {
            Some(caps) => {
                let s = caps.get(1).unwrap().as_str();
                humantime::parse_rfc3339(s).unwrap()
            },

            None => continue,
        };

        if start_time.is_none() {
            start_time = Some(time);
        }

        if let Some(caps) = pkt_re.captures(&l) {
            // Flush previous event.
            if let Some(event) = event {
                events.push(event);
            }

            let mut ev = quic_trace::Event::new();

            let time_us = time.duration_since(start_time.unwrap()).unwrap();
            ev.set_time_us(time_us.as_micros() as u64);

            let ty = match caps.get(1).unwrap().as_str() {
                "rx" => quic_trace::EventType::PACKET_RECEIVED,
                "tx" => quic_trace::EventType::PACKET_SENT,
                _ => unreachable!(),
            };
            ev.set_event_type(ty);

            let ty = caps.get(2).unwrap().as_str();
            ev.set_encryption_level(str_to_enc_level(ty));

            let len = caps.get(3).unwrap().as_str();
            ev.set_packet_size(len.parse::<u64>().unwrap());

            let pn = caps.get(4).unwrap().as_str();
            ev.set_packet_number(pn.parse::<u64>().unwrap());

            event = Some(ev);
            continue;
        }

        if let Some(caps) = lost_re.captures(&l) {
            let mut ev = quic_trace::Event::new();

            let time_us = time.duration_since(start_time.unwrap()).unwrap();
            ev.set_time_us(time_us.as_micros() as u64);

            ev.set_event_type(quic_trace::EventType::PACKET_LOST);

            let pn = caps.get(1).unwrap().as_str();
            ev.set_packet_number(pn.parse::<u64>().unwrap());

            let ty = caps.get(2).unwrap().as_str().parse::<u64>().unwrap();
            ev.set_encryption_level(int_to_enc_level(ty));

            events.push(ev);
            continue;
        }

        if let Some(caps) = rec_re.captures(&l) {
            if event.is_none() {
                unreachable!();
            }

            let mut state = quic_trace::TransportState::new();

            let inflight = caps.get(3).unwrap().as_str();
            state.set_in_flight_bytes(inflight.parse::<u64>().unwrap());

            let cwnd = caps.get(4).unwrap().as_str();
            state.set_cwnd_bytes(cwnd.parse::<u64>().unwrap());

            let latest_rtt = caps.get(5).unwrap().as_str();
            let latest_rtt = str_to_duration(latest_rtt);
            state.set_last_rtt_us(latest_rtt.as_micros() as u64);

            let srtt = caps.get(6).unwrap().as_str();
            let srtt = if srtt == "None" {
                std::time::Duration::from_micros(0)
            } else {
                let srtt = &srtt[5..srtt.len() - 1];
                str_to_duration(srtt)
            };
            state.set_smoothed_rtt_us(srtt.as_micros() as u64);

            let min_rtt = caps.get(7).unwrap().as_str();
            let min_rtt = str_to_duration(min_rtt);
            state.set_smoothed_rtt_us(min_rtt.as_micros() as u64);

            event.as_mut().unwrap().set_transport_state(state);
            continue;
        }

        if let Some(caps) = stream_frm_re.captures(&l) {
            let mut frame = quic_trace::Frame::new();
            frame.set_frame_type(quic_trace::FrameType::STREAM);

            let mut info = quic_trace::StreamFrameInfo::new();

            let id = caps.get(2).unwrap().as_str();
            info.set_stream_id(id.parse::<u64>().unwrap());

            let off = caps.get(3).unwrap().as_str();
            info.set_offset(off.parse::<u64>().unwrap());

            let len = caps.get(4).unwrap().as_str();
            info.set_length(len.parse::<u64>().unwrap());

            let fin = caps.get(5).unwrap().as_str();
            match fin {
                "true" => info.set_fin(true),
                "false" => info.set_fin(false),
                _ => unreachable!(),
            }

            frame.set_stream_frame_info(info);

            event.as_mut().unwrap().mut_frames().push(frame);
            continue;
        }

        if let Some(caps) = ack_frm_re.captures(&l) {
            let mut frame = quic_trace::Frame::new();
            frame.set_frame_type(quic_trace::FrameType::ACK);

            let mut info = quic_trace::AckInfo::new();

            let delay = caps.get(2).unwrap().as_str();
            let delay = delay.parse::<u64>().unwrap() * 2_u64.pow(3_u32);
            info.set_ack_delay_us(delay);

            let mut blocks = Vec::new();

            let ranges = caps.get(3).unwrap().as_str();
            for r in ranges.split(", ") {
                let mut block = quic_trace::AckBlock::new();

                let mut parts = r.split("..");
                block.set_first_packet(
                    parts.next().unwrap().parse::<u64>().unwrap(),
                );
                block.set_last_packet(
                    parts.next().unwrap().parse::<u64>().unwrap(),
                );

                blocks.push(block);
            }

            info.set_acked_packets(protobuf::RepeatedField::from_vec(blocks));

            frame.set_ack_info(info);

            event.as_mut().unwrap().mut_frames().push(frame);
            continue;
        }

        if let Some(caps) = close_frm_re.captures(&l) {
            let mut frame = quic_trace::Frame::new();
            frame.set_frame_type(quic_trace::FrameType::CONNECTION_CLOSE);

            let mut info = quic_trace::CloseInfo::new();

            let err = caps.get(3).unwrap().as_str();
            info.set_error_code(u32::from_str_radix(err, 16).unwrap());

            frame.set_close_info(info);

            event.as_mut().unwrap().mut_frames().push(frame);
            continue;
        }
    }

    println!("Generated {} events", events.len());

    trace.set_events(protobuf::RepeatedField::from_vec(events));

    let mut cos = protobuf::CodedOutputStream::new(&mut out);
    trace.write_to(&mut cos).unwrap();
    cos.flush().unwrap();
}

fn str_to_enc_level(ty: &str) -> quic_trace::EncryptionLevel {
    match ty {
        "Initial" => quic_trace::EncryptionLevel::ENCRYPTION_INITIAL,
        "Handshake" => quic_trace::EncryptionLevel::ENCRYPTION_HANDSHAKE,
        "Application" => quic_trace::EncryptionLevel::ENCRYPTION_1RTT,
        _ => unreachable!(),
    }
}

fn int_to_enc_level(ty: u64) -> quic_trace::EncryptionLevel {
    match ty {
        0 => quic_trace::EncryptionLevel::ENCRYPTION_INITIAL,
        1 => quic_trace::EncryptionLevel::ENCRYPTION_HANDSHAKE,
        2 => quic_trace::EncryptionLevel::ENCRYPTION_1RTT,
        _ => unreachable!(),
    }
}

fn str_to_duration(d: &str) -> std::time::Duration {
    if let Ok(d) = humantime::parse_duration(d) {
        return d;
    }

    // humantime doesn't support parsing float duration, so do it manually.
    let end = d.chars().position(|c| !c.is_numeric() && c != '.').unwrap();
    let num = (&d[..end]).parse::<f64>().unwrap();
    let unit = &d[end..];

    let num = match unit {
        "s" => num,
        "ms" => num / 1_000_f64,
        "us" => num / 1_000_000_f64,
        "µs" => num / 1_000_000_f64,
        "ns" => num / 1_000_000_000_f64,
        _ => unreachable!(),
    };

    std::time::Duration::from_secs_f64(num)
}

mod quic_trace;
