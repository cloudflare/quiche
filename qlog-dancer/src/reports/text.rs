// Copyright (C) 2025, Cloudflare, Inc.
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

//! Reporting (tables etc.)

use qlog::events::quic::QuicFrame;
use tabled::settings::location::ByColumnName;
use tabled::settings::object::Segment;
use tabled::settings::Alignment;
use tabled::settings::Disable;
use tabled::settings::Modify;
use tabled::settings::Style;
use tabled::Table;

use crate::config::AppConfig;
use crate::datastore::Datastore;
use crate::datastore::PrintStatsConfig;
use crate::request_stub::*;
use crate::stringify_last;
use crate::LogFileData;

pub fn request_timing_table(
    lf: &LogFileData, config: &AppConfig,
) -> Option<Table> {
    let mut table = Table::new(lf.datastore.http_requests.values());
    table.with(Modify::new(Segment::all()).with(Alignment::right()));

    if config.report_omit_upload {
        table
            .with(Disable::column(ByColumnName::new(CLIENT_CONTENT_LENGTH)))
            .with(Disable::column(ByColumnName::new(CLIENT_TRANSFERRED)))
            .with(Disable::column(ByColumnName::new(UPLOAD_TIME)))
            .with(Disable::column(ByColumnName::new(UPLOAD_RATE)));
    }

    match lf.datastore.vantage_point {
        crate::datastore::VantagePoint::Client => {
            table
                .with(Disable::column(ByColumnName::new(SERVER_RX_HDR_TX_HDR)))
                .with(Disable::column(ByColumnName::new(
                    SERVER_TX_HDR_TX_FIRST_HDR,
                )))
                .with(Disable::column(ByColumnName::new(
                    SERVER_TX_HDR_TX_LAST_HDR,
                )))
                .with(Disable::column(ByColumnName::new(
                    SERVER_TX_FIRST_DATA_TX_LAST_DATA,
                )));
        },

        crate::datastore::VantagePoint::Server => {
            // TODO:
        },
    }

    if config.report_omit_priorities {
        table
            .with(Disable::column(ByColumnName::new(CLIENT_PRI)))
            .with(Disable::column(ByColumnName::new(SERVER_PRI)));
    }

    if config.report_text_csv {
        let style = Style::empty().vertical(',');

        table.with(style);
    }

    Some(table)
}

pub fn print_stats(data_store: &Datastore, config: &PrintStatsConfig) {
    if config.rx_flow_control {
        print_rx_max_data_frames(data_store);
        print_rx_max_stream_data_frames(data_store);
    }

    if config.tx_flow_control {
        print_tx_max_data_frames(data_store);
        print_tx_max_stream_data_frames(data_store);
    }

    if config.reset_streams {
        print_tx_reset_stream_frames(data_store);
        print_rx_reset_stream_frames(data_store);
    }

    if config.tx_stream_frames {
        print_tx_stream_frames(data_store);
    }

    if config.stream_buffering {
        print_local_stream_buffer_reads(data_store);
        print_local_stream_buffer_writes(data_store);
        print_local_stream_buffer_dropped(data_store);
    }

    if config.packet_stats {
        print_sent_packet_stats(data_store);
    }
}

fn print_sent_packet_stats(data_store: &Datastore) {
    println!("### sent packets ###");
    for (pkt_space, pkts) in &data_store.packet_sent {
        println!("\t# packet space={:?}", pkt_space);

        for (pkt_num, pkt_info) in pkts {
            let (length, payload_length) = match &pkt_info.raw {
                Some(raw) => (raw.length, raw.payload_length),

                None => (None, None),
            };

            println!(
                "\tpkt_num={}, acked=TODO-unknown, length={:?}, payload_length={:?}, ",
                pkt_num, length, payload_length
            );
        }
        println!();
    }
}

fn print_rx_max_data_frames(data_store: &Datastore) {
    println!("### received MAX_DATA frames ###");
    if data_store
        .received_stream_max_data_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        println!(
            "    first={:?}, last={:?}",
            data_store.received_max_data.first().unwrap(),
            data_store.received_max_data.last().unwrap()
        );
    }
}

fn print_tx_max_data_frames(data_store: &Datastore) {
    println!("### sent MAX_DATA frames ###");
    println!(
        "   total_count={}, first={:?}, last={:?}",
        data_store.sent_max_data.len(),
        data_store.sent_max_data.first().unwrap(),
        data_store.sent_max_data.last().unwrap()
    );
}

fn print_rx_max_stream_data_frames(data_store: &Datastore) {
    println!("### received MAX_STREAM_DATA frames ###");
    if data_store
        .received_stream_max_data_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        for entry in &data_store.received_stream_max_data_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1)
            );
        }
    }
}

fn print_tx_max_stream_data_frames(data_store: &Datastore) {
    println!("### sent MAX_STREAM_DATA frames ###");
    if data_store
        .sent_stream_max_data_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        for entry in &data_store.sent_stream_max_data_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}",
                entry.0,
                entry.1.len(),
                entry.1.first().unwrap(),
                entry.1.last().unwrap()
            );
        }
    }
}

fn print_tx_reset_stream_frames(data_store: &Datastore) {
    println!("### sent RESET_STREAM frames ###");
    if data_store.sent_reset_stream.is_empty() {
        println!("    None")
    } else {
        for entry in &data_store.sent_reset_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1)
            );
        }
    }
}

fn print_rx_reset_stream_frames(data_store: &Datastore) {
    println!("### received RESET_STREAM frames ###");
    if data_store.received_reset_stream.is_empty() {
        println!("    None")
    } else {
        for entry in &data_store.received_reset_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1)
            );
        }
    }
}

fn print_local_stream_buffer_reads(data_store: &Datastore) {
    println!("### local stream buffer reads ###");
    if data_store.stream_buffer_reads_tracker.per_stream.is_empty() {
        println!("    None")
    } else {
        for entry in &data_store.stream_buffer_reads_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first=(offset={}, length={}), last=(offset={}, length={}), total_length={}",
                entry.0,
                entry.1.len(),
                entry.1.first().unwrap().1.offset,
                entry.1.first().unwrap().1.length,
                entry.1.last().unwrap().1.offset,
                entry.1.last().unwrap().1.length,
                entry.1.last().unwrap().1.offset + entry.1.last().unwrap().1.length,
            );
        }
    }
}

fn print_local_stream_buffer_writes(data_store: &Datastore) {
    println!("### local stream buffer writes ###");
    if data_store
        .stream_buffer_writes_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        for entry in &data_store.stream_buffer_writes_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first=(offset={}, length={}), last=(offset={}, length={}), total_length={}",
                entry.0,
                entry.1.len(),
                entry.1.first().unwrap().1.offset,
                entry.1.first().unwrap().1.length,
                entry.1.last().unwrap().1.offset,
                entry.1.last().unwrap().1.length,
                entry.1.last().unwrap().1.offset + entry.1.last().unwrap().1.length,
            );
        }
    }
}

fn print_local_stream_buffer_dropped(data_store: &Datastore) {
    println!("### local stream buffer dropped ###");
    if data_store
        .stream_buffer_dropped_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        for entry in &data_store.stream_buffer_dropped_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first=(offset={}, length={}), last=(offset={}, length={}), total_length={}",
                entry.0,
                entry.1.len(),
                entry.1.first().unwrap().1.offset,
                entry.1.first().unwrap().1.length,
                entry.1.last().unwrap().1.offset,
                entry.1.last().unwrap().1.length,
                entry.1.last().unwrap().1.offset + entry.1.last().unwrap().1.length,
            );
        }
    }
}

fn print_tx_stream_frames(data_store: &Datastore) {
    println!("### sent STREAM frames ###");
    if data_store.sent_stream_frames.is_empty() {
        println!("    None")
    } else {
        for entry in &data_store.sent_stream_frames {
            let total = match entry.1.last() {
                Some((_, QuicFrame::Stream { offset, raw, .. })) => {
                    let offset = offset.unwrap_or_default();
                    let length = raw
                        .clone()
                        .unwrap_or_default()
                        .payload_length
                        .unwrap_or_default();
                    format!("{}", offset + length)
                },

                _ => "n/a".to_string(),
            };

            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}, total_length={}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1),
                total
            );
        }
    }
}

pub fn print_flow_control(data: &[LogFileData]) {
    // TODO make this a proper table
    println!("================");
    println!("flow control stuff");
    println!("================");
    for lf in data {
        println!(
            "Session={}, host={}",
            lf.datastore.session_id.unwrap_or(-1),
            lf.datastore
                .host
                .clone()
                .unwrap_or("ERROR UNKNOWN".to_string())
        );

        println!("  Initial Client connection window, Initial Client Bidi Local Stream Window");
        println!(
            "  {},{}",
            lf.datastore.client_quic_tps.initial_max_data.unwrap_or(0),
            lf.datastore
                .client_quic_tps
                .initial_max_stream_data_bidi_local
                .unwrap_or(0)
        );

        for (stream_id, points) in
            &lf.datastore.netlog_quic_client_side_window_updates
        {
            println!("  Stream {} flow control updates", stream_id);
            println!("    Time, Value");

            for (time, val) in points {
                println!("    {},{}", time, val);
            }
        }
    }
}

pub fn print_packet_loss(data: &[LogFileData]) {
    // TODO make this a proper table
    println!("================");
    println!("QUIC packet loss");
    println!("================");
    for lf in data {
        let is_received_some = lf
            .datastore
            .netlog_ack_sent_missing_packet
            .contains_key(&crate::PacketType::Handshake) ||
            lf.datastore
                .netlog_ack_sent_missing_packet
                .contains_key(&crate::PacketType::Initial) ||
            lf.datastore
                .netlog_ack_sent_missing_packet
                .contains_key(&crate::PacketType::OneRtt) ||
            lf.datastore
                .netlog_ack_sent_missing_packet
                .contains_key(&crate::PacketType::ZeroRtt) ||
            lf.datastore
                .netlog_ack_sent_missing_packet
                .contains_key(&crate::PacketType::Retry) ||
            lf.datastore
                .netlog_ack_sent_missing_packet
                .contains_key(&crate::PacketType::VersionNegotiation);

        if !lf.datastore.netlog_ack_received_missing_packet.is_empty() ||
            is_received_some
        {
            println!(
                "Session={}, host={}",
                lf.datastore.session_id.unwrap_or(-1),
                lf.datastore
                    .host
                    .clone()
                    .unwrap_or("ERROR UNKNOWN".to_string())
            );
        }

        if !lf.datastore.netlog_ack_received_missing_packet.is_empty() {
            println!("  Packets sent and lost");
            println!("    Packet Type, Packet tx count, Packet lost count, Packet loss %, Packets lost");

            for (pkt_type, pkt_nums) in
                &lf.datastore.netlog_ack_received_missing_packet
            {
                if let Some(pkts) = lf.datastore.packet_received.get(pkt_type) {
                    let total_pkts_tx = pkts.len();
                    let pkt_loss = pkt_nums.len() as f64 / total_pkts_tx as f64;

                    if !pkt_nums.is_empty() {
                        println!(
                            "    {:?}, {}, {}, {:.2}, {:?}",
                            pkt_type,
                            total_pkts_tx,
                            pkt_nums.len(),
                            pkt_loss * 100f64,
                            pkt_nums
                        );
                    }
                }
            }

            println!();
        }

        if is_received_some {
            println!("  Packet lost and not received");
            println!("    Packet Type, Packet rx count, Packet lost count, Packet loss %, Packets lost");

            for (pkt_type, pkt_nums) in
                &lf.datastore.netlog_ack_sent_missing_packet
            {
                if let Some(pkts) = lf.datastore.packet_received.get(pkt_type) {
                    let total_pkts_tx = pkts.len();
                    let pkt_loss = pkt_nums.len() as f64 / total_pkts_tx as f64;

                    if !pkt_nums.is_empty() {
                        println!(
                            "    {:?}, {}, {}, {:.2}, {:?}",
                            pkt_type,
                            total_pkts_tx,
                            pkt_nums.len(),
                            pkt_loss * 100f64,
                            pkt_nums
                        );
                    }
                }
            }

            println!();
        }
    }

    println!();
}
