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

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;

use log::error;
use log::trace;
use qlog::events::connectivity::TransportOwner;
use qlog::events::h3::Http3Frame;
use qlog::events::quic::AckedRanges;
use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use qlog::events::RawInfo;

use regex::Regex;
use tabled::Tabled;

use crate::request_stub::find_header_value;
use crate::request_stub::HttpRequestStub;
use crate::request_stub::NaOption;
use crate::trackers::StreamBufferTracker;
use crate::trackers::StreamMaxTracker;
use crate::LogFileData;
use crate::PacketType;
use crate::QlogPointf32;
use crate::QlogPointu64;
use crate::RawLogEvents::Netlog;
use netlog;
use netlog::h2;
use netlog::h2::Event::*;
use netlog::h2::*;
use netlog::h3;
use netlog::h3::Event::*;
use netlog::http;
use netlog::quic;
use netlog::quic::Event::*;
use netlog::quic::*;
use netlog::read_netlog_record;

pub type ParseResult<T> = Result<T, serde_json::Error>;
#[derive(Debug, Clone)]
pub struct PacketInfoStub {
    pub acked: Option<bool>,
    pub raw: Option<RawInfo>,
    pub created_time: f32,
    pub send_at_time: Option<f32>,
    pub ty: PacketType,
    pub number: u64,
}

#[derive(Clone, Debug)]
pub struct StreamAccess {
    pub offset: u64,
    pub length: u64,
}

#[derive(Default, Debug)]
pub struct PrintStatsConfig {
    pub rx_flow_control: bool,
    pub tx_flow_control: bool,
    pub reset_streams: bool,
    pub stream_buffering: bool,
    pub tx_stream_frames: bool,
    pub packet_stats: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RequestAtServerDeltas {
    pub rx_hdr_tx_hdr: NaOption<f32>,
    pub rx_hdr_tx_first_data: NaOption<f32>,
    pub rx_hdr_tx_last_data: NaOption<f32>,
    pub tx_first_data_tx_last_data: NaOption<f32>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RequestAtClientDeltas {
    pub discover_tx_hdr: NaOption<f32>,
    pub tx_hdr_rx_hdr: NaOption<f32>,
    pub tx_hdr_rx_first_data: NaOption<f32>,
    pub tx_hdr_rx_last_data: NaOption<f32>,
    pub tx_first_data_tx_last_data: NaOption<f32>,
    pub rx_first_data_rx_last_data: NaOption<f32>,
    pub rx_hdr_rx_last_data: NaOption<f32>,
}

#[derive(Debug, Default)]
pub enum RequestActor {
    #[default]
    Client,
    Server,
}

impl From<VantagePoint> for RequestActor {
    fn from(value: VantagePoint) -> Self {
        match value {
            VantagePoint::Client => RequestActor::Client,
            VantagePoint::Server => RequestActor::Server,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum VantagePoint {
    #[default]
    Client,
    Server,
}

#[derive(Debug, Default)]
pub struct StreamDatapoint {
    pub offset: u64,
    pub length: u64,
}

#[derive(Default, Clone, Copy, PartialEq)]
pub enum ApplicationProto {
    Http2,
    #[default]
    Http3,
}

impl Debug for ApplicationProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for ApplicationProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = match self {
            ApplicationProto::Http2 => "HTTP/2",
            ApplicationProto::Http3 => "HTTP/3",
        };

        write!(f, "{}", v)
    }
}

#[derive(Debug, Default, Tabled)]
pub struct QuicSessionClose {
    #[tabled(rename = "ID")]
    pub session_id: i64,
    #[tabled(rename = "SNI")]
    pub sni: String,
    #[tabled(rename = "Error")]
    pub quic_error: i64,
    #[tabled(rename = "Description")]
    pub quic_error_pretty: NaOption<String>,
    #[tabled(rename = "From peer")]
    pub from_peer: bool,
    #[tabled(rename = "Additional Details")]
    pub details: String,
}

#[derive(Debug, Default, Tabled)]
pub struct H2SessionClose {
    #[tabled(rename = "ID")]
    pub session_id: i64,
    #[tabled(rename = "SNI")]
    pub sni: String,
    #[tabled(rename = "Error")]
    pub net_err: i64,
    #[tabled(rename = "Description")]
    pub net_err_pretty: NaOption<String>,
    #[tabled(rename = "Additional Details")]
    pub details: String,
}

#[derive(Default, Debug)]
pub struct QuicStreamStopSending {
    pub quic_rst_stream_error: u64,
    pub quic_rst_stream_error_friendly: Option<String>,
}

impl Display for QuicStreamStopSending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "code={}, {}",
            self.quic_rst_stream_error,
            self.quic_rst_stream_error_friendly.as_deref().unwrap_or("")
        )
    }
}

#[derive(Default, Debug)]
pub struct QuicStreamReset {
    pub offset: u64,
    pub quic_rst_stream_error: u64,
    pub quic_rst_stream_error_friendly: Option<String>,
}

impl Display for QuicStreamReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "offset={}, code={}, {}",
            self.offset,
            self.quic_rst_stream_error,
            self.quic_rst_stream_error_friendly.as_deref().unwrap_or("")
        )
    }
}

#[derive(Default, Debug)]
pub struct H2StreamReset {
    pub error: String,
    pub description: String,
}

impl Display for H2StreamReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={}, {}", self.error, self.description,)
    }
}

#[derive(Default, Debug)]
pub struct Datastore {
    pub vantage_point: VantagePoint,
    pub application_proto: ApplicationProto,
    pub session_id: Option<i64>,
    pub host: Option<String>,

    pub h2_client_settings: Http2Settings,
    pub h2_server_settings: Http2Settings,

    pub client_quic_tps: TransportParameters,

    pub last_event_time: f32,

    // There are several packet spaces, so store a map of all packets sent
    // according to packet space. Each space then contains a map of packet
    // header info keyed off the packet number.
    pub packet_sent: HashMap<PacketType, BTreeMap<u64, PacketInfoStub>>,
    pub packet_received: HashMap<PacketType, BTreeMap<u64, PacketInfoStub>>,

    // TODO: netlog packet sent happens after frame, so we can't detect the
    // packet type properly. Stick all in one bucket for now and accept we'll
    // alias packet numbers that overlap between spaced
    pub netlog_ack_sent_missing_packet: BTreeMap<PacketType, BTreeSet<u64>>,
    pub netlog_ack_received_missing_packet: BTreeMap<PacketType, BTreeSet<u64>>,

    pub packet_acked: Vec<QlogPointu64>,

    pub local_cwnd: Vec<QlogPointu64>,
    pub local_bytes_in_flight: Vec<QlogPointu64>,
    pub local_ssthresh: Vec<QlogPointu64>,
    pub local_pacing_rate: Vec<QlogPointu64>,
    pub local_delivery_rate: Vec<QlogPointu64>,
    pub local_send_rate: Vec<QlogPointu64>,
    pub local_ack_rate: Vec<QlogPointu64>,

    pub local_min_rtt: Vec<QlogPointf32>,
    pub local_latest_rtt: Vec<QlogPointf32>,
    pub local_smoothed_rtt: Vec<QlogPointf32>,

    pub congestion_state_updates: Vec<(f32, u64, String)>,

    pub received_max_data: Vec<QlogPointu64>,

    /// Tracks per-stream max data: full history, current max, and cumulative
    /// sum.
    pub received_stream_max_data_tracker: StreamMaxTracker,

    pub sent_max_data: Vec<QlogPointu64>,

    /// Tracks per-stream max data: full history, current max, and cumulative
    /// sum.
    pub sent_stream_max_data_tracker: StreamMaxTracker,

    /// Tracks stream buffer reads: per-stream history, current max, and running
    /// sum.
    pub stream_buffer_reads_tracker: StreamBufferTracker,

    /// Tracks stream buffer writes: per-stream history, current max, and
    /// running sum.
    pub stream_buffer_writes_tracker: StreamBufferTracker,

    /// Tracks stream buffer dropped: per-stream history, current max, and
    /// running sum.
    pub stream_buffer_dropped_tracker: StreamBufferTracker,

    pub received_reset_stream: BTreeMap<u64, Vec<QuicFrame>>,
    pub sent_reset_stream: BTreeMap<u64, Vec<QuicFrame>>,

    pub received_stream_frames: BTreeMap<u64, Vec<(f32, StreamDatapoint)>>,
    pub received_stream_frames_count_based:
        BTreeMap<u64, Vec<(u64, StreamDatapoint)>>,
    pub total_received_stream_frame_count: u64,

    pub sent_stream_frames: BTreeMap<u64, Vec<(f32, QuicFrame)>>,
    pub sent_stream_frames_count_based: BTreeMap<u64, Vec<(u64, QuicFrame)>>,
    pub total_sent_stream_frame_count: u64,

    pub received_data_frames: BTreeMap<u64, Vec<(f32, u64)>>,
    pub received_data_frames_count_based: BTreeMap<u64, Vec<(u64, u64)>>,
    pub total_received_data_frame_count: u64,
    pub received_data_cumulative: BTreeMap<u64, Vec<(f32, u64)>>,
    pub received_data_cumulative_max: BTreeMap<u64, u64>,

    pub sent_data_frames: BTreeMap<u64, Vec<(f32, u64)>>,
    pub sent_data_frames_count_based: BTreeMap<u64, Vec<(u64, u64)>>,
    pub total_sent_data_frame_count: u64,
    pub sent_data_cumulative: BTreeMap<u64, Vec<(f32, u64)>>,
    pub sent_data_cumulative_max: BTreeMap<u64, u64>,

    pub http_requests: BTreeMap<u64, HttpRequestStub>,
    pub largest_data_frame_rx_length_global: u64,
    pub largest_data_frame_tx_length_global: u64,

    pub local_init_max_stream_data_bidi_local: u64,
    pub local_init_max_stream_data_uni: u64,
    pub peer_init_max_stream_data_bidi_local: u64,
    pub peer_init_max_stream_data_bidi_remote: u64,
    pub peer_init_max_stream_data_uni: u64,

    pub h2_recv_window_updates: BTreeMap<u32, Vec<(f32, i32)>>,

    // Balance against incoming data to make it easier to plot in some cases
    pub h2_send_window_updates_balanced: BTreeMap<u32, Vec<(f32, i32)>>,

    // Just store raw updates for clear absolute values
    pub h2_send_window_updates_absolute: BTreeMap<u32, Vec<(f32, u64)>>,

    pub netlog_quic_server_window_blocked: BTreeMap<i64, Vec<f32>>,
    pub netlog_quic_client_side_window_updates: BTreeMap<i64, Vec<(f32, u64)>>,

    pub netlog_h2_stream_received_connection_cumulative: Vec<QlogPointu64>,
    pub netlog_quic_stream_received_connection_cumulative: Vec<QlogPointu64>,

    pub received_packets_netlog: Vec<(f32, PacketInfoStub)>,
    pub discontinuous_packet_number_count: u64,

    pub netlog_ack_sent_missing_packets_raw: Vec<(f32, Vec<u64>)>,

    pub total_tx_ack: usize,
    pub max_ack_sent_missing_packets_size: usize,

    pub total_rx_ack: usize,
    pub max_ack_received_missing_packets_size: usize,

    pub quic_session_close: Option<QuicSessionClose>,
    pub h2_session_close: Option<H2SessionClose>,

    pub h2_concurrent_requests: u64,
}

fn is_bidi(stream_id: u64) -> bool {
    (stream_id & 0x2) == 0
}

impl Datastore {
    pub fn consume_netlog_event(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        event: &netlog::Event, constants: &netlog::constants::Constants,
        stream_bind: &StreamBindingMap,
        h3_session_requests: Option<&Vec<ReqOverH3>>,
    ) {
        match event {
            // nothing to do for this type just now
            netlog::Event::Http(_e) => (),
            netlog::Event::H2(e) => self.consume_netlog_h2(
                session_start_time,
                ev_hdr,
                e,
                constants,
                stream_bind,
            ),

            netlog::Event::H3(e) => self.consume_netlog_h3(
                session_start_time,
                ev_hdr,
                e,
                h3_session_requests,
            ),
            netlog::Event::Quic(e) =>
                self.consume_netlog_quic(session_start_time, ev_hdr, e, constants),
        }
    }

    fn consume_netlog_quic(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &quic::Event, constants: &netlog::constants::Constants,
    ) {
        let rel_event_time = (ev_hdr.time_num - session_start_time) as f32;

        match ev {
            QuicSessionStreamFrameReceived(e) => {
                let s = self
                    .received_stream_frames
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((rel_event_time, StreamDatapoint {
                    offset: e.params.offset,
                    length: e.params.length,
                }));

                let s = self
                    .received_stream_frames_count_based
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((
                    self.total_received_stream_frame_count,
                    StreamDatapoint {
                        offset: e.params.offset,
                        length: e.params.length,
                    },
                ));

                self.total_received_stream_frame_count += 1;

                if e.params.fin {
                    if let Some(req) =
                        self.http_requests.get_mut(&e.params.stream_id)
                    {
                        req.time_fin_rx = Some(rel_event_time);
                    }
                }

                let cumulative = if let Some(last) = self
                    .netlog_quic_stream_received_connection_cumulative
                    .last()
                {
                    last.1 + e.params.length
                } else {
                    // insert a 0'th point
                    e.params.length
                };

                self.netlog_quic_stream_received_connection_cumulative
                    .push((rel_event_time, cumulative));
            },

            QuicSessionUnauthenticatedPacketHeaderReceived(e) => {
                if let Some((_, last)) = self.received_packets_netlog.last() {
                    let gap = if e.params.packet_number > last.number {
                        e.params.packet_number - last.number
                    } else {
                        last.number.saturating_sub(e.params.packet_number)
                    };

                    if gap > 1 {
                        self.discontinuous_packet_number_count += 1;
                    }
                }

                let packet_type = PacketType::from_netlog_packet_header(
                    &e.params.header_format,
                    &e.params.long_header_type,
                );

                let packet_info = PacketInfoStub {
                    acked: None,
                    raw: None,
                    created_time: rel_event_time,
                    send_at_time: None,
                    ty: packet_type,
                    number: e.params.packet_number,
                };

                self.received_packets_netlog
                    .push((rel_event_time, packet_info.clone()));

                let s = self.packet_received.entry(packet_type).or_default();

                s.insert(e.params.packet_number, packet_info);
            },

            QuicSessionPacketSent(e) => {
                let packet_type = PacketType::from_netlog_encryption_level(
                    &e.params.encryption_level,
                );

                let packet_info = PacketInfoStub {
                    acked: None,
                    raw: None,
                    created_time: rel_event_time,
                    send_at_time: None,
                    ty: packet_type,
                    number: e.params.packet_number,
                };

                let s = self.packet_sent.entry(packet_type).or_default();

                s.insert(e.params.packet_number, packet_info);

                // Go back and update the Ack frame type if there was one
                if let Some(pkts) = self
                    .netlog_ack_sent_missing_packet
                    .get_mut(&PacketType::Unknown)
                {
                    if !pkts.is_empty() {
                        let old = std::mem::take(pkts);

                        let s = self
                            .netlog_ack_sent_missing_packet
                            .entry(packet_type)
                            .or_default();

                        for num in old {
                            s.insert(num);
                        }
                    }
                }
            },

            QuicSessionAckFrameSent(e) => {
                self.total_tx_ack += 1;
                self.max_ack_sent_missing_packets_size = std::cmp::max(
                    e.params.missing_packets.len(),
                    self.max_ack_sent_missing_packets_size,
                );

                if !e.params.missing_packets.is_empty() {
                    self.netlog_ack_sent_missing_packets_raw
                        .push((rel_event_time, e.params.missing_packets.clone()));
                }

                let s = self
                    .netlog_ack_sent_missing_packet
                    .entry(PacketType::Unknown)
                    .or_default();

                for pn in &e.params.missing_packets {
                    // At this stage, we don't know the packet type we sent the
                    // ACK in, because it comes later in the netlog. Insert with
                    // a placeholder now, and we'll update later in
                    // QuicSessionPacketSent handler. Ugly but functional.
                    s.insert(*pn);
                }
            },

            QuicSessionAckFrameReceived(e) => {
                self.total_rx_ack += 1;
                self.max_ack_received_missing_packets_size = std::cmp::max(
                    e.params.missing_packets.len(),
                    self.max_ack_sent_missing_packets_size,
                );

                if !e.params.missing_packets.is_empty() {
                    // For netlogs, it is assumed that the last packet received
                    // relates to this event.
                    let parent_packet = self.received_packets_netlog.last();
                    if let Some((_, pkt_info)) = parent_packet {
                        let s = self
                            .netlog_ack_received_missing_packet
                            .entry(pkt_info.ty)
                            .or_default();

                        for missing in &e.params.missing_packets {
                            s.insert(*missing);
                        }
                    }
                }
            },

            QuicSessionClosed(e) => {
                self.quic_session_close = Some(QuicSessionClose {
                    session_id: self.session_id.unwrap_or(-1),
                    sni: self.host.clone().unwrap_or("ERROR UNKNOWN".to_string()),
                    details: e.params.details.clone(),
                    from_peer: e.params.from_peer,
                    quic_error: e.params.quic_error,
                    quic_error_pretty: NaOption::new(
                        constants
                            .quic_error_id_keyed
                            .get(&e.params.quic_error)
                            .cloned(),
                    ),
                });
            },

            QuicSessionRstStreamFrameReceived(e) => {
                // Non-request streams can be reset, we don't care about them
                // right now
                if let Some(req) = self.http_requests.get_mut(&e.params.stream_id)
                {
                    req.quic_stream_reset_received = Some(QuicStreamReset {
                        offset: e.params.offset,
                        quic_rst_stream_error: e.params.quic_rst_stream_error,
                        quic_rst_stream_error_friendly: constants
                            .quic_rst_stream_error_id_keyed
                            .get(&(e.params.quic_rst_stream_error as i64))
                            .cloned(),
                    });
                }
            },

            QuicSessionRstStreamFrameSent(e) => {
                // Non-request streams can be reset, we don't care about them
                // right now
                if let Some(req) = self.http_requests.get_mut(&e.params.stream_id)
                {
                    req.quic_stream_reset_sent = Some(QuicStreamReset {
                        offset: e.params.offset,
                        quic_rst_stream_error: e.params.quic_rst_stream_error,
                        quic_rst_stream_error_friendly: constants
                            .quic_rst_stream_error_id_keyed
                            .get(&(e.params.quic_rst_stream_error as i64))
                            .cloned(),
                    });
                }
            },

            QuicSessionStopSendingFrameSent(e) => {
                // Non-request streams can be stopped, we don't care about them
                // right now
                if let Some(req) = self.http_requests.get_mut(&e.params.stream_id)
                {
                    req.quic_stream_stop_sending_sent =
                        Some(QuicStreamStopSending {
                            quic_rst_stream_error: e.params.quic_rst_stream_error,
                            quic_rst_stream_error_friendly: constants
                                .quic_rst_stream_error_id_keyed
                                .get(&(e.params.quic_rst_stream_error as i64))
                                .cloned(),
                        });
                }
            },

            QuicSessionBlockedFrameReceived(e) => {
                let s = self
                    .netlog_quic_server_window_blocked
                    .entry(e.params.stream_id)
                    .or_default();
                s.push(rel_event_time);
            },

            QuicSessionWindowUpdateFrameSent(e) => {
                let s = self
                    .netlog_quic_client_side_window_updates
                    .entry(e.params.stream_id)
                    .or_default();

                s.push((rel_event_time, e.params.byte_offset));
            },

            QuicSessionTransportParametersSent(e) => {
                self.client_quic_tps =
                    e.params.quic_transport_parameters.clone().into();

                let s = self
                    .netlog_quic_client_side_window_updates
                    .entry(-1)
                    .or_default();

                s.push((
                    rel_event_time,
                    self.client_quic_tps.initial_max_data.unwrap_or_default(),
                ));
            },

            // ignore the other events for now
            QuicSession(_) | QuicSessionTransportParametersReceived(_) => (),
        }
    }

    fn consume_netlog_h3(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &h3::Event, h3_session_requests: Option<&Vec<ReqOverH3>>,
    ) {
        let rel_event_time = (ev_hdr.time_num - session_start_time) as f32;

        match ev {
            Http3PriorityUpdateSent(e) => {
                let req =
                    self.get_or_insert_http_req(e.params.prioritized_element_id);
                req.priority_updates
                    .push(e.params.priority_field_value.clone());
            },

            Http3HeadersSent(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id);
                req.time_first_headers_tx.get_or_insert(rel_event_time);
                req.set_request_info_from_netlog(&e.params.headers);

                if let Some(reqs) = h3_session_requests {
                    for r in reqs {
                        if let Some(stream_id) = r.quic_stream_id {
                            if stream_id == e.params.stream_id {
                                // Hat-tip Olivia Trewin: this one cool trick
                                // allows u64's to be substracted into a correct
                                // i64.
                                req.time_discovery = Some(
                                    (r.discover_time
                                        .wrapping_sub(session_start_time)
                                        as i64)
                                        as f32,
                                );
                                break;
                            }
                        }
                    }
                }
            },

            // TODO: this is reception of headers frame, before the field
            // section is decoded. Ignore for now and just use the decoded event.
            Http3HeadersReceived(_) => (),

            Http3HeadersDecoded(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id);
                req.time_first_headers_rx.get_or_insert(rel_event_time);
                req.set_response_info_from_netlog(&e.params.headers);
            },

            Http3DataFrameReceived(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id);

                req.time_first_data_rx.get_or_insert(rel_event_time);

                let _ = req.time_last_data_rx.insert(rel_event_time);

                let length = e.params.payload_length;
                req.time_data_rx_set.push((rel_event_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );

                let s = self
                    .received_data_frames
                    .entry(e.params.stream_id)
                    .or_default();

                s.push((rel_event_time, e.params.payload_length));

                let s = self
                    .received_data_frames_count_based
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((
                    self.total_received_data_frame_count,
                    e.params.payload_length,
                ));

                self.total_received_data_frame_count += 1;

                let s = self
                    .received_data_cumulative
                    .entry(e.params.stream_id)
                    .or_default();

                let received_data_cumulative = if let Some(last) = s.last() {
                    last.1 + e.params.payload_length
                } else {
                    // insert a 0'th point
                    e.params.payload_length
                };

                s.push((rel_event_time, received_data_cumulative));

                let s = self
                    .received_data_cumulative_max
                    .entry(e.params.stream_id)
                    .or_default();

                *s = std::cmp::max(*s, received_data_cumulative);

                let s = self.http_requests.entry(e.params.stream_id).or_default();

                s.server_transferred_bytes = std::cmp::max(
                    s.server_transferred_bytes,
                    NaOption::new(Some(received_data_cumulative)),
                )
            },

            // TODO: add support for logging HTTP/2 sending
            Http3DataSent(_) => (),
        }
    }

    fn consume_netlog_h2(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &h2::Event, constants: &netlog::constants::Constants,
        stream_bind: &StreamBindingMap,
    ) {
        let rel_event_time = (ev_hdr.time_num - session_start_time) as f32;

        match ev {
            Http2SessionSendSettings(e) => {
                match Http2Settings::try_from(e.params.settings.as_slice()) {
                    Ok(v) => self.h2_client_settings = v,

                    Err(e) => error!("{}", e),
                }
            },

            Http2SessionRecvSetting(e) => {
                let re = Regex::new(H2_RECV_SETTING_PATTERN).unwrap();

                if let Some(m) =
                    re.captures(&e.params.id).and_then(|caps| caps.get(1))
                {
                    if let Ok(id) = m.as_str().parse::<u16>() {
                        self.h2_server_settings.set_from_wire(id, e.params.value);
                    } else {
                        error!("parsing H2 setting {:?}", e.params);
                    }
                } else {
                    error!("parsing H2 setting {:?}", e.params);
                }
            },
            Http2SessionSendHeaders(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id as u64);
                req.time_first_headers_tx.get_or_insert(rel_event_time);
                req.set_request_info_from_netlog(&e.params.headers);

                if let Some(sb) = stream_bind.get(&e.params.source_dependency.id)
                {
                    // Hat-tip Olivia Trewin: this one cool trick allows u64's to
                    // be substracted into a correct i64.
                    req.time_discovery = Some(
                        (sb.request_discovery_time
                            .wrapping_sub(session_start_time)
                            as i64) as f32,
                    );
                }

                self.h2_concurrent_requests += 1;
            },

            Http2SessionRecvHeaders(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id as u64);
                req.time_first_headers_rx.get_or_insert(rel_event_time);
                req.set_response_info_from_netlog(&e.params.headers);

                if e.params.fin {
                    self.h2_concurrent_requests -= 1;
                }
            },

            Http2SessionRecvData(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id as u64);

                req.time_first_data_rx.get_or_insert(rel_event_time);

                let _ = req.time_last_data_rx.insert(rel_event_time);

                let length = e.params.size as u64;
                req.time_data_rx_set.push((rel_event_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );

                let s = self
                    .received_data_frames
                    .entry(e.params.stream_id as u64)
                    .or_default();

                s.push((rel_event_time, e.params.size as u64));

                let s = self
                    .received_data_frames_count_based
                    .entry(e.params.stream_id as u64)
                    .or_default();
                s.push((
                    self.total_received_data_frame_count,
                    e.params.size as u64,
                ));

                self.total_received_data_frame_count += 1;

                let s = self
                    .received_data_cumulative
                    .entry(e.params.stream_id as u64)
                    .or_default();

                let received_data_cumulative = if let Some(last) = s.last() {
                    last.1 + e.params.size as u64
                } else {
                    // insert a 0'th point
                    e.params.size as u64
                };

                s.push((rel_event_time, received_data_cumulative));

                let s = self
                    .received_data_cumulative_max
                    .entry(e.params.stream_id as u64)
                    .or_default();

                *s = std::cmp::max(*s, received_data_cumulative);

                let s = self
                    .http_requests
                    .entry(e.params.stream_id as u64)
                    .or_default();

                s.server_transferred_bytes = std::cmp::max(
                    s.server_transferred_bytes,
                    NaOption::new(Some(received_data_cumulative)),
                );

                if e.params.fin {
                    self.h2_concurrent_requests -= 1;
                }

                let cumulative = if let Some(last) =
                    self.netlog_h2_stream_received_connection_cumulative.last()
                {
                    last.1 + e.params.size as u64
                } else {
                    // insert a 0'th point
                    e.params.size as u64
                };

                self.netlog_h2_stream_received_connection_cumulative
                    .push((rel_event_time, cumulative));
            },

            Http2SessionSendData(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id as u64);

                req.time_first_data_tx.get_or_insert(rel_event_time);

                let _ = req.time_last_data_tx.insert(rel_event_time);

                let length = e.params.size as u64;
                req.time_data_tx_set.push((rel_event_time, length));
                self.largest_data_frame_tx_length_global = std::cmp::max(
                    self.largest_data_frame_tx_length_global,
                    length,
                );

                let s = self
                    .sent_data_frames
                    .entry(e.params.stream_id as u64)
                    .or_default();

                s.push((rel_event_time, e.params.size as u64));

                let s = self
                    .sent_data_frames_count_based
                    .entry(e.params.stream_id as u64)
                    .or_default();
                s.push((self.total_sent_data_frame_count, e.params.size as u64));

                self.total_sent_data_frame_count += 1;

                // counterintuitively, reduces our local send window
                let s = self
                    .h2_send_window_updates_balanced
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((rel_event_time, -(e.params.size as i32)));

                let s = self
                    .sent_data_cumulative
                    .entry(e.params.stream_id as u64)
                    .or_default();

                let sent_data_cumulative = if let Some(last) = s.last() {
                    last.1 + e.params.size as u64
                } else {
                    // insert a 0'th point
                    e.params.size as u64
                };

                s.push((rel_event_time, sent_data_cumulative));

                let s = self
                    .sent_data_cumulative_max
                    .entry(e.params.stream_id as u64)
                    .or_default();

                *s = std::cmp::max(*s, sent_data_cumulative);

                let s = self
                    .http_requests
                    .entry(e.params.stream_id as u64)
                    .or_default();

                s.client_transferred_bytes = std::cmp::max(
                    s.client_transferred_bytes,
                    NaOption::new(Some(sent_data_cumulative)),
                );
            },

            // counterintuitively, updates our local send window
            Http2SessionRecvWindowUpdate(e) => {
                let s = self
                    .h2_send_window_updates_balanced
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((rel_event_time, e.params.delta));
            },

            // counterintuitively, updates our local receive window
            Http2SessionSendWindowUpdate(e) => {
                let s = self
                    .h2_send_window_updates_balanced
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((rel_event_time, e.params.delta));

                let s = self
                    .h2_send_window_updates_absolute
                    .entry(e.params.stream_id)
                    .or_default();
                // Window updates always have a positive delta, so this is fine.
                s.push((rel_event_time, e.params.delta as u64));
            },

            Http2SessionClose(e) => {
                self.h2_session_close = Some(H2SessionClose {
                    session_id: self.session_id.unwrap_or(-1),
                    sni: self.host.clone().unwrap_or("ERROR UNKNOWN".to_string()),
                    details: e.params.description.clone(),
                    net_err: e.params.net_error,
                    net_err_pretty: NaOption::new(
                        constants
                            .net_error_id_keyed
                            .get(&e.params.net_error)
                            .cloned(),
                    ),
                });
            },

            Http2SessionSendRstStream(e) => {
                if let Some(req) =
                    self.http_requests.get_mut(&(e.params.stream_id as u64))
                {
                    req.h2_stream_reset_sent = Some(H2StreamReset {
                        error: e.params.error_code.clone(),
                        description: e.params.description.clone(),
                    });
                }
            },

            Http2SessionRecvRstStream(e) => {
                if let Some(req) =
                    self.http_requests.get_mut(&(e.params.stream_id as u64))
                {
                    req.h2_stream_reset_receive = Some(H2StreamReset {
                        error: e.params.error_code.clone(),
                        description: "".to_string(),
                    });
                }
                self.h2_concurrent_requests -= 1;
            },

            // ignore the other events for now
            Http2Session(_) => (),
            Http2SessionInitialized(_) => (),
            Http2SessionUpdateRecvWindow(_) => (),
            Http2SessionUpdateSendWindow(_) => (),
            Http2SessionUpdateStreamsSendWindowSize(_) => (),
            Http2SessionStalledMaxStreams(_) => (),

            Http2StreamUpdateSendWindow(_) => (),
            Http2StreamUpdateRecvWindow(_) => (),
            Http2StreamStalledByStreamSendWindow(_) => (),
            Http2SessionPing(_) => (),

            Http2SessionRecvGoaway(_) => (),
        }
    }

    pub fn consume_qlog_event(
        &mut self, event: &qlog::events::Event, process_acks: bool,
    ) {
        let ev_time = event.time;

        if ev_time > self.last_event_time {
            self.last_event_time = ev_time;
        }

        match &event.data {
            EventData::TransportParametersSet(v) =>
                self.consume_qlog_transport_parameters_set(v),

            EventData::PacketReceived(v) =>
                self.consume_qlog_packet_received(v, ev_time, process_acks),

            EventData::PacketSent(v) => self.consume_qlog_packet_sent(v, ev_time),

            EventData::DataMoved(v) => self.consume_qlog_data_moved(v, ev_time),

            EventData::MetricsUpdated(v) =>
                self.consume_qlog_metrics_updated(v, ev_time),

            EventData::CongestionStateUpdated(v) =>
                self.consume_qlog_congestion_state_updated(v, ev_time),

            EventData::H3FrameCreated(v) => match self.vantage_point {
                VantagePoint::Client =>
                    self.consume_qlog_h3_frame_created_client(v, ev_time),
                VantagePoint::Server =>
                    self.consume_qlog_h3_frame_created_server(v, ev_time),
            },

            EventData::H3FrameParsed(v) => match self.vantage_point {
                VantagePoint::Client =>
                    self.consume_qlog_h3_frame_parsed_client(v, ev_time),
                VantagePoint::Server =>
                    self.consume_qlog_h3_frame_parsed_server(v, ev_time),
            },

            _ => (), // trace!("skipping {:?}", event.data),
        }
    }

    pub fn with_qlog_events(
        events: &[qlog::events::Event], vantage_point: &qlog::VantagePointType,
        process_acks: bool,
    ) -> Self {
        let vp = match vantage_point {
            qlog::VantagePointType::Client => VantagePoint::Client,
            qlog::VantagePointType::Server => VantagePoint::Server,
            _ => panic!("unknown vantage point type"),
        };

        let mut ds = Datastore {
            vantage_point: vp,
            ..Default::default()
        };

        for event in events {
            ds.consume_qlog_event(event, process_acks);
        }

        ds.hydrate_http_requests();
        ds.finalize();

        ds
    }

    pub fn finalize(&mut self) {
        if let Some(last) = self.local_cwnd.last().cloned() {
            self.local_cwnd.push((self.last_event_time, last.1));
        }

        if let Some(last) = self.local_pacing_rate.last().cloned() {
            trace!("pushing last {:?}", last);
            self.local_pacing_rate.push((self.last_event_time, last.1));
        }
    }

    pub fn hydrate_http_requests(&mut self) {
        for req in self.http_requests.values_mut() {
            req.calculate_deltas();
            req.calculate_upload_download_rate();
        }
    }

    fn consume_qlog_transport_parameters_set(
        &mut self, tp: &qlog::events::quic::TransportParametersSet,
    ) {
        match tp.owner {
            Some(TransportOwner::Local) => {
                if let Some(max_data) = tp.initial_max_data {
                    self.sent_max_data.push((0.0, max_data));
                }

                if let Some(max_stream_data) =
                    tp.initial_max_stream_data_bidi_local
                {
                    self.local_init_max_stream_data_bidi_local = max_stream_data;
                }

                if let Some(max_stream_data) = tp.initial_max_stream_data_uni {
                    self.local_init_max_stream_data_uni = max_stream_data;
                }
            },

            Some(TransportOwner::Remote) => {
                if let Some(max_data) = tp.initial_max_data {
                    self.received_max_data.push((0.0, max_data));
                }

                if let Some(max_stream_data) =
                    tp.initial_max_stream_data_bidi_local
                {
                    self.peer_init_max_stream_data_bidi_local = max_stream_data;
                }

                if let Some(max_stream_data) =
                    tp.initial_max_stream_data_bidi_remote
                {
                    self.peer_init_max_stream_data_bidi_remote = max_stream_data;
                }

                if let Some(max_stream_data) = tp.initial_max_stream_data_uni {
                    self.peer_init_max_stream_data_uni = max_stream_data;
                }
            },

            _ => unimplemented!(),
        }
    }

    fn consume_qlog_packet_received(
        &mut self, pr: &qlog::events::quic::PacketReceived, ev_time: f32,
        process_acks: bool,
    ) {
        if let Some(frames) = &pr.frames {
            for frame in frames {
                match frame {
                    QuicFrame::Ack { acked_ranges, .. } => {
                        if process_acks {
                            if let Some(ack_ranges) = acked_ranges {
                                let ty = PacketType::from_qlog_packet_type(
                                    &pr.header.packet_type,
                                );
                                if let Some(pkt_space) =
                                    self.packet_sent.get_mut(&ty)
                                {
                                    match ack_ranges {
                                        AckedRanges::Single(ranges) => {
                                            // TODO: qlog deserializer seems to
                                            // get confused (bug?) so work
                                            // around it detecting single or
                                            // pairs

                                            for pkt_nums in ranges {
                                                if pkt_nums.len() == 1 {
                                                    if let Some(pkt) = pkt_space
                                                        .get_mut(&pkt_nums[0])
                                                    {
                                                        pkt.acked = Some(true);
                                                    }
                                                } else if pkt_nums.len() == 2 {
                                                    // TODO: check ack ranges and
                                                    // rust
                                                    // Range mapping is correct
                                                    let actual_range = pkt_nums
                                                        [0]..
                                                        pkt_nums[1] + 1;

                                                    pkt_space
                                                        .range_mut(actual_range)
                                                        .for_each(|e| {
                                                            e.1.acked = Some(true)
                                                        });
                                                }
                                            }
                                        },
                                        AckedRanges::Double(ranges) => {
                                            for range in ranges {
                                                // TODO: check ack ranges and rust
                                                // Range mapping is correct
                                                let actual_range =
                                                    range.0..range.1 + 1;

                                                pkt_space
                                                    .range_mut(actual_range)
                                                    .for_each(|e| {
                                                        e.1.acked = Some(true)
                                                    });
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    },

                    QuicFrame::MaxData { maximum } => {
                        self.received_max_data.push((ev_time, *maximum));
                    },

                    QuicFrame::MaxStreamData { stream_id, maximum } => {
                        let init_val = if is_bidi(*stream_id) {
                            self.peer_init_max_stream_data_bidi_remote
                        } else {
                            self.peer_init_max_stream_data_uni
                        };
                        self.received_stream_max_data_tracker
                            .update(*stream_id, *maximum, ev_time, init_val);
                    },

                    QuicFrame::ResetStream { stream_id, .. } => {
                        let s = self
                            .received_reset_stream
                            .entry(*stream_id)
                            .or_default();
                        s.push(frame.clone());
                    },

                    QuicFrame::Stream {
                        stream_id,
                        length,
                        offset,
                        ..
                    } => {
                        let s = self
                            .received_stream_frames
                            .entry(*stream_id)
                            .or_default();
                        s.push((ev_time, StreamDatapoint {
                            length: *length,
                            offset: *offset,
                        }));

                        let s = self
                            .received_stream_frames_count_based
                            .entry(*stream_id)
                            .or_default();
                        s.push((
                            self.total_received_stream_frame_count,
                            StreamDatapoint {
                                length: *length,
                                offset: *offset,
                            },
                        ));

                        self.total_received_stream_frame_count += 1;
                    },

                    _ => (),
                }
            }
        }
    }

    fn consume_qlog_packet_sent(
        &mut self, ps: &qlog::events::quic::PacketSent, ev_time: f32,
    ) {
        // If there's no packet number we'll have to skip processing.
        if ps.header.packet_number.is_none() {
            return;
        }

        let packet_type =
            PacketType::from_qlog_packet_type(&ps.header.packet_type);
        let packet_info = PacketInfoStub {
            acked: None,
            raw: ps.raw.clone(),
            created_time: ev_time,
            send_at_time: ps.send_at_time,
            ty: packet_type,
            number: ps.header.packet_number.unwrap(),
        };

        let s = self.packet_sent.entry(packet_type).or_default();

        s.insert(ps.header.packet_number.unwrap(), packet_info);

        // Prefer to use the packet_sent send_at_time if it exists. Otherwise
        // fallback to the event time.
        let event_time = ps.send_at_time.unwrap_or(ev_time);

        if let Some(frames) = &ps.frames {
            for frame in frames {
                match frame {
                    QuicFrame::Ack { .. } => {
                        // TODO
                    },

                    QuicFrame::MaxData { maximum } => {
                        self.sent_max_data.push((event_time, *maximum));
                    },

                    QuicFrame::MaxStreamData { stream_id, maximum } => {
                        let init_val = if is_bidi(*stream_id) {
                            self.local_init_max_stream_data_bidi_local
                        } else {
                            self.local_init_max_stream_data_uni
                        };
                        self.sent_stream_max_data_tracker
                            .update(*stream_id, *maximum, ev_time, init_val);
                    },

                    QuicFrame::ResetStream { stream_id, .. } => {
                        let s =
                            self.sent_reset_stream.entry(*stream_id).or_default();
                        s.push(frame.clone());
                    },

                    QuicFrame::Stream { stream_id, .. } => {
                        let s = self
                            .sent_stream_frames
                            .entry(*stream_id)
                            .or_default();
                        s.push((event_time, frame.clone()));

                        let s = self
                            .sent_stream_frames_count_based
                            .entry(*stream_id)
                            .or_default();
                        s.push((
                            self.total_sent_stream_frame_count,
                            frame.clone(),
                        ));

                        self.total_sent_stream_frame_count += 1;
                    },

                    QuicFrame::DataBlocked { limit, .. } => {
                        trace!(
                            "todo DATA_BLOCKED t={} limit={}",
                            event_time,
                            limit
                        );
                    },

                    QuicFrame::StreamDataBlocked {
                        stream_id, limit, ..
                    } => {
                        trace!(
                            "todo STREAM_DATA_BLOCKED t={} stream={} limit={}",
                            event_time,
                            stream_id,
                            limit
                        );
                    },

                    _ => (),
                }
            }
        }
    }

    fn consume_qlog_data_moved(
        &mut self, dm: &qlog::events::quic::DataMoved, ev_time: f32,
    ) {
        if let Some(recipient) = &dm.to {
            let tracker = match recipient {
                qlog::events::DataRecipient::Application =>
                    &mut self.stream_buffer_reads_tracker,
                qlog::events::DataRecipient::Transport =>
                    &mut self.stream_buffer_writes_tracker,
                qlog::events::DataRecipient::Dropped =>
                    &mut self.stream_buffer_dropped_tracker,
                _ => todo!(),
            };

            if let Some(stream_id) = dm.stream_id {
                if let (Some(offset), Some(length)) = (dm.offset, dm.length) {
                    tracker.update(
                        stream_id,
                        StreamAccess { offset, length },
                        ev_time,
                    );
                }
            }
        }
    }

    fn consume_qlog_metrics_updated(
        &mut self, mu: &qlog::events::quic::MetricsUpdated, ev_time: f32,
    ) {
        if let Some(cwnd) = mu.congestion_window {
            self.local_cwnd.push((ev_time, cwnd));
        }

        if let Some(bif) = mu.bytes_in_flight {
            self.local_bytes_in_flight.push((ev_time, bif));
        }

        if let Some(rtt) = mu.min_rtt {
            self.local_min_rtt.push((ev_time, rtt));
        }

        if let Some(rtt) = mu.latest_rtt {
            self.local_latest_rtt.push((ev_time, rtt));
        }

        if let Some(rtt) = mu.smoothed_rtt {
            self.local_smoothed_rtt.push((ev_time, rtt));
        }

        if let Some(thresh) = mu.ssthresh {
            self.local_ssthresh.push((ev_time, thresh));
        }

        if let Some(pacing_rate) = mu.pacing_rate {
            self.local_pacing_rate.push((ev_time, pacing_rate));
        }

        // Extract rate metrics from ex_data
        if let Some(rate) = mu.ex_data.get("cf_delivery_rate").and_then(|v| v.as_u64()) {
            self.local_delivery_rate.push((ev_time, rate));
        }

        if let Some(rate) = mu.ex_data.get("cf_send_rate").and_then(|v| v.as_u64()) {
            self.local_send_rate.push((ev_time, rate));
        }

        if let Some(rate) = mu.ex_data.get("cf_ack_rate").and_then(|v| v.as_u64()) {
            self.local_ack_rate.push((ev_time, rate));
        }
    }

    fn consume_qlog_congestion_state_updated(
        &mut self, csu: &qlog::events::quic::CongestionStateUpdated, ev_time: f32,
    ) {
        // give this a virtual y-value of the last cwnd value recorded, we
        // can choose to use it or not later.
        self.congestion_state_updates.push((
            ev_time,
            self.local_cwnd.last().unwrap().1,
            csu.new.clone(),
        ));
    }

    fn get_or_insert_http_req(&mut self, stream_id: u64) -> &mut HttpRequestStub {
        self.http_requests
            .entry(stream_id)
            .or_insert(HttpRequestStub {
                stream_id,
                request_actor: self.vantage_point.into(),
                ..Default::default()
            })
    }

    fn consume_qlog_h3_frame_created_client(
        &mut self, fc: &qlog::events::h3::H3FrameCreated, ev_time: f32,
    ) {
        match &fc.frame {
            Http3Frame::Headers { headers } => {
                let req = self.get_or_insert_http_req(fc.stream_id);
                req.time_first_headers_tx.get_or_insert(ev_time);
                req.set_request_info_from_qlog(headers);
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fc.stream_id);

                req.time_first_data_tx.get_or_insert(ev_time);

                let _ = req.time_last_data_tx.insert(ev_time);

                let length = fc.length.unwrap_or_default();
                req.time_data_tx_set.push((ev_time, length));
                self.largest_data_frame_tx_length_global = std::cmp::max(
                    self.largest_data_frame_tx_length_global,
                    length,
                );
            },

            Http3Frame::PriorityUpdate {
                prioritized_element_id,
                priority_field_value,
                ..
            } => {
                let req = self.get_or_insert_http_req(*prioritized_element_id);
                req.priority_updates.push(priority_field_value.clone());
            },

            // ignore other frames
            _ => (),
        }
    }

    fn consume_qlog_h3_frame_created_server(
        &mut self, fc: &qlog::events::h3::H3FrameCreated, ev_time: f32,
    ) {
        match &fc.frame {
            Http3Frame::Headers { headers } => {
                let req = self.get_or_insert_http_req(fc.stream_id);
                req.time_first_headers_tx.get_or_insert(ev_time);
                req.set_response_info_from_qlog(headers);
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fc.stream_id);

                req.time_first_data_tx.get_or_insert(ev_time);

                let _ = req.time_last_data_tx.insert(ev_time);

                let length = fc.length.unwrap_or_default();
                req.time_data_tx_set.push((ev_time, length));
                self.largest_data_frame_tx_length_global = std::cmp::max(
                    self.largest_data_frame_tx_length_global,
                    length,
                );
            },

            // ignore other frames
            _ => (),
        }
    }

    fn consume_qlog_h3_frame_parsed_client(
        &mut self, fp: &qlog::events::h3::H3FrameParsed, ev_time: f32,
    ) {
        match &fp.frame {
            Http3Frame::Headers { headers } => {
                let req = self.get_or_insert_http_req(fp.stream_id);
                req.time_first_headers_rx.get_or_insert(ev_time);

                req.set_response_info_from_qlog(headers);
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fp.stream_id);

                req.time_first_data_rx.get_or_insert(ev_time);

                let _ = req.time_last_data_rx.insert(ev_time);

                // TODO: is default length sensible here?
                let length = fp.length.unwrap_or_default();
                req.time_data_rx_set.push((ev_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );

                let s =
                    self.received_data_frames.entry(fp.stream_id).or_default();

                s.push((ev_time, length));
            },

            // ignore other frames
            _ => (),
        }
    }

    fn consume_qlog_h3_frame_parsed_server(
        &mut self, fp: &qlog::events::h3::H3FrameParsed, ev_time: f32,
    ) {
        match &fp.frame {
            Http3Frame::Headers { headers } => {
                let req = self.get_or_insert_http_req(fp.stream_id);
                req.time_first_headers_rx.get_or_insert(ev_time);
                req.path = NaOption::new(find_header_value(headers, ":path"));
                req.client_pri_hdr =
                    NaOption::new(find_header_value(headers, "priority"));
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fp.stream_id);

                req.time_first_data_rx.get_or_insert(ev_time);

                let _ = req.time_last_data_rx.insert(ev_time);

                let length = fp.length.unwrap_or_default();
                req.time_data_rx_set.push((ev_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );
            },

            Http3Frame::PriorityUpdate {
                prioritized_element_id,
                priority_field_value,
                ..
            } => {
                let req = self.get_or_insert_http_req(*prioritized_element_id);
                req.priority_updates.push(priority_field_value.clone());
            },

            // ignore other frames
            _ => (),
        }
    }

    pub fn with_sqlog_reader_events(
        events: &[qlog::reader::Event], vantage_point: &qlog::VantagePointType,
        process_acks: bool,
    ) -> Self {
        let vp = match vantage_point {
            qlog::VantagePointType::Client => VantagePoint::Client,
            qlog::VantagePointType::Server => VantagePoint::Server,
            _ => panic!("unknown vantage point type"),
        };

        let mut ds = Datastore {
            total_sent_stream_frame_count: 0,
            vantage_point: vp,
            ..Default::default()
        };

        for event in events {
            match event {
                qlog::reader::Event::Qlog(ev) => {
                    ds.consume_qlog_event(ev, process_acks);
                },

                qlog::reader::Event::Json(ev) => {
                    // Just swallow the failure and move on
                    error!("unhandled Json event {:?}", ev);
                },
            }
        }

        ds.hydrate_http_requests();
        ds.finalize();

        ds
    }
}

#[derive(Tabled)]
pub struct NetlogSession {
    #[tabled(rename = "ID")]
    session_id: i64,
    #[tabled(rename = "Protocol")]
    application_proto: ApplicationProto,
    #[tabled(rename = "SNI")]
    host: String,
    start_time: u64,
}

impl Debug for NetlogSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "app proto={:?}, host={}",
            self.application_proto, self.host
        )
    }
}

pub struct RequestDiscovery {
    pub time: u64,
    pub stream_job_id: Option<i64>,
}

pub struct StreamBind {
    pub time: u64,
    pub request_discovery_id: i64,
    pub request_discovery_time: u64,
}

pub type RequestDiscoveryMap = BTreeMap<i64, RequestDiscovery>;
pub type StreamBindingMap = BTreeMap<i64, StreamBind>;

#[derive(Debug)]
pub struct ReqOverH3 {
    pub id: i64,
    pub discover_time: u64,
    pub session_id: Option<i64>,
    pub quic_stream_id: Option<u64>,
}

pub type RequestOverH3Map = BTreeMap<i64, Vec<ReqOverH3>>;

pub fn with_netlog_reader<R: std::io::BufRead>(
    reader: &mut R, hostname_filter: HashSet<String>,
    constants: &netlog::constants::Constants,
) -> (Vec<LogFileData>, BTreeMap<i64, NetlogSession>) {
    // second line in a netlog is always `"events": [` so skip it
    read_netlog_record(reader);

    let mut sessions: BTreeMap<i64, NetlogSession> = BTreeMap::new();
    let mut session_events: BTreeMap<
        i64,
        Vec<(netlog::EventHeader, netlog::Event)>,
    > = BTreeMap::new();

    let mut h3_session_requests: RequestOverH3Map = BTreeMap::new();

    let mut req_id_to_session_id: BTreeMap<i64, i64> = BTreeMap::new();

    let mut request_discovery: RequestDiscoveryMap = BTreeMap::new();
    let mut stream_bind: StreamBindingMap = BTreeMap::new();

    while let Some(event) = read_netlog_record(reader) {
        let res: Result<netlog::EventHeader, serde_json::Error> =
            serde_json::from_slice(&event);

        match res {
            Ok(mut event_hdr) => {
                event_hdr.populate_strings(constants);
                event_hdr.time_num = event_hdr.time.parse::<u64>().unwrap();

                // If this is a session creation, store the session, so we can
                // link events with it. The source ID of these events is the
                // unique value that we will use to link things together.
                // This assumes events belonging to a session do not occur
                // before the session is created.
                if event_hdr.phase_string == "PHASE_BEGIN" {
                    match event_hdr.ty_string.as_str() {
                        "QUIC_SESSION" => {
                            let ev: QuicSessionEvent =
                                serde_json::from_slice(&event).unwrap();

                            // QUIC sessions split host and port, which
                            // interferes with filter expression, so merge them
                            let host =
                                format!("{}:{}", ev.params.host, ev.params.port,);

                            sessions.insert(event_hdr.source.id, NetlogSession {
                                session_id: event_hdr.source.id,
                                application_proto: ApplicationProto::Http3,
                                host: host.clone(),
                                start_time: event_hdr
                                    .time
                                    .parse::<u64>()
                                    .unwrap(),
                            });

                            let do_insert = hostname_filter.is_empty() ||
                                hostname_filter.contains(&host);

                            if do_insert {
                                session_events
                                    .insert(event_hdr.source.id, Vec::new());

                                h3_session_requests
                                    .insert(event_hdr.source.id, Vec::new());
                            }
                        },

                        "HTTP2_SESSION" => {
                            let ev: Http2SessionEvent =
                                serde_json::from_slice(&event).unwrap();

                            sessions.insert(event_hdr.source.id, NetlogSession {
                                session_id: event_hdr.source.id,
                                application_proto: ApplicationProto::Http2,
                                host: ev.params.host.clone(),
                                start_time: event_hdr
                                    .time
                                    .parse::<u64>()
                                    .unwrap(),
                            });

                            let do_insert = hostname_filter.is_empty() ||
                                hostname_filter.contains(&ev.params.host);

                            if do_insert {
                                session_events
                                    .insert(event_hdr.source.id, Vec::new());
                            }
                        },

                        "CORS_REQUEST" => {
                            // Seems to be the earliest netlog event related to
                            // any request.
                            request_discovery.insert(
                                event_hdr.source.id,
                                RequestDiscovery {
                                    time: event_hdr.time_num,
                                    stream_job_id: None,
                                },
                            );
                        },

                        _ => (),
                    }
                }

                if event_hdr.ty_string.starts_with("HTTP_") {
                    let event = netlog::http::parse_event(&event_hdr, &event);

                    // This will eventually deal with other events, and having
                    // to refactor back and forth is a waste.
                    #[allow(clippy::single_match)]
                    match event {
                        Some(netlog::Event::Http(e)) => {
                            match e {
                                http::Event::HttpStreamJobBoundToRequest(v)  => {
                                    let request_discovery_id = v.params.source_dependency.id;
                                    if let Some(rd) = request_discovery.get_mut(&request_discovery_id) {
                                        stream_bind.insert(event_hdr.source.id, StreamBind{time: event_hdr.time_num, request_discovery_id, request_discovery_time: rd.time});
                                        rd.stream_job_id = Some(event_hdr.source.id);
                                    }
                                },

                                http::Event::HttpStreamRequestBoundToQuicSession(v) => {
                                    let request_discovery_id = event_hdr.source.id;
                                    if let Some(rd) = request_discovery.get(&request_discovery_id) {

                                        if let Some(session_requests) = h3_session_requests.get_mut(&v.params.source_dependency.id) {
                                            let req = ReqOverH3{id: event_hdr.source.id, discover_time: rd.time, session_id: Some(v.params.source_dependency.id), quic_stream_id: None };
                                            session_requests.push(req);

                                            // populate reverse mapping, each unique request ID has a session ID
                                            req_id_to_session_id.insert(event_hdr.source.id, v.params.source_dependency.id);
                                        }
                                    }
                                }

                                http::Event::HttpTransactionQuicSendRequestHeaders(v) => {
                                    let req_id = event_hdr.source.id;
                                    if let Some(session_id) = req_id_to_session_id.get(&req_id) {
                                        if let Some(reqs) = h3_session_requests.get_mut(session_id) {
                                            // todo replace vec with map?
                                            for req in reqs {
                                                if req.id == req_id {
                                                    req.quic_stream_id = Some(v.params.quic_stream_id);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                _ => (),
                            }
                        },

                        // ignore other events
                        _ => (),
                    }
                }

                if let Some(session) =
                    session_events.get_mut(&event_hdr.source.id)
                {
                    if let Some(ev) = netlog::parse_event(&event_hdr, &event) {
                        session.push((event_hdr, ev));
                    }
                }
            },

            Err(e) => {
                error!("Error deserializing: {}", e);
                error!("input value {}", String::from_utf8_lossy(&event));

                // Just swallow the failure and move on
            },
        }
    }

    println!("All sessions in this netlog = {:#?}", sessions);

    let mut log_file_data = Vec::new();

    for (session_id, details) in &sessions {
        if let Some(events) = session_events.get(session_id) {
            let mut ds = Datastore {
                session_id: Some(*session_id),
                application_proto: details.application_proto,
                host: Some(details.host.clone()),
                total_sent_stream_frame_count: 0,
                ..Default::default()
            };

            for (ev_hdr, event) in events {
                ds.consume_netlog_event(
                    details.start_time,
                    ev_hdr,
                    event,
                    constants,
                    &stream_bind,
                    h3_session_requests.get(session_id),
                );
            }

            ds.hydrate_http_requests();
            ds.finalize();
            log_file_data.push(LogFileData {
                datastore: ds,
                raw: Netlog,
            });
        }
    }

    (log_file_data, sessions)
}
