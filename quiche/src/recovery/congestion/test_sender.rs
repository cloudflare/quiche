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

use std::collections::VecDeque;
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::congestion::Congestion;
use crate::recovery::rtt::RttStats;
use crate::recovery::Acked;
use crate::recovery::RecoveryConfig;
use crate::recovery::Sent;
use crate::CongestionControlAlgorithm;

pub(crate) struct TestSender {
    cc: Congestion,
    pub(crate) next_pkt: u64,
    pub(crate) next_ack: u64,
    pub(crate) bytes_in_flight: usize,
    pub(crate) time: Instant,
    rtt_stats: RttStats,
    sent_packets: VecDeque<Sent>,
}

impl TestSender {
    pub(crate) fn new(algo: CongestionControlAlgorithm, hystart: bool) -> Self {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(algo);
        cfg.enable_hystart(hystart);

        TestSender {
            next_pkt: 0,
            next_ack: 0,
            bytes_in_flight: 0,
            time: Instant::now(),
            rtt_stats: RttStats::new(Duration::from_micros(0)),
            cc: Congestion::from_config(&RecoveryConfig::from_config(&cfg)),
            sent_packets: VecDeque::new(),
        }
    }

    pub(crate) fn send_packet(&mut self, bytes: usize) {
        let mut sent = Sent {
            pkt_num: self.next_pkt,
            frames: Default::default(),
            time_sent: self.time,
            time_acked: None,
            time_lost: None,
            size: bytes,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: self.time,
            first_sent_time: self.time,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        self.cc.on_packet_sent(
            self.bytes_in_flight,
            bytes,
            self.time,
            &mut sent,
            &self.rtt_stats,
            0,
            true,
        );

        self.sent_packets.push_back(sent);

        self.bytes_in_flight += bytes;
        self.next_pkt += 1;
    }

    pub(crate) fn inject_ack(&mut self, acked: Acked, now: Instant) {
        let _ = self.sent_packets.pop_front().unwrap();

        self.cc.on_packets_acked(
            self.bytes_in_flight,
            &mut vec![acked],
            &self.rtt_stats,
            now,
        );
    }

    pub(crate) fn ack_n_packets(&mut self, n: usize, bytes: usize) {
        let mut acked = Vec::new();

        for _ in 0..n {
            let unacked = self.sent_packets.pop_front().unwrap();

            acked.push(Acked {
                pkt_num: unacked.pkt_num,
                time_sent: unacked.time_sent,
                size: unacked.size,

                rtt: self.time.saturating_duration_since(unacked.time_sent),
                delivered: unacked.delivered,
                delivered_time: unacked.delivered_time,
                first_sent_time: unacked.first_sent_time,
                is_app_limited: unacked.is_app_limited,
            });

            self.next_ack += 1;
        }

        self.cc.on_packets_acked(
            self.bytes_in_flight,
            &mut acked,
            &self.rtt_stats,
            self.time,
        );

        self.bytes_in_flight -= n * bytes;
    }

    pub(crate) fn lose_n_packets(
        &mut self, n: usize, bytes: usize, time_sent: Option<Instant>,
    ) {
        let mut unacked = None;

        for _ in 0..n {
            self.next_ack += 1;
            unacked = self.sent_packets.pop_front();
        }

        let mut unacked = unacked.unwrap();
        if let Some(time) = time_sent {
            unacked.time_sent = time;
        }

        if !self.cc.in_congestion_recovery(unacked.time_sent) {
            (self.cc.cc_ops.checkpoint)(&mut self.cc);
        }

        (self.cc_ops.congestion_event)(
            &mut self.cc,
            self.bytes_in_flight,
            n * bytes,
            &unacked,
            self.time,
        );

        self.cc.lost_count += n;
        self.bytes_in_flight -= n * bytes;
    }

    pub(crate) fn update_rtt(&mut self, rtt: Duration) {
        self.rtt_stats
            .update_rtt(rtt, Duration::ZERO, self.time, true)
    }

    pub(crate) fn advance_time(&mut self, period: Duration) {
        self.time += period;
    }
}

impl Deref for TestSender {
    type Target = Congestion;

    fn deref(&self) -> &Self::Target {
        &self.cc
    }
}

impl DerefMut for TestSender {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cc
    }
}
