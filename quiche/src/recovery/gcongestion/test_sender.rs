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

use super::Acked;
use crate::packet;
use crate::ranges::RangeSet;
use crate::recovery::gcongestion::GRecovery;
use crate::recovery::HandshakeStatus;
use crate::recovery::RecoveryConfig;
use crate::recovery::RecoveryOps;
use crate::recovery::Sent;
use crate::CongestionControlAlgorithm;

pub(crate) struct TestSender {
    pub(crate) cc: GRecovery,
    pub(crate) next_pkt: u64,
    pub(crate) next_ack: u64,
    pub(crate) bytes_in_flight: usize,
    pub(crate) time: Instant,
    sent_packets: VecDeque<Sent>,
}

impl TestSender {
    pub(crate) fn new(
        algo: CongestionControlAlgorithm, enable_bbr_fix: bool,
    ) -> Self {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(algo);
        cfg.enable_hystart(false);

        cfg.set_enable_bbr_fix(enable_bbr_fix);
        TestSender {
            next_pkt: 0,
            next_ack: 0,
            bytes_in_flight: 0,
            time: Instant::now(),
            cc: GRecovery::new(&RecoveryConfig::from_config(&cfg)).unwrap(),
            sent_packets: VecDeque::new(),
        }
    }

    pub(crate) fn send_packet(
        &mut self, bytes: usize, epoch: packet::Epoch,
        handshake_status: HandshakeStatus,
    ) {
        let sent = Sent {
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
            has_data: true,
            is_pmtud_probe: false,
        };

        self.cc.on_packet_sent(
            sent.clone(),
            epoch,
            handshake_status,
            self.time,
            &"".to_owned(),
        );

        self.sent_packets.push_back(sent.clone());

        self.bytes_in_flight += bytes;
        self.next_pkt += 1;
    }

    pub(crate) fn ack_n_packets(
        &mut self, n: usize, bytes: usize, ack_delay: u64, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, skip_pn: Option<u64>,
    ) {
        let mut acked = Vec::new();
        let mut range = RangeSet::new(n);
        for _ in 0..n {
            let unacked = self.sent_packets.pop_front().unwrap();
            acked.push(Acked {
                pkt_num: unacked.pkt_num,
                time_sent: unacked.time_sent,
            });
            range.push_item(unacked.pkt_num as u64);
            self.next_ack += 1;
        }
        let _ = self.cc.on_ack_received(
            &range,
            ack_delay,
            epoch,
            handshake_status,
            self.time,
            skip_pn,
            &"".to_ascii_lowercase(),
        );
        self.bytes_in_flight -= n * bytes;
    }

    pub(crate) fn advance_time(&mut self, period: Duration) {
        self.time += period;
    }
}

impl Deref for TestSender {
    type Target = GRecovery;

    fn deref(&self) -> &Self::Target {
        &self.cc
    }
}

impl DerefMut for TestSender {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cc
    }
}
