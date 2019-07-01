// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use std::collections::BTreeMap;

use crate::frame;
use crate::packet;
use crate::ranges;

// Loss Recovery
const PACKET_THRESHOLD: u64 = 3;

const GRANULARITY: Duration = Duration::from_millis(1);

const INITIAL_RTT: Duration = Duration::from_millis(500);

// Congestion Control
pub const INITIAL_WINDOW_PACKETS: usize = 10;

const MAX_DATAGRAM_SIZE: usize = 1452;

const INITIAL_WINDOW: usize = INITIAL_WINDOW_PACKETS * MAX_DATAGRAM_SIZE;
const MINIMUM_WINDOW: usize = 2 * MAX_DATAGRAM_SIZE;

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

#[derive(Debug)]
pub struct Sent {
    pub pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    pub time: Instant,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,

    pub is_crypto: bool,
}

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    crypto_count: u32,

    pto_count: u32,

    time_of_last_sent_ack_eliciting_pkt: Instant,

    time_of_last_sent_crypto_pkt: Instant,

    largest_acked_pkt: [u64; packet::EPOCH_COUNT],

    latest_rtt: Duration,

    smoothed_rtt: Option<Duration>,

    rttvar: Duration,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: [Option<Instant>; packet::EPOCH_COUNT],

    sent: [BTreeMap<u64, Sent>; packet::EPOCH_COUNT],

    pub lost: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub acked: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub lost_count: usize,

    bytes_in_flight: usize,

    crypto_bytes_in_flight: usize,

    cwnd: usize,

    recovery_start_time: Option<Instant>,

    ssthresh: usize,

    pub probes: usize,
}

impl Default for Recovery {
    fn default() -> Recovery {
        let now = Instant::now();

        Recovery {
            loss_detection_timer: None,

            crypto_count: 0,

            pto_count: 0,

            time_of_last_sent_crypto_pkt: now,

            time_of_last_sent_ack_eliciting_pkt: now,

            largest_acked_pkt: [std::u64::MAX; packet::EPOCH_COUNT],

            latest_rtt: Duration::new(0, 0),

            smoothed_rtt: None,

            min_rtt: Duration::new(0, 0),

            rttvar: Duration::new(0, 0),

            max_ack_delay: Duration::from_millis(25),

            loss_time: [None; packet::EPOCH_COUNT],

            sent: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],

            lost: [Vec::new(), Vec::new(), Vec::new()],

            acked: [Vec::new(), Vec::new(), Vec::new()],

            lost_count: 0,

            bytes_in_flight: 0,

            crypto_bytes_in_flight: 0,

            cwnd: INITIAL_WINDOW,

            recovery_start_time: None,

            ssthresh: std::usize::MAX,

            probes: 0,
        }
    }
}

impl Recovery {
    pub fn on_packet_sent(
        &mut self, pkt: Sent, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) {
        let pkt_num = pkt.pkt_num;
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let is_crypto = pkt.is_crypto;
        let sent_bytes = pkt.size;

        self.sent[epoch].insert(pkt_num, pkt);

        if in_flight {
            if is_crypto {
                self.time_of_last_sent_crypto_pkt = now;

                self.crypto_bytes_in_flight += sent_bytes;
            }

            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_pkt = now;
            }

            // OnPacketSentCC
            self.bytes_in_flight += sent_bytes;

            self.set_loss_detection_timer();
        }

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_ack_received(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) {
        let largest_acked = ranges.largest().unwrap();

        if self.largest_acked_pkt[epoch] == std::u64::MAX {
            self.largest_acked_pkt[epoch] = largest_acked;
        } else {
            self.largest_acked_pkt[epoch] =
                cmp::max(self.largest_acked_pkt[epoch], largest_acked);
        }

        if let Some(pkt) = self.sent[epoch].get(&self.largest_acked_pkt[epoch]) {
            if pkt.ack_eliciting {
                let latest_rtt = now - pkt.time;

                let ack_delay = if epoch == packet::EPOCH_APPLICATION {
                    Duration::from_micros(ack_delay)
                } else {
                    Duration::from_micros(0)
                };

                self.update_rtt(latest_rtt, ack_delay);
            }
        }

        let mut has_newly_acked = false;

        // Processing ACKed packets in reverse order (from largest to smallest)
        // appears to be faster, possibly due to the BTreeMap implementation.
        for pn in ranges.flatten().rev() {
            let newly_acked = self.on_packet_acked(pn, epoch);
            has_newly_acked = cmp::max(has_newly_acked, newly_acked);

            if newly_acked {
                trace!("{} packet newly acked {}", trace_id, pn);
            }
        }

        if !has_newly_acked {
            return;
        }

        self.detect_lost_packets(epoch, now, trace_id);

        self.crypto_count = 0;
        self.pto_count = 0;

        self.set_loss_detection_timer();

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_loss_detection_timeout(&mut self, now: Instant, trace_id: &str) {
        let (loss_time, epoch) = self.earliest_loss_time();

        if loss_time.is_some() {
            self.detect_lost_packets(epoch, now, trace_id);
        } else if self.crypto_bytes_in_flight > 0 {
            // Retransmit unacked data from all packet number spaces.
            for e in packet::EPOCH_INITIAL..packet::EPOCH_COUNT {
                for p in self.sent[e].values().filter(|p| p.is_crypto) {
                    self.lost[e].extend_from_slice(&p.frames);
                }
            }

            trace!("{} resend unacked crypto data ({:?})", trace_id, self);

            self.crypto_count += 1;
        } else {
            self.pto_count += 1;
            self.probes = 2;
        }

        self.set_loss_detection_timer();

        trace!("{} {:?}", trace_id, self);
    }

    pub fn drop_unacked_data(&mut self, epoch: packet::Epoch) {
        let mut unacked_bytes = 0;
        let mut crypto_unacked_bytes = 0;

        for p in self.sent[epoch].values_mut().filter(|p| p.in_flight) {
            unacked_bytes += p.size;

            if p.is_crypto {
                crypto_unacked_bytes += p.size;
            }
        }

        self.crypto_bytes_in_flight -= crypto_unacked_bytes;
        self.bytes_in_flight -= unacked_bytes;

        self.sent[epoch].clear();
        self.lost[epoch].clear();
        self.acked[epoch].clear();
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    pub fn cwnd(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.probes > 0 {
            return std::usize::MAX;
        }

        if self.bytes_in_flight > self.cwnd {
            return 0;
        }

        self.cwnd - self.bytes_in_flight
    }

    pub fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(INITIAL_RTT)
    }

    pub fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rttvar * 4, GRANULARITY) + self.max_ack_delay
    }

    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = latest_rtt;

        match self.smoothed_rtt {
            // First RTT sample.
            None => {
                self.min_rtt = latest_rtt;

                self.smoothed_rtt = Some(latest_rtt);

                self.rttvar = latest_rtt / 2;
            },

            Some(srtt) => {
                self.min_rtt = cmp::min(self.min_rtt, latest_rtt);

                let ack_delay = cmp::min(self.max_ack_delay, ack_delay);

                // Adjust for ack delay if plausible.
                let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
                    latest_rtt - ack_delay
                } else {
                    latest_rtt
                };

                self.rttvar = (self.rttvar * 3 + sub_abs(srtt, adjusted_rtt)) / 4;

                self.smoothed_rtt = Some((srtt * 7 + adjusted_rtt) / 8);
            },
        }
    }

    fn earliest_loss_time(&mut self) -> (Option<Instant>, packet::Epoch) {
        let mut epoch = packet::EPOCH_INITIAL;
        let mut time = self.loss_time[epoch];

        for e in packet::EPOCH_HANDSHAKE..packet::EPOCH_COUNT {
            let new_time = self.loss_time[e];

            if new_time.is_some() && (time.is_none() || new_time < time) {
                time = new_time;
                epoch = e;
            }
        }

        (time, epoch)
    }

    fn set_loss_detection_timer(&mut self) {
        let (loss_time, _) = self.earliest_loss_time();
        if loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = loss_time;
            return;
        }

        if self.crypto_bytes_in_flight > 0 {
            // Crypto retransmission timer.
            let mut timeout = self.rtt() * 2;

            timeout = cmp::max(timeout, GRANULARITY);
            timeout *= 2_u32.pow(self.crypto_count);

            self.loss_detection_timer =
                Some(self.time_of_last_sent_crypto_pkt + timeout);

            return;
        }

        if self.bytes_in_flight == 0 {
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let timeout = self.pto() * 2_u32.pow(self.pto_count);

        self.loss_detection_timer =
            Some(self.time_of_last_sent_ack_eliciting_pkt + timeout);
    }

    fn detect_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) {
        let mut lost_pkt: Vec<u64> = Vec::new();

        let largest_acked = self.largest_acked_pkt[epoch];

        let loss_delay = (cmp::max(self.latest_rtt, self.rtt()) * 9) / 8;
        let loss_delay = cmp::max(loss_delay, GRANULARITY);

        let lost_send_time = now - loss_delay;

        self.loss_time[epoch] = None;

        for (_, unacked) in self.sent[epoch].range(..=largest_acked) {
            if unacked.time <= lost_send_time ||
                largest_acked >= unacked.pkt_num + PACKET_THRESHOLD
            {
                if unacked.in_flight {
                    trace!(
                        "{} packet {} lost on epoch {}",
                        trace_id,
                        unacked.pkt_num,
                        epoch
                    );
                }

                // We can't remove the lost packet from |self.sent| here, so
                // simply keep track of the number so it can be removed later.
                lost_pkt.push(unacked.pkt_num);
            } else {
                let loss_time = match self.loss_time[epoch] {
                    None => unacked.time + loss_delay,

                    Some(loss_time) =>
                        cmp::min(loss_time, unacked.time + loss_delay),
                };

                self.loss_time[epoch] = Some(loss_time);
            }
        }

        if !lost_pkt.is_empty() {
            self.on_packets_lost(lost_pkt, epoch, now);
        }
    }

    fn in_recovery(&self, sent_time: Instant) -> bool {
        match self.recovery_start_time {
            Some(recovery_start_time) => sent_time <= recovery_start_time,

            None => false,
        }
    }

    fn on_packet_acked(&mut self, pkt_num: u64, epoch: packet::Epoch) -> bool {
        // Check if packet is newly acked.
        if let Some(mut p) = self.sent[epoch].remove(&pkt_num) {
            self.acked[epoch].append(&mut p.frames);

            if p.in_flight {
                // OnPacketAckedCC
                self.bytes_in_flight -= p.size;

                if p.is_crypto {
                    self.crypto_bytes_in_flight -= p.size;
                }

                if self.in_recovery(p.time) {
                    return true;
                }

                if self.cwnd < self.ssthresh {
                    // Slow start.
                    self.cwnd += p.size;
                } else {
                    // Congestion avoidance.
                    self.cwnd += (MAX_DATAGRAM_SIZE * p.size) / self.cwnd;
                }
            }

            return true;
        }

        // Is not newly acked.
        false
    }

    fn in_persistent_congestion(&mut self, _largest_lost_pkt: &Sent) -> bool {
        let _congestion_period = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;

        // TODO: properly detect persistent congestion
        false
    }

    fn on_packets_lost(
        &mut self, lost_pkt: Vec<u64>, epoch: packet::Epoch, now: Instant,
    ) {
        // Differently from OnPacketsLost(), we need to handle both
        // in-flight and non-in-flight packets, so need to keep track
        // of whether we saw any lost in-flight packet to trigger the
        // congestion event later.
        let mut largest_lost_pkt: Option<Sent> = None;

        for lost in lost_pkt {
            let mut p = self.sent[epoch].remove(&lost).unwrap();

            self.lost_count += 1;

            if !p.in_flight {
                continue;
            }

            self.bytes_in_flight -= p.size;

            if p.is_crypto {
                self.crypto_bytes_in_flight -= p.size;
            }

            self.lost[epoch].append(&mut p.frames);

            largest_lost_pkt = Some(p);
        }

        if let Some(largest_lost_pkt) = largest_lost_pkt {
            // CongestionEvent
            if !self.in_recovery(largest_lost_pkt.time) {
                self.recovery_start_time = Some(now);

                self.cwnd /= 2;
                self.cwnd = cmp::max(self.cwnd, MINIMUM_WINDOW);
                self.ssthresh = self.cwnd;
            }

            if self.in_persistent_congestion(&largest_lost_pkt) {
                self.cwnd = MINIMUM_WINDOW;
            }
        }
    }
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.loss_detection_timer {
            Some(v) => {
                let now = Instant::now();

                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "timer={:?} ", d)?;
                } else {
                    write!(f, "timer=exp ")?;
                }
            },

            None => {
                write!(f, "timer=none ")?;
            },
        };

        write!(f, "crypto={} ", self.crypto_bytes_in_flight)?;
        write!(f, "inflight={} ", self.bytes_in_flight)?;
        write!(f, "cwnd={} ", self.cwnd)?;
        write!(f, "latest_rtt={:?} ", self.latest_rtt)?;
        write!(f, "srtt={:?} ", self.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", self.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rttvar)?;
        write!(f, "probes={} ", self.probes)?;

        Ok(())
    }
}

fn sub_abs(lhs: Duration, rhs: Duration) -> Duration {
    if lhs > rhs {
        lhs - rhs
    } else {
        rhs - lhs
    }
}
