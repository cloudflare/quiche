// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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
use crate::ranges;

// Loss Recovery
const PACKET_THRESHOLD: u64 = 3;

const GRANULARITY: Duration = Duration::from_millis(1);

const INITIAL_RTT: Duration = Duration::from_millis(100);

// Congestion Control
const MAX_DATAGRAM_SIZE: usize = 1452;

const INITIAL_WINDOW: usize = 10 * MAX_DATAGRAM_SIZE;
const MINIMUM_WINDOW: usize = 2 * MAX_DATAGRAM_SIZE;

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 2;

#[derive(Debug)]
pub struct Sent {
    pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    time: Instant,

    size: usize,

    ack_eliciting: bool,

    is_crypto: bool,
}

impl Sent {
    pub fn new(pkt_num: u64, frames: Vec<frame::Frame>, sent_bytes: usize,
               ack_eliciting: bool, is_crypto: bool, now: Instant) -> Sent {
        let sent_bytes = if ack_eliciting { sent_bytes } else { 0 };

        Sent {
            pkt_num,
            frames,
            time: now,
            size: sent_bytes,
            ack_eliciting,
            is_crypto,
        }
    }
}

pub struct InFlight {
    pub sent: BTreeMap<u64, Sent>,
    pub lost: Vec<frame::Frame>,
    pub acked: Vec<frame::Frame>,
}

impl Default for InFlight {
    fn default() -> InFlight {
        InFlight {
            sent: BTreeMap::new(),
            lost: Vec::new(),
            acked: Vec::new(),
        }
    }
}

impl InFlight {
    pub fn retransmit_unacked_crypto(&mut self, trace_id: &str) -> usize {
        let mut unacked_bytes = 0;

        for p in &mut self.sent.values_mut().filter(|p| p.is_crypto) {
            p.frames.retain(|f|
                match f {
                    frame::Frame::Crypto { .. } => true,

                    _ => false,
                });

            trace!("{} crypto packet lost {}", trace_id, p.pkt_num);

            unacked_bytes += p.size;

            self.lost.append(&mut p.frames);
        }

        self.sent.clear();

        unacked_bytes
    }

    pub fn drop_unacked_data(&mut self) -> (usize, usize) {
        let mut unacked_bytes = 0;
        let mut crypto_unacked_bytes = 0;

        for p in self.sent.values_mut().filter(|p| p.ack_eliciting) {
            unacked_bytes += p.size;

            if p.is_crypto {
                crypto_unacked_bytes += p.size;
            }
        }

        self.sent.clear();

        (crypto_unacked_bytes, unacked_bytes)
    }
}

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    crypto_count: u32,

    pto_count: u32,

    time_of_last_sent_ack_eliciting_pkt: Instant,

    time_of_last_sent_crypto_pkt: Instant,

    largest_sent_pkt: u64,

    largest_acked_pkt: u64,

    latest_rtt: Duration,

    smoothed_rtt: Duration,

    rttvar: Duration,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: Option<Instant>,

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

            largest_sent_pkt: 0,

            largest_acked_pkt: 0,

            latest_rtt: Duration::new(0, 0),

            smoothed_rtt: Duration::new(0, 0),

            min_rtt: Duration::from_secs(std::u64::MAX),

            rttvar: Duration::new(0, 0),

            max_ack_delay: Duration::from_millis(25),

            loss_time: None,

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
    pub fn on_packet_sent(&mut self, pkt: Sent, flight: &mut InFlight,
                          now: Instant, trace_id: &str) {
        let pkt_num = pkt.pkt_num;
        let ack_eliciting = pkt.ack_eliciting;
        let is_crypto = pkt.is_crypto;
        let sent_bytes = pkt.size;

        self.largest_sent_pkt = pkt_num;

        flight.sent.insert(pkt_num, pkt);

        if ack_eliciting {
            if is_crypto {
                self.time_of_last_sent_crypto_pkt = now;

                self.crypto_bytes_in_flight += sent_bytes;
            }

            self.time_of_last_sent_ack_eliciting_pkt = now;

            // OnPacketSentCC
            self.bytes_in_flight += sent_bytes;

            self.set_loss_detection_timer();
        }

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_ack_received(&mut self, ranges: &ranges::RangeSet, ack_delay: u64,
                           flight: &mut InFlight, now: Instant, trace_id: &str) {
        self.largest_acked_pkt = cmp::max(self.largest_acked_pkt,
                                          ranges.largest().unwrap());

        if let Some(pkt) = flight.sent.get(&self.largest_acked_pkt) {
            if pkt.ack_eliciting {
                let ack_delay = Duration::from_micros(ack_delay);
                self.update_rtt(pkt.time.elapsed(), ack_delay);
            }
        }

        let mut has_newly_acked = false;

        for pn in ranges.flatten().rev() {
            let newly_acked = self.on_packet_acked(pn, flight);
            has_newly_acked = cmp::max(has_newly_acked, newly_acked);

            if newly_acked {
                trace!("{} packet newly acked {}", trace_id, pn);
            }
        }

        if !has_newly_acked {
            return;
        }

        self.detect_lost_packets(flight, now, trace_id);

        self.crypto_count = 0;
        self.pto_count = 0;

        self.set_loss_detection_timer();

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_loss_detection_timer(&mut self,
                                   in_flight: &mut InFlight,
                                   hs_flight: &mut InFlight,
                                   flight: &mut InFlight,
                                   now: Instant, trace_id: &str) {
        if self.crypto_bytes_in_flight > 0 {
            self.crypto_count += 1;

            let unacked_bytes = in_flight.retransmit_unacked_crypto(trace_id);
            self.crypto_bytes_in_flight -= unacked_bytes;
            self.bytes_in_flight -= unacked_bytes;

            let unacked_bytes = hs_flight.retransmit_unacked_crypto(trace_id);
            self.crypto_bytes_in_flight -= unacked_bytes;
            self.bytes_in_flight -= unacked_bytes;

            let unacked_bytes = flight.retransmit_unacked_crypto(trace_id);
            self.crypto_bytes_in_flight -= unacked_bytes;
            self.bytes_in_flight -= unacked_bytes;
        } else if self.loss_time.is_some() {
            self.detect_lost_packets(flight, now, trace_id);
        } else {
            self.pto_count += 1;
            self.probes = 2;
        }

        self.set_loss_detection_timer();

        trace!("{} {:?}", trace_id, self);
    }

    pub fn drop_unacked_data(&mut self, flight: &mut InFlight) {
        let (crypto_unacked_bytes, unacked_bytes) = flight.drop_unacked_data();

        self.crypto_bytes_in_flight -= crypto_unacked_bytes;
        self.bytes_in_flight -= unacked_bytes;
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

    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        let zero = Duration::new(0, 0);

        let ack_delay = cmp::min(self.max_ack_delay, ack_delay);

        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);

        if latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt = latest_rtt - ack_delay;
        }

        if self.smoothed_rtt == zero {
            self.rttvar = self.latest_rtt / 2;

            self.smoothed_rtt = self.latest_rtt;
        } else {
            let rttvar_sample = sub_abs(self.smoothed_rtt, self.latest_rtt);

            self.rttvar = (self.rttvar * 3 + rttvar_sample) / 4;

            self.smoothed_rtt = (self.smoothed_rtt * 7 + self.latest_rtt) / 8;
        }
    }

    fn set_loss_detection_timer(&mut self) {
        let zero = Duration::new(0, 0);

        if self.bytes_in_flight == 0 {
            self.loss_detection_timer = None;
            return;
        }

        if self.crypto_bytes_in_flight > 0 {
            // Crypto retransmission timer.
            let mut timeout = if self.smoothed_rtt == zero {
                INITIAL_RTT * 2
            } else {
                self.smoothed_rtt * 2
            };

            timeout = cmp::max(timeout, GRANULARITY);
            timeout *= 2_u32.pow(self.crypto_count);

            self.loss_detection_timer =
                Some(self.time_of_last_sent_crypto_pkt + timeout);

            return;
        }

        if self.loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = self.loss_time;
            return;
        }

        // PTO timer.
        let mut timeout = self.smoothed_rtt +
                          (self.rttvar * 4) +
                          self.max_ack_delay;

        timeout = cmp::max(timeout, GRANULARITY);
        timeout *= 2_u32.pow(self.pto_count);

        self.loss_detection_timer =
            Some(self.time_of_last_sent_ack_eliciting_pkt + timeout);
    }

    fn detect_lost_packets(&mut self, flight: &mut InFlight, now: Instant,
                           trace_id: &str) {
        let mut lost_pkt: Vec<u64> = Vec::new();

        let largest_acked = self.largest_acked_pkt;

        let loss_delay = (cmp::max(self.latest_rtt, self.smoothed_rtt) * 9) / 8;

        let lost_send_time = now - loss_delay;

        let lost_pkt_num = largest_acked.checked_sub(PACKET_THRESHOLD)
                                        .unwrap_or(0);

        self.loss_time = None;

        for (_, unacked) in flight.sent.range(..=largest_acked) {
            if unacked.time <= lost_send_time || unacked.pkt_num <= lost_pkt_num {
                if unacked.ack_eliciting {
                    trace!("{} packet lost {}", trace_id, unacked.pkt_num);
                }

                // We can't remove the lost packet from |flight.sent| here, so
                // simply keep track of the number so it can be removed later.
                lost_pkt.push(unacked.pkt_num);
            } else if self.loss_time.is_none() {
                self.loss_time = Some(unacked.time + loss_delay);
            } else {
                let loss_time = self.loss_time.unwrap();
                self.loss_time =
                    Some(cmp::min(loss_time, unacked.time + loss_delay));
            }
        }

        if !lost_pkt.is_empty() {
            self.on_packets_lost(lost_pkt, flight, now);
        }
    }

    fn in_recovery(&self, sent_time: Instant) -> bool {
        match self.recovery_start_time {
            Some(recovery_start_time) => sent_time <= recovery_start_time,

            None => false,
        }
    }

    fn on_packet_acked(&mut self, pkt_num: u64, flight: &mut InFlight) -> bool {
        // Check if packet is newly acked.
        if let Some(mut p) = flight.sent.remove(&pkt_num) {
            flight.acked.append(&mut p.frames);

            if p.ack_eliciting {
                // OnPacketAckedCC
                self.bytes_in_flight -= p.size;

                if p.is_crypto {
                    self.crypto_bytes_in_flight -= p.size;
                }

                if self.in_recovery(p.time) {
                    return true;
                }

                if self.cwnd < self.ssthresh {
                    self.cwnd += p.size;
                } else {
                    self.cwnd += (MAX_DATAGRAM_SIZE * p.size) / self.cwnd;
                }
            }

            return true;
        }

        // Is not newly acked.
        false
    }

    fn on_packets_lost(&mut self, lost_pkt: Vec<u64>, flight: &mut InFlight,
                       now: Instant) {
        // Differently from OnPacketsLost(), we need to handle both
        // ACK-eliciting and non-ACK-eliciting packets, so need to keep of
        // whether we saw any lost ACK-eliciting packet to trigger the
        // congestion event later.
        let mut largest_lost_pkt_sent_time: Option<Instant> = None;

        for lost in lost_pkt {
            let mut p = flight.sent.remove(&lost).unwrap();

            if !p.ack_eliciting {
                continue;
            }

            self.bytes_in_flight -= p.size;

            if p.is_crypto {
                self.crypto_bytes_in_flight -= p.size;
            }

            flight.lost.append(&mut p.frames);

            largest_lost_pkt_sent_time = Some(p.time);
        }

        if largest_lost_pkt_sent_time.is_none() {
            return;
        }

        // CongestionEvent
        if !self.in_recovery(largest_lost_pkt_sent_time.unwrap()) {
            self.recovery_start_time = Some(now);

            self.cwnd /= 2;
            self.cwnd = cmp::max(self.cwnd, MINIMUM_WINDOW);
            self.ssthresh = self.cwnd;

            if self.pto_count > PERSISTENT_CONGESTION_THRESHOLD {
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
