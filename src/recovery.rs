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
use std::fmt;

use std::time::Duration;
use std::time::Instant;

use std::collections::BTreeMap;

use crate::frame;
use crate::ranges;

// Loss Recovery
const INITIAL_RTT: Duration = Duration::from_millis(100);

const MIN_TLP_TIMEOUT: Duration = Duration::from_millis(10);

const MIN_RTO_TIMEOUT: Duration = Duration::from_millis(200);

const MAX_TLP_COUNT: u32 = 2;

const REORDERING_THRESHOLD: u64 = 3;

// Congestion Control
const MAX_DATAGRAM_SIZE: usize = 1460;

const INITIAL_WINDOW: usize = 10 * MAX_DATAGRAM_SIZE;
const MINIMUM_WINDOW: usize = 2 * MAX_DATAGRAM_SIZE;

#[derive(Debug)]
pub struct Sent {
    pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    time: Instant,

    size: usize,

    retransmittable: bool,

    is_crypto: bool,
}

impl Sent {
    pub fn new(pkt_num: u64, frames: Vec<frame::Frame>, sent_bytes: usize,
               retransmittable: bool, is_crypto: bool, now: Instant) -> Sent {
        let sent_bytes = if retransmittable { sent_bytes } else { 0 };

        Sent {
            pkt_num,
            frames,
            time: now,
            size: sent_bytes,
            retransmittable,
            is_crypto,
        }
    }
}

pub struct InFlight {
    pub sent: BTreeMap<u64, Sent>,
    pub lost: Vec<frame::Frame>,
    pub acked: Vec<frame::Frame>,
}

impl InFlight {
    pub fn retransmit_unacked_crypto(&mut self) -> usize {
        let mut unacked_bytes = 0;

        for p in &mut self.sent.values_mut() {
            p.frames.retain(|f|
                match f {
                    frame::Frame::Crypto { .. } => true,
                    _ => false,
                });

            unacked_bytes += p.size;

            self.lost.append(&mut p.frames);
        }

        self.sent.clear();

        unacked_bytes
    }
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

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    crypto_count: u32,

    tlp_count: u32,

    rto_count: u32,

    largest_sent_before_rto: u64,

    time_of_last_sent_retransmittable_packet: Instant,

    time_of_last_sent_crypto_packet: Instant,

    largest_sent_pkt: u64,

    largest_acked: u64,

    latest_rtt: Duration,

    smoothed_rtt: Duration,

    rttvar: Duration,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: Option<Instant>,

    cwnd: usize,

    bytes_in_flight: usize,

    recovery_start_time: Option<Instant>,

    ssthresh: usize,

    pub probes: usize,
}

impl Recovery {
    pub fn on_packet_sent(&mut self, pkt: Sent, flight: &mut InFlight,
                          now: Instant, trace_id: &str) {
        let pkt_num = pkt.pkt_num;
        let retransmittable = pkt.retransmittable;
        let is_crypto = pkt.is_crypto;
        let sent_bytes = pkt.size;

        self.largest_sent_pkt = pkt_num;

        flight.sent.insert(pkt_num, pkt);

        if retransmittable {
            if is_crypto {
                self.time_of_last_sent_crypto_packet = now;
            }

            self.time_of_last_sent_retransmittable_packet = now;

            // OnPacketSentCC
            self.bytes_in_flight += sent_bytes;

            self.set_loss_detection_timer(flight);
        }

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_ack_received(&mut self, ranges: &ranges::RangeSet, ack_delay: u64,
                           flight: &mut InFlight, now: Instant, trace_id: &str) {
        let largest_acked = ranges.largest().unwrap();

        if let Some(pkt) = flight.sent.get(&largest_acked) {
            self.largest_acked = cmp::max(self.largest_acked, largest_acked);
            self.update_rtt(pkt.time.elapsed(), ack_delay);
        }

        for pn in ranges.flatten().rev() {
            trace!("{} packet acked {}", trace_id, pn);
            self.on_packet_acked(pn, flight);
        }

        let smallest_acked = ranges.smallest().unwrap();

        if self.rto_count > 0 && smallest_acked > self.largest_sent_before_rto {
            // OnRetransmissionTimeoutVerified
            self.cwnd = MINIMUM_WINDOW;

            let mut lost_pkt: Vec<u64> = Vec::new();

            for p in flight.sent.values().filter(|p| p.pkt_num < smallest_acked) {
                error!("{} packet detected lost {}", trace_id, p.pkt_num);

                lost_pkt.push(p.pkt_num);
            }

            for lost in lost_pkt {
                let mut p = flight.sent.remove(&lost).unwrap();

                self.bytes_in_flight -= p.size;
                flight.lost.append(&mut p.frames);
            }
        }

        self.crypto_count = 0;
        self.tlp_count = 0;
        self.rto_count = 0;

        self.detect_lost_packets(largest_acked, flight, now, trace_id);
        self.set_loss_detection_timer(flight);

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_loss_detection_timer(&mut self,
                                   in_flight: &mut InFlight,
                                   hs_flight: &mut InFlight,
                                   flight: &mut InFlight,
                                   now: Instant, trace_id: &str) {
        if !in_flight.sent.is_empty() || !hs_flight.sent.is_empty() {
            self.crypto_count += 1;

            self.bytes_in_flight -= in_flight.retransmit_unacked_crypto();
            self.bytes_in_flight -= hs_flight.retransmit_unacked_crypto();
        } else if self.loss_time.is_some() {
            let largest_acked = self.largest_acked;
            self.detect_lost_packets(largest_acked, flight, now, trace_id);
        } else if self.tlp_count < MAX_TLP_COUNT {
            self.tlp_count += 1;

            self.probes = 1;
        } else {
            if self.rto_count == 0 {
                self.largest_sent_before_rto = self.largest_sent_pkt;
            }

            self.rto_count += 1;

            self.probes = 2;
        }

        self.set_loss_detection_timer(flight);

        trace!("{} {:?}", trace_id, self);
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

    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: u64) {
        let zero = Duration::new(0, 0);

        let ack_delay = Duration::from_micros(ack_delay);

        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);
        self.latest_rtt = cmp::max(latest_rtt.checked_sub(ack_delay)
                                             .unwrap_or(zero),
                                   self.min_rtt);

        if self.smoothed_rtt == zero {
            self.rttvar = self.latest_rtt / 2;

            self.smoothed_rtt = self.latest_rtt;
        } else {
            let rttvar_sample = sub_abs(self.smoothed_rtt, self.latest_rtt);

            self.rttvar = (self.rttvar * 3 + rttvar_sample) / 4;

            self.smoothed_rtt = (self.smoothed_rtt * 7 + self.latest_rtt) / 8;
        }
    }

    fn set_loss_detection_timer(&mut self, flight: &InFlight) {
        let zero = Duration::new(0, 0);

        if self.bytes_in_flight == 0 {
            self.loss_detection_timer = None;
            return;
        }

        // Crypto retransmission timer.
        if flight.sent.values().any(|p| p.is_crypto) {
            let mut timeout = if self.smoothed_rtt == zero {
                INITIAL_RTT * 2
            } else {
                self.smoothed_rtt * 2
            };

            timeout = cmp::max(timeout, MIN_TLP_TIMEOUT);
            timeout *= 2_u32.pow(self.crypto_count);

            self.loss_detection_timer =
                Some(self.time_of_last_sent_crypto_packet + timeout);

            return;
        }

        // Early retransmit timer or time loss detection.
        if self.loss_time.is_some() {
            self.loss_detection_timer = self.loss_time;
            return;
        }

        // RTO or TLP timer.
        let mut timeout = self.smoothed_rtt +
                          (self.rttvar * 4) +
                          self.max_ack_delay;

        timeout = cmp::max(timeout, MIN_RTO_TIMEOUT);
        timeout *= 2_u32.pow(self.rto_count);

        if self.tlp_count < MAX_TLP_COUNT {
            let tlp_timeout = cmp::max(
                (self.smoothed_rtt * 3) / 2 + self.max_ack_delay,
                MIN_TLP_TIMEOUT
            );

            timeout = cmp::min(tlp_timeout, timeout);
        }

        self.loss_detection_timer =
            Some(self.time_of_last_sent_retransmittable_packet + timeout);
    }

    fn detect_lost_packets(&mut self, largest_acked: u64, flight: &mut InFlight,
                           now: Instant, trace_id: &str) {
        self.loss_time = None;

        // TODO: do time loss detection
        let delay_until_lost = if largest_acked == self.largest_sent_pkt {
            cmp::max(self.latest_rtt * 9, self.smoothed_rtt * 9) / 8
        } else {
            Duration::from_secs(std::u64::MAX)
        };

        let mut lost_pkt: Vec<u64> = Vec::new();

        for unacked in flight.sent.values().filter(|p| p.pkt_num < largest_acked) {
            let time_since_sent = unacked.time.elapsed();
            let delta = largest_acked - unacked.pkt_num;

            if time_since_sent > delay_until_lost || delta > REORDERING_THRESHOLD {
                if unacked.retransmittable {
                    error!("{} packet lost {}", trace_id, unacked.pkt_num);
                }

                lost_pkt.push(unacked.pkt_num);
            } else if delay_until_lost.as_secs() != std::u64::MAX {
                self.loss_time = Some(now + delay_until_lost - time_since_sent);
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

    fn on_packet_acked(&mut self, pkt_num: u64, flight: &mut InFlight) {
        if let Some(mut p) = flight.sent.remove(&pkt_num) {
            flight.acked.append(&mut p.frames);

            if p.retransmittable {
                // OnPacketAckedCC
                self.bytes_in_flight -= p.size;

                if self.in_recovery(p.time) {
                    return;
                }

                if self.cwnd < self.ssthresh {
                    self.cwnd += p.size;
                } else {
                    self.cwnd += (MAX_DATAGRAM_SIZE * p.size) / self.cwnd;
                }
            }
        }
    }

    fn on_packets_lost(&mut self, lost_pkt: Vec<u64>, flight: &mut InFlight,
                       now: Instant) {
        let mut largest_lost_packet = 0;
        let mut largest_lost_packet_sent_time = now;

        for lost in lost_pkt {
            let mut p = flight.sent.remove(&lost).unwrap();

            if !p.retransmittable {
                continue;
            }

            self.bytes_in_flight -= p.size;
            flight.lost.append(&mut p.frames);

            if lost > largest_lost_packet {
                largest_lost_packet = lost;
                largest_lost_packet_sent_time = p.time;
            }
        }

        if !self.in_recovery(largest_lost_packet_sent_time) {
            self.recovery_start_time = Some(now);

            self.cwnd /= 2;
            self.cwnd = cmp::max(self.cwnd, MINIMUM_WINDOW);
            self.ssthresh = self.cwnd;
        }
    }
}

impl Default for Recovery {
    fn default() -> Recovery {
        let now = Instant::now();

        Recovery {
            loss_detection_timer: None,

            crypto_count: 0,

            tlp_count: 0,

            rto_count: 0,

            time_of_last_sent_crypto_packet: now,

            time_of_last_sent_retransmittable_packet: now,

            largest_sent_pkt: 0,

            largest_sent_before_rto: 0,

            largest_acked: 0,

            latest_rtt: Duration::new(0, 0),

            smoothed_rtt: Duration::new(0, 0),

            min_rtt: Duration::from_secs(std::u64::MAX),

            rttvar: Duration::new(0, 0),

            max_ack_delay: Duration::from_millis(25),

            loss_time: None,

            cwnd: INITIAL_WINDOW,

            bytes_in_flight: 0,

            recovery_start_time: None,

            ssthresh: std::usize::MAX,

            probes: 0,
        }
    }
}

impl fmt::Debug for Recovery {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
