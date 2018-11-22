// Copyright (c) 2018, Alessandro Ghedini
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
use std::time;

use std::collections::BTreeMap;

use frame;
use ranges;

const INITIAL_RTT: time::Duration = time::Duration::from_millis(100);

const MIN_TLP_TIMEOUT: time::Duration = time::Duration::from_millis(10);

const MIN_RTO_TIMEOUT: time::Duration = time::Duration::from_millis(200);

const MAX_TLP_COUNT: u32 = 2;

const REORDERING_THRESHOLD: u64 = 3;

pub struct Sent {
    pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    timestamp: time::Instant,

    sent_bytes: usize,

    retransmittable: bool,

    is_crypto: bool,
}

impl Sent {
    pub fn new(pkt_num: u64, frames: Vec<frame::Frame>, sent_bytes: usize,
               retransmittable: bool, is_crypto: bool) -> Sent {
        let now = time::Instant::now();

        let sent_bytes = if retransmittable { sent_bytes } else { 0 };

        Sent {
            pkt_num,
            frames,
            timestamp: now,
            sent_bytes,
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
    loss_detection_timer: Option<time::Instant>,

    crypto_count: u32,

    tlp_count: u32,

    rto_count: u32,

    time_of_last_sent_retransmittable_packet: time::Instant,

    time_of_last_sent_crypto_packet: time::Instant,

    largest_sent_pkt: u64,

    largest_sent_before_rto: u64,

    largest_acked: u64,

    latest_rtt: time::Duration,

    smoothed_rtt: Option<time::Duration>,

    min_rtt: time::Duration,

    rttvar: time::Duration,

    max_ack_delay: time::Duration,

    bytes_in_flight: usize,

    loss_time: Option<time::Instant>,
}

impl Recovery {
    pub fn on_packet_sent(&mut self, pkt: Sent, flight: &mut InFlight,
                          trace_id: &str) {
        let pkt_num = pkt.pkt_num;
        let retransmittable = pkt.retransmittable;
        let is_crypto = pkt.is_crypto;
        let sent_bytes = pkt.sent_bytes;

        self.largest_sent_pkt = pkt_num;

        flight.sent.insert(pkt_num, pkt);

        if retransmittable {
            let now = time::Instant::now();

            if is_crypto {
                self.time_of_last_sent_crypto_packet = now;
            }

            self.time_of_last_sent_retransmittable_packet = now;

            self.bytes_in_flight += sent_bytes;

            self.set_loss_detection_timer(flight);
        }

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_ack_received(&mut self, ranges: &ranges::RangeSet, ack_delay: u64,
                           flight: &mut InFlight, trace_id: &str) {
        let largest_acked = ranges.largest().unwrap();

        if let Some(pkt) = flight.sent.get(&largest_acked) {
            self.largest_acked = cmp::max(self.largest_acked, largest_acked);
            self.latest_rtt = pkt.timestamp.elapsed();
            self.update_rtt(ack_delay);
        }

        for pn in ranges.flatten().rev() {
            match flight.sent.remove(&pn) {
                Some(mut p) => {
                    if p.retransmittable {
                        self.bytes_in_flight -= p.sent_bytes;
                    }

                    flight.acked.append(&mut p.frames);
                },

                None => (),
            }
        }

        let smallest_acked = ranges.smallest().unwrap();

        if self.rto_count > 0 && smallest_acked > self.largest_sent_before_rto {
            // TODO: OnRetransmissionTimeoutVerified
        }

        self.crypto_count = 0;
        self.tlp_count = 0;
        self.rto_count = 0;

        self.detect_lost_packets(largest_acked, flight, trace_id);
        self.set_loss_detection_timer(flight);

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_loss_detection_timer(&mut self, flight: &mut InFlight,
                                   trace_id: &str) {
        let mut lost_pkt: Vec<u64> = Vec::new();

        if flight.sent.values().any(|p| p.is_crypto) {
            self.crypto_count += 1;

            for p in flight.sent.values().filter(|p| p.is_crypto) {
                error!("{} packet lost {}", trace_id, p.pkt_num);

                lost_pkt.push(p.pkt_num);
            }
        } else if self.loss_time.is_some() {
            let largest_acked = self.largest_acked;
            self.detect_lost_packets(largest_acked, flight, trace_id);
        } else if self.tlp_count < MAX_TLP_COUNT {
            self.tlp_count += 1;

            // TODO: send TLP
        } else {
            if self.rto_count == 0 {
                self.largest_sent_before_rto = self.largest_sent_pkt;
            }

            self.rto_count += 1;

            // TODO: resend packet
        }

        self.set_loss_detection_timer(flight);

        self.on_packets_lost(lost_pkt, flight);

        trace!("{} {:?}", trace_id, self);
    }

    pub fn loss_detection_timer(&self) -> Option<time::Instant> {
        self.loss_detection_timer
    }

    pub fn expired(&self) -> bool {
        if let Some(timer) = self.loss_detection_timer {
            let now = time::Instant::now();
            if now >= timer {
                return true;
            }
        }

        return false;
    }

    fn update_rtt(&mut self, ack_delay: u64) {
        let ack_delay = time::Duration::from_micros(ack_delay);

        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);

        if self.latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt -= ack_delay;
        }

        if let Some(smoothed_rtt) = self.smoothed_rtt {
            let rttvar_sample = sub_abs(smoothed_rtt, self.latest_rtt);

            self.rttvar = ((self.rttvar * 3) + rttvar_sample) / 4;

            self.smoothed_rtt = Some(((smoothed_rtt * 7) + self.latest_rtt) / 8);
        } else {
            self.rttvar = self.latest_rtt / 2;

            self.smoothed_rtt = Some(self.latest_rtt);
        }
    }

    fn set_loss_detection_timer(&mut self, flight: &InFlight) {
        if self.bytes_in_flight == 0 {
            self.loss_detection_timer = None;
            return;
        }

        if flight.sent.values().any(|p| p.is_crypto) {
            // Crypto retransmission timer.
            let mut timeout = match self.smoothed_rtt {
                None => INITIAL_RTT * 2,
                Some(smoothed_rtt) => smoothed_rtt * 2,
            };

            timeout = cmp::max(timeout, MIN_TLP_TIMEOUT);
            timeout *= 2_u32.pow(self.crypto_count);

            self.loss_detection_timer =
                Some(self.time_of_last_sent_crypto_packet + timeout);

            return;
        }

        let timeout = match self.loss_time {
            // Early retransmit timer or time loss detection.
            Some(loss_time) =>
                loss_time - self.time_of_last_sent_retransmittable_packet,

            // RTO or TLP timer.
            None => {
                let mut timeout = self.smoothed_rtt.unwrap() +
                                  self.rttvar * 4 +
                                  self.max_ack_delay;

                timeout = cmp::max(timeout, MIN_RTO_TIMEOUT);
                timeout *= 2 ^ self.rto_count as u32;

                if self.tlp_count < MAX_TLP_COUNT {
                    let tlp_timeout = cmp::max(
                        (self.smoothed_rtt.unwrap() * 3) / 2 + self.max_ack_delay,
                        MIN_TLP_TIMEOUT
                    );

                    timeout = cmp::min(timeout, tlp_timeout);
                }

                timeout
            },
        };

        self.loss_detection_timer =
            Some(self.time_of_last_sent_retransmittable_packet + timeout);
    }

    fn detect_lost_packets(&mut self, largest_acked: u64, flight: &mut InFlight,
                           trace_id: &str) {
        self.loss_time = None;

        // TODO: do time loss detection
        let delay_until_lost = if largest_acked == self.largest_sent_pkt {
             (cmp::max(self.latest_rtt, self.smoothed_rtt.unwrap()) * 9) / 8
        } else {
            time::Duration::from_secs(std::u64::MAX)
        };

        let mut lost_pkt: Vec<u64> = Vec::new();

        for unacked in flight.sent.values().filter(|p| p.pkt_num < largest_acked) {
            let time_since_sent = unacked.timestamp.elapsed();
            let delat = largest_acked - unacked.pkt_num;

            if time_since_sent > delay_until_lost || delat > REORDERING_THRESHOLD {
                error!("{} packet lost {}", trace_id, unacked.pkt_num);

                lost_pkt.push(unacked.pkt_num);
            } else if self.loss_time.is_none() &&
                      delay_until_lost.as_secs() != std::u64::MAX {
                let now = time::Instant::now();
                self.loss_time = Some(now + delay_until_lost - time_since_sent);
            }
        }

        self.on_packets_lost(lost_pkt, flight);
    }

    fn on_packets_lost(&mut self, lost_pkt: Vec<u64>, flight: &mut InFlight) {
        for lost in lost_pkt {
            let mut p = flight.sent.remove(&lost).unwrap();
            self.bytes_in_flight -= p.sent_bytes;
            flight.lost.append(&mut p.frames);
        }
    }
}

impl Default for Recovery {
    fn default() -> Recovery {
        let now = time::Instant::now();

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

            latest_rtt: time::Duration::new(0, 0),

            smoothed_rtt: None,

            min_rtt: time::Duration::from_secs(std::u64::MAX),

            rttvar: time::Duration::new(0, 0),

            // TODO: use value from peer transport params
            max_ack_delay: time::Duration::from_millis(25),

            bytes_in_flight: 0,

            loss_time: None,
        }
    }
}

impl fmt::Debug for Recovery {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let smoothed_rtt = match self.smoothed_rtt {
            Some(v) => v,
            None => time::Duration::new(0, 0),
        };

        write!(f, "latest_rtt={:?} srtt={:?} min_rtt={:?} rttvar={:?}",
               self.latest_rtt, smoothed_rtt, self.min_rtt, self.rttvar)
    }
}

fn sub_abs(lhs: time::Duration, rhs: time::Duration) -> time::Duration {
    if lhs > rhs {
        lhs - rhs
    } else {
        rhs - lhs
    }
}
