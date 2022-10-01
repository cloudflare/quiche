// Copyright (C) 2020-2022, Cloudflare, Inc.
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

//! Delivery rate estimation.
//!
//! This implements the algorithm for estimating delivery rate as described in
//! <https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-01>

use std::time::Duration;
use std::time::Instant;

use crate::recovery::Acked;
use crate::recovery::Sent;

#[derive(Debug)]
pub struct Rate {
    delivered: usize,

    delivered_time: Instant,

    first_sent_time: Instant,

    // Packet number of the last sent packet with app limited.
    end_of_app_limited: u64,

    // Packet number of the last sent packet.
    last_sent_packet: u64,

    // Packet number of the largest acked packet.
    largest_acked: u64,

    // Sample of rate estimation.
    rate_sample: RateSample,
}

impl Default for Rate {
    fn default() -> Self {
        let now = Instant::now();

        Rate {
            delivered: 0,

            delivered_time: now,

            first_sent_time: now,

            end_of_app_limited: 0,

            last_sent_packet: 0,

            largest_acked: 0,

            rate_sample: RateSample::default(),
        }
    }
}

impl Rate {
    pub fn on_packet_sent(&mut self, pkt: &mut Sent, bytes_in_flight: usize) {
        // No packets in flight.
        if bytes_in_flight == 0 {
            self.first_sent_time = pkt.time_sent;
            self.delivered_time = pkt.time_sent;
        }

        pkt.first_sent_time = self.first_sent_time;
        pkt.delivered_time = self.delivered_time;
        pkt.delivered = self.delivered;
        pkt.is_app_limited = self.app_limited();

        self.last_sent_packet = pkt.pkt_num;
    }

    // Update the delivery rate sample when a packet is acked.
    pub fn update_rate_sample(&mut self, pkt: &Acked, now: Instant) {
        self.delivered += pkt.size;
        self.delivered_time = now;

        // Update info using the newest packet. If rate_sample is not yet
        // initialized, initialize with the first packet.
        if self.rate_sample.prior_time.is_none() ||
            pkt.delivered > self.rate_sample.prior_delivered
        {
            self.rate_sample.prior_delivered = pkt.delivered;
            self.rate_sample.prior_time = Some(pkt.delivered_time);
            self.rate_sample.is_app_limited = pkt.is_app_limited;
            self.rate_sample.send_elapsed =
                pkt.time_sent.saturating_duration_since(pkt.first_sent_time);
            self.rate_sample.rtt = pkt.rtt;
            self.rate_sample.ack_elapsed = self
                .delivered_time
                .saturating_duration_since(pkt.delivered_time);

            self.first_sent_time = pkt.time_sent;
        }

        self.largest_acked = self.largest_acked.max(pkt.pkt_num);
    }

    pub fn generate_rate_sample(&mut self, min_rtt: Duration) {
        // End app-limited phase if bubble is ACKed and gone.
        if self.app_limited() && self.largest_acked > self.end_of_app_limited {
            self.update_app_limited(false);
        }

        if self.rate_sample.prior_time.is_some() {
            let interval = self
                .rate_sample
                .send_elapsed
                .max(self.rate_sample.ack_elapsed);

            self.rate_sample.delivered =
                self.delivered - self.rate_sample.prior_delivered;
            self.rate_sample.interval = interval;

            if interval < min_rtt {
                self.rate_sample.interval = Duration::ZERO;

                // No reliable sample.
                return;
            }

            if !interval.is_zero() {
                // Fill in rate_sample with a rate sample.
                self.rate_sample.delivery_rate =
                    (self.rate_sample.delivered as f64 / interval.as_secs_f64())
                        as u64;
            }
        }
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.end_of_app_limited = if v { self.last_sent_packet.max(1) } else { 0 }
    }

    pub fn app_limited(&mut self) -> bool {
        self.end_of_app_limited != 0
    }

    pub fn delivered(&self) -> usize {
        self.delivered
    }

    pub fn sample_delivery_rate(&self) -> u64 {
        self.rate_sample.delivery_rate
    }

    pub fn sample_rtt(&self) -> Duration {
        self.rate_sample.rtt
    }

    pub fn sample_is_app_limited(&self) -> bool {
        self.rate_sample.is_app_limited
    }
}

#[derive(Default, Debug)]
struct RateSample {
    delivery_rate: u64,

    is_app_limited: bool,

    interval: Duration,

    delivered: usize,

    prior_delivered: usize,

    prior_time: Option<Instant>,

    send_elapsed: Duration,

    ack_elapsed: Duration,

    rtt: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recovery::*;

    #[test]
    fn rate_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut r = Recovery::new(&config);

        let now = Instant::now();
        let mss = r.max_datagram_size();

        // Send 2 packets.
        for pn in 0..2 {
            let pkt = Sent {
                pkt_num: pn,
                frames: vec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::EPOCH_APPLICATION,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        // Ack 2 packets.
        for pn in 0..2 {
            let acked = Acked {
                pkt_num: pn,
                time_sent: now,
                size: mss,
                rtt,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now - rtt,
                is_app_limited: false,
            };

            r.delivery_rate.update_rate_sample(&acked, now);
        }

        // Update rate sample after 1 rtt.
        r.delivery_rate.generate_rate_sample(rtt);

        // Bytes acked so far.
        assert_eq!(r.delivery_rate.delivered(), 2400);

        // Estimated delivery rate = (1200 x 2) / 0.05s = 48000.
        assert_eq!(r.delivery_rate(), 48000);
    }

    #[test]
    fn app_limited_cwnd_full() {
        let config = Config::new(0xbabababa).unwrap();
        let mut r = Recovery::new(&config);

        let now = Instant::now();
        let mss = r.max_datagram_size();

        // Send 10 packets to fill cwnd.
        for pn in 0..10 {
            let pkt = Sent {
                pkt_num: pn,
                frames: vec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::EPOCH_APPLICATION,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.app_limited(), false);
        assert_eq!(r.delivery_rate.sample_is_app_limited(), false);
    }

    #[test]
    fn app_limited_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut r = Recovery::new(&config);

        let now = Instant::now();
        let mss = r.max_datagram_size();

        // Send 5 packets.
        for pn in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: vec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::EPOCH_APPLICATION,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..5);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::EPOCH_APPLICATION,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((0, 0)),
        );

        assert_eq!(r.app_limited(), true);
        // Rate sample is not app limited (all acked).
        assert_eq!(r.delivery_rate.sample_is_app_limited(), false);
        assert_eq!(r.delivery_rate.sample_rtt(), rtt);
    }
}
