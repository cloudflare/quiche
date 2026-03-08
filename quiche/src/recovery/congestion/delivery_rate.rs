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

use crate::recovery::bandwidth::Bandwidth;

use super::Acked;
use super::Sent;

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

            rate_sample: RateSample::new(),
        }
    }
}

impl Rate {
    pub fn on_packet_sent(
        &mut self, pkt: &mut Sent, bytes_in_flight: usize, bytes_lost: u64,
    ) {
        // No packets in flight.
        if bytes_in_flight == 0 {
            self.first_sent_time = pkt.time_sent;
            self.delivered_time = pkt.time_sent;
        }

        pkt.first_sent_time = self.first_sent_time;
        pkt.delivered_time = self.delivered_time;
        pkt.delivered = self.delivered;
        pkt.is_app_limited = self.app_limited();
        pkt.tx_in_flight = bytes_in_flight;
        pkt.lost = bytes_lost;

        self.last_sent_packet = pkt.pkt_num;
    }

    // Update the delivery rate sample when a packet is acked.
    pub fn update_rate_sample(&mut self, pkt: &Acked, now: Instant) {
        self.delivered += pkt.size;
        self.delivered_time = now;

        // Update info using the newest packet. If rate_sample is not yet
        // initialized, initialize with the first packet.
        if self.rate_sample.prior_time.is_none() ||
            pkt.delivered >= self.rate_sample.prior_delivered
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
                let rate_sample_bandwidth = {
                    let rate_sample_bytes_per_second = (self.rate_sample.delivered
                        as f64 /
                        interval.as_secs_f64())
                        as u64;

                    Bandwidth::from_bytes_per_second(rate_sample_bytes_per_second)
                };

                // Match the [linux] implementation and only generate a new
                // sample delivery rate if either:
                // - the sample was not app_limited
                // - the new rate is higher than the previous value
                //
                // [linux] https://github.com/torvalds/linux/commit/eb8329e0a04db0061f714f033b4454326ba147f4
                if !self.rate_sample.is_app_limited ||
                    rate_sample_bandwidth > self.rate_sample.bandwidth
                {
                    self.update_delivery_rate(rate_sample_bandwidth);
                }
            }
        }
    }

    fn update_delivery_rate(&mut self, bandwidth: Bandwidth) {
        self.rate_sample.bandwidth = bandwidth;
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.end_of_app_limited =
            if v { self.last_sent_packet.max(1) } else { 0 };
    }

    pub fn app_limited(&mut self) -> bool {
        self.end_of_app_limited != 0
    }

    #[cfg(test)]
    pub fn delivered(&self) -> usize {
        self.delivered
    }

    pub fn sample_delivery_rate(&self) -> Bandwidth {
        self.rate_sample.bandwidth
    }

    #[cfg(test)]
    pub fn sample_is_app_limited(&self) -> bool {
        self.rate_sample.is_app_limited
    }
}

#[derive(Debug)]
struct RateSample {
    // The sample delivery_rate in bytes/sec
    bandwidth: Bandwidth,

    is_app_limited: bool,

    interval: Duration,

    delivered: usize,

    prior_delivered: usize,

    prior_time: Option<Instant>,

    send_elapsed: Duration,

    ack_elapsed: Duration,

    rtt: Duration,
}

impl RateSample {
    const fn new() -> Self {
        RateSample {
            bandwidth: Bandwidth::zero(),
            is_app_limited: false,
            interval: Duration::ZERO,
            delivered: 0,
            prior_delivered: 0,
            prior_time: None,
            send_elapsed: Duration::ZERO,
            ack_elapsed: Duration::ZERO,
            rtt: Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::packet;
    use crate::ranges;
    use crate::recovery::congestion::recovery::LegacyRecovery;
    use crate::recovery::HandshakeStatus;
    use crate::recovery::RecoveryOps;
    use crate::test_utils;
    use crate::Config;
    use crate::OnAckReceivedOutcome;
    use std::ops::Range;

    // A [RateSample](delivery_rate::RateSample) is app_limited if it was
    // generated when the [Rate](delivery_rate::Rate) was app_limited.
    //
    // The following test generates RateSamples before and after Rate is
    // app_limited and asserts on app_limited status for samples.
    #[test]
    fn sample_is_app_limited() {
        let config = Config::new(0xbabababa).unwrap();
        let mut r = LegacyRecovery::new(&config);
        let mut now = Instant::now();
        let mss = r.max_datagram_size();

        // Not App Limited prior to any activity
        assert!(!r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 0);
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());

        // Send/Ack first batch to generate a new delivery_rate sample.
        let rtt = Duration::from_secs(2);
        helper_send_and_ack_packets(&mut r, 0..4, now, rtt, mss);

        // Marking Rate as app_limited.
        r.delivery_rate_update_app_limited(true);
        assert!(r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 3);

        // Rate is app_limited.
        assert!(r.congestion.delivery_rate.app_limited());
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());

        // Send/Ack second batch to generate a new delivery_rate sample.
        now += rtt;
        helper_send_and_ack_packets(&mut r, 4..8, now, rtt, mss);

        // Rate is no longer app limited since we sent a packet larger than
        // `end_of_app_limited`
        assert!(!r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 0);
        // The RateSample is also app_limited
        assert!(r.congestion.delivery_rate.sample_is_app_limited());
    }

    // A [RateSample](delivery_rate::RateSample) is is only updated if either not
    // app_limited or greater than the previous value.
    #[test]
    fn app_limited_delivery_rate() {
        // confirm that rate sample is not generated when app limited
        let config = Config::new(0xbabababa).unwrap();
        let mut r = LegacyRecovery::new(&config);
        let mut now = Instant::now();
        let mss = r.max_datagram_size();

        // Not App Limited prior to any activity
        assert!(!r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 0);
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());

        // First batch
        // Send/Ack first batch to generate a new delivery_rate sample.
        let mut rtt = Duration::from_secs(2);
        helper_send_and_ack_packets(&mut r, 0..2, now, rtt, mss);

        // Marking Rate as app_limited.
        r.delivery_rate_update_app_limited(true);
        assert!(r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 1);
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());

        let first_delivery_rate = r.delivery_rate().to_bytes_per_second();
        let expected_delivery_rate = (mss * 2) as u64 / rtt.as_secs();
        assert_eq!(expected_delivery_rate, 1200);
        assert_eq!(first_delivery_rate, expected_delivery_rate);

        // Second batch
        // Since Rtt is larger, the delivery_rate will be smaller and not generate
        // a new RateSample.
        now += rtt;
        rtt = Duration::from_secs(4);
        helper_send_and_ack_packets(&mut r, 2..4, now, rtt, mss);

        // Rate is no longer app limited since we sent a packet larger than
        // `end_of_app_limited`
        assert!(!r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 0);
        // The RateSample is also app_limited
        assert!(r.congestion.delivery_rate.sample_is_app_limited());

        // Delivery rate NOT updated since the delivery rate is less than previous
        // value
        let expected_delivery_rate = (mss * 2) as u64 / rtt.as_secs();
        assert_eq!(expected_delivery_rate, 600);
        let app_limited_delivery_rate = r.delivery_rate().to_bytes_per_second();
        assert_eq!(app_limited_delivery_rate, first_delivery_rate);

        // Marking Rate as app_limited.
        r.delivery_rate_update_app_limited(true);
        assert!(r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 3);
        // The RateSample is also app_limited
        assert!(r.congestion.delivery_rate.sample_is_app_limited());

        // Third batch
        // Since Rtt is smaller, the delivery_rate will be larger and not generate
        // a new RateSample even when app_limited.
        now += rtt;
        rtt = Duration::from_secs(1);
        helper_send_and_ack_packets(&mut r, 4..6, now, rtt, mss);

        // Rate is no longer app limited since we sent a packet larger than
        // `end_of_app_limited`
        assert!(!r.congestion.delivery_rate.app_limited());
        assert_eq!(r.congestion.delivery_rate.end_of_app_limited, 0);
        // The RateSample is also app_limited
        assert!(r.congestion.delivery_rate.sample_is_app_limited());

        // Delivery rate NOT updated since the delivery rate is less than previous
        // value
        let expected_delivery_rate = (mss * 2) as u64 / rtt.as_secs();
        assert_eq!(expected_delivery_rate, 2400);
        let app_limited_delivery_rate = r.delivery_rate().to_bytes_per_second();
        assert_eq!(app_limited_delivery_rate, expected_delivery_rate);
    }

    #[test]
    fn rate_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut r = LegacyRecovery::new(&config);

        let now = Instant::now();
        let mss = r.max_datagram_size();

        // Send 2 packets.
        for pn in 0..2 {
            let pkt = test_utils::helper_packet_sent(pn, now, mss);

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
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
                first_sent_time: now.checked_sub(rtt).unwrap(),
                is_app_limited: false,
            };

            r.congestion.delivery_rate.update_rate_sample(&acked, now);
        }

        // Update rate sample after 1 rtt.
        r.congestion.delivery_rate.generate_rate_sample(rtt);

        // Bytes acked so far.
        assert_eq!(r.congestion.delivery_rate.delivered(), 2400);

        // Estimated delivery rate = (1200 x 2) / 0.05s = 48000.
        assert_eq!(r.delivery_rate().to_bytes_per_second(), 48000);
    }

    #[test]
    fn app_limited_cwnd_full() {
        let config = Config::new(0xbabababa).unwrap();
        let mut r = LegacyRecovery::new(&config);

        let now = Instant::now();
        let mss = r.max_datagram_size();

        // Not App Limited prior to any activity
        assert!(!r.app_limited());
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());

        // Send 10 packets to fill cwnd.
        for pn in 0..5 {
            let pkt = test_utils::helper_packet_sent(pn, now, mss);
            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        // App Limited after sending partial cwnd worth of data
        assert!(r.app_limited());
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());

        for pn in 5..10 {
            let pkt = test_utils::helper_packet_sent(pn, now, mss);
            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        // Not App Limited after sending full cwnd worth of data
        assert!(!r.app_limited());
        assert!(!r.congestion.delivery_rate.sample_is_app_limited());
    }

    fn helper_send_and_ack_packets(
        recovery: &mut LegacyRecovery, range: Range<u64>, now: Instant,
        rtt: Duration, mss: usize,
    ) {
        for pn in range.clone() {
            let pkt = test_utils::helper_packet_sent(pn, now, mss);
            recovery.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let packet_count = range.clone().count();

        // Ack packets, which generates a new delivery_rate
        let mut acked = ranges::RangeSet::default();
        acked.insert(range);

        let ack_outcome = recovery
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now + rtt,
                None,
                "",
            )
            .unwrap();

        assert_eq!(ack_outcome, OnAckReceivedOutcome {
            lost_packets: 0,
            lost_bytes: 0,
            acked_bytes: mss * packet_count,
            spurious_losses: 0,
        });
    }
}
