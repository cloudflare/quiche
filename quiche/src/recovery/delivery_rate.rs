// Copyright (C) 2020, Cloudflare, Inc.
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
//! <https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-00>

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use crate::recovery::Sent;

#[derive(Default)]
pub struct Rate {
    delivered: usize,

    delivered_time: Option<Instant>,

    recent_delivered_packet_sent_time: Option<Instant>,

    app_limited_at_pkt: usize,

    rate_sample: RateSample,
}

impl Rate {
    pub fn on_packet_sent(&mut self, pkt: &mut Sent, now: Instant) {
        if self.delivered_time.is_none() {
            self.delivered_time = Some(now);
        }

        if self.recent_delivered_packet_sent_time.is_none() {
            self.recent_delivered_packet_sent_time = Some(now);
        }

        pkt.delivered = self.delivered;
        pkt.delivered_time = self.delivered_time.unwrap();

        pkt.recent_delivered_packet_sent_time =
            self.recent_delivered_packet_sent_time.unwrap();

        pkt.is_app_limited = self.app_limited_at_pkt > 0;
    }

    pub fn on_packet_acked(&mut self, pkt: &Sent, now: Instant) {
        self.rate_sample.prior_time = Some(pkt.delivered_time);

        self.delivered += pkt.size;
        self.delivered_time = Some(now);

        if pkt.delivered > self.rate_sample.prior_delivered {
            self.rate_sample.prior_delivered = pkt.delivered;

            self.rate_sample.send_elapsed =
                pkt.time_sent - pkt.recent_delivered_packet_sent_time;

            self.rate_sample.ack_elapsed = self
                .delivered_time
                .unwrap()
                .duration_since(pkt.delivered_time);

            self.recent_delivered_packet_sent_time = Some(pkt.time_sent);
        }
    }

    pub fn estimate(&mut self) {
        if (self.app_limited_at_pkt > 0) &&
            (self.delivered > self.app_limited_at_pkt)
        {
            self.app_limited_at_pkt = 0;
        }

        match self.rate_sample.prior_time {
            Some(_) => {
                self.rate_sample.delivered =
                    self.delivered - self.rate_sample.prior_delivered;

                self.rate_sample.interval = cmp::max(
                    self.rate_sample.send_elapsed,
                    self.rate_sample.ack_elapsed,
                );
            },
            None => return,
        }

        if self.rate_sample.interval.as_secs_f64() > 0.0 {
            self.rate_sample.delivery_rate = (self.rate_sample.delivered as f64 /
                self.rate_sample.interval.as_secs_f64())
                as u64;
        }
    }

    pub fn check_app_limited(&mut self, bytes_in_flight: usize) {
        let limited = self.delivered + bytes_in_flight;
        self.app_limited_at_pkt = if limited > 0 { limited } else { 1 };
    }

    pub fn delivery_rate(&self) -> u64 {
        self.rate_sample.delivery_rate
    }
}

impl std::fmt::Debug for Rate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "delivered={:?} ", self.delivered)?;

        if let Some(t) = self.delivered_time {
            write!(f, "delivered_time={:?} ", t.elapsed())?;
        }

        if let Some(t) = self.recent_delivered_packet_sent_time {
            write!(f, "recent_delivered_packet_sent_time={:?} ", t.elapsed())?;
        }

        write!(f, "app_limited_at_pkt={:?} ", self.app_limited_at_pkt)?;

        Ok(())
    }
}

#[derive(Default)]
struct RateSample {
    delivery_rate: u64,

    interval: Duration,

    delivered: usize,

    prior_delivered: usize,

    prior_time: Option<Instant>,

    send_elapsed: Duration,

    ack_elapsed: Duration,
}

impl std::fmt::Debug for RateSample {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "delivery_rate={:?} ", self.delivery_rate)?;
        write!(f, "interval={:?} ", self.interval)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        write!(f, "prior_delivered={:?} ", self.prior_delivered)?;
        write!(f, "send_elapsed={:?} ", self.send_elapsed)?;
        if let Some(t) = self.prior_time {
            write!(f, "prior_time={:?} ", t.elapsed())?;
        }
        write!(f, "ack_elapsed={:?}", self.ack_elapsed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recovery::*;

    #[test]
    fn rate_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut recovery = Recovery::new(&config);

        let mut pkt_1 = Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
            has_data: false,
        };

        recovery
            .delivery_rate
            .on_packet_sent(&mut pkt_1, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recovery
            .delivery_rate
            .on_packet_acked(&pkt_1, Instant::now());

        let mut pkt_2 = Sent {
            pkt_num: 1,
            frames: vec![],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
            has_data: false,
        };

        recovery
            .delivery_rate
            .on_packet_sent(&mut pkt_2, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recovery
            .delivery_rate
            .on_packet_acked(&pkt_2, Instant::now());
        recovery.delivery_rate.estimate();

        assert!(recovery.delivery_rate() > 0);
    }

    #[test]
    fn app_limited_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut recvry = Recovery::new(&config);

        let mut pkt_1 = Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
            has_data: false,
        };

        recvry
            .delivery_rate
            .on_packet_sent(&mut pkt_1, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recvry.delivery_rate.on_packet_acked(&pkt_1, Instant::now());

        let mut pkt_2 = Sent {
            pkt_num: 1,
            frames: vec![],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
            has_data: false,
        };

        recvry.app_limited = true;
        recvry
            .delivery_rate
            .check_app_limited(recvry.bytes_in_flight);
        recvry
            .delivery_rate
            .on_packet_sent(&mut pkt_2, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recvry.delivery_rate.on_packet_acked(&pkt_2, Instant::now());
        recvry.delivery_rate.estimate();

        assert_eq!(recvry.delivery_rate.app_limited_at_pkt, 0);
    }
}
