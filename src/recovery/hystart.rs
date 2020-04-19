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

//! HyStart++
//!
//! This implementation is based on the following I-D:
//!
//! https://tools.ietf.org/html/draft-balasubramanian-tcpm-hystartplusplus-02

use std::cmp;
use std::time::Duration;
use std::time::Instant;

use crate::recovery;

/// Constants from I-D.
const LOW_CWND: usize = 16;

const MIN_RTT_THRESH: Duration = Duration::from_millis(4);

const MAX_RTT_THRESH: Duration = Duration::from_millis(16);

pub const LSS_DIVISOR: f64 = 0.25;

pub const N_RTT_SAMPLE: usize = 8;

#[derive(Default)]
pub struct Hystart {
    enabled: bool,

    window_end: Option<u64>,

    last_round_min_rtt: Option<Duration>,

    current_round_min_rtt: Option<Duration>,

    rtt_sample_count: usize,

    lss_start_time: Option<Instant>,
}

impl std::fmt::Debug for Hystart {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "window_end={:?} ", self.window_end)?;
        write!(f, "last_round_min_rtt={:?} ", self.last_round_min_rtt)?;
        write!(f, "current_round_min_rtt={:?} ", self.current_round_min_rtt)?;
        write!(f, "rtt_sample_count={:?} ", self.rtt_sample_count)?;
        write!(f, "lss_start_time={:?} ", self.lss_start_time)?;

        Ok(())
    }
}

impl Hystart {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,

            ..Default::default()
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn lss_start_time(&self) -> Option<Instant> {
        self.lss_start_time
    }

    pub fn start_round(&mut self, pkt_num: u64) {
        if self.window_end.is_none() {
            *self = Hystart {
                enabled: self.enabled,

                window_end: Some(pkt_num),

                last_round_min_rtt: self.current_round_min_rtt,

                current_round_min_rtt: None,

                rtt_sample_count: 0,

                lss_start_time: None,
            };
        }
    }

    // Returns a new (ssthresh, cwnd) during slow start.
    pub fn on_packet_acked(
        &mut self, packet: &recovery::Acked, rtt: Duration, cwnd: usize,
        ssthresh: usize, now: Instant,
    ) -> (usize, usize) {
        let mut ssthresh = ssthresh;
        let mut cwnd = cwnd;

        if self.lss_start_time().is_none() {
            // Reno Slow Start.
            cwnd += packet.size;

            if let Some(current_round_min_rtt) = self.current_round_min_rtt {
                self.current_round_min_rtt =
                    Some(cmp::min(current_round_min_rtt, rtt));
            } else {
                self.current_round_min_rtt = Some(rtt);
            }

            self.rtt_sample_count += 1;

            if cwnd >= (LOW_CWND * recovery::MAX_DATAGRAM_SIZE) &&
                self.rtt_sample_count >= N_RTT_SAMPLE &&
                self.current_round_min_rtt.is_some() &&
                self.last_round_min_rtt.is_some()
            {
                // clamp(min_rtt_thresh, last_round_min_rtt/8,
                // max_rtt_thresh)
                let rtt_thresh = cmp::max(
                    self.last_round_min_rtt.unwrap() / 8,
                    MIN_RTT_THRESH,
                );
                let rtt_thresh = cmp::min(rtt_thresh, MAX_RTT_THRESH);

                // Check if we can exit to LSS.
                if self.current_round_min_rtt.unwrap() >=
                    (self.last_round_min_rtt.unwrap() + rtt_thresh)
                {
                    ssthresh = cwnd;

                    self.lss_start_time = Some(now);
                }
            }

            // Check if we reached the end of the round.
            if let Some(end_pkt_num) = self.window_end {
                if packet.pkt_num >= end_pkt_num {
                    // Start of a new round.
                    self.window_end = None;
                }
            }
        } else {
            // LSS (Limited Slow Start).
            let k = cwnd as f64 / (LSS_DIVISOR * ssthresh as f64);

            cwnd += (packet.size as f64 / k) as usize;
        }

        (cwnd, ssthresh)
    }

    // Exit HyStart++ when entering congestion avoidance.
    pub fn congestion_event(&mut self) {
        if self.window_end.is_some() {
            self.window_end = None;

            self.lss_start_time = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_round() {
        let mut hspp = Hystart::default();
        let pkt_num = 100;

        hspp.start_round(pkt_num);

        assert_eq!(hspp.window_end, Some(pkt_num));
        assert_eq!(hspp.current_round_min_rtt, None);
    }

    #[test]
    fn reno_slow_start() {
        let mut hspp = Hystart::default();
        let pkt_num = 100;
        let size = 1000;
        let now = Instant::now();

        hspp.start_round(pkt_num);

        assert_eq!(hspp.window_end, Some(pkt_num));

        let p = recovery::Acked {
            pkt_num,
            time_sent: now + Duration::from_millis(10),
            size,
        };

        let init_cwnd = 30000;
        let init_ssthresh = 1000000;

        let (cwnd, ssthresh) = hspp.on_packet_acked(
            &p,
            Duration::from_millis(10),
            init_cwnd,
            init_ssthresh,
            now,
        );

        // Expecting Reno slow start.
        assert_eq!(hspp.lss_start_time().is_some(), false);
        assert_eq!((cwnd, ssthresh), (init_cwnd + size, init_ssthresh));
    }

    #[test]
    fn limited_slow_start() {
        let mut hspp = Hystart::default();
        let size = 1000;
        let now = Instant::now();

        // 1st round rtt = 50ms
        let rtt_1st = 50;

        // end of 1st round
        let pkt_1st = N_RTT_SAMPLE as u64;

        hspp.start_round(pkt_1st);

        assert_eq!(hspp.window_end, Some(pkt_1st));

        let (mut cwnd, mut ssthresh) = (30000, 1000000);
        let mut pkt_num = 0;

        // 1st round.
        for _ in 0..N_RTT_SAMPLE + 1 {
            let p = recovery::Acked {
                pkt_num,
                time_sent: now + Duration::from_millis(pkt_num),
                size,
            };

            // We use a fixed rtt for 1st round.
            let rtt = Duration::from_millis(rtt_1st);

            let (new_cwnd, new_ssthresh) =
                hspp.on_packet_acked(&p, rtt, cwnd, ssthresh, now);

            cwnd = new_cwnd;
            ssthresh = new_ssthresh;

            pkt_num += 1;
        }

        // 2nd round. rtt = 100ms to trigger LSS.
        let rtt_2nd = 100;

        hspp.start_round(pkt_1st * 2 + 1);

        for _ in 0..N_RTT_SAMPLE + 1 {
            let p = recovery::Acked {
                pkt_num,
                time_sent: now + Duration::from_millis(pkt_num),
                size,
            };

            // Keep increasing rtt to simulate buffer queueing delay
            // This is to exit from slow slart to LSS.
            let rtt = Duration::from_millis(rtt_2nd + pkt_num * 4);

            let (new_cwnd, new_ssthresh) =
                hspp.on_packet_acked(&p, rtt, cwnd, ssthresh, now);

            cwnd = new_cwnd;
            ssthresh = new_ssthresh;

            pkt_num += 1;
        }

        // At this point, cwnd exits to LSS mode.
        assert_eq!(hspp.lss_start_time().is_some(), true);

        // Check if current cwnd is in LSS.
        let cur_ssthresh = 47000;
        let k = cur_ssthresh as f64 / (LSS_DIVISOR * cur_ssthresh as f64);
        let lss_cwnd = cur_ssthresh as f64 + size as f64 / k;

        assert_eq!((cwnd, ssthresh), (lss_cwnd as usize, cur_ssthresh));
    }

    #[test]
    fn congestion_event() {
        let mut hspp = Hystart::default();
        let pkt_num = 100;

        hspp.start_round(pkt_num);

        assert_eq!(hspp.window_end, Some(pkt_num));

        // When moving into CA mode, window_end should be cleared.
        hspp.congestion_event();

        assert_eq!(hspp.window_end, None);
    }
}
