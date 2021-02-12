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
//! <https://tools.ietf.org/html/draft-balasubramanian-tcpm-hystartplusplus-03>

use std::cmp;
use std::time::Duration;
use std::time::Instant;

use crate::packet;
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

    pub fn in_lss(&self, epoch: packet::Epoch) -> bool {
        self.enabled &&
            epoch == packet::EPOCH_APPLICATION &&
            self.lss_start_time().is_some()
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

    // Returns true if LSS started.
    pub fn try_enter_lss(
        &mut self, packet: &recovery::Acked, rtt: Duration, cwnd: usize,
        now: Instant, max_datagram_size: usize,
    ) -> bool {
        if self.lss_start_time().is_none() {
            if let Some(current_round_min_rtt) = self.current_round_min_rtt {
                self.current_round_min_rtt =
                    Some(cmp::min(current_round_min_rtt, rtt));
            } else {
                self.current_round_min_rtt = Some(rtt);
            }

            self.rtt_sample_count += 1;

            if cwnd >= (LOW_CWND * max_datagram_size) &&
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
        }

        self.lss_start_time.is_some()
    }

    // Return a new cwnd during LSS (Limited Slow Start).
    pub fn lss_cwnd(
        &self, pkt_size: usize, bytes_acked: usize, cwnd: usize, ssthresh: usize,
        max_datagram_size: usize,
    ) -> usize {
        let k = cwnd as f64 / (LSS_DIVISOR * ssthresh as f64);

        cwnd + cmp::min(
            pkt_size,
            max_datagram_size * recovery::ABC_L -
                cmp::min(bytes_acked, max_datagram_size * recovery::ABC_L),
        ) / k as usize
    }

    // Exit HyStart++ when entering congestion avoidance.
    pub fn congestion_event(&mut self) {
        self.window_end = None;
        self.lss_start_time = None;
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
    fn lss_cwnd() {
        let hspp = Hystart::default();

        let datagram_size = 1200;
        let mut cwnd = 24000;
        let ssthresh = 24000;

        let lss_cwnd =
            hspp.lss_cwnd(datagram_size, 0, cwnd, ssthresh, datagram_size);

        assert_eq!(
            cwnd + (datagram_size as f64 * LSS_DIVISOR) as usize,
            lss_cwnd
        );

        cwnd = lss_cwnd;

        let lss_cwnd = hspp.lss_cwnd(
            datagram_size,
            datagram_size,
            cwnd,
            ssthresh,
            datagram_size,
        );

        assert_eq!(
            cwnd + (datagram_size as f64 * LSS_DIVISOR) as usize,
            lss_cwnd
        );
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
