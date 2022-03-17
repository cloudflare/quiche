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
//! <https://datatracker.ietf.org/doc/html/draft-ietf-tcpm-hystartplusplus-04>

use std::cmp;
use std::time::Duration;
use std::time::Instant;

use crate::packet;
use crate::recovery;

/// Constants from I-D.
const MIN_RTT_THRESH: Duration = Duration::from_millis(4);

const MAX_RTT_THRESH: Duration = Duration::from_millis(16);

pub const N_RTT_SAMPLE: usize = 8;

pub const CSS_GROWTH_DIVISOR: usize = 4;

pub const CSS_ROUNDS: usize = 5;

#[derive(Default)]
pub struct Hystart {
    enabled: bool,

    window_end: Option<u64>,

    last_round_min_rtt: Duration,

    current_round_min_rtt: Duration,

    css_baseline_min_rtt: Duration,

    rtt_sample_count: usize,

    css_start_time: Option<Instant>,

    css_round_count: usize,
}

impl std::fmt::Debug for Hystart {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "window_end={:?} ", self.window_end)?;
        write!(f, "last_round_min_rtt={:?} ", self.last_round_min_rtt)?;
        write!(f, "current_round_min_rtt={:?} ", self.current_round_min_rtt)?;
        write!(f, "css_baseline_min_rtt={:?} ", self.css_baseline_min_rtt)?;
        write!(f, "rtt_sample_count={:?} ", self.rtt_sample_count)?;
        write!(f, "css_start_time={:?} ", self.css_start_time)?;
        write!(f, "css_round_count={:?}", self.css_round_count)?;

        Ok(())
    }
}

impl Hystart {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,

            last_round_min_rtt: Duration::MAX,

            current_round_min_rtt: Duration::MAX,

            css_baseline_min_rtt: Duration::MAX,

            ..Default::default()
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.enabled);
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn css_start_time(&self) -> Option<Instant> {
        self.css_start_time
    }

    pub fn in_css(&self, epoch: packet::Epoch) -> bool {
        self.enabled &&
            epoch == packet::EPOCH_APPLICATION &&
            self.css_start_time().is_some()
    }

    pub fn start_round(&mut self, pkt_num: u64) {
        if self.window_end.is_none() {
            self.window_end = Some(pkt_num);

            self.last_round_min_rtt = self.current_round_min_rtt;

            self.current_round_min_rtt = Duration::MAX;

            self.rtt_sample_count = 0;
        }
    }

    // On receiving ACK. Returns true if need to enter Congestion Avoidance.
    pub fn on_packet_acked(
        &mut self, epoch: packet::Epoch, packet: &recovery::Acked, rtt: Duration,
        now: Instant,
    ) -> bool {
        if !(self.enabled && epoch == packet::EPOCH_APPLICATION) {
            return false;
        }

        self.current_round_min_rtt = cmp::min(self.current_round_min_rtt, rtt);

        self.rtt_sample_count += 1;

        // Slow Start.
        if self.css_start_time().is_none() {
            if self.rtt_sample_count >= N_RTT_SAMPLE &&
                self.current_round_min_rtt != Duration::MAX &&
                self.last_round_min_rtt != Duration::MAX
            {
                // clamp(min_rtt_thresh, last_round_min_rtt/8,
                // max_rtt_thresh)
                let rtt_thresh =
                    cmp::max(self.last_round_min_rtt / 8, MIN_RTT_THRESH);
                let rtt_thresh = cmp::min(rtt_thresh, MAX_RTT_THRESH);

                // Check if we can exit to CSS.
                if self.current_round_min_rtt >=
                    self.last_round_min_rtt.saturating_add(rtt_thresh)
                {
                    self.css_baseline_min_rtt = self.current_round_min_rtt;
                    self.css_start_time = Some(now);
                }
            }
        } else {
            // Conservative Slow Start.
            if self.rtt_sample_count >= N_RTT_SAMPLE {
                self.rtt_sample_count = 0;

                if self.current_round_min_rtt < self.css_baseline_min_rtt {
                    self.css_baseline_min_rtt = Duration::MAX;

                    // Back to Slow Start.
                    self.css_start_time = None;
                    self.css_round_count = 0;
                }
            }
        }

        // Check if we reached the end of the round.
        if let Some(end_pkt_num) = self.window_end {
            if packet.pkt_num >= end_pkt_num {
                // Start of a new round.
                self.window_end = None;

                if self.css_start_time().is_some() {
                    self.css_round_count += 1;

                    // End of CSS - exit to congestion avoidance.
                    if self.css_round_count >= CSS_ROUNDS {
                        self.css_round_count = 0;
                        return true;
                    }
                }
            }
        }

        false
    }

    // Return a cwnd increment during CSS (Conservative Slow Start).
    pub fn css_cwnd_inc(&self, pkt_size: usize) -> usize {
        pkt_size / CSS_GROWTH_DIVISOR
    }

    // Exit HyStart++ when entering congestion avoidance.
    pub fn congestion_event(&mut self) {
        self.window_end = None;
        self.css_start_time = None;
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
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
    }

    #[test]
    fn css_cwnd_inc() {
        let hspp = Hystart::default();
        let datagram_size = 1200;

        let css_cwnd_inc = hspp.css_cwnd_inc(datagram_size);

        assert_eq!(datagram_size / CSS_GROWTH_DIVISOR, css_cwnd_inc);
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
