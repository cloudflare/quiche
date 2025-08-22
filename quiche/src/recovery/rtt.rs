// Copyright (C) 2024, Cloudflare, Inc.
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

use std::time::Duration;
use std::time::Instant;

use crate::minmax::Minmax;
use crate::recovery::GRANULARITY;

pub(crate) const RTT_WINDOW: Duration = Duration::from_secs(300);

pub struct RttStats {
    pub(super) latest_rtt: Duration,

    max_rtt: Duration,

    pub(super) smoothed_rtt: Duration,

    pub(super) rttvar: Duration,

    pub(super) min_rtt: Minmax<Duration>,

    pub(super) max_ack_delay: Duration,

    pub(super) has_first_rtt_sample: bool,

    ack_freq_last_used_rtt: Duration,

    pub(super) ack_freq_required: bool,
}

impl std::fmt::Debug for RttStats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("RttStats")
            .field("lastest_rtt", &self.latest_rtt)
            .field("srtt", &self.smoothed_rtt)
            .field("minrtt", &*self.min_rtt)
            .field("rttvar", &self.rttvar)
            .finish()
    }
}

impl RttStats {
    pub(crate) fn new(initial_rtt: Duration, max_ack_delay: Duration) -> Self {
        RttStats {
            latest_rtt: Duration::ZERO,
            min_rtt: Minmax::new(initial_rtt),
            smoothed_rtt: initial_rtt,
            max_rtt: initial_rtt,
            rttvar: initial_rtt / 2,
            has_first_rtt_sample: false,
            max_ack_delay,
            ack_freq_last_used_rtt: initial_rtt,
            ack_freq_required: false,
        }
    }

    pub(crate) fn update_rtt(
        &mut self, latest_rtt: Duration, mut ack_delay: Duration, now: Instant,
        handshake_confirmed: bool,
    ) {
        self.latest_rtt = latest_rtt;

        if !self.has_first_rtt_sample {
            self.min_rtt.reset(now, latest_rtt);
            self.smoothed_rtt = latest_rtt;
            self.max_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.has_first_rtt_sample = true;
            self.ack_freq_last_used_rtt = latest_rtt;
            self.ack_freq_required = true;
            return;
        }

        // min_rtt ignores acknowledgment delay.
        self.min_rtt.running_min(RTT_WINDOW, now, latest_rtt);

        self.max_rtt = self.max_rtt.max(latest_rtt);

        // Limit ack_delay by max_ack_delay after handshake confirmation.
        if handshake_confirmed {
            ack_delay = ack_delay.min(self.max_ack_delay);
        }

        // Adjust for acknowledgment delay if plausible.
        let mut adjusted_rtt = latest_rtt;
        if latest_rtt >= *self.min_rtt + ack_delay {
            adjusted_rtt = latest_rtt - ack_delay;
        }

        self.rttvar = self.rttvar * 3 / 4 +
            Duration::from_nanos(
                self.smoothed_rtt
                    .as_nanos()
                    .abs_diff(adjusted_rtt.as_nanos()) as u64 /
                    4,
            );

        self.smoothed_rtt = self.smoothed_rtt * 7 / 8 + adjusted_rtt / 8;

        if !self.ack_freq_required &&
            2.0 * self
                .smoothed_rtt
                .abs_diff(self.ack_freq_last_used_rtt)
                .div_duration_f32(
                    self.smoothed_rtt + self.ack_freq_last_used_rtt,
                ) >
                0.5
        {
            // send AckFrequency frame if the smoothed rtt is modified by at least
            // 50% since the last AckFrequency frame was sent
            // This value is arbitrary since the draft don't specify anything
            // apart from "a relevant change":
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-11#name-congestion-control
            // Ideally, an ACK_FREQUENCY frame is sent only when a relevant change
            // in the congestion window or smoothed RTT is detected that impacts
            // the local setting of the reordering threshold or locally-selected
            // calculation of the either Ack-Eliciting Threshold or the Requested
            // Max Ack Delay.
            self.ack_freq_required = true;
        }
    }

    pub(crate) fn set_ack_freq_send(&mut self, used_rtt: Duration) {
        self.ack_freq_last_used_rtt = used_rtt;
        self.ack_freq_required = false;
    }

    pub(crate) fn is_ack_freq_required(&self) -> bool {
        self.ack_freq_required
    }

    pub(crate) fn mark_ack_freq_as_required(&mut self) {
        self.ack_freq_required = true;
    }

    pub(crate) fn rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    #[allow(dead_code)]
    pub(crate) fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    pub(crate) fn rttvar(&self) -> Duration {
        self.rttvar
    }

    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        if self.has_first_rtt_sample {
            Some(*self.min_rtt)
        } else {
            None
        }
    }

    pub(crate) fn max_rtt(&self) -> Option<Duration> {
        if self.has_first_rtt_sample {
            Some(self.max_rtt)
        } else {
            None
        }
    }

    pub(crate) fn loss_delay(&self, time_thresh: f64) -> Duration {
        self.latest_rtt
            .max(self.smoothed_rtt)
            .mul_f64(time_thresh)
            .max(GRANULARITY)
    }
}
