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

pub(crate) const INITIAL_RTT: Duration = Duration::from_millis(333);

pub(crate) const RTT_WINDOW: Duration = Duration::from_secs(300);

pub struct RttStats {
    pub(super) latest_rtt: Duration,

    pub(super) smoothed_rtt: Duration,

    pub(super) rttvar: Duration,

    pub(super) min_rtt: Minmax<Duration>,

    pub(super) max_ack_delay: Duration,

    pub(super) first_rtt_sample: Option<Instant>,
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
    pub(crate) fn new(max_ack_delay: Duration) -> Self {
        RttStats {
            latest_rtt: Duration::ZERO,
            min_rtt: Minmax::new(Duration::ZERO),
            smoothed_rtt: INITIAL_RTT,
            rttvar: INITIAL_RTT / 2,
            first_rtt_sample: None,
            max_ack_delay,
        }
    }

    pub(crate) fn update_rtt(
        &mut self, latest_rtt: Duration, mut ack_delay: Duration, now: Instant,
        handshake_confirmed: bool,
    ) {
        self.latest_rtt = latest_rtt;

        if self.first_rtt_sample.is_none() {
            self.min_rtt.reset(now, latest_rtt);
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.first_rtt_sample = Some(now);
            return;
        }

        // min_rtt ignores acknowledgment delay.
        self.min_rtt.running_min(RTT_WINDOW, now, latest_rtt);

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
    }

    pub(crate) fn rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.ne(&Duration::ZERO).then_some(*self.min_rtt)
    }
}
