// Copyright (C) 2026, Cloudflare, Inc.
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

use crate::recovery::gcongestion::BbrRttJumpDetector;

mod global_min;
mod hmm;

use self::global_min::GlobalMinDetector;
use self::hmm::HmmDetector;

#[derive(Debug)]
pub(super) struct RttJumpDetector {
    /// Total number of confirmed persistent RTT jump episodes.
    persistent_jump_count: u64,
    /// The start time of the most recently confirmed persistent RTT jump
    /// episode, if any.
    last_persistent_jump_time: Option<Instant>,
    /// The detector selected for this connection.
    detector: ActiveRttJumpDetector,
}

#[derive(Debug)]
enum ActiveRttJumpDetector {
    Disabled,
    GlobalMin(GlobalMinDetector),
    Hmm(HmmDetector),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RttJumpUpdate {
    None,
    PersistentConfirmed { episode_start_time: Instant },
}

impl RttJumpDetector {
    pub(super) fn new(mode: BbrRttJumpDetector) -> Self {
        let detector = match mode {
            BbrRttJumpDetector::Disabled => ActiveRttJumpDetector::Disabled,
            BbrRttJumpDetector::GlobalMin =>
                ActiveRttJumpDetector::GlobalMin(GlobalMinDetector::default()),
            BbrRttJumpDetector::Hmm =>
                ActiveRttJumpDetector::Hmm(HmmDetector::default()),
        };

        Self {
            persistent_jump_count: 0,
            last_persistent_jump_time: None,
            detector,
        }
    }

    /// Runs the connection's selected RTT jump detector for one RTT sample.
    pub(super) fn on_rtt_sample(
        &mut self, rtt_sample: Duration, event_time: Instant,
        full_bandwidth_reached: bool,
    ) {
        let update = match &mut self.detector {
            ActiveRttJumpDetector::Disabled => RttJumpUpdate::None,
            ActiveRttJumpDetector::GlobalMin(detector) => detector.on_rtt_sample(
                rtt_sample,
                event_time,
                full_bandwidth_reached,
            ),
            ActiveRttJumpDetector::Hmm(detector) => detector.on_rtt_sample(
                rtt_sample,
                event_time,
                full_bandwidth_reached,
            ),
        };

        self.apply_update(update);
    }

    fn apply_update(&mut self, update: RttJumpUpdate) {
        match update {
            RttJumpUpdate::None => {},
            RttJumpUpdate::PersistentConfirmed { episode_start_time } => {
                self.persistent_jump_count += 1;
                self.last_persistent_jump_time = Some(episode_start_time);
            },
        }
    }

    /// Total number of confirmed persistent RTT jump episodes.
    pub(super) fn rtt_persistent_jump_count(&self) -> u64 {
        self.persistent_jump_count
    }

    /// The start time of the most recently confirmed persistent RTT jump
    /// episode, if any.
    #[cfg(test)]
    pub(super) fn last_persistent_jump_time(&self) -> Option<Instant> {
        self.last_persistent_jump_time
    }

    /// Whether an RTT jump episode is currently active.
    #[cfg(test)]
    pub(super) fn is_rtt_jump_active(&self) -> bool {
        match &self.detector {
            ActiveRttJumpDetector::Disabled => false,
            ActiveRttJumpDetector::GlobalMin(detector) =>
                detector.is_rtt_jump_active(),
            ActiveRttJumpDetector::Hmm(detector) => detector.is_rtt_jump_active(),
        }
    }

    /// Whether the current RTT jump episode has been confirmed as persistent.
    #[cfg(test)]
    pub(super) fn is_rtt_jump_persistent(&self) -> bool {
        match &self.detector {
            ActiveRttJumpDetector::Disabled => false,
            ActiveRttJumpDetector::GlobalMin(detector) =>
                detector.is_rtt_jump_persistent(),
            ActiveRttJumpDetector::Hmm(detector) =>
                detector.is_rtt_jump_persistent(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use crate::recovery::gcongestion::BbrRttJumpDetector;

    use super::*;

    const RTT_JUMP: Duration = Duration::from_millis(151);

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    fn sample(
        detector: &mut RttJumpDetector, base: Instant, offset: Duration,
        rtt: Duration,
    ) {
        detector.on_rtt_sample(rtt, base + offset, true);
    }

    #[test]
    fn disabled_detector_does_not_store_active_behavior() {
        let mut detector = RttJumpDetector::new(BbrRttJumpDetector::Disabled);
        let base = Instant::now();

        for pkt in 1..20 {
            sample(&mut detector, base, ms(pkt * 100), RTT_JUMP);
        }

        assert!(!detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());
        assert_eq!(detector.rtt_persistent_jump_count(), 0);
        assert_eq!(detector.last_persistent_jump_time(), None);
    }
}
