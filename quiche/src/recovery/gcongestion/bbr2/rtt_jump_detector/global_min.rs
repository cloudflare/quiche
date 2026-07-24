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

use super::RttJumpUpdate;

// An RTT jump is a sustained RTT increase above the connection-lifetime minimum
// RTT. The GlobalMin detector treats samples above 3x that baseline as
// elevated, counts a jump only after repeated elevated samples persist for a
// baseline-scaled dwell period, and clears the episode when RTT falls back to
// 3x baseline or below.
//
// GlobalMin episode lifecycle:
//
//     elevated        sustained elevated       clear
// Idle -------> Active -----------------> Persistent
//   ^              |                           |
//   |              | clear                     | clear
//   +--------------+---------------------------+
//
// Sample trace:
//
//           __A__                __P__
//      __A__|    |       __A__A__|     |__P__
//     |         |       |                   |
//  I__|         |___I___|                   |___I
// I__|
//
// I = Idle
// A = Active
// P = Persistent

/// Tracks the lifecycle of a global-min RTT jump episode.
#[derive(Debug, Default, Clone, Copy)]
enum GlobalMinEpisode {
    /// No elevation currently observed.
    #[default]
    Idle,
    /// A jump has been observed but not yet sustained long enough to be
    /// considered persistent.
    Active {
        elevated_samples: usize,
        episode_start_time: Instant,
    },
    /// The elevated RTT has been confirmed as a persistent network condition.
    Persistent,
}

/// Multiplicative factor over the global-min RTT baseline above which a sample
/// is classified as an RTT jump.
const GLOBAL_MIN_JUMP_THRESHOLD: f32 = 3.0;

/// Elevated RTT samples required before an active episode becomes persistent.
const GLOBAL_MIN_CONFIRM_SAMPLES: usize = 3;

/// Minimum episode duration, expressed as a multiple of the global-min RTT
/// baseline, required before an active episode becomes persistent.
const GLOBAL_MIN_CONFIRM_DURATION_MULTIPLIER: u32 = 3;

#[derive(Debug, Default)]
pub(super) struct GlobalMinDetector {
    /// Connection-lifetime minimum RTT sample used by the detector.
    baseline: Option<Duration>,
    /// Lifecycle state used to distinguish transient RTT spikes from persistent
    /// increases.
    episode: GlobalMinEpisode,
}

impl GlobalMinDetector {
    /// Global-min RTT jump detector step: connection-lifetime minimum baseline
    /// with a strict multiplicative jump test and a sample/duration
    /// confirmation gate.
    pub(super) fn on_rtt_sample(
        &mut self, rtt_sample: Duration, event_time: Instant,
        full_bandwidth_reached: bool,
    ) -> RttJumpUpdate {
        if !full_bandwidth_reached {
            self.update_baseline(rtt_sample);
            return RttJumpUpdate::None;
        }

        let Some(baseline) = self.baseline else {
            self.update_baseline(rtt_sample);
            return RttJumpUpdate::None;
        };

        let is_jump = rtt_sample > baseline.mul_f32(GLOBAL_MIN_JUMP_THRESHOLD);
        let is_clear = !is_jump;
        let mut update = RttJumpUpdate::None;

        match self.episode {
            GlobalMinEpisode::Idle =>
                if is_jump {
                    self.episode = GlobalMinEpisode::Active {
                        elevated_samples: 1,
                        episode_start_time: event_time,
                    };
                },

            GlobalMinEpisode::Active {
                elevated_samples,
                episode_start_time,
            } =>
                if is_clear {
                    self.episode = GlobalMinEpisode::Idle;
                } else {
                    let elevated_samples = elevated_samples + 1;
                    let dwell = baseline * GLOBAL_MIN_CONFIRM_DURATION_MULTIPLIER;
                    let samples_ok =
                        elevated_samples >= GLOBAL_MIN_CONFIRM_SAMPLES;
                    let time_ok = event_time
                        .saturating_duration_since(episode_start_time) >=
                        dwell;

                    if samples_ok && time_ok {
                        update = RttJumpUpdate::PersistentConfirmed {
                            episode_start_time,
                        };
                        self.episode = GlobalMinEpisode::Persistent;
                    } else {
                        self.episode = GlobalMinEpisode::Active {
                            elevated_samples,
                            episode_start_time,
                        };
                    }
                },

            GlobalMinEpisode::Persistent =>
                if is_clear {
                    self.episode = GlobalMinEpisode::Idle;
                },
        }

        self.update_baseline(rtt_sample);
        update
    }

    fn update_baseline(&mut self, rtt_sample: Duration) {
        self.baseline =
            Some(self.baseline.map_or(rtt_sample, |min| min.min(rtt_sample)));
    }

    #[cfg(test)]
    pub(super) fn is_rtt_jump_active(&self) -> bool {
        !matches!(self.episode, GlobalMinEpisode::Idle)
    }

    #[cfg(test)]
    pub(super) fn is_rtt_jump_persistent(&self) -> bool {
        matches!(self.episode, GlobalMinEpisode::Persistent)
    }
}

#[cfg(test)]
#[path = "global_min_tests.rs"]
mod tests;
