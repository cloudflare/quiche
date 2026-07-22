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

// An RTT jump is a sustained RTT increase above the connection-lifetime minimum
// RTT baseline. The GlobalMin detector treats samples above 3x that baseline as
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
//             __A__                __P__
//       __A__|    |       __A__A__|     |__P__
//       |         |       |                   |
//    I__|         |___I___|                   |___I
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
pub(super) struct RttJumpDetector {
    /// Connection-lifetime minimum RTT sample used by the detector.
    baseline: Option<Duration>,
    /// Lifecycle state used to distinguish transient RTT spikes from persistent
    /// increases.
    episode: GlobalMinEpisode,
    /// Total number of confirmed persistent RTT jump episodes.
    persistent_jump_count: u64,
    /// The start time of the most recently confirmed persistent RTT jump
    /// episode, if any.
    last_persistent_jump_time: Option<Instant>,
}

impl RttJumpDetector {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Runs the selected RTT jump detector for one RTT sample.
    pub(super) fn on_rtt_sample_with_mode(
        &mut self, mode: BbrRttJumpDetector, rtt_sample: Duration,
        event_time: Instant, full_bandwidth_reached: bool,
    ) {
        match mode {
            BbrRttJumpDetector::Disabled => {},
            BbrRttJumpDetector::GlobalMin => self.on_rtt_sample_global_min(
                rtt_sample,
                event_time,
                full_bandwidth_reached,
            ),
        }
    }

    /// Global-min RTT jump detector step: connection-lifetime minimum baseline
    /// with a strict multiplicative jump test and a sample/duration
    /// confirmation gate.
    fn on_rtt_sample_global_min(
        &mut self, rtt_sample: Duration, event_time: Instant,
        full_bandwidth_reached: bool,
    ) {
        if !full_bandwidth_reached {
            self.update_baseline(rtt_sample);
            return;
        }

        let Some(baseline) = self.baseline else {
            self.update_baseline(rtt_sample);
            return;
        };

        let is_jump = rtt_sample > baseline.mul_f32(GLOBAL_MIN_JUMP_THRESHOLD);
        let is_clear = !is_jump;

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
                        self.persistent_jump_count += 1;
                        self.last_persistent_jump_time = Some(episode_start_time);
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
    }

    fn update_baseline(&mut self, rtt_sample: Duration) {
        self.baseline =
            Some(self.baseline.map_or(rtt_sample, |min| min.min(rtt_sample)));
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
        !matches!(self.episode, GlobalMinEpisode::Idle)
    }

    /// Whether the current RTT jump episode has been confirmed as persistent.
    #[cfg(test)]
    pub(super) fn is_rtt_jump_persistent(&self) -> bool {
        matches!(self.episode, GlobalMinEpisode::Persistent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(50);
    const RTT_3X: Duration = Duration::from_millis(150);
    const RTT_JUMP: Duration = Duration::from_millis(151);
    const LOW_RTT: Duration = Duration::from_millis(10);
    const HIGH_RTT: Duration = Duration::from_millis(500);

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    fn sample(
        detector: &mut RttJumpDetector, base: Instant, offset: Duration,
        rtt: Duration,
    ) {
        sample_with_full_bandwidth(detector, base, offset, rtt, true);
    }

    fn sample_with_full_bandwidth(
        detector: &mut RttJumpDetector, base: Instant, offset: Duration,
        rtt: Duration, full_bandwidth_reached: bool,
    ) {
        detector.on_rtt_sample_with_mode(
            BbrRttJumpDetector::GlobalMin,
            rtt,
            base + offset,
            full_bandwidth_reached,
        );
    }

    #[test]
    fn global_min_detector_uses_strict_3x_threshold() {
        let base = Instant::now();

        let mut at_edge = RttJumpDetector::new();
        sample(&mut at_edge, base, ms(10), RTT);
        sample(&mut at_edge, base, ms(20), RTT_3X);
        assert!(!at_edge.is_rtt_jump_active());

        let mut just_above = RttJumpDetector::new();
        sample(&mut just_above, base, ms(10), RTT);
        sample(&mut just_above, base, ms(20), RTT_JUMP);
        assert!(just_above.is_rtt_jump_active());
    }

    #[test]
    fn global_min_detector_clears_active_at_or_below_threshold() {
        let base = Instant::now();

        let mut at_edge = RttJumpDetector::new();
        sample(&mut at_edge, base, ms(10), RTT);
        sample(&mut at_edge, base, ms(20), RTT_JUMP);
        assert!(at_edge.is_rtt_jump_active());
        sample(&mut at_edge, base, ms(30), RTT_3X);
        assert!(!at_edge.is_rtt_jump_active());

        let mut below_edge = RttJumpDetector::new();
        sample(&mut below_edge, base, ms(10), RTT);
        sample(&mut below_edge, base, ms(20), RTT_JUMP);
        assert!(below_edge.is_rtt_jump_active());
        sample(&mut below_edge, base, ms(30), RTT);
        assert!(!below_edge.is_rtt_jump_active());
    }

    #[test]
    fn global_min_detector_sustained_step_becomes_persistent() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();

        sample(&mut detector, base, ms(10), RTT);
        sample(&mut detector, base, ms(20), RTT_JUMP);
        assert!(detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(30), RTT_JUMP);
        assert!(!detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(170), RTT_JUMP);
        assert!(detector.is_rtt_jump_persistent());
        assert_eq!(detector.rtt_persistent_jump_count(), 1);
        assert_eq!(detector.last_persistent_jump_time(), Some(base + ms(20)));
    }

    #[test]
    fn global_min_detector_clears_persistent_at_or_below_threshold() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();

        sample(&mut detector, base, ms(10), RTT);
        sample(&mut detector, base, ms(20), RTT_JUMP);
        sample(&mut detector, base, ms(30), RTT_JUMP);
        sample(&mut detector, base, ms(170), RTT_JUMP);
        assert!(detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(180), RTT_3X);
        assert!(!detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());
        assert_eq!(detector.rtt_persistent_jump_count(), 1);
    }

    #[test]
    fn global_min_detector_tracks_downward_baseline() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();

        sample(&mut detector, base, ms(100), ms(100));
        sample(&mut detector, base, ms(200), ms(299));
        assert!(!detector.is_rtt_jump_active());

        sample(&mut detector, base, ms(300), RTT);
        assert!(!detector.is_rtt_jump_active());

        sample(&mut detector, base, ms(400), RTT_JUMP);
        assert!(detector.is_rtt_jump_active());
    }

    #[test]
    fn global_min_detector_repeated_elevation_waits_for_dwell() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();

        sample(&mut detector, base, ms(10), RTT);
        sample(&mut detector, base, ms(20), RTT_JUMP);
        sample(&mut detector, base, ms(30), RTT_JUMP);
        sample(&mut detector, base, ms(40), RTT_JUMP);

        assert!(detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());
        assert_eq!(detector.rtt_persistent_jump_count(), 0);
    }

    #[test]
    fn global_min_detector_ignores_jumps_before_full_bandwidth() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();

        sample_with_full_bandwidth(&mut detector, base, ms(10), RTT, false);
        sample_with_full_bandwidth(&mut detector, base, ms(20), RTT_JUMP, false);
        sample_with_full_bandwidth(&mut detector, base, ms(30), RTT_JUMP, false);
        sample_with_full_bandwidth(&mut detector, base, ms(170), RTT_JUMP, false);

        assert!(!detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());
        assert_eq!(detector.rtt_persistent_jump_count(), 0);

        sample(&mut detector, base, ms(180), RTT_JUMP);
        assert!(detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(190), RTT_JUMP);
        assert!(!detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(330), RTT_JUMP);
        assert!(detector.is_rtt_jump_persistent());
        assert_eq!(detector.rtt_persistent_jump_count(), 1);
    }

    #[test]
    fn global_min_detector_uses_baseline_scaled_dwell() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();
        let jump = HIGH_RTT.mul_f32(GLOBAL_MIN_JUMP_THRESHOLD) + ms(1);

        sample(&mut detector, base, ms(10), HIGH_RTT);
        sample(&mut detector, base, ms(20), jump);
        sample(&mut detector, base, ms(100), jump);
        sample(&mut detector, base, ms(200), jump);

        assert!(detector.is_rtt_jump_active());
        assert!(!detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(1520), jump);
        assert!(detector.is_rtt_jump_persistent());
    }

    #[test]
    fn global_min_detector_handles_low_rtt_dwell() {
        let mut detector = RttJumpDetector::new();
        let base = Instant::now();
        let jump = LOW_RTT.mul_f32(GLOBAL_MIN_JUMP_THRESHOLD) + ms(1);

        sample(&mut detector, base, ms(10), LOW_RTT);
        sample(&mut detector, base, ms(20), jump);
        sample(&mut detector, base, ms(30), jump);
        assert!(!detector.is_rtt_jump_persistent());

        sample(&mut detector, base, ms(50), jump);
        assert!(detector.is_rtt_jump_persistent());
    }
}
