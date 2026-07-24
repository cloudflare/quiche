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

// 3-state discrete-emission Hidden Markov Model (HMM) RTT jump detector
// (forward filtering only).
//
// The detector is threshold agnostic: rather than binning the raw RTT ratio
// against fixed multiplicative cutoffs, it tracks the elevation the connection
// *operates* at above the running-min baseline (an EWMA of the relative
// deviation observed during calm samples, floored at `HMM_ELEVATION_FLOOR`) and
// standardizes each sample as its jump *above* that operating elevation, in
// multiples of it. A "jump" is therefore measured against the connection's own
// operating point, so ordinary slow self-queueing is less likely to commit as a
// persistent jump while genuine step changes remain detectable across links
// with very different absolute RTT and jitter.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmmState {
    Normal,
    Transient,
    Persistent,
}

impl HmmState {
    fn as_index(self) -> usize {
        match self {
            HmmState::Normal => 0,
            HmmState::Transient => 1,
            HmmState::Persistent => 2,
        }
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => HmmState::Normal,
            1 => HmmState::Transient,
            2 => HmmState::Persistent,
            _ => unreachable!("invalid HMM state index"),
        }
    }

    fn from_episode(episode: HmmEpisode) -> Self {
        match episode {
            HmmEpisode::Idle => HmmState::Normal,
            HmmEpisode::Active => HmmState::Transient,
            HmmEpisode::Persistent => HmmState::Persistent,
        }
    }

    fn to_episode(self) -> HmmEpisode {
        match self {
            HmmState::Normal => HmmEpisode::Idle,
            HmmState::Transient => HmmEpisode::Active,
            HmmState::Persistent => HmmEpisode::Persistent,
        }
    }

    fn is_more_elevated_than(self, other: Self) -> bool {
        self.as_index() > other.as_index()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum HmmEpisode {
    #[default]
    Idle,
    Active,
    Persistent,
}

const HMM_STATE_COUNT: usize = 3;
const HMM_BINS: usize = 5;

/// Valid RTT samples observed before the HMM may leave `Idle`.
const HMM_WARMUP_SAMPLES: u32 = 8;

/// Minimum wall-clock dwell for any committed-state transition.
const HMM_MIN_DWELL: Duration = Duration::from_millis(80);

/// RTTs the raw HMM argmax must continuously hold `Transient` before a
/// transient episode is committed.
const HMM_TRANSIENT_DWELL_RTTS: f32 = 1.0;

/// RTTs the raw HMM argmax must continuously hold `Persistent` before a
/// persistent jump is committed.
const HMM_PERSIST_DWELL_RTTS: f32 = 5.0;

/// RTTs the raw HMM argmax must continuously hold a calmer state before a
/// committed episode exits.
const HMM_CLEAR_DWELL_RTTS: f32 = 1.0;

/// HMM persistent-state samples required before committing a persistent jump.
const HMM_PERSIST_CONFIRM_SAMPLES: u32 = 3;

// These matrices are fixed model parameters for RTT-jump detection, calibrated
// offline from constructed RTT-jump scenarios. They intentionally remain fixed
// at runtime: the online adaptive parts of this detector are the per-connection
// operating-elevation estimate and RTT-scaled dwell gates. Adapting the
// probabilities online would make detections non-deterministic and risks
// learning persistent RTT jumps as normal behavior.

/// HMM transition matrix `A[i][j]` = P(state_t = j | state_{t-1} = i).
const HMM_TRANSITION: [[f32; HMM_STATE_COUNT]; HMM_STATE_COUNT] = [
    // from Normal: strongly self-sticky; the small leak prefers Transient over
    // Persistent so onset is routed through the middle state.
    [0.9939, 0.0055, 0.0006],
    // from Transient: decays back to Normal unless elevation is reinforced.
    [0.4500, 0.3500, 0.2000],
    // from Persistent: very sticky once a sustained shift is established.
    [0.0243, 0.1603, 0.8154],
];

/// HMM emission matrix `B[state][bin]` = P(bin | state) over the K = 5
/// standardized-elevation bins defined by `HMM_STD_BIN_EDGES`.
const HMM_EMISSION: [[f32; HMM_BINS]; HMM_STATE_COUNT] = [
    // Normal: almost always within a dispersion of the baseline.
    [0.9996, 0.0001, 0.0001, 0.0001, 0.0001],
    // Transient: moderate-to-large elevation.
    [0.1000, 0.3500, 0.3000, 0.1500, 0.1000],
    // Persistent: sustained elevation above the operating level.
    [0.0001, 0.5000, 0.2200, 0.1600, 0.1199],
];

/// Upper-exclusive bin edges for the standardized elevation
/// `max(rel - dispersion, 0) / dispersion`.
const HMM_STD_BIN_EDGES: [f32; HMM_BINS - 1] = [1.0, 2.0, 4.0, 8.0];

/// EWMA weight for the online dispersion estimate.
const HMM_DISP_EWMA_ALPHA: f32 = 0.0625;

/// Lower bound on the operating-elevation estimate used to standardize a
/// sample.
const HMM_ELEVATION_FLOOR: f32 = 0.20;

/// Map a standardized elevation onto its discrete emission bin.
fn hmm_std_bin(elevation: f32, edges: &[f32; HMM_BINS - 1]) -> usize {
    let mut bin = 0;
    while bin < edges.len() && elevation >= edges[bin] {
        bin += 1;
    }
    bin
}

/// One scaled forward-filter step.
fn hmm_forward_step(
    alpha: &mut [f32; HMM_STATE_COUNT], bin: usize,
    transition: &[[f32; HMM_STATE_COUNT]; HMM_STATE_COUNT],
    emission: &[[f32; HMM_BINS]; HMM_STATE_COUNT],
) {
    let mut next = [0.0f32; HMM_STATE_COUNT];
    for (j, next_j) in next.iter_mut().enumerate() {
        let mut predicted = 0.0f32;
        for (i, &alpha_i) in alpha.iter().enumerate() {
            predicted += alpha_i * transition[i][j];
        }
        *next_j = predicted * emission[j][bin];
    }

    let sum: f32 = next.iter().sum();
    if sum > 0.0 {
        let scale = 1.0 / sum;
        for (dst, src) in alpha.iter_mut().zip(next.iter()) {
            *dst = src * scale;
        }
    } else {
        *alpha = [1.0, 0.0, 0.0];
    }
}

/// `argmax_j alpha[j]`, ties broken toward the lower (calmer) state.
fn hmm_argmax(alpha: &[f32; HMM_STATE_COUNT]) -> HmmState {
    let mut best = 0;
    for state in 1..HMM_STATE_COUNT {
        if alpha[state] > alpha[best] {
            best = state;
        }
    }
    HmmState::from_index(best)
}

fn relative_elevation(rtt_sample: Duration, baseline: Option<Duration>) -> f32 {
    match baseline {
        Some(baseline) if !baseline.is_zero() =>
            (rtt_sample.as_secs_f32() / baseline.as_secs_f32() - 1.0).max(0.0),
        _ => 0.0,
    }
}

fn dwell_for_transition(
    current: HmmState, pending: HmmState, rtt_sample: Duration,
) -> Duration {
    let rtts = if pending.is_more_elevated_than(current) {
        match pending {
            HmmState::Persistent => HMM_PERSIST_DWELL_RTTS,
            HmmState::Transient => HMM_TRANSIENT_DWELL_RTTS,
            HmmState::Normal => unreachable!("normal is not elevated"),
        }
    } else {
        HMM_CLEAR_DWELL_RTTS
    };

    HMM_MIN_DWELL.max(rtt_sample.mul_f32(rtts))
}

#[derive(Debug)]
pub(super) struct HmmDetector {
    episode: HmmEpisode,
    /// Scaled forward-filter posterior over `[Normal, Transient, Persistent]`.
    alpha: [f32; HMM_STATE_COUNT],
    /// Count of valid RTT samples fed to the HMM detector.
    valid_samples: u32,
    /// Count of warmup samples that carried usable dispersion information.
    warmup_contrib: u32,
    /// Online per-connection estimate of the elevation the connection operates
    /// at above the running-min baseline.
    dispersion: f32,
    /// Detector-private running-min RTT baseline.
    baseline: Option<Duration>,
    /// Raw per-sample argmax state currently being accumulated toward a commit.
    pending_state: HmmState,
    /// Event time of the first sample of the current pending run.
    pending_start_time: Option<Instant>,
    /// Samples observed while the same pending target remains stable.
    pending_samples: u32,
    /// Whether the current non-idle episode has already been counted.
    episode_counted: bool,
}

impl Default for HmmDetector {
    fn default() -> Self {
        Self {
            episode: HmmEpisode::Idle,
            alpha: [1.0, 0.0, 0.0],
            valid_samples: 0,
            warmup_contrib: 0,
            dispersion: 0.0,
            baseline: None,
            pending_state: HmmState::Normal,
            pending_start_time: None,
            pending_samples: 0,
            episode_counted: false,
        }
    }
}

impl HmmDetector {
    /// HMM RTT jump detector step: one scaled forward-filter update mapped onto
    /// the committed episode state.
    pub(super) fn on_rtt_sample(
        &mut self, rtt_sample: Duration, event_time: Instant,
        full_bandwidth_reached: bool,
    ) -> RttJumpUpdate {
        self.valid_samples = self.valid_samples.saturating_add(1);

        let rel = relative_elevation(rtt_sample, self.baseline);

        if self.valid_samples <= HMM_WARMUP_SAMPLES {
            if rel > 0.0 {
                self.warmup_contrib = self.warmup_contrib.saturating_add(1);
                self.dispersion +=
                    (rel - self.dispersion) / self.warmup_contrib as f32;
            }
            self.update_baseline(rtt_sample);
            return RttJumpUpdate::None;
        }

        let scale = self.dispersion.max(HMM_ELEVATION_FLOOR);
        let elevation = (rel - self.dispersion).max(0.0) / scale;
        let bin = hmm_std_bin(elevation, &HMM_STD_BIN_EDGES);
        hmm_forward_step(&mut self.alpha, bin, &HMM_TRANSITION, &HMM_EMISSION);

        let raw = hmm_argmax(&self.alpha);

        if !full_bandwidth_reached {
            self.reset_pending(HmmState::Normal);
            self.update_adaptive_state(rtt_sample, false);
            return RttJumpUpdate::None;
        }

        let committed_state = HmmState::from_episode(self.episode);
        let mut committed_to_normal = false;
        let mut update = RttJumpUpdate::None;

        if raw == committed_state {
            self.reset_pending(committed_state);
        } else {
            if raw != self.pending_state || self.pending_start_time.is_none() {
                self.pending_state = raw;
                self.pending_start_time = Some(event_time);
                self.pending_samples = 1;
            } else {
                self.pending_samples = self.pending_samples.saturating_add(1);
            }

            let episode_start = self.pending_start_time.unwrap_or(event_time);
            let dwell = dwell_for_transition(committed_state, raw, rtt_sample);
            let samples_ok = raw != HmmState::Persistent ||
                self.pending_samples >= HMM_PERSIST_CONFIRM_SAMPLES;
            let time_ok =
                event_time.saturating_duration_since(episode_start) >= dwell;

            if samples_ok && time_ok {
                match raw {
                    HmmState::Persistent => {
                        if !self.episode_counted {
                            self.episode_counted = true;
                            update = RttJumpUpdate::PersistentConfirmed {
                                episode_start_time: episode_start,
                            };
                        }
                        self.episode = raw.to_episode();
                    },
                    HmmState::Transient => {
                        self.episode = raw.to_episode();
                    },
                    HmmState::Normal => {
                        committed_to_normal = true;
                        self.episode_counted = false;
                        self.episode = raw.to_episode();
                    },
                }
                self.reset_pending(raw);
            }
        }

        self.update_adaptive_state(rtt_sample, committed_to_normal);
        update
    }

    fn reset_pending(&mut self, state: HmmState) {
        self.pending_state = state;
        self.pending_start_time = None;
        self.pending_samples = 0;
    }

    fn update_adaptive_state(
        &mut self, rtt_sample: Duration, committed_to_normal: bool,
    ) {
        if committed_to_normal {
            self.baseline = Some(rtt_sample);
        } else {
            self.update_baseline(rtt_sample);
        }

        let rel = relative_elevation(rtt_sample, self.baseline);

        if matches!(self.episode, HmmEpisode::Idle) &&
            self.pending_start_time.is_none()
        {
            self.dispersion += HMM_DISP_EWMA_ALPHA * (rel - self.dispersion);
        }
    }

    fn update_baseline(&mut self, rtt_sample: Duration) {
        self.baseline =
            Some(self.baseline.map_or(rtt_sample, |min| min.min(rtt_sample)));
    }

    #[cfg(test)]
    pub(super) fn is_rtt_jump_active(&self) -> bool {
        !matches!(self.episode, HmmEpisode::Idle)
    }

    #[cfg(test)]
    pub(super) fn is_rtt_jump_persistent(&self) -> bool {
        matches!(self.episode, HmmEpisode::Persistent)
    }
}

#[cfg(test)]
#[path = "hmm_tests.rs"]
mod tests;
