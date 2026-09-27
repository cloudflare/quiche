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

use super::super::ActiveRttJumpDetector;
use super::super::RttJumpDetector;
use super::*;

const RTT: Duration = Duration::from_millis(50);
const RTT_2X: Duration = Duration::from_millis(100);
const RTT_3X: Duration = Duration::from_millis(150);
const HIGH_RTT: Duration = Duration::from_millis(500);
const HIGH_RTT_3X: Duration = Duration::from_millis(1500);
const LOW_RTT: Duration = Duration::from_millis(10);

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
    detector.on_rtt_sample(rtt, base + offset, full_bandwidth_reached);
}

fn hmm_detector() -> RttJumpDetector {
    RttJumpDetector::new(BbrRttJumpDetector::Hmm)
}

fn hmm_build_baseline(
    detector: &mut RttJumpDetector, count: u64, base: Instant, rtt: Duration,
) {
    for pkt in 1..=count {
        sample(detector, base, ms(pkt * 10), rtt);
    }
    assert!(!detector.is_rtt_jump_active());
}

fn prewarmed_hmm_with_pending(
    episode: HmmEpisode, baseline: Duration, alpha: [f32; HMM_STATE_COUNT],
    pending_state: HmmState, pending_start_time: Instant, pending_samples: u32,
    episode_counted: bool,
) -> HmmDetector {
    HmmDetector {
        episode,
        valid_samples: HMM_WARMUP_SAMPLES + 1,
        baseline: Some(baseline),
        dispersion: HMM_ELEVATION_FLOOR,
        alpha,
        pending_state,
        pending_start_time: Some(pending_start_time),
        pending_samples,
        episode_counted,
        ..HmmDetector::default()
    }
}

fn detector_with_hmm(
    hmm: HmmDetector, persistent_jump_count: u64,
) -> RttJumpDetector {
    RttJumpDetector {
        persistent_jump_count,
        last_persistent_jump_time: None,
        detector: ActiveRttJumpDetector::Hmm(hmm),
    }
}

#[test]
fn hmm_no_jump_on_stable_rtt() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    for pkt in 1..21u64 {
        sample(&mut detector, base, ms(pkt * 10), RTT);
    }

    assert!(!detector.is_rtt_jump_active());
    assert!(!detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 0);
    assert_eq!(detector.last_persistent_jump_time(), None);
}

#[test]
fn hmm_warmup_suppresses_cold_start_spike() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    // Models early self-queueing before the detector has enough normal
    // samples to estimate the connection's operating elevation.
    sample(&mut detector, base, ms(0), RTT);
    sample(&mut detector, base, ms(10), RTT_3X * 2);
    sample(&mut detector, base, ms(20), RTT_3X * 2);

    assert!(!detector.is_rtt_jump_active());
    assert_eq!(detector.rtt_persistent_jump_count(), 0);
}

#[test]
fn hmm_single_spike_does_not_commit() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    hmm_build_baseline(&mut detector, 12, base, RTT);

    sample(&mut detector, base, ms(130), RTT_3X);
    assert!(!detector.is_rtt_jump_active());
    assert!(!detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 0);
    assert_eq!(detector.last_persistent_jump_time(), None);

    sample(&mut detector, base, ms(140), RTT);
    assert!(!detector.is_rtt_jump_active());
}

#[test]
fn hmm_sustained_step_becomes_persistent() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    hmm_build_baseline(&mut detector, 12, base, RTT);

    let mut offset = 200u64;
    for _ in 13u64..27 {
        sample(&mut detector, base, ms(offset), RTT_3X);
        offset += 100;
    }

    assert!(detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 1);
    assert!(detector.last_persistent_jump_time().is_some());
}

#[test]
fn hmm_persistent_requires_confirming_samples() {
    let base = Instant::now();
    let hmm = prewarmed_hmm_with_pending(
        HmmEpisode::Active,
        RTT,
        [0.0, 0.0, 1.0],
        HmmState::Persistent,
        base,
        1,
        false,
    );
    let mut detector = detector_with_hmm(hmm, 0);

    sample(&mut detector, base, ms(800), RTT_3X);

    assert!(!detector.is_rtt_jump_persistent());

    sample(&mut detector, base, ms(900), RTT_3X);
    assert!(detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 1);
}

#[test]
fn hmm_persistent_requires_rtt_scaled_dwell() {
    let base = Instant::now();
    let hmm = prewarmed_hmm_with_pending(
        HmmEpisode::Active,
        HIGH_RTT,
        [0.0, 0.0, 1.0],
        HmmState::Persistent,
        base,
        HMM_PERSIST_CONFIRM_SAMPLES,
        false,
    );
    let mut detector = detector_with_hmm(hmm, 0);

    sample(&mut detector, base, ms(7000), HIGH_RTT_3X);
    assert!(!detector.is_rtt_jump_persistent());

    sample(&mut detector, base, ms(7600), HIGH_RTT_3X);
    assert!(detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 1);
}

#[test]
fn hmm_transient_high_rtt_waits_for_rtt_scaled_dwell() {
    let base = Instant::now();
    let mut early = prewarmed_hmm_with_pending(
        HmmEpisode::Idle,
        HIGH_RTT,
        [0.0, 1.0, 0.0],
        HmmState::Transient,
        base,
        1,
        false,
    );

    early.on_rtt_sample(HIGH_RTT_3X, base + ms(80), true);
    assert!(!early.is_rtt_jump_active());

    let mut late = prewarmed_hmm_with_pending(
        HmmEpisode::Idle,
        HIGH_RTT,
        [0.0, 1.0, 0.0],
        HmmState::Transient,
        base,
        1,
        false,
    );

    late.on_rtt_sample(HIGH_RTT_3X, base + HIGH_RTT_3X, true);
    assert!(late.is_rtt_jump_active());
}

#[test]
fn hmm_clear_high_rtt_waits_for_rtt_scaled_dwell() {
    let base = Instant::now();
    let mut detector = prewarmed_hmm_with_pending(
        HmmEpisode::Persistent,
        HIGH_RTT,
        [1.0, 0.0, 0.0],
        HmmState::Normal,
        base,
        1,
        true,
    );

    detector.on_rtt_sample(HIGH_RTT, base + ms(80), true);
    assert!(detector.is_rtt_jump_persistent());

    detector.on_rtt_sample(HIGH_RTT, base + HIGH_RTT, true);
    assert!(!detector.is_rtt_jump_active());
}

#[test]
fn hmm_clear_rebases_dispersion_to_new_normal() {
    let base = Instant::now();
    let mut detector = prewarmed_hmm_with_pending(
        HmmEpisode::Persistent,
        RTT,
        [1.0, 0.0, 0.0],
        HmmState::Normal,
        base,
        1,
        true,
    );
    detector.dispersion = 0.8;
    let initial_dispersion = detector.dispersion;

    detector.on_rtt_sample(RTT_2X, base + RTT_2X, true);

    assert!(!detector.is_rtt_jump_active());
    assert_eq!(detector.baseline, Some(RTT_2X));
    assert!(detector.dispersion < initial_dispersion);
}

#[test]
fn hmm_low_rtt_still_respects_min_dwell() {
    assert_eq!(
        dwell_for_transition(HmmState::Normal, HmmState::Transient, LOW_RTT),
        HMM_MIN_DWELL
    );
}

#[test]
fn hmm_reentering_persistent_same_episode_does_not_recount() {
    let base = Instant::now();
    let hmm = prewarmed_hmm_with_pending(
        HmmEpisode::Active,
        RTT,
        [0.0, 0.0, 1.0],
        HmmState::Persistent,
        base,
        HMM_PERSIST_CONFIRM_SAMPLES,
        true,
    );
    let mut detector = detector_with_hmm(hmm, 1);

    sample(&mut detector, base, ms(1000), RTT_3X);

    assert!(detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 1);
}

#[test]
fn hmm_clear_allows_later_jump_to_recount() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    hmm_build_baseline(&mut detector, 12, base, RTT);

    let mut offset = 200u64;
    while !detector.is_rtt_jump_persistent() {
        sample(&mut detector, base, ms(offset), RTT_3X);
        offset += 100;
        assert!(offset < 5000, "first persistent jump was never confirmed");
    }
    assert_eq!(detector.rtt_persistent_jump_count(), 1);

    while detector.is_rtt_jump_active() {
        sample(&mut detector, base, ms(offset), RTT);
        offset += 100;
        assert!(offset < 8000, "persistent jump was never cleared");
    }
    assert_eq!(detector.rtt_persistent_jump_count(), 1);

    while !detector.is_rtt_jump_persistent() {
        sample(&mut detector, base, ms(offset), RTT_3X);
        offset += 100;
        assert!(offset < 13000, "second persistent jump was never confirmed");
    }
    assert_eq!(detector.rtt_persistent_jump_count(), 2);
}

#[test]
fn hmm_sustained_plateau_does_not_clear() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    hmm_build_baseline(&mut detector, 12, base, RTT);

    let mut offset = 200u64;
    while !detector.is_rtt_jump_persistent() {
        sample(&mut detector, base, ms(offset), RTT_3X);
        offset += 100;
        assert!(offset < 5000, "persistent jump was never confirmed");
    }

    for _ in 0..100u64 {
        sample(&mut detector, base, ms(offset), RTT_3X);
        assert!(
            detector.is_rtt_jump_persistent(),
            "sustained plateau cleared at t={offset}ms"
        );
        offset += 100;
    }
    assert_eq!(detector.rtt_persistent_jump_count(), 1);
}

#[test]
fn hmm_self_calibration_absorbs_jump_within_link_noise() {
    let base = Instant::now();

    let mut quiet = hmm_detector();
    hmm_build_baseline(&mut quiet, 8, base, RTT);
    let mut fired = false;
    for pkt in 9..109u64 {
        sample(&mut quiet, base, ms(pkt * 10), RTT_2X);
        fired |= quiet.is_rtt_jump_active();
    }
    assert!(fired, "quiet link should flag a sustained 2x step");

    let mut noisy = hmm_detector();
    let warmup = [50u64, 100, 100, 100, 100, 100, 100, 100];
    for (i, &rtt) in warmup.iter().enumerate() {
        let pkt = i as u64 + 1;
        sample(&mut noisy, base, ms(pkt * 10), ms(rtt));
    }
    let mut fired = false;
    for pkt in 9..109u64 {
        sample(&mut noisy, base, ms(pkt * 10), RTT_2X);
        fired |= noisy.is_rtt_jump_active();
    }
    assert!(!fired, "noisy link should absorb the same 2x step");
}

#[test]
fn hmm_detection_is_scale_invariant() {
    fn fires_for_base(base_rtt: Duration) -> bool {
        let mut detector = hmm_detector();
        let base = Instant::now();
        hmm_build_baseline(&mut detector, 8, base, base_rtt);
        let mut fired = false;
        for pkt in 9..31u64 {
            sample(&mut detector, base, base_rtt * pkt as u32, base_rtt * 2);
            fired |= detector.is_rtt_jump_persistent();
        }
        fired
    }

    assert!(fires_for_base(RTT));
    assert_eq!(fires_for_base(RTT), fires_for_base(HIGH_RTT));
}

#[test]
fn hmm_startup_grace_suppresses_commits() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    for pkt in 1..9u64 {
        sample_with_full_bandwidth(&mut detector, base, ms(pkt * 10), RTT, false);
    }

    for pkt in 9..15u64 {
        sample_with_full_bandwidth(
            &mut detector,
            base,
            ms(pkt * 10),
            RTT_3X,
            false,
        );
        assert!(
            !detector.is_rtt_jump_active(),
            "startup grace must suppress commits (sample {pkt})"
        );
    }
    assert!(!detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 0);
    assert_eq!(detector.last_persistent_jump_time(), None);

    let mut offset = 300u64;
    let mut fired = false;
    for _ in 15u64..27 {
        sample(&mut detector, base, ms(offset), RTT_3X);
        fired |= detector.is_rtt_jump_active();
        offset += 100;
    }
    assert!(fired, "detection must resume after leaving Startup");
}

#[test]
fn hmm_startup_resets_pending_transition_before_detection_resumes() {
    let mut detector = hmm_detector();
    let base = Instant::now();

    for pkt in 1..9u64 {
        sample_with_full_bandwidth(&mut detector, base, ms(pkt * 10), RTT, false);
    }

    for pkt in 9..21u64 {
        sample_with_full_bandwidth(
            &mut detector,
            base,
            ms(pkt * 100),
            RTT_3X,
            false,
        );
    }

    sample(&mut detector, base, ms(2100), RTT_3X);
    assert!(!detector.is_rtt_jump_persistent());
    assert_eq!(detector.rtt_persistent_jump_count(), 0);
}

#[test]
fn hmm_forward_filter_is_deterministic_for_known_bins() {
    let mut alpha = [1.0, 0.0, 0.0];

    hmm_forward_step(&mut alpha, 0, &HMM_TRANSITION, &HMM_EMISSION);
    assert_eq!(hmm_argmax(&alpha), HmmState::Normal);

    for _ in 0..8 {
        hmm_forward_step(&mut alpha, 2, &HMM_TRANSITION, &HMM_EMISSION);
    }

    assert_eq!(hmm_argmax(&alpha), HmmState::Persistent);
}
