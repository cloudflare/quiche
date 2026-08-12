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

use super::super::RttJumpDetector;
use super::*;

const RTT: Duration = Duration::from_millis(50);
const RTT_3X: Duration = Duration::from_millis(150);
const RTT_JUMP: Duration = Duration::from_millis(151);
const LOW_RTT: Duration = Duration::from_millis(10);
const HIGH_RTT: Duration = Duration::from_millis(500);
const HIGH_RTT_JUMP: Duration = Duration::from_millis(1501);

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

fn global_min_detector() -> RttJumpDetector {
    RttJumpDetector::new(BbrRttJumpDetector::GlobalMin)
}

#[test]
fn global_min_detector_uses_strict_3x_threshold() {
    let base = Instant::now();

    let mut at_edge = global_min_detector();
    sample(&mut at_edge, base, ms(10), RTT);
    sample(&mut at_edge, base, ms(20), RTT_3X);
    assert!(!at_edge.is_rtt_jump_active());

    let mut just_above = global_min_detector();
    sample(&mut just_above, base, ms(10), RTT);
    sample(&mut just_above, base, ms(20), RTT_JUMP);
    assert!(just_above.is_rtt_jump_active());
}

#[test]
fn global_min_detector_clears_active_at_or_below_threshold() {
    let base = Instant::now();

    let mut at_edge = global_min_detector();
    sample(&mut at_edge, base, ms(10), RTT);
    sample(&mut at_edge, base, ms(20), RTT_JUMP);
    assert!(at_edge.is_rtt_jump_active());
    sample(&mut at_edge, base, ms(30), RTT_3X);
    assert!(!at_edge.is_rtt_jump_active());

    let mut below_edge = global_min_detector();
    sample(&mut below_edge, base, ms(10), RTT);
    sample(&mut below_edge, base, ms(20), RTT_JUMP);
    assert!(below_edge.is_rtt_jump_active());
    sample(&mut below_edge, base, ms(30), RTT);
    assert!(!below_edge.is_rtt_jump_active());
}

#[test]
fn global_min_detector_sustained_step_becomes_persistent() {
    let mut detector = global_min_detector();
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
    let mut detector = global_min_detector();
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
    let mut detector = global_min_detector();
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
    let mut detector = global_min_detector();
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
    let mut detector = global_min_detector();
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
    let mut detector = global_min_detector();
    let base = Instant::now();

    sample(&mut detector, base, ms(10), HIGH_RTT);
    sample(&mut detector, base, ms(20), HIGH_RTT_JUMP);
    sample(&mut detector, base, ms(100), HIGH_RTT_JUMP);
    sample(&mut detector, base, ms(200), HIGH_RTT_JUMP);

    assert!(detector.is_rtt_jump_active());
    assert!(!detector.is_rtt_jump_persistent());

    sample(&mut detector, base, ms(1520), HIGH_RTT_JUMP);
    assert!(detector.is_rtt_jump_persistent());
}

#[test]
fn global_min_detector_handles_low_rtt_dwell() {
    let mut detector = global_min_detector();
    let base = Instant::now();
    let jump = LOW_RTT.mul_f32(GLOBAL_MIN_JUMP_THRESHOLD) + ms(1);

    sample(&mut detector, base, ms(10), LOW_RTT);
    sample(&mut detector, base, ms(20), jump);
    sample(&mut detector, base, ms(30), jump);
    assert!(!detector.is_rtt_jump_persistent());

    sample(&mut detector, base, ms(50), jump);
    assert!(detector.is_rtt_jump_persistent());
}
