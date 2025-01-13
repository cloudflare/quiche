// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright (C) 2023, Cloudflare, Inc.
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

mod bandwidth_sampler;
mod windowed_filter;

use std::time::Duration;
use std::time::Instant;

pub use bandwidth_sampler::BandwidthSampler;
pub use bandwidth_sampler::SendTimeState;

use self::windowed_filter::WindowedFilter;

use super::bandwidth::Bandwidth;
use super::Acked;
use super::CongestionControl;
use super::Lost;
use super::RttStats;

/// The time after which the current min_rtt value expires.
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
/// The minimum time the connection can spend in PROBE_RTT mode.
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);

/// The cycle of gains used during the PROBE_BW stage.
const PACING_GAIN: [f32; 8] = [1.25, 0.75, 1., 1., 1., 1., 1., 1.];
/// The length of the gain cycle.
const GAIN_CYCLE_LENGTH: usize = PACING_GAIN.len();
/// The size of the bandwidth filter window, in round-trips.
const BANDWIDTH_WINDOW_SIZE: usize = GAIN_CYCLE_LENGTH + 2;

/// If the bandwidth does not increase by the factor of
/// [`STARTUP_GROWTH_TARGET`]
/// within [`ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP`] rounds, the
/// connection will exit the STARTUP mode.
const STARTUP_GROWTH_TARGET: f32 = 1.25;
const ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: usize = 3;

/// The maximum packet size of any QUIC packet over IPv6, based on ethernet's
/// max size, minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds
/// an additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
/// max packet size is 1500 bytes,  1500 - 48 = 1452.
const MAX_V6_PACKET_SIZE: usize = 1452;
/// The maximum outgoing packet size allowed.
const MAX_OUTGOING_PACKET_SIZE: usize = MAX_V6_PACKET_SIZE;
const DEFAULT_MIN_CONGESTION_WINDOW: usize = MAX_OUTGOING_PACKET_SIZE * 4;

// The gain used for the STARTUP, equal to 2/ln(2).
const DEFAULT_HIGH_GAIN: f32 = 2.885;

const QUIC_BBR2_DEFAULT_STARTUP_FULL_LOSS_COUNT: usize = 8;
const QUIC_BBR2_DEFAULT_LOSS_THRESHOLD: f64 = 0.02;
const QUIC_BBR_CWND_GAIN: f32 = 2.;

static mut RNG: Option<ring::rand::SystemRandom> = None;
static RNG_INIT: std::sync::Once = std::sync::Once::new();

fn get_tiny_rand() -> u8 {
    use ring::rand::SecureRandom;
    let mut r = 0u8;
    RNG_INIT.call_once(|| unsafe {
        RNG = Some(ring::rand::SystemRandom::new());
    });
    unsafe {
        // Only mutable access is synchronized above
        #[allow(static_mut_refs)]
        RNG.as_ref()
            .unwrap()
            .fill(std::slice::from_mut(&mut r))
            .unwrap();
    }
    r
}

#[derive(Debug)]
pub(crate) struct BBR {
    /// The maximum allowed number of bytes in flight.
    congestion_window: usize,
    /// The initial value of the [`congestion_window`].
    initial_congestion_window: usize,

    recovery_window: usize,
    /// The smallest value the [`congestion_window`] can achieve.
    min_congestion_window: usize,
    /// The largest value the [`congestion_window`] can achieve.
    max_congestion_window: usize,
    mode: Mode,
    recovery_state: RecoveryState,

    last_sent_packet: u64,
    exiting_quiescence: bool,

    /// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
    /// that the time is yet unknown as the number of packets in flight has not
    /// reached the required value.
    exit_probe_rtt_at: Option<Instant>,
    /// Indicates whether a round-trip has passed since PROBE_RTT became active.
    probe_rtt_round_passed: bool,

    /// Indicates whether the connection has reached the full bandwidth mode.
    is_at_full_bandwidth: bool,

    /// Number of rounds during which there was no significant bandwidth
    /// increase.
    rounds_without_bandwidth_gain: usize,
    /// The bandwidth compared to which the increase is measured.
    bandwidth_at_last_round: Bandwidth,

    /// Indicates whether the most recent bandwidth sample was marked as
    /// app-limited.
    last_sample_is_app_limited: bool,
    /// Indicates whether any non app-limited samples have been recorded.
    has_non_app_limited_sample: bool,

    // Receiving acknowledgement of a packet after [`end_recovery_at`] will cause
    // BBR to exit the recovery mode.  A value above zero indicates at least one
    // loss has been detected, so it must not be set back to zero.
    end_recovery_at: Option<u64>,

    /// Acknowledgement of any packet after [`current_round_trip_end`] will
    /// cause the round trip counter to advance.
    current_round_trip_end: Option<u64>,

    /// Number of congestion events with some losses, in the current round.
    num_loss_events_in_round: usize,

    /// Number of total bytes lost in the current round.
    bytes_lost_in_round: usize,

    /// The number of the round trips that have occurred during the connection.
    round_trip_count: usize,

    /// Minimum RTT estimate.  Automatically expires within 10 seconds (and
    /// triggers PROBE_RTT mode) if no new value is sampled during that period.
    min_rtt: Option<Duration>,

    /// The time at which the current value of [`min_rtt`] was assigned.
    min_rtt_timestamp: Option<Instant>,

    /// The pacing gain applied during the STARTUP phase.
    high_gain: f32,

    /// The CWND gain applied during the STARTUP phase.
    high_cwnd_gain: f32,
    // The pacing gain applied during the DRAIN phase.
    drain_gain: f32,
    /// The current pacing rate of the connection.
    pacing_rate: Bandwidth,

    /// The gain currently applied to the pacing rate.
    pacing_gain: f32,
    /// The gain currently applied to the congestion window.
    congestion_window_gain: f32,
    /// The gain used for the congestion window during PROBE_BW.  Latched from
    /// quic_bbr_cwnd_gain flag.
    congestion_window_gain_constant: f32,
    /// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
    num_startup_rtts: usize,
    /// Number of round-trips in PROBE_BW mode, used for determining the current
    /// pacing gain cycle.
    cycle_current_offset: usize,
    /// The time at which the last pacing gain cycle was started.
    last_cycle_start: Option<Instant>,

    /// When true, add the most recent ack aggregation measurement during
    /// STARTUP.
    enable_ack_aggregation_during_startup: bool,
    /// When true, expire the windowed ack aggregation values in STARTUP when
    /// bandwidth increases more than 25%.
    expire_ack_aggregation_in_startup: bool,

    /// If true, will not exit low gain mode until bytes_in_flight drops below
    /// BDP or it's time for high gain mode.
    drain_to_target: bool,

    /// If true, slow down pacing rate in STARTUP when overshooting is detected.
    detect_overshooting: bool,
    /// Bytes lost while [`detect_overshooting`] is true.
    bytes_lost_while_detecting_overshooting: usize,

    /// Slow down pacing rate if [`bytes_lost_while_detecting_overshooting`] *
    /// [`bytes_lost_multiplier_while_detecting_overshooting`] > IW.
    bytes_lost_multiplier_while_detecting_overshooting: usize,

    /// When overshooting is detected, do not drop [`pacing_rate`] below this
    /// value / min_rtt.
    cwnd_to_calculate_min_pacing_rate: usize,

    sampler: BandwidthSampler,
    max_bandwidth: WindowedFilter<Bandwidth, usize, usize>,

    mss: usize,
}

#[derive(Debug, PartialEq)]
enum Mode {
    /// Startup phase of the connection.
    Startup,
    /// After achieving the highest possible bandwidth during the startup, lower
    /// the pacing rate in order to drain the queue.
    Drain,
    /// Cruising mode.
    ProbeBw,
    /// Temporarily slow down sending in order to empty the buffer and measure
    /// the real minimum RTT.
    ProbeRtt,
}

#[derive(Debug, PartialEq)]
enum RecoveryState {
    /// Do not limit.
    NotInRecovery,
    /// Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    /// Allow two extra outstanding bytes for each byte acknowledged (slow
    /// start).
    Growth,
}

impl BBR {
    pub(crate) fn new(
        initial_congestion_window: usize, max_congestion_window: usize,
        max_segment_size: usize,
    ) -> Self {
        BBR {
            congestion_window: initial_congestion_window * max_segment_size,
            initial_congestion_window: initial_congestion_window *
                max_segment_size,
            recovery_window: max_congestion_window * max_segment_size,
            min_congestion_window: DEFAULT_MIN_CONGESTION_WINDOW,
            max_congestion_window: max_congestion_window * max_segment_size,
            cwnd_to_calculate_min_pacing_rate: initial_congestion_window *
                max_segment_size,
            mode: Mode::Startup,
            recovery_state: RecoveryState::NotInRecovery,
            last_sent_packet: 0,
            exiting_quiescence: false,
            exit_probe_rtt_at: None,
            probe_rtt_round_passed: false,
            is_at_full_bandwidth: false,
            rounds_without_bandwidth_gain: 0,
            bandwidth_at_last_round: Bandwidth::zero(),
            last_sample_is_app_limited: false,
            has_non_app_limited_sample: false,
            end_recovery_at: None,
            current_round_trip_end: None,
            num_loss_events_in_round: 0,
            bytes_lost_in_round: 0,
            round_trip_count: 0,
            min_rtt: None,
            min_rtt_timestamp: None,
            high_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DEFAULT_HIGH_GAIN,
            drain_gain: 1. / DEFAULT_HIGH_GAIN,
            pacing_rate: Bandwidth::zero(),
            pacing_gain: 1.,
            congestion_window_gain: 1.,
            congestion_window_gain_constant: QUIC_BBR_CWND_GAIN,
            num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            cycle_current_offset: 0,
            last_cycle_start: None,
            enable_ack_aggregation_during_startup: false,
            expire_ack_aggregation_in_startup: false,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_while_detecting_overshooting: 0,
            bytes_lost_multiplier_while_detecting_overshooting: 2,
            sampler: BandwidthSampler::new(BANDWIDTH_WINDOW_SIZE, true),
            max_bandwidth: WindowedFilter::new(BANDWIDTH_WINDOW_SIZE),
            mss: max_segment_size,
        }
    }

    fn probe_rtt_congestion_window(&self) -> usize {
        self.min_congestion_window
    }

    fn update_round_trip_counter(&mut self, last_acked_packet: u64) -> bool {
        if let Some(rt_end) = self.current_round_trip_end {
            if last_acked_packet <= rt_end {
                return false;
            }
        }

        self.round_trip_count += 1;
        self.current_round_trip_end = Some(self.last_sent_packet);
        true
    }

    fn update_recovery_state(
        &mut self, last_acked_packet: u64, has_losses: bool, is_round_start: bool,
    ) {
        // Disable recovery in startup, if loss-based exit is enabled.
        if !self.is_at_full_bandwidth {
            return;
        }

        // Exit recovery when there are no losses for a round.
        if has_losses {
            self.end_recovery_at = Some(self.last_sent_packet);
        }

        match self.recovery_state {
            RecoveryState::NotInRecovery => {
                // Enter conservation on the first loss.
                if has_losses {
                    self.recovery_state = RecoveryState::Conservation;
                    // This will cause the `recovery_window` to be set to the
                    // correct value in [`calculate_recovery_window`].
                    self.recovery_window = 0;
                    // Since the conservation phase is meant to be lasting for a
                    // whole round, extend the current round
                    // as if it were started right now.
                    self.current_round_trip_end = Some(self.last_sent_packet);
                }
            },
            RecoveryState::Conservation | RecoveryState::Growth => {
                if self.recovery_state == RecoveryState::Conservation &&
                    is_round_start
                {
                    self.recovery_state = RecoveryState::Growth;
                }

                if !has_losses &&
                    self.end_recovery_at
                        .map(|er| last_acked_packet > er)
                        .unwrap_or(false)
                {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            },
        }
    }

    fn maybe_update_min_rtt(
        &mut self, now: Instant, sample_min_rtt: Duration,
    ) -> bool {
        // Do not expire min_rtt if none was ever available.
        let min_rtt_expired = self
            .min_rtt_timestamp
            .map(|min_rtt| now > min_rtt + MIN_RTT_EXPIRY)
            .unwrap_or(false);

        if min_rtt_expired ||
            Some(sample_min_rtt) < self.min_rtt ||
            self.min_rtt.is_none()
        {
            self.min_rtt = Some(sample_min_rtt);
            self.min_rtt_timestamp = Some(now);
        }
        min_rtt_expired
    }

    fn update_gain_cycle_phase(
        &mut self, now: Instant, prior_in_flight: usize, has_losses: bool,
        rtt_stats: &RttStats, bytes_in_flight: usize,
    ) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|l| now.duration_since(l) > *rtt_stats.min_rtt)
            .unwrap_or(true);

        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not
        // able to hold that much.
        if self.pacing_gain > 1.0 &&
            !has_losses &&
            prior_in_flight <
                self.get_target_congestion_window(
                    self.pacing_gain,
                    rtt_stats,
                )
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the
        // extra queue which could have been incurred by probing prior to
        // it.  If the number of bytes in flight falls down to the
        // estimated BDP value earlier, conclude that the queue has been
        // successfully drained and exit this cycle early.
        if self.pacing_gain < 1.0 &&
            bytes_in_flight <= self.get_target_congestion_window(1., rtt_stats)
        {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.cycle_current_offset =
                (self.cycle_current_offset + 1) % GAIN_CYCLE_LENGTH;

            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.
            // Low gain mode will be exited immediately when the target BDP is
            // achieved.
            if self.drain_to_target &&
                self.pacing_gain < 1. &&
                PACING_GAIN[self.cycle_current_offset] == 1. &&
                bytes_in_flight >
                    self.get_target_congestion_window(1., rtt_stats)
            {
                return;
            }
            self.pacing_gain = PACING_GAIN[self.cycle_current_offset];
        }
    }

    fn get_target_congestion_window(
        &self, gain: f32, rtt_stats: &RttStats,
    ) -> usize {
        let bdp = self
            .bandwidth_estimate(rtt_stats)
            .to_bytes_per_period(*rtt_stats.min_rtt);

        let mut congestion_window = (gain * (bdp as f32)) as usize;

        // BDP estimate will be zero if no bandwidth samples are available yet.
        if congestion_window == 0 {
            congestion_window =
                (gain * (self.initial_congestion_window as f32)) as usize;
        }

        congestion_window.max(self.min_congestion_window)
    }

    fn check_if_full_bandwidth_reached(
        &mut self, last_packet_send_state: &SendTimeState, rtt_stats: &RttStats,
    ) {
        if self.last_sample_is_app_limited {
            return;
        }
        let target = self.bandwidth_at_last_round * STARTUP_GROWTH_TARGET;
        let bandwidth_estimate = self.bandwidth_estimate(rtt_stats);
        if bandwidth_estimate > target {
            self.bandwidth_at_last_round = bandwidth_estimate;
            self.rounds_without_bandwidth_gain = 0;
            if self.expire_ack_aggregation_in_startup {
                // Expire old excess delivery measurements now that bandwidth
                // increased.
                self.sampler
                    .reset_max_ack_height_tracker(0, self.round_trip_count);
            }
            return;
        }

        self.rounds_without_bandwidth_gain += 1;
        if (self.rounds_without_bandwidth_gain >= self.num_startup_rtts) ||
            self.should_exit_startup_due_to_loss(last_packet_send_state)
        {
            self.is_at_full_bandwidth = true;
        }
    }

    fn calculate_pacing_rate(&mut self, bytes_lost: usize, rtt_stats: &RttStats) {
        let bandwidth_estimate = self.bandwidth_estimate(rtt_stats);
        let min_rtt = *rtt_stats.min_rtt;

        if bandwidth_estimate == Bandwidth::zero() {
            return;
        }

        let target_rate = bandwidth_estimate * self.pacing_gain;

        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements
        // are available.
        if self.pacing_rate == Bandwidth::zero() && !min_rtt.is_zero() {
            self.pacing_rate = Bandwidth::from_bytes_and_time_delta(
                self.initial_congestion_window,
                min_rtt,
            );
            return;
        }

        if self.detect_overshooting {
            self.bytes_lost_while_detecting_overshooting += bytes_lost;
            // Check for overshooting with network parameters adjusted when pacing
            // rate
            // > target_rate and loss has been detected.
            if self.pacing_rate > target_rate &&
                self.bytes_lost_while_detecting_overshooting > 0 &&
                (self.has_non_app_limited_sample ||
                    self.bytes_lost_while_detecting_overshooting *
                        self.bytes_lost_multiplier_while_detecting_overshooting >
                        self.initial_congestion_window)
            {
                // We are fairly sure overshoot happens if 1) there is at
                // least one non app-limited bw sample or
                // 2) half of IW gets lost. Slow pacing
                // rate.
                self.pacing_rate =
                    target_rate.max(Bandwidth::from_bytes_and_time_delta(
                        self.cwnd_to_calculate_min_pacing_rate,
                        min_rtt,
                    ));

                self.bytes_lost_while_detecting_overshooting = 0;
                self.detect_overshooting = false;
            }
        }

        // Do not decrease the pacing rate during startup.
        self.pacing_rate = self.pacing_rate.max(target_rate);
    }

    fn calculate_congestion_window(
        &mut self, bytes_acked: usize, excess_acked: usize, rtt_stats: &RttStats,
    ) {
        if self.mode == Mode::ProbeRtt {
            return;
        }

        let mut target_window = self
            .get_target_congestion_window(self.congestion_window_gain, rtt_stats);

        // println!("target window {} {} {:?}" , target_window,
        // self.congestion_window_gain,*rtt_stats.min_rtt );
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window += self.sampler.max_ack_height().unwrap();
        } else if self.enable_ack_aggregation_during_startup {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max
            // filter.
            target_window += excess_acked;
        }

        // Instead of immediately setting the target CWND as the new one, BBR
        // grows the CWND towards |target_window| by only increasing it
        // |bytes_acked| at a time.
        if self.is_at_full_bandwidth {
            self.congestion_window =
                target_window.min(self.congestion_window + bytes_acked);
        } else if self.congestion_window < target_window ||
            self.sampler.total_bytes_acked() < self.initial_congestion_window
        {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.congestion_window += bytes_acked;
        }

        // Enforce the limits on the congestion window.
        self.congestion_window = self
            .congestion_window
            .max(self.min_congestion_window)
            .min(self.max_congestion_window);
    }

    fn calculate_recovery_window(
        &mut self, bytes_acked: usize, bytes_lost: usize, bytes_in_flight: usize,
    ) {
        if self.recovery_state == RecoveryState::NotInRecovery {
            return;
        }

        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = bytes_in_flight + bytes_acked;
            self.recovery_window =
                self.recovery_window.max(self.min_congestion_window);
            return;
        }

        // Remove losses from the recovery window, while accounting for a
        // potential integer underflow.
        self.recovery_window = if self.recovery_window >= bytes_lost {
            self.recovery_window - bytes_lost
        } else {
            self.mss
        };

        // In CONSERVATION mode, just subtracting losses is sufficient.  In
        // GROWTH, release additional |bytes_acked| to achieve a
        // slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window += bytes_acked;
        }

        // Always allow sending at least |bytes_acked| in response.
        self.recovery_window = self
            .recovery_window
            .max(bytes_in_flight + bytes_acked)
            .max(self.min_congestion_window);
    }

    fn should_exit_startup_due_to_loss(
        &mut self, last_packet_send_state: &SendTimeState,
    ) -> bool {
        if self.num_loss_events_in_round <
            QUIC_BBR2_DEFAULT_STARTUP_FULL_LOSS_COUNT ||
            !last_packet_send_state.is_valid
        {
            return false;
        }

        let inflight_at_send = last_packet_send_state.bytes_in_flight;

        if inflight_at_send > 0 && self.bytes_lost_in_round > 0 {
            if self.bytes_lost_in_round >
                (inflight_at_send as f64 * QUIC_BBR2_DEFAULT_LOSS_THRESHOLD)
                    as usize
            {
                return true;
            }
            return false;
        }

        false
    }

    fn maybe_exit_startup_or_drain(
        &mut self, now: Instant, rtt_stats: &RttStats, bytes_in_flight: usize,
    ) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.congestion_window_gain = self.high_cwnd_gain;
        }

        if self.mode == Mode::Drain &&
            bytes_in_flight <= self.get_target_congestion_window(1., rtt_stats)
        {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self, now: Instant, is_round_start: bool, min_rtt_expired: bool,
        bytes_in_flight: usize,
    ) {
        if min_rtt_expired &&
            !self.exiting_quiescence &&
            self.mode != Mode::ProbeRtt
        {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.;
            // Do not decide on the time to exit PROBE_RTT until the
            // `bytes_in_flight` is at the target small value.
            self.exit_probe_rtt_at = None;
        }

        if self.mode == Mode::ProbeRtt {
            self.sampler.on_app_limited();

            if self.exit_probe_rtt_at.is_none() {
                // If the window has reached the appropriate size, schedule
                // exiting PROBE_RTT.  The CWND during PROBE_RTT
                // is kMinimumCongestionWindow, but we allow an
                // extra packet since QUIC checks CWND before sending a
                // packet.
                if bytes_in_flight <
                    self.probe_rtt_congestion_window() +
                        MAX_OUTGOING_PACKET_SIZE
                {
                    self.exit_probe_rtt_at = Some(now + PROBE_RTT_TIME);
                    self.probe_rtt_round_passed = false;
                }
            } else {
                if is_round_start {
                    self.probe_rtt_round_passed = true;
                }
                if self.exit_probe_rtt_at.is_some() &&
                    Some(now) >= self.exit_probe_rtt_at &&
                    self.probe_rtt_round_passed
                {
                    self.min_rtt_timestamp = Some(now);
                    if !self.is_at_full_bandwidth {
                        self.enter_startup_mode();
                    } else {
                        self.enter_probe_bandwidth_mode(now);
                    }
                }
            }
        }

        self.exiting_quiescence = false;
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.congestion_window_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.congestion_window_gain = self.congestion_window_gain_constant;
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would
        // not follow each other.
        self.cycle_current_offset =
            get_tiny_rand() as usize % (GAIN_CYCLE_LENGTH - 1);
        if self.cycle_current_offset >= 1 {
            self.cycle_current_offset += 1;
        }

        self.last_cycle_start = Some(now);
        self.pacing_gain = PACING_GAIN[self.cycle_current_offset];
    }
}

impl CongestionControl for BBR {
    fn get_congestion_window(&self) -> usize {
        if self.mode == Mode::ProbeRtt {
            return self.probe_rtt_congestion_window();
        }

        if self.is_in_recovery() {
            return self.congestion_window.min(self.recovery_window);
        }

        self.congestion_window
    }

    fn get_congestion_window_in_packets(&self) -> usize {
        self.get_congestion_window() / self.mss
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight < self.get_congestion_window()
    }

    fn on_packet_sent(
        &mut self, sent_time: std::time::Instant, bytes_in_flight: usize,
        packet_number: u64, bytes: usize, is_retransmissible: bool,
        _rtt_stats: &RttStats,
    ) {
        self.last_sent_packet = packet_number;

        if bytes_in_flight == 0 && self.sampler.is_app_limited() {
            self.exiting_quiescence = true;
        }

        self.sampler.on_packet_sent(
            sent_time,
            packet_number,
            bytes,
            bytes_in_flight,
            is_retransmissible,
        );
    }

    fn on_congestion_event(
        &mut self, _rtt_updated: bool, prior_in_flight: usize,
        bytes_in_flight: usize, event_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], least_unacked: u64, rtt_stats: &RttStats,
    ) {
        let have_lost_packets = !lost_packets.is_empty();

        let total_bytes_acked_before = self.sampler.total_bytes_acked();
        let total_bytes_lost_before = self.sampler.total_bytes_lost();

        let mut is_round_start = false;
        let mut min_rtt_expired = false;

        // The send state of the largest packet in acked_packets, unless it is
        // empty. If acked_packets is empty, it's the send state of the largest
        // packet in lost_packets.

        if let Some(largest_acked) = acked_packets.last() {
            is_round_start =
                self.update_round_trip_counter(largest_acked.pkt_num);
            self.update_recovery_state(
                largest_acked.pkt_num,
                have_lost_packets,
                is_round_start,
            );
        }

        let sample = self.sampler.on_congestion_event(
            event_time,
            acked_packets,
            lost_packets,
            self.max_bandwidth.get_best(),
            Bandwidth::infinite(),
            self.round_trip_count,
        );

        if sample.last_packet_send_state.is_valid {
            self.last_sample_is_app_limited =
                sample.last_packet_send_state.is_app_limited;
            self.has_non_app_limited_sample |= self.last_sample_is_app_limited;
        }
        // Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b)
        // all packets in |acked_packets| did not generate valid samples.
        // (e.g. ack of ack-only packets). In both cases,
        // sampler_.total_bytes_acked() will not change.
        if total_bytes_acked_before != self.sampler.total_bytes_acked() &&
            (!sample.sample_is_app_limited ||
                sample.sample_max_bandwidth > self.max_bandwidth.get_best())
        {
            self.max_bandwidth.update(
                sample.sample_max_bandwidth.unwrap_or(Bandwidth::zero()),
                self.round_trip_count,
            );
        }

        if sample.sample_rtt.is_some() {
            min_rtt_expired =
                self.maybe_update_min_rtt(event_time, sample.sample_rtt.unwrap());
        }

        let bytes_lost =
            self.sampler.total_bytes_lost() - total_bytes_lost_before;

        let excess_acked = sample.extra_acked;
        let last_packet_send_state = sample.last_packet_send_state;

        if have_lost_packets {
            self.num_loss_events_in_round += 1;
            self.bytes_lost_in_round += bytes_lost;
        }

        // Handle logic specific to PROBE_BW mode.
        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(
                event_time,
                prior_in_flight,
                have_lost_packets,
                rtt_stats,
                bytes_in_flight,
            );
        }

        // Handle logic specific to STARTUP and DRAIN modes.
        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bandwidth_reached(
                &last_packet_send_state,
                rtt_stats,
            );
        }

        self.maybe_exit_startup_or_drain(event_time, rtt_stats, bytes_in_flight);

        // Handle logic specific to PROBE_RTT.
        self.maybe_enter_or_exit_probe_rtt(
            event_time,
            is_round_start,
            min_rtt_expired,
            bytes_in_flight,
        );

        // Calculate number of packets acked and lost.
        let bytes_acked =
            self.sampler.total_bytes_acked() - total_bytes_acked_before;

        // After the model is updated, recalculate the pacing rate and congestion
        // window.
        self.calculate_pacing_rate(bytes_lost, rtt_stats);
        self.calculate_congestion_window(bytes_acked, excess_acked, rtt_stats);
        self.calculate_recovery_window(bytes_acked, bytes_lost, bytes_in_flight);

        // Cleanup internal state.
        self.sampler.remove_obsolete_packets(least_unacked);
        if is_round_start {
            self.num_loss_events_in_round = 0;
            self.bytes_lost_in_round = 0;
        }
    }

    fn on_packet_neutered(&mut self, packet_number: u64) {
        self.sampler.on_packet_neutered(packet_number);
    }

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn on_connection_migration(&mut self) {}

    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool {
        let congestion_window = self.get_congestion_window();
        bytes_in_flight >= congestion_window
    }

    fn is_in_recovery(&self) -> bool {
        self.recovery_state != RecoveryState::NotInRecovery
    }

    fn pacing_rate(
        &self, _bytes_in_flight: usize, _rtt_stats: &RttStats,
    ) -> Bandwidth {
        self.pacing_rate
    }

    fn bandwidth_estimate(&self, _rtt_stats: &RttStats) -> Bandwidth {
        self.max_bandwidth.get_best().unwrap_or(Bandwidth::zero())
    }

    fn update_mss(&mut self, new_mss: usize) {
        if self.mss == new_mss {
            return;
        }

        self.congestion_window = (self.congestion_window * new_mss) / self.mss;
        self.min_congestion_window =
            (self.min_congestion_window * new_mss) / self.mss;
        self.max_congestion_window =
            (self.max_congestion_window * new_mss) / self.mss;
        self.initial_congestion_window =
            (self.initial_congestion_window * new_mss) / self.mss;
        self.recovery_window = (self.recovery_window * new_mss) / self.mss;
        self.max_congestion_window =
            (self.max_congestion_window * new_mss) / self.mss;
        self.cwnd_to_calculate_min_pacing_rate =
            (self.cwnd_to_calculate_min_pacing_rate * new_mss) / self.mss;
        self.mss = new_mss;
    }
}
