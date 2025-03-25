// Copyright (c) 2015 The Chromium Authors. All rights reserved.
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

use std::ops::Add;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::gcongestion::Acked;
use crate::recovery::gcongestion::Lost;

use super::mode::Cycle;
use super::mode::CyclePhase;
use super::mode::Mode;
use super::mode::ModeImpl;
use super::network_model::BBRv2NetworkModel;
use super::network_model::DEFAULT_MSS;
use super::BBRv2CongestionEvent;
use super::BwLoMode;
use super::Limits;
use super::PARAMS;

#[derive(Debug)]
pub(super) struct ProbeBW {
    pub(super) model: BBRv2NetworkModel,
    pub(super) cycle: Cycle,
}

#[derive(PartialEq, PartialOrd)]
enum AdaptUpperBoundsResult {
    AdaptedOk,
    AdaptedProbedTooHigh,
    NotAdaptedInflightHighNotSet,
    NotAdaptedInvalidSample,
}

impl ModeImpl for ProbeBW {
    fn enter(
        &mut self, now: Instant, _congestion_event: Option<&BBRv2CongestionEvent>,
    ) {
        self.cycle.start_time = now;

        match self.cycle.phase {
            super::mode::CyclePhase::NotStarted => {
                // First time entering PROBE_BW. Start a new probing cycle.
                self.enter_probe_down(false, false, now)
            },
            super::mode::CyclePhase::Cruise => self.enter_probe_cruise(now),
            super::mode::CyclePhase::Refill =>
                self.enter_probe_refill(self.cycle.probe_up_rounds, now),
            super::mode::CyclePhase::Up | super::mode::CyclePhase::Down => {},
        }
    }

    fn on_congestion_event(
        mut self, prior_in_flight: usize, event_time: Instant, _: &[Acked],
        _: &[Lost], congestion_event: &mut BBRv2CongestionEvent,
        target_bytes_inflight: usize,
    ) -> Mode {
        if congestion_event.end_of_round_trip {
            if self.cycle.start_time != event_time {
                self.cycle.rounds_since_probe += 1;
            }

            if self.cycle.phase_start_time != event_time {
                self.cycle.rounds_in_phase += 1;
            }
        }

        let mut switch_to_probe_rtt = false;

        match self.cycle.phase {
            CyclePhase::NotStarted => unreachable!(),
            CyclePhase::Up => self.update_probe_up(
                prior_in_flight,
                target_bytes_inflight,
                congestion_event,
            ),
            CyclePhase::Down => {
                self.update_probe_down(target_bytes_inflight, congestion_event);
                if self.cycle.phase != CyclePhase::Down &&
                    self.model.maybe_expire_min_rtt(congestion_event)
                {
                    switch_to_probe_rtt = true;
                }
            },
            CyclePhase::Cruise =>
                self.update_probe_cruise(target_bytes_inflight, congestion_event),
            CyclePhase::Refill =>
                self.update_probe_refill(target_bytes_inflight, congestion_event),
        }

        // Do not need to set the gains if switching to PROBE_RTT, they will be
        // set when `ProbeRTT::enter` is called.
        if !switch_to_probe_rtt {
            self.model.set_pacing_gain(self.cycle.phase.gain());
            self.model.set_cwnd_gain(PARAMS.probe_bw_cwnd_gain);
        }

        if switch_to_probe_rtt {
            self.into_probe_rtt(event_time, Some(congestion_event))
        } else {
            Mode::ProbeBW(self)
        }
    }

    fn get_cwnd_limits(&self) -> Limits<usize> {
        if self.cycle.phase == CyclePhase::Cruise {
            let limit = self
                .model
                .inflight_lo()
                .min(self.model.inflight_hi_with_headroom());
            return Limits::no_greater_than(limit);
        }

        if self.cycle.phase == CyclePhase::Up &&
            PARAMS.probe_up_ignore_inflight_hi
        {
            // Similar to STARTUP.
            return Limits::no_greater_than(self.model.inflight_lo());
        }

        Limits::no_greater_than(
            self.model.inflight_lo().min(self.model.inflight_hi()),
        )
    }

    fn is_probing_for_bandwidth(&self) -> bool {
        self.cycle.phase == CyclePhase::Refill ||
            self.cycle.phase == CyclePhase::Up
    }

    fn on_exit_quiescence(
        mut self, now: Instant, quiescence_start_time: Instant,
    ) -> Mode {
        self.model
            .postpone_min_rtt_timestamp(now - quiescence_start_time);
        Mode::ProbeBW(self)
    }

    fn leave(
        &mut self, _now: Instant,
        _congestion_event: Option<&BBRv2CongestionEvent>,
    ) {
    }
}

impl ProbeBW {
    fn enter_probe_down(
        &mut self, probed_too_high: bool, stopped_risky_probe: bool, now: Instant,
    ) {
        let cycle = &mut self.cycle;
        cycle.last_cycle_probed_too_high = probed_too_high;
        cycle.last_cycle_stopped_risky_probe = stopped_risky_probe;

        cycle.phase = CyclePhase::Down;
        cycle.start_time = now;
        cycle.phase_start_time = now;
        cycle.rounds_in_phase = 0;

        if PARAMS.bw_lo_mode != BwLoMode::Default {
            // Clear bandwidth lo if it was set in PROBE_UP, because losses in
            // PROBE_UP should not permanently change bandwidth_lo.
            // It's possible for bandwidth_lo to be set during REFILL, but if that
            // was a valid value, it'll quickly be rediscovered.
            self.model.clear_bandwidth_lo();
        }

        // Pick probe wait time.
        // TODO(vlad): actually pick time
        cycle.rounds_since_probe = 0;
        cycle.probe_wait_time = Some(
            PARAMS.probe_bw_probe_base_duration + Duration::from_micros(500),
        );

        cycle.probe_up_bytes = None;
        cycle.probe_up_app_limited_since_inflight_hi_limited = false;
        cycle.has_advanced_max_bw = false;
        self.model.restart_round_early();
    }

    fn enter_probe_cruise(&mut self, now: Instant) {
        if self.cycle.phase == CyclePhase::Down {
            self.exit_probe_down();
        }

        let cycle = &mut self.cycle;

        self.model.cap_inflight_lo(self.model.inflight_hi());
        cycle.phase = CyclePhase::Cruise;
        cycle.phase_start_time = now;
        cycle.rounds_in_phase = 0;
        cycle.is_sample_from_probing = false;
    }

    fn enter_probe_refill(&mut self, probe_up_rounds: usize, now: Instant) {
        if self.cycle.phase == CyclePhase::Down {
            self.exit_probe_down();
        }

        let cycle = &mut self.cycle;

        cycle.phase = CyclePhase::Refill;
        cycle.phase_start_time = now;
        cycle.rounds_in_phase = 0;

        cycle.is_sample_from_probing = false;
        cycle.last_cycle_stopped_risky_probe = false;

        self.model.clear_bandwidth_lo();
        self.model.clear_inflight_lo();
        cycle.probe_up_rounds = probe_up_rounds;
        cycle.probe_up_acked = 0;
        self.model.restart_round_early();
    }

    fn enter_probe_up(&mut self, now: Instant, cwnd: usize) {
        let cycle = &mut self.cycle;

        cycle.phase = CyclePhase::Up;
        cycle.phase_start_time = now;
        cycle.rounds_in_phase = 0;
        cycle.is_sample_from_probing = true;
        self.raise_inflight_high_slope(cwnd);
        self.model.restart_round_early();
    }

    fn exit_probe_down(&mut self) {
        if !self.cycle.has_advanced_max_bw {
            self.model.advance_max_bandwidth_filter();
            self.cycle.has_advanced_max_bw = true;
        }
    }

    fn update_probe_down(
        &mut self, target_bytes_inflight: usize,
        congestion_event: &BBRv2CongestionEvent,
    ) {
        if self.cycle.rounds_in_phase == 1 && congestion_event.end_of_round_trip {
            self.cycle.is_sample_from_probing = false;

            if !congestion_event.last_packet_send_state.is_app_limited {
                self.model.advance_max_bandwidth_filter();
                self.cycle.has_advanced_max_bw = true;
            }

            if self.cycle.last_cycle_stopped_risky_probe &&
                !self.cycle.last_cycle_probed_too_high
            {
                self.enter_probe_refill(0, congestion_event.event_time);
                return;
            }
        }

        self.maybe_adapt_upper_bounds(target_bytes_inflight, congestion_event);

        if self
            .is_time_to_probe_bandwidth(target_bytes_inflight, congestion_event)
        {
            self.enter_probe_refill(0, congestion_event.event_time);
            return;
        }

        if self.has_stayed_long_enough_in_probe_down(congestion_event) {
            self.enter_probe_cruise(congestion_event.event_time);
            return;
        }

        let inflight_with_headroom = self.model.inflight_hi_with_headroom();
        let bytes_in_flight = congestion_event.bytes_in_flight;

        if bytes_in_flight > inflight_with_headroom {
            // Stay in PROBE_DOWN.
            return;
        }

        // Transition to PROBE_CRUISE iff we've drained to target.
        let bdp = self.model.bdp0();

        if bytes_in_flight < bdp {
            self.enter_probe_cruise(congestion_event.event_time);
        }
    }

    fn update_probe_cruise(
        &mut self, target_bytes_inflight: usize,
        congestion_event: &BBRv2CongestionEvent,
    ) {
        self.maybe_adapt_upper_bounds(target_bytes_inflight, congestion_event);

        if self
            .is_time_to_probe_bandwidth(target_bytes_inflight, congestion_event)
        {
            self.enter_probe_refill(0, congestion_event.event_time);
        }
    }

    fn update_probe_refill(
        &mut self, target_bytes_inflight: usize,
        congestion_event: &BBRv2CongestionEvent,
    ) {
        self.maybe_adapt_upper_bounds(target_bytes_inflight, congestion_event);

        if self.cycle.rounds_in_phase > 0 && congestion_event.end_of_round_trip {
            self.enter_probe_up(
                congestion_event.event_time,
                congestion_event.prior_cwnd,
            );
        }
    }

    fn update_probe_up(
        &mut self, prior_in_flight: usize, target_bytes_inflight: usize,
        congestion_event: &BBRv2CongestionEvent,
    ) {
        if self.maybe_adapt_upper_bounds(target_bytes_inflight, congestion_event) ==
            AdaptUpperBoundsResult::AdaptedProbedTooHigh
        {
            self.enter_probe_down(true, false, congestion_event.event_time);
            return;
        }

        self.probe_inflight_high_upward(congestion_event);

        let mut is_risky = false;
        let mut is_queuing = false;
        if self.cycle.last_cycle_probed_too_high &&
            prior_in_flight >= self.model.inflight_hi()
        {
            is_risky = true;
        } else if self.cycle.rounds_in_phase > 0 {
            if PARAMS.max_probe_up_queue_rounds > 0 {
                if congestion_event.end_of_round_trip {
                    self.model.check_persistent_queue(PARAMS.full_bw_threshold);
                    if self.model.rounds_with_queueing() >=
                        PARAMS.max_probe_up_queue_rounds
                    {
                        is_queuing = true;
                    }
                }
            } else {
                let mut queuing_threshold_extra_bytes =
                    self.model.queueing_threshold_extra_bytes();
                if PARAMS.add_ack_height_to_queueing_threshold {
                    queuing_threshold_extra_bytes += self.model.max_ack_height();
                }
                let queuing_threshold = (PARAMS.full_bw_threshold *
                    self.model.bdp0() as f32)
                    as usize +
                    queuing_threshold_extra_bytes;

                is_queuing =
                    congestion_event.bytes_in_flight >= queuing_threshold;
            }
        }

        if is_risky || is_queuing {
            self.enter_probe_down(false, is_risky, congestion_event.event_time);
        }
    }

    fn is_time_to_probe_bandwidth(
        &self, target_bytes_inflight: usize,
        congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        if self.has_cycle_lasted(
            self.cycle.probe_wait_time.unwrap(),
            congestion_event,
        ) {
            return true;
        }

        if self.is_time_to_probe_for_reno_coexistence(
            target_bytes_inflight,
            1.0,
            congestion_event,
        ) {
            return true;
        }

        false
    }

    fn maybe_adapt_upper_bounds(
        &mut self, target_bytes_inflight: usize,
        congestion_event: &BBRv2CongestionEvent,
    ) -> AdaptUpperBoundsResult {
        let send_state = congestion_event.last_packet_send_state;

        if !send_state.is_valid {
            return AdaptUpperBoundsResult::NotAdaptedInvalidSample;
        }

        // TODO(vlad): use BytesInFlight?
        let mut inflight_at_send = send_state.bytes_in_flight;
        if PARAMS.use_bytes_delivered_for_inflight_hi {
            inflight_at_send = self.model.total_bytes_acked() -
                congestion_event.last_packet_send_state.total_bytes_acked;
        }

        if self.cycle.is_sample_from_probing {
            if self.model.is_inflight_too_high(
                congestion_event,
                PARAMS.probe_bw_full_loss_count,
            ) {
                self.cycle.is_sample_from_probing = false;
                if !send_state.is_app_limited ||
                    PARAMS.max_probe_up_queue_rounds > 0
                {
                    let inflight_target = (target_bytes_inflight as f32 *
                        (1.0 - PARAMS.beta))
                        as usize;

                    let mut new_inflight_hi =
                        inflight_at_send.max(inflight_target);

                    if PARAMS.limit_inflight_hi_by_max_delivered {
                        new_inflight_hi = self
                            .model
                            .max_bytes_delivered_in_round()
                            .max(new_inflight_hi);
                    }

                    self.model.set_inflight_hi(new_inflight_hi);
                }
                return AdaptUpperBoundsResult::AdaptedProbedTooHigh;
            }
            return AdaptUpperBoundsResult::AdaptedOk;
        }

        if self.model.inflight_hi() == self.model.inflight_hi_default() {
            return AdaptUpperBoundsResult::NotAdaptedInflightHighNotSet;
        }

        // Raise the upper bound for inflight.
        if inflight_at_send > self.model.inflight_hi() {
            self.model.set_inflight_hi(inflight_at_send);
        }

        AdaptUpperBoundsResult::AdaptedOk
    }

    fn has_cycle_lasted(
        &self, duration: Duration, congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        (congestion_event.event_time - self.cycle.start_time) > duration
    }

    fn has_phase_lasted(
        &self, duration: Duration, congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        (congestion_event.event_time - self.cycle.phase_start_time) > duration
    }

    fn is_time_to_probe_for_reno_coexistence(
        &self, target_bytes_inflight: usize, probe_wait_fraction: f64,
        _congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        if !PARAMS.enable_reno_coexistence {
            return false;
        }

        let mut rounds = PARAMS.probe_bw_probe_max_rounds;
        if PARAMS.probe_bw_probe_reno_gain > 0.0 {
            let reno_rounds = (PARAMS.probe_bw_probe_reno_gain *
                target_bytes_inflight as f32 /
                DEFAULT_MSS as f32) as usize;
            rounds = reno_rounds.min(rounds);
        }

        self.cycle.rounds_since_probe >=
            (rounds as f64 * probe_wait_fraction) as usize
    }

    // Used to prevent a BBR2 flow from staying in PROBE_DOWN for too
    // long, as seen in some multi-sender simulator tests.
    fn has_stayed_long_enough_in_probe_down(
        &self, congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        // Stay in PROBE_DOWN for at most the time of a min rtt, as it is done in
        // BBRv1.
        self.has_phase_lasted(self.model.min_rtt(), congestion_event)
    }

    fn raise_inflight_high_slope(&mut self, cwnd: usize) {
        let growth_this_round = 1usize << self.cycle.probe_up_rounds;
        // The number 30 below means `growth_this_round` is capped at 1G and the
        // lower bound of `probe_up_bytes` is (practically) 1 mss, at this
        // speed `inflight_hi`` grows by approximately 1 packet per packet acked.
        self.cycle.probe_up_rounds = self.cycle.probe_up_rounds.add(1).min(30);
        let probe_up_bytes = cwnd / growth_this_round;
        self.cycle.probe_up_bytes = Some(probe_up_bytes.max(DEFAULT_MSS));
    }

    fn probe_inflight_high_upward(
        &mut self, congestion_event: &BBRv2CongestionEvent,
    ) {
        if PARAMS.probe_up_ignore_inflight_hi {
            // When inflight_hi is disabled in PROBE_UP, it increases when
            // the number of bytes delivered in a round is larger inflight_hi.
            return;
        } else {
            // TODO(vlad): probe_up_simplify_inflight_hi?
            if congestion_event.prior_bytes_in_flight <
                congestion_event.prior_cwnd
            {
                // Not fully utilizing cwnd, so can't safely grow.
                return;
            }

            if congestion_event.prior_cwnd < self.model.inflight_hi() {
                // Not fully using inflight_hi, so don't grow it.
                return;
            }

            self.cycle.probe_up_acked += congestion_event.bytes_acked;
        }

        if let Some(probe_up_bytes) = self.cycle.probe_up_bytes.as_mut() {
            if self.cycle.probe_up_acked >= *probe_up_bytes {
                let delta = self.cycle.probe_up_acked / *probe_up_bytes;
                self.cycle.probe_up_acked -= *probe_up_bytes;
                let new_inflight_hi =
                    self.model.inflight_hi() + delta * DEFAULT_MSS;
                if new_inflight_hi > self.model.inflight_hi() {
                    self.model.set_inflight_hi(new_inflight_hi);
                }
            }
        }

        if congestion_event.end_of_round_trip {
            self.raise_inflight_high_slope(congestion_event.prior_cwnd);
        }
    }

    fn into_probe_rtt(
        mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    ) -> Mode {
        self.leave(now, congestion_event);
        let mut next_mode = Mode::probe_rtt(self.model, self.cycle);
        next_mode.enter(now, congestion_event);
        next_mode
    }
}
