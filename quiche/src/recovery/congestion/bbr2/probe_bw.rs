use std::ops::Add;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::congestion::Acked;
use crate::recovery::congestion::Lost;

use super::mode::Cycle;
use super::mode::CyclePhase;
use super::mode::Mode;
use super::mode::ModeImpl;
use super::network_model::BBRv2NetworkModel;
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
        match self.cycle.phase {
            super::mode::CyclePhase::NotStarted => {
                // First time entering PROBE_BW. Start a new probing cycle.
                self.enter_probe_down(false, false, now)
            },
            super::mode::CyclePhase::Up | super::mode::CyclePhase::Down => {
                self.cycle.start_time = now;
            },
            super::mode::CyclePhase::Cruise => {
                self.cycle.start_time = now;
                self.enter_probe_cruise(now);
            },
            super::mode::CyclePhase::Refill => {
                self.cycle.start_time = now;
                self.enter_probe_refill(self.cycle.probe_up_rounds, now)
            },
        }
    }

    fn is_probing_for_bandwidth(&self) -> bool {
        self.cycle.phase == CyclePhase::Refill ||
            self.cycle.phase == CyclePhase::Up
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
        // set when Bbr2ProbeRttMode::Enter is called.
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
            return Limits {
                lo: 0,
                hi: self
                    .model
                    .inflight_lo()
                    .min(self.model.inflight_hi_with_headroom()),
            };
        }

        if self.cycle.phase == CyclePhase::Up {
            // Similar to STARTUP.
            return Limits {
                lo: 0,
                hi: self.model.inflight_lo(),
            };
        }

        Limits {
            lo: 0,
            hi: self.model.inflight_lo().min(self.model.inflight_hi()),
        }
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
        cycle.start_time = now;
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
                return self.enter_probe_refill(0, congestion_event.event_time);
            }
        }

        self.maybe_adapt_upper_bounds(target_bytes_inflight, congestion_event);

        if self
            .is_time_to_probe_bandwidth(target_bytes_inflight, congestion_event)
        {
            return self.enter_probe_refill(0, congestion_event.event_time);
        }

        if self.has_stayed_long_enough_in_probe_down(congestion_event) {
            return self.enter_probe_cruise(congestion_event.event_time);
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

            // TCP uses min_rtt instead of a full round:
            //   HasPhaseLasted(model_->MinRtt(), congestion_event)
        } else if self.cycle.rounds_in_phase > 0 {
            let mut queuing_threshold_extra_bytes = 2 * 1400;
            if PARAMS.add_ack_height_to_queueing_threshold {
                queuing_threshold_extra_bytes += self.model.max_ack_height();
            }
            let queuing_threshold =
                (PARAMS.full_bw_threshold * self.model.bdp0() as f32) as usize +
                    queuing_threshold_extra_bytes;

            is_queuing = congestion_event.bytes_in_flight >= queuing_threshold;
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
        let inflight_at_send = send_state.bytes_in_flight;

        if self.model.is_inflight_too_high(
            congestion_event,
            PARAMS.probe_bw_full_loss_count,
        ) && self.cycle.is_sample_from_probing
        {
            self.cycle.is_sample_from_probing = false;
            if !send_state.is_app_limited {
                let inflight_target =
                    (target_bytes_inflight as f32 * (1.0 - PARAMS.beta)) as usize;

                self.model
                    .set_inflight_hi(inflight_at_send.max(inflight_target));

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
        let mut rounds = PARAMS.probe_bw_probe_max_rounds;
        if PARAMS.probe_bw_probe_reno_gain > 0.0 {
            let reno_rounds = (PARAMS.probe_bw_probe_reno_gain *
                target_bytes_inflight as f32 /
                1300.) as usize;
            rounds = reno_rounds.min(rounds);
        }

        self.cycle.rounds_since_probe >=
            (rounds as f64 * probe_wait_fraction) as usize
    }

    // QUIC only. Used to prevent a Bbr2 flow from staying in PROBE_DOWN for too
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
        // speed inflight_hi grows by approximately 1 packet per packet
        // acked.
        self.cycle.probe_up_rounds = self.cycle.probe_up_rounds.add(1).min(30);
        self.cycle.probe_up_bytes = Some(cwnd / growth_this_round);
    }

    fn probe_inflight_high_upward(
        &mut self, _congestion_event: &BBRv2CongestionEvent,
    ) {
        // if (Params().probe_up_ignore_inflight_hi) {
        // When inflight_hi is disabled in PROBE_UP, it increases when
        // the number of bytes delivered in a round is larger inflight_hi.
        // return;
        //}
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
