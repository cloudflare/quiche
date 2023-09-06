use std::time::Instant;

use crate::recovery::congestion::Acked;
use crate::recovery::congestion::Lost;

use super::mode::Cycle;
use super::mode::Mode;
use super::mode::ModeImpl;
use super::network_model::BBRv2NetworkModel;
use super::BBRv2CongestionEvent;
use super::Limits;
use super::PARAMS;

#[derive(Debug)]
pub(super) struct ProbeRTT {
    pub(super) model: BBRv2NetworkModel,
    pub(super) cycle: Cycle,
    exit_time: Option<Instant>,
}

impl ProbeRTT {
    pub(super) fn new(model: BBRv2NetworkModel, cycle: Cycle) -> Self {
        ProbeRTT {
            model,
            cycle,
            exit_time: None,
        }
    }

    fn into_probe_bw(
        mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    ) -> Mode {
        self.leave(now, congestion_event);
        let mut next_mode = Mode::probe_bw(self.model, self.cycle);
        next_mode.enter(now, congestion_event);
        next_mode
    }

    fn inflight_target(&self) -> usize {
        self.model.bdp(
            self.model.max_bandwidth(),
            PARAMS.probe_rtt_inflight_target_bdp_fraction,
        )
    }
}

impl ModeImpl for ProbeRTT {
    fn is_probing_for_bandwidth(&self) -> bool {
        false
    }

    fn on_congestion_event(
        mut self, _prior_in_flight: usize, event_time: Instant,
        _acked_packets: &[Acked], _lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        _target_bytes_inflight: usize,
    ) -> Mode {
        if self.exit_time.is_none() {
            if congestion_event.bytes_in_flight <= self.inflight_target() {
                self.exit_time =
                    Some(congestion_event.event_time + PARAMS.probe_rtt_duration)
            }
            return Mode::ProbeRTT(self);
        }

        if self.exit_time.is_some() &&
            congestion_event.event_time > self.exit_time.unwrap()
        {
            Mode::ProbeRTT(self)
        } else {
            self.into_probe_bw(event_time, Some(congestion_event))
        }
    }

    fn get_cwnd_limits(&self) -> Limits<usize> {
        let inflight_upper_bound = self
            .model
            .inflight_lo()
            .min(self.model.inflight_hi_with_headroom());
        Limits {
            lo: 0,
            hi: inflight_upper_bound.min(self.inflight_target()),
        }
    }

    fn on_exit_quiescence(
        self, now: Instant, _quiescence_start_time: Instant,
    ) -> Mode {
        if let Some(exit_time) = self.exit_time {
            if exit_time > now {
                return self.into_probe_bw(now, None);
            }
        }
        Mode::ProbeRTT(self)
    }

    fn enter(
        &mut self, _now: Instant,
        _congestion_event: Option<&BBRv2CongestionEvent>,
    ) {
        self.model.set_pacing_gain(1.0);
        self.model.set_cwnd_gain(1.0);
        self.exit_time = None;
    }

    fn leave(
        &mut self, _now: Instant,
        _congestion_event: Option<&BBRv2CongestionEvent>,
    ) {
    }
}
