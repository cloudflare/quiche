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
pub(super) struct Drain {
    pub(super) model: BBRv2NetworkModel,
    pub(super) cycle: Cycle,
}

impl ModeImpl for Drain {
    fn is_probing_for_bandwidth(&self) -> bool {
        false
    }

    fn on_congestion_event(
        mut self, _prior_in_flight: usize, event_time: Instant,
        _acked_packets: &[Acked], _lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        _target_bytes_inflight: usize,
    ) -> Mode {
        self.model.set_pacing_gain(PARAMS.drain_pacing_gain);
        // Only STARTUP can transition to DRAIN, both of them use the same cwnd
        // gain.
        self.model.set_cwnd_gain(PARAMS.drain_cwnd_gain);

        let drain_target = self.drain_target();
        if congestion_event.bytes_in_flight <= drain_target {
            return self.into_probe_bw(event_time, Some(congestion_event));
        }

        Mode::Drain(self)
    }

    fn get_cwnd_limits(&self) -> Limits<usize> {
        Limits {
            lo: 0,
            hi: self.model.inflight_lo(),
        }
    }

    fn on_exit_quiescence(
        self, _now: Instant, _quiescence_start_time: Instant,
    ) -> Mode {
        Mode::Drain(self)
    }

    fn enter(&mut self, _: Instant, _: Option<&BBRv2CongestionEvent>) {}

    fn leave(&mut self, _: Instant, _: Option<&BBRv2CongestionEvent>) {}
}

impl Drain {
    fn into_probe_bw(
        mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    ) -> Mode {
        self.leave(now, congestion_event);
        let mut next_mode = Mode::probe_bw(self.model, self.cycle);
        next_mode.enter(now, congestion_event);
        next_mode
    }

    fn drain_target(&self) -> usize {
        self.model.bdp0()
    }
}
