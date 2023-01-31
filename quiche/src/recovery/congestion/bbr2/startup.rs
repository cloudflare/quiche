use std::time::Instant;

use super::mode::Mode;
use super::mode::ModeImpl;
use super::network_model::BBRv2NetworkModel;
use super::BBRv2CongestionEvent;
use super::Limits;
use super::PARAMS;

#[derive(Debug)]
pub(super) struct Startup {
    pub(super) model: BBRv2NetworkModel,
}

impl ModeImpl for Startup {
    fn is_probing_for_bandwidth(&self) -> bool {
        true
    }

    fn on_congestion_event(
        mut self, _prior_in_flight: usize, event_time: std::time::Instant,
        _acked_packets: &[crate::recovery::Acked],
        _lost_packets: &[crate::recovery::congestion::Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        _target_bytes_inflight: usize,
    ) -> Mode {
        if self.model.full_bandwidth_reached() {
            return self.into_drain(event_time, Some(congestion_event));
        }

        if !congestion_event.end_of_round_trip {
            return Mode::Startup(self);
        }

        let has_bandwidth_growth =
            self.model.has_bandwidth_growth(congestion_event);

        #[allow(clippy::absurd_extreme_comparisons)]
        if PARAMS.max_startup_queue_rounds > 0 && !has_bandwidth_growth {
            // 1.75 is less than the 2x CWND gain, but substantially more than
            // 1.25x, the minimum bandwidth increase expected during
            // STARTUP.
            self.model.check_persistent_queue(1.75);
        }
        // TCP BBR always exits upon excessive losses. QUIC BBRv1 does not exit
        // upon excessive losses, if enough bandwidth growth is observed or if the
        // sample was app limited.
        if !congestion_event.last_packet_send_state.is_app_limited
            && !has_bandwidth_growth
        {
            self.check_excessive_losses(congestion_event);
        }

        if self.model.full_bandwidth_reached() {
            self.into_drain(event_time, Some(congestion_event))
        } else {
            Mode::Startup(self)
        }
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
        Mode::Startup(self)
    }

    fn enter(
        &mut self, _now: Instant,
        _congestion_event: Option<&BBRv2CongestionEvent>,
    ) {
        unreachable!("Enter should never be called for startup")
    }

    fn leave(
        &mut self, _now: Instant,
        _congestion_event: Option<&BBRv2CongestionEvent>,
    ) {
    }
}

impl Startup {
    fn into_drain(
        mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    ) -> Mode {
        self.leave(now, congestion_event);
        let mut next_mode = Mode::drain(self.model);
        next_mode.enter(now, congestion_event);
        next_mode
    }

    fn check_excessive_losses(
        &mut self, congestion_event: &mut BBRv2CongestionEvent,
    ) {
        if self.model.full_bandwidth_reached() {
            return;
        }

        // At the end of a round trip. Check if loss is too high in this round.
        if self.model.is_inflight_too_high(
            congestion_event,
            PARAMS.startup_full_loss_count,
        ) {
            let new_inflight_hi = self
                .model
                .bdp0()
                .max(self.model.max_bytes_delivered_in_round());
            self.model.set_inflight_hi(new_inflight_hi);
            self.model.set_full_bandwidth_reached();
        }
    }
}
