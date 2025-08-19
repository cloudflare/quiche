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

use std::fmt::Debug;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::gcongestion::bbr2::Params;
use crate::recovery::gcongestion::Lost;
use crate::recovery::RecoveryStats;

use super::drain::Drain;
use super::network_model::BBRv2NetworkModel;
use super::probe_bw::ProbeBW;
use super::probe_rtt::ProbeRTT;
use super::startup::Startup;
use super::Acked;
use super::BBRv2CongestionEvent;
use super::Limits;

#[derive(Debug, Default, PartialEq)]
pub(super) enum CyclePhase {
    #[default]
    NotStarted,
    Up,
    Down,
    Cruise,
    Refill,
}

impl CyclePhase {
    pub(super) fn pacing_gain(&self, params: &Params) -> f32 {
        match self {
            CyclePhase::Up => params.probe_bw_probe_up_pacing_gain,
            CyclePhase::Down => params.probe_bw_probe_down_pacing_gain,
            _ => params.probe_bw_default_pacing_gain,
        }
    }

    pub(super) fn cwnd_gain(&self, params: &Params) -> f32 {
        match self {
            CyclePhase::Up => params.probe_bw_up_cwnd_gain,
            _ => params.probe_bw_cwnd_gain,
        }
    }
}

#[derive(Debug)]
pub(super) struct Cycle {
    pub(super) start_time: Instant,
    pub(super) phase: CyclePhase,
    pub(super) rounds_in_phase: usize,
    pub(super) phase_start_time: Instant,
    pub(super) rounds_since_probe: usize,
    pub(super) probe_wait_time: Option<Duration>,
    pub(super) probe_up_rounds: usize,
    pub(super) probe_up_bytes: Option<usize>,
    pub(super) probe_up_acked: usize,
    pub(super) probe_up_app_limited_since_inflight_hi_limited: bool,
    // Whether max bandwidth filter window has advanced in this cycle. It is
    // advanced once per cycle.
    pub(super) has_advanced_max_bw: bool,
    pub(super) is_sample_from_probing: bool,

    pub(super) last_cycle_probed_too_high: bool,
    pub(super) last_cycle_stopped_risky_probe: bool,
}

impl Default for Cycle {
    fn default() -> Self {
        let now = Instant::now();

        Cycle {
            start_time: now,
            phase_start_time: now,

            phase: CyclePhase::NotStarted,
            rounds_in_phase: 0,
            rounds_since_probe: 0,
            probe_wait_time: None,
            probe_up_rounds: 0,
            probe_up_bytes: None,
            probe_up_acked: 0,
            probe_up_app_limited_since_inflight_hi_limited: false,
            has_advanced_max_bw: false,
            is_sample_from_probing: false,
            last_cycle_probed_too_high: false,
            last_cycle_stopped_risky_probe: false,
        }
    }
}

#[enum_dispatch::enum_dispatch]
pub(super) trait ModeImpl: Debug {
    #[cfg(feature = "qlog")]
    fn state_str(&self) -> &'static str;

    fn enter(
        &mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
        params: &Params,
    );

    fn leave(
        &mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    );

    fn is_probing_for_bandwidth(&self) -> bool;

    #[allow(clippy::too_many_arguments)]
    fn on_congestion_event(
        self, prior_in_flight: usize, event_time: Instant,
        acked_packets: &[Acked], lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        target_bytes_inflight: usize, params: &Params,
        recovery_stats: &mut RecoveryStats, cwnd: usize,
    ) -> Mode;

    fn get_cwnd_limits(&self, params: &Params) -> Limits<usize>;

    fn on_exit_quiescence(
        self, now: Instant, quiescence_start_time: Instant, params: &Params,
    ) -> Mode;
}

#[enum_dispatch::enum_dispatch(ModeImpl)]
#[derive(Debug)]
pub(super) enum Mode {
    Startup(Startup),
    Drain(Drain),
    ProbeBW(ProbeBW),
    ProbeRTT(ProbeRTT),
    Placheolder(Placeholder),
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Placheolder(Placeholder {})
    }
}

impl Mode {
    pub(super) fn startup(model: BBRv2NetworkModel) -> Self {
        Mode::Startup(Startup { model })
    }

    pub(super) fn drain(model: BBRv2NetworkModel) -> Self {
        Mode::Drain(Drain {
            model,
            cycle: Default::default(),
        })
    }

    pub(super) fn probe_bw(model: BBRv2NetworkModel, cycle: Cycle) -> Self {
        Mode::ProbeBW(ProbeBW { model, cycle })
    }

    pub(super) fn probe_rtt(model: BBRv2NetworkModel, cycle: Cycle) -> Self {
        Mode::ProbeRTT(ProbeRTT::new(model, cycle))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn do_on_congestion_event(
        &mut self, prior_in_flight: usize, event_time: Instant,
        acked_packets: &[Acked], lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        target_bytes_inflight: usize, params: &Params,
        recovery_stats: &mut RecoveryStats, cwnd: usize,
    ) -> bool {
        let mode_before = std::mem::discriminant(self);

        *self = std::mem::take(self).on_congestion_event(
            prior_in_flight,
            event_time,
            acked_packets,
            lost_packets,
            congestion_event,
            target_bytes_inflight,
            params,
            recovery_stats,
            cwnd,
        );

        let mode_after = std::mem::discriminant(self);

        mode_before != mode_after
    }

    pub(super) fn do_on_exit_quiescence(
        &mut self, now: Instant, quiescence_start_time: Instant, params: &Params,
    ) {
        *self = std::mem::take(self).on_exit_quiescence(
            now,
            quiescence_start_time,
            params,
        )
    }

    pub fn network_model(&self) -> &BBRv2NetworkModel {
        match self {
            Mode::Startup(Startup { model }) => model,
            Mode::Drain(Drain { model, .. }) => model,
            Mode::ProbeBW(ProbeBW { model, .. }) => model,
            Mode::ProbeRTT(ProbeRTT { model, .. }) => model,
            Mode::Placheolder(_) => unreachable!(),
        }
    }

    pub fn network_model_mut(&mut self) -> &mut BBRv2NetworkModel {
        match self {
            Mode::Startup(Startup { model }) => model,
            Mode::Drain(Drain { model, .. }) => model,
            Mode::ProbeBW(ProbeBW { model, .. }) => model,
            Mode::ProbeRTT(ProbeRTT { model, .. }) => model,
            Mode::Placheolder(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct Placeholder {}

impl ModeImpl for Placeholder {
    #[cfg(feature = "qlog")]
    fn state_str(&self) -> &'static str {
        unreachable!()
    }

    fn enter(
        &mut self, _: Instant, _: Option<&BBRv2CongestionEvent>, _params: &Params,
    ) {
        unreachable!()
    }

    fn leave(&mut self, _: Instant, _: Option<&BBRv2CongestionEvent>) {
        unreachable!()
    }

    fn is_probing_for_bandwidth(&self) -> bool {
        unreachable!()
    }

    fn on_congestion_event(
        self, _: usize, _: Instant, _: &[Acked], _: &[Lost],
        _: &mut BBRv2CongestionEvent, _: usize, _params: &Params,
        _recovery_stats: &mut RecoveryStats, _cwnd: usize,
    ) -> Mode {
        unreachable!()
    }

    fn get_cwnd_limits(&self, _params: &Params) -> Limits<usize> {
        unreachable!()
    }

    fn on_exit_quiescence(
        self, _: Instant, _: Instant, _params: &Params,
    ) -> Mode {
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::gcongestion::bbr2::DEFAULT_PARAMS;
    use crate::BbrParams;

    #[test]
    fn cycle_params() {
        let custom_bbr_settings = BbrParams {
            probe_bw_up_cwnd_gain: Some(2.25),
            probe_bw_cwnd_gain: Some(2.0),
            ..Default::default()
        };
        let params = &DEFAULT_PARAMS.with_overrides(&custom_bbr_settings);

        assert_eq!(CyclePhase::Up.pacing_gain(params), 1.25);
        assert_eq!(CyclePhase::Up.cwnd_gain(params), 2.25);

        assert_eq!(CyclePhase::Down.pacing_gain(params), 0.9);
        assert_eq!(CyclePhase::Down.cwnd_gain(params), 2.0);

        assert_eq!(CyclePhase::NotStarted.pacing_gain(params), 1.0);
        assert_eq!(CyclePhase::NotStarted.cwnd_gain(params), 2.0);

        assert_eq!(CyclePhase::Cruise.pacing_gain(params), 1.0);
        assert_eq!(CyclePhase::Cruise.cwnd_gain(params), 2.0);

        assert_eq!(CyclePhase::Refill.pacing_gain(params), 1.0);
        assert_eq!(CyclePhase::Refill.cwnd_gain(params), 2.0);
    }
}
