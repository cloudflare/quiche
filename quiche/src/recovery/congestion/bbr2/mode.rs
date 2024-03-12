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
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::congestion::Lost;
use crate::recovery::Acked;

use super::drain::Drain;
use super::network_model::BBRv2NetworkModel;
use super::probe_bw::ProbeBW;
use super::probe_rtt::ProbeRTT;
use super::startup::Startup;
use super::BBRv2CongestionEvent;
use super::Limits;
use super::PARAMS;

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
    pub(super) fn gain(&self) -> f32 {
        match self {
            CyclePhase::Up => PARAMS.probe_bw_probe_up_pacing_gain,
            CyclePhase::Down => PARAMS.probe_bw_probe_down_pacing_gain,
            _ => PARAMS.probe_bw_default_pacing_gain,
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
    fn enter(
        &mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    );

    fn leave(
        &mut self, now: Instant, congestion_event: Option<&BBRv2CongestionEvent>,
    );

    fn is_probing_for_bandwidth(&self) -> bool;

    fn on_congestion_event(
        self, prior_in_flight: usize, event_time: Instant,
        acked_packets: &[Acked], lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        target_bytes_inflight: usize,
    ) -> Mode;

    fn get_cwnd_limits(&self) -> Limits<usize>;

    fn on_exit_quiescence(
        self, now: Instant, quiescence_start_time: Instant,
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

    pub(super) fn do_on_congestion_event(
        &mut self, prior_in_flight: usize, event_time: Instant,
        acked_packets: &[Acked], lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
        target_bytes_inflight: usize,
    ) -> bool {
        let mode_before = std::mem::discriminant(self);

        *self = std::mem::take(self).on_congestion_event(
            prior_in_flight,
            event_time,
            acked_packets,
            lost_packets,
            congestion_event,
            target_bytes_inflight,
        );

        let mode_after = std::mem::discriminant(self);

        mode_before != mode_after
    }

    pub(super) fn do_on_exit_quiescence(
        &mut self, now: Instant, quiescence_start_time: Instant,
    ) {
        *self =
            std::mem::take(self).on_exit_quiescence(now, quiescence_start_time)
    }
}

impl Deref for Mode {
    type Target = BBRv2NetworkModel;

    fn deref(&self) -> &Self::Target {
        match self {
            Mode::Startup(Startup { model }) => model,
            Mode::Drain(Drain { model, .. }) => model,
            Mode::ProbeBW(ProbeBW { model, .. }) => model,
            Mode::ProbeRTT(ProbeRTT { model, .. }) => model,
            Mode::Placheolder(_) => unreachable!(),
        }
    }
}

impl DerefMut for Mode {
    fn deref_mut(&mut self) -> &mut Self::Target {
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
    fn enter(&mut self, _: Instant, _: Option<&BBRv2CongestionEvent>) {
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
        _: &mut BBRv2CongestionEvent, _: usize,
    ) -> Mode {
        unreachable!()
    }

    fn get_cwnd_limits(&self) -> Limits<usize> {
        unreachable!()
    }

    fn on_exit_quiescence(self, _: Instant, _: Instant) -> Mode {
        unreachable!()
    }
}
