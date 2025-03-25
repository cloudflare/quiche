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

use std::time::Instant;

use crate::recovery::gcongestion::Acked;
use crate::recovery::gcongestion::Lost;

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
        match self.exit_time {
            None => {
                if congestion_event.bytes_in_flight <= self.inflight_target() {
                    self.exit_time = Some(
                        congestion_event.event_time + PARAMS.probe_rtt_duration,
                    )
                }
                Mode::ProbeRTT(self)
            },
            Some(exit_time) =>
                if congestion_event.event_time > exit_time {
                    self.into_probe_bw(event_time, Some(congestion_event))
                } else {
                    Mode::ProbeRTT(self)
                },
        }
    }

    fn get_cwnd_limits(&self) -> Limits<usize> {
        let inflight_upper_bound = self
            .model
            .inflight_lo()
            .min(self.model.inflight_hi_with_headroom());
        Limits::no_greater_than(inflight_upper_bound.min(self.inflight_target()))
    }

    fn on_exit_quiescence(
        self, now: Instant, _quiescence_start_time: Instant,
    ) -> Mode {
        match self.exit_time {
            None => self.into_probe_bw(now, None),
            Some(exit_time) if now > exit_time => self.into_probe_bw(now, None),
            Some(_) => Mode::ProbeRTT(self),
        }
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
