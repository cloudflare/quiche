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
