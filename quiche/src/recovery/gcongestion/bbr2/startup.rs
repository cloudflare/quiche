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

use super::mode::Mode;
use super::mode::ModeImpl;
use super::network_model::BBRv2NetworkModel;
use super::Acked;
use super::BBRv2CongestionEvent;
use super::Limits;
use super::Lost;
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
        _acked_packets: &[Acked], _lost_packets: &[Lost],
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
        if !congestion_event.last_packet_send_state.is_app_limited &&
            !has_bandwidth_growth
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
        // Clear bandwidth_lo if it's set during STARTUP.
        self.model.clear_bandwidth_lo();
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
            let mut new_inflight_hi = self.model.bdp0();

            if PARAMS.startup_loss_exit_use_max_delivered_for_inflight_hi {
                new_inflight_hi = new_inflight_hi
                    .max(self.model.max_bytes_delivered_in_round());
            }

            self.model.set_inflight_hi(new_inflight_hi);
            self.model.set_full_bandwidth_reached();
        }
    }
}
