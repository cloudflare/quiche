// Copyright (C) 2022, Cloudflare, Inc.
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

use super::*;
use crate::recovery::Recovery;

use std::time::Instant;

// BBR2 Functions when trasmitting packets.
//
// 4.2.2.  Per-Transmit Steps
pub fn bbr2_on_transmit(r: &mut Recovery, now: Instant) {
    bbr2_handle_restart_from_idle(r, now);
}

// 4.4.3.  Logic
fn bbr2_handle_restart_from_idle(r: &mut Recovery, now: Instant) {
    if r.bytes_in_flight == 0 && r.delivery_rate.app_limited() {
        r.bbr2_state.idle_restart = true;
        r.bbr2_state.extra_acked_interval_start = now;

        if per_ack::bbr2_is_in_a_probe_bw_state(r) {
            pacing::bbr2_set_pacing_rate_with_gain(r, 1.0);
        } else if r.bbr2_state.state == BBR2StateMachine::ProbeRTT {
            per_ack::bbr2_check_probe_rtt_done(r, now);
        }
    }
}
