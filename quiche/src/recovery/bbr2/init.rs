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

// BBR2 Functions at Initialization.
//

// 4.2.1.  Initialization
pub fn bbr2_init(r: &mut Recovery) {
    let rtt = r.rtt();
    let now = Instant::now();

    let bbr = &mut r.bbr2_state;
    bbr.min_rtt = rtt;
    bbr.min_rtt_stamp = now;
    bbr.probe_rtt_done_stamp = None;
    bbr.probe_rtt_round_done = false;
    bbr.prior_cwnd = 0;
    bbr.idle_restart = false;
    bbr.extra_acked_interval_start = now;
    bbr.extra_acked_delivered = 0;
    bbr.bw_lo = u64::MAX;
    bbr.bw_hi = u64::MAX;
    bbr.inflight_lo = usize::MAX;
    bbr.inflight_hi = usize::MAX;
    bbr.probe_up_cnt = usize::MAX;

    r.send_quantum = r.max_datagram_size;

    per_loss::bbr2_reset_congestion_signals(r);
    per_loss::bbr2_reset_lower_bounds(r);
    bbr2_init_round_counting(r);
    bbr2_init_full_pipe(r);
    pacing::bbr2_init_pacing_rate(r);
    bbr2_enter_startup(r);
}

// 4.5.1.  BBR.round_count: Tracking Packet-Timed Round Trips
fn bbr2_init_round_counting(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.next_round_delivered = 0;
    bbr.round_start = false;
    bbr.round_count = 0;
}

// 4.3.1.1.  Startup Dynamics
pub fn bbr2_enter_startup(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.state = BBR2StateMachine::Startup;
    bbr.pacing_gain = STARTUP_PACING_GAIN;
    bbr.cwnd_gain = STARTUP_CWND_GAIN;
}

// 4.3.1.2.  Exiting Startup Based on Bandwidth Plateau
fn bbr2_init_full_pipe(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.filled_pipe = false;
    bbr.full_bw = 0;
    bbr.full_bw_count = 0;
}
