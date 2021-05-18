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

use std::time::Duration;
use std::time::Instant;

// BBR Functions at Initialization.
//

// 4.3.1.  Initialization Steps
pub fn bbr_init(r: &mut Recovery) {
    let rtt = r.rtt();
    let bbr = &mut r.bbr_state;

    bbr.rtprop = rtt;
    bbr.rtprop_stamp = Instant::now();
    bbr.next_round_delivered = r.delivery_rate.delivered();

    r.send_quantum = r.max_datagram_size;

    bbr_init_round_counting(r);
    bbr_init_full_pipe(r);
    bbr_init_pacing_rate(r);
    bbr_enter_startup(r);
}

// 4.1.1.3.  Tracking Time for the BBR.BtlBw Max Filter
fn bbr_init_round_counting(r: &mut Recovery) {
    let bbr = &mut r.bbr_state;

    bbr.next_round_delivered = 0;
    bbr.round_start = false;
    bbr.round_count = 0;
}

// 4.2.1.  Pacing Rate
fn bbr_init_pacing_rate(r: &mut Recovery) {
    let bbr = &mut r.bbr_state;

    let srtt = r
        .smoothed_rtt
        .unwrap_or_else(|| Duration::from_millis(1))
        .as_secs_f64();

    // At init, cwnd is initcwnd.
    let nominal_bandwidth = r.congestion_window as f64 / srtt;

    bbr.pacing_rate = (bbr.pacing_gain * nominal_bandwidth) as u64;
}

// 4.3.2.1.  Startup Dynamics
pub fn bbr_enter_startup(r: &mut Recovery) {
    let bbr = &mut r.bbr_state;

    bbr.state = BBRStateMachine::Startup;
    bbr.pacing_gain = BBR_HIGH_GAIN;
    bbr.cwnd_gain = BBR_HIGH_GAIN;
}

// 4.3.2.2.  Estimating When Startup has Filled the Pipe
fn bbr_init_full_pipe(r: &mut Recovery) {
    let bbr = &mut r.bbr_state;

    bbr.filled_pipe = false;
    bbr.full_bw = 0;
    bbr.full_bw_count = 0;
}
