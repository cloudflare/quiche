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

use std::time::Duration;

use crate::recovery::Recovery;

// BBR2 Transmit Packet Pacing Functions
//

// 4.6.2.  Pacing Rate: BBR.pacing_rate
pub fn bbr2_init_pacing_rate(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    let srtt = r
        .smoothed_rtt
        .unwrap_or_else(|| Duration::from_millis(1))
        .as_secs_f64();

    // At init, cwnd is initcwnd.
    let nominal_bandwidth = r.congestion_window as f64 / srtt;

    bbr.pacing_rate = (STARTUP_PACING_GAIN * nominal_bandwidth) as u64;
    bbr.init_pacing_rate = (STARTUP_PACING_GAIN * nominal_bandwidth) as u64;
}

pub fn bbr2_set_pacing_rate_with_gain(r: &mut Recovery, pacing_gain: f64) {
    let rate = (pacing_gain *
        r.bbr2_state.bw as f64 *
        (1.0 - PACING_MARGIN_PERCENT)) as u64;

    if r.bbr2_state.filled_pipe ||
        rate > r.bbr2_state.pacing_rate ||
        r.bbr2_state.pacing_rate == r.bbr2_state.init_pacing_rate
    {
        r.bbr2_state.pacing_rate = rate;
    }
}

pub fn bbr2_set_pacing_rate(r: &mut Recovery) {
    bbr2_set_pacing_rate_with_gain(r, r.bbr2_state.pacing_gain);
}
