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

// BBR2 Functions on every packet loss event.
//
// 4.2.4.  Per-Loss Steps
pub fn bbr2_update_on_loss(r: &mut Recovery, packet: &Sent, now: Instant) {
    bbr2_handle_lost_packet(r, packet, now);
}

// 4.5.6.  Updating the Model Upon Packet Loss
// 4.5.6.2.  Probing for Bandwidth In ProbeBW
pub fn bbr2_check_inflight_too_high(r: &mut Recovery, now: Instant) -> bool {
    if bbr2_is_inflight_too_high(r) {
        if r.bbr2_state.bw_probe_samples {
            bbr2_handle_inflight_too_high(r, now);
        }

        // inflight too high.
        return true;
    }

    // inflight not too high.
    false
}

pub fn bbr2_is_inflight_too_high(r: &mut Recovery) -> bool {
    r.bbr2_state.lost > (r.bbr2_state.tx_in_flight as f64 * LOSS_THRESH) as usize
}

fn bbr2_handle_inflight_too_high(r: &mut Recovery, now: Instant) {
    // Only react once per bw probe.
    r.bbr2_state.bw_probe_samples = false;

    if !r.delivery_rate.sample_is_app_limited() {
        r.bbr2_state.inflight_hi = r
            .bbr2_state
            .tx_in_flight
            .max((per_ack::bbr2_target_inflight(r) as f64 * BETA) as usize);
    }

    if r.bbr2_state.state == BBR2StateMachine::ProbeBWUP {
        per_ack::bbr2_start_probe_bw_down(r, now);
    }
}

fn bbr2_handle_lost_packet(r: &mut Recovery, packet: &Sent, now: Instant) {
    if !r.bbr2_state.bw_probe_samples {
        return;
    }

    r.bbr2_state.tx_in_flight = packet.tx_in_flight;
    r.bbr2_state.lost = (r.bytes_lost - packet.lost) as usize;

    r.delivery_rate_update_app_limited(packet.is_app_limited);

    if bbr2_is_inflight_too_high(r) {
        r.bbr2_state.tx_in_flight = bbr2_inflight_hi_from_lost_packet(r, packet);

        bbr2_handle_inflight_too_high(r, now);
    }
}

fn bbr2_inflight_hi_from_lost_packet(r: &mut Recovery, packet: &Sent) -> usize {
    let size = packet.size;
    let inflight_prev = r.bbr2_state.tx_in_flight - size;
    let lost_prev = r.bbr2_state.lost - size;
    let lost_prefix = (LOSS_THRESH * inflight_prev as f64 - lost_prev as f64) /
        (1.0 - LOSS_THRESH);

    inflight_prev + lost_prefix as usize
}

// 4.5.6.3.  When not Probing for Bandwidth
pub fn bbr2_update_latest_delivery_signals(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    // Near start of ACK processing.
    bbr.loss_round_start = false;
    bbr.bw_latest = bbr.bw_latest.max(r.delivery_rate.sample_delivery_rate());
    bbr.inflight_latest =
        bbr.inflight_latest.max(r.delivery_rate.sample_delivered());

    if r.delivery_rate.sample_prior_delivered() >= bbr.loss_round_delivered {
        bbr.loss_round_delivered = r.delivery_rate.delivered();
        bbr.loss_round_start = true;
    }
}

pub fn bbr2_advance_latest_delivery_signals(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    // Near end of ACK processing.
    if bbr.loss_round_start {
        bbr.bw_latest = r.delivery_rate.sample_delivery_rate();
        bbr.inflight_latest = r.delivery_rate.sample_delivered();
    }
}

pub fn bbr2_reset_congestion_signals(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.loss_in_round = false;
    bbr.loss_events_in_round = 0;
    bbr.bw_latest = 0;
    bbr.inflight_latest = 0;
}

pub fn bbr2_update_congestion_signals(r: &mut Recovery, packet: &Acked) {
    // Update congestion state on every ACK.
    per_ack::bbr2_update_max_bw(r, packet);

    if r.bbr2_state.lost > 0 {
        r.bbr2_state.loss_in_round = true;
        r.bbr2_state.loss_events_in_round += 1;
    }

    if !r.bbr2_state.loss_round_start {
        // Wait until end of round trip.
        return;
    }

    bbr2_adapt_lower_bounds_from_congestion(r);

    r.bbr2_state.loss_in_round = false;
    r.bbr2_state.loss_events_in_round = 0;
}

fn bbr2_adapt_lower_bounds_from_congestion(r: &mut Recovery) {
    // Once per round-trip respond to congestion.
    if bbr2_is_probing_bw(r) {
        return;
    }

    if r.bbr2_state.loss_in_round {
        bbr2_init_lower_bounds(r);
        bbr2_loss_lower_bounds(r);
    }
}

fn bbr2_init_lower_bounds(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    // Handle the first congestion episode in this cycle.
    if bbr.bw_lo == u64::MAX {
        bbr.bw_lo = bbr.max_bw;
    }

    if bbr.inflight_lo == usize::MAX {
        bbr.inflight_lo = r.congestion_window;
    }
}

fn bbr2_loss_lower_bounds(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    // Adjust model once per round based on loss.
    bbr.bw_lo = bbr.bw_latest.max((bbr.bw_lo as f64 * BETA) as u64);
    bbr.inflight_lo = bbr
        .inflight_latest
        .max((bbr.inflight_lo as f64 * BETA) as usize);
}

pub fn bbr2_reset_lower_bounds(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.bw_lo = u64::MAX;
    bbr.inflight_lo = usize::MAX;
}

pub fn bbr2_bound_bw_for_model(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.bw = bbr.max_bw.min(bbr.bw_lo.min(bbr.bw_hi));
}

// This function is not defined in the draft but used.
fn bbr2_is_probing_bw(r: &mut Recovery) -> bool {
    let state = r.bbr2_state.state;

    state == BBR2StateMachine::Startup ||
        state == BBR2StateMachine::ProbeBWREFILL ||
        state == BBR2StateMachine::ProbeBWUP
}
