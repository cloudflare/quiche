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
use crate::rand;
use crate::recovery;

use std::cmp;
use std::time::Instant;

/// 1.2Mbps in bytes/sec
const PACING_RATE_1_2MBPS: u64 = 1200 * 1000 / 8;

/// The minimal cwnd value BBR2 tries to target, in bytes
#[inline]
fn bbr2_min_pipe_cwnd(r: &mut Recovery) -> usize {
    MIN_PIPE_CWND_PKTS * r.max_datagram_size
}

// BBR2 Functions when ACK is received.
//
pub fn bbr2_update_model_and_state(
    r: &mut Recovery, packet: &Acked, now: Instant,
) {
    per_loss::bbr2_update_latest_delivery_signals(r);
    per_loss::bbr2_update_congestion_signals(r, packet);
    bbr2_update_ack_aggregation(r, packet, now);
    bbr2_check_startup_done(r);
    bbr2_check_drain(r, now);
    bbr2_update_probe_bw_cycle_phase(r, now);
    bbr2_update_min_rtt(r, now);
    bbr2_check_probe_rtt(r, now);
    per_loss::bbr2_advance_latest_delivery_signals(r);
    per_loss::bbr2_bound_bw_for_model(r);
}

pub fn bbr2_update_control_parameters(r: &mut Recovery, now: Instant) {
    pacing::bbr2_set_pacing_rate(r);
    bbr2_set_send_quantum(r);

    // Set outgoing packet pacing rate
    // It is called here because send_quantum may be updated too.
    r.set_pacing_rate(r.bbr2_state.pacing_rate, now);

    bbr2_set_cwnd(r);
}

// BBR2 Functions while processing ACKs.
//

// 4.3.1.1.  Startup Dynamics
fn bbr2_check_startup_done(r: &mut Recovery) {
    bbr2_check_startup_full_bandwidth(r);
    bbr2_check_startup_high_loss(r);

    if r.bbr2_state.state == BBR2StateMachine::Startup && r.bbr2_state.filled_pipe
    {
        bbr2_enter_drain(r);
    }
}

// 4.3.1.2.  Exiting Startup Based on Bandwidth Plateau
fn bbr2_check_startup_full_bandwidth(r: &mut Recovery) {
    if r.bbr2_state.filled_pipe ||
        !r.bbr2_state.round_start ||
        r.delivery_rate.sample_is_app_limited()
    {
        // No need to check for a full pipe now.
        return;
    }

    // Still growing?
    if r.bbr2_state.max_bw >=
        (r.bbr2_state.full_bw as f64 * MAX_BW_GROWTH_THRESHOLD) as u64
    {
        // Record new baseline level
        r.bbr2_state.full_bw = r.bbr2_state.max_bw;
        r.bbr2_state.full_bw_count = 0;
        return;
    }

    // Another round w/o much growth
    r.bbr2_state.full_bw_count += 1;

    if r.bbr2_state.full_bw_count >= MAX_BW_COUNT {
        r.bbr2_state.filled_pipe = true;
    }
}

// 4.3.1.3.  Exiting Startup Based on Packet Loss
fn bbr2_check_startup_high_loss(r: &mut Recovery) {
    // TODO: this is not implemented (not in the draft)
    if r.bbr2_state.loss_round_start &&
        r.bbr2_state.in_recovery &&
        r.bbr2_state.loss_events_in_round >= FULL_LOSS_COUNT as usize &&
        per_loss::bbr2_is_inflight_too_high(r)
    {
        bbr2_handle_queue_too_high_in_startup(r);
    }
    if r.bbr2_state.loss_round_start {
        r.bbr2_state.loss_events_in_round = 0
    }
}

fn bbr2_handle_queue_too_high_in_startup(r: &mut Recovery) {
    r.bbr2_state.filled_pipe = true;
    r.bbr2_state.inflight_hi = bbr2_inflight(r, r.bbr2_state.max_bw, 1.0);
}

// 4.3.2.  Drain
fn bbr2_enter_drain(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.state = BBR2StateMachine::Drain;

    // pace slowly
    bbr.pacing_gain = PACING_GAIN / STARTUP_CWND_GAIN;

    // maintain cwnd
    bbr.cwnd_gain = STARTUP_CWND_GAIN;
}

fn bbr2_check_drain(r: &mut Recovery, now: Instant) {
    if r.bbr2_state.state == BBR2StateMachine::Drain &&
        r.bytes_in_flight <= bbr2_inflight(r, r.bbr2_state.max_bw, 1.0)
    {
        // BBR estimates the queue was drained
        bbr2_enter_probe_bw(r, now);
    }
}

// 4.3.3.  ProbeBW
// 4.3.3.5.3.  Design Considerations for Choosing Constant Parameters
fn bbr2_check_time_to_probe_bw(r: &mut Recovery, now: Instant) -> bool {
    // Is it time to transition from DOWN or CRUISE to REFILL?
    if bbr2_has_elapsed_in_phase(r, r.bbr2_state.bw_probe_wait, now) ||
        bbr2_is_reno_coexistence_probe_time(r)
    {
        bbr2_start_probe_bw_refill(r);

        return true;
    }

    false
}

// Randomized decision about how long to wait until
// probing for bandwidth, using round count and wall clock.
fn bbr2_pick_probe_wait(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    // Decide random round-trip bound for wait
    bbr.rounds_since_probe = rand::rand_u8() as usize % 2;

    // Decide the random wall clock bound for wait
    bbr.bw_probe_wait = Duration::from_secs_f64(
        2.0 + rand::rand_u64_uniform(1000000) as f64 / 1000000.0,
    );
}

fn bbr2_is_reno_coexistence_probe_time(r: &mut Recovery) -> bool {
    let reno_rounds = bbr2_target_inflight(r);
    let rounds = reno_rounds.min(63);

    r.bbr2_state.rounds_since_probe >= rounds
}

// How much data do we want in flight?
// Our estimated BDP, unless congestion cut cwnd.
pub fn bbr2_target_inflight(r: &mut Recovery) -> usize {
    r.bbr2_state.bdp.min(r.congestion_window)
}

// 4.3.3.6.  ProbeBW Algorithm Details
fn bbr2_enter_probe_bw(r: &mut Recovery, now: Instant) {
    bbr2_start_probe_bw_down(r, now);
}

pub fn bbr2_start_probe_bw_down(r: &mut Recovery, now: Instant) {
    per_loss::bbr2_reset_congestion_signals(r);

    // not growing inflight_hi
    r.bbr2_state.probe_up_cnt = usize::MAX;

    bbr2_pick_probe_wait(r);

    // start wall clock
    r.bbr2_state.cycle_stamp = now;
    r.bbr2_state.ack_phase = BBR2AckPhase::ProbeStopping;

    bbr2_start_round(r);

    r.bbr2_state.state = BBR2StateMachine::ProbeBWDOWN;
    r.bbr2_state.pacing_gain = PROBE_DOWN_PACING_GAIN;
    r.bbr2_state.cwnd_gain = CWND_GAIN
}

fn bbr2_start_probe_bw_cruise(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.state = BBR2StateMachine::ProbeBWCRUISE;
    bbr.pacing_gain = PACING_GAIN;
    bbr.cwnd_gain = CWND_GAIN;
}

fn bbr2_start_probe_bw_refill(r: &mut Recovery) {
    per_loss::bbr2_reset_lower_bounds(r);

    r.bbr2_state.bw_probe_up_rounds = 0;
    r.bbr2_state.bw_probe_up_acks = 0;
    r.bbr2_state.ack_phase = BBR2AckPhase::Refilling;

    bbr2_start_round(r);

    r.bbr2_state.state = BBR2StateMachine::ProbeBWREFILL;
    r.bbr2_state.pacing_gain = PACING_GAIN;
    r.bbr2_state.cwnd_gain = CWND_GAIN;
}

fn bbr2_start_probe_bw_up(r: &mut Recovery, now: Instant) {
    r.bbr2_state.ack_phase = BBR2AckPhase::ProbeStarting;

    bbr2_start_round(r);

    // Start wall clock.
    r.bbr2_state.cycle_stamp = now;
    r.bbr2_state.state = BBR2StateMachine::ProbeBWUP;
    r.bbr2_state.pacing_gain = PROBE_UP_PACING_GAIN;
    r.bbr2_state.cwnd_gain = CWND_GAIN;

    bbr2_raise_inflight_hi_slope(r);
}

// The core state machine logic for ProbeBW
fn bbr2_update_probe_bw_cycle_phase(r: &mut Recovery, now: Instant) {
    if !r.bbr2_state.filled_pipe {
        // only handling steady-state behavior here
        return;
    }

    bbr2_adapt_upper_bounds(r, now);

    if !bbr2_is_in_a_probe_bw_state(r) {
        // only handling ProbeBW states here
        return;
    }

    match r.bbr2_state.state {
        BBR2StateMachine::ProbeBWDOWN => {
            if bbr2_check_time_to_probe_bw(r, now) {
                // Already decided state transition.
                return;
            }

            if bbr2_check_time_to_cruise(r) {
                bbr2_start_probe_bw_cruise(r);
            }
        },

        BBR2StateMachine::ProbeBWCRUISE => {
            bbr2_check_time_to_probe_bw(r, now);
        },

        BBR2StateMachine::ProbeBWREFILL => {
            // After one round of REFILL, start UP.
            if r.bbr2_state.round_start {
                r.bbr2_state.bw_probe_samples = true;

                bbr2_start_probe_bw_up(r, now);
            }
        },

        BBR2StateMachine::ProbeBWUP => {
            if bbr2_has_elapsed_in_phase(r, r.bbr2_state.min_rtt, now) &&
                r.bytes_in_flight > bbr2_inflight(r, r.bbr2_state.max_bw, 1.25)
            {
                bbr2_start_probe_bw_down(r, now);
            }
        },

        _ => (),
    }
}

pub fn bbr2_is_in_a_probe_bw_state(r: &mut Recovery) -> bool {
    let state = r.bbr2_state.state;

    state == BBR2StateMachine::ProbeBWDOWN ||
        state == BBR2StateMachine::ProbeBWCRUISE ||
        state == BBR2StateMachine::ProbeBWREFILL ||
        state == BBR2StateMachine::ProbeBWUP
}

fn bbr2_check_time_to_cruise(r: &mut Recovery) -> bool {
    if r.bytes_in_flight > bbr2_inflight_with_headroom(r) {
        // Not enough headroom.
        return false;
    }

    if r.bytes_in_flight <= bbr2_inflight(r, r.bbr2_state.max_bw, 1.0) {
        // inflight <= estimated BDP
        return true;
    }

    false
}

fn bbr2_has_elapsed_in_phase(
    r: &mut Recovery, interval: Duration, now: Instant,
) -> bool {
    now > r.bbr2_state.cycle_stamp + interval
}

// Return a volume of data that tries to leave free
// headroom in the bottleneck buffer or link for
// other flows, for fairness convergence and lower
// RTTs and loss
fn bbr2_inflight_with_headroom(r: &mut Recovery) -> usize {
    let bbr = &mut r.bbr2_state;

    if bbr.inflight_hi == usize::MAX {
        return usize::MAX;
    }

    let headroom = ((HEADROOM * bbr.inflight_hi as f64) as usize).max(1);

    bbr.inflight_hi
        .saturating_sub(headroom)
        .max(bbr2_min_pipe_cwnd(r))
}

// Raise inflight_hi slope if appropriate.
fn bbr2_raise_inflight_hi_slope(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    let growth_this_round = (1 << bbr.bw_probe_up_rounds) * r.max_datagram_size;

    bbr.bw_probe_up_rounds = (bbr.bw_probe_up_rounds + 1).min(30);
    bbr.probe_up_cnt = (r.congestion_window / growth_this_round).max(1);
}

// Increase inflight_hi if appropriate.
fn bbr2_probe_inflight_hi_upward(r: &mut Recovery) {
    if r.app_limited() || r.congestion_window < r.bbr2_state.inflight_hi {
        // Not fully using inflight_hi, so don't grow it.
        return;
    }

    let bbr = &mut r.bbr2_state;

    // bw_probe_up_acks is a packet count.
    bbr.bw_probe_up_acks += 1;

    if bbr.bw_probe_up_acks >= bbr.probe_up_cnt {
        let delta = bbr.bw_probe_up_acks / bbr.probe_up_cnt;

        bbr.bw_probe_up_acks -= delta * bbr.probe_up_cnt;

        bbr.inflight_hi += delta * r.max_datagram_size;
    }

    if bbr.round_start {
        bbr2_raise_inflight_hi_slope(r);
    }
}

// Track ACK state and update bbr.max_bw window and
// bbr.inflight_hi and bbr.bw_hi.
fn bbr2_adapt_upper_bounds(r: &mut Recovery, now: Instant) {
    if r.bbr2_state.ack_phase == BBR2AckPhase::ProbeStarting &&
        r.bbr2_state.round_start
    {
        // Starting to get bw probing samples.
        r.bbr2_state.ack_phase = BBR2AckPhase::ProbeFeedback;
    }

    if r.bbr2_state.ack_phase == BBR2AckPhase::ProbeStopping &&
        r.bbr2_state.round_start
    {
        r.bbr2_state.bw_probe_samples = false;
        r.bbr2_state.ack_phase = BBR2AckPhase::Init;

        // End of samples from bw probing phase.
        if bbr2_is_in_a_probe_bw_state(r) &&
            !r.delivery_rate.sample_is_app_limited()
        {
            bbr2_advance_max_bw_filter(r);
        }
    }

    if !per_loss::bbr2_check_inflight_too_high(r, now) {
        // Loss rate is safe. Adjust upper bounds upward.
        if r.bbr2_state.inflight_hi == usize::MAX ||
            r.bbr2_state.bw_hi == u64::MAX
        {
            // No upper bounds to raise.
            return;
        }

        if r.bbr2_state.tx_in_flight > r.bbr2_state.inflight_hi {
            r.bbr2_state.inflight_hi = r.bbr2_state.tx_in_flight;
        }

        // TODO: what's rs.bw???
        if r.delivery_rate() > r.bbr2_state.bw_hi {
            r.bbr2_state.bw_hi = r.delivery_rate();
        }

        if r.bbr2_state.state == BBR2StateMachine::ProbeBWUP {
            bbr2_probe_inflight_hi_upward(r);
        }
    }
}

// 4.3.4. ProbeRTT
// 4.3.4.4.  ProbeRTT Logic
fn bbr2_update_min_rtt(r: &mut Recovery, now: Instant) {
    let bbr = &mut r.bbr2_state;

    bbr.probe_rtt_expired = now > bbr.probe_rtt_min_stamp + PROBE_RTT_INTERVAL;

    let rs_rtt = r.delivery_rate.sample_rtt();

    if !rs_rtt.is_zero() &&
        (rs_rtt < bbr.probe_rtt_min_delay || bbr.probe_rtt_expired)
    {
        bbr.probe_rtt_min_delay = rs_rtt;
        bbr.probe_rtt_min_stamp = now;
    }

    let min_rtt_expired =
        now > bbr.min_rtt_stamp + rs_rtt.saturating_mul(MIN_RTT_FILTER_LEN);

    // To do: Figure out Probe RTT logic
    // if bbr.probe_rtt_min_delay < bbr.min_rtt ||  bbr.min_rtt == INITIAL_RTT ||
    // min_rtt_expired {
    if bbr.min_rtt == INITIAL_RTT || min_rtt_expired {
        // bbr.min_rtt = bbr.probe_rtt_min_delay;
        // bbr.min_rtt_stamp = bbr.probe_rtt_min_stamp;
        bbr.min_rtt = rs_rtt;
        bbr.min_rtt_stamp = now;
    }
}

fn bbr2_check_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr2_state.state != BBR2StateMachine::ProbeRTT &&
        r.bbr2_state.probe_rtt_expired &&
        !r.bbr2_state.idle_restart
    {
        bbr2_enter_probe_rtt(r);

        r.bbr2_state.prior_cwnd = per_ack::bbr2_save_cwnd(r);
        r.bbr2_state.probe_rtt_done_stamp = None;
        r.bbr2_state.ack_phase = BBR2AckPhase::ProbeStopping;

        bbr2_start_round(r);
    }

    if r.bbr2_state.state == BBR2StateMachine::ProbeRTT {
        bbr2_handle_probe_rtt(r, now);
    }

    if r.delivery_rate.sample_delivered() > 0 {
        r.bbr2_state.idle_restart = false;
    }
}

fn bbr2_enter_probe_rtt(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    bbr.state = BBR2StateMachine::ProbeRTT;
    bbr.pacing_gain = PACING_GAIN;
    bbr.cwnd_gain = PROBE_RTT_CWND_GAIN;
}

fn bbr2_handle_probe_rtt(r: &mut Recovery, now: Instant) {
    // Ignore low rate samples during ProbeRTT.
    r.delivery_rate.update_app_limited(true);

    if r.bbr2_state.probe_rtt_done_stamp.is_some() {
        if r.bbr2_state.round_start {
            r.bbr2_state.probe_rtt_round_done = true;
        }

        if r.bbr2_state.probe_rtt_round_done {
            bbr2_check_probe_rtt_done(r, now);
        }
    } else if r.bytes_in_flight <= bbr2_probe_rtt_cwnd(r) {
        // Wait for at least ProbeRTTDuration to elapse.
        r.bbr2_state.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);

        // Wait for at lease one round to elapse.
        r.bbr2_state.probe_rtt_round_done = false;

        bbr2_start_round(r);
    }
}

pub fn bbr2_check_probe_rtt_done(r: &mut Recovery, now: Instant) {
    let bbr = &mut r.bbr2_state;

    if let Some(probe_rtt_done_stamp) = bbr.probe_rtt_done_stamp {
        if now > probe_rtt_done_stamp {
            // Schedule next ProbeRTT.
            bbr.probe_rtt_min_stamp = now;

            bbr2_restore_cwnd(r);
            bbr2_exit_probe_rtt(r, now);
        }
    }
}

// 4.3.4.5.  Exiting ProbeRTT
fn bbr2_exit_probe_rtt(r: &mut Recovery, now: Instant) {
    per_loss::bbr2_reset_lower_bounds(r);

    if r.bbr2_state.filled_pipe {
        bbr2_start_probe_bw_down(r, now);
        bbr2_start_probe_bw_cruise(r);
    } else {
        init::bbr2_enter_startup(r);
    }
}

// 4.5.1.  BBR.round_count: Tracking Packet-Timed Round Trips
fn bbr2_update_round(r: &mut Recovery, packet: &Acked) {
    if packet.delivered >= r.bbr2_state.next_round_delivered {
        bbr2_start_round(r);

        r.bbr2_state.round_count += 1;
        r.bbr2_state.rounds_since_probe += 1;
        r.bbr2_state.round_start = true;
    } else {
        r.bbr2_state.round_start = false;
    }
}

fn bbr2_start_round(r: &mut Recovery) {
    r.bbr2_state.next_round_delivered = r.delivery_rate.delivered();
}

// 4.5.2.4.  Updating the BBR.max_bw Max Filter
pub fn bbr2_update_max_bw(r: &mut Recovery, packet: &Acked) {
    bbr2_update_round(r, packet);

    if r.delivery_rate() >= r.bbr2_state.max_bw ||
        !r.delivery_rate.sample_is_app_limited()
    {
        let max_bw_filter_len = r
            .delivery_rate
            .sample_rtt()
            .saturating_mul(MIN_RTT_FILTER_LEN);

        r.bbr2_state.max_bw = r.bbr2_state.max_bw_filter.running_max(
            max_bw_filter_len,
            r.bbr2_state.start_time +
                Duration::from_secs(r.bbr2_state.cycle_count),
            r.delivery_rate(),
        );
    }
}

// 4.5.2.5.  Tracking Time for the BBR.max_bw Max Filter
fn bbr2_advance_max_bw_filter(r: &mut Recovery) {
    r.bbr2_state.cycle_count += 1;
}

// 4.5.4.  BBR.offload_budget
fn bbr2_update_offload_budget(r: &mut Recovery) {
    r.bbr2_state.offload_budget = 3 * r.send_quantum;
}

// 4.5.5.  BBR.extra_acked
fn bbr2_update_ack_aggregation(r: &mut Recovery, packet: &Acked, now: Instant) {
    let bbr = &mut r.bbr2_state;

    // Find excess ACKed beyond expected amount over this interval.
    let interval = now - bbr.extra_acked_interval_start;
    let mut expected_delivered =
        (bbr.bw as f64 * interval.as_secs_f64()) as usize;

    // Reset interval if ACK rate is below expected rate.
    if bbr.extra_acked_delivered <= expected_delivered {
        bbr.extra_acked_delivered = 0;
        bbr.extra_acked_interval_start = now;
        expected_delivered = 0;
    }

    bbr.extra_acked_delivered += packet.size;

    let extra = bbr.extra_acked_delivered.saturating_sub(expected_delivered);
    let extra = extra.min(r.congestion_window);

    let extra_acked_filter_len = r
        .delivery_rate
        .sample_rtt()
        .saturating_mul(MIN_RTT_FILTER_LEN);

    bbr.extra_acked = bbr.extra_acked_filter.running_max(
        extra_acked_filter_len,
        bbr.start_time + Duration::from_secs(bbr.round_count),
        extra,
    );
}

// 4.6.3.  Send Quantum: BBR.send_quantum
fn bbr2_set_send_quantum(r: &mut Recovery) {
    let bbr = &mut r.bbr2_state;

    let rate = bbr.pacing_rate;
    let floor = if rate < PACING_RATE_1_2MBPS {
        r.max_datagram_size
    } else {
        2 * r.max_datagram_size
    };

    r.send_quantum = cmp::min((rate / 1000_u64) as usize, 64 * 1024); // Assumes send buffer is limited to 64KB
    r.send_quantum = r.send_quantum.max(floor);
}

// 4.6.4.1.  Initial cwnd
// 4.6.4.2.  Computing BBR.max_inflight
fn bbr2_bdp_multiple(r: &mut Recovery, bw: u64, gain: f64) -> usize {
    let bbr = &mut r.bbr2_state;

    if bbr.min_rtt == Duration::MAX {
        // No valid RTT samples yet.
        return r.max_datagram_size * r.initial_congestion_window_packets;
    }

    bbr.bdp = (bw as f64 * bbr.min_rtt.as_secs_f64()) as usize;

    (gain * bbr.bdp as f64) as usize
}

fn bbr2_quantization_budget(r: &mut Recovery, inflight: usize) -> usize {
    bbr2_update_offload_budget(r);

    let inflight = inflight.max(r.bbr2_state.offload_budget);
    let inflight = inflight.max(bbr2_min_pipe_cwnd(r));

    // TODO: cycle_idx is unused
    if r.bbr2_state.state == BBR2StateMachine::ProbeBWUP {
        return inflight + 2 * r.max_datagram_size;
    }

    inflight
}

fn bbr2_inflight(r: &mut Recovery, bw: u64, gain: f64) -> usize {
    let inflight = bbr2_bdp_multiple(r, bw, gain);

    bbr2_quantization_budget(r, inflight)
}

fn bbr2_update_max_inflight(r: &mut Recovery) {
    // TODO: not implemented (not in the draft)
    // bbr2_update_aggregation_budget(r);

    let inflight =
        bbr2_bdp_multiple(r, r.bbr2_state.max_bw, r.bbr2_state.cwnd_gain);
    let inflight = inflight + r.bbr2_state.extra_acked;

    r.bbr2_state.max_inflight = bbr2_quantization_budget(r, inflight);
}

// 4.6.4.4.  Modulating cwnd in Loss Recovery
pub fn bbr2_save_cwnd(r: &mut Recovery) -> usize {
    if !r.bbr2_state.in_recovery &&
        r.bbr2_state.state != BBR2StateMachine::ProbeRTT
    {
        r.congestion_window
    } else {
        r.congestion_window.max(r.bbr2_state.prior_cwnd)
    }
}

pub fn bbr2_restore_cwnd(r: &mut Recovery) {
    r.congestion_window = r.congestion_window.max(r.bbr2_state.prior_cwnd);
}

fn bbr2_modulate_cwnd_for_recovery(r: &mut Recovery) {
    let acked_bytes = r.bbr2_state.newly_acked_bytes;
    let lost_bytes = r.bbr2_state.newly_lost_bytes;

    if lost_bytes > 0 {
        // QUIC mininum cwnd is 2 x MSS.
        r.congestion_window = r
            .congestion_window
            .saturating_sub(lost_bytes)
            .max(r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS);
    }

    if r.bbr2_state.packet_conservation {
        r.congestion_window =
            r.congestion_window.max(r.bytes_in_flight + acked_bytes);
    }
}

// 4.6.4.5.  Modulating cwnd in ProbeRTT
fn bbr2_probe_rtt_cwnd(r: &mut Recovery) -> usize {
    let probe_rtt_cwnd =
        bbr2_bdp_multiple(r, r.bbr2_state.bw, PROBE_RTT_CWND_GAIN);

    probe_rtt_cwnd.max(bbr2_min_pipe_cwnd(r))
}

fn bbr2_bound_cwnd_for_probe_rtt(r: &mut Recovery) {
    if r.bbr2_state.state == BBR2StateMachine::ProbeRTT {
        r.congestion_window = r.congestion_window.min(bbr2_probe_rtt_cwnd(r));
    }
}

// 4.6.4.6.  Core cwnd Adjustment Mechanism
fn bbr2_set_cwnd(r: &mut Recovery) {
    let acked_bytes = r.bbr2_state.newly_acked_bytes;

    bbr2_update_max_inflight(r);
    bbr2_modulate_cwnd_for_recovery(r);

    if !r.bbr2_state.packet_conservation {
        if r.bbr2_state.filled_pipe {
            r.congestion_window = cmp::min(
                r.congestion_window + acked_bytes,
                r.bbr2_state.max_inflight,
            )
        } else if r.congestion_window < r.bbr2_state.max_inflight ||
            r.delivery_rate.delivered() <
                r.max_datagram_size * r.initial_congestion_window_packets
        {
            r.congestion_window += acked_bytes;
        }

        r.congestion_window = r.congestion_window.max(bbr2_min_pipe_cwnd(r))
    }

    bbr2_bound_cwnd_for_probe_rtt(r);
    bbr2_bound_cwnd_for_model(r);
}

// 4.6.4.7.  Bounding cwnd Based on Recent Congestion
fn bbr2_bound_cwnd_for_model(r: &mut Recovery) {
    let mut cap = usize::MAX;

    if bbr2_is_in_a_probe_bw_state(r) &&
        r.bbr2_state.state != BBR2StateMachine::ProbeBWCRUISE
    {
        cap = r.bbr2_state.inflight_hi;
    } else if r.bbr2_state.state == BBR2StateMachine::ProbeRTT ||
        r.bbr2_state.state == BBR2StateMachine::ProbeBWCRUISE
    {
        cap = bbr2_inflight_with_headroom(r);
    }

    // Apply inflight_lo (possibly infinite).
    cap = cap.min(r.bbr2_state.inflight_lo);
    cap = cap.max(bbr2_min_pipe_cwnd(r));

    r.congestion_window = r.congestion_window.min(cap);
}
