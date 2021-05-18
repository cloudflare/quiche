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

/// 24Mbps in bytes/sec
const PACING_RATE_24MBPS: u64 = 24 * 1000 * 1000 / 8;

/// The minimal cwnd value BBR tries to target, in bytes
#[inline]
fn bbr_min_pipe_cwnd(r: &mut Recovery) -> usize {
    BBR_MIN_PIPE_CWND_PKTS * r.max_datagram_size
}

// BBR Functions when ACK is received.
//
pub fn bbr_update_model_and_state(
    r: &mut Recovery, packet: &Acked, now: Instant,
) {
    bbr_update_btlbw(r, packet);
    bbr_check_cycle_phase(r, now);
    bbr_check_full_pipe(r);
    bbr_check_drain(r, now);
    bbr_update_rtprop(r, now);
    bbr_check_probe_rtt(r, now);
}

pub fn bbr_update_control_parameters(r: &mut Recovery, now: Instant) {
    pacing::bbr_set_pacing_rate(r);
    bbr_set_send_quantum(r);

    // Set outgoing packet pacing rate
    // It is called here because send_quantum may be updated too.
    r.set_pacing_rate(r.bbr_state.pacing_rate, now);

    bbr_set_cwnd(r);
}

// BBR Functions while processing ACKs.
//

// 4.1.1.5.  Updating the BBR.BtlBw Max Filter
fn bbr_update_btlbw(r: &mut Recovery, packet: &Acked) {
    bbr_update_round(r, packet);

    if r.delivery_rate() >= r.bbr_state.btlbw ||
        !r.delivery_rate.sample_is_app_limited()
    {
        // Since minmax filter is based on time,
        // start_time + (round_count as seconds) is used instead.
        r.bbr_state.btlbw = r.bbr_state.btlbwfilter.running_max(
            BTLBW_FILTER_LEN,
            r.bbr_state.start_time + Duration::from_secs(r.bbr_state.round_count),
            r.delivery_rate(),
        );
    }
}

// 4.1.1.3 Tracking Time for the BBR.BtlBw Max Filter
fn bbr_update_round(r: &mut Recovery, packet: &Acked) {
    let bbr = &mut r.bbr_state;

    if packet.delivered >= bbr.next_round_delivered {
        bbr.next_round_delivered = r.delivery_rate.delivered();
        bbr.round_count += 1;
        bbr.round_start = true;
        bbr.packet_conservation = false;
    } else {
        bbr.round_start = false;
    }
}

// 4.1.2.3. Updating the BBR.RTprop Min Filter
fn bbr_update_rtprop(r: &mut Recovery, now: Instant) {
    let bbr = &mut r.bbr_state;
    let rs_rtt = r.delivery_rate.sample_rtt();

    bbr.rtprop_expired = now > bbr.rtprop_stamp + RTPROP_FILTER_LEN;

    if !rs_rtt.is_zero() && (rs_rtt <= bbr.rtprop || bbr.rtprop_expired) {
        bbr.rtprop = rs_rtt;
        bbr.rtprop_stamp = now;
    }
}

// 4.2.2 Send Quantum
fn bbr_set_send_quantum(r: &mut Recovery) {
    let rate = r.bbr_state.pacing_rate;

    r.send_quantum = match rate {
        rate if rate < PACING_RATE_1_2MBPS => r.max_datagram_size,

        rate if rate < PACING_RATE_24MBPS => 2 * r.max_datagram_size,

        _ => cmp::min((rate / 1000_u64) as usize, 64 * 1024),
    }
}

// 4.2.3.2 Target cwnd
fn bbr_inflight(r: &mut Recovery, gain: f64) -> usize {
    let bbr = &mut r.bbr_state;

    if bbr.rtprop == Duration::MAX {
        return r.max_datagram_size * INITIAL_WINDOW_PACKETS;
    }

    let quanta = 3 * r.send_quantum;
    let estimated_bdp = bbr.btlbw as f64 * bbr.rtprop.as_secs_f64();

    (gain * estimated_bdp) as usize + quanta
}

fn bbr_update_target_cwnd(r: &mut Recovery) {
    r.bbr_state.target_cwnd = bbr_inflight(r, r.bbr_state.cwnd_gain);
}

// 4.2.3.4 Modulating cwnd in Loss Recovery
pub fn bbr_save_cwnd(r: &mut Recovery) -> usize {
    if !r.bbr_state.in_recovery && r.bbr_state.state != BBRStateMachine::ProbeRTT
    {
        r.congestion_window
    } else {
        r.congestion_window.max(r.bbr_state.prior_cwnd)
    }
}

pub fn bbr_restore_cwnd(r: &mut Recovery) {
    r.congestion_window = r.congestion_window.max(r.bbr_state.prior_cwnd);
}

fn bbr_modulate_cwnd_for_recovery(r: &mut Recovery) {
    let acked_bytes = r.bbr_state.newly_acked_bytes;
    let lost_bytes = r.bbr_state.newly_lost_bytes;

    if lost_bytes > 0 {
        // QUIC mininum cwnd is 2 x MSS.
        r.congestion_window = r
            .congestion_window
            .saturating_sub(lost_bytes)
            .max(r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS);
    }

    if r.bbr_state.packet_conservation {
        r.congestion_window =
            r.congestion_window.max(r.bytes_in_flight + acked_bytes);
    }
}

// 4.2.3.5 Modulating cwnd in ProbeRTT
fn bbr_modulate_cwnd_for_probe_rtt(r: &mut Recovery) {
    if r.bbr_state.state == BBRStateMachine::ProbeRTT {
        r.congestion_window = r.congestion_window.min(bbr_min_pipe_cwnd(r))
    }
}

// 4.2.3.6 Core cwnd Adjustment Mechanism
fn bbr_set_cwnd(r: &mut Recovery) {
    let acked_bytes = r.bbr_state.newly_acked_bytes;

    bbr_update_target_cwnd(r);
    bbr_modulate_cwnd_for_recovery(r);

    if !r.bbr_state.packet_conservation {
        if r.bbr_state.filled_pipe {
            r.congestion_window = cmp::min(
                r.congestion_window + acked_bytes,
                r.bbr_state.target_cwnd,
            )
        } else if r.congestion_window < r.bbr_state.target_cwnd ||
            r.delivery_rate.delivered() <
                r.max_datagram_size * INITIAL_WINDOW_PACKETS
        {
            r.congestion_window += acked_bytes;
        }

        r.congestion_window = r.congestion_window.max(bbr_min_pipe_cwnd(r))
    }

    bbr_modulate_cwnd_for_probe_rtt(r);
}

// 4.3.2.2.  Estimating When Startup has Filled the Pipe
fn bbr_check_full_pipe(r: &mut Recovery) {
    // No need to check for a full pipe now.
    if r.bbr_state.filled_pipe ||
        !r.bbr_state.round_start ||
        r.delivery_rate.sample_is_app_limited()
    {
        return;
    }

    // BBR.BtlBw still growing?
    if r.bbr_state.btlbw >=
        (r.bbr_state.full_bw as f64 * BTLBW_GROWTH_TARGET) as u64
    {
        // record new baseline level
        r.bbr_state.full_bw = r.bbr_state.btlbw;
        r.bbr_state.full_bw_count = 0;
        return;
    }

    // another round w/o much growth
    r.bbr_state.full_bw_count += 1;

    if r.bbr_state.full_bw_count >= 3 {
        r.bbr_state.filled_pipe = true;
    }
}

// 4.3.3.  Drain
fn bbr_enter_drain(r: &mut Recovery) {
    let bbr = &mut r.bbr_state;

    bbr.state = BBRStateMachine::Drain;

    // pace slowly
    bbr.pacing_gain = 1.0 / BBR_HIGH_GAIN;

    // maintain cwnd
    bbr.cwnd_gain = BBR_HIGH_GAIN;
}

fn bbr_check_drain(r: &mut Recovery, now: Instant) {
    if r.bbr_state.state == BBRStateMachine::Startup && r.bbr_state.filled_pipe {
        bbr_enter_drain(r);
    }

    if r.bbr_state.state == BBRStateMachine::Drain &&
        r.bytes_in_flight <= bbr_inflight(r, 1.0)
    {
        // we estimate queue is drained
        bbr_enter_probe_bw(r, now);
    }
}

// 4.3.4.3.  Gain Cycling Algorithm
fn bbr_enter_probe_bw(r: &mut Recovery, now: Instant) {
    let bbr = &mut r.bbr_state;

    bbr.state = BBRStateMachine::ProbeBW;
    bbr.pacing_gain = 1.0;
    bbr.cwnd_gain = 2.0;

    // cycle_index will be one of (1, 2, 3, 4, 5, 6, 7). Since
    // bbr_advance_cycle_phase() is called right next and it will
    // increase cycle_index by 1, the actual cycle_index in the
    // beginning of ProbeBW will be one of (2, 3, 4, 5, 6, 7, 0)
    // to avoid index 1 (pacing_gain=3/4). See 4.3.4.2 for details.
    bbr.cycle_index = BBR_GAIN_CYCLE_LEN -
        1 -
        (rand::rand_u64_uniform(BBR_GAIN_CYCLE_LEN as u64 - 1) as usize);

    bbr_advance_cycle_phase(r, now);
}

fn bbr_check_cycle_phase(r: &mut Recovery, now: Instant) {
    let bbr = &mut r.bbr_state;

    if bbr.state == BBRStateMachine::ProbeBW && bbr_is_next_cycle_phase(r, now) {
        bbr_advance_cycle_phase(r, now);
    }
}

fn bbr_advance_cycle_phase(r: &mut Recovery, now: Instant) {
    let bbr = &mut r.bbr_state;

    bbr.cycle_stamp = now;
    bbr.cycle_index = (bbr.cycle_index + 1) % BBR_GAIN_CYCLE_LEN;
    bbr.pacing_gain = PACING_GAIN_CYCLE[bbr.cycle_index];
}

fn bbr_is_next_cycle_phase(r: &mut Recovery, now: Instant) -> bool {
    let bbr = &mut r.bbr_state;
    let lost_bytes = bbr.newly_lost_bytes;
    let pacing_gain = bbr.pacing_gain;
    let prior_in_flight = bbr.prior_bytes_in_flight;

    let is_full_length = (now - bbr.cycle_stamp) > bbr.rtprop;

    // pacing_gain == 1.0
    if (pacing_gain - 1.0).abs() < f64::EPSILON {
        return is_full_length;
    }

    if pacing_gain > 1.0 {
        return is_full_length &&
            (lost_bytes > 0 ||
                prior_in_flight >= bbr_inflight(r, pacing_gain));
    }

    is_full_length || prior_in_flight <= bbr_inflight(r, 1.0)
}

// 4.3.5.  ProbeRTT
fn bbr_check_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr_state.state != BBRStateMachine::ProbeRTT &&
        r.bbr_state.rtprop_expired &&
        !r.bbr_state.idle_restart
    {
        bbr_enter_probe_rtt(r);

        r.bbr_state.prior_cwnd = bbr_save_cwnd(r);
        r.bbr_state.probe_rtt_done_stamp = None;
    }

    if r.bbr_state.state == BBRStateMachine::ProbeRTT {
        bbr_handle_probe_rtt(r, now);
    }

    r.bbr_state.idle_restart = false;
}

fn bbr_enter_probe_rtt(r: &mut Recovery) {
    let bbr = &mut r.bbr_state;

    bbr.state = BBRStateMachine::ProbeRTT;
    bbr.pacing_gain = 1.0;
    bbr.cwnd_gain = 1.0;
}

fn bbr_handle_probe_rtt(r: &mut Recovery, now: Instant) {
    // Ignore low rate samples during ProbeRTT.
    r.delivery_rate.update_app_limited(true);

    if let Some(probe_rtt_done_stamp) = r.bbr_state.probe_rtt_done_stamp {
        if r.bbr_state.round_start {
            r.bbr_state.probe_rtt_round_done = true;
        }

        if r.bbr_state.probe_rtt_round_done && now > probe_rtt_done_stamp {
            r.bbr_state.rtprop_stamp = now;

            bbr_restore_cwnd(r);
            bbr_exit_probe_rtt(r, now);
        }
    } else if r.bytes_in_flight <= bbr_min_pipe_cwnd(r) {
        r.bbr_state.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
        r.bbr_state.probe_rtt_round_done = false;
        r.bbr_state.next_round_delivered = r.delivery_rate.delivered();
    }
}

fn bbr_exit_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr_state.filled_pipe {
        bbr_enter_probe_bw(r, now);
    } else {
        init::bbr_enter_startup(r);
    }
}
