// While writing this implementation, codebases written under open-source
// licenses were referenced. Attribution to those code bases follows:
//
// BBR Linux kernel module
// Copyright (c) 2013, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of Google Inc. nor the names of its contributors may
//       be used to endorse or promote products derived from this software
//       without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// BBR in Chromium quiche
// Copyright 2015 The Chromium Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! BBR Congestion Control
//!
//! This implementation is primarily based on the following draft:
//! <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>
//!
//! The following other code bases were also referenced where the RFC was
//! lacking:
//!
//! - BBR in the Linux kernel:
//! <https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/tree/net/ipv4/tcp_bbr.c>
//! - BBR in Chromium quiche:
//! <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>

use crate::minmax::Minmax;
use crate::packet;
use crate::rand;
use crate::recovery::Acked;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;
use std::f64::consts::LN_2;
use std::time::Duration;
use std::time::Instant;

/// Gains for startup and drain phases
const HIGH_GAIN: f64 = 2.0 / LN_2;
const LOW_GAIN: f64 = 1.0 / HIGH_GAIN;

/// Gains for ProbeBw
const NORMAL_PACING_GAIN: f64 = 1.0;
const NORMAL_CWND_GAIN: f64 = 2.0;

/// Time a RTT sample is valid for
const RTT_WINDOW: Duration = Duration::from_secs(10);

/// How long ProbeRtt should last
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);

/// Congestion window gain for ProbeRtt
const PROBE_RTT_CWND_GAIN: f64 = 1.0;

/// Number of RTTs a bandwidth sample is valid for
const BW_WINDOW: u32 = 10;

/// Smallest number of packets to keep in the network
const MIN_PIPE_CWND: usize = 4;

/// Gains to use during ProbeBw gain cycling
const PROBE_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// Minimum number of long-term sampling intervals
const LT_MIN_RTTS: u64 = 4;

/// Maximum amount of RTTs to wait for long-term to start before ending
/// sampling
const LT_MAX_SAMPLE_RTTS: u64 = 4 * LT_MIN_RTTS;

/// Maximum amount of RTTs long-term mode is on for
const LT_MAX_RTTS: u64 = 48;

/// Ratio of lost to delivered packets required for long-term mode to turn on
const LT_LOSS_THRESH: usize = 5;

/// Difference ratio for two bandwidth samples to be considered consistent
const LT_BW_RATIO: u64 = 8;

/// Absolute difference for two bandwidth samples to be considered consistent
const LT_BW_DIFF: u64 = 500;

pub static BBR: CongestionControlOps = CongestionControlOps {
    on_packet_sent,
    on_packet_acked,
    congestion_event,
    collapse_cwnd,
    checkpoint,
    rollback,
    has_custom_pacing,
};

/// BBR state variables
pub struct State {
    /// Current BBR state
    mode: Mode,

    /// Windowed maximum bottleneck bandwidth
    bw_filter: Minmax<u32, u64>,
    bw_max: u64,

    /// Round counting
    next_round_delivered: usize,
    round_start: bool,
    round_count: u32,

    /// Windowed minimum RTT
    rtt_min: Duration,
    rtt_stamp: Instant,
    rtt_expired: bool,
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,

    /// Pacing variables
    pacing_rate: u64,
    pacing_gain: f64,

    /// Startup end conditions
    filled_pipe: bool,
    full_bw: u64,
    full_bw_count: u64,

    /// Send quantum
    send_quantum: usize,

    /// Congestion window
    target_cwnd: usize,
    saved_cwnd: usize,
    cwnd_gain: f64,

    /// ProbeBw gain cycling
    probe_gain_idx: usize,
    cycle_stamp: Instant,

    /// Idle restart
    idle_restart: bool,

    /// Loss tracking
    bytes_lost: usize,
    bytes_last_lost: usize,
    bytes_newly_lost: usize,

    /// Packet conservation
    conservation: PacketConservation,
    end_conservation: usize,

    /// Long-term sampling
    lt_sampling: bool,
    lt_last_stamp: Instant,
    lt_last_delivered: usize,
    lt_last_lost: usize,
    lt_rtt_cnt: u64,
    lt_use_bw: bool,
    lt_bw: u64,
}

impl Default for State {
    fn default() -> Self {
        let now = Instant::now();

        State {
            bw_filter: Minmax::new(0, 0),
            bw_max: 0,
            mode: Mode::Startup,
            next_round_delivered: 0,
            round_start: false,
            round_count: 0,
            rtt_min: crate::recovery::INITIAL_RTT,
            rtt_stamp: now,
            rtt_expired: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            pacing_rate: 0,
            pacing_gain: HIGH_GAIN,
            filled_pipe: false,
            full_bw: 0,
            full_bw_count: 0,
            send_quantum: 0,
            target_cwnd: 0,
            saved_cwnd: 0,
            cwnd_gain: HIGH_GAIN,
            probe_gain_idx: 0,
            cycle_stamp: now,
            idle_restart: false,
            bytes_lost: 0,
            bytes_last_lost: 0,
            bytes_newly_lost: 0,
            conservation: PacketConservation::Normal,
            end_conservation: 0,
            lt_sampling: false,
            lt_last_stamp: now,
            lt_last_delivered: 0,
            lt_last_lost: 0,
            lt_rtt_cnt: 0,
            lt_use_bw: false,
            lt_bw: 0,
        }
    }
}

/// BBR states.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// Packet conservation states.
#[derive(Clone, Copy, Debug, PartialEq)]
enum PacketConservation {
    Conservation,
    Growth,
    Normal,
}

pub fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, _now: Instant) {
    handle_restart_from_idle(r);
    r.bytes_in_flight += sent_bytes;
}

fn on_packet_acked(
    r: &mut Recovery, packet: &Acked, _epoch: packet::Epoch, now: Instant,
) {
    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(packet.size);

    // Update loss tracking
    r.bbr_state.bytes_newly_lost =
        r.bbr_state.bytes_lost - r.bbr_state.bytes_last_lost;
    r.bbr_state.bytes_last_lost = r.bbr_state.bytes_lost;

    // TODO: Account for ack aggregation
    update_bw(r, packet, now);
    check_cycle_phase(r, packet, now);
    check_full_pipe(r, packet);
    check_drain(r);
    update_rtt(r, now);
    check_probe_rtt(r, now);

    set_pacing_rate(r);
    set_send_quantum(r);
    set_cwnd(r, packet);
}

fn congestion_event(
    r: &mut Recovery, lost_bytes: usize, _time_sent: Instant,
    _epoch: packet::Epoch, _now: Instant,
) {
    r.bbr_state.bytes_lost += lost_bytes;

    if lost_bytes > 0 {
        // Start or extend packet conservation
        r.bbr_state.end_conservation = r.bytes_acked;

        if r.bbr_state.conservation == PacketConservation::Normal &&
            r.bbr_state.filled_pipe
        {
            // First loss outside startup, start packet conservation
            save_cwnd(r);
            r.bbr_state.conservation = PacketConservation::Conservation;

            // Drop congestion window to bytes in flight but allow for a fast
            // retransmit.
            r.congestion_window = r.bytes_in_flight + lost_bytes;

            // Extend the current round, conservation should last for at least
            // one RTT.
            r.bbr_state.next_round_delivered = r.bytes_acked;
        }
    }
}

pub fn collapse_cwnd(_r: &mut Recovery) {}

fn has_custom_pacing() -> bool {
    true
}

fn checkpoint(_r: &mut Recovery) {}

fn save_cwnd(r: &mut Recovery) {
    r.bbr_state.saved_cwnd = if r.bbr_state.conservation ==
        PacketConservation::Normal &&
        r.bbr_state.mode != Mode::ProbeRtt
    {
        r.congestion_window
    } else {
        std::cmp::max(r.bbr_state.saved_cwnd, r.congestion_window)
    }
}

fn rollback(_r: &mut Recovery) {}

fn restore_cwnd(r: &mut Recovery) {
    r.congestion_window =
        std::cmp::max(r.congestion_window, r.bbr_state.saved_cwnd);
}

fn update_bw(r: &mut Recovery, packet: &Acked, now: Instant) {
    update_round(r, packet);
    lt_bw_sampling(r, packet, now);

    let rate = r.delivery_rate();

    // Update filter with latest bandwidth samples, but ignore app limited
    // samples.
    if rate >= r.bbr_state.bw_max || !packet.is_app_limited {
        r.bbr_state.bw_max = r.bbr_state.bw_filter.running_max(
            BW_WINDOW,
            r.bbr_state.round_count,
            rate,
        );
    }
}

/// Long-term sampling mode designed to avoid incurring large amounts of packet
/// loss in the presence of traffic policers.
///
/// Basic idea is to start a sampling process when a packet is lost and measure
/// the ratio between lost and delivered packets. If over 20% of packets are
/// lost, assume we're in the presence of a token bucket policer and use a
/// long-term average bandwidth measurement instead of the normal measurement.
///
/// After a large number of RTTs, the long-term measurement should expire to
/// allow BBR to detect any changes in network capacity.
fn lt_bw_sampling(r: &mut Recovery, packet: &Acked, now: Instant) {
    if r.bbr_state.lt_use_bw {
        // We're already using the long-term rate, track RTTs and reset if
        // the measurement has expired.
        if r.bbr_state.mode == Mode::ProbeBw && r.bbr_state.round_start {
            r.bbr_state.lt_rtt_cnt += 1;
            if r.bbr_state.lt_rtt_cnt >= LT_MAX_RTTS {
                lt_reset(r, now);
                enter_probe_bw(r);
            }
        }

        return;
    }

    if !r.bbr_state.lt_sampling {
        if r.bbr_state.bytes_newly_lost == 0 {
            return;
        }

        // Bytes lost, start sampling
        lt_reset_interval(r, now);
        r.bbr_state.lt_sampling = true;
    }

    if packet.is_app_limited {
        // Don't use app limit samples, disable sampling
        lt_reset(r, now);
        return;
    }

    if r.bbr_state.round_start {
        r.bbr_state.lt_rtt_cnt += 1;
    }

    if r.bbr_state.lt_rtt_cnt < LT_MIN_RTTS {
        // Need to sample for more RTTs
        return;
    }

    if r.bbr_state.lt_rtt_cnt > LT_MAX_SAMPLE_RTTS {
        // Didn't detect policing within sampling interval, disable sampling
        lt_reset(r, now);
        return;
    }

    if r.bbr_state.bytes_newly_lost == 0 {
        return;
    }

    // Bytes have been lost, now we check to see if more than 20% of sent
    // packets have been lost within the interval.

    let lost = r.bbr_state.bytes_lost - r.bbr_state.lt_last_lost;
    let delivered = r.bytes_acked - r.bbr_state.lt_last_delivered;

    if delivered == 0 || lost * LT_LOSS_THRESH < delivered {
        return;
    }

    // More than 20% lost, store the measurement.
    let interval = now - r.bbr_state.lt_last_stamp;
    let rate = (delivered as f64 / interval.as_secs_f64()) as u64;

    // Check if we have a previous measurement
    if r.bbr_state.lt_bw != 0 {
        let diff = (rate as i64 - r.bbr_state.lt_bw as i64).abs() as u64;
        if diff * LT_BW_RATIO <= r.bbr_state.lt_bw || diff <= LT_BW_DIFF {
            // We've made two consistent measurements, so we're probably
            // being policed.

            // Average the last two measurements
            r.bbr_state.lt_bw = (rate + r.bbr_state.lt_bw) / 2;

            // Use the long-term sampling rate
            r.bbr_state.lt_use_bw = true;
            r.bbr_state.pacing_gain = NORMAL_PACING_GAIN;
            r.bbr_state.lt_rtt_cnt = 0;
            return;
        }
    }

    // Store the measurement and restart sampling
    r.bbr_state.lt_bw = rate;
    lt_reset_interval(r, now);
}

/// Restart long-term sampling timer
fn lt_reset_interval(r: &mut Recovery, now: Instant) {
    r.bbr_state.lt_last_stamp = now;
    r.bbr_state.lt_last_delivered = r.bytes_acked;
    r.bbr_state.lt_last_lost = r.bbr_state.bytes_lost;
    r.bbr_state.lt_rtt_cnt = 0;
}

/// Reset long-term bandwidth estimate
fn lt_reset(r: &mut Recovery, now: Instant) {
    r.bbr_state.lt_use_bw = false;
    r.bbr_state.lt_bw = 0;
    r.bbr_state.lt_sampling = false;
    lt_reset_interval(r, now);
}

fn update_round(r: &mut Recovery, packet: &Acked) {
    if packet.delivered >= r.bbr_state.next_round_delivered {
        // Move to the next round
        r.bbr_state.next_round_delivered = r.bytes_acked;
        r.bbr_state.round_count += 1;
        r.bbr_state.round_start = true;

        if r.bbr_state.conservation == PacketConservation::Conservation {
            // Move to the next phase of conservation
            r.bbr_state.conservation = PacketConservation::Growth;
        }
    } else {
        r.bbr_state.round_start = false;
    }

    if packet.delivered >= r.bbr_state.end_conservation &&
        r.bbr_state.conservation != PacketConservation::Normal
    {
        // It's been one RTT since the last loss, assume its been repaired
        r.bbr_state.conservation = PacketConservation::Normal;
        restore_cwnd(r);
    }
}

fn update_rtt(r: &mut Recovery, now: Instant) {
    // Check if the RTT sample has expired
    r.bbr_state.rtt_expired = now > r.bbr_state.rtt_stamp + RTT_WINDOW;

    if r.latest_rtt <= r.bbr_state.rtt_min || r.bbr_state.rtt_expired {
        // New RTT sample found
        r.bbr_state.rtt_min = r.latest_rtt;
        r.bbr_state.rtt_stamp = now;
    }
}

fn set_pacing_rate(r: &mut Recovery) {
    set_pacing_rate_gain(r, r.bbr_state.pacing_gain);
}

fn set_pacing_rate_gain(r: &mut Recovery, gain: f64) {
    let rate = (gain * bw(r) as f64) as u64;

    // Use the new pacing rate if we've left startup or its higher than our
    // current rate.
    if r.bbr_state.filled_pipe || rate > r.bbr_state.pacing_rate {
        r.bbr_state.pacing_rate = rate;
        r.pacing_rate = rate;
    }
}

/// Update send quantum, the number of bytes that should be dispatched to the
/// socket at a time to amortise datagram sending costs while ensuring
/// datagrams are paced as evenly as possible.
fn set_send_quantum(r: &mut Recovery) {
    const LOW_THRESH: u64 = 157286; // 1.2Mbps in MBps
    const HIGH_THRESH: u64 = 3145728; // 24Mbps in MBps
    const HIGH_QUANTUM: usize = 65536; // 64KB

    r.bbr_state.send_quantum = if r.bbr_state.pacing_rate < LOW_THRESH {
        // Under 1.2Mbps, one datagram should be sent at a time
        r.max_datagram_size()
    } else if r.bbr_state.pacing_rate < HIGH_THRESH {
        // 1.2Mbps to 24Mbps, two datagrams should be sent at a time
        2 * r.max_datagram_size()
    } else {
        // Above 24Mbps, datagrams should be sent at least every millisecond
        std::cmp::min((r.bbr_state.pacing_rate / 1000) as usize, HIGH_QUANTUM)
    };
}

/// Upper bound of bytes in flight based on bandwidth-delay product, gain, and
/// sending quantum.
fn inflight(r: &Recovery, gain: f64) -> usize {
    let quanta = 3 * r.bbr_state.send_quantum;
    let estimated_bdp =
        r.bbr_state.bw_max as f64 * r.bbr_state.rtt_min.as_secs_f64();
    (gain * estimated_bdp) as usize + quanta
}

fn update_target_cwnd(r: &mut Recovery) {
    r.bbr_state.target_cwnd = inflight(r, r.bbr_state.cwnd_gain);
}

/// Keep congestion window bounded below the probe RTT maximum.
fn modulate_cwnd_for_probe_rtt(r: &mut Recovery) {
    if r.bbr_state.mode == Mode::ProbeRtt {
        r.congestion_window = std::cmp::min(
            r.congestion_window,
            MIN_PIPE_CWND * r.max_datagram_size(),
        );
    }
}

fn modulate_cwnd_for_recovery(r: &mut Recovery) {
    if r.bbr_state.bytes_newly_lost > 0 {
        // Remove lost bytes from congestion window
        r.congestion_window = std::cmp::max(
            r.congestion_window - r.bbr_state.bytes_newly_lost,
            MIN_PIPE_CWND * r.max_datagram_size(),
        );
    }
}

fn set_cwnd(r: &mut Recovery, packet: &Acked) {
    update_target_cwnd(r);

    if r.bbr_state.conservation != PacketConservation::Normal {
        modulate_cwnd_for_recovery(r);
    }

    // If conservation is active, just keep the window stable
    if r.bbr_state.conservation != PacketConservation::Conservation {
        if r.bbr_state.filled_pipe {
            // After startup, increase congestion window for each byte acked
            // until target is reached.
            r.congestion_window = std::cmp::min(
                r.congestion_window + packet.size,
                r.bbr_state.target_cwnd,
            );
        } else if r.congestion_window < r.bbr_state.target_cwnd ||
            r.bytes_acked < MIN_PIPE_CWND * r.max_datagram_size()
        {
            // Otherwise, increase congestion window unbounded.
            r.congestion_window += packet.size;
        }

        // Keep congestion window above minimum.
        r.congestion_window = std::cmp::max(
            r.congestion_window,
            MIN_PIPE_CWND * r.max_datagram_size(),
        );
    }

    modulate_cwnd_for_probe_rtt(r);
}

fn check_full_pipe(r: &mut Recovery, packet: &Acked) {
    if r.bbr_state.filled_pipe ||
        !r.bbr_state.round_start ||
        packet.is_app_limited
    {
        return;
    }

    // Check if BW still growing by more than 25%
    if r.bbr_state.bw_max >= (r.bbr_state.full_bw * 5) / 4 {
        // Reset counting
        r.bbr_state.full_bw = r.bbr_state.bw_max;
        r.bbr_state.full_bw_count = 0;
        return;
    }

    // BW did not grow, start keeping count
    r.bbr_state.full_bw_count += 1;

    if r.bbr_state.full_bw_count >= 3 {
        // Pipe filled, start draining
        r.bbr_state.filled_pipe = true;
    }
}

fn enter_startup(r: &mut Recovery) {
    r.bbr_state.mode = Mode::Startup;
    r.bbr_state.pacing_gain = HIGH_GAIN;
    r.bbr_state.cwnd_gain = HIGH_GAIN;
}

fn enter_drain(r: &mut Recovery) {
    r.bbr_state.mode = Mode::Drain;
    r.bbr_state.pacing_gain = LOW_GAIN;
    r.bbr_state.cwnd_gain = HIGH_GAIN;
}

fn check_drain(r: &mut Recovery) {
    if r.bbr_state.mode == Mode::Startup && r.bbr_state.filled_pipe {
        enter_drain(r);
    }

    if r.bbr_state.mode == Mode::Drain &&
        r.bytes_in_flight <= inflight(r, NORMAL_PACING_GAIN)
    {
        // Can exit drain, bytes in flight below capacity
        enter_probe_bw(r);
    }
}

fn enter_probe_bw(r: &mut Recovery) {
    r.bbr_state.mode = Mode::ProbeBw;
    r.bbr_state.pacing_gain = NORMAL_PACING_GAIN;
    r.bbr_state.cwnd_gain = NORMAL_CWND_GAIN;
    r.bbr_state.probe_gain_idx =
        PROBE_GAINS.len() - 1 - rand::rand_u64_uniform(7) as usize;
}

fn check_cycle_phase(r: &mut Recovery, packet: &Acked, now: Instant) {
    if r.bbr_state.mode == Mode::ProbeBw && is_next_cycle_phase(r, packet, now) {
        advance_cycle_phase(r, now);
    }
}

fn is_next_cycle_phase(r: &mut Recovery, packet: &Acked, now: Instant) -> bool {
    let is_full_length = now - r.bbr_state.cycle_stamp > r.bbr_state.rtt_min;
    let prior_inflight = r.bytes_in_flight + packet.size;

    if r.bbr_state.pacing_gain == NORMAL_PACING_GAIN {
        // Advance to next round once cycle is elapsed
        is_full_length
    } else if r.bbr_state.pacing_gain > NORMAL_PACING_GAIN {
        // If we're probing, advance once cycle is elapsed and there are either
        // losses or bytes inflight isn't growing.
        is_full_length &&
            (r.bbr_state.bytes_newly_lost > 0 ||
                prior_inflight >= inflight(r, r.bbr_state.pacing_gain))
    } else {
        // If we're draining, wait until cycle is elapsed or inflight grows.
        is_full_length || prior_inflight <= inflight(r, NORMAL_PACING_GAIN)
    }
}

fn advance_cycle_phase(r: &mut Recovery, now: Instant) {
    r.bbr_state.cycle_stamp = now;
    r.bbr_state.probe_gain_idx =
        (r.bbr_state.probe_gain_idx + 1) % PROBE_GAINS.len();
    if r.bbr_state.lt_use_bw {
        // If using long-term, just use the normal gain
        r.bbr_state.pacing_gain = NORMAL_PACING_GAIN;
    } else {
        r.bbr_state.pacing_gain = PROBE_GAINS[r.bbr_state.probe_gain_idx];
    }
}

fn handle_restart_from_idle(r: &mut Recovery) {
    // Refresh pacing rate if starting from idle
    if r.bytes_in_flight == 0 && r.app_limited() {
        // Avoid entering probe RTT
        r.bbr_state.idle_restart = true;
        if r.bbr_state.mode == Mode::ProbeBw {
            set_pacing_rate_gain(r, NORMAL_PACING_GAIN);
        }
    }
}

fn check_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr_state.mode != Mode::ProbeRtt &&
        r.bbr_state.rtt_expired &&
        !r.bbr_state.idle_restart
    {
        // Enter RTT if the sample has expired
        enter_probe_rtt(r);
        save_cwnd(r);
        r.bbr_state.probe_rtt_done_stamp = None;
    }

    if r.bbr_state.mode == Mode::ProbeRtt {
        handle_probe_rtt(r, now);
    }

    r.bbr_state.idle_restart = false;
}

fn enter_probe_rtt(r: &mut Recovery) {
    r.bbr_state.mode = Mode::ProbeRtt;
    r.bbr_state.pacing_gain = NORMAL_PACING_GAIN;
    r.bbr_state.cwnd_gain = PROBE_RTT_CWND_GAIN;
}

fn handle_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr_state.probe_rtt_done_stamp.is_none() &&
        r.bytes_in_flight <= MIN_PIPE_CWND * r.max_datagram_size()
    {
        // Bytes dropped down to window, start probing for RTT
        r.bbr_state.probe_rtt_done_stamp = Some(now + PROBE_RTT_TIME);
        r.bbr_state.probe_rtt_round_done = false;
        r.bbr_state.next_round_delivered = r.bytes_acked;
    } else if let Some(probe_rtt_done_stamp) = r.bbr_state.probe_rtt_done_stamp {
        if r.bbr_state.round_start {
            r.bbr_state.probe_rtt_round_done = true;
        }

        if r.bbr_state.probe_rtt_round_done && now > probe_rtt_done_stamp {
            // Probe RTT done
            r.bbr_state.rtt_stamp = now;
            restore_cwnd(r);
            exit_probe_rtt(r);
        }
    }
}

fn exit_probe_rtt(r: &mut Recovery) {
    if r.bbr_state.filled_pipe {
        enter_probe_bw(r);
    } else {
        enter_startup(r);
    }
}

/// Returns the current bandwidth estimate
fn bw(r: &mut Recovery) -> u64 {
    if r.bbr_state.lt_use_bw {
        r.bbr_state.lt_bw
    } else {
        r.bbr_state.bw_max
    }
}
