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

mod drain;
mod mode;
mod network_model;
mod probe_bw;
mod probe_rtt;
mod startup;

use std::time::Duration;
use std::time::Instant;

use network_model::BBRv2NetworkModel;

use crate::recovery::bandwidth::Bandwidth;
use crate::recovery::Acked;

use self::mode::Mode;
use self::mode::ModeImpl;

use super::bbr::SendTimeState;
use super::CongestionControl;
use super::Lost;
use super::RttStats;

const MAX_MODE_CHANGES_PER_CONGESTION_EVENT: usize = 4;

#[derive(PartialEq)]
#[allow(dead_code)]
enum BwLoMode {
    Default,
    MinRttReduction,
    InflightReduction,
    CwndReduction,
}

struct Params {
    // STARTUP parameters.
    /// The gain for CWND in startup.
    startup_cwnd_gain: f32,

    startup_pacing_gain: f32,

    /// STARTUP or PROBE_UP are exited if the total bandwidth growth is less
    /// than `full_bw_threshold` in the last `startup_full_bw_rounds`` round
    /// trips.
    full_bw_threshold: f32,

    startup_full_bw_rounds: usize,

    /// Number of rounds to stay in STARTUP when there's a sufficient queue that
    /// bytes_in_flight never drops below the target (1.75 * BDP).  0 indicates
    /// the feature is disabled and we never exit due to queueing.
    max_startup_queue_rounds: usize,

    /// The minimum number of loss marking events to exit STARTUP.
    startup_full_loss_count: usize,

    /// DRAIN parameters.
    drain_cwnd_gain: f32,

    drain_pacing_gain: f32,

    // PROBE_BW parameters.
    /// Max number of rounds before probing for Reno-coexistence.
    probe_bw_probe_max_rounds: usize,

    enable_reno_coexistence: bool,

    /// Multiplier to get Reno-style probe epoch duration as: k * BDP round
    /// trips. If zero, disables Reno-style BDP-scaled coexistence mechanism.
    probe_bw_probe_reno_gain: f32,

    /// Minimum duration for BBR-native probes.
    probe_bw_probe_base_duration: Duration,

    /// The minimum number of loss marking events to exit the PROBE_UP phase.
    probe_bw_full_loss_count: usize,

    /// Pacing gains.
    probe_bw_probe_up_pacing_gain: f32,
    probe_bw_probe_down_pacing_gain: f32,
    probe_bw_default_pacing_gain: f32,

    probe_bw_cwnd_gain: f32,

    // PROBE_UP parameters.
    probe_up_ignore_inflight_hi: bool,

    /// Number of rounds to stay in PROBE_UP when there's a sufficient queue
    /// that bytes_in_flight never drops below the target.  0 indicates the
    /// feature is disabled and we never exit due to queueing.
    // TODO(vlad):
    max_probe_up_queue_rounds: usize,

    // PROBE_RTT parameters.
    probe_rtt_inflight_target_bdp_fraction: f32,

    /// The default period for entering PROBE_RTT
    probe_rtt_period: Duration,

    probe_rtt_duration: Duration,

    // Parameters used by multiple modes.
    /// The initial value of the max ack height filter's window length.
    initial_max_ack_height_filter_window: usize,

    /// The default fraction of unutilized headroom to try to leave in path
    /// upon high loss.
    inflight_hi_headroom: f32,

    /// Estimate startup/bw probing has gone too far if loss rate exceeds this.
    loss_threshold: f32,

    /// A common factor for multiplicative decreases. Used for adjusting
    /// `bandwidth_lo``, `inflight_lo`` and `inflight_hi`` upon losses.
    beta: f32,

    // Experimental flags.
    add_ack_height_to_queueing_threshold: bool,

    /// Don't run PROBE_RTT on the regular schedule
    avoid_unnecessary_probe_rtt: bool,

    /// When exiting STARTUP due to loss, set `inflight_hi`` to the max of bdp
    /// and max bytes delivered in round.
    limit_inflight_hi_by_max_delivered: bool,

    startup_loss_exit_use_max_delivered_for_inflight_hi: bool,

    /// Increase `inflight_hi`` based on delievered, not inflight.
    use_bytes_delivered_for_inflight_hi: bool,

    /// Set the pacing gain to 25% larger than the recent BW increase in
    /// STARTUP.
    decrease_startup_pacing_at_end_of_round: bool,

    /// Avoid Overestimation in Bandwidth Sampler with ack aggregation
    overestimate_avoidance: bool,

    bw_lo_mode: BwLoMode,
}

const PARAMS: Params = Params {
    startup_cwnd_gain: 2.0,

    startup_pacing_gain: 2.773,

    full_bw_threshold: 1.25,

    startup_full_bw_rounds: 3,

    max_startup_queue_rounds: 0,

    startup_full_loss_count: 8,

    drain_cwnd_gain: 2.0,

    drain_pacing_gain: 1.0 / 2.885,

    probe_bw_probe_max_rounds: 63,

    enable_reno_coexistence: true,

    probe_bw_probe_reno_gain: 1.0,

    probe_bw_probe_base_duration: Duration::from_millis(2000),

    probe_bw_full_loss_count: 2,

    probe_bw_probe_up_pacing_gain: 1.25,

    probe_bw_probe_down_pacing_gain: 0.9, // BBRv3

    probe_bw_default_pacing_gain: 1.0,

    probe_bw_cwnd_gain: 2.25, // BBRv3

    probe_up_ignore_inflight_hi: false,

    max_probe_up_queue_rounds: 2,

    probe_rtt_inflight_target_bdp_fraction: 0.5,

    probe_rtt_period: Duration::from_millis(10000),

    probe_rtt_duration: Duration::from_millis(200),

    initial_max_ack_height_filter_window: 10,

    inflight_hi_headroom: 0.15,

    loss_threshold: 0.015,

    beta: 0.3,

    add_ack_height_to_queueing_threshold: false,

    avoid_unnecessary_probe_rtt: true,

    limit_inflight_hi_by_max_delivered: true,

    startup_loss_exit_use_max_delivered_for_inflight_hi: true,

    use_bytes_delivered_for_inflight_hi: true,

    decrease_startup_pacing_at_end_of_round: true,

    overestimate_avoidance: true,

    bw_lo_mode: BwLoMode::Default,
};

#[derive(Debug)]
struct Limits<T: Ord> {
    lo: T,
    hi: T,
}

impl<T: Ord + Clone + Copy> Limits<T> {
    fn min(&self) -> T {
        self.lo
    }

    fn apply_limits(&self, val: T) -> T {
        val.max(self.lo).min(self.hi)
    }
}

impl<T: Ord + Clone + Copy + From<u8>> Limits<T> {
    pub(crate) fn no_greater_than(val: T) -> Self {
        Self {
            lo: T::from(0),
            hi: val,
        }
    }
}

#[derive(Debug)]
pub(crate) struct BBRv2 {
    mode: Mode,
    cwnd: usize,
    mss: usize,

    pacing_rate: Bandwidth,

    cwnd_limits: Limits<usize>,

    initial_cwnd: usize,

    last_sample_is_app_limited: bool,
    has_non_app_limited_sample: bool,
    last_quiescence_start: Option<Instant>,
}

struct BBRv2CongestionEvent {
    event_time: Instant,

    /// The congestion window prior to the processing of the ack/loss events.
    prior_cwnd: usize,
    /// Total bytes inflight before the processing of the ack/loss events.
    prior_bytes_in_flight: usize,

    /// Total bytes inflight after the processing of the ack/loss events.
    bytes_in_flight: usize,
    /// Total bytes acked from acks in this event.
    bytes_acked: usize,
    /// Total bytes lost from losses in this event.
    bytes_lost: usize,

    /// Whether acked_packets indicates the end of a round trip.
    end_of_round_trip: bool,
    // When the event happened, whether the sender is probing for bandwidth.
    is_probing_for_bandwidth: bool,

    // Maximum bandwidth of all bandwidth samples from acked_packets.
    // This sample may be app-limited, and will be None if there are no newly
    // acknowledged inflight packets.
    sample_max_bandwidth: Option<Bandwidth>,

    /// Minimum rtt of all bandwidth samples from acked_packets.
    /// None if acked_packets is empty.
    sample_min_rtt: Option<Duration>,

    /// The send state of the largest packet in acked_packets, unless it is
    /// empty. If acked_packets is empty, it's the send state of the largest
    /// packet in lost_packets.
    last_packet_send_state: SendTimeState,
}

impl BBRv2CongestionEvent {
    fn new(
        event_time: Instant, prior_cwnd: usize, prior_bytes_in_flight: usize,
        is_probing_for_bandwidth: bool,
    ) -> Self {
        BBRv2CongestionEvent {
            event_time,
            prior_cwnd,
            prior_bytes_in_flight,
            is_probing_for_bandwidth,
            bytes_in_flight: 0,
            bytes_acked: 0,
            bytes_lost: 0,
            end_of_round_trip: false,
            last_packet_send_state: Default::default(),
            sample_max_bandwidth: None,
            sample_min_rtt: None,
        }
    }
}

impl BBRv2 {
    pub fn new(
        initial_congestion_window: usize, max_congestion_window: usize,
        max_segment_size: usize, smoothed_rtt: Duration,
    ) -> Self {
        let cwnd = initial_congestion_window * max_segment_size;
        BBRv2 {
            mode: Mode::startup(BBRv2NetworkModel::new(
                PARAMS.startup_cwnd_gain,
                PARAMS.startup_pacing_gain,
                PARAMS.overestimate_avoidance,
            )),
            cwnd,
            pacing_rate: Bandwidth::from_bytes_and_time_delta(cwnd, smoothed_rtt) *
                2.885,
            cwnd_limits: Limits {
                lo: initial_congestion_window * max_segment_size,
                hi: max_congestion_window * max_segment_size,
            },
            initial_cwnd: initial_congestion_window * max_segment_size,
            last_sample_is_app_limited: false,
            has_non_app_limited_sample: false,
            last_quiescence_start: None,
            mss: max_segment_size,
        }
    }

    fn on_exit_quiescence(&mut self, now: Instant) {
        if let Some(last_quiescence_start) = self.last_quiescence_start.take() {
            self.mode.do_on_exit_quiescence(now, last_quiescence_start)
        }
    }

    fn get_target_congestion_window(&self, gain: f32) -> usize {
        self.mode
            .bdp(self.mode.bandwidth_estimate(), gain)
            .max(self.cwnd_limits.min())
    }

    fn update_pacing_rate(&mut self, bytes_acked: usize) {
        let bandwidth_estimate = match self.mode.bandwidth_estimate() {
            e if e == Bandwidth::zero() => return,
            e => e,
        };

        if self.mode.total_bytes_acked() == bytes_acked {
            // After the first ACK, cwnd is still the initial congestion window.
            self.pacing_rate = Bandwidth::from_bytes_and_time_delta(
                self.cwnd,
                self.mode.min_rtt(),
            );
            return;
        }

        let target_rate = bandwidth_estimate * self.mode.pacing_gain();
        if self.mode.full_bandwidth_reached() {
            self.pacing_rate = target_rate;
            return;
        }

        if PARAMS.decrease_startup_pacing_at_end_of_round &&
            self.mode.pacing_gain() < PARAMS.startup_pacing_gain
        {
            self.pacing_rate = target_rate;
            return;
        }

        if PARAMS.bw_lo_mode != BwLoMode::Default &&
            self.mode.loss_events_in_round() > 0
        {
            self.pacing_rate = target_rate;
            return;
        }

        // By default, the pacing rate never decreases in STARTUP.
        self.pacing_rate = self.pacing_rate.max(target_rate);
    }

    fn update_congestion_window(&mut self, bytes_acked: usize) {
        let mut target_cwnd =
            self.get_target_congestion_window(self.mode.cwnd_gain());

        let prior_cwnd = self.cwnd;
        if self.mode.full_bandwidth_reached() {
            target_cwnd += self.mode.max_ack_height();
            self.cwnd = target_cwnd.min(prior_cwnd + bytes_acked);
        } else if prior_cwnd < target_cwnd || prior_cwnd < 2 * self.initial_cwnd {
            self.cwnd = prior_cwnd + bytes_acked;
        }

        self.cwnd = self.mode.get_cwnd_limits().apply_limits(self.cwnd);
        self.cwnd = self.cwnd_limits.apply_limits(self.cwnd);
    }

    fn on_enter_quiescence(&mut self, time: Instant) {
        self.last_quiescence_start = Some(time);
    }

    fn target_bytes_inflight(&self) -> usize {
        let bdp = self.mode.bdp1(self.mode.bandwidth_estimate());
        bdp.min(self.get_congestion_window())
    }
}

impl CongestionControl for BBRv2 {
    fn get_congestion_window(&self) -> usize {
        self.cwnd
    }

    fn get_congestion_window_in_packets(&self) -> usize {
        self.cwnd / self.mss
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight < self.get_congestion_window()
    }

    fn on_packet_sent(
        &mut self, sent_time: std::time::Instant, bytes_in_flight: usize,
        packet_number: u64, bytes: usize, is_retransmissible: bool,
        rtt_stats: &RttStats,
    ) {
        if bytes_in_flight == 0 && PARAMS.avoid_unnecessary_probe_rtt {
            self.on_exit_quiescence(sent_time);
        }

        self.mode.on_packet_sent(
            sent_time,
            bytes_in_flight,
            packet_number,
            bytes,
            is_retransmissible,
            rtt_stats,
        );
    }

    fn on_congestion_event(
        &mut self, _rtt_updated: bool, prior_in_flight: usize,
        _bytes_in_flight: usize, event_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], least_unacked: u64, _rtt_stats: &RttStats,
    ) {
        let mut congestion_event = BBRv2CongestionEvent::new(
            event_time,
            self.cwnd,
            prior_in_flight,
            self.mode.is_probing_for_bandwidth(),
        );

        self.mode.on_congestion_event_start(
            acked_packets,
            lost_packets,
            &mut congestion_event,
        );

        // Number of mode changes allowed for this congestion event.
        let mut mode_changes_allowed = MAX_MODE_CHANGES_PER_CONGESTION_EVENT;
        while mode_changes_allowed > 0 &&
            self.mode.do_on_congestion_event(
                prior_in_flight,
                event_time,
                acked_packets,
                lost_packets,
                &mut congestion_event,
                self.target_bytes_inflight(),
            )
        {
            mode_changes_allowed -= 1;
        }

        self.update_pacing_rate(congestion_event.bytes_acked);

        self.update_congestion_window(congestion_event.bytes_acked);

        self.mode
            .on_congestion_event_finish(least_unacked, &congestion_event);
        self.last_sample_is_app_limited =
            congestion_event.last_packet_send_state.is_app_limited;
        if !self.last_sample_is_app_limited {
            self.has_non_app_limited_sample = true;
        }
        if congestion_event.bytes_in_flight == 0 &&
            PARAMS.avoid_unnecessary_probe_rtt
        {
            self.on_enter_quiescence(event_time);
        }
    }

    fn on_packet_neutered(&mut self, packet_number: u64) {
        self.mode.on_packet_neutered(packet_number);
    }

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn on_connection_migration(&mut self) {}

    fn is_in_recovery(&self) -> bool {
        // TODO(vlad): is this true?
        self.last_quiescence_start.is_none()
    }

    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight >= self.get_congestion_window()
    }

    fn pacing_rate(
        &self, _bytes_in_flight: usize, _rtt_stats: &super::RttStats,
    ) -> Bandwidth {
        self.pacing_rate
    }

    fn bandwidth_estimate(&self, _rtt_stats: &super::RttStats) -> Bandwidth {
        self.mode.bandwidth_estimate()
    }

    fn update_mss(&mut self, new_mss: usize) {
        self.cwnd_limits.hi = self.cwnd_limits.hi * new_mss / self.mss;
        self.cwnd_limits.lo = self.cwnd_limits.lo * new_mss / self.mss;
        self.cwnd = self.cwnd * new_mss / self.mss;
        self.initial_cwnd = self.initial_cwnd * new_mss / self.mss;
        self.mss = new_mss;
    }

    fn on_app_limited(&mut self, bytes_in_flight: usize) {
        if bytes_in_flight >= self.get_congestion_window() {
            return;
        }

        self.mode.on_app_limited()
    }

    fn limit_cwnd(&mut self, max_cwnd: usize) {
        self.cwnd_limits.hi = max_cwnd
    }
}
