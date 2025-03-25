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

use std::ops::Add;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::gcongestion::bandwidth::Bandwidth;
use crate::recovery::gcongestion::bbr::BandwidthSampler;
use crate::recovery::gcongestion::Lost;
use crate::recovery::rtt::RttStats;
use crate::recovery::rtt::INITIAL_RTT;

use super::Acked;
use super::BBRv2CongestionEvent;
use super::BwLoMode;
use super::PARAMS;

pub(super) const DEFAULT_MSS: usize = 1300;

#[derive(Debug)]
struct RoundTripCounter {
    round_trip_count: usize,
    last_sent_packet: u64,
    // The last sent packet number of the current round trip.
    end_of_round_trip: Option<u64>,
}

impl RoundTripCounter {
    /// Must be called in ascending packet number order.
    fn on_packet_sent(&mut self, packet_number: u64) {
        self.last_sent_packet = packet_number;
    }

    /// Return whether a round trip has just completed.
    fn on_packets_acked(&mut self, last_acked_packet: u64) -> bool {
        match self.end_of_round_trip {
            Some(pkt) if last_acked_packet <= pkt => false,
            _ => {
                self.round_trip_count += 1;
                self.end_of_round_trip = Some(self.last_sent_packet);
                true
            },
        }
    }

    fn restart_round(&mut self) {
        self.end_of_round_trip = Some(self.last_sent_packet)
    }
}

#[derive(Debug)]
struct MinRttFilter {
    min_rtt: Duration,
    min_rtt_timestamp: Instant,
}

impl MinRttFilter {
    fn get(&self) -> Duration {
        self.min_rtt
    }

    fn get_timestamps(&self) -> Instant {
        self.min_rtt_timestamp
    }

    fn update(&mut self, sample_rtt: Duration, now: Instant) {
        if sample_rtt < self.min_rtt {
            self.min_rtt = sample_rtt;
            self.min_rtt_timestamp = now;
        }
    }

    fn force_update(&mut self, sample_rtt: Duration, now: Instant) {
        self.min_rtt = sample_rtt;
        self.min_rtt_timestamp = now;
    }
}

#[derive(Debug)]
struct MaxBandwidthFilter {
    max_bandwidth: [Bandwidth; 2],
}

impl MaxBandwidthFilter {
    fn get(&self) -> Bandwidth {
        self.max_bandwidth[0].max(self.max_bandwidth[1])
    }

    fn update(&mut self, sample: Bandwidth) {
        self.max_bandwidth[1] = self.max_bandwidth[1].max(sample);
    }

    fn advance(&mut self) {
        if self.max_bandwidth[1] == Bandwidth::zero() {
            return;
        }

        self.max_bandwidth[0] = self.max_bandwidth[1];
        self.max_bandwidth[1] = Bandwidth::zero();
    }
}

/// Bbr2NetworkModel takes low level congestion signals(packets sent/acked/lost)
/// as input and produces BBRv2 model parameters like inflight_(hi|lo),
/// bandwidth_(hi|lo), bandwidth and rtt estimates, etc.
#[derive(Debug)]
pub(super) struct BBRv2NetworkModel {
    round_trip_counter: RoundTripCounter,
    /// Bandwidth sampler provides BBR with the bandwidth measurements at
    /// individual points.
    bandwidth_sampler: BandwidthSampler,
    /// The filter that tracks the maximum bandwidth over multiple recent round
    /// trips.
    max_bandwidth_filter: MaxBandwidthFilter,
    min_rtt_filter: MinRttFilter,
    /// Bytes lost in the current round. Updated once per congestion event.
    bytes_lost_in_round: usize,
    /// Number of loss marking events in the current round.
    loss_events_in_round: usize,

    /// A max of bytes delivered among all congestion events in the current
    /// round. A congestions event's bytes delivered is the total bytes
    /// acked between time Ts and Ta, which is the time when the largest
    /// acked packet(within the congestion event) was sent and acked,
    /// respectively.
    max_bytes_delivered_in_round: usize,

    /// The minimum bytes in flight during this round.
    min_bytes_in_flight_in_round: usize,
    /// True if sending was limited by inflight_hi anytime in the current round.
    inflight_hi_limited_in_round: bool,

    /// Max bandwidth in the current round. Updated once per congestion event.
    bandwidth_latest: Bandwidth,
    /// Max bandwidth of recent rounds. Updated once per round.
    bandwidth_lo: Option<Bandwidth>,
    prior_bandwidth_lo: Option<Bandwidth>,

    /// Max inflight in the current round. Updated once per congestion event.
    inflight_latest: usize,
    /// Max inflight of recent rounds. Updated once per round.
    inflight_lo: usize,
    inflight_hi: usize,

    cwnd_gain: f32,
    pacing_gain: f32,

    /// Whether we are cwnd limited prior to the start of the current
    /// aggregation epoch.
    cwnd_limited_before_aggregation_epoch: bool,

    /// STARTUP-centric fields which experimentally used by PROBE_UP.
    full_bandwidth_reached: bool,
    full_bandwidth_baseline: Bandwidth,
    rounds_without_bandwidth_growth: usize,

    // Used by STARTUP and PROBE_UP to decide when to exit.
    rounds_with_queueing: usize,
}

impl BBRv2NetworkModel {
    pub(super) fn new(
        cwnd_gain: f32, pacing_gain: f32, overestimate_avoidance: bool,
    ) -> Self {
        BBRv2NetworkModel {
            min_bytes_in_flight_in_round: usize::MAX,
            inflight_hi_limited_in_round: false,
            bandwidth_sampler: BandwidthSampler::new(
                PARAMS.initial_max_ack_height_filter_window,
                overestimate_avoidance,
            ),
            round_trip_counter: RoundTripCounter {
                round_trip_count: 0,
                last_sent_packet: 0,
                end_of_round_trip: None,
            },
            min_rtt_filter: MinRttFilter {
                min_rtt: INITIAL_RTT,
                min_rtt_timestamp: Instant::now(),
            },
            max_bandwidth_filter: MaxBandwidthFilter {
                max_bandwidth: [Bandwidth::zero(), Bandwidth::zero()],
            },
            cwnd_limited_before_aggregation_epoch: false,
            cwnd_gain,
            pacing_gain,
            full_bandwidth_reached: false,
            bytes_lost_in_round: 0,
            loss_events_in_round: 0,
            max_bytes_delivered_in_round: 0,
            bandwidth_latest: Bandwidth::zero(),
            bandwidth_lo: None,
            prior_bandwidth_lo: None,
            inflight_latest: 0,
            inflight_lo: usize::MAX,
            inflight_hi: usize::MAX,

            full_bandwidth_baseline: Bandwidth::zero(),
            rounds_without_bandwidth_growth: 0,
            rounds_with_queueing: 0,
        }
    }

    pub(super) fn max_ack_height(&self) -> usize {
        self.bandwidth_sampler.max_ack_height().unwrap_or(0)
    }

    pub(super) fn bandwidth_estimate(&self) -> Bandwidth {
        match (self.bandwidth_lo, self.max_bandwidth()) {
            (None, b) => b,
            (Some(a), b) => a.min(b),
        }
    }

    pub(super) fn bdp(&self, bandwidth: Bandwidth, gain: f32) -> usize {
        (bandwidth * gain).to_bytes_per_period(self.min_rtt()) as usize
    }

    pub(super) fn bdp1(&self, bandwidth: Bandwidth) -> usize {
        self.bdp(bandwidth, 1.0)
    }

    pub(super) fn bdp0(&self) -> usize {
        self.bdp1(self.max_bandwidth())
    }

    pub(super) fn min_rtt(&self) -> Duration {
        self.min_rtt_filter.get()
    }

    pub(super) fn min_rtt_timestamp(&self) -> Instant {
        self.min_rtt_filter.get_timestamps()
    }

    pub(super) fn max_bandwidth(&self) -> Bandwidth {
        self.max_bandwidth_filter.get()
    }

    pub(super) fn on_packet_sent(
        &mut self, sent_time: Instant, bytes_in_flight: usize,
        packet_number: u64, bytes: usize, is_retransmissible: bool,
        _rtt_stats: &RttStats,
    ) {
        // Updating the min here ensures a more realistic (0) value when flows
        // exit quiescence.
        self.min_bytes_in_flight_in_round =
            self.min_bytes_in_flight_in_round.min(bytes_in_flight);

        if bytes_in_flight + bytes >= self.inflight_hi {
            self.inflight_hi_limited_in_round = true;
        }
        self.round_trip_counter.on_packet_sent(packet_number);

        self.bandwidth_sampler.on_packet_sent(
            sent_time,
            packet_number,
            bytes,
            bytes_in_flight,
            is_retransmissible,
        );
    }

    pub(super) fn on_congestion_event_start(
        &mut self, acked_packets: &[Acked], lost_packets: &[Lost],
        congestion_event: &mut BBRv2CongestionEvent,
    ) {
        let prior_bytes_acked = self.total_bytes_acked();
        let prior_bytes_lost = self.total_bytes_lost();

        let event_time = congestion_event.event_time;

        congestion_event.end_of_round_trip =
            if let Some(largest_acked) = acked_packets.last() {
                self.round_trip_counter
                    .on_packets_acked(largest_acked.pkt_num)
            } else {
                false
            };

        let sample = self.bandwidth_sampler.on_congestion_event(
            event_time,
            acked_packets,
            lost_packets,
            Some(self.max_bandwidth()),
            self.bandwidth_lo.unwrap_or(Bandwidth::infinite()),
            self.round_trip_count(),
        );

        if sample.extra_acked == 0 {
            self.cwnd_limited_before_aggregation_epoch = congestion_event
                .prior_bytes_in_flight >=
                congestion_event.prior_cwnd;
        }

        if sample.last_packet_send_state.is_valid {
            congestion_event.last_packet_send_state =
                sample.last_packet_send_state;
        }

        // Avoid updating `max_bandwidth_filter` if a) this is a loss-only event,
        // or b) all packets in `acked_packets` did not generate valid
        // samples. (e.g. ack of ack-only packets). In both cases,
        // total_bytes_acked() will not change.
        if let Some(sample_max) = sample.sample_max_bandwidth {
            if prior_bytes_acked != self.total_bytes_acked() {
                congestion_event.sample_max_bandwidth = Some(sample_max);
                if !sample.sample_is_app_limited ||
                    sample_max > self.max_bandwidth()
                {
                    self.max_bandwidth_filter.update(sample_max);
                }
            }
        }

        if let Some(rtt_sample) = sample.sample_rtt {
            congestion_event.sample_min_rtt = Some(rtt_sample);
            self.min_rtt_filter.update(rtt_sample, event_time);
        }

        congestion_event.bytes_acked =
            self.total_bytes_acked() - prior_bytes_acked;
        congestion_event.bytes_lost = self.total_bytes_lost() - prior_bytes_lost;

        congestion_event.bytes_in_flight = congestion_event
            .prior_bytes_in_flight
            .saturating_sub(congestion_event.bytes_acked)
            .saturating_sub(congestion_event.bytes_lost);

        if congestion_event.bytes_lost > 0 {
            self.bytes_lost_in_round += congestion_event.bytes_lost;
            self.loss_events_in_round += 1;
        }

        if congestion_event.bytes_acked > 0 &&
            congestion_event.last_packet_send_state.is_valid &&
            self.total_bytes_acked() >
                congestion_event.last_packet_send_state.total_bytes_acked
        {
            let bytes_delivered = self.total_bytes_acked() -
                congestion_event.last_packet_send_state.total_bytes_acked;
            self.max_bytes_delivered_in_round =
                self.max_bytes_delivered_in_round.max(bytes_delivered);
        }

        self.min_bytes_in_flight_in_round = self
            .min_bytes_in_flight_in_round
            .min(congestion_event.bytes_in_flight);

        // `bandwidth_latest` and `inflight_latest` only increased within a
        // round.
        if sample.sample_max_bandwidth > Some(self.bandwidth_latest) {
            self.bandwidth_latest = sample.sample_max_bandwidth.unwrap();
        }

        if sample.sample_max_inflight > self.inflight_latest {
            self.inflight_latest = sample.sample_max_inflight;
        }

        // Adapt lower bounds(bandwidth_lo and inflight_lo).
        self.adapt_lower_bounds(congestion_event);

        if !congestion_event.end_of_round_trip {
            return;
        }

        if let Some(bandwidth) = sample.sample_max_bandwidth {
            self.bandwidth_latest = bandwidth;
        }

        if sample.sample_max_inflight > 0 {
            self.inflight_latest = sample.sample_max_inflight;
        }
    }

    pub(super) fn on_packet_neutered(&mut self, packet_number: u64) {
        self.bandwidth_sampler.on_packet_neutered(packet_number)
    }

    fn adapt_lower_bounds(&mut self, congestion_event: &BBRv2CongestionEvent) {
        if PARAMS.bw_lo_mode == BwLoMode::Default {
            if !congestion_event.end_of_round_trip ||
                congestion_event.is_probing_for_bandwidth
            {
                return;
            }

            if self.bytes_lost_in_round > 0 {
                if self.bandwidth_lo.is_none() {
                    self.bandwidth_lo = Some(self.max_bandwidth());
                }

                self.bandwidth_lo = Some(
                    self.bandwidth_latest
                        .max(self.bandwidth_lo.unwrap() * (1.0 - PARAMS.beta)),
                );

                if self.inflight_lo == usize::MAX {
                    self.inflight_lo = congestion_event.prior_cwnd;
                }

                let inflight_lo_new =
                    (self.inflight_lo as f32 * (1.0 - PARAMS.beta)) as usize;
                self.inflight_lo = self.inflight_latest.max(inflight_lo_new);
            }
            return;
        }

        if congestion_event.bytes_lost == 0 {
            return;
        }

        // Ignore losses from packets sent when probing for more bandwidth in
        // STARTUP or PROBE_UP when they're lost in DRAIN or PROBE_DOWN.
        if self.pacing_gain() < 1. {
            return;
        }

        // Decrease bandwidth_lo whenever there is loss.
        // Set `bandwidth_lo`if it is not yet set.
        if self.bandwidth_lo.is_none() {
            self.bandwidth_lo = Some(self.max_bandwidth());
        }

        // Save `bandwidth_lo` if it hasn't already been saved.
        if self.prior_bandwidth_lo.is_none() {
            self.prior_bandwidth_lo = self.bandwidth_lo;
        }

        match PARAMS.bw_lo_mode {
            BwLoMode::Default => unreachable!("Handled above"),
            BwLoMode::MinRttReduction => {
                let reduction = Bandwidth::from_bytes_and_time_delta(
                    congestion_event.bytes_lost,
                    self.min_rtt(),
                );

                self.bandwidth_lo = self
                    .bandwidth_lo
                    .map(|b| (b - reduction).unwrap_or(Bandwidth::zero()));
            },
            BwLoMode::InflightReduction => {
                // Use a max of BDP and inflight to avoid starving app-limited
                // flows.
                let effective_inflight =
                    self.bdp0().max(congestion_event.prior_bytes_in_flight);
                // This could use bytes_lost_in_round if the bandwidth_lo_ was
                // saved when entering 'recovery', but this BBRv2
                // implementation doesn't have recovery defined.
                self.bandwidth_lo = self.bandwidth_lo.map(|b| {
                    b * ((effective_inflight as f64 -
                        congestion_event.bytes_lost as f64) /
                        effective_inflight as f64)
                });
            },
            BwLoMode::CwndReduction => {
                self.bandwidth_lo = self.bandwidth_lo.map(|b| {
                    b * ((congestion_event.prior_cwnd as f64 -
                        congestion_event.bytes_lost as f64) /
                        congestion_event.prior_cwnd as f64)
                });
            },
        }

        let mut last_bandwidth = self.bandwidth_latest;
        // sample_max_bandwidth will be None if the loss is triggered by a timer
        // expiring. Ideally we'd use the most recent bandwidth sample,
        // but bandwidth_latest is safer than None.
        if congestion_event.sample_max_bandwidth.is_some() {
            // bandwidth_latest is the max bandwidth for the round, but to allow
            // fast, conservation style response to loss, use the last sample.
            last_bandwidth = congestion_event.sample_max_bandwidth.unwrap();
        }
        if self.pacing_gain > PARAMS.full_bw_threshold {
            // In STARTUP, `pacing_gain` is applied to `bandwidth_lo` in
            // update_pacing_rate, so this backs that multiplication out to allow
            // the pacing rate to decrease, but not below
            // last_bandwidth * full_bw_threshold.
            self.bandwidth_lo = self.bandwidth_lo.max(Some(
                last_bandwidth * (PARAMS.full_bw_threshold / self.pacing_gain),
            ));
        } else {
            // Ensure bandwidth_lo isn't lower than last_bandwidth.
            self.bandwidth_lo = self.bandwidth_lo.max(Some(last_bandwidth))
        }
        // If it's the end of the round, ensure bandwidth_lo doesn't decrease more
        // than beta.
        if congestion_event.end_of_round_trip {
            self.bandwidth_lo = self.bandwidth_lo.max(
                self.prior_bandwidth_lo
                    .take()
                    .map(|b| b * (1.0 - PARAMS.beta)),
            )
        }
        // These modes ignore inflight_lo as well.
    }

    pub(super) fn on_congestion_event_finish(
        &mut self, least_unacked_packet: u64,
        congestion_event: &BBRv2CongestionEvent,
    ) {
        if congestion_event.end_of_round_trip {
            self.on_new_round();
        }

        self.bandwidth_sampler
            .remove_obsolete_packets(least_unacked_packet);
    }

    pub(super) fn maybe_expire_min_rtt(
        &mut self, congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        if congestion_event.sample_min_rtt.is_none() {
            return false;
        }

        if congestion_event.event_time <
            self.min_rtt_filter.min_rtt_timestamp + PARAMS.probe_rtt_period
        {
            return false;
        }

        self.min_rtt_filter.force_update(
            congestion_event.sample_min_rtt.unwrap(),
            congestion_event.event_time,
        );

        true
    }

    pub(super) fn is_inflight_too_high(
        &self, congestion_event: &BBRv2CongestionEvent, max_loss_events: usize,
    ) -> bool {
        let send_state = &congestion_event.last_packet_send_state;

        if !send_state.is_valid {
            // Not enough information.
            return false;
        }

        if self.loss_events_in_round < max_loss_events {
            return false;
        }

        // TODO(vlad): BytesInFlight(send_state);
        let inflight_at_send = send_state.bytes_in_flight;

        let bytes_lost_in_round = self.bytes_lost_in_round;

        if inflight_at_send > 0 && bytes_lost_in_round > 0 {
            let lost_in_round_threshold =
                (inflight_at_send as f32 * PARAMS.loss_threshold) as usize;
            if bytes_lost_in_round > lost_in_round_threshold {
                return true;
            }
        }

        false
    }

    pub(super) fn restart_round_early(&mut self) {
        self.on_new_round();
        self.round_trip_counter.restart_round();
        self.rounds_with_queueing = 0;
    }

    fn on_new_round(&mut self) {
        self.bytes_lost_in_round = 0;
        self.loss_events_in_round = 0;
        self.max_bytes_delivered_in_round = 0;
        self.min_bytes_in_flight_in_round = usize::MAX;
        self.inflight_hi_limited_in_round = false;
    }

    pub(super) fn has_bandwidth_growth(
        &mut self, congestion_event: &BBRv2CongestionEvent,
    ) -> bool {
        let threshold = self.full_bandwidth_baseline * PARAMS.full_bw_threshold;

        if self.max_bandwidth() >= threshold {
            self.full_bandwidth_baseline = self.max_bandwidth();
            self.rounds_without_bandwidth_growth = 0;
            return true;
        }

        self.rounds_without_bandwidth_growth += 1;

        // full_bandwidth_reached is only set to true when not app-limited
        if self.rounds_without_bandwidth_growth >= PARAMS.startup_full_bw_rounds &&
            !congestion_event.last_packet_send_state.is_app_limited
        {
            self.full_bandwidth_reached = true;
        }

        false
    }

    pub(super) fn queueing_threshold_extra_bytes(&self) -> usize {
        // TODO(vlad): 2 * mss
        2 * DEFAULT_MSS
    }

    pub(super) fn check_persistent_queue(&mut self, target_gain: f32) {
        let target = self
            .bdp(self.max_bandwidth(), target_gain)
            .max(self.bdp0() + self.queueing_threshold_extra_bytes());

        if self.min_bytes_in_flight_in_round < target {
            self.rounds_with_queueing = 0;
            return;
        }

        self.rounds_with_queueing += 1;
        #[allow(clippy::absurd_extreme_comparisons)]
        if self.rounds_with_queueing >= PARAMS.max_startup_queue_rounds {
            self.full_bandwidth_reached = true;
        }
    }

    pub(super) fn max_bytes_delivered_in_round(&self) -> usize {
        self.max_bytes_delivered_in_round
    }

    pub(super) fn total_bytes_acked(&self) -> usize {
        self.bandwidth_sampler.total_bytes_acked()
    }

    pub(super) fn total_bytes_lost(&self) -> usize {
        self.bandwidth_sampler.total_bytes_lost()
    }

    fn round_trip_count(&self) -> usize {
        self.round_trip_counter.round_trip_count
    }

    pub(super) fn full_bandwidth_reached(&self) -> bool {
        self.full_bandwidth_reached
    }

    pub(super) fn set_full_bandwidth_reached(&mut self) {
        self.full_bandwidth_reached = true
    }

    pub(super) fn pacing_gain(&self) -> f32 {
        self.pacing_gain
    }

    pub(super) fn set_pacing_gain(&mut self, pacing_gain: f32) {
        self.pacing_gain = pacing_gain
    }

    pub(super) fn cwnd_gain(&self) -> f32 {
        self.cwnd_gain
    }

    pub(super) fn set_cwnd_gain(&mut self, cwnd_gain: f32) {
        self.cwnd_gain = cwnd_gain
    }

    pub(super) fn inflight_hi(&self) -> usize {
        self.inflight_hi
    }

    pub(super) fn inflight_hi_with_headroom(&self) -> usize {
        let headroom =
            (self.inflight_hi as f32 * PARAMS.inflight_hi_headroom) as usize;
        self.inflight_hi.saturating_sub(headroom)
    }

    pub(super) fn set_inflight_hi(&mut self, new_inflight_hi: usize) {
        self.inflight_hi = new_inflight_hi
    }

    pub(super) fn inflight_hi_default(&self) -> usize {
        usize::MAX
    }

    pub(super) fn inflight_lo(&self) -> usize {
        self.inflight_lo
    }

    pub(super) fn clear_inflight_lo(&mut self) {
        self.inflight_lo = usize::MAX
    }

    pub(super) fn cap_inflight_lo(&mut self, cap: usize) {
        if self.inflight_lo != usize::MAX {
            self.inflight_lo = cap.min(self.inflight_lo)
        }
    }

    pub(super) fn clear_bandwidth_lo(&mut self) {
        self.bandwidth_lo = None
    }

    pub(super) fn advance_max_bandwidth_filter(&mut self) {
        self.max_bandwidth_filter.advance()
    }

    pub(super) fn postpone_min_rtt_timestamp(&mut self, duration: Duration) {
        self.min_rtt_filter
            .force_update(self.min_rtt(), self.min_rtt_timestamp().add(duration));
    }

    pub(super) fn on_app_limited(&mut self) {
        self.bandwidth_sampler.on_app_limited()
    }

    pub(super) fn loss_events_in_round(&self) -> usize {
        self.loss_events_in_round
    }

    pub(super) fn rounds_with_queueing(&self) -> usize {
        self.rounds_with_queueing
    }
}
