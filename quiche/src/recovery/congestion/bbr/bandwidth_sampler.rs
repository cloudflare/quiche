// Copyright (c) 2016 The Chromium Authors. All rights reserved.
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

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::bandwidth::Bandwidth;
use crate::recovery::congestion::Lost;
use crate::recovery::windowed_filter::WindowedFilter;
use crate::recovery::Acked;

#[derive(Debug)]
struct ConnectionStateMap<T> {
    packet_map: VecDeque<(u64, Option<T>)>,
}

impl<T> Default for ConnectionStateMap<T> {
    fn default() -> Self {
        ConnectionStateMap {
            packet_map: VecDeque::new(),
        }
    }
}

impl<T> ConnectionStateMap<T> {
    fn insert(&mut self, pkt_num: u64, val: T) {
        if let Some((last_pkt, _)) = self.packet_map.back() {
            assert!(pkt_num > *last_pkt, "{} > {}", pkt_num, *last_pkt);
        }

        self.packet_map.push_back((pkt_num, Some(val)));
    }

    fn take(&mut self, pkt_num: u64) -> Option<T> {
        // First we check if the next packet is the one we are looking for
        let first = self.packet_map.front()?;
        if first.0 == pkt_num {
            return self.packet_map.pop_front().and_then(|(_, v)| v);
        }
        // Use binary search
        let ret =
            match self.packet_map.binary_search_by_key(&pkt_num, |&(n, _)| n) {
                Ok(found) =>
                    self.packet_map.get_mut(found).and_then(|(_, v)| v.take()),
                Err(_) => None,
            };

        while let Some((_, None)) = self.packet_map.front() {
            self.packet_map.pop_front();
        }

        ret
    }

    #[cfg(test)]
    fn peek(&self, pkt_num: u64) -> Option<&T> {
        // Use binary search
        match self.packet_map.binary_search_by_key(&pkt_num, |&(n, _)| n) {
            Ok(found) => self.packet_map.get(found).and_then(|(_, v)| v.as_ref()),
            Err(_) => None,
        }
    }

    fn remove_obsolete(&mut self, least_acked: u64) {
        while match self.packet_map.front() {
            Some(&(p, _)) if p < least_acked => {
                self.packet_map.pop_front();
                true
            },
            _ => false,
        } {}
    }
}

#[derive(Debug)]
pub struct BandwidthSampler {
    /// The total number of congestion controlled bytes sent during the
    /// connection.
    total_bytes_sent: usize,
    total_bytes_acked: usize,
    total_bytes_lost: usize,
    total_bytes_neutered: usize,
    last_sent_packet: u64,
    last_acked_packet: u64,
    is_app_limited: bool,
    last_acked_packet_ack_time: Instant,
    total_bytes_sent_at_last_acked_packet: usize,
    last_acked_packet_sent_time: Instant,
    recent_ack_points: RecentAckPoints,
    a0_candidates: VecDeque<AckPoint>,
    connection_state_map: ConnectionStateMap<ConnectionStateOnSentPacket>,
    max_ack_height_tracker: MaxAckHeightTracker,
    /// The packet that will be acknowledged after this one will cause the
    /// sampler to exit the app-limited phase.
    end_of_app_limited_phase: Option<u64>,
    overestimate_avoidance: bool,
    limit_max_ack_height_tracker_by_send_rate: bool,

    total_bytes_acked_after_last_ack_event: usize,
}

/// A subset of [`ConnectionStateOnSentPacket`] which is returned
/// to the caller when the packet is acked or lost.
#[derive(Debug, Default, Clone, Copy)]
pub struct SendTimeState {
    /// Whether other states in this object is valid.
    pub is_valid: bool,
    /// Whether the sender is app limited at the time the packet was sent.
    /// App limited bandwidth sample might be artificially low because the
    /// sender did not have enough data to send in order to saturate the
    /// link.
    pub is_app_limited: bool,
    /// Total number of sent bytes at the time the packet was sent.
    /// Includes the packet itself.
    pub total_bytes_sent: usize,
    /// Total number of acked bytes at the time the packet was sent.
    pub total_bytes_acked: usize,
    /// Total number of lost bytes at the time the packet was sent.
    #[allow(dead_code)]
    pub total_bytes_lost: usize,
    /// Total number of inflight bytes at the time the packet was sent.
    /// Includes the packet itself.
    /// It should be equal to `total_bytes_sent` minus the sum of
    /// `total_bytes_acked`, `total_bytes_lost` and total neutered bytes.
    pub bytes_in_flight: usize,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
struct ExtraAckedEvent {
    /// The excess bytes acknowlwedged in the time delta for this event.
    extra_acked: usize,
    /// The bytes acknowledged and time delta from the event.
    bytes_acked: usize,
    time_delta: Duration,
    /// The round trip of the event.
    round: usize,
}

struct BandwidthSample {
    /// The bandwidth at that particular sample.
    bandwidth: Bandwidth,
    /// The RTT measurement at this particular sample.  Does not correct for
    /// delayed ack time.
    rtt: Duration,
    /// [`send_rate`] is computed from the current packet being acked('P') and
    /// an earlier packet that is acked before P was sent.
    send_rate: Option<Bandwidth>,
    /// States captured when the packet was sent.
    state_at_send: SendTimeState,
}

/// [`AckPoint`] represents a point on the ack line.
#[derive(Debug, Clone, Copy)]
struct AckPoint {
    ack_time: Instant,
    total_bytes_acked: usize,
}

/// [`RecentAckPoints`] maintains the most recent 2 ack points at distinct
/// times.
#[derive(Debug, Default)]
struct RecentAckPoints {
    ack_points: [Option<AckPoint>; 2],
}

// [`ConnectionStateOnSentPacket`] represents the information about a sent
// packet and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
#[derive(Debug)]
struct ConnectionStateOnSentPacket {
    /// Time at which the packet is sent.
    sent_time: Instant,
    /// Size of the packet.
    size: usize,
    /// The value of [`total_bytes_sent_at_last_acked_packet`] at the time the
    /// packet was sent.
    total_bytes_sent_at_last_acked_packet: usize,
    /// The value of [`last_acked_packet_sent_time`] at the time the packet was
    /// sent.
    last_acked_packet_sent_time: Instant,
    /// The value of [`last_acked_packet_ack_time`] at the time the packet was
    /// sent.
    last_acked_packet_ack_time: Instant,
    /// Send time states that are returned to the congestion controller when the
    /// packet is acked or lost.
    send_time_state: SendTimeState,
}

/// [`MaxAckHeightTracker`] is part of the [`BandwidthSampler`]. It is called
/// after every ack event to keep track the degree of ack
/// aggregation(a.k.a "ack height").
#[derive(Debug)]
struct MaxAckHeightTracker {
    /// Tracks the maximum number of bytes acked faster than the estimated
    /// bandwidth.
    max_ack_height_filter: WindowedFilter<ExtraAckedEvent, usize, usize>,
    /// The time this aggregation started and the number of bytes acked during
    /// it.
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: usize,
    /// The last sent packet number before the current aggregation epoch
    /// started.
    last_sent_packet_number_before_epoch: u64,
    /// The number of ack aggregation epochs ever started, including the ongoing
    /// one. Stats only.
    num_ack_aggregation_epochs: u64,
    ack_aggregation_bandwidth_threshold: f64,
    start_new_aggregation_epoch_after_full_round: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

#[derive(Default)]
pub(crate) struct CongestionEventSample {
    /// The maximum bandwidth sample from all acked packets.
    pub sample_max_bandwidth: Option<Bandwidth>,
    /// Whether [`sample_max_bandwidth`] is from a app-limited sample.
    pub sample_is_app_limited: bool,
    /// The minimum rtt sample from all acked packets.
    pub sample_rtt: Option<Duration>,
    /// For each packet p in acked packets, this is the max value of
    /// INFLIGHT(p), where INFLIGHT(p) is the number of bytes acked while p
    /// is inflight.
    pub sample_max_inflight: usize,
    /// The send state of the largest packet in acked_packets, unless it is
    /// empty. If acked_packets is empty, it's the send state of the largest
    /// packet in lost_packets.
    pub last_packet_send_state: SendTimeState,
    /// The number of extra bytes acked from this ack event, compared to what is
    /// expected from the flow's bandwidth. Larger value means more ack
    /// aggregation.
    pub extra_acked: usize,
}

impl MaxAckHeightTracker {
    pub(crate) fn new(window: usize, overestimate_avoidance: bool) -> Self {
        MaxAckHeightTracker {
            max_ack_height_filter: WindowedFilter::new(window),
            aggregation_epoch_start_time: None,
            aggregation_epoch_bytes: 0,
            last_sent_packet_number_before_epoch: 0,
            num_ack_aggregation_epochs: 0,
            ack_aggregation_bandwidth_threshold: if overestimate_avoidance {
                2.0
            } else {
                1.0
            },
            start_new_aggregation_epoch_after_full_round: true,
            reduce_extra_acked_on_bandwidth_increase: true,
        }
    }

    fn reset(&mut self, new_height: usize, new_time: usize) {
        self.max_ack_height_filter.reset(
            ExtraAckedEvent {
                extra_acked: new_height,
                bytes_acked: 0,
                time_delta: Duration::ZERO,
                round: new_time,
            },
            new_time,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self, bandwidth_estimate: Bandwidth, is_new_max_bandwidth: bool,
        round_trip_count: usize, last_sent_packet_number: u64,
        last_acked_packet_number: u64, ack_time: Instant, bytes_acked: usize,
    ) -> usize {
        let mut force_new_epoch = false;

        if self.reduce_extra_acked_on_bandwidth_increase && is_new_max_bandwidth {
            // Save and clear existing entries.
            let mut best =
                self.max_ack_height_filter.get_best().unwrap_or_default();
            let mut second_best = self
                .max_ack_height_filter
                .get_second_best()
                .unwrap_or_default();
            let mut third_best = self
                .max_ack_height_filter
                .get_third_best()
                .unwrap_or_default();
            self.max_ack_height_filter.clear();

            // Reinsert the heights into the filter after recalculating.
            let expected_bytes_acked =
                bandwidth_estimate.to_bytes_per_period(best.time_delta) as usize;
            if expected_bytes_acked < best.bytes_acked {
                best.extra_acked = best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter.update(best, best.round);
            }

            let expected_bytes_acked = bandwidth_estimate
                .to_bytes_per_period(second_best.time_delta)
                as usize;
            if expected_bytes_acked < second_best.bytes_acked {
                second_best.extra_acked =
                    second_best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter
                    .update(second_best, second_best.round);
            }

            let expected_bytes_acked = bandwidth_estimate
                .to_bytes_per_period(third_best.time_delta)
                as usize;
            if expected_bytes_acked < third_best.bytes_acked {
                third_best.extra_acked =
                    third_best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter
                    .update(third_best, third_best.round);
            }
        }

        // If any packet sent after the start of the epoch has been acked, start a
        // new epoch.
        if self.start_new_aggregation_epoch_after_full_round &&
            last_acked_packet_number >
                self.last_sent_packet_number_before_epoch
        {
            force_new_epoch = true;
        }

        let epoch_start_time = match self.aggregation_epoch_start_time {
            Some(time) if !force_new_epoch => time,
            _ => {
                self.aggregation_epoch_bytes = bytes_acked;
                self.aggregation_epoch_start_time = Some(ack_time);
                self.last_sent_packet_number_before_epoch =
                    last_sent_packet_number;
                self.num_ack_aggregation_epochs += 1;
                return 0;
            },
        };

        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let aggregation_delta = ack_time.duration_since(epoch_start_time);
        let expected_bytes_acked =
            bandwidth_estimate.to_bytes_per_period(aggregation_delta) as usize;
        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes <=
            (self.ack_aggregation_bandwidth_threshold *
                expected_bytes_acked as f64) as usize
        {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = bytes_acked;
            self.aggregation_epoch_start_time = Some(ack_time);
            self.last_sent_packet_number_before_epoch = last_sent_packet_number;
            self.num_ack_aggregation_epochs += 1;
            return 0;
        }

        self.aggregation_epoch_bytes += bytes_acked;

        // Compute how many extra bytes were delivered vs max bandwidth.
        let extra_bytes_acked =
            self.aggregation_epoch_bytes - expected_bytes_acked;

        let new_event = ExtraAckedEvent {
            extra_acked: extra_bytes_acked,
            bytes_acked: self.aggregation_epoch_bytes,
            time_delta: aggregation_delta,
            round: 0,
        };

        self.max_ack_height_filter
            .update(new_event, round_trip_count);
        extra_bytes_acked
    }
}

impl From<(Instant, usize, usize, &BandwidthSampler)>
    for ConnectionStateOnSentPacket
{
    fn from(
        (sent_time, size, bytes_in_flight, sampler): (
            Instant,
            usize,
            usize,
            &BandwidthSampler,
        ),
    ) -> Self {
        ConnectionStateOnSentPacket {
            sent_time,
            size,
            total_bytes_sent_at_last_acked_packet: sampler
                .total_bytes_sent_at_last_acked_packet,
            last_acked_packet_sent_time: sampler.last_acked_packet_sent_time,
            last_acked_packet_ack_time: sampler.last_acked_packet_ack_time,
            send_time_state: SendTimeState {
                is_valid: true,
                is_app_limited: sampler.is_app_limited,
                total_bytes_sent: sampler.total_bytes_sent,
                total_bytes_acked: sampler.total_bytes_acked,
                total_bytes_lost: sampler.total_bytes_lost,
                bytes_in_flight,
            },
        }
    }
}

impl RecentAckPoints {
    fn update(&mut self, ack_time: Instant, total_bytes_acked: usize) {
        assert!(
            total_bytes_acked >=
                self.ack_points[1].map(|p| p.total_bytes_acked).unwrap_or(0)
        );

        self.ack_points[0] = self.ack_points[1];
        self.ack_points[1] = Some(AckPoint {
            ack_time,
            total_bytes_acked,
        });
    }

    fn clear(&mut self) {
        self.ack_points = Default::default();
    }

    fn most_recent(&self) -> Option<AckPoint> {
        self.ack_points[1]
    }

    fn less_recent_point(&self) -> Option<AckPoint> {
        self.ack_points[0].or(self.ack_points[1])
    }
}

impl BandwidthSampler {
    pub(crate) fn new(
        max_height_tracker_window_length: usize, overestimate_avoidance: bool,
    ) -> Self {
        BandwidthSampler {
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            total_bytes_lost: 0,
            total_bytes_neutered: 0,
            total_bytes_sent_at_last_acked_packet: 0,
            last_acked_packet_sent_time: Instant::now(),
            last_acked_packet_ack_time: Instant::now(),
            is_app_limited: true,
            connection_state_map: ConnectionStateMap::default(),
            max_ack_height_tracker: MaxAckHeightTracker::new(
                max_height_tracker_window_length,
                overestimate_avoidance,
            ),
            total_bytes_acked_after_last_ack_event: 0,
            overestimate_avoidance,
            limit_max_ack_height_tracker_by_send_rate: false,

            last_sent_packet: 0,
            last_acked_packet: 0,
            recent_ack_points: RecentAckPoints::default(),
            a0_candidates: VecDeque::new(),
            end_of_app_limited_phase: None,
        }
    }

    pub(crate) fn is_app_limited(&self) -> bool {
        self.is_app_limited
    }

    pub(crate) fn on_packet_sent(
        &mut self, sent_time: Instant, packet_number: u64, bytes: usize,
        bytes_in_flight: usize, has_retransmittable_data: bool,
    ) {
        self.last_sent_packet = packet_number;

        if !has_retransmittable_data {
            return;
        }

        self.total_bytes_sent += bytes;

        // If there are no packets in flight, the time at which the new
        // transmission opens can be treated as the A_0 point for the
        // purpose of bandwidth sampling. This underestimates bandwidth to
        // some extent, and produces some artificially low samples for
        // most packets in flight, but it provides with samples at
        // important points where we would not have them otherwise, most
        // importantly at the beginning of the connection.
        if bytes_in_flight == 0 {
            self.last_acked_packet_ack_time = sent_time;
            if self.overestimate_avoidance {
                self.recent_ack_points.clear();
                self.recent_ack_points
                    .update(sent_time, self.total_bytes_acked);
                self.a0_candidates.clear();
                self.a0_candidates
                    .push_back(self.recent_ack_points.most_recent().unwrap());
            }

            self.total_bytes_sent_at_last_acked_packet = self.total_bytes_sent;

            // In this situation ack compression is not a concern, set send rate
            // to effectively infinite.
            self.last_acked_packet_sent_time = sent_time;
        }

        self.connection_state_map.insert(
            packet_number,
            (sent_time, bytes, bytes_in_flight + bytes, &*self).into(),
        );
    }

    pub(crate) fn on_packet_neutered(&mut self, packet_number: u64) {
        if let Some(pkt) = self.connection_state_map.take(packet_number) {
            self.total_bytes_neutered += pkt.size;
        }
    }

    pub(crate) fn on_congestion_event(
        &mut self, ack_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], mut max_bandwidth: Option<Bandwidth>,
        est_bandwidth_upper_bound: Bandwidth, round_trip_count: usize,
    ) -> CongestionEventSample {
        let mut last_lost_packet_send_state = SendTimeState::default();
        let mut last_acked_packet_send_state = SendTimeState::default();
        let mut last_lost_packet_num = 0u64;
        let mut last_acked_packet_num = 0u64;

        for packet in lost_packets {
            let send_state =
                self.on_packet_lost(packet.packet_number, packet.bytes_lost);
            if send_state.is_valid {
                last_lost_packet_send_state = send_state;
                last_lost_packet_num = packet.packet_number;
            }
        }

        if acked_packets.is_empty() {
            // Only populate send state for a loss-only event.
            return CongestionEventSample {
                last_packet_send_state: last_lost_packet_send_state,
                ..Default::default()
            };
        }

        let mut event_sample = CongestionEventSample::default();

        let mut max_send_rate = None;
        for packet in acked_packets {
            let sample =
                match self.on_packet_acknowledged(ack_time, packet.pkt_num) {
                    Some(sample) if sample.state_at_send.is_valid => sample,
                    _ => continue,
                };

            last_acked_packet_send_state = sample.state_at_send;
            last_acked_packet_num = packet.pkt_num;

            event_sample.sample_rtt = Some(
                sample
                    .rtt
                    .min(*event_sample.sample_rtt.get_or_insert(sample.rtt)),
            );

            if Some(sample.bandwidth) > event_sample.sample_max_bandwidth {
                event_sample.sample_max_bandwidth = Some(sample.bandwidth);
                event_sample.sample_is_app_limited =
                    sample.state_at_send.is_app_limited;
            }
            max_send_rate = max_send_rate.max(sample.send_rate);

            let inflight_sample = self.total_bytes_acked -
                last_acked_packet_send_state.total_bytes_acked;
            if inflight_sample > event_sample.sample_max_inflight {
                event_sample.sample_max_inflight = inflight_sample;
            }
        }

        if !last_lost_packet_send_state.is_valid {
            event_sample.last_packet_send_state = last_acked_packet_send_state;
        } else if !last_acked_packet_send_state.is_valid {
            event_sample.last_packet_send_state = last_lost_packet_send_state;
        } else {
            // If two packets are inflight and an alarm is armed to lose a packet
            // and it wakes up late, then the first of two in flight packets could
            // have been acknowledged before the wakeup, which re-evaluates loss
            // detection, and could declare the later of the two lost.
            event_sample.last_packet_send_state =
                if last_acked_packet_num > last_lost_packet_num {
                    last_acked_packet_send_state
                } else {
                    last_lost_packet_send_state
                };
        }

        let is_new_max_bandwidth =
            event_sample.sample_max_bandwidth > max_bandwidth;
        max_bandwidth = event_sample.sample_max_bandwidth.max(max_bandwidth);

        if self.limit_max_ack_height_tracker_by_send_rate {
            max_bandwidth = max_bandwidth.max(max_send_rate);
        }

        let bandwidth_estimate = if let Some(max_bandwidth) = max_bandwidth {
            max_bandwidth.min(est_bandwidth_upper_bound)
        } else {
            est_bandwidth_upper_bound
        };

        event_sample.extra_acked = self.on_ack_event_end(
            bandwidth_estimate,
            is_new_max_bandwidth,
            round_trip_count,
        );

        event_sample
    }

    fn on_packet_lost(
        &mut self, packet_number: u64, bytes_lost: usize,
    ) -> SendTimeState {
        let mut send_time_state = SendTimeState::default();

        self.total_bytes_lost += bytes_lost;
        if let Some(state) = self.connection_state_map.take(packet_number) {
            send_time_state = state.send_time_state;
            send_time_state.is_valid = true;
        }

        send_time_state
    }

    fn on_ack_event_end(
        &mut self, bandwidth_estimate: Bandwidth, is_new_max_bandwidth: bool,
        round_trip_count: usize,
    ) -> usize {
        let newly_acked_bytes =
            self.total_bytes_acked - self.total_bytes_acked_after_last_ack_event;

        if newly_acked_bytes == 0 {
            return 0;
        }

        self.total_bytes_acked_after_last_ack_event = self.total_bytes_acked;
        let extra_acked = self.max_ack_height_tracker.update(
            bandwidth_estimate,
            is_new_max_bandwidth,
            round_trip_count,
            self.last_sent_packet,
            self.last_acked_packet,
            self.last_acked_packet_ack_time,
            newly_acked_bytes,
        );
        // If `extra_acked` is zero, i.e. this ack event marks the start of a new
        // ack aggregation epoch, save `less_recent_point`, which is the
        // last ack point of the previous epoch, as a A0 candidate.
        if self.overestimate_avoidance && extra_acked == 0 {
            self.a0_candidates
                .push_back(self.recent_ack_points.less_recent_point().unwrap());
        }

        extra_acked
    }

    fn on_packet_acknowledged(
        &mut self, ack_time: Instant, packet_number: u64,
    ) -> Option<BandwidthSample> {
        self.last_acked_packet = packet_number;
        let sent_packet = match self.connection_state_map.take(packet_number) {
            None => return None,
            Some(state) => state,
        };

        self.total_bytes_acked += sent_packet.size;
        self.total_bytes_sent_at_last_acked_packet =
            sent_packet.send_time_state.total_bytes_sent;
        self.last_acked_packet_sent_time = sent_packet.sent_time;
        self.last_acked_packet_ack_time = ack_time;
        if self.overestimate_avoidance {
            self.recent_ack_points
                .update(ack_time, self.total_bytes_acked);
        }

        if self.is_app_limited {
            // Exit app-limited phase in two cases:
            // (1) end_of_app_limited_phase is not initialized, i.e., so far all
            // packets are sent while there are buffered packets or pending data.
            // (2) The current acked packet is after the sent packet marked as the
            // end of the app limit phase.
            if self.end_of_app_limited_phase.is_none() ||
                Some(packet_number) > self.end_of_app_limited_phase
            {
                self.is_app_limited = false;
            }
        }

        // No send rate indicates that the sampler is supposed to discard the
        // current send rate sample and use only the ack rate.
        let send_rate = if sent_packet.sent_time >
            sent_packet.last_acked_packet_sent_time
        {
            Some(Bandwidth::from_bytes_and_time_delta(
                sent_packet.send_time_state.total_bytes_sent -
                    sent_packet.total_bytes_sent_at_last_acked_packet,
                sent_packet.sent_time - sent_packet.last_acked_packet_sent_time,
            ))
        } else {
            None
        };

        let a0 = if self.overestimate_avoidance {
            Self::choose_a0_point(
                &mut self.a0_candidates,
                sent_packet.send_time_state.total_bytes_acked,
            )
        } else {
            None
        };

        let a0 = a0.unwrap_or(AckPoint {
            ack_time: sent_packet.last_acked_packet_ack_time,
            total_bytes_acked: sent_packet.send_time_state.total_bytes_acked,
        });

        // During the slope calculation, ensure that ack time of the current
        // packet is always larger than the time of the previous packet,
        // otherwise division by zero or integer underflow can occur.
        if ack_time <= a0.ack_time {
            return None;
        }

        let ack_rate = Bandwidth::from_bytes_and_time_delta(
            self.total_bytes_acked - a0.total_bytes_acked,
            ack_time.duration_since(a0.ack_time),
        );

        let bandwidth = if let Some(send_rate) = send_rate {
            send_rate.min(ack_rate)
        } else {
            ack_rate
        };

        // Note: this sample does not account for delayed acknowledgement time.
        // This means that the RTT measurements here can be artificially
        // high, especially on low bandwidth connections.
        let rtt = ack_time.duration_since(sent_packet.sent_time);

        Some(BandwidthSample {
            bandwidth,
            rtt,
            send_rate,
            state_at_send: SendTimeState {
                is_valid: true,
                ..sent_packet.send_time_state
            },
        })
    }

    fn choose_a0_point(
        a0_candidates: &mut VecDeque<AckPoint>, total_bytes_acked: usize,
    ) -> Option<AckPoint> {
        if a0_candidates.is_empty() {
            return None;
        }

        while let Some(candidate) = a0_candidates.get(1) {
            if candidate.total_bytes_acked > total_bytes_acked {
                return Some(*candidate);
            }
            a0_candidates.pop_front();
        }

        Some(a0_candidates[0])
    }

    pub(crate) fn total_bytes_acked(&self) -> usize {
        self.total_bytes_acked
    }

    pub(crate) fn total_bytes_lost(&self) -> usize {
        self.total_bytes_lost
    }

    pub(crate) fn reset_max_ack_height_tracker(
        &mut self, new_height: usize, new_time: usize,
    ) {
        self.max_ack_height_tracker.reset(new_height, new_time);
    }

    pub(crate) fn max_ack_height(&self) -> Option<usize> {
        self.max_ack_height_tracker
            .max_ack_height_filter
            .get_best()
            .map(|b| b.extra_acked)
    }

    pub(crate) fn on_app_limited(&mut self) {
        self.is_app_limited = true;
        self.end_of_app_limited_phase = Some(self.last_sent_packet);
    }

    pub(crate) fn remove_obsolete_packets(&mut self, least_acked: u64) {
        // A packet can become obsolete when it is removed from
        // QuicUnackedPacketMap's view of inflight before it is acked or
        // marked as lost. For example, when
        // QuicSentPacketManager::RetransmitCryptoPackets retransmits a crypto
        // packet, the packet is removed from QuicUnackedPacketMap's
        // inflight, but is not marked as acked or lost in the
        // BandwidthSampler.
        self.connection_state_map.remove_obsolete(least_acked);
    }
}

#[cfg(test)]
mod bandwidth_sampler_tests {
    use super::*;

    const REGULAR_PACKET_SIZE: usize = 1280;

    struct TestSender {
        sampler: BandwidthSampler,
        sampler_app_limited_at_start: bool,
        bytes_in_flight: usize,
        clock: Instant,
        max_bandwidth: Bandwidth,
        est_bandwidth_upper_bound: Bandwidth,
        round_trip_count: usize,
    }

    impl TestSender {
        fn new() -> Self {
            let sampler = BandwidthSampler::new(0, false);
            TestSender {
                sampler_app_limited_at_start: sampler.is_app_limited(),
                sampler,
                bytes_in_flight: 0,
                clock: Instant::now(),
                max_bandwidth: Bandwidth::zero(),
                est_bandwidth_upper_bound: Bandwidth::infinite(),
                round_trip_count: 0,
            }
        }

        fn get_packet_size(&self, pkt_num: u64) -> usize {
            self.sampler
                .connection_state_map
                .peek(pkt_num)
                .unwrap()
                .size
        }

        fn get_packet_time(&self, pkt_num: u64) -> Instant {
            self.sampler
                .connection_state_map
                .peek(pkt_num)
                .unwrap()
                .sent_time
        }

        fn number_of_tracked_packets(&self) -> usize {
            self.sampler.connection_state_map.packet_map.len()
        }

        fn make_acked_packet(&self, pkt_num: u64) -> Acked {
            let size = self.get_packet_size(pkt_num);
            let time_sent = self.get_packet_time(pkt_num);

            Acked {
                pkt_num,
                time_sent,
                size,
            }
        }

        fn make_lost_packet(&self, pkt_num: u64) -> Lost {
            let size = self.get_packet_size(pkt_num);
            Lost {
                packet_number: pkt_num,
                bytes_lost: size,
            }
        }

        fn ack_packet(&mut self, pkt_num: u64) -> BandwidthSample {
            let size = self.get_packet_size(pkt_num);
            self.bytes_in_flight -= size;

            let sample = self.sampler.on_congestion_event(
                self.clock,
                &[self.make_acked_packet(pkt_num)],
                &[],
                Some(self.max_bandwidth),
                self.est_bandwidth_upper_bound,
                self.round_trip_count,
            );

            let max_bandwidth =
                self.max_bandwidth.max(sample.sample_max_bandwidth.unwrap());

            let bandwidth_sample = BandwidthSample {
                bandwidth: max_bandwidth,
                rtt: sample.sample_rtt.unwrap(),
                send_rate: None,
                state_at_send: sample.last_packet_send_state,
            };
            assert!(bandwidth_sample.state_at_send.is_valid);
            bandwidth_sample
        }

        fn lose_packet(&mut self, pkt_num: u64) -> SendTimeState {
            let size = self.get_packet_size(pkt_num);
            self.bytes_in_flight -= size;

            let sample = self.sampler.on_congestion_event(
                self.clock,
                &[],
                &[self.make_lost_packet(pkt_num)],
                Some(self.max_bandwidth),
                self.est_bandwidth_upper_bound,
                self.round_trip_count,
            );

            assert!(sample.last_packet_send_state.is_valid);
            assert_eq!(sample.sample_max_bandwidth, None);
            assert_eq!(sample.sample_rtt, None);
            sample.last_packet_send_state
        }

        fn on_congestion_event(
            &mut self, acked: &[u64], lost: &[u64],
        ) -> CongestionEventSample {
            let acked = acked
                .into_iter()
                .map(|pkt| {
                    let acked = self.make_acked_packet(*pkt);
                    self.bytes_in_flight -= acked.size;
                    acked
                })
                .collect::<Vec<_>>();

            let lost = lost
                .into_iter()
                .map(|pkt| {
                    let lost = self.make_lost_packet(*pkt);
                    self.bytes_in_flight -= lost.bytes_lost;
                    lost
                })
                .collect::<Vec<_>>();

            let sample = self.sampler.on_congestion_event(
                self.clock,
                &acked,
                &lost,
                Some(self.max_bandwidth),
                self.est_bandwidth_upper_bound,
                self.round_trip_count,
            );

            self.max_bandwidth =
                self.max_bandwidth.max(sample.sample_max_bandwidth.unwrap());

            sample
        }

        fn send_packet(
            &mut self, pkt_num: u64, pkt_sz: usize,
            has_retransmittable_data: bool,
        ) {
            self.sampler.on_packet_sent(
                self.clock,
                pkt_num,
                pkt_sz,
                self.bytes_in_flight,
                has_retransmittable_data,
            );
            if has_retransmittable_data {
                self.bytes_in_flight += pkt_sz;
            }
        }

        fn advance_time(&mut self, delta: Duration) {
            self.clock += delta;
        }

        // Sends one packet and acks it.  Then, send 20 packets.  Finally, send
        // another 20 packets while acknowledging previous 20.
        fn send_40_and_ack_first_20(&mut self, time_between_packets: Duration) {
            // Send 20 packets at a constant inter-packet time.
            for i in 1..=20 {
                self.send_packet(i, REGULAR_PACKET_SIZE, true);
                self.advance_time(time_between_packets);
            }

            // Ack packets 1 to 20, while sending new packets at the same rate as
            // before.
            for i in 1..=20 {
                self.ack_packet(i);
                self.send_packet(i + 20, REGULAR_PACKET_SIZE, true);
                self.advance_time(time_between_packets);
            }
        }
    }

    #[test]
    fn send_and_wait() {
        let mut test_sender = TestSender::new();
        let mut time_between_packets = Duration::from_millis(10);
        let mut expected_bandwidth =
            Bandwidth::from_bytes_per_second(REGULAR_PACKET_SIZE as u64 * 100);

        // Send packets at the constant bandwidth.
        for i in 1..20 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
            let current_sample = test_sender.ack_packet(i);
            assert_eq!(expected_bandwidth, current_sample.bandwidth);
        }

        // Send packets at the exponentially decreasing bandwidth.
        for i in 20..25 {
            time_between_packets = time_between_packets * 2;
            expected_bandwidth = expected_bandwidth * 0.5;

            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
            let current_sample = test_sender.ack_packet(i);
            assert_eq!(expected_bandwidth, current_sample.bandwidth);
        }

        test_sender.sampler.remove_obsolete_packets(25);
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    #[test]
    fn send_time_state() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(10);

        // Send packets 1-5.
        for i in 1..=5 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            assert_eq!(
                test_sender.sampler.total_bytes_sent,
                REGULAR_PACKET_SIZE * i as usize
            );
            test_sender.advance_time(time_between_packets);
        }

        // Ack packet 1.
        let send_time_state = test_sender.ack_packet(1).state_at_send;
        assert_eq!(REGULAR_PACKET_SIZE * 1, send_time_state.total_bytes_sent);
        assert_eq!(0, send_time_state.total_bytes_acked);
        assert_eq!(0, send_time_state.total_bytes_lost);
        assert_eq!(
            REGULAR_PACKET_SIZE * 1,
            test_sender.sampler.total_bytes_acked
        );

        // Lose packet 2.
        let send_time_state = test_sender.lose_packet(2);
        assert_eq!(REGULAR_PACKET_SIZE * 2, send_time_state.total_bytes_sent);
        assert_eq!(0, send_time_state.total_bytes_acked);
        assert_eq!(0, send_time_state.total_bytes_lost);
        assert_eq!(
            REGULAR_PACKET_SIZE * 1,
            test_sender.sampler.total_bytes_lost
        );

        // Lose packet 3.
        let send_time_state = test_sender.lose_packet(3);
        assert_eq!(REGULAR_PACKET_SIZE * 3, send_time_state.total_bytes_sent);
        assert_eq!(0, send_time_state.total_bytes_acked);
        assert_eq!(0, send_time_state.total_bytes_lost);
        assert_eq!(
            REGULAR_PACKET_SIZE * 2,
            test_sender.sampler.total_bytes_lost
        );

        // Send packets 6-10.
        for i in 6..=10 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            assert_eq!(
                test_sender.sampler.total_bytes_sent,
                REGULAR_PACKET_SIZE * i as usize
            );
            test_sender.advance_time(time_between_packets);
        }

        // Ack all inflight packets.
        let mut acked_packet_count = 1;
        assert_eq!(
            REGULAR_PACKET_SIZE * acked_packet_count,
            test_sender.sampler.total_bytes_acked
        );
        for i in 4..=10 {
            let send_time_state = test_sender.ack_packet(i).state_at_send;
            acked_packet_count += 1;
            assert_eq!(
                REGULAR_PACKET_SIZE * acked_packet_count,
                test_sender.sampler.total_bytes_acked
            );
            assert_eq!(
                REGULAR_PACKET_SIZE * i as usize,
                send_time_state.total_bytes_sent
            );

            if i <= 5 {
                assert_eq!(0, send_time_state.total_bytes_acked);
                assert_eq!(0, send_time_state.total_bytes_lost);
            } else {
                assert_eq!(
                    REGULAR_PACKET_SIZE * 1,
                    send_time_state.total_bytes_acked
                );
                assert_eq!(
                    REGULAR_PACKET_SIZE * 2,
                    send_time_state.total_bytes_lost
                );
            }

            // This equation works because there is no neutered bytes.
            assert_eq!(
                send_time_state.total_bytes_sent -
                    send_time_state.total_bytes_acked -
                    send_time_state.total_bytes_lost,
                send_time_state.bytes_in_flight
            );

            test_sender.advance_time(time_between_packets);
        }
    }

    /// Test the sampler during regular windowed sender scenario with fixed CWND
    /// of 20.
    #[test]
    fn send_paced() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let expected_bandwidth =
            Bandwidth::from_kbits_per_second(REGULAR_PACKET_SIZE as u64 * 8);

        test_sender.send_40_and_ack_first_20(time_between_packets);

        // Ack the packets 21 to 40, arriving at the correct bandwidth.
        for i in 21..=40 {
            let last_bandwidth = test_sender.ack_packet(i).bandwidth;
            assert_eq!(expected_bandwidth, last_bandwidth);
            test_sender.advance_time(time_between_packets);
        }
        test_sender.sampler.remove_obsolete_packets(41);
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    /// Test the sampler in a scenario where 50% of packets is consistently
    /// lost.
    #[test]
    fn send_with_losses() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let expected_bandwidth =
            Bandwidth::from_kbits_per_second(REGULAR_PACKET_SIZE as u64 / 2 * 8);

        // Send 20 packets, each 1 ms apart.
        for i in 1..=20 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        // Ack packets 1 to 20, losing every even-numbered packet, while sending
        // new packets at the same rate as before.
        for i in 1..=20 {
            if i % 2 == 0 {
                test_sender.ack_packet(i);
            } else {
                test_sender.lose_packet(i);
            }
            test_sender.send_packet(i + 20, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        // Ack the packets 21 to 40 with the same loss pattern.
        for i in 21..=40 {
            if i % 2 == 0 {
                let last_bandwidth = test_sender.ack_packet(i).bandwidth;
                assert_eq!(expected_bandwidth, last_bandwidth);
            } else {
                test_sender.lose_packet(i);
            }
            test_sender.advance_time(time_between_packets);
        }
        test_sender.sampler.remove_obsolete_packets(41);
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    /// Test the sampler in a scenario where the 50% of packets are not
    /// congestion controlled (specifically, non-retransmittable data is not
    /// congestion controlled).  Should be functionally consistent in behavior
    /// with the [`send_with_losses`] test.
    #[test]
    fn not_congestion_controlled() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let expected_bandwidth =
            Bandwidth::from_kbits_per_second(REGULAR_PACKET_SIZE as u64 / 2 * 8);

        // Send 20 packets, each 1 ms apart. Every even packet is not congestion
        // controlled.
        for i in 1..=20 {
            let has_retransmittable_data = i % 2 == 0;
            test_sender.send_packet(
                i,
                REGULAR_PACKET_SIZE,
                has_retransmittable_data,
            );
            test_sender.advance_time(time_between_packets);
        }

        // Ensure only congestion controlled packets are tracked.
        assert_eq!(10, test_sender.number_of_tracked_packets());

        // Ack packets 2 to 21, ignoring every even-numbered packet, while sending
        // new packets at the same rate as before.
        for i in 1..=20 {
            if i % 2 == 0 {
                test_sender.ack_packet(i);
            }
            let has_retransmittable_data = i % 2 == 0;
            test_sender.send_packet(
                i + 20,
                REGULAR_PACKET_SIZE,
                has_retransmittable_data,
            );
            test_sender.advance_time(time_between_packets);
        }

        // Ack the packets 22 to 41 with the same congestion controlled pattern.
        for i in 21..=40 {
            if i % 2 == 0 {
                let last_bandwidth = test_sender.ack_packet(i).bandwidth;
                assert_eq!(expected_bandwidth, last_bandwidth);
            }
            test_sender.advance_time(time_between_packets);
        }

        test_sender.sampler.remove_obsolete_packets(41);
        // Since only congestion controlled packets are entered into the map, it
        // has to be empty at this point.
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    /// Simulate a situation where ACKs arrive in burst and earlier than usual,
    /// thus producing an ACK rate which is higher than the original send rate.
    #[test]
    fn compressed_ack() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let expected_bandwidth =
            Bandwidth::from_kbits_per_second(REGULAR_PACKET_SIZE as u64 * 8);

        test_sender.send_40_and_ack_first_20(time_between_packets);

        // Simulate an RTT somewhat lower than the one for 1-to-21 transmission.
        test_sender.advance_time(time_between_packets * 15);

        // Ack the packets 21 to 40 almost immediately at once.
        let ridiculously_small_time_delta = Duration::from_micros(20);
        let mut last_bandwidth = Bandwidth::zero();
        for i in 21..=40 {
            last_bandwidth = test_sender.ack_packet(i).bandwidth;
            test_sender.advance_time(ridiculously_small_time_delta);
        }
        assert_eq!(expected_bandwidth, last_bandwidth);

        test_sender.sampler.remove_obsolete_packets(41);
        // Since only congestion controlled packets are entered into the map, it
        // has to be empty at this point.
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    /// Tests receiving ACK packets in the reverse order.
    #[test]
    fn reordered_ack() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let expected_bandwidth =
            Bandwidth::from_kbits_per_second(REGULAR_PACKET_SIZE as u64 * 8);

        test_sender.send_40_and_ack_first_20(time_between_packets);

        // Ack the packets 21 to 40 in the reverse order, while sending packets 41
        // to 60.
        for i in 0..20 {
            let last_bandwidth = test_sender.ack_packet(40 - i).bandwidth;
            assert_eq!(expected_bandwidth, last_bandwidth);
            test_sender.send_packet(41 + i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        // Ack the packets 41 to 60, now in the regular order.
        for i in 41..=60 {
            let last_bandwidth = test_sender.ack_packet(i).bandwidth;
            assert_eq!(expected_bandwidth, last_bandwidth);
            test_sender.advance_time(time_between_packets);
        }

        test_sender.sampler.remove_obsolete_packets(61);
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    /// Test the app-limited logic.
    #[test]
    fn app_limited() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let expected_bandwidth =
            Bandwidth::from_kbits_per_second(REGULAR_PACKET_SIZE as u64 * 8);

        for i in 1..=20 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        for i in 1..=20 {
            let sample = test_sender.ack_packet(i);
            assert_eq!(
                sample.state_at_send.is_app_limited,
                test_sender.sampler_app_limited_at_start
            );
            test_sender.send_packet(i + 20, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        // We are now app-limited. Ack 21 to 40 as usual, but do not send anything
        // for now.
        test_sender.sampler.on_app_limited();
        for i in 21..=40 {
            let sample = test_sender.ack_packet(i);
            assert!(!sample.state_at_send.is_app_limited);
            assert_eq!(expected_bandwidth, sample.bandwidth);
            test_sender.advance_time(time_between_packets);
        }

        // Enter quiescence.
        test_sender.advance_time(Duration::from_secs(1));

        // Send packets 41 to 60, all of which would be marked as app-limited.
        for i in 41..=60 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        // Ack packets 41 to 60, while sending packets 61 to 80.  41 to 60 should
        // be app-limited and underestimate the bandwidth due to that.
        for i in 41..=60 {
            let sample = test_sender.ack_packet(i);
            assert!(sample.state_at_send.is_app_limited);
            assert!(sample.bandwidth < expected_bandwidth * 0.7);
            test_sender.send_packet(i + 20, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }

        // Run out of packets, and then ack packet 61 to 80, all of which should
        // have correct non-app-limited samples.
        for i in 61..=80 {
            let sample = test_sender.ack_packet(i);
            assert!(!sample.state_at_send.is_app_limited);
            assert_eq!(sample.bandwidth, expected_bandwidth);
            test_sender.advance_time(time_between_packets);
        }

        test_sender.sampler.remove_obsolete_packets(81);
        assert_eq!(0, test_sender.number_of_tracked_packets());
        assert_eq!(0, test_sender.bytes_in_flight);
    }

    /// Test the samples taken at the first flight of packets sent.
    #[test]
    fn first_round_trip() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(1);
        let rtt = Duration::from_millis(800);
        let num_packets = 10;
        let num_bytes = REGULAR_PACKET_SIZE * num_packets;
        let real_bandwidth = Bandwidth::from_bytes_and_time_delta(num_bytes, rtt);

        for i in 1..=10 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
        }
        test_sender.advance_time(rtt - time_between_packets * num_packets as _);

        let mut last_sample = Bandwidth::zero();
        for i in 1..=10 {
            let sample = test_sender.ack_packet(i).bandwidth;
            assert!(sample > last_sample);
            last_sample = sample;
            test_sender.advance_time(time_between_packets);
        }

        // The final measured sample for the first flight of sample is expected to
        // be smaller than the real bandwidth, yet it should not lose more
        // than 10%. The specific value of the error depends on the
        // difference between the RTT and the time it takes to exhaust the
        // congestion window (i.e. in the limit when all packets are sent
        // simultaneously, last sample would indicate the real bandwidth).
        assert!(last_sample < real_bandwidth);
        assert!(last_sample > real_bandwidth * 0.9);
    }

    /// Test sampler's ability to remove obsolete packets.
    #[test]
    fn remove_obsolete_packets() {
        let mut test_sender = TestSender::new();

        for i in 1..=5 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
        }
        test_sender.advance_time(Duration::from_millis(100));
        assert_eq!(5, test_sender.number_of_tracked_packets());
        test_sender.sampler.remove_obsolete_packets(4);
        assert_eq!(2, test_sender.number_of_tracked_packets());
        test_sender.lose_packet(4);
        test_sender.sampler.remove_obsolete_packets(5);
        assert_eq!(1, test_sender.number_of_tracked_packets());
        test_sender.ack_packet(5);
        test_sender.sampler.remove_obsolete_packets(6);
        assert_eq!(0, test_sender.number_of_tracked_packets());
    }

    #[test]
    fn neuter_packet() {
        let mut test_sender = TestSender::new();
        test_sender.send_packet(1, REGULAR_PACKET_SIZE, true);
        assert_eq!(test_sender.sampler.total_bytes_neutered, 0);
        test_sender.advance_time(Duration::from_millis(10));
        test_sender.sampler.on_packet_neutered(1);
        assert!(0 < test_sender.sampler.total_bytes_neutered);
        assert_eq!(0, test_sender.sampler.total_bytes_acked);

        // If packet 1 is acked it should not produce a bandwidth sample.
        let acked = Acked {
            pkt_num: 1,
            time_sent: test_sender.clock,
            size: REGULAR_PACKET_SIZE,
        };
        test_sender.advance_time(Duration::from_millis(10));
        let sample = test_sender.sampler.on_congestion_event(
            test_sender.clock,
            &[acked],
            &[],
            Some(test_sender.max_bandwidth),
            test_sender.est_bandwidth_upper_bound,
            test_sender.round_trip_count,
        );

        assert_eq!(0, test_sender.sampler.total_bytes_acked);
        assert!(sample.sample_max_bandwidth.is_none());
        assert!(!sample.sample_is_app_limited);
        assert!(sample.sample_rtt.is_none());
        assert_eq!(sample.sample_max_inflight, 0);
        assert_eq!(sample.extra_acked, 0);
    }

    /// Make sure a default constructed [`CongestionEventSample`] has the
    /// correct initial values for
    /// [`BandwidthSampler::on_congestion_event()`] to work.
    #[test]
    fn congestion_event_sample_default_values() {
        let sample = CongestionEventSample::default();
        assert!(sample.sample_max_bandwidth.is_none());
        assert!(!sample.sample_is_app_limited);
        assert!(sample.sample_rtt.is_none());
        assert_eq!(sample.sample_max_inflight, 0);
        assert_eq!(sample.extra_acked, 0);
    }

    /// 1) Send 2 packets, 2) Ack both in 1 event, 3) Repeat.
    #[test]
    fn two_acked_packets_per_event() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(10);
        let sending_rate = Bandwidth::from_bytes_and_time_delta(
            REGULAR_PACKET_SIZE,
            time_between_packets,
        );

        for i in 1..21 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
            if i % 2 != 0 {
                continue;
            }

            let sample = test_sender.on_congestion_event(&[i - 1, i], &[]);
            assert_eq!(sending_rate, sample.sample_max_bandwidth.unwrap());
            assert_eq!(time_between_packets, sample.sample_rtt.unwrap());
            assert_eq!(2 * REGULAR_PACKET_SIZE, sample.sample_max_inflight);
            assert!(sample.last_packet_send_state.is_valid);
            assert_eq!(
                2 * REGULAR_PACKET_SIZE,
                sample.last_packet_send_state.bytes_in_flight
            );
            assert_eq!(
                i as usize * REGULAR_PACKET_SIZE,
                sample.last_packet_send_state.total_bytes_sent
            );
            assert_eq!(
                (i - 2) as usize * REGULAR_PACKET_SIZE,
                sample.last_packet_send_state.total_bytes_acked
            );
            assert_eq!(0, sample.last_packet_send_state.total_bytes_lost);
            test_sender.sampler.remove_obsolete_packets(i - 2);
        }
    }

    #[test]
    fn lose_every_other_packet() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(10);
        let sending_rate = Bandwidth::from_bytes_and_time_delta(
            REGULAR_PACKET_SIZE,
            time_between_packets,
        );

        for i in 1..21 {
            test_sender.send_packet(i, REGULAR_PACKET_SIZE, true);
            test_sender.advance_time(time_between_packets);
            if i % 2 != 0 {
                continue;
            }
            // Ack packet i and lose i-1.
            let sample = test_sender.on_congestion_event(&[i], &[i - 1]);
            // Losing 50% packets means sending rate is twice the bandwidth.

            assert_eq!(sending_rate, sample.sample_max_bandwidth.unwrap() * 2.);
            assert_eq!(time_between_packets, sample.sample_rtt.unwrap());
            assert_eq!(REGULAR_PACKET_SIZE, sample.sample_max_inflight);
            assert!(sample.last_packet_send_state.is_valid);
            assert_eq!(
                2 * REGULAR_PACKET_SIZE,
                sample.last_packet_send_state.bytes_in_flight
            );
            assert_eq!(
                i as usize * REGULAR_PACKET_SIZE,
                sample.last_packet_send_state.total_bytes_sent
            );
            assert_eq!(
                (i - 2) as usize * REGULAR_PACKET_SIZE / 2,
                sample.last_packet_send_state.total_bytes_acked
            );
            assert_eq!(
                (i - 2) as usize * REGULAR_PACKET_SIZE / 2,
                sample.last_packet_send_state.total_bytes_lost
            );
            test_sender.sampler.remove_obsolete_packets(i - 2);
        }
    }

    #[test]
    fn ack_height_respect_bandwidth_estimate_upper_bound() {
        let mut test_sender = TestSender::new();
        let time_between_packets = Duration::from_millis(10);
        let first_packet_sending_rate = Bandwidth::from_bytes_and_time_delta(
            REGULAR_PACKET_SIZE,
            time_between_packets,
        );

        // Send packets 1 to 4 and ack packet 1.
        test_sender.send_packet(1, REGULAR_PACKET_SIZE, true);
        test_sender.advance_time(time_between_packets);
        test_sender.send_packet(2, REGULAR_PACKET_SIZE, true);
        test_sender.send_packet(3, REGULAR_PACKET_SIZE, true);
        test_sender.send_packet(4, REGULAR_PACKET_SIZE, true);
        let sample = test_sender.on_congestion_event(&[1], &[]);
        assert_eq!(
            first_packet_sending_rate,
            sample.sample_max_bandwidth.unwrap()
        );
        assert_eq!(first_packet_sending_rate, test_sender.max_bandwidth);

        // Ack packet 2, 3 and 4, all of which uses S(1) to calculate ack rate
        // since there were no acks at the time they were sent.
        test_sender.round_trip_count += 1;
        test_sender.est_bandwidth_upper_bound = first_packet_sending_rate * 0.3;
        test_sender.advance_time(time_between_packets);

        let sample = test_sender.on_congestion_event(&[2, 3, 4], &[]);

        assert_eq!(
            first_packet_sending_rate * 2.,
            sample.sample_max_bandwidth.unwrap()
        );
        assert_eq!(
            test_sender.max_bandwidth,
            sample.sample_max_bandwidth.unwrap()
        );
        assert!(2 * REGULAR_PACKET_SIZE < sample.extra_acked);
    }
}

#[cfg(test)]
mod max_ack_height_tracker_tests {
    use super::*;

    struct TestTracker {
        tracker: MaxAckHeightTracker,
        bandwidth: Bandwidth,
        start: Instant,
        now: Instant,
        last_sent_packet_number: u64,
        last_acked_packet_number: u64,
        rtt: Duration,
    }

    impl TestTracker {
        fn new() -> Self {
            let mut tracker = MaxAckHeightTracker::new(10, false);
            tracker.ack_aggregation_bandwidth_threshold = 1.8;
            tracker.start_new_aggregation_epoch_after_full_round = true;
            let start = Instant::now();
            TestTracker {
                tracker,
                start,
                now: start + Duration::from_millis(1),
                bandwidth: Bandwidth::from_bytes_per_second(10 * 1000),
                last_sent_packet_number: 0,
                last_acked_packet_number: 0,
                rtt: Duration::from_millis(60),
            }
        }

        // Run a full aggregation episode, which is one or more aggregated acks,
        // followed by a quiet period in which no ack happens.
        // After this function returns, the time is set to the earliest point at
        // which any ack event will cause tracker_.Update() to start a new
        // aggregation.
        fn aggregation_episode(
            &mut self, aggregation_bandwidth: Bandwidth,
            aggregation_duration: Duration, bytes_per_ack: usize,
            expect_new_aggregation_epoch: bool,
        ) {
            assert!(aggregation_bandwidth >= self.bandwidth);
            let start_time = self.now;

            let aggregation_bytes =
                (aggregation_bandwidth * aggregation_duration) as usize;

            let num_acks = aggregation_bytes / bytes_per_ack;
            assert_eq!(aggregation_bytes, num_acks * bytes_per_ack);

            let time_between_acks = Duration::from_micros(
                aggregation_duration.as_micros() as u64 / num_acks as u64,
            );
            assert_eq!(aggregation_duration, time_between_acks * num_acks as u32);

            // The total duration of aggregation time and quiet period.
            let total_duration = Duration::from_micros(
                (aggregation_bytes as u64 * 8 * 1000000) /
                    self.bandwidth.to_bits_per_second() as u64,
            );

            assert_eq!(aggregation_bytes as u64, self.bandwidth * total_duration);

            let mut last_extra_acked = 0;

            for bytes in (0..aggregation_bytes).step_by(bytes_per_ack) {
                let extra_acked = self.tracker.update(
                    self.bandwidth,
                    true,
                    self.round_trip_count(),
                    self.last_sent_packet_number,
                    self.last_acked_packet_number,
                    self.now,
                    bytes_per_ack,
                );
                // `extra_acked` should be 0 if either
                // [1] We are at the beginning of a aggregation epoch(bytes==0)
                // and the     the current tracker implementation
                // can identify it, or [2] We are not really
                // aggregating acks.
                if (bytes == 0 && expect_new_aggregation_epoch) ||
                    (aggregation_bandwidth == self.bandwidth)
                {
                    assert_eq!(0, extra_acked);
                } else {
                    assert!(last_extra_acked < extra_acked);
                }
                self.now = self.now + time_between_acks;
                last_extra_acked = extra_acked;
            }

            // Advance past the quiet period.
            self.now = start_time + total_duration;
        }

        fn round_trip_count(&self) -> usize {
            ((self.now - self.start).as_micros() / self.rtt.as_micros()) as usize
        }
    }

    fn test_inner(
        bandwidth_gain: f64, agg_duration: Duration, byte_per_ack: usize,
    ) {
        let mut test_tracker = TestTracker::new();

        let rnd = |tracker: &mut TestTracker, expect: bool| {
            tracker.aggregation_episode(
                tracker.bandwidth * bandwidth_gain,
                agg_duration,
                byte_per_ack,
                expect,
            );
        };

        rnd(&mut test_tracker, true);
        rnd(&mut test_tracker, true);

        test_tracker.now = test_tracker
            .now
            .checked_sub(Duration::from_millis(1))
            .unwrap();

        if test_tracker.tracker.ack_aggregation_bandwidth_threshold > 1.1 {
            rnd(&mut test_tracker, true);
            assert_eq!(3, test_tracker.tracker.num_ack_aggregation_epochs);
        } else {
            rnd(&mut test_tracker, false);
            assert_eq!(2, test_tracker.tracker.num_ack_aggregation_epochs);
        }
    }

    #[test]
    fn very_aggregated_large_acks() {
        test_inner(20.0, Duration::from_millis(6), 1200)
    }

    #[test]
    fn very_aggregated_small_acks() {
        test_inner(20., Duration::from_millis(6), 300)
    }

    #[test]
    fn somewhat_aggregated_large_acks() {
        test_inner(2.0, Duration::from_millis(50), 1000)
    }

    #[test]
    fn somewhat_aggregated_small_acks() {
        test_inner(2.0, Duration::from_millis(50), 100)
    }

    #[test]
    fn not_aggregated() {
        let mut test_tracker = TestTracker::new();
        test_tracker.aggregation_episode(
            test_tracker.bandwidth,
            Duration::from_millis(100),
            100,
            true,
        );
        assert!(2 < test_tracker.tracker.num_ack_aggregation_epochs);
    }

    #[test]
    fn start_new_epoch_after_a_full_round() {
        let mut test_tracker = TestTracker::new();

        test_tracker.last_sent_packet_number = 10;

        test_tracker.aggregation_episode(
            test_tracker.bandwidth * 2.0,
            Duration::from_millis(50),
            100,
            true,
        );

        test_tracker.last_acked_packet_number = 11;

        // Update with a tiny bandwidth causes a very low expected bytes acked,
        // which in turn causes the current epoch to continue if the
        // `tracker` doesn't check the packet numbers.
        test_tracker.tracker.update(
            test_tracker.bandwidth * 0.1,
            true,
            test_tracker.round_trip_count(),
            test_tracker.last_sent_packet_number,
            test_tracker.last_acked_packet_number,
            test_tracker.now,
            100,
        );

        assert_eq!(2, test_tracker.tracker.num_ack_aggregation_epochs)
    }
}
