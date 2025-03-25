// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use std::collections::VecDeque;

use crate::recovery::HandshakeStatus;
use super::RecoveryConfig;
use super::Sent;

use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::Result;

#[cfg(feature = "qlog")]
use crate::recovery::QlogMetrics;

use crate::frame;
use crate::packet;
use crate::ranges;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use super::pacer;
use super::Congestion;
use crate::recovery::LossDetectionTimer;
use crate::recovery::rtt::RttStats;
use crate::recovery::{INITIAL_PACKET_THRESHOLD, MAX_PACKET_THRESHOLD, INITIAL_TIME_THRESHOLD, GRANULARITY, MAX_PTO_PROBES_COUNT, MAX_OUTSTANDING_NON_ACK_ELICITING};

#[derive(Default)]
struct RecoveryEpoch {
    /// The time the most recent ack-eliciting packet was sent.
    time_of_last_ack_eliciting_packet: Option<Instant>,

    /// The largest packet number acknowledged in the packet number space so
    /// far.
    largest_acked_packet: Option<u64>,

    /// The time at which the next packet in that packet number space can be
    /// considered lost based on exceeding the reordering window in time.
    loss_time: Option<Instant>,

    /// An association of packet numbers in a packet number space to information
    /// about them.
    sent_packets: VecDeque<Sent>,

    loss_probes: usize,
    in_flight_count: usize,

    acked_frames: Vec<frame::Frame>,
    lost_frames: Vec<frame::Frame>,
}

struct AckedDetectionResult {
    acked_bytes: usize,
    spurious_losses: usize,
    spurious_pkt_thresh: Option<u64>,
    has_ack_eliciting: bool,
    has_in_flight_spurious_loss: bool,
}

struct LossDetectionResult {
    largest_lost_pkt: Option<Sent>,
    lost_packets: usize,
    lost_bytes: usize,
    pmtud_lost_bytes: usize,
}

impl RecoveryEpoch {
    fn detect_and_remove_acked_packets(
        &mut self, now: Instant, acked: &RangeSet, newly_acked: &mut Vec<Acked>,
        rtt_stats: &RttStats, trace_id: &str,
    ) -> AckedDetectionResult {
        newly_acked.clear();

        let mut acked_bytes = 0;
        let mut spurious_losses = 0;
        let mut spurious_pkt_thresh = None;
        let mut has_ack_eliciting = false;
        let mut has_in_flight_spurious_loss = false;

        let largest_acked = self.largest_acked_packet.unwrap();

        for ack in acked.iter() {
            // Because packets always have incrementing numbers, they are always
            // in sorted order.
            let start = if self
                .sent_packets
                .front()
                .filter(|e| e.pkt_num >= ack.start)
                .is_some()
            {
                // Usually it will be the first packet.
                0
            } else {
                self.sent_packets
                    .binary_search_by_key(&ack.start, |p| p.pkt_num)
                    .unwrap_or_else(|e| e)
            };

            for unacked in self.sent_packets.range_mut(start..) {
                if unacked.pkt_num >= ack.end {
                    break;
                }

                if unacked.time_acked.is_some() {
                    // Already acked.
                } else if unacked.time_lost.is_some() {
                    // An acked packet was already declared lost.
                    spurious_losses += 1;
                    spurious_pkt_thresh
                        .get_or_insert(largest_acked - unacked.pkt_num + 1);
                    unacked.time_acked = Some(now);

                    if unacked.in_flight {
                        has_in_flight_spurious_loss = true;
                    }
                } else {
                    if unacked.in_flight {
                        self.in_flight_count -= 1;
                        acked_bytes += unacked.size;
                    }

                    newly_acked.push(Acked {
                        pkt_num: unacked.pkt_num,
                        time_sent: unacked.time_sent,
                        size: unacked.size,

                        rtt: now.saturating_duration_since(unacked.time_sent),
                        delivered: unacked.delivered,
                        delivered_time: unacked.delivered_time,
                        first_sent_time: unacked.first_sent_time,
                        is_app_limited: unacked.is_app_limited,
                    });

                    trace!("{} packet newly acked {}", trace_id, unacked.pkt_num);

                    self.acked_frames
                        .extend(std::mem::take(&mut unacked.frames));

                    has_ack_eliciting |= unacked.ack_eliciting;
                    unacked.time_acked = Some(now);
                }
            }
        }

        self.drain_acked_and_lost_packets(now - rtt_stats.rtt());

        AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
            has_in_flight_spurious_loss,
        }
    }

    fn detect_lost_packets(
        &mut self, loss_delay: Duration, pkt_thresh: u64, now: Instant,
        trace_id: &str, epoch: Epoch,
    ) -> LossDetectionResult {
        self.loss_time = None;

        // Minimum time of kGranularity before packets are deemed lost.
        let loss_delay = cmp::max(loss_delay, GRANULARITY);
        let largest_acked = self.largest_acked_packet.unwrap_or(0);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now.checked_sub(loss_delay).unwrap();

        let mut lost_packets = 0;
        let mut lost_bytes = 0;
        let mut pmtud_lost_bytes = 0;

        let mut largest_lost_pkt = None;

        let unacked_iter = self.sent_packets
        .iter_mut()
        // Skip packets that follow the largest acked packet.
        .take_while(|p| p.pkt_num <= largest_acked)
        // Skip packets that have already been acked or lost.
        .filter(|p| p.time_acked.is_none() && p.time_lost.is_none());

        for unacked in unacked_iter {
            // Mark packet as lost, or set time when it should be marked.
            if unacked.time_sent <= lost_send_time ||
                largest_acked >= unacked.pkt_num + pkt_thresh
            {
                self.lost_frames.extend(unacked.frames.drain(..));

                unacked.time_lost = Some(now);

                if unacked.pmtud {
                    pmtud_lost_bytes += unacked.size;
                    self.in_flight_count -= 1;

                    // Do not track PMTUD probes losses.
                    continue;
                }

                if unacked.in_flight {
                    lost_bytes += unacked.size;

                    // Frames have already been removed from the packet, so
                    // cloning the whole packet should be relatively cheap.
                    largest_lost_pkt = Some(unacked.clone());

                    self.in_flight_count -= 1;

                    trace!(
                        "{} packet {} lost on epoch {}",
                        trace_id,
                        unacked.pkt_num,
                        epoch
                    );
                }

                lost_packets += 1;
            } else {
                let loss_time = match self.loss_time {
                    None => unacked.time_sent + loss_delay,

                    Some(loss_time) =>
                        cmp::min(loss_time, unacked.time_sent + loss_delay),
                };

                self.loss_time = Some(loss_time);
                break;
            }
        }

        LossDetectionResult {
            largest_lost_pkt,
            lost_packets,
            lost_bytes,
            pmtud_lost_bytes,
        }
    }

    fn drain_acked_and_lost_packets(&mut self, loss_thresh: Instant) {
        // In order to avoid removing elements from the middle of the list
        // (which would require copying other elements to compact the list),
        // we only remove a contiguous range of elements from the start of the
        // list.
        //
        // This means that acked or lost elements coming after this will not
        // be removed at this point, but their removal is delayed for a later
        // time, once the gaps have been filled.
        while let Some(pkt) = self.sent_packets.front() {
            if let Some(time_lost) = pkt.time_lost {
                if time_lost > loss_thresh {
                    break;
                }
            }

            if pkt.time_acked.is_none() && pkt.time_lost.is_none() {
                break;
            }

            self.sent_packets.pop_front();
        }
    }
}

pub struct Recovery {
    epochs: [RecoveryEpoch; packet::Epoch::count()],

    loss_timer: LossDetectionTimer,

    pto_count: u32,

    rtt_stats: RttStats,

    pub lost_spurious_count: usize,

    pkt_thresh: u64,

    time_thresh: f64,

    pub bytes_in_flight: usize,

    bytes_sent: usize,

    pub bytes_lost: u64,

    pub max_datagram_size: usize,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    /// How many non-ack-eliciting packets have been sent.
    outstanding_non_ack_eliciting: usize,

    pub congestion: Congestion,

    /// A resusable list of acks.
    newly_acked: Vec<Acked>,
}

impl Recovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        Self {
            epochs: Default::default(),

            loss_timer: Default::default(),

            pto_count: 0,

            rtt_stats: RttStats::new(recovery_config.max_ack_delay),

            lost_spurious_count: 0,

            pkt_thresh: INITIAL_PACKET_THRESHOLD,

            time_thresh: INITIAL_TIME_THRESHOLD,

            bytes_in_flight: 0,

            bytes_sent: 0,

            bytes_lost: 0,

            max_datagram_size: recovery_config.max_send_udp_payload_size,

            #[cfg(feature = "qlog")]
            qlog_metrics: QlogMetrics::default(),

            outstanding_non_ack_eliciting: 0,

            congestion: Congestion::from_config(recovery_config),

            newly_acked: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn new(config: &crate::Config) -> Self {
        Self::new_with_config(&RecoveryConfig::from_config(config))
    }

    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    pub fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool {
        self.epochs[epoch].loss_probes > 0 ||
            self.outstanding_non_ack_eliciting >=
                MAX_OUTSTANDING_NON_ACK_ELICITING
    }

    pub fn get_acked_frames(
        &mut self, epoch: packet::Epoch,
    ) -> impl Iterator<Item = frame::Frame> + '_ {
        self.epochs[epoch].acked_frames.drain(..)
    }

    pub fn get_lost_frames(
        &mut self, epoch: packet::Epoch,
    ) -> impl Iterator<Item = frame::Frame> + '_ {
        self.epochs[epoch].lost_frames.drain(..)
    }

    pub fn get_largest_acked_on_epoch(
        &self, epoch: packet::Epoch,
    ) -> Option<u64> {
        self.epochs[epoch].largest_acked_packet
    }

    pub fn has_lost_frames(&self, epoch: packet::Epoch) -> bool {
        !self.epochs[epoch].lost_frames.is_empty()
    }

    pub fn loss_probes(&self, epoch: packet::Epoch) -> usize {
        self.epochs[epoch].loss_probes
    }

    #[cfg(test)]
    pub fn inc_loss_probes(&mut self, epoch: packet::Epoch) {
        self.epochs[epoch].loss_probes += 1;
    }

    pub fn ping_sent(&mut self, epoch: packet::Epoch) {
        self.epochs[epoch].loss_probes =
            self.epochs[epoch].loss_probes.saturating_sub(1);
    }

    pub fn on_packet_sent(
        &mut self, mut pkt: Sent, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) {
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let sent_bytes = pkt.size;

        if ack_eliciting {
            self.outstanding_non_ack_eliciting = 0;
        } else {
            self.outstanding_non_ack_eliciting += 1;
        }

        if in_flight && ack_eliciting {
            self.epochs[epoch].time_of_last_ack_eliciting_packet = Some(now);
        }

        self.congestion.on_packet_sent(
            self.bytes_in_flight,
            sent_bytes,
            now,
            &mut pkt,
            &self.rtt_stats,
            self.bytes_lost,
            in_flight,
        );

        if in_flight {
            self.epochs[epoch].in_flight_count += 1;
            self.bytes_in_flight += sent_bytes;

            self.set_loss_detection_timer(handshake_status, now);
        }

        self.bytes_sent += sent_bytes;

        self.epochs[epoch].sent_packets.push_back(pkt);

        trace!("{} {:?}", trace_id, self);
    }

    pub fn get_packet_send_time(&self) -> Instant {
        self.congestion.get_packet_send_time()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_ack_received(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> Result<(usize, usize, usize)> {
        let largest_acked = ranges.last().unwrap();

        // Update the largest acked packet.
        let largest_acked = self.epochs[epoch]
            .largest_acked_packet
            .unwrap_or(0)
            .max(largest_acked);

        self.epochs[epoch].largest_acked_packet = Some(largest_acked);

        let AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
            has_in_flight_spurious_loss,
        } = self.epochs[epoch].detect_and_remove_acked_packets(
            now,
            ranges,
            &mut self.newly_acked,
            &self.rtt_stats,
            trace_id,
        );

        self.lost_spurious_count += spurious_losses;
        if let Some(thresh) = spurious_pkt_thresh {
            self.pkt_thresh =
                self.pkt_thresh.max(thresh.min(MAX_PACKET_THRESHOLD));
        }

        // Undo congestion window update.
        if has_in_flight_spurious_loss {
            (self.congestion.cc_ops.rollback)(&mut self.congestion);
        }

        if self.newly_acked.is_empty() {
            return Ok((0, 0, 0));
        }

        // Check if largest packet is newly acked.
        let largest_newly_acked = self.newly_acked.last().unwrap();

        if largest_newly_acked.pkt_num == largest_acked && has_ack_eliciting {
            let latest_rtt = now - largest_newly_acked.time_sent;
            self.rtt_stats.update_rtt(
                latest_rtt,
                Duration::from_micros(ack_delay),
                now,
                handshake_status.completed,
            );
        }

        // Detect and mark lost packets without removing them from the sent
        // packets list.
        let loss = self.detect_lost_packets(epoch, now, trace_id);

        self.congestion.on_packets_acked(
            self.bytes_in_flight,
            &mut self.newly_acked,
            &self.rtt_stats,
            now,
        );

        self.bytes_in_flight -= acked_bytes;

        self.pto_count = 0;

        self.set_loss_detection_timer(handshake_status, now);

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now - self.rtt_stats.rtt());

        Ok((loss.0, loss.1, acked_bytes))
    }

    pub fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> (usize, usize) {
        let (earliest_loss_time, epoch) = self.loss_time_and_space();

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            let loss = self.detect_lost_packets(epoch, now, trace_id);

            self.set_loss_detection_timer(handshake_status, now);

            trace!("{} {:?}", trace_id, self);
            return loss;
        }

        let epoch = if self.bytes_in_flight > 0 {
            // Send new data if available, else retransmit old data. If neither
            // is available, send a single PING frame.
            let (_, e) = self.pto_time_and_space(handshake_status, now);

            e
        } else {
            // Client sends an anti-deadlock packet: Initial is padded to earn
            // more anti-amplification credit, a Handshake packet proves address
            // ownership.
            if handshake_status.has_handshake_keys {
                packet::Epoch::Handshake
            } else {
                packet::Epoch::Initial
            }
        };

        self.pto_count += 1;

        let epoch = &mut self.epochs[epoch];

        epoch.loss_probes =
            cmp::min(self.pto_count as usize, MAX_PTO_PROBES_COUNT);

        let unacked_iter = epoch.sent_packets
            .iter_mut()
            // Skip packets that have already been acked or lost, and packets
            // that don't contain either CRYPTO or STREAM frames.
            .filter(|p| p.has_data && p.time_acked.is_none() && p.time_lost.is_none())
            // Only return as many packets as the number of probe packets that
            // will be sent.
            .take(epoch.loss_probes);

        // Retransmit the frames from the oldest sent packets on PTO. However
        // the packets are not actually declared lost (so there is no effect to
        // congestion control), we just reschedule the data they carried.
        //
        // This will also trigger sending an ACK and retransmitting frames like
        // HANDSHAKE_DONE and MAX_DATA / MAX_STREAM_DATA as well, in addition
        // to CRYPTO and STREAM, if the original packet carried them.
        for unacked in unacked_iter {
            epoch.lost_frames.extend_from_slice(&unacked.frames);
        }

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{} {:?}", trace_id, self);

        (0, 0)
    }

    pub fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let epoch = &mut self.epochs[epoch];

        let unacked_bytes = epoch
            .sent_packets
            .iter()
            .filter(|p| {
                p.in_flight && p.time_acked.is_none() && p.time_lost.is_none()
            })
            .fold(0, |acc, p| acc + p.size);

        self.bytes_in_flight -= unacked_bytes;

        epoch.sent_packets.clear();
        epoch.lost_frames.clear();
        epoch.acked_frames.clear();

        epoch.time_of_last_ack_eliciting_packet = None;
        epoch.loss_time = None;
        epoch.loss_probes = 0;
        epoch.in_flight_count = 0;

        self.set_loss_detection_timer(handshake_status, now);
    }

    pub fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        // Time threshold loss detection.
        self.detect_lost_packets(epoch, now, trace_id)
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_timer.time
    }

    pub fn cwnd(&self) -> usize {
        self.congestion.congestion_window()
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.epochs.iter().any(|e| e.loss_probes > 0) {
            return usize::MAX;
        }

        // Open more space (snd_cnt) for PRR when allowed.
        self.cwnd().saturating_sub(self.bytes_in_flight) +
            self.congestion.prr.snd_cnt
    }

    pub fn rtt(&self) -> Duration {
        self.rtt_stats.rtt()
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.rtt_stats.min_rtt()
    }

    pub fn rttvar(&self) -> Duration {
        self.rtt_stats.rttvar
    }

    pub fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rtt_stats.rttvar * 4, GRANULARITY)
    }

    pub fn delivery_rate(&self) -> u64 {
        self.congestion.delivery_rate()
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn pmtud_update_max_datagram_size(
        &mut self, new_max_datagram_size: usize,
    ) {
        // Congestion Window is updated only when it's not updated already.
        // Update cwnd if it hasn't been updated yet.
        if self.cwnd() ==
            self.max_datagram_size *
                self.congestion.initial_congestion_window_packets
        {
            self.congestion.congestion_window = new_max_datagram_size *
                self.congestion.initial_congestion_window_packets;
        }

        self.congestion.pacer = pacer::Pacer::new(
            self.congestion.pacer.enabled(),
            self.cwnd(),
            0,
            new_max_datagram_size,
            self.congestion.pacer.max_pacing_rate(),
        );

        self.max_datagram_size = new_max_datagram_size;
    }

    pub fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.pmtud_update_max_datagram_size(
            self.max_datagram_size.min(new_max_datagram_size),
        )
    }

    fn loss_time_and_space(&self) -> (Option<Instant>, packet::Epoch) {
        let mut epoch = packet::Epoch::Initial;
        let mut time = self.epochs[epoch].loss_time;

        // Iterate over all packet number spaces starting from Handshake.
        for e in [packet::Epoch::Handshake, packet::Epoch::Application] {
            let new_time = self.epochs[e].loss_time;
            if time.is_none() || new_time < time {
                time = new_time;
                epoch = e;
            }
        }

        (time, epoch)
    }

    fn pto_time_and_space(
        &self, handshake_status: HandshakeStatus, now: Instant,
    ) -> (Option<Instant>, packet::Epoch) {
        let mut duration = self.pto() * 2_u32.pow(self.pto_count);

        // Arm PTO from now when there are no inflight packets.
        if self.bytes_in_flight == 0 {
            if handshake_status.has_handshake_keys {
                return (Some(now + duration), packet::Epoch::Handshake);
            } else {
                return (Some(now + duration), packet::Epoch::Initial);
            }
        }

        let mut pto_timeout = None;
        let mut pto_space = packet::Epoch::Initial;

        // Iterate over all packet number spaces.
        for e in [
            packet::Epoch::Initial,
            packet::Epoch::Handshake,
            packet::Epoch::Application,
        ] {
            let epoch = &self.epochs[e];
            if epoch.in_flight_count == 0 {
                continue;
            }

            if e == packet::Epoch::Application {
                // Skip Application Data until handshake completes.
                if !handshake_status.completed {
                    return (pto_timeout, pto_space);
                }

                // Include max_ack_delay and backoff for Application Data.
                duration +=
                    self.rtt_stats.max_ack_delay * 2_u32.pow(self.pto_count);
            }

            let new_time = epoch
                .time_of_last_ack_eliciting_packet
                .map(|t| t + duration);

            if pto_timeout.is_none() || new_time < pto_timeout {
                pto_timeout = new_time;
                pto_space = e;
            }
        }

        (pto_timeout, pto_space)
    }

    fn set_loss_detection_timer(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
    ) {
        let (earliest_loss_time, _) = self.loss_time_and_space();

        if let Some(to) = earliest_loss_time {
            // Time threshold loss detection.
            self.loss_timer.update(to);
            return;
        }

        if self.bytes_in_flight == 0 && handshake_status.peer_verified_address {
            self.loss_timer.clear();
            return;
        }

        // PTO timer.
        if let (Some(timeout), _) = self.pto_time_and_space(handshake_status, now)
        {
            self.loss_timer.update(timeout);
        }
    }

    fn detect_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        let loss_delay = cmp::max(self.rtt_stats.latest_rtt, self.rtt())
            .mul_f64(self.time_thresh);

        let loss = self.epochs[epoch].detect_lost_packets(
            loss_delay,
            self.pkt_thresh,
            now,
            trace_id,
            epoch,
        );

        if let Some(pkt) = loss.largest_lost_pkt {
            if !self.congestion.in_congestion_recovery(pkt.time_sent) {
                (self.congestion.cc_ops.checkpoint)(&mut self.congestion);
            }

            (self.congestion.cc_ops.congestion_event)(
                &mut self.congestion,
                self.bytes_in_flight,
                loss.lost_bytes,
                &pkt,
                now,
            );

            self.bytes_in_flight -= loss.lost_bytes;
        };

        self.bytes_in_flight -= loss.pmtud_lost_bytes;

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now - self.rtt_stats.rtt());

        self.congestion.lost_count += loss.lost_packets;

        (loss.lost_packets, loss.lost_bytes)
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.congestion.app_limited = v;
    }

    #[cfg(test)]
    pub fn app_limited(&self) -> bool {
        self.congestion.app_limited
    }

    pub fn delivery_rate_update_app_limited(&mut self, v: bool) {
        self.congestion.delivery_rate.update_app_limited(v);
    }

    pub fn update_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.rtt_stats.max_ack_delay = max_ack_delay;
    }

    #[cfg(feature = "qlog")]
    pub fn maybe_qlog(&mut self) -> Option<EventData> {
        let qlog_metrics = QlogMetrics {
            min_rtt: *self.rtt_stats.min_rtt,
            smoothed_rtt: self.rtt(),
            latest_rtt: self.rtt_stats.latest_rtt,
            rttvar: self.rtt_stats.rttvar,
            cwnd: self.cwnd() as u64,
            bytes_in_flight: self.bytes_in_flight as u64,
            ssthresh: self.congestion.ssthresh as u64,
            pacing_rate: self.congestion.pacer.rate(),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    pub fn send_quantum(&self) -> usize {
        self.congestion.send_quantum()
    }

    pub fn lost_count(&self) -> usize {
        self.congestion.lost_count
    }
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.loss_timer.time {
            Some(v) => {
                let now = Instant::now();

                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "timer={d:?} ")?;
                } else {
                    write!(f, "timer=exp ")?;
                }
            },

            None => {
                write!(f, "timer=none ")?;
            },
        };

        write!(f, "latest_rtt={:?} ", self.rtt_stats.latest_rtt)?;
        write!(f, "srtt={:?} ", self.rtt_stats.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", *self.rtt_stats.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rtt_stats.rttvar)?;
        write!(f, "cwnd={} ", self.cwnd())?;
        write!(f, "ssthresh={} ", self.congestion.ssthresh)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight)?;
        write!(f, "app_limited={} ", self.congestion.app_limited)?;
        write!(
            f,
            "congestion_recovery_start_time={:?} ",
            self.congestion.congestion_recovery_start_time
        )?;
        write!(f, "{:?} ", self.congestion.delivery_rate)?;
        write!(f, "pacer={:?} ", self.congestion.pacer)?;

        if self.congestion.hystart.enabled() {
            write!(f, "hystart={:?} ", self.congestion.hystart)?;
        }

        // CC-specific debug info
        (self.congestion.cc_ops.debug_fmt)(&self.congestion, f)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct Acked {
    pub pkt_num: u64,

    pub time_sent: Instant,

    pub size: usize,

    pub rtt: Duration,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;
    use std::str::FromStr;
    use crate::recovery::congestion::PACING_MULTIPLIER;
    use crate::CongestionControlAlgorithm;

    #[test]
    fn lookup_cc_algo_ok() {
        let algo = CongestionControlAlgorithm::from_str("reno").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::Reno);
    }

    #[test]
    fn lookup_cc_algo_bad() {
        assert_eq!(
            CongestionControlAlgorithm::from_str("???"),
            Err(crate::Error::CongestionControl)
        );
    }

    #[test]
    fn loss_on_pto() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: 2,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 3,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((0, 0, 2 * 1000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);
        assert_eq!(r.congestion.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // PTO.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.epochs[packet::Epoch::Application].loss_probes, 1);
        assert_eq!(r.congestion.lost_count, 0);
        assert_eq!(r.pto_count, 1);

        let p = Sent {
            pkt_num: 4,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 5,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);
        assert_eq!(r.congestion.lost_count, 0);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // PTO packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(4..6);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((2, 2000, 2 * 1000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.congestion.lost_count, 2);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
    }

    #[test]
    fn loss_on_timer() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: 2,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 3,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets and the last one are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);
        acked.insert(3..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((0, 0, 3 * 1000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.congestion.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.epochs[packet::Epoch::Application].loss_probes, 0);

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.congestion.lost_count, 1);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
    }

    #[test]
    fn loss_on_reordering() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: 2,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 3,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // ACKs are reordered.
        let mut acked = ranges::RangeSet::default();
        acked.insert(2..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((1, 1000, 1000 * 2))
        );

        now += Duration::from_millis(10);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(r.pkt_thresh, INITIAL_PACKET_THRESHOLD);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((0, 0, 1000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        // Spurious loss.
        assert_eq!(r.congestion.lost_count, 1);
        assert_eq!(r.lost_spurious_count, 1);

        // Packet threshold was increased.
        assert_eq!(r.pkt_thresh, 4);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
    }

    #[test]
    fn pacing() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);

        // send out first packet (a full initcwnd).
        let p = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 12000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 1);
        assert_eq!(r.bytes_in_flight, 12000);

        // First packet will be sent out immediately.
        assert_eq!(r.congestion.pacer.rate(), 0);
        assert_eq!(r.get_packet_send_time(), now);

        // Wait 50ms for ACK.
        now += Duration::from_millis(50);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..1);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((0, 0, 12000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.rtt_stats.smoothed_rtt, Duration::from_millis(50));

        // 1 MSS increased.
        assert_eq!(r.cwnd(), 12000 + 1200);

        // Send out second packet.
        let p = Sent {
            pkt_num: 1,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 6000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 1);
        assert_eq!(r.bytes_in_flight, 6000);

        // Pacing is not done during initial phase of connection.
        assert_eq!(r.get_packet_send_time(), now);

        // Send the third packet out.
        let p = Sent {
            pkt_num: 2,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 6000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 12000);

        // Send the third packet out.
        let p = Sent {
            pkt_num: 3,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 3);
        assert_eq!(r.bytes_in_flight, 13000);

        // We pace this outgoing packet. as all conditions for pacing
        // are passed.
        let pacing_rate =
            (r.cwnd() as f64 * PACING_MULTIPLIER / 0.05) as u64;
        assert_eq!(r.congestion.pacer.rate(), pacing_rate);

        assert_eq!(
            r.get_packet_send_time(),
            now + Duration::from_secs_f64(12000.0 / pacing_rate as f64)
        );
    }

    #[test]
    fn pmtud_loss_on_timer() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 1);
        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: true,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 2);

        let p = Sent {
            pkt_num: 2,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 3);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first  packets and the last one are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..1);
        acked.insert(2..3);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            Ok((0, 0, 2 * 1000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.congestion.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.epochs[packet::Epoch::Application].loss_probes, 0);

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.cwnd(), 12000);

        assert_eq!(r.congestion.lost_count, 0);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.congestion.lost_count, 0);
    }
}
