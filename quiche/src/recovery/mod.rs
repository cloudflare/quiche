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

use std::str::FromStr;

use std::time::Duration;
use std::time::Instant;

use std::collections::VecDeque;

use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::Config;
use crate::Result;

use crate::frame;
use crate::packet;
use crate::ranges;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use smallvec::SmallVec;

use self::rtt::RttStats;

// Loss Recovery
const INITIAL_PACKET_THRESHOLD: u64 = 3;

const MAX_PACKET_THRESHOLD: u64 = 20;

const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

const MAX_PTO_PROBES_COUNT: usize = 2;

const MINIMUM_WINDOW_PACKETS: usize = 2;

const LOSS_REDUCTION_FACTOR: f64 = 0.5;

const PACING_MULTIPLIER: f64 = 1.25;

// How many non ACK eliciting packets we send before including a PING to solicit
// an ACK.
pub(super) const MAX_OUTSTANDING_NON_ACK_ELICITING: usize = 24;

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
                        tx_in_flight: unacked.tx_in_flight,
                        lost: unacked.lost,
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

#[derive(Default)]
struct LossDetectionTimer {
    time: Option<Instant>,
}

impl LossDetectionTimer {
    fn update(&mut self, timeout: Instant) {
        self.time = Some(timeout);
    }

    fn clear(&mut self) {
        self.time = None;
    }
}

pub struct Recovery {
    epochs: [RecoveryEpoch; packet::Epoch::count()],

    loss_timer: LossDetectionTimer,

    pto_count: u32,

    rtt_stats: RttStats,

    pub lost_count: usize,

    pub lost_spurious_count: usize,

    app_limited: bool,

    delivery_rate: delivery_rate::Rate,

    pkt_thresh: u64,

    time_thresh: f64,

    // Congestion control.
    cc_ops: &'static CongestionControlOps,

    congestion_window: usize,

    bytes_in_flight: usize,

    ssthresh: usize,

    bytes_acked_sl: usize,

    bytes_acked_ca: usize,

    bytes_sent: usize,

    pub bytes_lost: u64,

    congestion_recovery_start_time: Option<Instant>,

    max_datagram_size: usize,

    cubic_state: cubic::State,

    // HyStart++.
    hystart: hystart::Hystart,

    // Pacing.
    pub pacer: pacer::Pacer,

    // RFC6937 PRR.
    prr: prr::PRR,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    // The maximum size of a data aggregate scheduled and
    // transmitted together.
    send_quantum: usize,

    // BBR state.
    bbr_state: bbr::State,

    // BBRv2 state.
    bbr2_state: bbr2::State,

    /// How many non-ack-eliciting packets have been sent.
    outstanding_non_ack_eliciting: usize,

    /// Initial congestion window size in terms of packet count.
    initial_congestion_window_packets: usize,
}

pub struct RecoveryConfig {
    max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    cc_ops: &'static CongestionControlOps,
    hystart: bool,
    pacing: bool,
    max_pacing_rate: Option<u64>,
    initial_congestion_window_packets: usize,
}

impl RecoveryConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_send_udp_payload_size: config.max_send_udp_payload_size,
            max_ack_delay: Duration::ZERO,
            cc_ops: config.cc_algorithm.into(),
            hystart: config.hystart,
            pacing: config.pacing,
            max_pacing_rate: config.max_pacing_rate,
            initial_congestion_window_packets: config
                .initial_congestion_window_packets,
        }
    }
}

impl Recovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        let initial_congestion_window = recovery_config.max_send_udp_payload_size *
            recovery_config.initial_congestion_window_packets;

        Recovery {
            epochs: Default::default(),

            loss_timer: Default::default(),

            pto_count: 0,

            rtt_stats: RttStats::new(recovery_config.max_ack_delay),

            lost_count: 0,
            lost_spurious_count: 0,

            congestion_window: initial_congestion_window,

            pkt_thresh: INITIAL_PACKET_THRESHOLD,

            time_thresh: INITIAL_TIME_THRESHOLD,

            bytes_in_flight: 0,

            ssthresh: usize::MAX,

            bytes_acked_sl: 0,

            bytes_acked_ca: 0,

            bytes_sent: 0,

            bytes_lost: 0,

            congestion_recovery_start_time: None,

            max_datagram_size: recovery_config.max_send_udp_payload_size,

            cc_ops: recovery_config.cc_ops,

            delivery_rate: delivery_rate::Rate::default(),

            cubic_state: cubic::State::default(),

            app_limited: false,

            hystart: hystart::Hystart::new(recovery_config.hystart),

            pacer: pacer::Pacer::new(
                recovery_config.pacing,
                initial_congestion_window,
                0,
                recovery_config.max_send_udp_payload_size,
                recovery_config.max_pacing_rate,
            ),

            prr: prr::PRR::default(),

            send_quantum: initial_congestion_window,

            #[cfg(feature = "qlog")]
            qlog_metrics: QlogMetrics::default(),

            bbr_state: bbr::State::new(),

            bbr2_state: bbr2::State::new(),

            outstanding_non_ack_eliciting: 0,

            initial_congestion_window_packets: recovery_config
                .initial_congestion_window_packets,
        }
    }

    pub fn new(config: &Config) -> Self {
        Self::new_with_config(&RecoveryConfig::from_config(config))
    }

    pub fn on_init(&mut self) {
        (self.cc_ops.on_init)(self);
    }

    pub fn reset(&mut self) {
        self.congestion_window =
            self.max_datagram_size * self.initial_congestion_window_packets;
        self.epochs.iter_mut().for_each(|e| e.in_flight_count = 0);
        self.congestion_recovery_start_time = None;
        self.ssthresh = usize::MAX;
        (self.cc_ops.reset)(self);
        self.hystart.reset();
        self.prr = prr::PRR::default();
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
        let pkt_num = pkt.pkt_num;

        if ack_eliciting {
            self.outstanding_non_ack_eliciting = 0;
        } else {
            self.outstanding_non_ack_eliciting += 1;
        }

        if in_flight {
            if ack_eliciting {
                self.epochs[epoch].time_of_last_ack_eliciting_packet = Some(now);
            }

            self.on_packet_sent_cc(pkt_num, sent_bytes, now);

            self.epochs[epoch].in_flight_count += 1;

            self.set_loss_detection_timer(handshake_status, now);
        }

        self.bytes_sent += sent_bytes;

        // Pacing: Set the pacing rate if CC doesn't do its own.
        if !(self.cc_ops.has_custom_pacing)() &&
            self.rtt_stats.first_rtt_sample.is_some()
        {
            let rate = PACING_MULTIPLIER * self.congestion_window as f64 /
                self.rtt_stats.smoothed_rtt.as_secs_f64();
            self.set_pacing_rate(rate as u64, now);
        }

        self.schedule_next_packet(now, sent_bytes);

        pkt.time_sent = self.get_packet_send_time();

        // bytes_in_flight is already updated. Use previous value.
        self.delivery_rate.on_packet_sent(
            &mut pkt,
            self.bytes_in_flight - sent_bytes,
            self.bytes_lost,
        );

        self.epochs[epoch].sent_packets.push_back(pkt);

        trace!("{} {:?}", trace_id, self);
    }

    fn on_packet_sent_cc(
        &mut self, pkt_num: u64, sent_bytes: usize, now: Instant,
    ) {
        self.update_app_limited(
            (self.bytes_in_flight + sent_bytes) < self.congestion_window,
        );

        (self.cc_ops.on_packet_sent)(self, sent_bytes, now);

        self.prr.on_packet_sent(sent_bytes);

        // HyStart++: Start of the round in a slow start.
        if self.hystart.enabled() && self.congestion_window < self.ssthresh {
            self.hystart.start_round(pkt_num);
        }

        self.bytes_in_flight += sent_bytes;
    }

    pub fn set_pacing_rate(&mut self, rate: u64, now: Instant) {
        self.pacer.update(self.send_quantum, rate, now);
    }

    pub fn get_packet_send_time(&self) -> Instant {
        self.pacer.next_time()
    }

    fn schedule_next_packet(&mut self, now: Instant, packet_size: usize) {
        // Don't pace in any of these cases:
        //   * Packet contains no data.
        //   * The congestion window is within initcwnd.

        let in_initcwnd = self.bytes_sent <
            self.max_datagram_size * self.initial_congestion_window_packets;

        let sent_bytes = if !self.pacer.enabled() || in_initcwnd {
            0
        } else {
            packet_size
        };

        self.pacer.send(sent_bytes, now);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_ack_received(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str, newly_acked: &mut Vec<Acked>,
    ) -> Result<(usize, usize)> {
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
            newly_acked,
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
            (self.cc_ops.rollback)(self);
        }

        if newly_acked.is_empty() {
            return Ok((0, 0));
        }

        // Check if largest packet is newly acked.
        let largest_newly_acked = newly_acked.last().unwrap();

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

        self.on_packets_acked(newly_acked, now);

        self.bytes_in_flight -= acked_bytes;

        self.pto_count = 0;

        self.set_loss_detection_timer(handshake_status, now);

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now - self.rtt_stats.rtt());

        Ok(loss)
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
        self.congestion_window
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.epochs.iter().any(|e| e.loss_probes > 0) {
            return usize::MAX;
        }

        // Open more space (snd_cnt) for PRR when allowed.
        self.congestion_window.saturating_sub(self.bytes_in_flight) +
            self.prr.snd_cnt
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
        self.delivery_rate.sample_delivery_rate()
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn pmtud_update_max_datagram_size(
        &mut self, new_max_datagram_size: usize,
    ) {
        // Congestion Window is updated only when it's not updated already.
        if self.congestion_window ==
            self.max_datagram_size * self.initial_congestion_window_packets
        {
            self.congestion_window =
                new_max_datagram_size * self.initial_congestion_window_packets;
        }

        self.pacer = pacer::Pacer::new(
            self.pacer.enabled(),
            self.congestion_window,
            0,
            new_max_datagram_size,
            self.pacer.max_pacing_rate(),
        );
        self.max_datagram_size = new_max_datagram_size;
    }

    pub fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        let max_datagram_size =
            cmp::min(self.max_datagram_size, new_max_datagram_size);

        // Update cwnd if it hasn't been updated yet.
        if self.congestion_window ==
            self.max_datagram_size * self.initial_congestion_window_packets
        {
            self.congestion_window =
                max_datagram_size * self.initial_congestion_window_packets;
        }

        self.pacer = pacer::Pacer::new(
            self.pacer.enabled(),
            self.congestion_window,
            0,
            max_datagram_size,
            self.pacer.max_pacing_rate(),
        );

        self.max_datagram_size = max_datagram_size;
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
            self.on_packets_lost(loss.lost_bytes, &pkt, now);
        };

        self.bytes_in_flight -= loss.pmtud_lost_bytes;

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now - self.rtt_stats.rtt());

        self.lost_count += loss.lost_packets;

        (loss.lost_packets, loss.lost_bytes)
    }

    fn on_packets_acked(&mut self, acked: &mut Vec<Acked>, now: Instant) {
        // Update delivery rate sample per acked packet.
        for pkt in acked.iter() {
            self.delivery_rate.update_rate_sample(pkt, now);
        }

        // Fill in a rate sample.
        self.delivery_rate
            .generate_rate_sample(*self.rtt_stats.min_rtt);

        // Call congestion control hooks.
        (self.cc_ops.on_packets_acked)(self, acked, now);
    }

    fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(congestion_recovery_start_time) =>
                sent_time <= congestion_recovery_start_time,

            None => false,
        }
    }

    fn in_persistent_congestion(&mut self, _largest_lost_pkt_num: u64) -> bool {
        let _congestion_period = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;

        // TODO: properly detect persistent congestion
        false
    }

    fn on_packets_lost(
        &mut self, lost_bytes: usize, largest_lost_pkt: &Sent, now: Instant,
    ) {
        self.congestion_event(lost_bytes, largest_lost_pkt, now);

        if self.in_persistent_congestion(largest_lost_pkt.pkt_num) {
            self.collapse_cwnd();
        }

        self.bytes_in_flight -= lost_bytes;
    }

    fn congestion_event(
        &mut self, lost_bytes: usize, largest_lost_pkt: &Sent, now: Instant,
    ) {
        let time_sent = largest_lost_pkt.time_sent;

        if !self.in_congestion_recovery(time_sent) {
            (self.cc_ops.checkpoint)(self);
        }

        (self.cc_ops.congestion_event)(self, lost_bytes, largest_lost_pkt, now);
    }

    fn collapse_cwnd(&mut self) {
        (self.cc_ops.collapse_cwnd)(self);
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.app_limited = v;
    }

    pub fn app_limited(&self) -> bool {
        self.app_limited
    }

    pub fn delivery_rate_update_app_limited(&mut self, v: bool) {
        self.delivery_rate.update_app_limited(v);
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
            ssthresh: self.ssthresh as u64,
            pacing_rate: self.pacer.rate(),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    pub fn send_quantum(&self) -> usize {
        self.send_quantum
    }
}

/// Available congestion control algorithms.
///
/// This enum provides currently available list of congestion control
/// algorithms.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum CongestionControlAlgorithm {
    /// Reno congestion control algorithm. `reno` in a string form.
    Reno  = 0,
    /// CUBIC congestion control algorithm (default). `cubic` in a string form.
    CUBIC = 1,
    /// BBR congestion control algorithm. `bbr` in a string form.
    BBR   = 2,
    /// BBRv2 congestion control algorithm. `bbr2` in a string form.
    BBR2  = 3,
}

impl FromStr for CongestionControlAlgorithm {
    type Err = crate::Error;

    /// Converts a string to `CongestionControlAlgorithm`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "reno" => Ok(CongestionControlAlgorithm::Reno),
            "cubic" => Ok(CongestionControlAlgorithm::CUBIC),
            "bbr" => Ok(CongestionControlAlgorithm::BBR),
            "bbr2" => Ok(CongestionControlAlgorithm::BBR2),

            _ => Err(crate::Error::CongestionControl),
        }
    }
}

pub struct CongestionControlOps {
    pub on_init: fn(r: &mut Recovery),

    pub reset: fn(r: &mut Recovery),

    pub on_packet_sent: fn(r: &mut Recovery, sent_bytes: usize, now: Instant),

    pub on_packets_acked:
        fn(r: &mut Recovery, packets: &mut Vec<Acked>, now: Instant),

    pub congestion_event: fn(
        r: &mut Recovery,
        lost_bytes: usize,
        largest_lost_packet: &Sent,
        now: Instant,
    ),

    pub collapse_cwnd: fn(r: &mut Recovery),

    pub checkpoint: fn(r: &mut Recovery),

    pub rollback: fn(r: &mut Recovery) -> bool,

    pub has_custom_pacing: fn() -> bool,

    pub debug_fmt:
        fn(r: &Recovery, formatter: &mut std::fmt::Formatter) -> std::fmt::Result,
}

impl From<CongestionControlAlgorithm> for &'static CongestionControlOps {
    fn from(algo: CongestionControlAlgorithm) -> Self {
        match algo {
            CongestionControlAlgorithm::Reno => &reno::RENO,
            CongestionControlAlgorithm::CUBIC => &cubic::CUBIC,
            CongestionControlAlgorithm::BBR => &bbr::BBR,
            CongestionControlAlgorithm::BBR2 => &bbr2::BBR2,
        }
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
        write!(f, "cwnd={} ", self.congestion_window)?;
        write!(f, "ssthresh={} ", self.ssthresh)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight)?;
        write!(f, "app_limited={} ", self.app_limited)?;
        write!(
            f,
            "congestion_recovery_start_time={:?} ",
            self.congestion_recovery_start_time
        )?;
        write!(f, "{:?} ", self.delivery_rate)?;
        write!(f, "pacer={:?} ", self.pacer)?;

        if self.hystart.enabled() {
            write!(f, "hystart={:?} ", self.hystart)?;
        }

        // CC-specific debug info
        (self.cc_ops.debug_fmt)(self, f)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct Sent {
    pub pkt_num: u64,

    pub frames: SmallVec<[frame::Frame; 1]>,

    pub time_sent: Instant,

    pub time_acked: Option<Instant>,

    pub time_lost: Option<Instant>,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,

    pub tx_in_flight: usize,

    pub lost: u64,

    pub has_data: bool,

    pub pmtud: bool,
}

impl std::fmt::Debug for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pkt_num={:?} ", self.pkt_num)?;
        write!(f, "pkt_sent_time={:?} ", self.time_sent)?;
        write!(f, "pkt_size={:?} ", self.size)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        write!(f, "delivered_time={:?} ", self.delivered_time)?;
        write!(f, "first_sent_time={:?} ", self.first_sent_time)?;
        write!(f, "is_app_limited={} ", self.is_app_limited)?;
        write!(f, "tx_in_flight={} ", self.tx_in_flight)?;
        write!(f, "lost={} ", self.lost)?;
        write!(f, "has_data={} ", self.has_data)?;
        write!(f, "pmtud={}", self.pmtud)?;

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

    pub tx_in_flight: usize,

    pub lost: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HandshakeStatus {
    pub has_handshake_keys: bool,

    pub peer_verified_address: bool,

    pub completed: bool,
}

#[cfg(test)]
impl Default for HandshakeStatus {
    fn default() -> HandshakeStatus {
        HandshakeStatus {
            has_handshake_keys: true,

            peer_verified_address: true,

            completed: true,
        }
    }
}

// We don't need to log all qlog metrics every time there is a recovery event.
// Instead, we can log only the MetricsUpdated event data fields that we care
// about, only when they change. To support this, the QLogMetrics structure
// keeps a running picture of the fields.
#[derive(Default)]
#[cfg(feature = "qlog")]
struct QlogMetrics {
    min_rtt: Duration,
    smoothed_rtt: Duration,
    latest_rtt: Duration,
    rttvar: Duration,
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    pacing_rate: u64,
}

#[cfg(feature = "qlog")]
impl QlogMetrics {
    // Make a qlog event if the latest instance of QlogMetrics is different.
    //
    // This function diffs each of the fields. A qlog MetricsUpdated event is
    // only generated if at least one field is different. Where fields are
    // different, the qlog event contains the latest value.
    fn maybe_update(&mut self, latest: Self) -> Option<EventData> {
        let mut emit_event = false;

        let new_min_rtt = if self.min_rtt != latest.min_rtt {
            self.min_rtt = latest.min_rtt;
            emit_event = true;
            Some(latest.min_rtt.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_smoothed_rtt = if self.smoothed_rtt != latest.smoothed_rtt {
            self.smoothed_rtt = latest.smoothed_rtt;
            emit_event = true;
            Some(latest.smoothed_rtt.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_latest_rtt = if self.latest_rtt != latest.latest_rtt {
            self.latest_rtt = latest.latest_rtt;
            emit_event = true;
            Some(latest.latest_rtt.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_rttvar = if self.rttvar != latest.rttvar {
            self.rttvar = latest.rttvar;
            emit_event = true;
            Some(latest.rttvar.as_secs_f32() * 1000.0)
        } else {
            None
        };

        let new_cwnd = if self.cwnd != latest.cwnd {
            self.cwnd = latest.cwnd;
            emit_event = true;
            Some(latest.cwnd)
        } else {
            None
        };

        let new_bytes_in_flight =
            if self.bytes_in_flight != latest.bytes_in_flight {
                self.bytes_in_flight = latest.bytes_in_flight;
                emit_event = true;
                Some(latest.bytes_in_flight)
            } else {
                None
            };

        let new_ssthresh = if self.ssthresh != latest.ssthresh {
            self.ssthresh = latest.ssthresh;
            emit_event = true;
            Some(latest.ssthresh)
        } else {
            None
        };

        let new_pacing_rate = if self.pacing_rate != latest.pacing_rate {
            self.pacing_rate = latest.pacing_rate;
            emit_event = true;
            Some(latest.pacing_rate)
        } else {
            None
        };

        if emit_event {
            // QVis can't use all these fields and they can be large.
            return Some(EventData::MetricsUpdated(
                qlog::events::quic::MetricsUpdated {
                    min_rtt: new_min_rtt,
                    smoothed_rtt: new_smoothed_rtt,
                    latest_rtt: new_latest_rtt,
                    rtt_variance: new_rttvar,
                    pto_count: None,
                    congestion_window: new_cwnd,
                    bytes_in_flight: new_bytes_in_flight,
                    ssthresh: new_ssthresh,
                    packets_in_flight: None,
                    pacing_rate: new_pacing_rate,
                },
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

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
    fn collapse_cwnd() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        // cwnd will be reset.
        r.collapse_cwnd();
        assert_eq!(r.cwnd(), r.max_datagram_size * MINIMUM_WINDOW_PACKETS);
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
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // PTO.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.epochs[packet::Epoch::Application].loss_probes, 1);
        assert_eq!(r.lost_count, 0);
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
        assert_eq!(r.lost_count, 0);

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
                &mut Vec::new(),
            ),
            Ok((2, 2000))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 2);

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
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.epochs[packet::Epoch::Application].loss_probes, 0);

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 1);

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
                &mut Vec::new(),
            ),
            Ok((1, 1000))
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
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        // Spurious loss.
        assert_eq!(r.lost_count, 1);
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
        assert_eq!(r.pacer.rate(), 0);
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
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.rtt_stats.smoothed_rtt, Duration::from_millis(50));

        // 1 MSS increased.
        assert_eq!(r.congestion_window, 12000 + 1200);

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
            (r.congestion_window as f64 * PACING_MULTIPLIER / 0.05) as u64;
        assert_eq!(r.pacer.rate(), pacing_rate);

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
                &mut Vec::new(),
            ),
            Ok((0, 0))
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.epochs[packet::Epoch::Application].loss_probes, 0);

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.congestion_window, 12000);

        assert_eq!(r.lost_count, 0);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_lost_packets(packet::Epoch::Application, now, "");

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.lost_count, 0);
    }
}

mod bbr;
mod bbr2;
mod cubic;
mod delivery_rate;
mod hystart;
mod pacer;
mod prr;
mod reno;
mod rtt;
