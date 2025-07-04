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

use super::RecoveryConfig;
use super::Sent;

use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::recovery::Bandwidth;
use crate::recovery::HandshakeStatus;
use crate::recovery::OnLossDetectionTimeoutOutcome;
use crate::recovery::RecoveryOps;
use crate::recovery::StartupExit;
use crate::Error;
use crate::Result;

#[cfg(feature = "qlog")]
use crate::recovery::QlogMetrics;

use crate::frame;
use crate::packet;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use super::pacer;
use super::Congestion;
use crate::recovery::bytes_in_flight::BytesInFlight;
use crate::recovery::rtt::RttStats;
use crate::recovery::LossDetectionTimer;
use crate::recovery::OnAckReceivedOutcome;
use crate::recovery::ReleaseDecision;
use crate::recovery::ReleaseTime;
use crate::recovery::GRANULARITY;
use crate::recovery::INITIAL_PACKET_THRESHOLD;
use crate::recovery::INITIAL_TIME_THRESHOLD;
use crate::recovery::MAX_OUTSTANDING_NON_ACK_ELICITING;
use crate::recovery::MAX_PACKET_THRESHOLD;
use crate::recovery::MAX_PTO_PROBES_COUNT;

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

    /// The largest packet number sent in the packet number space so far.
    #[cfg(test)]
    test_largest_sent_pkt_num_on_path: Option<u64>,
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
    // `peer_sent_ack_ranges` should not be used without validation.
    fn detect_and_remove_acked_packets(
        &mut self, now: Instant, peer_sent_ack_ranges: &RangeSet,
        newly_acked: &mut Vec<Acked>, rtt_stats: &RttStats, skip_pn: Option<u64>,
        trace_id: &str,
    ) -> Result<AckedDetectionResult> {
        newly_acked.clear();

        let mut acked_bytes = 0;
        let mut spurious_losses = 0;
        let mut spurious_pkt_thresh = None;
        let mut has_ack_eliciting = false;
        let mut has_in_flight_spurious_loss = false;

        let largest_ack_received = peer_sent_ack_ranges
            .last()
            .expect("ACK frames should always have at least one ack range");
        let largest_acked = self
            .largest_acked_packet
            .unwrap_or(0)
            .max(largest_ack_received);

        for peer_sent_range in peer_sent_ack_ranges.iter() {
            if skip_pn.is_some_and(|skip_pn| peer_sent_range.contains(&skip_pn)) {
                // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
                // An endpoint SHOULD treat receipt of an acknowledgment
                // for a packet it did not send as
                // a connection error of type PROTOCOL_VIOLATION
                return Err(Error::OptimisticAckDetected);
            }

            // Because packets always have incrementing numbers, they are always
            // in sorted order.
            let start = if self
                .sent_packets
                .front()
                .filter(|e| e.pkt_num >= peer_sent_range.start)
                .is_some()
            {
                // Usually it will be the first packet.
                0
            } else {
                self.sent_packets
                    .binary_search_by_key(&peer_sent_range.start, |p| p.pkt_num)
                    .unwrap_or_else(|e| e)
            };

            for unacked in self.sent_packets.range_mut(start..) {
                if unacked.pkt_num >= peer_sent_range.end {
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

        Ok(AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
            has_in_flight_spurious_loss,
        })
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

                if unacked.is_pmtud_probe {
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

pub struct LegacyRecovery {
    epochs: [RecoveryEpoch; packet::Epoch::count()],

    loss_timer: LossDetectionTimer,

    pto_count: u32,

    rtt_stats: RttStats,

    lost_spurious_count: usize,

    pkt_thresh: u64,

    time_thresh: f64,

    bytes_in_flight: BytesInFlight,

    bytes_sent: usize,

    bytes_lost: u64,

    pub max_datagram_size: usize,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    #[cfg(feature = "qlog")]
    qlog_prev_cc_state: &'static str,

    /// How many non-ack-eliciting packets have been sent.
    outstanding_non_ack_eliciting: usize,

    pub congestion: Congestion,

    /// A resusable list of acks.
    newly_acked: Vec<Acked>,
}

impl LegacyRecovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        Self {
            epochs: Default::default(),

            loss_timer: Default::default(),

            pto_count: 0,

            rtt_stats: RttStats::new(recovery_config.max_ack_delay),

            lost_spurious_count: 0,

            pkt_thresh: INITIAL_PACKET_THRESHOLD,

            time_thresh: INITIAL_TIME_THRESHOLD,

            bytes_in_flight: Default::default(),

            bytes_sent: 0,

            bytes_lost: 0,

            max_datagram_size: recovery_config.max_send_udp_payload_size,

            #[cfg(feature = "qlog")]
            qlog_metrics: QlogMetrics::default(),

            #[cfg(feature = "qlog")]
            qlog_prev_cc_state: "",

            outstanding_non_ack_eliciting: 0,

            congestion: Congestion::from_config(recovery_config),

            newly_acked: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn new(config: &crate::Config) -> Self {
        Self::new_with_config(&RecoveryConfig::from_config(config))
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
        if self.bytes_in_flight.is_zero() {
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

        if self.bytes_in_flight.is_zero() &&
            handshake_status.peer_verified_address
        {
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
                self.bytes_in_flight.get(),
                loss.lost_bytes,
                &pkt,
                now,
            );

            self.bytes_in_flight
                .saturating_subtract(loss.lost_bytes, now);
        };

        self.bytes_in_flight
            .saturating_subtract(loss.pmtud_lost_bytes, now);

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now - self.rtt_stats.rtt());

        self.congestion.lost_count += loss.lost_packets;

        (loss.lost_packets, loss.lost_bytes)
    }
}

impl RecoveryOps for LegacyRecovery {
    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool {
        self.epochs[epoch].loss_probes > 0 ||
            self.outstanding_non_ack_eliciting >=
                MAX_OUTSTANDING_NON_ACK_ELICITING
    }

    fn get_acked_frames(&mut self, epoch: packet::Epoch) -> Vec<frame::Frame> {
        std::mem::take(&mut self.epochs[epoch].acked_frames)
    }

    fn get_lost_frames(&mut self, epoch: packet::Epoch) -> Vec<frame::Frame> {
        std::mem::take(&mut self.epochs[epoch].lost_frames)
    }

    fn get_largest_acked_on_epoch(&self, epoch: packet::Epoch) -> Option<u64> {
        self.epochs[epoch].largest_acked_packet
    }

    fn has_lost_frames(&self, epoch: packet::Epoch) -> bool {
        !self.epochs[epoch].lost_frames.is_empty()
    }

    fn loss_probes(&self, epoch: packet::Epoch) -> usize {
        self.epochs[epoch].loss_probes
    }

    #[cfg(test)]
    fn inc_loss_probes(&mut self, epoch: packet::Epoch) {
        self.epochs[epoch].loss_probes += 1;
    }

    fn ping_sent(&mut self, epoch: packet::Epoch) {
        self.epochs[epoch].loss_probes =
            self.epochs[epoch].loss_probes.saturating_sub(1);
    }

    fn on_packet_sent(
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
            self.bytes_in_flight.get(),
            sent_bytes,
            now,
            &mut pkt,
            &self.rtt_stats,
            self.bytes_lost,
            in_flight,
        );

        if in_flight {
            self.epochs[epoch].in_flight_count += 1;
            self.bytes_in_flight.add(sent_bytes, now);

            self.set_loss_detection_timer(handshake_status, now);
        }

        self.bytes_sent += sent_bytes;

        #[cfg(test)]
        {
            self.epochs[epoch].test_largest_sent_pkt_num_on_path = self.epochs
                [epoch]
                .test_largest_sent_pkt_num_on_path
                .max(Some(pkt.pkt_num));
        }

        self.epochs[epoch].sent_packets.push_back(pkt);

        trace!("{trace_id} {self:?}");
    }

    fn get_packet_send_time(&self, _now: Instant) -> Instant {
        // TODO .max(now)
        self.congestion.get_packet_send_time()
    }

    // `peer_sent_ack_ranges` should not be used without validation.
    fn on_ack_received(
        &mut self, peer_sent_ack_ranges: &RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_status: HandshakeStatus, now: Instant,
        skip_pn: Option<u64>, trace_id: &str,
    ) -> Result<OnAckReceivedOutcome> {
        let AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
            has_in_flight_spurious_loss,
        } = self.epochs[epoch].detect_and_remove_acked_packets(
            now,
            peer_sent_ack_ranges,
            &mut self.newly_acked,
            &self.rtt_stats,
            skip_pn,
            trace_id,
        )?;

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
            return Ok(OnAckReceivedOutcome::default());
        }

        let largest_newly_acked = self.newly_acked.last().unwrap();

        // Update `largest_acked_packet` based on the validated `newly_acked`
        // value.
        let largest_acked_pkt_num = self.epochs[epoch]
            .largest_acked_packet
            .unwrap_or(0)
            .max(largest_newly_acked.pkt_num);
        self.epochs[epoch].largest_acked_packet = Some(largest_acked_pkt_num);

        // Check if largest packet is newly acked.
        if largest_newly_acked.pkt_num == largest_acked_pkt_num &&
            has_ack_eliciting
        {
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
        let (lost_packets, lost_bytes) =
            self.detect_lost_packets(epoch, now, trace_id);

        self.congestion.on_packets_acked(
            self.bytes_in_flight.get(),
            &mut self.newly_acked,
            &self.rtt_stats,
            now,
        );

        self.bytes_in_flight.saturating_subtract(acked_bytes, now);

        self.pto_count = 0;

        self.set_loss_detection_timer(handshake_status, now);

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now - self.rtt_stats.rtt());

        Ok(OnAckReceivedOutcome {
            lost_packets,
            lost_bytes,
            acked_bytes,
            spurious_losses,
        })
    }

    fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> OnLossDetectionTimeoutOutcome {
        let (earliest_loss_time, epoch) = self.loss_time_and_space();

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            let (lost_packets, lost_bytes) =
                self.detect_lost_packets(epoch, now, trace_id);

            self.set_loss_detection_timer(handshake_status, now);

            trace!("{trace_id} {self:?}");
            return OnLossDetectionTimeoutOutcome {
                lost_packets,
                lost_bytes,
            };
        }

        let epoch = if self.bytes_in_flight.get() > 0 {
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

        trace!("{trace_id} {self:?}");

        OnLossDetectionTimeoutOutcome {
            lost_packets: 0,
            lost_bytes: 0,
        }
    }

    fn on_pkt_num_space_discarded(
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

        self.bytes_in_flight.saturating_subtract(unacked_bytes, now);

        epoch.sent_packets.clear();
        epoch.lost_frames.clear();
        epoch.acked_frames.clear();

        epoch.time_of_last_ack_eliciting_packet = None;
        epoch.loss_time = None;
        epoch.loss_probes = 0;
        epoch.in_flight_count = 0;

        self.set_loss_detection_timer(handshake_status, now);
    }

    fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        // Time threshold loss detection.
        self.detect_lost_packets(epoch, now, trace_id)
    }

    fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_timer.time
    }

    fn cwnd(&self) -> usize {
        self.congestion.congestion_window()
    }

    fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.epochs.iter().any(|e| e.loss_probes > 0) {
            return usize::MAX;
        }

        // Open more space (snd_cnt) for PRR when allowed.
        self.cwnd().saturating_sub(self.bytes_in_flight.get()) +
            self.congestion.prr.snd_cnt
    }

    fn rtt(&self) -> Duration {
        self.rtt_stats.rtt()
    }

    fn min_rtt(&self) -> Option<Duration> {
        self.rtt_stats.min_rtt()
    }

    fn max_rtt(&self) -> Option<Duration> {
        self.rtt_stats.max_rtt()
    }

    fn rttvar(&self) -> Duration {
        self.rtt_stats.rttvar
    }

    fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rtt_stats.rttvar * 4, GRANULARITY)
    }

    /// The most recent data delivery rate estimate.
    fn delivery_rate(&self) -> Bandwidth {
        self.congestion.delivery_rate()
    }

    /// Statistics from when a CCA first exited the startup phase.
    fn startup_exit(&self) -> Option<StartupExit> {
        self.congestion.ssthresh.startup_exit()
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
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

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.pmtud_update_max_datagram_size(
            self.max_datagram_size.min(new_max_datagram_size),
        )
    }

    #[cfg(test)]
    fn sent_packets_len(&self, epoch: packet::Epoch) -> usize {
        self.epochs[epoch].sent_packets.len()
    }

    #[cfg(test)]
    fn in_flight_count(&self, epoch: packet::Epoch) -> usize {
        self.epochs[epoch].in_flight_count
    }

    #[cfg(test)]
    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight.get()
    }

    fn bytes_in_flight_duration(&self) -> Duration {
        self.bytes_in_flight.get_duration()
    }

    #[cfg(test)]
    fn pacing_rate(&self) -> u64 {
        self.congestion.pacer.rate()
    }

    #[cfg(test)]
    fn pto_count(&self) -> u32 {
        self.pto_count
    }

    #[cfg(test)]
    fn pkt_thresh(&self) -> u64 {
        self.pkt_thresh
    }

    #[cfg(test)]
    fn lost_spurious_count(&self) -> usize {
        self.lost_spurious_count
    }

    #[cfg(test)]
    fn detect_lost_packets_for_test(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> (usize, usize) {
        self.detect_lost_packets(epoch, now, "")
    }

    // FIXME only used by gcongestion
    fn on_app_limited(&mut self) {
        // Not implemented for legacy recovery, update_app_limited and
        // delivery_rate_update_app_limited used instead.
    }

    #[cfg(test)]
    fn largest_sent_pkt_num_on_path(&self, epoch: packet::Epoch) -> Option<u64> {
        self.epochs[epoch].test_largest_sent_pkt_num_on_path
    }

    #[cfg(test)]
    fn app_limited(&self) -> bool {
        self.congestion.app_limited
    }

    fn update_app_limited(&mut self, v: bool) {
        self.congestion.update_app_limited(v);
    }

    // FIXME only used by congestion
    fn delivery_rate_update_app_limited(&mut self, v: bool) {
        self.congestion.delivery_rate.update_app_limited(v);
    }

    // FIXME only used by congestion
    fn update_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.rtt_stats.max_ack_delay = max_ack_delay;
    }

    #[cfg(feature = "qlog")]
    fn state_str(&self, now: Instant) -> &'static str {
        (self.congestion.cc_ops.state_str)(&self.congestion, now)
    }

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_event_data(&mut self) -> Option<EventData> {
        let qlog_metrics = QlogMetrics {
            min_rtt: *self.rtt_stats.min_rtt,
            smoothed_rtt: self.rtt(),
            latest_rtt: self.rtt_stats.latest_rtt,
            rttvar: self.rtt_stats.rttvar,
            cwnd: self.cwnd() as u64,
            bytes_in_flight: self.bytes_in_flight.get() as u64,
            ssthresh: Some(self.congestion.ssthresh.get() as u64),
            pacing_rate: self.congestion.pacer.rate(),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_cc_state(
        &mut self, now: Instant,
    ) -> Option<&'static str> {
        let cc_state = self.state_str(now);
        if cc_state != self.qlog_prev_cc_state {
            self.qlog_prev_cc_state = cc_state;
            Some(cc_state)
        } else {
            None
        }
    }

    fn send_quantum(&self) -> usize {
        self.congestion.send_quantum()
    }

    // TODO tests
    fn get_next_release_time(&self) -> ReleaseDecision {
        let now = Instant::now();
        let next_send_time = self.congestion.get_packet_send_time();
        if next_send_time > now {
            ReleaseDecision {
                time: ReleaseTime::At(next_send_time),
                allow_burst: false,
            }
        } else {
            ReleaseDecision {
                time: ReleaseTime::Immediate,
                allow_burst: false,
            }
        }
    }

    fn gcongestion_enabled(&self) -> bool {
        false
    }

    fn lost_count(&self) -> usize {
        self.congestion.lost_count
    }

    fn bytes_lost(&self) -> u64 {
        self.bytes_lost
    }
}

impl std::fmt::Debug for LegacyRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "timer={:?} ", self.loss_timer)?;
        write!(f, "latest_rtt={:?} ", self.rtt_stats.latest_rtt)?;
        write!(f, "srtt={:?} ", self.rtt_stats.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", *self.rtt_stats.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rtt_stats.rttvar)?;
        write!(f, "cwnd={} ", self.cwnd())?;
        write!(f, "ssthresh={} ", self.congestion.ssthresh.get())?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight.get())?;
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
