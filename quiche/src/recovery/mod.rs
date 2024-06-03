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

use std::collections::VecDeque;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use crate::frame::Frame;
use crate::packet;
use crate::ranges::RangeSet;
use crate::Config;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use smallvec::SmallVec;

use self::bandwidth::Bandwidth;
use self::congestion::Acked;
use self::congestion::Congestion;
use self::congestion::CongestionControl;
use self::congestion::Lost;
use self::pacer::Pacer;
pub use self::pacer::ReleaseDecision;
use self::rtt::RttStats;

// Loss Recovery
const INITIAL_PACKET_THRESHOLD: u64 = 3;

const MAX_PACKET_THRESHOLD: u64 = 20;

const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

pub(crate) const GRANULARITY: Duration = Duration::from_millis(1);

const MAX_PTO_PROBES_COUNT: usize = 2;

// Congestion Control
const INITIAL_WINDOW_PACKETS: usize = 10;

const MAX_WINDOW_PACKETS: usize = 20_000;

// How many non ACK eliciting packets we send before including a PING to solicit
// an ACK.
pub(super) const MAX_OUTSTANDING_NON_ACK_ELICITING: usize = 24;

#[derive(Default)]
struct RecoveryEpoch {
    /// The time the most recent ack-eliciting packet was sent.
    time_of_last_ack_eliciting_packet: Option<Instant>,
    /// The largest packet number acknowledged in the packet number space so far
    largest_acked_packet: Option<u64>,
    /// The time at which the next packet in that packet number space can be
    /// considered lost based on exceeding the reordering window in time
    loss_time: Option<Instant>,
    /// An association of packet numbers in a packet number space to information
    /// about them.
    sent_packets: VecDeque<SentPacket>,

    loss_probes: usize,
    pkts_in_flight: usize,

    acked_frames: Vec<Frame>,
    lost_frames: Vec<Frame>,
}

struct AckedDetectionResult {
    acked_bytes: usize,
    spurious_losses: usize,
    spurious_pkt_thresh: Option<u64>,
    has_ack_eliciting: bool,
}

struct LossDetectionResult {
    lost_bytes: usize,
    lost_packets: usize,

    pmtud_lost_bytes: usize,
    pmtud_lost_packets: SmallVec<[u64; 1]>,
}

impl RecoveryEpoch {
    /// Discard the Epoch state and return the total size of unacked packets
    /// that were discarded
    fn discard(&mut self, cc: &mut impl CongestionControl) -> usize {
        let unacked_bytes = self
            .sent_packets
            .drain(..)
            .map(|p| {
                if let SentPacket {
                    status:
                        SentStatus::Sent {
                            in_flight,
                            sent_bytes,
                            ..
                        },
                    pkt_num,
                } = p
                {
                    cc.on_packet_neutered(pkt_num);
                    if in_flight {
                        return sent_bytes;
                    }
                }
                0
            })
            .sum();

        std::mem::take(&mut self.sent_packets);
        self.time_of_last_ack_eliciting_packet = None;
        self.loss_time = None;
        self.loss_probes = 0;
        self.pkts_in_flight = 0;

        unacked_bytes
    }

    fn detect_and_remove_acked_packets(
        &mut self, acked: &RangeSet, newly_acked: &mut Vec<Acked>, trace_id: &str,
    ) -> AckedDetectionResult {
        // Update the largest acked packet
        self.largest_acked_packet.replace(
            self.largest_acked_packet
                .unwrap_or(0)
                .max(acked.last().unwrap()),
        );

        newly_acked.clear();
        let mut acked_bytes = 0;
        let mut spurious_losses = 0;
        let mut spurious_pkt_thresh = None;
        let mut has_ack_eliciting = false;
        let largest_acked = self.largest_acked_packet.unwrap();

        for ack in acked.iter() {
            // Because packets always have incrementing numbers, they are always
            // in sorted order
            let start = if self
                .sent_packets
                .front()
                .filter(|e| e.pkt_num >= ack.start)
                .is_some()
            {
                // Usually it will be the first packet
                0
            } else {
                self.sent_packets
                    .binary_search_by_key(&ack.start, |p| p.pkt_num)
                    .unwrap_or_else(|e| e)
            };

            for SentPacket { pkt_num, status } in
                self.sent_packets.range_mut(start..)
            {
                if *pkt_num < ack.end {
                    match status.ack() {
                        SentStatus::Sent {
                            time_sent,
                            in_flight,
                            sent_bytes,
                            frames,
                            ack_eliciting,
                            ..
                        } => {
                            if in_flight {
                                self.pkts_in_flight -= 1;
                                acked_bytes += sent_bytes;
                            }
                            newly_acked.push(Acked {
                                pkt_num: *pkt_num,
                                time_sent,
                                size: sent_bytes,
                            });

                            self.acked_frames.extend(frames);

                            has_ack_eliciting |= ack_eliciting;

                            trace!("{} packet newly acked {}", trace_id, pkt_num);
                        },

                        SentStatus::Acked => {},
                        SentStatus::Lost => {
                            // An acked packet was already declared lost
                            spurious_losses += 1;
                            spurious_pkt_thresh
                                .get_or_insert(largest_acked - *pkt_num + 1);
                        },
                    }
                } else {
                    break;
                }
            }
        }

        self.drain_acked_and_lost_packets();

        AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
        }
    }

    fn detect_and_remove_lost_packets(
        &mut self, loss_delay: Duration, pkt_thresh: u64, now: Instant,
        newly_lost: &mut Vec<Lost>,
    ) -> LossDetectionResult {
        newly_lost.clear();
        let mut lost_bytes = 0;
        self.loss_time = None;

        let lost_send_time = now.checked_sub(loss_delay).unwrap();
        let largest_acked = self.largest_acked_packet.unwrap_or(0);
        let mut pmtud_lost_bytes = 0;
        let mut pmtud_lost_packets = SmallVec::new();

        for SentPacket { pkt_num, status } in &mut self.sent_packets {
            if *pkt_num > largest_acked {
                break;
            }

            if let SentStatus::Sent { time_sent, .. } = status {
                if *time_sent <= lost_send_time ||
                    largest_acked >= *pkt_num + pkt_thresh
                {
                    if let SentStatus::Sent {
                        in_flight,
                        sent_bytes,
                        frames,
                        pmtud,
                        ..
                    } = status.lose()
                    {
                        self.lost_frames.extend(frames);

                        if in_flight {
                            self.pkts_in_flight -= 1;

                            if pmtud {
                                pmtud_lost_bytes += sent_bytes;
                                pmtud_lost_packets.push(*pkt_num);
                                // Do not track PMTUD probes losses
                                continue;
                            }

                            lost_bytes += sent_bytes;
                        }

                        newly_lost.push(Lost {
                            packet_number: *pkt_num,
                            bytes_lost: sent_bytes,
                        });
                    }
                } else {
                    self.loss_time = Some(*time_sent + loss_delay);
                    break;
                }
            }
        }

        LossDetectionResult {
            lost_bytes,
            lost_packets: newly_lost.len(),

            pmtud_lost_bytes,
            pmtud_lost_packets,
        }
    }

    /// Remove packets that were already handled from the front of the queue,
    /// but avoid removing packets from the middle of the queue to avoid
    /// compaction
    fn drain_acked_and_lost_packets(&mut self) {
        while let Some(SentPacket {
            status: SentStatus::Acked | SentStatus::Lost,
            ..
        }) = self.sent_packets.front()
        {
            self.sent_packets.pop_front();
        }
    }

    fn least_unacked(&self) -> u64 {
        for pkt in self.sent_packets.iter() {
            if let SentPacket {
                pkt_num,
                status: SentStatus::Sent { .. },
            } = pkt
            {
                return *pkt_num;
            }
        }

        self.largest_acked_packet.unwrap_or(0) + 1
    }
}

#[derive(Debug)]
struct SentPacket {
    pkt_num: u64,
    status: SentStatus,
}

#[derive(Debug)]
enum SentStatus {
    Sent {
        time_sent: Instant,
        ack_eliciting: bool,
        in_flight: bool,
        has_data: bool,
        pmtud: bool,
        sent_bytes: usize,
        frames: SmallVec<[Frame; 1]>,
    },
    Acked,
    Lost,
}

impl SentStatus {
    fn ack(&mut self) -> Self {
        std::mem::replace(self, SentStatus::Acked)
    }

    fn lose(&mut self) -> Self {
        if !matches!(self, SentStatus::Acked) {
            std::mem::replace(self, SentStatus::Lost)
        } else {
            SentStatus::Acked
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

    pub max_ack_delay: Duration,

    pub lost_count: usize,

    pub lost_spurious_count: usize,

    pkt_thresh: u64,

    time_thresh: f64,

    bytes_in_flight: usize,

    bytes_sent: usize,

    pub bytes_lost: u64,

    max_datagram_size: usize,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    /// How many non-ack-eliciting packets have been sent.
    outstanding_non_ack_eliciting: usize,

    /// A [`Vec`] that can be reused for calls of
    /// [`detect_and_remove_acked_packets`] to avoid allocations
    acked_reuse: Vec<Acked>,
    /// A [`Vec`] that can be reused for calls of
    /// [`detect_and_remove_lost_packets`] to avoid allocations
    lost_reuse: Vec<Lost>,

    pacer: Pacer,
}

pub struct RecoveryConfig {
    max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    cc_algorithm: CongestionControlAlgorithm,
    pacing_enabled: bool,
    max_pacing_rate: Option<Bandwidth>,
}

impl RecoveryConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_send_udp_payload_size: config.max_send_udp_payload_size,
            max_ack_delay: Duration::ZERO,
            cc_algorithm: config.cc_algorithm,
            pacing_enabled: config.pacing,
            max_pacing_rate: config
                .max_pacing_rate
                .map(Bandwidth::from_mbits_per_second),
        }
    }
}

impl Recovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        let cc = match recovery_config.cc_algorithm {
            CongestionControlAlgorithm::Reno => Congestion::reno(
                INITIAL_WINDOW_PACKETS,
                MAX_WINDOW_PACKETS,
                recovery_config.max_send_udp_payload_size,
            ),
            CongestionControlAlgorithm::CUBIC => Congestion::cubic(
                INITIAL_WINDOW_PACKETS,
                MAX_WINDOW_PACKETS,
                recovery_config.max_send_udp_payload_size,
            ),
            CongestionControlAlgorithm::BBR => Congestion::bbr(
                INITIAL_WINDOW_PACKETS,
                MAX_WINDOW_PACKETS,
                recovery_config.max_send_udp_payload_size,
            ),
            CongestionControlAlgorithm::BBRv2 => Congestion::bbrv2(
                INITIAL_WINDOW_PACKETS,
                MAX_WINDOW_PACKETS,
                recovery_config.max_send_udp_payload_size,
            ),
        };

        Recovery {
            epochs: Default::default(),
            rtt_stats: Default::default(),
            loss_timer: Default::default(),
            pto_count: 0,

            max_ack_delay: recovery_config.max_ack_delay,

            lost_count: 0,
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

            pacer: Pacer::new(
                recovery_config.pacing_enabled,
                cc,
                recovery_config.max_pacing_rate,
            ),

            lost_reuse: Vec::new(),
            acked_reuse: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn new(config: &Config) -> Self {
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
    ) -> impl Iterator<Item = Frame> + '_ {
        self.epochs[epoch].acked_frames.drain(..)
    }

    pub fn get_lost_frames(
        &mut self, epoch: packet::Epoch,
    ) -> impl Iterator<Item = Frame> + '_ {
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
        &mut self, pkt: Sent, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) {
        let time_sent = self.get_next_release_time().time(now).unwrap_or(now);

        let epoch = &mut self.epochs[epoch];

        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let sent_bytes = pkt.size;
        let pkt_num = pkt.pkt_num;

        if let Some(SentPacket { pkt_num, .. }) = epoch.sent_packets.back() {
            assert!(*pkt_num < pkt.pkt_num, "Packet numbers must increase");
        }

        let status = SentStatus::Sent {
            time_sent,
            ack_eliciting,
            in_flight,
            pmtud: pkt.pmtud,
            has_data: pkt.has_data,
            sent_bytes,
            frames: pkt.frames,
        };

        epoch.sent_packets.push_back(SentPacket { pkt_num, status });

        if ack_eliciting {
            epoch.time_of_last_ack_eliciting_packet = Some(time_sent);
            self.outstanding_non_ack_eliciting = 0;
        } else {
            self.outstanding_non_ack_eliciting += 1;
        }

        if in_flight {
            self.pacer.on_packet_sent(
                time_sent,
                self.bytes_in_flight,
                pkt_num,
                sent_bytes,
                pkt.has_data,
                &self.rtt_stats,
            );

            self.bytes_in_flight += sent_bytes;
            epoch.pkts_in_flight += 1;
            self.set_loss_detection_timer(handshake_status, time_sent);
        }

        self.bytes_sent += sent_bytes;

        trace!("{} {:?}", trace_id, self);
    }

    pub fn get_packet_send_time(&self) -> Instant {
        let now = Instant::now();
        self.pacer.get_next_release_time().time(now).unwrap_or(now)
    }

    pub fn on_ack_received(
        &mut self, ranges: &RangeSet, ack_delay: u64, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) -> (usize, usize, usize) {
        let prior_in_flight = self.bytes_in_flight;

        let AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
        } = self.epochs[epoch].detect_and_remove_acked_packets(
            ranges,
            &mut self.acked_reuse,
            trace_id,
        );

        self.lost_spurious_count += spurious_losses;
        if let Some(thresh) = spurious_pkt_thresh {
            self.pkt_thresh =
                self.pkt_thresh.max(thresh.min(MAX_PACKET_THRESHOLD));
        }

        if self.acked_reuse.is_empty() {
            return (0, 0, 0);
        }

        self.bytes_in_flight -= acked_bytes;

        // Check if largest packet is newly acked
        let largest_newly_acked = self.acked_reuse.last().unwrap();
        let update_rtt: bool = largest_newly_acked.pkt_num ==
            ranges.last().unwrap() &&
            has_ack_eliciting;
        if update_rtt {
            let latest_rtt = now - largest_newly_acked.time_sent;
            self.rtt_stats.update_rtt(
                latest_rtt,
                Duration::from_micros(ack_delay),
                now,
                handshake_status.completed,
                self.max_ack_delay,
            );
        }

        let (lost_bytes, lost_packets) =
            self.detect_and_remove_lost_packets(epoch, now);

        self.pacer.on_congestion_event(
            update_rtt,
            prior_in_flight,
            self.bytes_in_flight,
            now,
            &self.acked_reuse,
            &self.lost_reuse,
            self.epochs[epoch].least_unacked(),
            &self.rtt_stats,
        );

        self.pto_count = 0;
        self.lost_count += lost_packets;

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{} {:?}", trace_id, self);

        (lost_packets, lost_bytes, acked_bytes)
    }

    fn detect_and_remove_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> (usize, usize) {
        let lost = &mut self.lost_reuse;

        let LossDetectionResult {
            lost_bytes,
            lost_packets,

            pmtud_lost_bytes,
            pmtud_lost_packets,
        } = self.epochs[epoch].detect_and_remove_lost_packets(
            self.rtt_stats.loss_delay(self.time_thresh),
            self.pkt_thresh,
            now,
            lost,
        );

        self.bytes_in_flight -= lost_bytes + pmtud_lost_bytes;

        for pkt in pmtud_lost_packets {
            self.pacer.on_packet_neutered(pkt);
        }

        (lost_bytes, lost_packets)
    }

    pub fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> (usize, usize) {
        let (earliest_loss_time, epoch) = self.loss_time_and_space();

        if earliest_loss_time.is_some() {
            let prior_in_flight = self.bytes_in_flight;

            let (lost_bytes, lost_packets) =
                self.detect_and_remove_lost_packets(epoch, now);

            self.pacer.on_congestion_event(
                false,
                prior_in_flight,
                self.bytes_in_flight,
                now,
                &[],
                &self.lost_reuse,
                self.epochs[epoch].least_unacked(),
                &self.rtt_stats,
            );

            self.lost_count += lost_packets;

            self.set_loss_detection_timer(handshake_status, now);

            trace!("{} {:?}", trace_id, self);
            return (lost_packets, lost_bytes);
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

        epoch.loss_probes = MAX_PTO_PROBES_COUNT.min(self.pto_count as usize);

        // Skip packets that have already been acked or lost, and packets
        // that don't contain either CRYPTO or STREAM frames and only return as
        // many packets as the number of probe packets that will be sent.
        let unacked_frames = epoch
            .sent_packets
            .iter_mut()
            .filter_map(|p| {
                if let SentStatus::Sent {
                    has_data: true,
                    frames,
                    ..
                } = &p.status
                {
                    Some(frames)
                } else {
                    None
                }
            })
            .take(epoch.loss_probes)
            .flatten();

        // Retransmit the frames from the oldest sent packets on PTO. However
        // the packets are not actually declared lost (so there is no effect to
        // congestion control), we just reschedule the data they carried.
        //
        // This will also trigger sending an ACK and retransmitting frames like
        // HANDSHAKE_DONE and MAX_DATA / MAX_STREAM_DATA as well, in addition
        // to CRYPTO and STREAM, if the original packet carried them.
        epoch.lost_frames.extend(unacked_frames.cloned());

        self.pacer
            .on_retransmission_timeout(!epoch.lost_frames.is_empty());

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{} {:?}", trace_id, self);
        (0, 0)
    }

    pub fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let epoch = &mut self.epochs[epoch];
        self.bytes_in_flight = self
            .bytes_in_flight
            .saturating_sub(epoch.discard(&mut self.pacer));
        self.set_loss_detection_timer(handshake_status, now);
    }

    pub fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, _trace_id: &str,
    ) -> (usize, usize) {
        let (lost_bytes, lost_packets) =
            self.detect_and_remove_lost_packets(epoch, now);

        (lost_packets, lost_bytes)
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_timer.time
    }

    pub fn cwnd(&self) -> usize {
        self.pacer.get_congestion_window()
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.epochs.iter().any(|e| e.loss_probes > 0) {
            return std::usize::MAX;
        }

        self.cwnd().saturating_sub(self.bytes_in_flight)
    }

    pub fn rtt(&self) -> Duration {
        self.rtt_stats.smoothed_rtt
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        let min_rtt = *self.rtt_stats.min_rtt;
        if min_rtt == Duration::MAX {
            return None;
        }

        Some(min_rtt)
    }

    pub fn rttvar(&self) -> Duration {
        self.rtt_stats.rttvar
    }

    pub fn pto(&self) -> Duration {
        let r = &self.rtt_stats;
        r.smoothed_rtt + (r.rttvar * 4).max(GRANULARITY)
    }

    pub fn delivery_rate(&self) -> u64 {
        self.pacer
            .bandwidth_estimate(&self.rtt_stats)
            .to_bits_per_second()
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn pmtud_update_max_datagram_size(
        &mut self, new_max_datagram_size: usize,
    ) {
        self.max_datagram_size = new_max_datagram_size;
        self.pacer.update_mss(self.max_datagram_size);
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
        let mut duration = self.pto() * (1 << self.pto_count);

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
        for &e in packet::Epoch::epochs(
            packet::Epoch::Initial..=packet::Epoch::Application,
        ) {
            if self.epochs[e].pkts_in_flight == 0 {
                continue;
            }

            if e == packet::Epoch::Application {
                // Skip Application Data until handshake completes.
                if !handshake_status.completed {
                    return (pto_timeout, pto_space);
                }

                // Include max_ack_delay and backoff for Application Data.
                duration += self.max_ack_delay * 2_u32.pow(self.pto_count);
            }

            let new_time = self.epochs[e]
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
        if let (Some(earliest_loss_time), _) = self.loss_time_and_space() {
            // Time threshold loss detection.
            self.loss_timer.update(earliest_loss_time);
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

    pub fn on_app_limited(&mut self) {
        self.pacer.on_app_limited(self.bytes_in_flight)
    }

    #[cfg(test)]
    pub fn app_limited(&self) -> bool {
        self.pacer.is_app_limited(self.bytes_in_flight)
    }

    pub fn update_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.max_ack_delay = max_ack_delay;
    }

    pub fn get_next_release_time(&self) -> ReleaseDecision {
        self.pacer.get_next_release_time()
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
            ssthresh: self.pacer.ssthresh(),
            pacing_rate: self.delivery_rate(),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    pub fn send_quantum(&self) -> usize {
        let pacing_rate = self
            .pacer
            .pacing_rate(self.bytes_in_flight, &self.rtt_stats);

        let floor = if pacing_rate < Bandwidth::from_kbits_per_second(1200) {
            self.max_datagram_size
        } else {
            2 * self.max_datagram_size
        };

        pacing_rate
            .to_bytes_per_period(pacer::ReleaseDecision::EQUAL_THRESHOLD)
            .min(64 * 1024)
            .max(floor as u64) as usize
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
    BBRv2 = 3,
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
            "bbr2" => Ok(CongestionControlAlgorithm::BBRv2),
            _ => Err(crate::Error::CongestionControl),
        }
    }
}

impl std::fmt::Debug for LossDetectionTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.time {
            Some(v) => {
                let now = Instant::now();
                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "timer={d:?} ")
                } else {
                    write!(f, "timer=exp ")
                }
            },
            None => write!(f, "timer=none "),
        }
    }
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "timer={:?} ", self.loss_detection_timer())?;
        write!(f, "rtt_stats={:?} ", self.rtt_stats)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight)?;
        write!(f, "{:?} ", self.pacer)?;
        Ok(())
    }
}

pub struct Sent {
    pub pkt_num: u64,
    pub frames: SmallVec<[Frame; 1]>,
    pub size: usize,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub has_data: bool,
    pub pmtud: bool,
}

impl std::fmt::Debug for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pkt_num={:?} ", self.pkt_num)?;
        write!(f, "pkt_size={:?} ", self.size)?;
        write!(f, "has_data={} ", self.has_data)?;
        write!(f, "pmtud={} ", self.pmtud)?;

        Ok(())
    }
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
    ssthresh: Option<u64>,
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
            latest.ssthresh
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            (0, 0, 2000)
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // PTO.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 1);
        assert_eq!(r.lost_count, 0);
        assert_eq!(r.pto_count, 1);

        let p = Sent {
            pkt_num: 4,
            frames: smallvec![],
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
        let mut acked = RangeSet::default();
        acked.insert(4..6);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            (2, 2000, 2000)
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 4);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.lost_count, 2);

        // Wait 1 RTT.
        now += r.rtt();

        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        r.epochs[packet::Epoch::Application].drain_acked_and_lost_packets();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0)
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
        let mut acked = RangeSet::default();
        acked.insert(0..2);
        acked.insert(3..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            (0, 0, 3000)
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 2);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.lost_count, 1);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_and_remove_lost_packets(packet::Epoch::Application, now);
        r.epochs[packet::Epoch::Application].drain_acked_and_lost_packets();

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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
        let mut acked = RangeSet::default();
        acked.insert(2..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            (1, 1000, 2000)
        );

        now += Duration::from_millis(10);

        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(r.pkt_thresh, INITIAL_PACKET_THRESHOLD);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                ""
            ),
            (0, 0, 1000)
        );

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        // Spurious loss.
        assert_eq!(r.lost_count, 1);
        assert_eq!(r.lost_spurious_count, 1);

        // Packet threshold was increased.
        assert_eq!(r.pkt_thresh, 4);
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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

        let p = Sent {
            pkt_num: 2,
            frames: smallvec![],
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
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

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first  packets and the last one are acked.
        let mut acked = RangeSet::default();
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
            (0, 0, 2000)
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
        // assert_eq!(r.epochs[packet::Epoch::Application].in_flight_count, 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.cwnd(), 12000);

        assert_eq!(r.lost_count, 0);

        // Wait 1 RTT.
        now += r.rtt();

        r.detect_and_remove_lost_packets(packet::Epoch::Application, now);
        r.epochs[packet::Epoch::Application].drain_acked_and_lost_packets();

        assert_eq!(r.epochs[packet::Epoch::Application].sent_packets.len(), 0);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(r.lost_count, 0);
    }
}

mod bandwidth;
mod congestion;
mod pacer;
mod rtt;
mod windowed_filter;
