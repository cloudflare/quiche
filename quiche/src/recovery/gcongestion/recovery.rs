use crate::packet;

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use smallvec::SmallVec;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

#[cfg(feature = "qlog")]
use crate::recovery::QlogMetrics;

use crate::frame;

use crate::recovery::rtt::RttStats;
use crate::recovery::CongestionControlAlgorithm;
use crate::recovery::HandshakeStatus;
use crate::recovery::LossDetectionTimer;
use crate::recovery::RangeSet;
use crate::recovery::RecoveryApi;
use crate::recovery::RecoveryConfig;
use crate::recovery::ReleaseDecision;
use crate::recovery::Sent;
use crate::recovery::GRANULARITY;
use crate::recovery::INITIAL_PACKET_THRESHOLD;
use crate::recovery::INITIAL_TIME_THRESHOLD;
use crate::recovery::INITIAL_WINDOW_PACKETS;
use crate::recovery::MAX_OUTSTANDING_NON_ACK_ELICITING;
use crate::recovery::MAX_PACKET_THRESHOLD;
use crate::recovery::MAX_PTO_PROBES_COUNT;
use crate::recovery::MAX_WINDOW_PACKETS;

use super::bandwidth::Bandwidth;
use super::pacer::Pacer;
use super::Acked;
use super::Congestion;
use super::CongestionControl;
use super::Lost;

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
        frames: SmallVec<[frame::Frame; 1]>,
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
    sent_packets: VecDeque<SentPacket>,

    loss_probes: usize,
    pkts_in_flight: usize,

    acked_frames: Vec<frame::Frame>,
    lost_frames: Vec<frame::Frame>,
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

pub struct GRecovery {
    epochs: [RecoveryEpoch; packet::Epoch::count()],

    loss_timer: LossDetectionTimer,

    pto_count: u32,

    rtt_stats: RttStats,

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

    /// A resusable list of acks.
    newly_acked: Vec<Acked>,

    /// A [`Vec`] that can be reused for calls of
    /// [`detect_and_remove_lost_packets`] to avoid allocations
    lost_reuse: Vec<Lost>,

    pacer: Pacer,
}

impl GRecovery {
    pub fn new(recovery_config: &RecoveryConfig) -> Option<Self> {
        let cc = match recovery_config.cc_algorithm {
            CongestionControlAlgorithm::BbrGcongestion => Congestion::bbr(
                INITIAL_WINDOW_PACKETS,
                MAX_WINDOW_PACKETS,
                recovery_config.max_send_udp_payload_size,
            ),
            CongestionControlAlgorithm::Bbr2Gcongestion => Congestion::bbrv2(
                INITIAL_WINDOW_PACKETS,
                MAX_WINDOW_PACKETS,
                recovery_config.max_send_udp_payload_size,
            ),
            _ => return None,
        };

        Some(Self {
            epochs: Default::default(),
            rtt_stats: RttStats::new(recovery_config.max_ack_delay),
            loss_timer: Default::default(),
            pto_count: 0,

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
                recovery_config.pacing,
                cc,
                recovery_config
                    .max_pacing_rate
                    .map(Bandwidth::from_mbits_per_second),
            ),

            newly_acked: Vec::new(),
            lost_reuse: Vec::new(),
        })
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
                duration +=
                    self.rtt_stats.max_ack_delay * 2_u32.pow(self.pto_count);
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
}

impl RecoveryApi for GRecovery {
    fn lost_count(&self) -> usize {
        self.lost_count
    }

    fn bytes_lost(&self) -> u64 {
        self.bytes_lost
    }

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

    fn get_packet_send_time(&self) -> Instant {
        let now = Instant::now();
        self.pacer.get_next_release_time().time(now).unwrap_or(now)
    }

    fn on_ack_received(
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
            &mut self.newly_acked,
            trace_id,
        );

        self.lost_spurious_count += spurious_losses;
        if let Some(thresh) = spurious_pkt_thresh {
            self.pkt_thresh =
                self.pkt_thresh.max(thresh.min(MAX_PACKET_THRESHOLD));
        }

        if self.newly_acked.is_empty() {
            return (0, 0, 0);
        }

        self.bytes_in_flight -= acked_bytes;

        // Check if largest packet is newly acked.
        let largest_newly_acked = self.newly_acked.last().unwrap();
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
            );
        }

        let (lost_bytes, lost_packets) =
            self.detect_and_remove_lost_packets(epoch, now);

        self.pacer.on_congestion_event(
            update_rtt,
            prior_in_flight,
            self.bytes_in_flight,
            now,
            &self.newly_acked,
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

    fn on_loss_detection_timeout(
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
            .flatten()
            .filter(|f| !matches!(f, frame::Frame::DatagramHeader { .. }));

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

    fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let epoch = &mut self.epochs[epoch];
        self.bytes_in_flight = self
            .bytes_in_flight
            .saturating_sub(epoch.discard(&mut self.pacer));
        self.set_loss_detection_timer(handshake_status, now);
    }

    fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, _trace_id: &str,
    ) -> (usize, usize) {
        let (lost_bytes, lost_packets) =
            self.detect_and_remove_lost_packets(epoch, now);

        (lost_packets, lost_bytes)
    }

    fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_timer.time
    }

    fn cwnd(&self) -> usize {
        self.pacer.get_congestion_window()
    }

    fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.epochs.iter().any(|e| e.loss_probes > 0) {
            return usize::MAX;
        }

        self.cwnd().saturating_sub(self.bytes_in_flight)
    }

    fn rtt(&self) -> Duration {
        self.rtt_stats.rtt()
    }

    fn min_rtt(&self) -> Option<Duration> {
        self.rtt_stats.min_rtt()
    }

    fn rttvar(&self) -> Duration {
        self.rtt_stats.rttvar()
    }

    fn pto(&self) -> Duration {
        let r = &self.rtt_stats;
        r.rtt() + (r.rttvar() * 4).max(GRANULARITY)
    }

    fn delivery_rate(&self) -> u64 {
        self.pacer
            .bandwidth_estimate(&self.rtt_stats)
            .to_bits_per_second()
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.max_datagram_size = new_max_datagram_size;
        self.pacer.update_mss(self.max_datagram_size);
    }

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.pmtud_update_max_datagram_size(
            self.max_datagram_size.min(new_max_datagram_size),
        )
    }

    fn on_app_limited(&mut self) {
        self.pacer.on_app_limited(self.bytes_in_flight)
    }

    #[cfg(test)]
    fn sent_packets_len(&self, epoch: packet::Epoch) -> usize {
        self.epochs[epoch].sent_packets.len()
    }

    #[cfg(test)]
    fn in_flight_count(&self, epoch: packet::Epoch) -> usize {
        self.epochs[epoch].pkts_in_flight
    }

    #[cfg(test)]
    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    #[cfg(test)]
    fn pacing_rate(&self) -> u64 {
        self.pacer
            .pacing_rate(self.bytes_in_flight, &self.rtt_stats)
            .to_bytes_per_period(Duration::from_secs(1))
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
        let ret = self.detect_and_remove_lost_packets(epoch, now);
        self.epochs[epoch].drain_acked_and_lost_packets();
        ret
    }

    #[cfg(test)]
    fn app_limited(&self) -> bool {
        self.pacer.is_app_limited(self.bytes_in_flight)
    }

    fn update_app_limited(&mut self, _v: bool) {
        // TODO
    }

    fn delivery_rate_update_app_limited(&mut self, _v: bool) {
        // TODO
    }

    fn update_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.rtt_stats.max_ack_delay = max_ack_delay;
    }

    fn get_next_release_time(&self) -> ReleaseDecision {
        self.pacer.get_next_release_time()
    }

    fn use_get_next_release_time(&self) -> bool {
        true
    }

    #[cfg(feature = "qlog")]
    fn maybe_qlog(&mut self) -> Option<EventData> {
        let qlog_metrics = QlogMetrics {
            min_rtt: self.rtt_stats.min_rtt().unwrap_or(Duration::MAX),
            smoothed_rtt: self.rtt(),
            latest_rtt: self.rtt_stats.latest_rtt(),
            rttvar: self.rtt_stats.rttvar(),
            cwnd: self.cwnd() as u64,
            bytes_in_flight: self.bytes_in_flight as u64,
            ssthresh: self.pacer.ssthresh(),
            pacing_rate: self.delivery_rate(),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    fn send_quantum(&self) -> usize {
        let pacing_rate = self
            .pacer
            .pacing_rate(self.bytes_in_flight, &self.rtt_stats);

        let floor = if pacing_rate < Bandwidth::from_kbits_per_second(1200) {
            self.max_datagram_size
        } else {
            2 * self.max_datagram_size
        };

        pacing_rate
            .to_bytes_per_period(ReleaseDecision::EQUAL_THRESHOLD)
            .min(64 * 1024)
            .max(floor as u64) as usize
    }
}

impl std::fmt::Debug for GRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "timer={:?} ", self.loss_detection_timer())?;
        write!(f, "rtt_stats={:?} ", self.rtt_stats)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight)?;
        write!(f, "{:?} ", self.pacer)?;
        Ok(())
    }
}
