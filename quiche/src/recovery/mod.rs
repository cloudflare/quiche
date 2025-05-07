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

use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use crate::frame;
use crate::packet;
use crate::ranges::RangeSet;
use crate::Config;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use smallvec::SmallVec;

use self::congestion::recovery::LegacyRecovery;
use self::gcongestion::GRecovery;
pub use gcongestion::BbrBwLoReductionStrategy;
pub use gcongestion::BbrParams;

// Loss Recovery
const INITIAL_PACKET_THRESHOLD: u64 = 3;

const MAX_PACKET_THRESHOLD: u64 = 20;

const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const MAX_PTO_PROBES_COUNT: usize = 2;

const MINIMUM_WINDOW_PACKETS: usize = 2;

const LOSS_REDUCTION_FACTOR: f64 = 0.5;

// How many non ACK eliciting packets we send before including a PING to solicit
// an ACK.
pub(super) const MAX_OUTSTANDING_NON_ACK_ELICITING: usize = 24;

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

impl std::fmt::Debug for LossDetectionTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.time {
            Some(v) => {
                let now = Instant::now();
                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "{d:?}")
                } else {
                    write!(f, "exp")
                }
            },
            None => write!(f, "none"),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct RecoveryConfig {
    pub max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    pub cc_algorithm: CongestionControlAlgorithm,
    pub custom_bbr_params: Option<BbrParams>,
    pub hystart: bool,
    pub pacing: bool,
    pub max_pacing_rate: Option<u64>,
    pub initial_congestion_window_packets: usize,
}

impl RecoveryConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_send_udp_payload_size: config.max_send_udp_payload_size,
            max_ack_delay: Duration::ZERO,
            cc_algorithm: config.cc_algorithm,
            custom_bbr_params: config.custom_bbr_params,
            hystart: config.hystart,
            pacing: config.pacing,
            max_pacing_rate: config.max_pacing_rate,
            initial_congestion_window_packets: config
                .initial_congestion_window_packets,
        }
    }
}

#[enum_dispatch::enum_dispatch(RecoveryOps)]
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Recovery {
    Legacy(LegacyRecovery),
    GCongestion(GRecovery),
}

#[derive(Debug, Default, PartialEq)]
pub struct OnAckReceivedOutcome {
    pub lost_packets: usize,
    pub lost_bytes: usize,
    pub acked_bytes: usize,
}

#[enum_dispatch::enum_dispatch]
/// Api for the Recovery implementation
pub trait RecoveryOps {
    fn lost_count(&self) -> usize;
    fn bytes_lost(&self) -> u64;

    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool;

    fn get_acked_frames(&mut self, epoch: packet::Epoch) -> Vec<frame::Frame>;

    fn get_lost_frames(&mut self, epoch: packet::Epoch) -> Vec<frame::Frame>;

    fn get_largest_acked_on_epoch(&self, epoch: packet::Epoch) -> Option<u64>;
    fn has_lost_frames(&self, epoch: packet::Epoch) -> bool;
    fn loss_probes(&self, epoch: packet::Epoch) -> usize;
    #[cfg(test)]
    fn inc_loss_probes(&mut self, epoch: packet::Epoch);

    fn ping_sent(&mut self, epoch: packet::Epoch);

    fn on_packet_sent(
        &mut self, pkt: Sent, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    );
    fn get_packet_send_time(&self, now: Instant) -> Instant;

    fn on_ack_received(
        &mut self, ranges: &RangeSet, ack_delay: u64, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) -> OnAckReceivedOutcome;

    fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> (usize, usize);
    fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    );
    fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, _trace_id: &str,
    ) -> (usize, usize);
    fn loss_detection_timer(&self) -> Option<Instant>;
    fn cwnd(&self) -> usize;
    fn cwnd_available(&self) -> usize;
    fn rtt(&self) -> Duration;

    fn min_rtt(&self) -> Option<Duration>;

    fn rttvar(&self) -> Duration;

    fn pto(&self) -> Duration;

    fn delivery_rate(&self) -> u64;

    fn max_datagram_size(&self) -> usize;

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize);

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize);

    fn on_app_limited(&mut self);

    #[cfg(test)]
    fn app_limited(&self) -> bool;

    #[cfg(test)]
    fn sent_packets_len(&self, epoch: packet::Epoch) -> usize;

    #[cfg(test)]
    fn bytes_in_flight(&self) -> usize;

    #[cfg(test)]
    fn in_flight_count(&self, epoch: packet::Epoch) -> usize;

    #[cfg(test)]
    fn pacing_rate(&self) -> u64;

    #[cfg(test)]
    fn pto_count(&self) -> u32;

    #[cfg(test)]
    fn pkt_thresh(&self) -> u64;

    #[cfg(test)]
    fn lost_spurious_count(&self) -> usize;

    #[cfg(test)]
    fn detect_lost_packets_for_test(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> (usize, usize);

    fn update_app_limited(&mut self, v: bool);

    fn delivery_rate_update_app_limited(&mut self, v: bool);

    fn update_max_ack_delay(&mut self, max_ack_delay: Duration);

    #[cfg(feature = "qlog")]
    fn maybe_qlog(&mut self) -> Option<EventData>;
    fn send_quantum(&self) -> usize;

    fn get_next_release_time(&self) -> ReleaseDecision;

    fn gcongestion_enabled(&self) -> bool;
}

impl Recovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        let grecovery = GRecovery::new(recovery_config);
        if let Some(grecovery) = grecovery {
            Recovery::from(grecovery)
        } else {
            Recovery::from(LegacyRecovery::new_with_config(recovery_config))
        }
    }

    #[cfg(test)]
    pub fn new(config: &crate::Config) -> Self {
        Self::new_with_config(&RecoveryConfig::from_config(config))
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
    Reno            = 0,
    /// CUBIC congestion control algorithm (default). `cubic` in a string form.
    CUBIC           = 1,
    /// BBR congestion control algorithm. `bbr` in a string form.
    BBR             = 2,
    /// BBRv2 congestion control algorithm. `bbr2` in a string form.
    BBR2            = 3,
    /// BBRv2 congestion control algorithm implementation from gcongestion
    /// branch. `bbr2_gcongestion` in a string form.
    Bbr2Gcongestion = 4,
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
            #[cfg(not(feature = "gcongestion"))]
            "bbr2" => Ok(CongestionControlAlgorithm::BBR2),
            #[cfg(feature = "gcongestion")]
            "bbr2" => Ok(CongestionControlAlgorithm::Bbr2Gcongestion),
            "bbr2_gcongestion" => Ok(CongestionControlAlgorithm::Bbr2Gcongestion),
            _ => Err(crate::Error::CongestionControl),
        }
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
                    congestion_window: new_cwnd,
                    bytes_in_flight: new_bytes_in_flight,
                    ssthresh: new_ssthresh,
                    pacing_rate: new_pacing_rate,
                    ..Default::default()
                },
            ));
        }

        None
    }
}

/// When the pacer thinks is a good time to release the next packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTime {
    Immediate,
    At(Instant),
}

/// When the next packet should be release and if it can be part of a burst
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseDecision {
    time: ReleaseTime,
    allow_burst: bool,
}

impl ReleaseTime {
    /// Add the specific delay to the current time
    #[allow(dead_code)]
    fn inc(&mut self, delay: Duration) {
        match self {
            ReleaseTime::Immediate => {},
            ReleaseTime::At(time) => *time += delay,
        }
    }

    /// Set the time to the later of two times
    #[allow(dead_code)]
    fn set_max(&mut self, other: Instant) {
        match self {
            ReleaseTime::Immediate => *self = ReleaseTime::At(other),
            ReleaseTime::At(time) => *self = ReleaseTime::At(other.max(*time)),
        }
    }
}

impl ReleaseDecision {
    pub(crate) const EQUAL_THRESHOLD: Duration = Duration::from_micros(50);

    /// Get the [`Instant`] the next packet should be released. It will never be
    /// in the past.
    #[allow(dead_code)]
    #[inline]
    pub fn time(&self, now: Instant) -> Option<Instant> {
        match self.time {
            ReleaseTime::Immediate => None,
            ReleaseTime::At(other) => other.gt(&now).then_some(other),
        }
    }

    /// Can this packet be appended to a previous burst
    #[allow(dead_code)]
    #[inline]
    pub fn can_burst(&self) -> bool {
        self.allow_burst
    }

    /// Check if the two packets can be released at the same time
    #[allow(dead_code)]
    #[inline]
    pub fn time_eq(&self, other: &Self, now: Instant) -> bool {
        let delta = match (self.time(now), other.time(now)) {
            (None, None) => Duration::ZERO,
            (Some(t), None) | (None, Some(t)) => t.duration_since(now),
            (Some(t1), Some(t2)) if t1 < t2 => t2.duration_since(t1),
            (Some(t1), Some(t2)) => t1.duration_since(t2),
        };

        delta <= Self::EQUAL_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::packet;
    use crate::ranges;
    use crate::recovery::congestion::PACING_MULTIPLIER;
    use crate::CongestionControlAlgorithm;
    use smallvec::smallvec;
    use std::str::FromStr;

    fn recovery_for_alg(algo: CongestionControlAlgorithm) -> Recovery {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(algo);
        Recovery::new(&cfg)
    }

    #[test]
    fn lookup_cc_algo_ok() {
        let algo = CongestionControlAlgorithm::from_str("reno").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::Reno);
        assert!(!recovery_for_alg(algo).gcongestion_enabled());

        let algo = CongestionControlAlgorithm::from_str("cubic").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::CUBIC);
        assert!(!recovery_for_alg(algo).gcongestion_enabled());

        let algo = CongestionControlAlgorithm::from_str("bbr").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::BBR);
        assert!(!recovery_for_alg(algo).gcongestion_enabled());

        let algo = CongestionControlAlgorithm::from_str("bbr2").unwrap();
        #[cfg(not(feature = "gcongestion"))]
        {
            assert_eq!(algo, CongestionControlAlgorithm::BBR2);
            assert!(!recovery_for_alg(algo).gcongestion_enabled());
        }
        #[cfg(feature = "gcongestion")]
        {
            assert_eq!(algo, CongestionControlAlgorithm::Bbr2Gcongestion);
            assert!(recovery_for_alg(algo).gcongestion_enabled());
        }

        let algo =
            CongestionControlAlgorithm::from_str("bbr2_gcongestion").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::Bbr2Gcongestion);
        assert!(recovery_for_alg(algo).gcongestion_enabled());
    }

    #[test]
    fn lookup_cc_algo_bad() {
        assert_eq!(
            CongestionControlAlgorithm::from_str("???"),
            Err(crate::Error::CongestionControl)
        );
    }

    #[rstest]
    fn loss_on_pto(
        #[values("reno", "cubic", "bbr", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

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

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);

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

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 4000);

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
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2000);
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // PTO.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 1);
        assert_eq!(r.lost_count(), 0);
        assert_eq!(r.pto_count(), 1);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 4000);
        assert_eq!(r.lost_count(), 0);

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
            OnAckReceivedOutcome {
                lost_packets: 2,
                lost_bytes: 2000,
                acked_bytes: 2 * 1000
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 0);

        assert_eq!(r.lost_count(), 2);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
    }

    #[rstest]
    fn loss_on_timer(
        #[values("reno", "cubic", "bbr", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 4000);

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
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 3 * 1000
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 0);

        assert_eq!(r.lost_count(), 1);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
    }

    #[rstest]
    fn loss_on_reordering(
        #[values("reno", "cubic", "bbr", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3000);

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
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 4000);

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
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000 * 2
            }
        );

        now += Duration::from_millis(10);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(r.pkt_thresh(), INITIAL_PACKET_THRESHOLD);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);

        // Spurious loss.
        assert_eq!(r.lost_count(), 1);
        assert_eq!(r.lost_spurious_count(), 1);

        // Packet threshold was increased.
        assert_eq!(r.pkt_thresh(), 4);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
    }

    #[rstest]
    fn pacing(
        #[values("reno", "cubic", "bbr", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // send out first packet burst (a full initcwnd).
        for i in 0..10 {
            let p = Sent {
                pkt_num: i,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: 1200,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: true,
                pmtud: false,
            };

            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 10);
        assert_eq!(r.bytes_in_flight(), 12000);

        // Next packet will be sent out immediately.
        if cc_algorithm_name != "bbr2_gcongestion" {
            assert_eq!(r.pacing_rate(), 0);
        } else {
            assert_eq!(r.pacing_rate(), 103963);
        }
        assert_eq!(r.get_packet_send_time(now), now);

        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 0);

        // Wait 50ms for ACK.
        now += Duration::from_millis(50);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..10);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            ),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 12000
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.rtt(), Duration::from_millis(50));

        // 10 MSS increased due to acks.
        assert_eq!(r.cwnd(), 12000 + 1200 * 10);

        // Send the second packet burst.
        let p = Sent {
            pkt_num: 10,
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
            has_data: true,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 6000);

        if cc_algorithm_name != "bbr2_gcongestion" {
            // Pacing is not done during initial phase of connection.
            assert_eq!(r.get_packet_send_time(now), now);
        } else {
            // Pacing is done from the beginning.
            assert_ne!(r.get_packet_send_time(now), now);
        }

        // Send the third packet burst.
        let p = Sent {
            pkt_num: 11,
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
            has_data: true,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 12000);

        // Send the fourth packet burst.
        let p = Sent {
            pkt_num: 12,
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
            has_data: true,
            pmtud: false,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 13000);

        // We pace this outgoing packet. as all conditions for pacing
        // are passed.
        let pacing_rate = match cc_algorithm_name {
            "bbr" => {
                // Constants from congestion/bbr/mod.rs
                let cwnd_gain = 2.0;
                let startup_pacing_gain = 2.89;
                // Adjust for cwnd_gain.  BW estimate was made before the CWND
                // increase.
                let bw = r.cwnd() as f64 /
                    cwnd_gain /
                    Duration::from_millis(50).as_secs_f64();
                (bw * startup_pacing_gain) as u64
            },
            "bbr2_gcongestion" => {
                let cwnd_gain: f64 = 2.0;
                // Adjust for cwnd_gain.  BW estimate was made before the CWND
                // increase.
                let bw = r.cwnd() as f64 /
                    cwnd_gain /
                    Duration::from_millis(50).as_secs_f64();
                bw as u64
            },
            "bbr2" => {
                // Constants from congestion/bbr2/mod.rs
                let cwnd_gain = 2.0;
                let startup_pacing_gain = 2.77;
                let pacing_margin_percent = 0.01;
                // Adjust for cwnd_gain.  BW estimate was made before the CWND
                // increase.
                let bw = r.cwnd() as f64 /
                    cwnd_gain /
                    Duration::from_millis(50).as_secs_f64();
                (bw * startup_pacing_gain * (1.0 - pacing_margin_percent)) as u64
            },
            _ => {
                let bw =
                    r.cwnd() as f64 / Duration::from_millis(50).as_secs_f64();
                (bw * PACING_MULTIPLIER) as u64
            },
        };
        assert_eq!(r.pacing_rate(), pacing_rate);

        let scale_factor = if cc_algorithm_name == "bbr2_gcongestion" {
            // For bbr2_gcongestion, send time is almost 13000 / pacing_rate.
            // Don't know where 13000 comes from.
            1.08333332
        } else {
            1.0
        };
        assert_eq!(
            r.get_packet_send_time(now) - now,
            Duration::from_secs_f64(scale_factor * 12000.0 / pacing_rate as f64)
        );
    }

    #[rstest]
    fn pmtud_loss_on_timer(
        #[values("reno", "cubic", "bbr", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);
        assert_eq!(r.cwnd(), 12000);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

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

        assert_eq!(r.in_flight_count(packet::Epoch::Application), 1);
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);

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

        assert_eq!(r.in_flight_count(packet::Epoch::Application), 2);

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

        assert_eq!(r.in_flight_count(packet::Epoch::Application), 3);

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
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.in_flight_count(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.cwnd(), match cc_algorithm_name {
            "bbr" => 14000,
            "bbr2" => 14000,
            _ => 12000,
        });

        assert_eq!(r.lost_count(), 0);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.in_flight_count(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.lost_count(), 0);
    }
}

mod congestion;
mod gcongestion;
mod rtt;
