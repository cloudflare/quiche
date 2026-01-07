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
pub(crate) use crate::recovery::bandwidth::Bandwidth;
use crate::Config;
use crate::Result;

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

// Time threshold used to calculate the loss time.
//
// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2
const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

// Reduce the sensitivity to packet reordering after the first reordering event.
//
// Packet reorder is not a real loss event so quickly reduce the sensitivity to
// avoid penializing subsequent packet reordering.
//
// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2
//
// Implementations MAY experiment with absolute thresholds, thresholds from
// previous connections, adaptive thresholds, or the including of RTT variation.
// Smaller thresholds reduce reordering resilience and increase spurious
// retransmissions, and larger thresholds increase loss detection delay.
const PACKET_REORDER_TIME_THRESHOLD: f64 = 5.0 / 4.0;

// # Experiment: enable_relaxed_loss_threshold
//
// Time threshold overhead used to calculate the loss time.
//
// The actual threshold is calcualted as 1 + INITIAL_TIME_THRESHOLD_OVERHEAD and
// equivalent to INITIAL_TIME_THRESHOLD.
const INITIAL_TIME_THRESHOLD_OVERHEAD: f64 = 1.0 / 8.0;
// # Experiment: enable_relaxed_loss_threshold
//
// The factor by which to increase the time threshold on spurious loss.
const TIME_THRESHOLD_OVERHEAD_MULTIPLIER: f64 = 2.0;

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
    pub initial_rtt: Duration,
    pub max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    pub cc_algorithm: CongestionControlAlgorithm,
    pub custom_bbr_params: Option<BbrParams>,
    pub hystart: bool,
    pub pacing: bool,
    pub max_pacing_rate: Option<u64>,
    pub initial_congestion_window_packets: usize,
    pub enable_relaxed_loss_threshold: bool,
}

impl RecoveryConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            initial_rtt: config.initial_rtt,
            max_send_udp_payload_size: config.max_send_udp_payload_size,
            max_ack_delay: Duration::ZERO,
            cc_algorithm: config.cc_algorithm,
            custom_bbr_params: config.custom_bbr_params,
            hystart: config.hystart,
            pacing: config.pacing,
            max_pacing_rate: config.max_pacing_rate,
            initial_congestion_window_packets: config
                .initial_congestion_window_packets,
            enable_relaxed_loss_threshold: config.enable_relaxed_loss_threshold,
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
    pub spurious_losses: usize,
}

#[derive(Debug, Default)]
pub struct OnLossDetectionTimeoutOutcome {
    pub lost_packets: usize,
    pub lost_bytes: usize,
}

#[enum_dispatch::enum_dispatch]
/// Api for the Recovery implementation
pub trait RecoveryOps {
    fn lost_count(&self) -> usize;
    fn bytes_lost(&self) -> u64;

    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool;

    fn next_acked_frame(&mut self, epoch: packet::Epoch) -> Option<frame::Frame>;

    fn next_lost_frame(&mut self, epoch: packet::Epoch) -> Option<frame::Frame>;

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

    #[allow(clippy::too_many_arguments)]
    fn on_ack_received(
        &mut self, ranges: &RangeSet, ack_delay: u64, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, skip_pn: Option<u64>,
        trace_id: &str,
    ) -> Result<OnAckReceivedOutcome>;

    fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> OnLossDetectionTimeoutOutcome;
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

    fn max_rtt(&self) -> Option<Duration>;

    fn rttvar(&self) -> Duration;

    fn pto(&self) -> Duration;

    /// The most recent data delivery rate estimate.
    fn delivery_rate(&self) -> Bandwidth;

    /// Maximum bandwidth estimate, if one is available.
    fn max_bandwidth(&self) -> Option<Bandwidth>;

    /// Statistics from when a CCA first exited the startup phase.
    fn startup_exit(&self) -> Option<StartupExit>;

    fn max_datagram_size(&self) -> usize;

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize);

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize);

    fn on_app_limited(&mut self);

    // Since a recovery module is path specific, this tracks the largest packet
    // sent per path.
    #[cfg(test)]
    fn largest_sent_pkt_num_on_path(&self, epoch: packet::Epoch) -> Option<u64>;

    #[cfg(test)]
    fn app_limited(&self) -> bool;

    #[cfg(test)]
    fn sent_packets_len(&self, epoch: packet::Epoch) -> usize;

    fn bytes_in_flight(&self) -> usize;

    fn bytes_in_flight_duration(&self) -> Duration;

    #[cfg(test)]
    fn in_flight_count(&self, epoch: packet::Epoch) -> usize;

    #[cfg(test)]
    fn pacing_rate(&self) -> u64;

    #[cfg(test)]
    fn pto_count(&self) -> u32;

    // This value might be `None` when experiment `enable_relaxed_loss_threshold`
    // is enabled for gcongestion
    #[cfg(test)]
    fn pkt_thresh(&self) -> Option<u64>;

    #[cfg(test)]
    fn time_thresh(&self) -> f64;

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
    fn state_str(&self, now: Instant) -> &'static str;

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_event_data(&mut self) -> Option<EventData>;

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_cc_state(&mut self, now: Instant)
        -> Option<&'static str>;

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

    #[cfg(feature = "qlog")]
    pub fn maybe_qlog(
        &mut self, qlog: &mut qlog::streamer::QlogStreamer, now: Instant,
    ) {
        if let Some(ev_data) = self.get_updated_qlog_event_data() {
            qlog.add_event_data_with_instant(ev_data, now).ok();
        }

        if let Some(cc_state) = self.get_updated_qlog_cc_state(now) {
            let ev_data = EventData::CongestionStateUpdated(
                qlog::events::quic::CongestionStateUpdated {
                    old: None,
                    new: cc_state.to_string(),
                    trigger: None,
                },
            );

            qlog.add_event_data_with_instant(ev_data, now).ok();
        }
    }

    #[cfg(test)]
    pub fn new(config: &Config) -> Self {
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
            "bbr" => Ok(CongestionControlAlgorithm::Bbr2Gcongestion),
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

    pub is_pmtud_probe: bool,
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
        write!(f, "is_pmtud_probe={}", self.is_pmtud_probe)?;

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
    fn inc(&mut self, delay: Duration) {
        match self {
            ReleaseTime::Immediate => {},
            ReleaseTime::At(time) => *time += delay,
        }
    }

    /// Set the time to the later of two times
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
    #[inline]
    pub fn time(&self, now: Instant) -> Option<Instant> {
        match self.time {
            ReleaseTime::Immediate => None,
            ReleaseTime::At(other) => other.gt(&now).then_some(other),
        }
    }

    /// Can this packet be appended to a previous burst
    #[inline]
    pub fn can_burst(&self) -> bool {
        self.allow_burst
    }

    /// Check if the two packets can be released at the same time
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

/// Recovery statistics
#[derive(Default, Debug)]
pub struct RecoveryStats {
    startup_exit: Option<StartupExit>,
}

impl RecoveryStats {
    // Record statistics when a CCA first exits startup.
    pub fn set_startup_exit(&mut self, startup_exit: StartupExit) {
        if self.startup_exit.is_none() {
            self.startup_exit = Some(startup_exit);
        }
    }
}

/// Statistics from when a CCA first exited the startup phase.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StartupExit {
    /// The congestion_window recorded at Startup exit.
    pub cwnd: usize,

    /// The bandwidth estimate recorded at Startup exit.
    pub bandwidth: Option<u64>,

    /// The reason a CCA exited the startup phase.
    pub reason: StartupExitReason,
}

impl StartupExit {
    fn new(
        cwnd: usize, bandwidth: Option<Bandwidth>, reason: StartupExitReason,
    ) -> Self {
        let bandwidth = bandwidth.map(Bandwidth::to_bytes_per_second);
        Self {
            cwnd,
            bandwidth,
            reason,
        }
    }
}

/// The reason a CCA exited the startup phase.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StartupExitReason {
    /// Exit startup due to excessive loss
    Loss,

    /// Exit startup due to bandwidth plateau.
    BandwidthPlateau,

    /// Exit startup due to persistent queue.
    PersistentQueue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet;
    use crate::test_utils;
    use crate::CongestionControlAlgorithm;
    use crate::DEFAULT_INITIAL_RTT;
    use rstest::rstest;
    use smallvec::smallvec;
    use std::str::FromStr;

    fn recovery_for_alg(algo: CongestionControlAlgorithm) -> Recovery {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
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
        assert_eq!(algo, CongestionControlAlgorithm::Bbr2Gcongestion);
        assert!(recovery_for_alg(algo).gcongestion_enabled());

        let algo = CongestionControlAlgorithm::from_str("bbr2").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::Bbr2Gcongestion);
        assert!(recovery_for_alg(algo).gcongestion_enabled());

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
        #[values("reno", "cubic", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(10));
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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(30));

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(30));
        assert_eq!(r.lost_count(), 0);

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
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 2,
                lost_bytes: 2000,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(40));

        assert_eq!(r.lost_count(), 2);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        if cc_algorithm_name == "reno" || cc_algorithm_name == "cubic" {
            assert!(r.startup_exit().is_some());
            assert_eq!(r.startup_exit().unwrap().reason, StartupExitReason::Loss);
        } else {
            assert_eq!(r.startup_exit(), None);
        }
    }

    #[rstest]
    fn loss_on_timer(
        #[values("reno", "cubic", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 3 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(10));
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_micros(11250));

        assert_eq!(r.lost_count(), 1);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        if cc_algorithm_name == "reno" || cc_algorithm_name == "cubic" {
            assert!(r.startup_exit().is_some());
            assert_eq!(r.startup_exit().unwrap().reason, StartupExitReason::Loss);
        } else {
            assert_eq!(r.startup_exit(), None);
        }
    }

    #[rstest]
    fn loss_on_reordering(
        #[values("reno", "cubic", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // Start by sending a few packets.
        //
        // pkt number: [0, 1, 2, 3]
        for i in 0..4 {
            let p = test_utils::helper_packet_sent(i, now, 1000);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            let pkt_count = (i + 1) as usize;
            assert_eq!(r.sent_packets_len(packet::Epoch::Application), pkt_count);
            assert_eq!(r.bytes_in_flight(), pkt_count * 1000);
            assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);
        }

        // Wait for 10ms after sending.
        now += Duration::from_millis(10);

        // Recieve reordered ACKs, i.e. pkt_num [2, 3]
        let mut acked = RangeSet::default();
        acked.insert(2..4);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000 * 2,
                spurious_losses: 0,
            }
        );
        // Since we only remove packets from the back to avoid compaction, the
        // send length remains the same after receiving reordered ACKs
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.pkt_thresh().unwrap(), INITIAL_PACKET_THRESHOLD);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for 10ms after receiving first set of ACKs.
        now += Duration::from_millis(10);

        // Recieve remaining ACKs, i.e. pkt_num [0, 1]
        let mut acked = RangeSet::default();
        acked.insert(0..2);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000,
                spurious_losses: 1,
            }
        );
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(20));

        // Spurious loss.
        assert_eq!(r.lost_count(), 1);
        assert_eq!(r.lost_spurious_count(), 1);

        // Packet threshold was increased.
        assert_eq!(r.pkt_thresh().unwrap(), 4);
        assert_eq!(r.time_thresh(), PACKET_REORDER_TIME_THRESHOLD);

        // Wait 1 RTT.
        now += r.rtt();

        // All packets have been ACKed so dont expect additional lost packets
        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        if cc_algorithm_name == "reno" || cc_algorithm_name == "cubic" {
            assert!(r.startup_exit().is_some());
            assert_eq!(r.startup_exit().unwrap().reason, StartupExitReason::Loss);
        } else {
            assert_eq!(r.startup_exit(), None);
        }
    }

    // TODO: This should run agains both `congestion` and `gcongestion`.
    // `congestion` and `gcongestion` behave differently. That might be ok
    // given the different algorithms but it would be ideal to merge and share
    // the logic.
    #[rstest]
    fn time_thresholds_on_reordering(
        #[values("bbr2_gcongestion")] cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut now = Instant::now();
        let mut r = Recovery::new(&cfg);
        assert_eq!(r.rtt(), DEFAULT_INITIAL_RTT);

        // Pick time between and above thresholds for testing threshold increase.
        //
        //```
        //              between_thresh_ms
        //                         |
        //    initial_thresh_ms    |     spurious_thresh_ms
        //      v                  v             v
        // --------------------------------------------------
        //      | ................ | ..................... |
        //            THRESH_GAP         THRESH_GAP
        // ```
        // 
        // Threshold gap time.
        const THRESH_GAP: Duration = Duration::from_millis(30);
        // Initial time theshold based on inital RTT.
        let initial_thresh_ms =
            DEFAULT_INITIAL_RTT.mul_f64(INITIAL_TIME_THRESHOLD);
        // The time threshold after spurious loss.
        let spurious_thresh_ms: Duration =
            DEFAULT_INITIAL_RTT.mul_f64(PACKET_REORDER_TIME_THRESHOLD);
        // Time between the two thresholds
        let between_thresh_ms = initial_thresh_ms + THRESH_GAP;
        assert!(between_thresh_ms > initial_thresh_ms);
        assert!(between_thresh_ms < spurious_thresh_ms);
        assert!(between_thresh_ms + THRESH_GAP > spurious_thresh_ms);

        for i in 0..6 {
            let send_time = now + i * between_thresh_ms;

            let p = test_utils::helper_packet_sent(i.into(), send_time, 1000);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                send_time,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 6);
        assert_eq!(r.bytes_in_flight(), 6 * 1000);
        assert_eq!(r.pkt_thresh().unwrap(), INITIAL_PACKET_THRESHOLD);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for `between_thresh_ms` after sending to trigger loss based on
        // loss threshold.
        now += between_thresh_ms;

        // Ack packet: 1
        //
        // [0, 1, 2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(1..2);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        assert_eq!(r.pkt_thresh().unwrap(), INITIAL_PACKET_THRESHOLD);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Ack packet: 0
        //
        // [0, 1, 2, 3, 4, 5]
        //  ^  x
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 0,
                spurious_losses: 1,
            }
        );
        // The time_thresh after spurious loss
        assert_eq!(r.time_thresh(), PACKET_REORDER_TIME_THRESHOLD);

        // Wait for `between_thresh_ms` after sending. However, since the
        // threshold has increased, we do not expect loss.
        now += between_thresh_ms;

        // Ack packet: 3
        //
        // [2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(3..4);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );

        // Wait for and additional `plus_overhead` to trigger loss based on the
        // new time threshold.
        now += THRESH_GAP;

        // Ack packet: 4
        //
        // [2, 3, 4, 5]
        //     x  ^
        let mut acked = RangeSet::default();
        acked.insert(4..5);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
    }

    // TODO: Implement enable_relaxed_loss_threshold and enable this test for the
    // congestion module.
    #[rstest]
    fn relaxed_thresholds_on_reordering(
        #[values("bbr2_gcongestion")] cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.enable_relaxed_loss_threshold = true;
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut now = Instant::now();
        let mut r = Recovery::new(&cfg);
        assert_eq!(r.rtt(), DEFAULT_INITIAL_RTT);

        // Pick time between and above thresholds for testing threshold increase.
        //
        //```
        //              between_thresh_ms
        //                         |
        //    initial_thresh_ms    |     spurious_thresh_ms
        //      v                  v             v
        // --------------------------------------------------
        //      | ................ | ..................... |
        //            THRESH_GAP         THRESH_GAP
        // ```
        // Threshold gap time.
        const THRESH_GAP: Duration = Duration::from_millis(30);
        // Initial time theshold based on inital RTT.
        let initial_thresh_ms =
            DEFAULT_INITIAL_RTT.mul_f64(INITIAL_TIME_THRESHOLD);
        // The time threshold after spurious loss.
        let spurious_thresh_ms: Duration =
            DEFAULT_INITIAL_RTT.mul_f64(PACKET_REORDER_TIME_THRESHOLD);
        // Time between the two thresholds
        let between_thresh_ms = initial_thresh_ms + THRESH_GAP;
        assert!(between_thresh_ms > initial_thresh_ms);
        assert!(between_thresh_ms < spurious_thresh_ms);
        assert!(between_thresh_ms + THRESH_GAP > spurious_thresh_ms);

        for i in 0..6 {
            let send_time = now + i * between_thresh_ms;

            let p = test_utils::helper_packet_sent(i.into(), send_time, 1000);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                send_time,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 6);
        assert_eq!(r.bytes_in_flight(), 6 * 1000);
        // Intitial thresholds
        assert_eq!(r.pkt_thresh().unwrap(), INITIAL_PACKET_THRESHOLD);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for `between_thresh_ms` after sending to trigger loss based on
        // loss threshold.
        now += between_thresh_ms;

        // Ack packet: 1
        //
        // [0, 1, 2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(1..2);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        // Thresholds after 1st loss
        assert_eq!(r.pkt_thresh().unwrap(), INITIAL_PACKET_THRESHOLD);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Ack packet: 0
        //
        // [0, 1, 2, 3, 4, 5]
        //  ^  x
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 0,
                spurious_losses: 1,
            }
        );
        // Thresholds after 1st spurious loss
        //
        // Packet threshold should be disabled. Time threshold overhead should
        // stay the same.
        assert_eq!(r.pkt_thresh(), None);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Set now to send time of packet 2 so we can trigger spurious loss for
        // packet 2.
        now += between_thresh_ms;
        // Then wait for `between_thresh_ms` after sending packet 2 to trigger
        // loss. Since the time threshold has NOT increased, expect a
        // loss.
        now += between_thresh_ms;

        // Ack packet: 3
        //
        // [2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(3..4);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        // Thresholds after 2nd loss.
        assert_eq!(r.pkt_thresh(), None);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for and additional `plus_overhead` to trigger loss based on the
        // new time threshold.
        // now += THRESH_GAP;

        // Ack packet: 2
        //
        // [2, 3, 4, 5]
        //  ^  x
        let mut acked = RangeSet::default();
        acked.insert(2..3);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 0,
                spurious_losses: 1,
            }
        );
        // Thresholds after 2nd spurious loss.
        //
        // Time threshold overhead should double.
        assert_eq!(r.pkt_thresh(), None);
        let double_time_thresh_overhead =
            1.0 + 2.0 * INITIAL_TIME_THRESHOLD_OVERHEAD;
        assert_eq!(r.time_thresh(), double_time_thresh_overhead);
    }

    #[rstest]
    fn pacing(
        #[values("reno", "cubic", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let pacing_enabled = cc_algorithm_name == "bbr2" ||
            cc_algorithm_name == "bbr2_gcongestion";

        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
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
                is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        if !pacing_enabled {
            assert_eq!(r.pacing_rate(), 0);
        } else {
            assert_eq!(r.pacing_rate(), 103963);
        }
        assert_eq!(r.get_packet_send_time(now), now);

        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 0);

        // Wait 50ms for ACK.
        let initial_rtt = Duration::from_millis(50);
        now += initial_rtt;

        let mut acked = RangeSet::default();
        acked.insert(0..10);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 12000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);
        assert_eq!(r.min_rtt(), Some(initial_rtt));
        assert_eq!(r.rtt(), initial_rtt);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);

        if !pacing_enabled {
            // Pacing is disabled.
            assert_eq!(r.get_packet_send_time(now), now);
        } else {
            // Pacing is done from the beginning.
            assert_ne!(r.get_packet_send_time(now), now);
        }

        // Send the third and fourth packet bursts together.
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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);

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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);

        // We pace this outgoing packet. as all conditions for pacing
        // are passed.
        let pacing_rate = if pacing_enabled {
            let cwnd_gain: f64 = 2.0;
            // Adjust for cwnd_gain.  BW estimate was made before the CWND
            // increase.
            let bw = r.cwnd() as f64 / cwnd_gain / initial_rtt.as_secs_f64();
            bw as u64
        } else {
            0
        };
        assert_eq!(r.pacing_rate(), pacing_rate);

        let scale_factor = if pacing_enabled {
            // For bbr2_gcongestion, send time is almost 13000 / pacing_rate.
            // Don't know where 13000 comes from.
            1.08333332
        } else {
            1.0
        };
        assert_eq!(
            r.get_packet_send_time(now) - now,
            if pacing_enabled {
                Duration::from_secs_f64(
                    scale_factor * 12000.0 / pacing_rate as f64,
                )
            } else {
                Duration::ZERO
            }
        );
        assert_eq!(r.startup_exit(), None);

        let reduced_rtt = Duration::from_millis(40);
        now += reduced_rtt;

        let mut acked = RangeSet::default();
        acked.insert(10..11);

        assert_eq!(
            r.on_ack_received(
                &acked,
                0,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 6000,
                spurious_losses: 0,
            }
        );

        let expected_srtt = (7 * initial_rtt + reduced_rtt) / 8;
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 7000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt + reduced_rtt);
        assert_eq!(r.min_rtt(), Some(reduced_rtt));
        assert_eq!(r.rtt(), expected_srtt);

        let mut acked = RangeSet::default();
        acked.insert(11..12);

        assert_eq!(
            r.on_ack_received(
                &acked,
                0,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 6000,
                spurious_losses: 0,
            }
        );

        // When enabled, the pacer adds a 25msec delay to the packet
        // sends which will be applied to the sent times tracked by
        // the recovery module, bringing down RTT to 15msec.
        let expected_min_rtt = if pacing_enabled {
            reduced_rtt - Duration::from_millis(25)
        } else {
            reduced_rtt
        };

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt + reduced_rtt);
        assert_eq!(r.min_rtt(), Some(expected_min_rtt));

        let expected_srtt = (7 * expected_srtt + expected_min_rtt) / 8;
        assert_eq!(r.rtt(), expected_srtt);

        let mut acked = RangeSet::default();
        acked.insert(12..13);

        assert_eq!(
            r.on_ack_received(
                &acked,
                0,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );

        // Pacer adds 50msec delay to the second packet, resulting in
        // an effective RTT of 0.
        let expected_min_rtt = if pacing_enabled {
            Duration::from_millis(0)
        } else {
            reduced_rtt
        };
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt + reduced_rtt);
        assert_eq!(r.min_rtt(), Some(expected_min_rtt));

        let expected_srtt = (7 * expected_srtt + expected_min_rtt) / 8;
        assert_eq!(r.rtt(), expected_srtt);
    }

    #[rstest]
    // initial_cwnd / first_rtt == initial_pacing_rate.  Pacing is 1.0 * bw before
    // and after.
    #[case::bw_estimate_equal_after_first_rtt(1.0, 1.0)]
    // initial_cwnd / first_rtt < initial_pacing_rate.  Pacing decreases from 2 *
    // bw to 1.0 * bw.
    #[case::bw_estimate_decrease_after_first_rtt(2.0, 1.0)]
    // initial_cwnd / first_rtt > initial_pacing_rate from 0.5 * bw to 1.0 * bw.
    // Initial pacing remains 0.5 * bw because the initial_pacing_rate parameter
    // is used an upper bound for the pacing rate after the first RTT.
    // Pacing rate after the first ACK should be:
    // min(initial_pacing_rate_bytes_per_second, init_cwnd / first_rtt)
    #[case::bw_estimate_increase_after_first_rtt(0.5, 0.5)]
    #[cfg(feature = "internal")]
    fn initial_pacing_rate_override(
        #[case] initial_multipler: f64, #[case] expected_multiplier: f64,
    ) {
        let rtt = Duration::from_millis(50);
        let bw = Bandwidth::from_bytes_and_time_delta(12000, rtt);
        let initial_pacing_rate_hint = bw * initial_multipler;
        let expected_pacing_with_rtt_measurement = bw * expected_multiplier;

        let cc_algorithm_name = "bbr2_gcongestion";
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
        cfg.set_custom_bbr_params(BbrParams {
            initial_pacing_rate_bytes_per_second: Some(
                initial_pacing_rate_hint.to_bytes_per_second(),
            ),
            ..Default::default()
        });

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // send some packets.
        for i in 0..2 {
            let p = test_utils::helper_packet_sent(i, now, 1200);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2400);
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        // Initial pacing rate matches the override value.
        assert_eq!(
            r.pacing_rate(),
            initial_pacing_rate_hint.to_bytes_per_second()
        );
        assert_eq!(r.get_packet_send_time(now), now);

        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 9600);

        // Wait 1 rtt for ACK.
        now += rtt;

        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2400,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), rtt);
        assert_eq!(r.rtt(), rtt);

        // Pacing rate is recalculated based on initial cwnd when the
        // first RTT estimate is available.
        assert_eq!(
            r.pacing_rate(),
            expected_pacing_with_rtt_measurement.to_bytes_per_second()
        );
    }

    #[rstest]
    fn validate_ack_range_on_ack_received(
        #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm_name(cc_algorithm_name).unwrap();

        let epoch = packet::Epoch::Application;
        let mut r = Recovery::new(&cfg);
        let mut now = Instant::now();
        assert_eq!(r.sent_packets_len(epoch), 0);

        // Send 4 packets
        let pkt_size = 1000;
        let pkt_count = 4;
        for pkt_num in 0..pkt_count {
            let sent = test_utils::helper_packet_sent(pkt_num, now, pkt_size);
            r.on_packet_sent(sent, epoch, HandshakeStatus::default(), now, "");
        }
        assert_eq!(r.sent_packets_len(epoch), pkt_count as usize);
        assert_eq!(r.bytes_in_flight(), pkt_count as usize * pkt_size);
        assert!(r.get_largest_acked_on_epoch(epoch).is_none());
        assert_eq!(r.largest_sent_pkt_num_on_path(epoch).unwrap(), 3);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // ACK 2 packets
        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                epoch,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(epoch), 2);
        assert_eq!(r.bytes_in_flight(), 2 * 1000);

        assert_eq!(r.get_largest_acked_on_epoch(epoch).unwrap(), 1);
        assert_eq!(r.largest_sent_pkt_num_on_path(epoch).unwrap(), 3);

        // ACK large range
        let mut acked = RangeSet::default();
        acked.insert(0..10);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                epoch,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );
        assert_eq!(r.sent_packets_len(epoch), 0);
        assert_eq!(r.bytes_in_flight(), 0);

        assert_eq!(r.get_largest_acked_on_epoch(epoch).unwrap(), 3);
        assert_eq!(r.largest_sent_pkt_num_on_path(epoch).unwrap(), 3);
    }

    #[rstest]
    fn pmtud_loss_on_timer(
        #[values("reno", "cubic", "bbr2", "bbr2_gcongestion")]
        cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
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
            is_pmtud_probe: false,
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
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

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
            is_pmtud_probe: true,
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
            is_pmtud_probe: false,
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
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(10));
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.in_flight_count(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_micros(11250));
        assert_eq!(r.cwnd(), 12000);

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
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_micros(11250));
        assert_eq!(r.lost_count(), 0);
        assert_eq!(r.startup_exit(), None);
    }

    // Modeling delivery_rate for gcongestion is non-trivial so we only test the
    // congestion specific algorithms.
    #[rstest]
    fn congestion_delivery_rate(
        #[values("reno", "cubic", "bbr2")] cc_algorithm_name: &str,
    ) {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);
        assert_eq!(r.cwnd(), 12000);

        let now = Instant::now();

        let mut total_bytes_sent = 0;
        for pn in 0..10 {
            // Start by sending a few packets.
            let bytes = 1000;
            let sent = test_utils::helper_packet_sent(pn, now, bytes);
            r.on_packet_sent(
                sent,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            total_bytes_sent += bytes;
        }

        // Ack
        let interval = Duration::from_secs(10);
        let mut acked = RangeSet::default();
        acked.insert(0..10);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now + interval,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: total_bytes_sent,
                spurious_losses: 0,
            }
        );
        assert_eq!(r.delivery_rate().to_bytes_per_second(), 1000);
        assert_eq!(r.min_rtt().unwrap(), interval);
        // delivery rate should be in units bytes/sec
        assert_eq!(
            total_bytes_sent as u64 / interval.as_secs(),
            r.delivery_rate().to_bytes_per_second()
        );
        assert_eq!(r.startup_exit(), None);
    }

    #[rstest]
    fn acks_with_no_retransmittable_data(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) {
        let rtt = Duration::from_millis(100);

        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert_eq!(cfg.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        let mut next_packet = 0;
        // send some packets.
        for _ in 0..3 {
            let p = test_utils::helper_packet_sent(next_packet, now, 1200);
            next_packet += 1;
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3600);
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        assert_eq!(
            r.pacing_rate(),
            if cc_algorithm_name == "bbr2_gcongestion" {
                103963
            } else {
                0
            },
        );
        assert_eq!(r.get_packet_send_time(now), now);
        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 8400);

        // Wait 1 rtt for ACK.
        now += rtt;

        let mut acked = RangeSet::default();
        acked.insert(0..3);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )
            .unwrap(),
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 3600,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), rtt);
        assert_eq!(r.rtt(), rtt);

        // Pacing rate is recalculated based on initial cwnd when the
        // first RTT estimate is available.
        assert_eq!(
            r.pacing_rate(),
            if cc_algorithm_name == "bbr2_gcongestion" {
                120000
            } else {
                0
            },
        );

        // Send some no "in_flight" packets
        for iter in 3..1000 {
            let mut p = test_utils::helper_packet_sent(next_packet, now, 1200);
            // `in_flight = false` marks packets as if they only contained ACK
            // frames.
            p.in_flight = false;
            next_packet += 1;
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            now += rtt;

            let mut acked = RangeSet::default();
            acked.insert(iter..(iter + 1));

            assert_eq!(
                r.on_ack_received(
                    &acked,
                    10,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    None,
                    "",
                )
                .unwrap(),
                OnAckReceivedOutcome {
                    lost_packets: 0,
                    lost_bytes: 0,
                    acked_bytes: 0,
                    spurious_losses: 0,
                }
            );

            // Verify that connection has not exited startup.
            assert_eq!(r.startup_exit(), None, "{iter}");

            // Unchanged metrics.
            assert_eq!(
                r.sent_packets_len(packet::Epoch::Application),
                0,
                "{iter}"
            );
            assert_eq!(r.bytes_in_flight(), 0, "{iter}");
            assert_eq!(r.bytes_in_flight_duration(), rtt, "{iter}");
            assert_eq!(
                r.pacing_rate(),
                if cc_algorithm_name == "bbr2_gcongestion" ||
                    cc_algorithm_name == "bbr2"
                {
                    120000
                } else {
                    0
                },
                "{iter}"
            );
        }
    }
}

mod bandwidth;
mod bytes_in_flight;
mod congestion;
mod gcongestion;
mod rtt;
