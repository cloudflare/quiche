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
use crate::Config;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use smallvec::SmallVec;

mod congestion;
mod rtt;

pub use self::congestion::recovery::Recovery;

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
                    write!(f, "timer={d:?} ")
                } else {
                    write!(f, "timer=exp ")
                }
            },
            None => write!(f, "timer=none "),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecoveryConfig {
    pub max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    pub cc_algorithm: CongestionControlAlgorithm,
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
            hystart: config.hystart,
            pacing: config.pacing,
            max_pacing_rate: config.max_pacing_rate,
            initial_congestion_window_packets: config
                .initial_congestion_window_packets,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet;
    use crate::ranges;
    use crate::recovery::congestion::PACING_MULTIPLIER;
    use crate::CongestionControlAlgorithm;
    use smallvec::smallvec;
    use std::str::FromStr;

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
        let pacing_rate = (r.cwnd() as f64 * PACING_MULTIPLIER / 0.05) as u64;
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
