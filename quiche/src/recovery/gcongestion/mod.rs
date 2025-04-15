// Copyright (C) 2024, Cloudflare, Inc.
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

pub mod bandwidth;
mod bbr;
mod bbr2;
pub mod pacer;
mod recovery;

use std::fmt::Debug;
use std::str::FromStr;
use std::time::Instant;

use self::bandwidth::Bandwidth;
pub use self::recovery::GRecovery;

use crate::recovery::rtt::RttStats;
use crate::recovery::rtt::INITIAL_RTT;
use crate::recovery::RecoveryConfig;

#[derive(Debug)]
pub struct Lost {
    pub(super) packet_number: u64,
    pub(super) bytes_lost: usize,
}

#[derive(Debug)]
pub struct Acked {
    pub(super) pkt_num: u64,
    pub(super) time_sent: Instant,
}

#[enum_dispatch::enum_dispatch(CongestionControl)]
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Congestion {
    BBRv2(bbr2::BBRv2),
}

impl Congestion {
    pub(super) fn bbrv2(
        initial_tcp_congestion_window: usize, max_congestion_window: usize,
        recovery_config: &RecoveryConfig,
    ) -> Self {
        Congestion::BBRv2(bbr2::BBRv2::new(
            initial_tcp_congestion_window,
            max_congestion_window,
            recovery_config.max_send_udp_payload_size,
            INITIAL_RTT,
            recovery_config.custom_bbr_params.as_ref(),
        ))
    }
}

#[enum_dispatch::enum_dispatch]
pub(super) trait CongestionControl: Debug {
    /// Returns the size of the current congestion window in bytes. Note, this
    /// is not the *available* window. Some send algorithms may not use a
    /// congestion window and will return 0.
    fn get_congestion_window(&self) -> usize;

    /// Returns the size of the current congestion window in packets. Note, this
    /// is not the *available* window. Some send algorithms may not use a
    /// congestion window and will return 0.
    fn get_congestion_window_in_packets(&self) -> usize;

    /// Make decision on whether the sender can send right now.  Note that even
    /// when this method returns true, the sending can be delayed due to pacing.
    fn can_send(&self, bytes_in_flight: usize) -> bool;

    /// Inform that we sent `bytes` to the wire, and if the packet is
    /// retransmittable. `bytes_in_flight` is the number of bytes in flight
    /// before the packet was sent. Note: this function must be called for
    /// every packet sent to the wire.
    fn on_packet_sent(
        &mut self, sent_time: Instant, bytes_in_flight: usize,
        packet_number: u64, bytes: usize, is_retransmissible: bool,
        rtt_stats: &RttStats,
    );

    /// Inform that `packet_number` has been neutered.
    fn on_packet_neutered(&mut self, _packet_number: u64) {}

    /// Indicates an update to the congestion state, caused either by an
    /// incoming ack or loss event timeout. `rtt_updated` indicates whether a
    /// new `latest_rtt` sample has been taken, `prior_in_flight` the bytes in
    /// flight prior to the congestion event. `acked_packets` and `lost_packets`
    /// are any packets considered acked or lost as a result of the
    /// congestion event.
    #[allow(clippy::too_many_arguments)]
    fn on_congestion_event(
        &mut self, rtt_updated: bool, prior_in_flight: usize,
        bytes_in_flight: usize, event_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], least_unacked: u64, rtt_stats: &RttStats,
    );

    /// Called when an RTO fires.  Resets the retransmission alarm if there are
    /// remaining unacked packets.
    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool);

    /// Called when connection migrates and cwnd needs to be reset.
    #[allow(dead_code)]
    fn on_connection_migration(&mut self);

    /// Adjust the current cwnd to a new maximal size
    fn limit_cwnd(&mut self, _max_cwnd: usize) {}

    fn is_in_recovery(&self) -> bool;

    #[allow(dead_code)]
    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool;

    #[cfg(test)]
    fn is_app_limited(&self, bytes_in_flight: usize) -> bool {
        !self.is_cwnd_limited(bytes_in_flight)
    }

    fn pacing_rate(
        &self, bytes_in_flight: usize, rtt_stats: &RttStats,
    ) -> Bandwidth;

    fn bandwidth_estimate(&self, rtt_stats: &RttStats) -> Bandwidth;

    fn update_mss(&mut self, new_mss: usize);

    fn on_app_limited(&mut self, _bytes_in_flight: usize) {}

    #[cfg(feature = "qlog")]
    fn ssthresh(&self) -> Option<u64> {
        None
    }
}

/// BBR settings used to customize the algorithm's behavior.
///
/// This functionality is experimental and will be removed in the future.
///
/// A congestion control algorithm has dual-responsibility of effective network
/// utilization and avoiding congestion. Custom values should be choosen
/// carefully since incorrect values can lead to network degradation for all
/// connections on the shared network.
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[repr(C)]
#[doc(hidden)]
pub struct BbrParams {
    /// Control Bbr startup gain.
    pub startup_cwnd_gain: Option<f32>,

    /// Control Bbr startup pacing gain.
    pub startup_pacing_gain: Option<f32>,

    /// Control Bbr full bandwidth threshold.
    pub full_bw_threshold: Option<f32>,

    /// Control Bbr startup loss count necessary to exit startup.
    pub startup_full_loss_count: Option<usize>,

    /// Control Bbr drain cwnd gain.
    pub drain_cwnd_gain: Option<f32>,

    /// Control Bbr drain pacing gain.
    pub drain_pacing_gain: Option<f32>,

    /// Control if Bbr should respect reno coexistence.
    pub enable_reno_coexistence: Option<bool>,

    /// Control Bbr bandwidth probe up pacing gain.
    pub probe_bw_probe_up_pacing_gain: Option<f32>,

    /// Control Bbr bandwidth probe down pacing gain.
    pub probe_bw_probe_down_pacing_gain: Option<f32>,

    /// Control Bbr probe bandwidth cwnd gain.
    pub probe_bw_cwnd_gain: Option<f32>,

    /// Control number of rounds Bbr should stay in probe up if bytes_in_flight
    /// doesn't drop below target.
    pub max_probe_up_queue_rounds: Option<usize>,

    /// Control Bbr loss threshold.
    pub loss_threshold: Option<f32>,

    /// Control if Bbr should use bytes delievered as an estimate for
    /// inflight_hi.
    pub use_bytes_delivered_for_inflight_hi: Option<bool>,

    /// Control if Bbr should adjust startup pacing at round end.
    pub decrease_startup_pacing_at_end_of_round: Option<bool>,

    /// Control Bbr bandwidth lo reduction strategy.
    pub bw_lo_reduction_strategy: Option<BbrBwLoReductionStrategy>,
}

/// Controls BBR's bandwidth reduction strategy on congestion event.
///
/// This functionality is experimental and will be removed in the future.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
#[doc(hidden)]
pub enum BbrBwLoReductionStrategy {
    /// Uses the default strategy based on `BBRBeta`.
    Default           = 0,

    /// Considers min-rtt to estimate bandwidth reduction.
    MinRttReduction   = 1,

    /// Considers inflight data to estimate bandwidth reduction.
    InflightReduction = 2,

    /// Considers cwnd to estimate bandwidth reduction.
    CwndReduction     = 3,
}

#[doc(hidden)]
impl FromStr for BbrBwLoReductionStrategy {
    type Err = crate::Error;

    /// Converts a string to `BbrBwLoReductionStrategy`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "default" => Ok(BbrBwLoReductionStrategy::Default),
            "minrtt" => Ok(BbrBwLoReductionStrategy::MinRttReduction),
            "inflight" => Ok(BbrBwLoReductionStrategy::InflightReduction),
            "cwnd" => Ok(BbrBwLoReductionStrategy::CwndReduction),

            _ => Err(crate::Error::CongestionControl),
        }
    }
}
