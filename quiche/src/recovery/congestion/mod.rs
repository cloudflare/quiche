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

use std::str::FromStr;
use std::time::Instant;

use super::rtt::RttStats;
use super::Acked;
use super::RecoveryConfig;
use super::Sent;

pub const PACING_MULTIPLIER: f64 = 1.25;
pub struct Congestion {
    // Congestion control.
    pub(crate) cc_ops: &'static CongestionControlOps,

    cubic_state: cubic::State,

    // HyStart++.
    pub(crate) hystart: hystart::Hystart,

    // Pacing.
    pub(crate) pacer: pacer::Pacer,

    // RFC6937 PRR.
    pub(crate) prr: prr::PRR,

    // The maximum size of a data aggregate scheduled and
    // transmitted together.
    send_quantum: usize,

    // BBR state.
    bbr_state: bbr::State,

    // BBRv2 state.
    bbr2_state: bbr2::State,

    pub(crate) congestion_window: usize,

    pub(crate) ssthresh: usize,

    bytes_acked_sl: usize,

    bytes_acked_ca: usize,

    pub(crate) congestion_recovery_start_time: Option<Instant>,

    pub(crate) app_limited: bool,

    pub(crate) delivery_rate: delivery_rate::Rate,

    /// Initial congestion window size in terms of packet count.
    pub(crate) initial_congestion_window_packets: usize,

    max_datagram_size: usize,

    pub(crate) lost_count: usize,
}

impl Congestion {
    pub(crate) fn from_config(recovery_config: &RecoveryConfig) -> Self {
        let initial_congestion_window = recovery_config.max_send_udp_payload_size *
            recovery_config.initial_congestion_window_packets;

        let mut cc = Congestion {
            congestion_window: initial_congestion_window,

            ssthresh: usize::MAX,

            bytes_acked_sl: 0,

            bytes_acked_ca: 0,

            congestion_recovery_start_time: None,

            cc_ops: recovery_config.cc_algorithm.into(),

            cubic_state: cubic::State::default(),

            app_limited: false,

            lost_count: 0,

            initial_congestion_window_packets: recovery_config
                .initial_congestion_window_packets,

            max_datagram_size: recovery_config.max_send_udp_payload_size,

            send_quantum: initial_congestion_window,

            delivery_rate: delivery_rate::Rate::default(),

            hystart: hystart::Hystart::new(recovery_config.hystart),

            pacer: pacer::Pacer::new(
                recovery_config.pacing,
                initial_congestion_window,
                0,
                recovery_config.max_send_udp_payload_size,
                recovery_config.max_pacing_rate,
            ),

            prr: prr::PRR::default(),

            bbr_state: bbr::State::new(),

            bbr2_state: bbr2::State::new(),
        };

        (cc.cc_ops.on_init)(&mut cc);

        cc
    }

    pub(crate) fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(congestion_recovery_start_time) =>
                sent_time <= congestion_recovery_start_time,

            None => false,
        }
    }

    pub(crate) fn delivery_rate(&self) -> u64 {
        self.delivery_rate.sample_delivery_rate()
    }

    pub(crate) fn send_quantum(&self) -> usize {
        self.send_quantum
    }

    pub(crate) fn set_pacing_rate(&mut self, rate: u64, now: Instant) {
        self.pacer.update(self.send_quantum, rate, now);
    }

    pub(crate) fn congestion_window(&self) -> usize {
        self.congestion_window
    }

    fn update_app_limited(&mut self, v: bool) {
        self.app_limited = v;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_packet_sent(
        &mut self, bytes_in_flight: usize, sent_bytes: usize, now: Instant,
        pkt: &mut Sent, rtt_stats: &RttStats, bytes_lost: u64, in_flight: bool,
    ) {
        if in_flight {
            self.update_app_limited(
                (bytes_in_flight + sent_bytes) < self.congestion_window,
            );

            (self.cc_ops.on_packet_sent)(self, sent_bytes, bytes_in_flight, now);

            self.prr.on_packet_sent(sent_bytes);

            // HyStart++: Start of the round in a slow start.
            if self.hystart.enabled() && self.congestion_window < self.ssthresh {
                self.hystart.start_round(pkt.pkt_num);
            }
        }

        // Pacing: Set the pacing rate if CC doesn't do its own.
        if !(self.cc_ops.has_custom_pacing)() &&
            rtt_stats.first_rtt_sample.is_some()
        {
            let rate = PACING_MULTIPLIER * self.congestion_window as f64 /
                rtt_stats.smoothed_rtt.as_secs_f64();
            self.set_pacing_rate(rate as u64, now);
        }

        self.schedule_next_packet(now, sent_bytes);

        pkt.time_sent = self.get_packet_send_time();

        // bytes_in_flight is already updated. Use previous value.
        self.delivery_rate
            .on_packet_sent(pkt, bytes_in_flight, bytes_lost);
    }

    pub(crate) fn on_packets_acked(
        &mut self, bytes_in_flight: usize, acked: &mut Vec<Acked>,
        rtt_stats: &RttStats, now: Instant,
    ) {
        // Update delivery rate sample per acked packet.
        for pkt in acked.iter() {
            self.delivery_rate.update_rate_sample(pkt, now);
        }

        // Fill in a rate sample.
        self.delivery_rate.generate_rate_sample(*rtt_stats.min_rtt);

        // Call congestion control hooks.
        (self.cc_ops.on_packets_acked)(
            self,
            bytes_in_flight,
            acked,
            now,
            rtt_stats,
        );
    }

    fn schedule_next_packet(&mut self, now: Instant, packet_size: usize) {
        // Don't pace in any of these cases:
        //   * Packet contains no data.
        //   * The congestion window is within initcwnd.

        let in_initcwnd = self.congestion_window <
            self.max_datagram_size * self.initial_congestion_window_packets;

        let sent_bytes = if !self.pacer.enabled() || in_initcwnd {
            0
        } else {
            packet_size
        };

        self.pacer.send(sent_bytes, now);
    }

    pub(crate) fn get_packet_send_time(&self) -> Instant {
        self.pacer.next_time()
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

pub(crate) struct CongestionControlOps {
    pub on_init: fn(r: &mut Congestion),

    pub on_packet_sent: fn(
        r: &mut Congestion,
        sent_bytes: usize,
        bytes_in_flight: usize,
        now: Instant,
    ),

    pub on_packets_acked: fn(
        r: &mut Congestion,
        bytes_in_flight: usize,
        packets: &mut Vec<Acked>,
        now: Instant,
        rtt_stats: &RttStats,
    ),

    pub congestion_event: fn(
        r: &mut Congestion,
        bytes_in_flight: usize,
        lost_bytes: usize,
        largest_lost_packet: &Sent,
        now: Instant,
    ),

    pub checkpoint: fn(r: &mut Congestion),

    pub rollback: fn(r: &mut Congestion) -> bool,

    pub has_custom_pacing: fn() -> bool,

    pub debug_fmt: fn(
        r: &Congestion,
        formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result,
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

mod bbr;
mod bbr2;
mod cubic;
mod delivery_rate;
mod hystart;
pub(crate) mod pacer;
mod prr;
mod reno;

#[cfg(test)]
mod test_sender;
