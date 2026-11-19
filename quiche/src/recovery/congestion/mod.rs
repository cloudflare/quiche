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

use std::cmp;
use std::time::Instant;

use self::recovery::Acked;
use super::bandwidth::Bandwidth;
use super::RecoveryConfig;
use super::Sent;
use crate::recovery::rtt;
use crate::recovery::rtt::RttStats;
use crate::recovery::CongestionControlAlgorithm;
use crate::recovery::RateLimitedIncrease;
use crate::StartupExit;
use crate::StartupExitReason;

pub struct SsThresh {
    // Current slow start threshold.  Defaults to usize::MAX which
    // indicates we're still in the initial slow start phase.
    ssthresh: usize,

    // Information about the slow start exit, if it already happened.
    // Set on the first call to update().
    startup_exit: Option<StartupExit>,
}

impl Default for SsThresh {
    fn default() -> Self {
        Self {
            ssthresh: usize::MAX,
            startup_exit: None,
        }
    }
}

impl SsThresh {
    fn get(&self) -> usize {
        self.ssthresh
    }

    fn startup_exit(&self) -> Option<StartupExit> {
        self.startup_exit
    }

    fn update(&mut self, ssthresh: usize, in_css: bool) {
        if self.startup_exit.is_none() {
            let reason = if in_css {
                // Exit happened in conservative slow start, attribute
                // the exit to CSS.
                StartupExitReason::ConservativeSlowStartRounds
            } else {
                // In normal slow start, attribute the exit to loss.
                StartupExitReason::Loss
            };
            self.startup_exit = Some(StartupExit::new(ssthresh, None, reason));
        }
        self.ssthresh = ssthresh;
    }
}

pub struct Congestion {
    // Congestion control.
    pub(crate) cc_ops: &'static CongestionControlOps,

    cubic_state: cubic::State,

    // HyStart++.
    pub(crate) hystart: hystart::Hystart,

    // RFC6937 PRR.
    pub(crate) prr: prr::PRR,

    // The maximum size of a data aggregate scheduled and
    // transmitted together.
    send_quantum: usize,

    pub(crate) congestion_window: usize,

    pub(crate) ssthresh: SsThresh,

    bytes_acked_sl: usize,

    bytes_acked_ca: usize,

    pub(crate) congestion_recovery_start_time: Option<Instant>,

    pub(crate) app_limited: bool,

    pub(crate) delivery_rate: delivery_rate::Rate,

    /// Initial congestion window size in terms of packet count.
    pub(crate) initial_congestion_window_packets: usize,

    #[cfg(feature = "congestion_window_unchecked_available")]
    /// Fixed congestion window in bytes for the unchecked controller.
    pub(crate) unchecked_congestion_window: usize,

    max_datagram_size: usize,

    pub(crate) lost_count: usize,

    pub(crate) enable_cubic_idle_restart_fix: bool,

    pub(crate) rate_limited_increase: RateLimitedIncrease,

    /// Largest FlightSize observed since the last cwnd reduction (maxFS in
    /// draft-ietf-ccwg-ratelimited-increase).
    max_fs: usize,
}

impl Congestion {
    pub(crate) fn from_config(recovery_config: &RecoveryConfig) -> Self {
        let initial_congestion_window = recovery_config.max_send_udp_payload_size *
            recovery_config.initial_congestion_window_packets;

        let mut cc = Congestion {
            congestion_window: initial_congestion_window,

            ssthresh: Default::default(),

            bytes_acked_sl: 0,

            bytes_acked_ca: 0,

            congestion_recovery_start_time: None,

            cc_ops: recovery_config.cc_algorithm.into(),

            cubic_state: cubic::State::default(),

            app_limited: false,

            lost_count: 0,

            initial_congestion_window_packets: recovery_config
                .initial_congestion_window_packets,
            #[cfg(feature = "congestion_window_unchecked_available")]
            unchecked_congestion_window: recovery_config
                .unchecked_congestion_window,

            max_datagram_size: recovery_config.max_send_udp_payload_size,

            send_quantum: initial_congestion_window,

            delivery_rate: delivery_rate::Rate::default(),

            hystart: hystart::Hystart::new(recovery_config.hystart),

            prr: prr::PRR::default(),

            enable_cubic_idle_restart_fix: recovery_config
                .enable_cubic_idle_restart_fix,

            rate_limited_increase: recovery_config.rate_limited_increase,

            max_fs: initial_congestion_window,
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

    /// The most recent data delivery rate estimate.
    pub(crate) fn delivery_rate(&self) -> Bandwidth {
        self.delivery_rate.sample_delivery_rate()
    }

    pub(crate) fn send_quantum(&self) -> usize {
        self.send_quantum
    }

    pub(crate) fn congestion_window(&self) -> usize {
        self.congestion_window
    }

    fn update_app_limited(&mut self, v: bool) {
        self.app_limited = v;
    }

    /// Returns true if Rate-Limited Increase is enabled and the sender is in
    /// traditional Slow Start (excluding HyStart++ Conservative Slow Start).
    ///
    /// This is the only condition under which Rate-Limited Increase changes
    /// behavior: when it is false, an app limited sender doesn't grow cwnd
    /// and [`Congestion::rate_limited_slow_start_cwnd()`] is a no-op.
    fn rate_limited_increase_applies(&self) -> bool {
        match self.rate_limited_increase {
            RateLimitedIncrease::Disabled => false,
            RateLimitedIncrease::SlowStart =>
                self.congestion_window < self.ssthresh.get() &&
                    !self.hystart.in_css(),
        }
    }

    /// Returns `new_cwnd` capped to limit(maxFS) = 2 * maxFS when
    /// [`Congestion::rate_limited_increase_applies()`]. The cap never reduces
    /// cwnd.
    fn rate_limited_slow_start_cwnd(&self, new_cwnd: usize) -> usize {
        if !self.rate_limited_increase_applies() {
            return new_cwnd;
        }

        let limit = self.max_fs.saturating_mul(2);

        cmp::max(self.congestion_window, cmp::min(new_cwnd, limit))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_packet_sent(
        &mut self, bytes_in_flight: usize, sent_bytes: usize, now: Instant,
        pkt: &mut Sent, bytes_lost: u64, in_flight: bool,
    ) {
        if in_flight {
            self.update_app_limited(
                (bytes_in_flight + sent_bytes) < self.congestion_window,
            );

            self.max_fs = cmp::max(self.max_fs, bytes_in_flight + sent_bytes);

            (self.cc_ops.on_packet_sent)(self, sent_bytes, bytes_in_flight, now);

            self.prr.on_packet_sent(sent_bytes);

            // HyStart++: Start of the round in a slow start.
            if self.hystart.enabled() &&
                self.congestion_window < self.ssthresh.get()
            {
                self.hystart.start_round(pkt.pkt_num);
            }
        }

        pkt.time_sent = now;

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
}

pub(crate) struct CongestionControlOps {
    pub on_init: fn(r: &mut Congestion),

    /// Updates controller state after the packet-size limit changes.
    pub on_mtu_update: fn(congestion: &mut Congestion),

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

    #[cfg(feature = "qlog")]
    pub state_str: fn(r: &Congestion, now: Instant) -> &'static str,

    pub debug_fmt: fn(
        r: &Congestion,
        formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result,
}

#[cfg(feature = "congestion_window_unchecked_available")]
static CONGESTION_WINDOW_UNCHECKED: CongestionControlOps = CongestionControlOps {
    on_init: reset_unchecked_congestion_window,
    on_mtu_update: reset_unchecked_congestion_window,
    on_packet_sent: |congestion, _, _, _| {
        reset_unchecked_congestion_window(congestion)
    },
    on_packets_acked: |congestion, _, _, _, _| {
        reset_unchecked_congestion_window(congestion)
    },
    congestion_event: |congestion, _, _, _, _| {
        reset_unchecked_congestion_window(congestion)
    },
    checkpoint: reset_unchecked_congestion_window,
    rollback: |congestion| {
        reset_unchecked_congestion_window(congestion);
        true
    },
    #[cfg(feature = "qlog")]
    state_str: |_, _| "congestion_window_unchecked",
    debug_fmt: |_, _| Ok(()),
};

#[cfg(feature = "congestion_window_unchecked_available")]
fn reset_unchecked_congestion_window(congestion: &mut Congestion) {
    congestion.congestion_window = congestion.unchecked_congestion_window;
}

impl From<CongestionControlAlgorithm> for &'static CongestionControlOps {
    fn from(algo: CongestionControlAlgorithm) -> Self {
        match algo {
            CongestionControlAlgorithm::Reno => &reno::RENO,
            CongestionControlAlgorithm::CUBIC => &cubic::CUBIC,
            // Bbr2Gcongestion is routed to the congestion implementation in
            // the gcongestion directory by Recovery::new_with_config;
            // LegacyRecovery never gets a RecoveryConfig with the
            // Bbr2Gcongestion algorithm.
            CongestionControlAlgorithm::Bbr2Gcongestion => unreachable!(),
            #[cfg(feature = "congestion_window_unchecked_available")]
            CongestionControlAlgorithm::CongestionWindowUnchecked =>
                &CONGESTION_WINDOW_UNCHECKED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "congestion_window_unchecked_available")]
    use crate::test_utils;
    #[cfg(feature = "congestion_window_unchecked_available")]
    use crate::Config;
    #[cfg(feature = "congestion_window_unchecked_available")]
    use rstest::rstest;
    #[cfg(feature = "congestion_window_unchecked_available")]
    use std::time::Duration;

    #[cfg(feature = "congestion_window_unchecked_available")]
    #[rstest]
    fn unchecked_window_is_restored_by_callbacks(
        #[values(usize::MAX, 40 * 1024 * 1024)] window: usize,
    ) {
        let mut config = Config::new(crate::PROTOCOL_VERSION)
            .expect("create transport configuration");
        config.set_cc_algorithm(
            CongestionControlAlgorithm::CongestionWindowUnchecked,
        );
        config.set_unchecked_congestion_window(window);
        let mut congestion =
            Congestion::from_config(&RecoveryConfig::from_config(&config));
        assert_eq!(congestion.congestion_window(), window);

        let callbacks: [fn(&mut Congestion); 5] = [
            |congestion| {
                (congestion.cc_ops.on_packet_sent)(
                    congestion,
                    1_200,
                    0,
                    Instant::now(),
                );
            },
            |congestion| {
                (congestion.cc_ops.on_packets_acked)(
                    congestion,
                    0,
                    &mut Vec::new(),
                    Instant::now(),
                    &RttStats::new(
                        Duration::from_millis(100),
                        Duration::from_millis(25),
                    ),
                );
            },
            |congestion| {
                let now = Instant::now();
                let packet = test_utils::helper_packet_sent(0, now, 1_200);
                (congestion.cc_ops.congestion_event)(
                    congestion, 1_200, 1_200, &packet, now,
                );
            },
            |congestion| (congestion.cc_ops.checkpoint)(congestion),
            |congestion| {
                assert!((congestion.cc_ops.rollback)(congestion));
            },
        ];

        for callback in callbacks {
            congestion.congestion_window = 0;
            callback(&mut congestion);
            assert_eq!(congestion.congestion_window(), window);
        }
    }

    #[test]
    fn ssthresh_init() {
        let ssthresh: SsThresh = Default::default();
        assert_eq!(ssthresh.get(), usize::MAX);
        assert_eq!(ssthresh.startup_exit(), None);
    }

    #[test]
    fn ssthresh_in_css() {
        let expected_startup_exit = StartupExit::new(
            1000,
            None,
            StartupExitReason::ConservativeSlowStartRounds,
        );
        let mut ssthresh: SsThresh = Default::default();
        ssthresh.update(1000, true);
        assert_eq!(ssthresh.get(), 1000);
        assert_eq!(ssthresh.startup_exit(), Some(expected_startup_exit));

        ssthresh.update(2000, true);
        assert_eq!(ssthresh.get(), 2000);
        // startup_exit is only updated on the first update.
        assert_eq!(ssthresh.startup_exit(), Some(expected_startup_exit));

        ssthresh.update(500, false);
        assert_eq!(ssthresh.get(), 500);
        assert_eq!(ssthresh.startup_exit(), Some(expected_startup_exit));
    }

    #[test]
    fn ssthresh_in_slow_start() {
        let expected_startup_exit =
            StartupExit::new(1000, None, StartupExitReason::Loss);
        let mut ssthresh: SsThresh = Default::default();
        ssthresh.update(1000, false);
        assert_eq!(ssthresh.get(), 1000);
        assert_eq!(ssthresh.startup_exit(), Some(expected_startup_exit));

        ssthresh.update(2000, true);
        assert_eq!(ssthresh.get(), 2000);
        // startup_exit is only updated on the first update.
        assert_eq!(ssthresh.startup_exit(), Some(expected_startup_exit));

        ssthresh.update(500, false);
        assert_eq!(ssthresh.get(), 500);
        assert_eq!(ssthresh.startup_exit(), Some(expected_startup_exit));
    }
}

#[cfg(test)]
mod rate_limited_increase_tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::test_sender::TestSender;
    use crate::CongestionControlAlgorithm;
    use crate::RateLimitedIncrease;

    const RTT: Duration = Duration::from_millis(100);

    /// A `Disabled` and a `SlowStart` sender driven through the same events.
    struct Pair {
        disabled: TestSender,
        slow_start: TestSender,
    }

    impl Pair {
        fn new(algo: CongestionControlAlgorithm) -> Self {
            let sender = |mode| {
                let mut sender = TestSender::new(algo, true);
                sender.rate_limited_increase = mode;
                sender
            };

            Pair {
                disabled: sender(RateLimitedIncrease::Disabled),
                slow_start: sender(RateLimitedIncrease::SlowStart),
            }
        }

        fn for_each(&mut self, f: impl Fn(&mut TestSender)) {
            f(&mut self.disabled);
            f(&mut self.slow_start);
        }

        /// Sends `n(sender)` full-sized packets on each sender, advances time
        /// by one RTT and ACKs them.
        fn round(&mut self, n: impl Fn(&TestSender) -> usize) {
            self.for_each(|sender| {
                let size = sender.max_datagram_size;
                let n = n(sender);

                for _ in 0..n {
                    sender.send_packet(size);
                }

                sender.advance_time(RTT);
                sender.ack_n_packets(n, size);
            });
        }

        /// cwnd of the `Disabled` and `SlowStart` senders, in packets.
        fn cwnd(&self) -> (usize, usize) {
            (cwnd_packets(&self.disabled), cwnd_packets(&self.slow_start))
        }
    }

    fn cwnd_packets(sender: &TestSender) -> usize {
        sender.congestion_window / sender.max_datagram_size
    }

    /// Reproduces the example in Appendix A of
    /// draft-ietf-ccwg-ratelimited-increase. This is the only case where the
    /// two modes differ: a rate-limited sender in traditional Slow Start.
    #[rstest]
    fn slow_start(
        #[values(
            CongestionControlAlgorithm::Reno,
            CongestionControlAlgorithm::CUBIC
        )]
        algo: CongestionControlAlgorithm,
    ) {
        let mut pair = Pair::new(algo);
        assert_eq!(pair.cwnd(), (10, 10));

        // `SlowStart` grows cwnd up to 2 * maxFS = 20, `Disabled` doesn't.
        pair.round(|_| 4);
        assert_eq!(pair.cwnd(), (10, 14));

        pair.round(|_| 8);
        assert_eq!(pair.cwnd(), (10, 20));

        pair.round(|_| 4);
        assert_eq!(pair.cwnd(), (10, 20));

        // Once cwnd-limited, both double cwnd as usual.
        pair.round(cwnd_packets);
        assert_eq!(pair.cwnd(), (20, 40));
        assert_eq!(
            pair.slow_start.max_fs,
            pair.slow_start.congestion_window / 2
        );
    }

    /// Outside of rate-limited traditional Slow Start, a `SlowStart` sender
    /// behaves exactly like a `Disabled` one: in traditional Slow Start while
    /// cwnd-limited, and in HyStart++ Conservative Slow Start and congestion
    /// avoidance whether rate-limited or not.
    #[rstest]
    fn same_as_disabled_outside_rate_limited_slow_start(
        #[values(
            CongestionControlAlgorithm::Reno,
            CongestionControlAlgorithm::CUBIC
        )]
        algo: CongestionControlAlgorithm,
    ) {
        let mut pair = Pair::new(algo);

        let rate_limited = |sender: &TestSender| cwnd_packets(sender) / 2;

        // Traditional Slow Start, cwnd-limited.
        for _ in 0..2 {
            pair.round(cwnd_packets);
            assert_eq!(pair.cwnd().0, pair.cwnd().1);
        }

        // HyStart++ Conservative Slow Start.
        pair.for_each(|sender| {
            let now = sender.time;
            sender.hystart.enter_css_for_test(now);
        });

        for cwnd_limited in [false, true, false] {
            pair.round(if cwnd_limited {
                cwnd_packets
            } else {
                rate_limited
            });
            assert!(pair.slow_start.hystart.in_css());
            assert_eq!(pair.cwnd().0, pair.cwnd().1);
        }

        // A loss moves both senders to congestion avoidance.
        pair.for_each(|sender| {
            let size = sender.max_datagram_size;

            sender.send_packet(size);
            sender.advance_time(RTT);
            sender.lose_n_packets(1, size, None);
            sender.advance_time(RTT);
        });

        assert_eq!(pair.cwnd().0, pair.cwnd().1);
        assert_eq!(pair.slow_start.max_fs, 0);

        let post_loss_cwnd = pair.cwnd().1;

        // Congestion avoidance.
        for i in 0..40 {
            let cwnd_limited = i % 2 == 1;

            pair.round(if cwnd_limited {
                cwnd_packets
            } else {
                rate_limited
            });
            assert!(
                pair.slow_start.congestion_window >=
                    pair.slow_start.ssthresh.get()
            );
            assert_eq!(pair.cwnd().0, pair.cwnd().1);
        }

        assert!(pair.cwnd().1 > post_loss_cwnd);
    }
}

mod cubic;
mod delivery_rate;
mod hystart;
mod prr;
pub(crate) mod recovery;
mod reno;

#[cfg(test)]
mod test_sender;
