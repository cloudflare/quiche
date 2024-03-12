// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright (C) 2023, Cloudflare, Inc.
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

mod cubic_bytes;
mod hybrid_slow_start;
mod prr;

use std::time::Duration;
use std::time::Instant;

use cubic_bytes::CubicBytes;
use hybrid_slow_start::HybridSlowStart;
use prr::PrrSender;

use super::Acked;
use super::Bandwidth;
use super::Lost;
use super::RttStats;

use super::CongestionControl;

const DEFAULT_NUM_CONNECTIONS: usize = 2;

const RENO_BETA: f32 = 0.7; // Reno backoff factor.

#[derive(Debug)]
pub(crate) struct Cubic {
    largest_sent_packet_number: Option<u64>,
    congestion_window: usize,
    max_congestion_window: usize,
    initial_tcp_congestion_window: usize,
    initial_max_tcp_congestion_window: usize,
    min_slow_start_exit_window: usize,
    min_congestion_window: usize,
    slow_start_threshold: usize,
    mss: usize,

    largest_acked_packet_number: Option<u64>,
    largest_sent_at_last_cutback: Option<u64>,
    num_acked_packets: usize,
    num_connections: usize,
    last_cutback_exited_slowstart: bool,
    slow_start_large_reduction: bool,

    prr: PrrSender,
    hybrid_slow_start: HybridSlowStart,
    cubic: CubicBytes,

    reno: bool,
}

impl Cubic {
    pub(crate) fn new(
        initial_tcp_congestion_window: usize, max_congestion_window: usize,
        max_segment_size: usize, reno: bool,
    ) -> Self {
        Cubic {
            largest_sent_packet_number: None,
            initial_tcp_congestion_window: initial_tcp_congestion_window *
                max_segment_size,
            initial_max_tcp_congestion_window: max_congestion_window *
                max_segment_size,
            congestion_window: initial_tcp_congestion_window * max_segment_size,
            max_congestion_window: max_congestion_window * max_segment_size,
            slow_start_threshold: max_congestion_window * max_segment_size,
            min_slow_start_exit_window: 2 * max_segment_size,
            min_congestion_window: 2 * max_segment_size,
            mss: max_segment_size,
            largest_acked_packet_number: None,
            largest_sent_at_last_cutback: None,
            last_cutback_exited_slowstart: false,
            slow_start_large_reduction: false,
            num_acked_packets: 0,
            num_connections: DEFAULT_NUM_CONNECTIONS * 2,
            prr: PrrSender::new(max_segment_size),
            hybrid_slow_start: HybridSlowStart::default(),
            cubic: CubicBytes::new(max_segment_size),
            reno,
        }
    }

    fn reno_beta(&self) -> f32 {
        // kNConnectionBeta is the backoff factor after loss for our N-connection
        // emulation, which emulates the effective backoff of an ensemble of N
        // TCP-Reno connections on a single loss event. The effective multiplier
        // is computed as:
        let num_connections = self.num_connections as f32;
        (num_connections - 1. + RENO_BETA) / num_connections
    }

    fn get_slow_start_threshold(&self) -> usize {
        self.slow_start_threshold
    }

    fn is_in_slow_start(&self) -> bool {
        self.get_congestion_window() < self.get_slow_start_threshold()
    }

    // Called when we receive an ack. Normal TCP tracks how many packets one ack
    // represents, but quic has a separate ack for each packet.
    fn maybe_increase_cwnd(
        &mut self, _acked_packet_number: u64, acked_bytes: usize,
        prior_in_flight: usize, event_time: Instant, min_rtt: Duration,
    ) {
        // Do not increase the congestion window unless the sender is close to
        // using the current window.
        if !self.is_cwnd_limited(prior_in_flight) {
            self.cubic.on_app_limited();
            return;
        }

        if self.congestion_window >= self.max_congestion_window {
            return;
        }

        if self.is_in_slow_start() {
            // TCP slow start, exponential growth, increase by one for each ACK.
            self.congestion_window += self.mss;
            return;
        }

        // Congestion avoidance.
        if self.reno {
            // Classic Reno congestion avoidance.
            self.num_acked_packets += 1;
            // Divide by num_connections to smoothly increase the CWND at a faster
            // rate than conventional Reno.
            if self.num_acked_packets * self.num_connections >=
                self.congestion_window / self.mss
            {
                self.congestion_window += self.mss;
                self.num_acked_packets = 0;
            }
        } else {
            self.congestion_window = self.max_congestion_window.min(
                self.cubic.congestion_window_after_ack(
                    acked_bytes,
                    self.congestion_window,
                    min_rtt,
                    event_time,
                ),
            )
        }
    }

    fn exit_slow_start(&mut self) {
        self.slow_start_threshold = self.congestion_window;
    }

    fn on_packet_lost(
        &mut self, packet_number: u64, bytes_lost: usize, prior_in_flight: usize,
    ) {
        // TCP NewReno (RFC6582) says that once a loss occurs, any losses in
        // packets already sent should be treated as a single loss event,
        // since it's expected.
        match self.largest_sent_at_last_cutback {
            Some(largest_sent_at_last_cutback)
                if packet_number <= largest_sent_at_last_cutback =>
            {
                if self.last_cutback_exited_slowstart &&
                    self.slow_start_large_reduction
                {
                    self.congestion_window = self
                        .min_slow_start_exit_window
                        .max(self.congestion_window - bytes_lost);
                    self.slow_start_threshold = self.congestion_window;
                }
                return;
            },
            _ => {},
        }

        self.last_cutback_exited_slowstart = self.is_in_slow_start();
        self.prr.on_packet_lost(prior_in_flight);

        if self.slow_start_large_reduction && self.is_in_slow_start() {
            assert!(self.mss < self.congestion_window);
            if self.congestion_window >= 2 * self.initial_tcp_congestion_window {
                self.min_slow_start_exit_window = self.congestion_window / 2;
            }
            self.congestion_window -= self.mss;
        } else if self.reno {
            self.congestion_window =
                (self.congestion_window as f32 * self.reno_beta()) as usize;
        } else {
            self.congestion_window = self
                .cubic
                .congestion_window_after_loss(self.congestion_window);
        }
        if self.congestion_window < self.min_congestion_window {
            self.congestion_window = self.min_congestion_window;
        }

        self.slow_start_threshold = self.congestion_window;

        self.largest_sent_at_last_cutback = self.largest_sent_packet_number;
        // Reset packet count from congestion avoidance mode. We start counting
        // again when we're out of recovery.
        self.num_acked_packets = 0;
    }

    fn handle_retransmission_timeout(&mut self) {
        self.cubic.reset();
        self.slow_start_threshold = self.congestion_window / 2;
        self.congestion_window = self.min_congestion_window;
    }

    fn on_packet_acked(
        &mut self, acked_packet_number: u64, acked_bytes: usize,
        prior_in_flight: usize, event_time: Instant, min_rtt: Duration,
    ) {
        self.largest_acked_packet_number = Some(
            self.largest_acked_packet_number
                .unwrap_or_default()
                .max(acked_packet_number),
        );

        if self.is_in_recovery() {
            self.prr.on_packet_acked(acked_bytes);
            return;
        }

        self.maybe_increase_cwnd(
            acked_packet_number,
            acked_bytes,
            prior_in_flight,
            event_time,
            min_rtt,
        );

        if self.is_in_slow_start() {
            self.hybrid_slow_start.on_packet_acked(acked_packet_number);
        }
    }
}

impl CongestionControl for Cubic {
    fn get_congestion_window(&self) -> usize {
        self.congestion_window
    }

    fn get_congestion_window_in_packets(&self) -> usize {
        self.congestion_window / self.mss
    }

    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool {
        let congestion_window = self.get_congestion_window();
        if bytes_in_flight >= congestion_window {
            return true;
        }
        let available_bytes = congestion_window - bytes_in_flight;
        let slow_start_limited =
            self.is_in_slow_start() && bytes_in_flight > congestion_window / 2;
        slow_start_limited || available_bytes <= self.mss * 3
    }

    fn is_in_recovery(&self) -> bool {
        if let (
            Some(largest_acked_packet_number),
            Some(largest_sent_at_last_cutback),
        ) = (
            self.largest_acked_packet_number,
            self.largest_sent_at_last_cutback,
        ) {
            return largest_acked_packet_number <= largest_sent_at_last_cutback;
        }

        false
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        if self.is_in_recovery() {
            // PRR is used when in recovery.
            return self.prr.can_send(
                self.get_congestion_window(),
                bytes_in_flight,
                self.get_slow_start_threshold(),
            );
        }

        self.get_congestion_window() > bytes_in_flight
    }

    fn on_packet_sent(
        &mut self, _sent_time: Instant, _bytes_in_flight: usize,
        packet_number: u64, bytes: usize, is_retransmissible: bool,
        _rtt_stats: &RttStats,
    ) {
        if !is_retransmissible {
            return;
        }

        if self.is_in_recovery() {
            // PRR is used when in recovery.
            self.prr.on_packet_sent(bytes);
        }

        self.largest_sent_packet_number = Some(packet_number);
        self.hybrid_slow_start.on_packet_sent(packet_number);
    }

    fn on_congestion_event(
        &mut self, rtt_updated: bool, prior_in_flight: usize,
        _bytes_in_flight: usize, event_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], _least_unacked: u64, rtt_stats: &RttStats,
    ) {
        if rtt_updated &&
            self.is_in_slow_start() &&
            self.hybrid_slow_start.should_exit_slow_start(
                rtt_stats.latest_rtt,
                *rtt_stats.min_rtt,
                self.get_congestion_window() / self.mss,
            )
        {
            self.exit_slow_start();
        }

        for lost in lost_packets {
            self.on_packet_lost(
                lost.packet_number,
                lost.bytes_lost,
                prior_in_flight,
            );
        }

        for acked in acked_packets {
            self.on_packet_acked(
                acked.pkt_num,
                acked.size,
                prior_in_flight,
                event_time,
                *rtt_stats.min_rtt,
            );
        }
    }

    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool) {
        self.largest_sent_at_last_cutback = None;
        if !packets_retransmitted {
            return;
        }
        self.hybrid_slow_start.restart();
        self.handle_retransmission_timeout();
    }

    fn on_connection_migration(&mut self) {
        self.hybrid_slow_start.restart();
        self.prr = PrrSender::new(self.mss);
        self.largest_acked_packet_number = None;
        self.largest_acked_packet_number = None;
        self.largest_sent_at_last_cutback = None;
        self.last_cutback_exited_slowstart = false;
        self.cubic.reset();
        self.num_acked_packets = 0;
        self.congestion_window = self.initial_tcp_congestion_window;
        self.max_congestion_window = self.initial_max_tcp_congestion_window;
        self.slow_start_threshold = self.initial_max_tcp_congestion_window;
    }

    fn update_mss(&mut self, new_mss: usize) {
        if self.mss == new_mss {
            return;
        }

        self.congestion_window = ((self.congestion_window as u64 *
            new_mss as u64) /
            self.mss as u64) as usize;
        self.min_congestion_window = ((self.min_congestion_window as u64 *
            new_mss as u64) /
            self.mss as u64) as usize;
        self.max_congestion_window = ((self.max_congestion_window as u64 *
            new_mss as u64) /
            self.mss as u64) as usize;
        self.initial_tcp_congestion_window =
            ((self.initial_tcp_congestion_window as u64 * new_mss as u64) /
                self.mss as u64) as usize;
        self.initial_max_tcp_congestion_window =
            ((self.initial_max_tcp_congestion_window as u64 * new_mss as u64) /
                self.mss as u64) as usize;
        self.min_slow_start_exit_window =
            ((self.min_slow_start_exit_window as u64 * new_mss as u64) /
                self.mss as u64) as usize;
        self.cubic.mss = new_mss;
        self.mss = new_mss;
    }

    fn pacing_rate(
        &self, _bytes_in_flight: usize, rtt_stats: &RttStats,
    ) -> Bandwidth {
        // We pace at twice the rate of the underlying sender's bandwidth estimate
        // during slow start and 1.25x during congestion avoidance to ensure
        // pacing doesn't prevent us from filling the window.
        let srtt = rtt_stats.smoothed_rtt;
        let bandwidth = Bandwidth::from_bytes_and_time_delta(
            self.get_congestion_window(),
            srtt,
        );
        bandwidth * if self.is_in_slow_start() { 2.0 } else { 1.25 }
    }

    fn bandwidth_estimate(&self, rtt_stats: &RttStats) -> Bandwidth {
        if rtt_stats.first_rtt_sample.is_none() {
            // If we haven't measured an rtt, the bandwidth estimate is unknown.
            Bandwidth::from_kbits_per_second(0)
        } else {
            Bandwidth::from_bytes_and_time_delta(
                self.get_congestion_window(),
                rtt_stats.smoothed_rtt,
            )
        }
    }

    fn limit_cwnd(&mut self, max_cwnd: usize) {
        self.congestion_window = self.congestion_window.min(max_cwnd);
    }

    #[cfg(feature = "qlog")]
    fn ssthresh(&self) -> Option<u64> {
        Some(self.slow_start_threshold as u64)
    }
}

#[cfg(test)]
mod tests {
    const MAX_SEGMENT_SIZE: usize = 1460;

    use super::*;

    const INITIAL_CONGESTION_WINDOW_PACKETS: usize = 10;
    const MAX_CONGESTION_WINDOW_PACKETS: usize = 200;
    const DEFAULT_WINDOW_TCP: usize =
        INITIAL_CONGESTION_WINDOW_PACKETS * MAX_SEGMENT_SIZE;

    struct TestSender {
        sender: Cubic,
        bytes_in_flight: usize,
        packet_number: u64,
        acked_packet_number: u64,
        clock: Instant,
        rtt_stats: RttStats,
    }

    impl TestSender {
        fn new(reno: bool) -> Self {
            TestSender {
                sender: Cubic::new(
                    INITIAL_CONGESTION_WINDOW_PACKETS,
                    MAX_CONGESTION_WINDOW_PACKETS,
                    MAX_SEGMENT_SIZE,
                    reno,
                ),
                bytes_in_flight: 0,
                packet_number: 1,
                acked_packet_number: 0,
                clock: Instant::now(),
                rtt_stats: RttStats::default(),
            }
        }

        fn send_available_send_window(&mut self, pkt_size: usize) -> usize {
            let mut packets_sent = 0;
            while self.can_send(self.bytes_in_flight) {
                self.sender.on_packet_sent(
                    self.clock,
                    self.bytes_in_flight,
                    self.packet_number,
                    pkt_size,
                    true,
                    &self.rtt_stats,
                );
                packets_sent += 1;
                self.bytes_in_flight += pkt_size;
                self.packet_number += 1;
            }
            packets_sent
        }

        fn lose_n_packets(&mut self, n: usize, pkt_size: usize) {
            let mut lost_packets = Vec::new();

            for _ in 0..n {
                self.acked_packet_number += 1;
                lost_packets.push(Lost {
                    packet_number: self.acked_packet_number,
                    bytes_lost: pkt_size,
                });
            }

            self.sender.on_congestion_event(
                false,
                self.bytes_in_flight,
                0,
                self.clock,
                &[],
                &lost_packets,
                0,
                &self.rtt_stats,
            );

            self.bytes_in_flight -= n * pkt_size;
        }

        fn lose_packet(&mut self, packet_number: u64) {
            self.sender.on_congestion_event(
                false,
                self.bytes_in_flight,
                0,
                self.clock,
                &[],
                &[Lost {
                    packet_number,
                    bytes_lost: MAX_SEGMENT_SIZE,
                }],
                0,
                &self.rtt_stats,
            );

            self.bytes_in_flight -= MAX_SEGMENT_SIZE;
        }

        // Normal is that TCP acks every other segment.
        fn ack_n_packets(&mut self, n: usize) {
            let latest_rtt = Duration::from_millis(60);
            self.rtt_stats.update_rtt(
                latest_rtt,
                Duration::ZERO,
                self.clock,
                false,
                Duration::ZERO,
            );

            let mut acked_packets = Vec::new();

            for _ in 0..n {
                self.acked_packet_number += 1;
                acked_packets.push(Acked {
                    pkt_num: self.acked_packet_number,
                    time_sent: self.clock,
                    size: MAX_SEGMENT_SIZE,
                });
            }

            self.sender.on_congestion_event(
                true,
                self.bytes_in_flight,
                0,
                self.clock,
                &acked_packets,
                &[],
                0,
                &self.rtt_stats,
            );

            self.bytes_in_flight =
                self.bytes_in_flight.wrapping_sub(n * MAX_SEGMENT_SIZE);
        }

        fn set_number_of_emulated_connection(&mut self, n: usize) {
            self.sender.num_connections = n;
            self.sender.cubic.num_connections = n;
        }
    }

    impl std::ops::Deref for TestSender {
        type Target = Cubic;

        fn deref(&self) -> &Self::Target {
            &self.sender
        }
    }

    impl std::ops::DerefMut for TestSender {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.sender
        }
    }

    #[test]
    fn simple_sender() {
        let mut sender = TestSender::new(true);
        // At startup make sure we are at the default.
        assert_eq!(DEFAULT_WINDOW_TCP, sender.get_congestion_window());
        // At startup make sure we can send.
        assert!(sender.can_send(0));
        // And that window is un-affected.
        assert_eq!(DEFAULT_WINDOW_TCP, sender.get_congestion_window());
        // Fill the send window with data, then verify that we can't send.
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        assert!(!sender.can_send(sender.get_congestion_window()));
    }

    #[test]
    fn application_limited_slow_start() {
        let mut sender = TestSender::new(true);
        let number_of_acks = 5;
        // At startup make sure we can send.
        assert!(sender.can_send(0));
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        for _ in 0..number_of_acks {
            sender.ack_n_packets(2);
        }
        let bytes_to_send = sender.get_congestion_window();
        // It's expected 2 acks will arrive when the bytes_in_flight are greater
        // than half the CWND.
        assert_eq!(DEFAULT_WINDOW_TCP + MAX_SEGMENT_SIZE * 2 * 2, bytes_to_send);
    }

    #[test]
    fn exponential_slow_start() {
        let mut sender = TestSender::new(true);
        let number_of_acks = 20;
        // At startup make sure we can send.
        assert!(sender.can_send(0));
        assert_eq!(
            Bandwidth::from_kbits_per_second(0),
            sender.bandwidth_estimate(&sender.rtt_stats)
        );
        for _ in 0..number_of_acks {
            // Send our full send window.
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        let cwnd = sender.get_congestion_window();
        assert_eq!(
            DEFAULT_WINDOW_TCP + MAX_SEGMENT_SIZE * 2 * number_of_acks,
            cwnd
        );
        assert_eq!(
            Bandwidth::from_bytes_and_time_delta(
                cwnd,
                sender.rtt_stats.smoothed_rtt
            ),
            sender.bandwidth_estimate(&sender.rtt_stats)
        );
    }

    #[test]
    fn slow_start_packet_loss() {
        let mut sender = TestSender::new(true);
        sender.set_number_of_emulated_connection(1);
        let number_of_acks = 10;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose a packet to exit slow start.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        let packets_in_recovery_window = expected_send_window / MAX_SEGMENT_SIZE;
        // We should now have fallen out of slow start with a reduced window.
        expected_send_window = (expected_send_window as f32 * RENO_BETA) as usize;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Recovery phase. We need to ack every packet in the recovery window
        // before we exit recovery.
        let number_of_packets_in_window = expected_send_window / MAX_SEGMENT_SIZE;
        sender.ack_n_packets(packets_in_recovery_window);
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // We need to ack an entire window before we increase CWND by 1.
        sender.ack_n_packets(number_of_packets_in_window - 2);
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Next ack should increase cwnd by 1.
        sender.ack_n_packets(1);
        expected_send_window += MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Now RTO and ensure slow start gets reset.
        assert!(sender.hybrid_slow_start.started);
        sender.on_retransmission_timeout(true);
        assert!(!sender.hybrid_slow_start.started);
    }

    #[test]
    fn slow_start_packet_loss_with_large_reduction() {
        let mut sender = TestSender::new(true);
        sender.slow_start_large_reduction = true;
        sender.set_number_of_emulated_connection(1);
        let number_of_acks = DEFAULT_WINDOW_TCP / (2 * MAX_SEGMENT_SIZE) - 1;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose a packet to exit slow start. We should now have fallen out of
        // slow start with a window reduced by 1.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        expected_send_window -= MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose 5 packets in recovery and verify that congestion window is reduced
        // further.
        sender.lose_n_packets(5, MAX_SEGMENT_SIZE);
        expected_send_window -= 5 * MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose another 10 packets and ensure it reduces below half the peak CWND,
        // because we never acked the full IW.
        sender.lose_n_packets(10, MAX_SEGMENT_SIZE);
        expected_send_window -= 10 * MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        let packets_in_recovery_window = expected_send_window / MAX_SEGMENT_SIZE;
        // Recovery phase. We need to ack every packet in the recovery window
        // before we exit recovery.
        let number_of_packets_in_window = expected_send_window / MAX_SEGMENT_SIZE;
        sender.ack_n_packets(packets_in_recovery_window);
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // We need to ack an entire window before we increase CWND by 1.
        sender.ack_n_packets(number_of_packets_in_window - 1);
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Next ack should increase cwnd by 1.
        sender.ack_n_packets(1);
        expected_send_window += MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Now RTO and ensure slow start gets reset.
        assert!(sender.hybrid_slow_start.started);
        sender.on_retransmission_timeout(true);
        assert!(!sender.hybrid_slow_start.started);
    }

    #[test]
    fn slow_start_half_packet_loss_with_large_reduction() {
        let mut sender = TestSender::new(true);
        sender.slow_start_large_reduction = true;
        sender.set_number_of_emulated_connection(1);
        let number_of_acks = 10;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE / 2);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE / 2);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + MAX_SEGMENT_SIZE * 2 * number_of_acks;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose a packet to exit slow start. We should now have fallen out of
        // slow start with a window reduced by 1.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        expected_send_window -= MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose 10 packets in recovery and verify that congestion window is
        // reduced by 5 packets.
        sender.lose_n_packets(10, MAX_SEGMENT_SIZE / 2);
        expected_send_window -= 5 * MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
    }

    #[test]
    fn slow_start_packet_loss_with_max_half_reduction() {
        let mut sender = TestSender::new(true);
        sender.slow_start_large_reduction = true;
        sender.set_number_of_emulated_connection(1);
        let number_of_acks = INITIAL_CONGESTION_WINDOW_PACKETS / 2;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose a packet to exit slow start. We should now have fallen out of
        // slow start with a window reduced by 1.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        expected_send_window -= MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Lose half the outstanding packets in recovery and verify the congestion
        // window is only reduced by a max of half.
        sender.lose_n_packets(number_of_acks * 2, MAX_SEGMENT_SIZE);
        expected_send_window -= (number_of_acks * 2 - 1) * MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        sender.lose_n_packets(5, MAX_SEGMENT_SIZE);
        assert_eq!(expected_send_window, sender.get_congestion_window());
    }

    #[test]
    fn np_prr_when_less_than_one_packet_in_flight() {
        let mut sender = TestSender::new(true);
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.lose_n_packets(
            INITIAL_CONGESTION_WINDOW_PACKETS - 1,
            MAX_SEGMENT_SIZE,
        );
        sender.ack_n_packets(1);
        // PRR will allow 2 packets for every ack during recovery.
        assert_eq!(2, sender.send_available_send_window(MAX_SEGMENT_SIZE));
        // Simulate abandoning all packets by supplying a bytes_in_flight of 0.
        // PRR should now allow a packet to be sent, even though prr's state
        // variables believe it has sent enough packets.
        assert!(sender.can_send(0));
    }

    #[test]
    fn slow_start_burst_packet_loss_prr() {
        let mut sender = TestSender::new(true);
        sender.set_number_of_emulated_connection(1);
        // Test based on the second example in RFC6937, though we also implement
        // forward acknowledgements, so the first two incoming acks will trigger
        // PRR immediately.
        // Ack 20 packets in 10 acks to raise the CWND to 30.
        let number_of_acks = 10;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);

        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());

        // Lose one more than the congestion window reduction, so that after loss,
        // bytes_in_flight is lesser than the congestion window.
        let send_window_after_loss =
            (RENO_BETA * expected_send_window as f32) as usize;
        let num_packets_to_lose = (expected_send_window - send_window_after_loss) /
            MAX_SEGMENT_SIZE +
            1;
        sender.lose_n_packets(num_packets_to_lose, MAX_SEGMENT_SIZE);
        // Immediately after the loss, ensure at least one packet can be sent.
        // Losses without subsequent acks can occur with timer based loss
        // detection.
        assert!(sender.can_send(sender.bytes_in_flight));
        sender.ack_n_packets(1);
        // We should now have fallen out of slow start with a reduced window.
        expected_send_window = (expected_send_window as f32 * RENO_BETA) as usize;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Only 2 packets should be allowed to be sent, per PRR-SSRB.
        assert_eq!(2, sender.send_available_send_window(MAX_SEGMENT_SIZE));
        // Ack the next packet, which triggers another loss.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        sender.ack_n_packets(1);
        // Send 2 packets to simulate PRR-SSRB.
        assert_eq!(2, sender.send_available_send_window(MAX_SEGMENT_SIZE));
        // Ack the next packet, which triggers another loss.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        sender.ack_n_packets(1);
        // Send 2 packets to simulate PRR-SSRB.
        assert_eq!(2, sender.send_available_send_window(MAX_SEGMENT_SIZE));
        // Exit recovery and return to sending at the new rate.
        for _ in 0..number_of_acks {
            sender.ack_n_packets(1);
            assert_eq!(1, sender.send_available_send_window(MAX_SEGMENT_SIZE));
        }
    }

    #[test]
    fn rto_congesion_window() {
        let mut sender = TestSender::new(true);
        assert_eq!(DEFAULT_WINDOW_TCP, sender.get_congestion_window());
        // Expect the window to decrease to the minimum once the RTO fires and
        // slow start threshold to be set to 1/2 of the CWND.
        sender.on_retransmission_timeout(true);
        assert_eq!(2 * MAX_SEGMENT_SIZE, sender.get_congestion_window());
        assert_eq!(5 * MAX_SEGMENT_SIZE, sender.slow_start_threshold);
    }

    #[test]
    fn rto_congestion_window_no_retransmisstion() {
        let mut sender = TestSender::new(true);
        // Expect the window to remain unchanged if the RTO fires but no packets
        // are retransmitted.
        sender.on_retransmission_timeout(false);
        assert_eq!(DEFAULT_WINDOW_TCP, sender.get_congestion_window());
    }

    #[test]
    fn tcp_cubic_reset_epoch_on_quiescence() {
        let mut sender = TestSender::new(false);
        let max_congestion_window = 50;
        let max_congestion_window_bytes =
            max_congestion_window * MAX_SEGMENT_SIZE;
        let mut num_sent = sender.send_available_send_window(MAX_SEGMENT_SIZE);
        // Make sure we fall out of slow start.
        let mut saved_cwnd = sender.get_congestion_window();
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        assert!(saved_cwnd > sender.get_congestion_window());
        // Ack the rest of the outstanding packets to get out of recovery.
        for _ in 1..num_sent {
            sender.ack_n_packets(1);
        }
        assert_eq!(0, sender.bytes_in_flight);
        // Send a new window of data and ack all; cubic growth should occur.
        saved_cwnd = sender.get_congestion_window();
        num_sent = sender.send_available_send_window(MAX_SEGMENT_SIZE);
        for _ in 0..num_sent {
            sender.ack_n_packets(1);
        }
        assert!(saved_cwnd < sender.get_congestion_window());
        assert!(max_congestion_window_bytes > sender.get_congestion_window());
        assert_eq!(0, sender.bytes_in_flight);
        // Quiescent time of 100 seconds
        sender.clock += Duration::from_millis(100000);
        // Send new window of data and ack one packet. Cubic epoch should have
        // been reset; ensure cwnd increase is not dramatic.
        saved_cwnd = sender.get_congestion_window();
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.ack_n_packets(1);
        assert!(
            saved_cwnd.abs_diff(sender.get_congestion_window()) <
                MAX_SEGMENT_SIZE
        );
        assert!(max_congestion_window_bytes > sender.get_congestion_window());
    }

    #[test]
    fn multiple_losses_in_one_window() {
        let mut sender = TestSender::new(false);
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let initial_window = sender.get_congestion_window();
        sender.lose_packet(sender.acked_packet_number + 1);
        let post_loss_window = sender.get_congestion_window();
        assert!(initial_window > post_loss_window);
        sender.lose_packet(sender.acked_packet_number + 3);
        assert_eq!(post_loss_window, sender.get_congestion_window());
        sender.lose_packet(sender.packet_number - 1);
        assert_eq!(post_loss_window, sender.get_congestion_window());
        // Lose a later packet and ensure the window decreases.
        sender.lose_packet(sender.packet_number);
        assert!(post_loss_window > sender.get_congestion_window());
    }

    #[test]
    fn two_connection_congestion_avoidance_at_end_of_recovery() {
        let mut sender = TestSender::new(true);
        sender.set_number_of_emulated_connection(2);
        // Ack 10 packets in 5 acks to raise the CWND to 20.
        let number_of_acks = 5;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        // We should now have fallen out of slow start with a reduced window.
        expected_send_window =
            (expected_send_window as f32 * sender.reno_beta()) as usize;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // No congestion window growth should occur in recovery phase, i.e., until
        // the currently outstanding 20 packets are acked.
        for _ in 0..10 {
            // Send our full send window.
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            assert!(sender.is_in_recovery());
            sender.ack_n_packets(2);
            assert_eq!(expected_send_window, sender.get_congestion_window());
        }
        assert!(!sender.is_in_recovery());
        // Out of recovery now. Congestion window should not grow for half an RTT.
        let mut packets_in_send_window = expected_send_window / MAX_SEGMENT_SIZE;
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.ack_n_packets(packets_in_send_window / 2 - 2);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Next ack should increase congestion window by 1MSS.
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.ack_n_packets(2);
        expected_send_window += MAX_SEGMENT_SIZE;
        packets_in_send_window += 1;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Congestion window should remain steady again for half an RTT.
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.ack_n_packets(packets_in_send_window / 2 - 1);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Next ack should cause congestion window to grow by 1MSS.
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.ack_n_packets(2);
        expected_send_window += MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
    }

    #[test]
    fn one_connection_congestion_avoidance_at_end_of_recovery() {
        let mut sender = TestSender::new(true);
        sender.set_number_of_emulated_connection(1);

        // Ack 10 packets in 5 acks to raise the CWND to 20.
        let number_of_acks = 5;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);

        // We should now have fallen out of slow start with a reduced window.
        expected_send_window =
            (expected_send_window as f32 * sender.reno_beta()) as usize;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // No congestion window growth should occur in recovery phase, i.e., until
        // the currently outstanding 20 packets are acked.
        for _ in 0..10 {
            // Send our full send window.
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            assert!(sender.is_in_recovery());
            sender.ack_n_packets(2);
            assert_eq!(expected_send_window, sender.get_congestion_window());
        }
        assert!(!sender.is_in_recovery());

        // Out of recovery now. Congestion window should not grow during RTT.
        for _ in (0..expected_send_window / MAX_SEGMENT_SIZE - 2).step_by(2) {
            // Send our full send window.
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
            assert_eq!(expected_send_window, sender.get_congestion_window());
        }

        // Next ack should cause congestion window to grow by 1MSS.
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        sender.ack_n_packets(2);
        expected_send_window += MAX_SEGMENT_SIZE;
        assert_eq!(expected_send_window, sender.get_congestion_window());
    }

    #[test]
    fn reset_after_connection_migration() {
        let mut sender = TestSender::new(true);
        sender.set_number_of_emulated_connection(1);
        let number_of_acks = 10;
        for _ in 0..number_of_acks {
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
            sender.ack_n_packets(2);
        }
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        let mut expected_send_window =
            DEFAULT_WINDOW_TCP + (MAX_SEGMENT_SIZE * 2 * number_of_acks);
        assert_eq!(expected_send_window, sender.get_congestion_window());
        // Loses a packet to exit slow start.
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        // We should now have fallen out of slow start with a reduced window. Slow
        // start threshold is also updated.
        expected_send_window = (expected_send_window as f32 * RENO_BETA) as usize;
        assert_eq!(expected_send_window, sender.get_congestion_window());
        assert_eq!(expected_send_window, sender.get_slow_start_threshold());
        // Resets cwnd and slow start threshold on connection migrations.
        sender.on_connection_migration();
        assert_eq!(DEFAULT_WINDOW_TCP, sender.get_congestion_window());
        assert_eq!(
            MAX_CONGESTION_WINDOW_PACKETS * MAX_SEGMENT_SIZE,
            sender.get_slow_start_threshold()
        );
        assert!(!sender.hybrid_slow_start.started);
    }

    #[test]
    fn limit_cwnd_increase_in_congestion_avoidance() {
        // Enable Cubic.
        let mut sender = TestSender::new(false);
        let num_sent = sender.send_available_send_window(MAX_SEGMENT_SIZE);
        // Make sure we fall out of slow start.
        let mut saved_cwnd = sender.get_congestion_window();
        sender.lose_n_packets(1, MAX_SEGMENT_SIZE);
        assert!(saved_cwnd > sender.get_congestion_window());
        // Ack the rest of the outstanding packets to get out of recovery.
        for _ in 1..num_sent {
            sender.ack_n_packets(1);
        }
        assert_eq!(0, sender.bytes_in_flight);
        // Send a new window of data and ack all; cubic growth should occur.
        saved_cwnd = sender.get_congestion_window();
        sender.send_available_send_window(MAX_SEGMENT_SIZE);
        // Ack packets until the CWND increases.
        while sender.get_congestion_window() == saved_cwnd {
            sender.ack_n_packets(1);
            sender.send_available_send_window(MAX_SEGMENT_SIZE);
        }
        // Bytes in flight may be larger than the CWND if the CWND isn't an exact
        // multiple of the packet sizes being sent.
        assert!(sender.bytes_in_flight > sender.get_congestion_window());
        saved_cwnd = sender.get_congestion_window();
        // Advance time 2 seconds waiting for an ack.
        sender.clock += Duration::from_secs(2);
        // Ack two packets. The CWND should increase by only one packet.
        sender.ack_n_packets(2);
        assert_eq!(
            saved_cwnd + MAX_SEGMENT_SIZE,
            sender.get_congestion_window()
        );
    }
}
