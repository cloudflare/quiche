// Copyright (C) 2019, Cloudflare, Inc.
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

//! Reno Congestion Control
//!
//! Note that Slow Start can use HyStart++ when enabled.

use std::cmp;
use std::time::Instant;

use crate::recovery;

use crate::recovery::rtt::RttStats;
use crate::recovery::Acked;
use crate::recovery::Sent;

use super::Congestion;
use super::CongestionControlOps;

pub(crate) static RENO: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    has_custom_pacing,
    debug_fmt,
};

pub fn on_init(_r: &mut Congestion) {}

pub fn on_packet_sent(
    _r: &mut Congestion, _sent_bytes: usize, _bytes_in_flight: usize,
    _now: Instant,
) {
}

fn on_packets_acked(
    r: &mut Congestion, _bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, rtt_stats: &RttStats,
) {
    for pkt in packets.drain(..) {
        on_packet_acked(r, &pkt, now, rtt_stats);
    }
}

fn on_packet_acked(
    r: &mut Congestion, packet: &Acked, now: Instant, rtt_stats: &RttStats,
) {
    if r.in_congestion_recovery(packet.time_sent) {
        return;
    }

    if r.app_limited {
        return;
    }

    if r.congestion_window < r.ssthresh {
        // In Slow slart, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        if r.hystart.in_css() {
            r.congestion_window += r.hystart.css_cwnd_inc(r.max_datagram_size);
        } else {
            r.congestion_window += r.max_datagram_size;
        }

        if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
            // Exit to congestion avoidance if CSS ends.
            r.ssthresh = r.congestion_window;
        }
    } else {
        // Congestion avoidance.
        r.bytes_acked_ca += packet.size;

        if r.bytes_acked_ca >= r.congestion_window {
            r.bytes_acked_ca -= r.congestion_window;
            r.congestion_window += r.max_datagram_size;
        }
    }
}

fn congestion_event(
    r: &mut Congestion, _bytes_in_flight: usize, _lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant,
) {
    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    let time_sent = largest_lost_pkt.time_sent;

    if !r.in_congestion_recovery(time_sent) {
        r.congestion_recovery_start_time = Some(now);

        r.congestion_window = (r.congestion_window as f64 *
            recovery::LOSS_REDUCTION_FACTOR)
            as usize;

        r.congestion_window = cmp::max(
            r.congestion_window,
            r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS,
        );

        r.bytes_acked_ca = (r.congestion_window as f64 *
            recovery::LOSS_REDUCTION_FACTOR) as usize;

        r.ssthresh = r.congestion_window;

        if r.hystart.in_css() {
            r.hystart.congestion_event();
        }
    }
}

fn checkpoint(_r: &mut Congestion) {}

fn rollback(_r: &mut Congestion) -> bool {
    true
}

fn has_custom_pacing() -> bool {
    false
}

fn debug_fmt(_r: &Congestion, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_sender {
    use std::collections::VecDeque;
    use std::ops::Deref;
    use std::ops::DerefMut;
    use std::time::Duration;
    use std::time::Instant;

    use crate::recovery::congestion::Congestion;
    use crate::recovery::rtt::RttStats;
    use crate::recovery::Acked;
    use crate::recovery::RecoveryConfig;
    use crate::recovery::Sent;
    use crate::CongestionControlAlgorithm;

    pub(crate) struct TestSender {
        cc: Congestion,
        pub(crate) next_pkt: u64,
        pub(crate) next_ack: u64,
        pub(crate) bytes_in_flight: usize,
        pub(crate) time: Instant,
        rtt_stats: RttStats,
        sent_packets: VecDeque<Sent>,
    }

    impl TestSender {
        pub(crate) fn new(
            algo: CongestionControlAlgorithm, hystart: bool,
        ) -> Self {
            let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
            cfg.set_cc_algorithm(algo);
            cfg.enable_hystart(hystart);

            TestSender {
                next_pkt: 0,
                next_ack: 0,
                bytes_in_flight: 0,
                time: Instant::now(),
                rtt_stats: RttStats::new(Duration::from_micros(0)),
                cc: Congestion::from_config(&RecoveryConfig::from_config(&cfg)),
                sent_packets: VecDeque::new(),
            }
        }

        pub(crate) fn send_packet(&mut self, bytes: usize) {
            let mut sent = Sent {
                pkt_num: self.next_pkt,
                frames: Default::default(),
                time_sent: self.time,
                time_acked: None,
                time_lost: None,
                size: bytes,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: self.time,
                first_sent_time: self.time,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            self.cc.on_packet_sent(
                self.bytes_in_flight,
                bytes,
                self.time,
                &mut sent,
                &self.rtt_stats,
                0,
                true,
            );

            self.sent_packets.push_back(sent);

            self.bytes_in_flight += bytes;
            self.next_pkt += 1;
        }

        pub(crate) fn inject_ack(&mut self, acked: Acked, now: Instant) {
            let _ = self.sent_packets.pop_front().unwrap();

            self.cc.on_packets_acked(
                self.bytes_in_flight,
                &mut vec![acked],
                &self.rtt_stats,
                now,
            );
        }

        pub(crate) fn ack_n_packets(&mut self, n: usize, bytes: usize) {
            let mut acked = Vec::new();

            for _ in 0..n {
                let unacked = self.sent_packets.pop_front().unwrap();

                acked.push(Acked {
                    pkt_num: unacked.pkt_num,
                    time_sent: unacked.time_sent,
                    size: unacked.size,

                    rtt: self.time.saturating_duration_since(unacked.time_sent),
                    delivered: unacked.delivered,
                    delivered_time: unacked.delivered_time,
                    first_sent_time: unacked.first_sent_time,
                    is_app_limited: unacked.is_app_limited,
                    tx_in_flight: unacked.tx_in_flight,
                    lost: unacked.lost,
                });

                self.next_ack += 1;
            }

            self.cc.on_packets_acked(
                self.bytes_in_flight,
                &mut acked,
                &self.rtt_stats,
                self.time,
            );

            self.bytes_in_flight -= n * bytes;
        }

        pub(crate) fn lose_n_packets(
            &mut self, n: usize, bytes: usize, time_sent: Option<Instant>,
        ) {
            let mut unacked = None;

            for _ in 0..n {
                self.next_ack += 1;
                unacked = self.sent_packets.pop_front();
            }

            let mut unacked = unacked.unwrap();
            if let Some(time) = time_sent {
                unacked.time_sent = time;
            }

            if !self.cc.in_congestion_recovery(unacked.time_sent) {
                (self.cc.cc_ops.checkpoint)(&mut self.cc);
            }

            (self.cc_ops.congestion_event)(
                &mut self.cc,
                self.bytes_in_flight,
                n * bytes,
                &unacked,
                self.time,
            );

            self.cc.lost_count += n;
            self.bytes_in_flight -= n * bytes;
        }

        pub(crate) fn update_rtt(&mut self, rtt: Duration) {
            self.rtt_stats
                .update_rtt(rtt, Duration::ZERO, self.time, true)
        }

        pub(crate) fn advance_time(&mut self, period: Duration) {
            self.time += period;
        }
    }

    impl Deref for TestSender {
        type Target = Congestion;

        fn deref(&self) -> &Self::Target {
            &self.cc
        }
    }

    impl DerefMut for TestSender {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.cc
        }
    }
}

#[cfg(test)]
mod tests {
    use self::test_sender::TestSender;

    use super::*;

    use crate::recovery::Recovery;
    use std::time::Duration;

    fn test_sender() -> TestSender {
        TestSender::new(recovery::CongestionControlAlgorithm::Reno, false)
    }

    #[test]
    fn reno_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let r = Recovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight, 0);
    }

    #[test]
    fn reno_slow_start() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(1, size);

        // Check if cwnd increased by packet size (slow start).
        assert_eq!(sender.congestion_window, cwnd_prev + size);
    }

    #[test]
    fn reno_slow_start_multi_acks() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(3, size);

        // Acked 3 packets.
        assert_eq!(sender.congestion_window, cwnd_prev + size * 3);
    }

    #[test]
    fn reno_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window;

        sender.send_packet(size);
        sender.lose_n_packets(1, size, None);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, sender.congestion_window);
    }

    #[test]
    fn reno_congestion_avoidance() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..14 {
            sender.send_packet(size);
        }

        let prev_cwnd = sender.congestion_window;

        sender.lose_n_packets(1, size, None);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd =
            (prev_cwnd as f64 * recovery::LOSS_REDUCTION_FACTOR) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);
        sender.advance_time(2 * rtt);

        sender.ack_n_packets(8, size);
        // After acking more than cwnd, expect cwnd increased by MSS
        assert_eq!(sender.congestion_window, cur_cwnd + size);
    }
}
