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
mod tests {
    use super::*;

    use crate::recovery::congestion::test_sender::TestSender;
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
