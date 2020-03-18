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

use std::time::Instant;

use crate::recovery;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;
use crate::recovery::Sent;

pub static RENO: CongestionControlOps = CongestionControlOps {
    on_packet_sent,
    on_packet_acked,
    congestion_event,
};

fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, _now: Instant) {
    r.bytes_in_flight += sent_bytes;
}

fn on_packet_acked(r: &mut Recovery, packet: &Sent, _now: Instant) {
    r.bytes_in_flight -= packet.size;

    if r.in_congestion_recovery(packet.time) {
        return;
    }

    if r.app_limited {
        return;
    }

    if r.congestion_window < r.ssthresh {
        // Slow start.
        r.congestion_window += packet.size;
    } else {
        // Congestion avoidance.
        r.congestion_window +=
            (recovery::MAX_DATAGRAM_SIZE * packet.size) / r.congestion_window;
    }
}

fn congestion_event(r: &mut Recovery, time_sent: Instant, now: Instant) {
    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    if !r.in_congestion_recovery(time_sent) {
        r.congestion_recovery_start_time = Some(now);

        r.congestion_window = (r.congestion_window as f64 *
            recovery::LOSS_REDUCTION_FACTOR)
            as usize;

        r.congestion_window =
            std::cmp::max(r.congestion_window, recovery::MINIMUM_WINDOW);

        r.ssthresh = r.congestion_window;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reno_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let r = Recovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight, 0);
    }

    #[test]
    fn reno_send() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let now = Instant::now();

        r.on_packet_sent_cc(1000, now);

        assert_eq!(r.bytes_in_flight, 1000);
    }

    #[test]
    fn reno_slow_start() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let now = Instant::now();

        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time: now,
            size: 5000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            recent_delivered_packet_sent_time: std::time::Instant::now(),
            is_app_limited: false,
        };

        // Send 5k x 4 = 20k, higher than default cwnd(~15k)
        // to become no longer app limited.
        r.on_packet_sent_cc(p.size, now);
        r.on_packet_sent_cc(p.size, now);
        r.on_packet_sent_cc(p.size, now);
        r.on_packet_sent_cc(p.size, now);

        let cwnd_prev = r.cwnd();

        r.on_packet_acked_cc(&p, now);

        // Check if cwnd increased by packet size (slow start).
        assert_eq!(r.cwnd(), cwnd_prev + p.size);
    }

    #[test]
    fn reno_congestion_event() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let prev_cwnd = r.cwnd();

        let now = Instant::now();

        r.congestion_event(now, now);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, r.cwnd());
    }

    #[test]
    fn reno_congestion_avoidance() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let prev_cwnd = r.cwnd();

        let now = Instant::now();

        // Send 20K bytes.
        r.on_packet_sent_cc(20000, now);

        r.congestion_event(now, now);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, r.cwnd());

        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time: now,
            size: 5000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            recent_delivered_packet_sent_time: std::time::Instant::now(),
            is_app_limited: false,
        };

        let prev_cwnd = r.cwnd();

        // Ack 5000 bytes.
        r.on_packet_acked_cc(&p, now);

        // Check if cwnd increase is smaller than a packet size (congestion
        // avoidance).
        assert!(r.cwnd() < prev_cwnd + 1111);
    }
}
