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

use crate::packet;
use crate::recovery;

use crate::recovery::Acked;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;

pub static RENO: CongestionControlOps = CongestionControlOps {
    on_packet_sent,
    on_packet_acked,
    congestion_event,
    collapse_cwnd,
};

pub fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, _now: Instant) {
    r.bytes_in_flight += sent_bytes;
}

fn on_packet_acked(
    r: &mut Recovery, packet: &Acked, epoch: packet::Epoch, now: Instant,
) {
    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(packet.size);

    if r.in_congestion_recovery(packet.time_sent) {
        return;
    }

    if r.app_limited {
        return;
    }

    if r.congestion_window < r.ssthresh {
        // Slow start.
        if r.hystart.enabled() && epoch == packet::EPOCH_APPLICATION {
            let (cwnd, ssthresh) = r.hystart_on_packet_acked(packet, now);

            r.congestion_window = cwnd;
            r.ssthresh = ssthresh;
        } else {
            r.congestion_window += packet.size;
        }
    } else {
        // Congestion avoidance.
        let mut reno_cwnd = r.congestion_window;

        r.bytes_acked += packet.size;

        if r.bytes_acked >= r.congestion_window {
            r.bytes_acked -= r.congestion_window;
            reno_cwnd += recovery::MAX_DATAGRAM_SIZE;
        }

        // When in Limited Slow Start, take the max of CA cwnd and
        // LSS cwnd.
        if r.hystart.enabled() &&
            epoch == packet::EPOCH_APPLICATION &&
            r.hystart.lss_start_time().is_some()
        {
            let (lss_cwnd, _) = r.hystart_on_packet_acked(packet, now);

            reno_cwnd = cmp::max(reno_cwnd, lss_cwnd);
        }

        r.congestion_window = reno_cwnd;
    }
}

fn congestion_event(
    r: &mut Recovery, time_sent: Instant, epoch: packet::Epoch, now: Instant,
) {
    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    if !r.in_congestion_recovery(time_sent) {
        r.congestion_recovery_start_time = Some(now);

        r.congestion_window = (r.congestion_window as f64 *
            recovery::LOSS_REDUCTION_FACTOR)
            as usize;

        r.congestion_window =
            cmp::max(r.congestion_window, recovery::MINIMUM_WINDOW);

        r.bytes_acked = (r.congestion_window as f64 *
            recovery::LOSS_REDUCTION_FACTOR) as usize;

        r.ssthresh = r.congestion_window;

        if r.hystart.enabled() && epoch == packet::EPOCH_APPLICATION {
            r.hystart.congestion_event();
        }
    }
}

pub fn collapse_cwnd(r: &mut Recovery) {
    r.congestion_window = recovery::MINIMUM_WINDOW;
    r.bytes_acked = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

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

        let p = recovery::Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 5000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            recent_delivered_packet_sent_time: std::time::Instant::now(),
            is_app_limited: false,
            has_data: false,
        };

        // Send 5k x 4 = 20k, higher than default cwnd(~15k)
        // to become no longer app limited.
        r.on_packet_sent_cc(p.size, now);
        r.on_packet_sent_cc(p.size, now);
        r.on_packet_sent_cc(p.size, now);
        r.on_packet_sent_cc(p.size, now);

        let cwnd_prev = r.cwnd();

        let acked = vec![Acked {
            pkt_num: p.pkt_num,
            time_sent: p.time_sent,
            size: p.size,
        }];

        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);

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

        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, r.cwnd());
    }

    #[test]
    fn reno_congestion_avoidance() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let prev_cwnd = r.cwnd();

        // Fill up bytes_in_flight to avoid app_limited=true
        r.on_packet_sent_cc(20000, now);

        // Trigger congestion event to update ssthresh
        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd =
            (prev_cwnd as f64 * recovery::LOSS_REDUCTION_FACTOR) as usize;
        assert_eq!(r.cwnd(), cur_cwnd);

        let rtt = Duration::from_millis(100);

        let acked = vec![Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: now + rtt,
            // More than cur_cwnd to increase cwnd
            size: 8000,
        }];

        // Ack more than cwnd bytes with rtt=100ms
        r.update_rtt(rtt, Duration::from_millis(0), now);
        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now + rtt * 2);

        // After acking more than cwnd, expect cwnd increased by MSS
        assert_eq!(r.cwnd(), cur_cwnd + recovery::MAX_DATAGRAM_SIZE);
    }
}
