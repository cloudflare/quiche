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

//! CUBIC Congestion Control
//!
//! This implementation is based on the following RFC:
//! <https://tools.ietf.org/html/rfc8312>
//!
//! Note that Slow Start can use HyStart++ when enabled.

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use crate::packet;
use crate::recovery;
use crate::recovery::reno;

use crate::recovery::Acked;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;

pub static CUBIC: CongestionControlOps = CongestionControlOps {
    on_packet_sent,
    on_packet_acked,
    congestion_event,
    collapse_cwnd,
};

/// CUBIC Constants.
///
/// These are recommended value in RFC8312.
const BETA_CUBIC: f64 = 0.7;

const C: f64 = 0.4;

/// CUBIC State Variables.
///
/// We need to keep those variables across the connection.
/// k, w_max, w_last_max is described in the RFC.
#[derive(Debug, Default)]
pub struct State {
    k: f64,

    w_max: f64,

    w_last_max: f64,

    // Used in CUBIC fix (see on_packet_sent())
    last_sent_time: Option<Instant>,

    // Store cwnd increment during congestion avoidance.
    cwnd_inc: usize,
}

/// CUBIC Functions.
///
/// Note that these calculations are based on a count of cwnd as bytes,
/// not packets.
/// Unit of t (duration) and RTT are based on seconds (f64).
impl State {
    // K = cbrt(w_max * (1 - beta_cubic) / C) (Eq. 2)
    fn cubic_k(&self, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        libm::cbrt(w_max * (1.0 - BETA_CUBIC) / C)
    }

    // W_cubic(t) = C * (t - K)^3 - w_max (Eq. 1)
    fn w_cubic(&self, t: Duration, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;

        (C * (t.as_secs_f64() - self.k).powi(3) + w_max) *
            max_datagram_size as f64
    }

    // W_est(t) = w_max * beta_cubic + 3 * (1 - beta_cubic) / (1 + beta_cubic) *
    // (t / RTT) (Eq. 4)
    fn w_est(&self, t: Duration, rtt: Duration, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        (w_max * BETA_CUBIC +
            3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * t.as_secs_f64() /
                rtt.as_secs_f64()) *
            max_datagram_size as f64
    }
}

fn collapse_cwnd(r: &mut Recovery) {
    let cubic = &mut r.cubic_state;

    r.congestion_recovery_start_time = None;

    cubic.w_last_max = r.congestion_window as f64;
    cubic.w_max = cubic.w_last_max;

    // 4.7 Timeout - reduce ssthresh based on BETA_CUBIC
    r.ssthresh = (r.congestion_window as f64 * BETA_CUBIC) as usize;
    r.ssthresh = cmp::max(
        r.ssthresh,
        r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS,
    );

    cubic.cwnd_inc = 0;

    reno::collapse_cwnd(r);
}

fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, now: Instant) {
    // See https://github.com/torvalds/linux/commit/30927520dbae297182990bb21d08762bcc35ce1d
    // First transmit when no packets in flight
    let cubic = &mut r.cubic_state;

    if let Some(last_sent_time) = cubic.last_sent_time {
        if r.bytes_in_flight == 0 {
            let delta = now - last_sent_time;

            // We were application limited (idle) for a while.
            // Shift epoch start to keep cwnd growth to cubic curve.
            if let Some(recovery_start_time) = r.congestion_recovery_start_time {
                if delta.as_nanos() > 0 {
                    r.congestion_recovery_start_time =
                        Some(recovery_start_time + delta);
                }
            }
        }
    }

    cubic.last_sent_time = Some(now);

    reno::on_packet_sent(r, sent_bytes, now);
}

fn on_packet_acked(
    r: &mut Recovery, packet: &Acked, epoch: packet::Epoch, now: Instant,
) {
    let in_congestion_recovery = r.in_congestion_recovery(packet.time_sent);

    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(packet.size);

    if in_congestion_recovery {
        return;
    }

    if r.app_limited {
        return;
    }

    if r.congestion_window < r.ssthresh {
        // Slow start.
        let cwnd_inc = cmp::min(
            packet.size,
            r.max_datagram_size * recovery::ABC_L -
                cmp::min(
                    r.bytes_acked_sl,
                    r.max_datagram_size * recovery::ABC_L,
                ),
        );

        // In Slow slart, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        r.congestion_window += cwnd_inc;

        if r.hystart.enabled() &&
            epoch == packet::EPOCH_APPLICATION &&
            r.hystart.try_enter_lss(
                packet,
                r.latest_rtt,
                r.congestion_window,
                now,
                r.max_datagram_size,
            )
        {
            r.ssthresh = r.congestion_window;
        }
    } else {
        // Congestion avoidance.
        let ca_start_time;

        // In LSS, use lss_start_time instead of congestion_recovery_start_time.
        if r.hystart.in_lss(epoch) {
            ca_start_time = r.hystart.lss_start_time().unwrap();

            // Reset w_max and k when LSS started.
            if r.cubic_state.w_max == 0.0 {
                r.cubic_state.w_max = r.congestion_window as f64;
                r.cubic_state.k = 0.0;
            }
        } else {
            match r.congestion_recovery_start_time {
                Some(t) => ca_start_time = t,
                None => {
                    // When we come here without congestion_event() triggered,
                    // initialize congestion_recovery_start_time, w_max and k.
                    ca_start_time = now;
                    r.congestion_recovery_start_time = Some(now);

                    r.cubic_state.w_max = r.congestion_window as f64;
                    r.cubic_state.k = 0.0;
                },
            }
        }

        let t = now - ca_start_time;

        // w_cubic(t + rtt)
        let w_cubic = r.cubic_state.w_cubic(t + r.min_rtt, r.max_datagram_size);

        // w_est(t)
        let w_est = r.cubic_state.w_est(t, r.min_rtt, r.max_datagram_size);

        let mut cubic_cwnd = r.congestion_window;

        if w_cubic < w_est {
            // TCP friendly region.
            cubic_cwnd = cmp::max(cubic_cwnd, w_est as usize);
        } else if cubic_cwnd < w_cubic as usize {
            // Concave region or convex region use same increment.
            let cubic_inc = (w_cubic - cubic_cwnd as f64) / cubic_cwnd as f64 *
                r.max_datagram_size as f64;

            cubic_cwnd += cubic_inc as usize;
        }

        // When in Limited Slow Start, take the max of CA cwnd and
        // LSS cwnd.
        if r.hystart.in_lss(epoch) {
            let lss_cwnd = r.hystart.lss_cwnd(
                packet.size,
                r.bytes_acked_sl,
                r.congestion_window,
                r.ssthresh,
                r.max_datagram_size,
            );

            r.bytes_acked_sl += packet.size;

            cubic_cwnd = cmp::max(cubic_cwnd, lss_cwnd);
        }

        // Update the increment and increase cwnd by MSS.
        r.cubic_state.cwnd_inc += cubic_cwnd - r.congestion_window;

        // cwnd_inc can be more than 1 MSS in the late stage of max probing.
        // however QUIC recovery draft 7.4 (Congestion Avoidance) limits
        // the increase of cwnd to 1 max_datagram_size per cwnd acknowledged.
        if r.cubic_state.cwnd_inc >= r.max_datagram_size {
            r.congestion_window += r.max_datagram_size;
            r.cubic_state.cwnd_inc = 0;
        }
    }
}

fn congestion_event(
    r: &mut Recovery, time_sent: Instant, epoch: packet::Epoch, now: Instant,
) {
    let in_congestion_recovery = r.in_congestion_recovery(time_sent);

    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    if !in_congestion_recovery {
        r.congestion_recovery_start_time = Some(now);

        // Fast convergence
        if r.cubic_state.w_max < r.cubic_state.w_last_max {
            r.cubic_state.w_last_max = r.cubic_state.w_max;
            r.cubic_state.w_max =
                r.cubic_state.w_max as f64 * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            r.cubic_state.w_last_max = r.cubic_state.w_max;
        }

        r.cubic_state.w_max = r.congestion_window as f64;
        r.ssthresh = (r.cubic_state.w_max * BETA_CUBIC) as usize;
        r.ssthresh = cmp::max(
            r.ssthresh,
            r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS,
        );
        r.congestion_window = r.ssthresh;
        r.cubic_state.k = r.cubic_state.cubic_k(r.max_datagram_size);

        r.cubic_state.cwnd_inc =
            (r.cubic_state.cwnd_inc as f64 * BETA_CUBIC) as usize;

        if r.hystart.in_lss(epoch) {
            r.hystart.congestion_event();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::hystart;

    #[test]
    fn cubic_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let r = Recovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight, 0);
    }

    #[test]
    fn cubic_send() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);

        r.on_packet_sent_cc(1000, Instant::now());

        assert_eq!(r.bytes_in_flight, 1000);
    }

    #[test]
    fn cubic_slow_start() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();

        let p = recovery::Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..recovery::INITIAL_WINDOW_PACKETS {
            r.on_packet_sent_cc(p.size, now);
        }

        let cwnd_prev = r.cwnd();

        let acked = vec![Acked {
            pkt_num: p.pkt_num,
            time_sent: p.time_sent,
            size: p.size,
        }];

        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);

        // Check if cwnd increased by packet size (slow start)
        assert_eq!(r.cwnd(), cwnd_prev + p.size);
    }

    #[test]
    fn cubic_slow_start_abc_l() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();

        let p = recovery::Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..recovery::INITIAL_WINDOW_PACKETS {
            r.on_packet_sent_cc(p.size, now);
        }

        let cwnd_prev = r.cwnd();

        let acked = vec![
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size * 3,
            },
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size * 3,
            },
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size * 3,
            },
        ];

        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);

        // Acked 3 packets, but cwnd will increase 2 x mss.
        assert_eq!(r.cwnd(), cwnd_prev + p.size * recovery::ABC_L);
    }

    #[test]
    fn cubic_congestion_event() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let prev_cwnd = r.cwnd();

        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // In CUBIC, after congestion event, cwnd will be reduced by (1 -
        // CUBIC_BETA)
        assert_eq!(prev_cwnd as f64 * BETA_CUBIC, r.cwnd() as f64);
    }

    #[test]
    fn cubic_congestion_avoidance() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let prev_cwnd = r.cwnd();

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..recovery::INITIAL_WINDOW_PACKETS {
            r.on_packet_sent_cc(r.max_datagram_size, now);
        }

        // Trigger congestion event to update ssthresh
        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(r.cwnd(), cur_cwnd);

        let rtt = Duration::from_millis(100);

        let acked = vec![Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: now + rtt,
            size: r.max_datagram_size,
        }];

        // Ack more than cwnd bytes with rtt=100ms
        r.update_rtt(rtt, Duration::from_millis(0), now);
        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now + rtt * 3);

        // After acking more than cwnd, expect cwnd increased by MSS
        assert_eq!(r.cwnd(), cur_cwnd + r.max_datagram_size);
    }

    #[test]
    fn cubic_collapse_cwnd_and_restart() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();

        // Fill up bytes_in_flight to avoid app_limited=true
        r.on_packet_sent_cc(30000, now);

        // Trigger congestion event to update ssthresh
        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // After persistent congestion, cwnd should be the minimum window
        r.collapse_cwnd();
        assert_eq!(
            r.cwnd(),
            r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS
        );

        let acked = vec![Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: now + Duration::from_millis(1),
            size: r.max_datagram_size,
        }];

        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);

        // Slow start again - cwnd will be increased by 1 MSS
        assert_eq!(
            r.cwnd(),
            r.max_datagram_size * (recovery::MINIMUM_WINDOW_PACKETS + 1)
        );
    }

    #[test]
    fn cubic_hystart_limited_slow_start() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);
        cfg.enable_hystart(true);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let pkt_num = 0;
        let epoch = packet::EPOCH_APPLICATION;

        let p = recovery::Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
            has_data: false,
        };

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;
        let pkts_1st_round = n_rtt_sample as u64;
        r.hystart.start_round(pkt_num);

        let rtt_1st = 50;

        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            r.on_packet_sent_cc(p.size, now);
        }

        // Receving Acks.
        let now = now + Duration::from_millis(rtt_1st);
        for _ in 0..n_rtt_sample {
            r.update_rtt(
                Duration::from_millis(rtt_1st),
                Duration::from_millis(0),
                now,
            );

            let acked = vec![Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
            }];

            r.on_packets_acked(acked, epoch, now);
        }

        // Not in LSS yet.
        assert_eq!(r.hystart.lss_start_time().is_some(), false);

        // 2nd round.
        r.hystart.start_round(pkts_1st_round * 2);

        let mut rtt_2nd = 100;
        let now = now + Duration::from_millis(rtt_2nd);

        // Send 2nd round packets.
        for _ in 0..n_rtt_sample {
            r.on_packet_sent_cc(p.size, now);
        }

        // Receving Acks.
        // Last ack will cause to exit to LSS.
        let mut cwnd_prev = r.cwnd();

        for _ in 0..n_rtt_sample {
            cwnd_prev = r.cwnd();
            r.update_rtt(
                Duration::from_millis(rtt_2nd),
                Duration::from_millis(0),
                now,
            );

            let acked = vec![Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
            }];

            r.on_packets_acked(acked, epoch, now);

            // Keep increasing RTT so that hystart exits to LSS.
            rtt_2nd += 4;
        }

        // Now we are in LSS.
        assert_eq!(r.hystart.lss_start_time().is_some(), true);
        assert_eq!(r.cwnd(), cwnd_prev + r.max_datagram_size);

        // Send a full cwnd.
        r.on_packet_sent_cc(r.cwnd(), now);

        // Ack'ing 4 packets to increase cwnd by 1 MSS during LSS
        cwnd_prev = r.cwnd();
        for _ in 0..4 {
            let acked = vec![Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
            }];
            r.on_packets_acked(acked, epoch, now);
        }

        // During LSS cwnd will be increased less than usual slow start.
        assert_eq!(r.cwnd(), cwnd_prev + r.max_datagram_size);
    }
}
