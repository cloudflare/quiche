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
//! This implementation is based on the following draft:
//! <https://tools.ietf.org/html/draft-ietf-tcpm-rfc8312bis-02>
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
    checkpoint,
    rollback,
    has_custom_pacing,
};

/// CUBIC Constants.
///
/// These are recommended value in RFC8312.
const BETA_CUBIC: f64 = 0.7;

const C: f64 = 0.4;

/// The packet count threshold to restore to the prior state if the
/// lost packet count since the last checkpoint is less than the threshold.
const RESTORE_COUNT_THRESHOLD: usize = 10;

/// Default value of alpha_aimd in the beginning of congestion avoidance.
const ALPHA_AIMD: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

/// CUBIC State Variables.
///
/// We need to keep those variables across the connection.
/// k, w_max, w_est are described in the RFC.
#[derive(Debug, Default)]
pub struct State {
    k: f64,

    w_max: f64,

    w_est: f64,

    alpha_aimd: f64,

    // Used in CUBIC fix (see on_packet_sent())
    last_sent_time: Option<Instant>,

    // Store cwnd increment during congestion avoidance.
    cwnd_inc: usize,

    // CUBIC state checkpoint preceding the last congestion event.
    prior: PriorState,
}

/// Stores the CUBIC state from before the last congestion event.
///
/// <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
#[derive(Debug, Default)]
struct PriorState {
    congestion_window: usize,

    ssthresh: usize,

    w_max: f64,

    w_last_max: f64,

    k: f64,

    epoch_start: Option<Instant>,

    lost_count: usize,
}

/// CUBIC Functions.
///
/// Note that these calculations are based on a count of cwnd as bytes,
/// not packets.
/// Unit of t (duration) and RTT are based on seconds (f64).
impl State {
    // K = cubic_root ((w_max - cwnd) / C) (Eq. 2)
    fn cubic_k(&self, cwnd: usize, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        let cwnd = cwnd as f64 / max_datagram_size as f64;

        libm::cbrt((w_max - cwnd) / C)
    }

    // W_cubic(t) = C * (t - K)^3 + w_max (Eq. 1)
    fn w_cubic(&self, t: Duration, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;

        (C * (t.as_secs_f64() - self.k).powi(3) + w_max) *
            max_datagram_size as f64
    }

    // W_est = W_est + alpha_aimd * (segments_acked / cwnd)  (Eq. 4)
    fn w_est_inc(
        &self, acked: usize, cwnd: usize, max_datagram_size: usize,
    ) -> f64 {
        self.alpha_aimd * (acked as f64 / cwnd as f64) * max_datagram_size as f64
    }
}

fn collapse_cwnd(r: &mut Recovery) {
    let cubic = &mut r.cubic_state;

    r.congestion_recovery_start_time = None;

    cubic.w_max = r.congestion_window as f64;

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

    // Detecting spurious congestion events.
    // <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
    //
    // When the recovery episode ends with recovering
    // a few packets (less than RESTORE_COUNT_THRESHOLD), it's considered
    // as spurious and restore to the previous state.
    if r.congestion_recovery_start_time.is_some() {
        let new_lost = r.lost_count - r.cubic_state.prior.lost_count;

        if r.congestion_window < r.cubic_state.prior.congestion_window &&
            new_lost < RESTORE_COUNT_THRESHOLD
        {
            rollback(r);
            return;
        }
    }

    if r.congestion_window < r.ssthresh {
        // In Slow slart, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        if r.bytes_acked_sl >= r.max_datagram_size {
            r.congestion_window += r.max_datagram_size;
            r.bytes_acked_sl -= r.max_datagram_size;
        }

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

                r.cubic_state.w_est = r.congestion_window as f64;
                r.cubic_state.alpha_aimd = ALPHA_AIMD;
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

                    r.cubic_state.w_est = r.congestion_window as f64;
                    r.cubic_state.alpha_aimd = ALPHA_AIMD;
                },
            }
        }

        let t = now - ca_start_time;

        // target = w_cubic(t + rtt)
        let target = r.cubic_state.w_cubic(t + r.min_rtt, r.max_datagram_size);

        // Clipping target to [cwnd, 1.5 x cwnd]
        let target = f64::max(target, r.congestion_window as f64);
        let target = f64::min(target, r.congestion_window as f64 * 1.5);

        // Update w_est.
        let w_est_inc = r.cubic_state.w_est_inc(
            packet.size,
            r.congestion_window,
            r.max_datagram_size,
        );
        r.cubic_state.w_est += w_est_inc;

        if r.cubic_state.w_est >= r.cubic_state.w_max {
            r.cubic_state.alpha_aimd = 1.0;
        }

        let mut cubic_cwnd = r.congestion_window;

        if r.cubic_state.w_cubic(t, r.max_datagram_size) < r.cubic_state.w_est {
            // AIMD friendly region (W_cubic(t) < W_est)
            cubic_cwnd = cmp::max(cubic_cwnd, r.cubic_state.w_est as usize);
        } else {
            // Concave region or convex region use same increment.
            let cubic_inc =
                r.max_datagram_size * (target as usize - cubic_cwnd) / cubic_cwnd;

            cubic_cwnd += cubic_inc;
        }

        // When in Limited Slow Start, take the max of CA cwnd and
        // LSS cwnd.
        if r.hystart.in_lss(epoch) {
            let lss_cwnd_inc = r.hystart.lss_cwnd_inc(
                packet.size,
                r.congestion_window,
                r.ssthresh,
            );

            cubic_cwnd = cmp::max(cubic_cwnd, r.congestion_window + lss_cwnd_inc);
        }

        // Update the increment and increase cwnd by MSS.
        r.cubic_state.cwnd_inc += cubic_cwnd - r.congestion_window;

        if r.cubic_state.cwnd_inc >= r.max_datagram_size {
            r.congestion_window += r.max_datagram_size;
            r.cubic_state.cwnd_inc -= r.max_datagram_size;
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
        if (r.congestion_window as f64) < r.cubic_state.w_max {
            r.cubic_state.w_max =
                r.congestion_window as f64 * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            r.cubic_state.w_max = r.congestion_window as f64;
        }

        r.ssthresh = (r.congestion_window as f64 * BETA_CUBIC) as usize;
        r.ssthresh = cmp::max(
            r.ssthresh,
            r.max_datagram_size * recovery::MINIMUM_WINDOW_PACKETS,
        );
        r.congestion_window = r.ssthresh;

        r.cubic_state.k = if r.cubic_state.w_max < r.congestion_window as f64 {
            0.0
        } else {
            r.cubic_state
                .cubic_k(r.congestion_window, r.max_datagram_size)
        };

        r.cubic_state.cwnd_inc =
            (r.cubic_state.cwnd_inc as f64 * BETA_CUBIC) as usize;

        r.cubic_state.w_est = r.congestion_window as f64;
        r.cubic_state.alpha_aimd = ALPHA_AIMD;

        if r.hystart.in_lss(epoch) {
            r.hystart.congestion_event();
        }
    }
}

fn checkpoint(r: &mut Recovery) {
    r.cubic_state.prior.congestion_window = r.congestion_window;
    r.cubic_state.prior.ssthresh = r.ssthresh;
    r.cubic_state.prior.w_max = r.cubic_state.w_max;
    r.cubic_state.prior.k = r.cubic_state.k;
    r.cubic_state.prior.epoch_start = r.congestion_recovery_start_time;
    r.cubic_state.prior.lost_count = r.lost_count;
}

fn rollback(r: &mut Recovery) {
    r.congestion_window = r.cubic_state.prior.congestion_window;
    r.ssthresh = r.cubic_state.prior.ssthresh;
    r.cubic_state.w_max = r.cubic_state.prior.w_max;
    r.cubic_state.k = r.cubic_state.prior.k;
    r.congestion_recovery_start_time = r.cubic_state.prior.epoch_start;
}

fn has_custom_pacing() -> bool {
    false
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
    fn cubic_slow_start_multi_acks() {
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
                size: p.size,
            },
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
            },
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
            },
        ];

        r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);

        // Acked 3 packets.
        assert_eq!(r.cwnd(), cwnd_prev + p.size * 3);
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
        let mut now = Instant::now();
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

        // Shift current time by 1 RTT.
        let rtt = Duration::from_millis(100);

        r.update_rtt(rtt, Duration::from_millis(0), now);

        // Exit from the recovery.
        now += rtt;

        // To avoid rollback
        r.lost_count += RESTORE_COUNT_THRESHOLD;

        // During Congestion Avoidance, it will take
        // 5 ACKs to increase cwnd by 1 MSS.
        for _ in 0..5 {
            let acked = vec![Acked {
                pkt_num: 0,
                time_sent: now,
                size: r.max_datagram_size,
            }];

            r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);
            now += rtt;
        }

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

    #[test]
    fn cubic_spurious_congestion_event() {
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

        // Trigger detecting sprurious congestion event
        r.on_packets_acked(
            acked,
            packet::EPOCH_APPLICATION,
            now + rtt + Duration::from_millis(5),
        );

        // cwnd is restored to the previous one.
        assert_eq!(r.cwnd(), prev_cwnd);
    }

    #[test]
    fn cubic_fast_convergence() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::CUBIC);

        let mut r = Recovery::new(&cfg);
        let mut now = Instant::now();
        let prev_cwnd = r.cwnd();

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..recovery::INITIAL_WINDOW_PACKETS {
            r.on_packet_sent_cc(r.max_datagram_size, now);
        }

        // Trigger congestion event to update ssthresh
        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // After 1st congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(r.cwnd(), cur_cwnd);

        // Shift current time by 1 RTT.
        let rtt = Duration::from_millis(100);
        r.update_rtt(rtt, Duration::from_millis(0), now);

        // Exit from the recovery.
        now += rtt;

        // To avoid rollback
        r.lost_count += RESTORE_COUNT_THRESHOLD;

        // During Congestion Avoidance, it will take
        // 5 ACKs to increase cwnd by 1 MSS.
        for _ in 0..5 {
            let acked = vec![Acked {
                pkt_num: 0,
                time_sent: now,
                size: r.max_datagram_size,
            }];

            r.on_packets_acked(acked, packet::EPOCH_APPLICATION, now);
            now += rtt;
        }

        assert_eq!(r.cwnd(), cur_cwnd + r.max_datagram_size);

        let prev_cwnd = r.cwnd();

        // Fast convergence: now there is 2nd congestion event and
        // cwnd is not fully recovered to w_max, w_max will be
        // further reduced.
        r.congestion_event(now, packet::EPOCH_APPLICATION, now);

        // After 2nd congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(r.cwnd(), cur_cwnd);

        // w_max will be further reduced, not prev_cwnd
        assert_eq!(
            r.cubic_state.w_max,
            prev_cwnd as f64 * (1.0 + BETA_CUBIC) / 2.0
        );
    }
}
