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

use crate::recovery;
use crate::recovery::rtt::RttStats;
use crate::recovery::Acked;
use crate::recovery::Sent;

use super::reno;
use super::Congestion;
use super::CongestionControlOps;

pub(crate) static CUBIC: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    has_custom_pacing,
    debug_fmt,
};

/// CUBIC Constants.
///
/// These are recommended value in RFC8312.
const BETA_CUBIC: f64 = 0.7;

const C: f64 = 0.4;

/// Threshold for rolling back state, as percentage of lost packets relative to
/// cwnd.
const ROLLBACK_THRESHOLD_PERCENT: usize = 20;

/// Minimum threshold for rolling back state, as number of packets.
const MIN_ROLLBACK_THRESHOLD: usize = 2;

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

fn on_init(_r: &mut Congestion) {}

fn on_packet_sent(
    r: &mut Congestion, sent_bytes: usize, bytes_in_flight: usize, now: Instant,
) {
    // See https://github.com/torvalds/linux/commit/30927520dbae297182990bb21d08762bcc35ce1d
    // First transmit when no packets in flight
    let cubic = &mut r.cubic_state;

    if let Some(last_sent_time) = cubic.last_sent_time {
        if bytes_in_flight == 0 {
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

    reno::on_packet_sent(r, sent_bytes, bytes_in_flight, now);
}

fn on_packets_acked(
    r: &mut Congestion, bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, rtt_stats: &RttStats,
) {
    for pkt in packets.drain(..) {
        on_packet_acked(r, bytes_in_flight, &pkt, now, rtt_stats);
    }
}

fn on_packet_acked(
    r: &mut Congestion, bytes_in_flight: usize, packet: &Acked, now: Instant,
    rtt_stats: &RttStats,
) {
    let in_congestion_recovery = r.in_congestion_recovery(packet.time_sent);

    if in_congestion_recovery {
        r.prr.on_packet_acked(
            packet.size,
            bytes_in_flight,
            r.ssthresh,
            r.max_datagram_size,
        );

        return;
    }

    if r.app_limited {
        return;
    }

    // Detecting spurious congestion events.
    // <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
    //
    // When the recovery episode ends with recovering
    // a few packets (less than cwnd / mss * ROLLBACK_THRESHOLD_PERCENT(%)), it's
    // considered as spurious and restore to the previous state.
    if r.congestion_recovery_start_time.is_some() {
        let new_lost = r.lost_count - r.cubic_state.prior.lost_count;

        let rollback_threshold = (r.congestion_window / r.max_datagram_size) *
            ROLLBACK_THRESHOLD_PERCENT /
            100;

        let rollback_threshold = rollback_threshold.max(MIN_ROLLBACK_THRESHOLD);

        if new_lost < rollback_threshold {
            let did_rollback = rollback(r);
            if did_rollback {
                return;
            }
        }
    }

    if r.congestion_window < r.ssthresh {
        // In Slow slart, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        if r.bytes_acked_sl >= r.max_datagram_size {
            if r.hystart.in_css() {
                r.congestion_window +=
                    r.hystart.css_cwnd_inc(r.max_datagram_size);
            } else {
                r.congestion_window += r.max_datagram_size;
            }

            r.bytes_acked_sl -= r.max_datagram_size;
        }

        if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
            // Exit to congestion avoidance if CSS ends.
            r.ssthresh = r.congestion_window;
        }
    } else {
        // Congestion avoidance.
        let ca_start_time;

        // In CSS, use css_start_time instead of congestion_recovery_start_time.
        if r.hystart.in_css() {
            ca_start_time = r.hystart.css_start_time().unwrap();

            // Reset w_max and k when CSS started.
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

        let t = now.saturating_duration_since(ca_start_time);

        // target = w_cubic(t + rtt)
        let target = r
            .cubic_state
            .w_cubic(t + *rtt_stats.min_rtt, r.max_datagram_size);

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

        // Update the increment and increase cwnd by MSS.
        r.cubic_state.cwnd_inc += cubic_cwnd - r.congestion_window;

        if r.cubic_state.cwnd_inc >= r.max_datagram_size {
            r.congestion_window += r.max_datagram_size;
            r.cubic_state.cwnd_inc -= r.max_datagram_size;
        }
    }
}

fn congestion_event(
    r: &mut Congestion, bytes_in_flight: usize, _lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant,
) {
    let time_sent = largest_lost_pkt.time_sent;
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

        if r.hystart.in_css() {
            r.hystart.congestion_event();
        }

        r.prr.congestion_event(bytes_in_flight);
    }
}

fn checkpoint(r: &mut Congestion) {
    r.cubic_state.prior.congestion_window = r.congestion_window;
    r.cubic_state.prior.ssthresh = r.ssthresh;
    r.cubic_state.prior.w_max = r.cubic_state.w_max;
    r.cubic_state.prior.k = r.cubic_state.k;
    r.cubic_state.prior.epoch_start = r.congestion_recovery_start_time;
    r.cubic_state.prior.lost_count = r.lost_count;
}

fn rollback(r: &mut Congestion) -> bool {
    // Don't go back to slow start.
    if r.cubic_state.prior.congestion_window < r.cubic_state.prior.ssthresh {
        return false;
    }

    if r.congestion_window >= r.cubic_state.prior.congestion_window {
        return false;
    }

    r.congestion_window = r.cubic_state.prior.congestion_window;
    r.ssthresh = r.cubic_state.prior.ssthresh;
    r.cubic_state.w_max = r.cubic_state.prior.w_max;
    r.cubic_state.k = r.cubic_state.prior.k;
    r.congestion_recovery_start_time = r.cubic_state.prior.epoch_start;

    true
}

fn has_custom_pacing() -> bool {
    false
}

fn debug_fmt(r: &Congestion, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(
        f,
        "cubic={{ k={} w_max={} }} ",
        r.cubic_state.k, r.cubic_state.w_max
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::CongestionControlAlgorithm;

    use crate::recovery::congestion::hystart;
    use crate::recovery::congestion::test_sender::TestSender;
    use crate::recovery::Recovery;

    fn test_sender() -> TestSender {
        TestSender::new(recovery::CongestionControlAlgorithm::CUBIC, false)
    }

    fn hystart_test_sender() -> TestSender {
        TestSender::new(recovery::CongestionControlAlgorithm::CUBIC, true)
    }

    #[test]
    fn cubic_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::CUBIC);

        let r = Recovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight, 0);
    }

    #[test]
    fn cubic_slow_start() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(1, size);

        // Check if cwnd increased by packet size (slow start)
        assert_eq!(sender.congestion_window, cwnd_prev + size);
    }

    #[test]
    fn cubic_slow_start_multi_acks() {
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
    fn cubic_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        sender.send_packet(size);

        let cwnd_prev = sender.congestion_window;

        sender.lose_n_packets(1, size, None);

        // In CUBIC, after congestion event, cwnd will be reduced by (1 -
        // CUBIC_BETA)
        assert_eq!(
            cwnd_prev as f64 * BETA_CUBIC,
            sender.congestion_window as f64
        );
    }

    #[test]
    fn cubic_congestion_avoidance() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        // Trigger congestion event to update ssthresh
        sender.lose_n_packets(1, size, None);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        // Shift current time by 1 RTT.
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);
        // Exit from the recovery.
        sender.advance_time(rtt);

        // During Congestion Avoidance, it will take
        // 5 ACKs to increase cwnd by 1 MSS.
        for _ in 0..5 {
            sender.ack_n_packets(1, size);
            sender.advance_time(rtt);
        }

        assert_eq!(sender.congestion_window, cur_cwnd + size);
    }

    #[test]
    fn cubic_hystart_css_to_ss() {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample, size);

        // Not in CSS yet.
        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round.
        let mut rtt_2nd = Duration::from_millis(100);

        sender.advance_time(rtt_2nd);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 2nd round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to CSS.
        let mut cwnd_prev = sender.congestion_window();

        for _ in 0..n_rtt_sample {
            cwnd_prev = sender.congestion_window();
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1, size);
            // Keep increasing RTT so that hystart exits to CSS.
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        // Now we are in CSS.
        assert!(sender.hystart.css_start_time().is_some());
        assert_eq!(sender.congestion_window(), cwnd_prev + size);

        // 3rd round, which RTT is less than previous round to
        // trigger back to Slow Start.
        let rtt_3rd = Duration::from_millis(80);
        sender.advance_time(rtt_3rd);
        cwnd_prev = sender.congestion_window();

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 3nd round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to SS.
        sender.update_rtt(rtt_3rd);
        sender.ack_n_packets(n_rtt_sample, size);

        // Now we are back in Slow Start.
        assert!(sender.hystart.css_start_time().is_none());
        assert_eq!(
            sender.congestion_window(),
            cwnd_prev +
                size / hystart::CSS_GROWTH_DIVISOR * hystart::N_RTT_SAMPLE
        );
    }

    #[test]
    fn cubic_hystart_css_to_ca() {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample, size);

        // Not in CSS yet.
        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round.
        let mut rtt_2nd = Duration::from_millis(100);
        sender.advance_time(rtt_2nd);
        // Send 2nd round packets.
        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to CSS.
        let mut cwnd_prev = sender.congestion_window();

        for _ in 0..n_rtt_sample {
            cwnd_prev = sender.congestion_window();
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1, size);
            // Keep increasing RTT so that hystart exits to CSS.
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        // Now we are in CSS.
        assert!(sender.hystart.css_start_time().is_some());
        assert_eq!(sender.congestion_window(), cwnd_prev + size);

        // Run 5 (CSS_ROUNDS) in CSS, to exit to congestion avoidance.
        let rtt_css = Duration::from_millis(100);
        sender.advance_time(rtt_css);

        for _ in 0..hystart::CSS_ROUNDS {
            // Send a round of packets.
            let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
            sender.hystart.start_round(next_rnd);
            for _ in 0..n_rtt_sample {
                sender.send_packet(size);
            }
            sender.update_app_limited(false);

            // Receiving Acks.
            sender.update_rtt(rtt_css);
            sender.ack_n_packets(n_rtt_sample, size);
        }
        // Now we are in congestion avoidance.
        assert_eq!(sender.congestion_window(), sender.ssthresh);
    }

    #[test]
    fn cubic_spurious_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window();

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.lose_n_packets(1, size, None);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window(), cur_cwnd);

        // Ack more than cwnd bytes with rtt=100ms
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);

        let acked = Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: sender.time + rtt,
            size,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };

        // Trigger detecting spurious congestion event
        sender.inject_ack(acked, sender.time + rtt + Duration::from_millis(5));

        // This is from slow start, no rollback.
        assert_eq!(sender.congestion_window(), cur_cwnd);

        sender.advance_time(rtt);

        let prev_cwnd = sender.congestion_window();

        sender.lose_n_packets(1, size, Some(sender.time));

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = (cur_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window(), cur_cwnd);

        sender.advance_time(rtt + Duration::from_millis(5));

        let acked = Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: sender.time + rtt,
            size,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };

        // Trigger detecting spurious congestion event.
        sender.inject_ack(acked, sender.time + rtt + Duration::from_millis(5));

        // cwnd is rolled back to the previous one.
        assert_eq!(sender.congestion_window(), prev_cwnd);
    }

    #[test]
    fn cubic_fast_convergence() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.congestion_window;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        // Trigger congestion event to update ssthresh
        sender.lose_n_packets(1, size, None);

        // After 1st congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        // Shift current time by 1 RTT.
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);
        // Exit from the recovery.
        sender.advance_time(rtt);

        // During Congestion Avoidance, it will take
        // 5 ACKs to increase cwnd by 1 MSS.
        for _ in 0..5 {
            sender.ack_n_packets(1, size);
            sender.advance_time(rtt);
        }

        assert_eq!(sender.congestion_window, cur_cwnd + size);

        let prev_cwnd = sender.congestion_window;

        // Fast convergence: now there is 2nd congestion event and
        // cwnd is not fully recovered to w_max, w_max will be
        // further reduced.
        sender.lose_n_packets(1, size, None);

        // After 2nd congestion event, cwnd will be reduced.
        let cur_cwnd = (prev_cwnd as f64 * BETA_CUBIC) as usize;
        assert_eq!(sender.congestion_window, cur_cwnd);

        // w_max will be further reduced, not prev_cwnd
        assert_eq!(
            sender.cubic_state.w_max,
            prev_cwnd as f64 * (1.0 + BETA_CUBIC) / 2.0
        );
    }
}
