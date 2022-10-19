// Copyright (C) 2022, Cloudflare, Inc.
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

//! Prague Congestion Control

use std::time::Duration;
use std::time::Instant;

use crate::packet;
use crate::recovery;
use crate::recovery::reno;

use crate::recovery::Acked;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;
use crate::recovery::Sent;

pub static PRAGUE: CongestionControlOps = CongestionControlOps {
    on_init,
    reset,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    process_ecn,
    collapse_cwnd,
    checkpoint,
    rollback,
    has_custom_pacing,
    debug_fmt,
};

/// The gain of the EWMA (1/16).
const G: f64 = 1.0 / 16.0;

// Minimum virtual RTT used to reduce the bias of small RTTs.
const RTT_VIRT_MIN: Duration = Duration::from_millis(25);

// The number of iterations before it starts being in reduced RTT-dependence.
const D: u32 = 500;

/// Prague State Variables.
#[derive(Debug, Default)]
pub struct State {
    /// Largest sent packet number set at the start of the round for EWMA,
    /// different from the common state that tracks round for CWR.
    largest_sent_pn: [u64; packet::Epoch::count()],

    /// Moving Average of ECN Feedback, as defined in Section 2.3.2 of
    /// https://www.ietf.org/archive/id/draft-briscoe-iccrg-prague-congestion-control-01.html
    alpha: f64,

    /// The rtt_virt/srtt ratio, ensured to be >= 1.0.
    rtt_virt_ratio: f64,

    reduced_due_to_ce: bool,

    /// The number of newly marked CE packets during this RTT.
    newly_ce_marked: u64,

    /// The number of newly acknowledged packets during this RTT.
    newly_acknowledged: u64,

    /// The number of CE congestion events.
    ce_event_cnt: u64,

    /// Time of the first packet sent ever.
    first_sent_packet_time: Option<Instant>,
}

fn on_init(_r: &mut Recovery) {}

fn reset(r: &mut Recovery) {
    r.prague_state = State::default();
    r.prague_state.alpha = 1.0;
}

fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, now: Instant) {
    if r.prague_state.first_sent_packet_time.is_none() {
        r.prague_state.first_sent_packet_time = Some(now);
    }
    reno::on_packet_sent(r, sent_bytes, now);
}

fn update_pacer_state(r: &mut Recovery, now: Instant) {
    let mut rate = if r.congestion_window < r.ssthresh {
        2.0 * r.congestion_window as f64
    } else {
        r.congestion_window as f64
    };
    rate /= r
        .smoothed_rtt
        .unwrap_or(recovery::INITIAL_RTT)
        .as_secs_f64();

    // Burst queue of at least 250 us.
    let burst = rate / (2.0_f64).powi(12);

    r.pacer
        .update(burst.round() as usize, rate.round() as u64, now);
}

fn on_packets_acked(
    r: &mut Recovery, packets: &mut Vec<Acked>, epoch: packet::Epoch,
    now: Instant,
) {
    for pkt in packets.drain(..) {
        on_packet_acked(r, &pkt, epoch, now);
    }
}

fn ca_after_ce(r: &mut Recovery, acked_bytes: usize) {
    let increase = (1.0 / r.prague_state.rtt_virt_ratio.powi(2)) *
        (acked_bytes as f64 / r.congestion_window as f64);
    r.congestion_window += increase.round() as usize;
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
        // In Slow slart, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        if r.hystart.in_css(epoch) {
            r.congestion_window += r.hystart.css_cwnd_inc(r.max_datagram_size);
        } else {
            r.congestion_window += r.max_datagram_size;
        }

        if r.hystart.on_packet_acked(epoch, packet, r.latest_rtt, now) {
            // Exit to congestion avoidance if CSS ends.
            r.ssthresh = r.congestion_window;
        }
    } else if r.prague_state.reduced_due_to_ce {
        ca_after_ce(r, packet.size);
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
    r: &mut Recovery, lost_bytes: usize, largest_lost_pkt: &Sent,
    epoch: packet::Epoch, now: Instant,
) {
    if r.in_congestion_recovery(largest_lost_pkt.time_sent) {
        return;
    }
    r.prague_state.reduced_due_to_ce = false;
    // FIXME only rely on reno for now. We could use cubic instead.
    reno::congestion_event(r, lost_bytes, largest_lost_pkt, epoch, now);

    update_pacer_state(r, now);
}

fn rtt_elapsed(r: &Recovery, epoch: packet::Epoch) -> bool {
    r.prague_state.largest_sent_pn[epoch] == 0 ||
        r.largest_acked_pkt[epoch] > r.prague_state.largest_sent_pn[epoch]
}

fn update_alpha(
    r: &mut Recovery, newly_ecn_marked_acked: u64, new_ce_counts: u64,
    epoch: packet::Epoch,
) {
    r.prague_state.newly_acknowledged += newly_ecn_marked_acked;
    r.prague_state.newly_ce_marked += new_ce_counts;

    // Update alpha only once per RTT.
    if !rtt_elapsed(r, epoch) {
        return;
    }

    if r.prague_state.newly_acknowledged == 0 {
        error!("This should not happen");
        return;
    }

    let frac = new_ce_counts as f64 / newly_ecn_marked_acked as f64;
    r.prague_state.alpha += G * (frac - r.prague_state.alpha);

    // Start a new round.
    r.prague_state.largest_sent_pn[epoch] = r.largest_sent_pkt[epoch];
    r.prague_state.newly_acknowledged = 0;
    r.prague_state.newly_ce_marked = 0;
}

fn enter_cwr(r: &mut Recovery, time_sent: Instant) {
    r.prague_state.ce_event_cnt += 1;

    let in_congestion_recovery = r.in_congestion_recovery(time_sent);
    if in_congestion_recovery {
        return;
    }

    // When we receive a CE-mark, we set ssthres to
    // (1 - alpha/2) * cwnd
    // and set cwnd to that value.
    let cwnd_float = r.congestion_window as f64;
    let reduction = (cwnd_float * r.prague_state.alpha) / 2.0;
    r.congestion_window = (cwnd_float - reduction).round() as usize;

    // Ensure at least 2 MSS.
    if r.congestion_window <
        recovery::MINIMUM_WINDOW_PACKETS * r.max_datagram_size
    {
        r.congestion_window = r.max_datagram_size;
    }
    r.ssthresh = r.congestion_window;

    r.prague_state.reduced_due_to_ce = true;
}

fn update_virt_rtt_ratio(r: &mut Recovery, now: Instant) {
    let srtt = r.smoothed_rtt.unwrap_or(recovery::INITIAL_RTT);
    let time_since_begin =
        now - r.prague_state.first_sent_packet_time.unwrap_or(now);
    if srtt >= RTT_VIRT_MIN || time_since_begin <= srtt * D {
        r.prague_state.rtt_virt_ratio = 1.0;
    } else {
        r.prague_state.rtt_virt_ratio =
            RTT_VIRT_MIN.as_secs_f64() / srtt.as_secs_f64();
    }
}

fn process_ecn(
    r: &mut Recovery, newly_ecn_marked_acked: u64, new_ce_marks: u64,
    acked_bytes: usize, largest_sent: &Sent, epoch: packet::Epoch, now: Instant,
) {
    if newly_ecn_marked_acked > 0 {
        update_alpha(r, newly_ecn_marked_acked, new_ce_marks, epoch);
    }
    if new_ce_marks == 0 {
        return;
    }
    trace!(
        "{} bytes were ACKed with {} packets newly CE marked",
        acked_bytes,
        new_ce_marks
    );

    update_virt_rtt_ratio(r, now);

    // Do not re-enter CWR twice in a RTT.
    if !rtt_elapsed(r, epoch) {
        return;
    }

    enter_cwr(r, largest_sent.time_sent);

    update_pacer_state(r, now);

    r.prague_state.largest_sent_pn[epoch] = r.largest_sent_pkt[epoch];
}

fn collapse_cwnd(r: &mut Recovery) {
    reno::collapse_cwnd(r);
}

fn checkpoint(_r: &mut Recovery) {}

fn rollback(_r: &mut Recovery) -> bool {
    // From reno
    true
}

fn has_custom_pacing() -> bool {
    true
}

fn debug_fmt(_r: &Recovery, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::recovery;

    use super::*;
    use smallvec::smallvec;

    #[test]
    fn prague_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Prague);

        let r = Recovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight, 0);
    }

    #[test]
    fn prague_send() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Prague);

        let mut r = Recovery::new(&cfg);

        let now = Instant::now();

        r.on_packet_sent_cc(1000, now);

        assert_eq!(r.bytes_in_flight, 1000);
    }

    #[test]
    fn prague_slow_start() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Prague);

        let mut r = Recovery::new(&cfg);

        let now = Instant::now();

        let p = recovery::Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            first_sent_time: std::time::Instant::now(),
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            ecn_marked: false,
        };

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..r.initial_congestion_window_packets {
            r.on_packet_sent_cc(p.size, now);
        }

        let cwnd_prev = r.cwnd();

        let mut acked = vec![Acked {
            pkt_num: p.pkt_num,
            time_sent: p.time_sent,
            size: p.size,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            rtt: Duration::ZERO,
        }];

        r.on_packets_acked(&mut acked, packet::Epoch::Application, now);

        // Check if cwnd increased by packet size (slow start).
        assert_eq!(r.cwnd(), cwnd_prev + p.size);
    }

    #[test]
    fn prague_slow_start_multi_acks() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Prague);

        let mut r = Recovery::new(&cfg);

        let now = Instant::now();

        let p = recovery::Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            first_sent_time: std::time::Instant::now(),
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            ecn_marked: false,
        };

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..r.initial_congestion_window_packets {
            r.on_packet_sent_cc(p.size, now);
        }

        let cwnd_prev = r.cwnd();

        let mut acked = vec![
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                rtt: Duration::ZERO,
            },
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                rtt: Duration::ZERO,
            },
            Acked {
                pkt_num: p.pkt_num,
                time_sent: p.time_sent,
                size: p.size,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                rtt: Duration::ZERO,
            },
        ];

        r.on_packets_acked(&mut acked, packet::Epoch::Application, now);

        // Acked 3 packets.
        assert_eq!(r.cwnd(), cwnd_prev + p.size * 3);
    }

    #[test]
    fn prague_congestion_event() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Prague);

        let mut r = Recovery::new(&cfg);

        let prev_cwnd = r.cwnd();

        let now = Instant::now();

        let p = recovery::Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            first_sent_time: std::time::Instant::now(),
            is_app_limited: false,
            has_data: false,
            tx_in_flight: 0,
            lost: 0,
            ecn_marked: false,
        };

        r.congestion_event(
            r.max_datagram_size,
            &p,
            packet::Epoch::Application,
            now,
        );

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, r.cwnd());
    }

    #[test]
    fn prague_congestion_avoidance() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::Prague);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let prev_cwnd = r.cwnd();

        // Fill up bytes_in_flight to avoid app_limited=true
        r.on_packet_sent_cc(20000, now);

        let p = recovery::Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: r.max_datagram_size,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            first_sent_time: std::time::Instant::now(),
            is_app_limited: false,
            has_data: false,
            tx_in_flight: 0,
            lost: 0,
            ecn_marked: false,
        };

        // Trigger congestion event to update ssthresh
        r.congestion_event(
            r.max_datagram_size,
            &p,
            packet::Epoch::Application,
            now,
        );

        // After congestion event, cwnd will be reduced.
        let cur_cwnd =
            (prev_cwnd as f64 * recovery::LOSS_REDUCTION_FACTOR) as usize;
        assert_eq!(r.cwnd(), cur_cwnd);

        let rtt = Duration::from_millis(100);

        let mut acked = vec![Acked {
            pkt_num: 0,
            // To exit from recovery
            time_sent: now + rtt,
            // More than cur_cwnd to increase cwnd
            size: 8000,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            rtt: Duration::ZERO,
        }];

        // Ack more than cwnd bytes with rtt=100ms
        r.update_rtt(rtt, Duration::from_millis(0), now);
        r.on_packets_acked(&mut acked, packet::Epoch::Application, now + rtt * 2);

        // After acking more than cwnd, expect cwnd increased by MSS
        assert_eq!(r.cwnd(), cur_cwnd + r.max_datagram_size);
    }
}
