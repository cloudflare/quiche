use std::time::Instant;

use crate::recovery;

use crate::recovery::congestion::Acked;
use crate::recovery::rtt::RttStats;
use crate::recovery::Sent;

use super::Congestion;
use super::CongestionControlOps;

const GIGABYTE: usize = 1usize << 30;

pub(crate) static CONGESTION_WINDOW_UNCHECKED: CongestionControlOps =
    CongestionControlOps {
        on_init,
        on_packet_sent,
        on_packets_acked,
        congestion_event,
        checkpoint,
        rollback,
        has_custom_pacing,
        #[cfg(feature = "qlog")]
        state_str,
        debug_fmt,
    };

pub fn on_init(r: &mut Congestion) {
    r.congestion_window = 16 * GIGABYTE;
}

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

    if r.congestion_window < r.ssthresh.get() {
        // In Slow start, bytes_acked_sl is used for counting
        // acknowledged bytes.
        r.bytes_acked_sl += packet.size;

        r.congestion_window = 16 * GIGABYTE;

        if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
            // Exit to congestion avoidance if CSS ends.
            r.ssthresh.update(r.congestion_window, true);
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
        r.congestion_window = 16 * GIGABYTE;

        r.bytes_acked_ca = (r.congestion_window as f64 *
            recovery::LOSS_REDUCTION_FACTOR) as usize;

        r.ssthresh.update(r.congestion_window, r.hystart.in_css());

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

#[cfg(feature = "qlog")]
fn state_str(_r: &Congestion, _now: Instant) -> &'static str {
    "congestion_window_unchecked"
}

fn debug_fmt(_r: &Congestion, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
    Ok(())
}
