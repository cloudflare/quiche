// Brutal congestion control, as used by Hysteria 2.
//
// Semantics follow apernet/hysteria core/internal/congestion/brutal/brutal.go:
// send at a fixed target rate, divide the rate (and scale the cwnd) by the
// observed ACK rate so that random loss does not reduce goodput. The ACK rate
// is sampled over the last 5 one-second slots, needs at least 50 samples and is
// never below 0.8. cwnd = rate * srtt * 2 / ack_rate, at least one datagram.

use std::time::Duration;
use std::time::Instant;

use super::Acked;
use super::Bandwidth;
use super::CongestionControl;
use super::Lost;
use crate::recovery::rtt::RttStats;
use crate::recovery::RecoveryStats;

const SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CWND_MULTIPLIER: f64 = 2.0;
/// Floor on the RTT the cwnd is sized from. Hysteria has none, but its sender
/// reacts to ACKs within microseconds. A sender with coarser ACK handling and
/// timers, whose RTT samples also exclude the peer's ACK delay, is otherwise
/// cwnd-bound far below the target rate on sub-millisecond paths (measured:
/// 55 -> 72 Mbit/s at 100 Mbit/s target, 5% loss, loopback-like RTT). It has no
/// effect once srtt exceeds it.
const MIN_CWND_RTT: Duration = Duration::from_millis(2);
/// cwnd used until the first RTT sample (Hysteria: 10240).
const INITIAL_CWND: usize = 10240;

#[derive(Debug, Default, Clone, Copy)]
struct Slot {
    second: u64,
    acked: u64,
    lost: u64,
}

#[derive(Debug)]
pub(crate) struct Brutal {
    bytes_per_second: u64,
    mss: usize,
    slots: [Slot; SLOT_COUNT],
    ack_rate: f64,
    /// Slot index is the second since the first congestion event.
    epoch: Option<Instant>,
    srtt: Option<Duration>,
}

impl Brutal {
    pub(crate) fn new(bytes_per_second: u64, mss: usize) -> Self {
        Brutal {
            bytes_per_second,
            mss,
            slots: Default::default(),
            ack_rate: 1.0,
            epoch: None,
            srtt: None,
        }
    }

    fn update_ack_rate(&mut self, now_sec: u64) {
        let min_sec = now_sec.saturating_sub(SLOT_COUNT as u64);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|s| s.second >= min_sec)
            .fold((0, 0), |(a, l), s| (a + s.acked, l + s.lost));

        self.ack_rate = if acked + lost < MIN_SAMPLE_COUNT {
            1.0
        } else {
            (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
        };
    }

    #[cfg(test)]
    pub(crate) fn ack_rate_factor(&self) -> f64 {
        self.ack_rate
    }

    pub(crate) fn time_sent_set_to_now(&self) -> bool {
        false
    }
}

impl CongestionControl for Brutal {
    #[cfg(feature = "qlog")]
    fn state_str(&self) -> &'static str {
        "brutal"
    }

    fn get_congestion_window(&self) -> usize {
        match self.srtt {
            None => INITIAL_CWND,
            Some(rtt) => ((self.bytes_per_second as f64
                * rtt.max(MIN_CWND_RTT).as_secs_f64()
                * CWND_MULTIPLIER
                / self.ack_rate) as usize)
                .max(self.mss),
        }
    }

    fn get_congestion_window_in_packets(&self) -> usize {
        self.get_congestion_window() / self.mss
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight <= self.get_congestion_window()
    }

    fn on_packet_sent(
        &mut self, _sent_time: Instant, _bytes_in_flight: usize,
        _packet_number: u64, _bytes: usize, _is_retransmissible: bool,
    ) {
    }

    fn on_congestion_event(
        &mut self, rtt_updated: bool, _prior_in_flight: usize,
        _bytes_in_flight: usize, event_time: Instant, acked_packets: &[Acked],
        lost_packets: &[Lost], _least_unacked: u64, rtt_stats: &RttStats,
        _recovery_stats: &mut RecoveryStats,
    ) {
        if rtt_updated || self.srtt.is_some() {
            self.srtt = Some(rtt_stats.smoothed_rtt);
        }

        let epoch = *self.epoch.get_or_insert(event_time);
        let now_sec = event_time.saturating_duration_since(epoch).as_secs();
        let slot = &mut self.slots[(now_sec % SLOT_COUNT as u64) as usize];
        if slot.second != now_sec {
            *slot = Slot {
                second: now_sec,
                ..Default::default()
            };
        }
        slot.acked += acked_packets.len() as u64;
        slot.lost += lost_packets.len() as u64;

        self.update_ack_rate(now_sec);
    }

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn on_connection_migration(&mut self) {}

    fn is_in_recovery(&self) -> bool {
        false
    }

    fn is_cwnd_limited(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight >= self.get_congestion_window()
    }

    fn pacing_rate(
        &self, _bytes_in_flight: usize, _rtt_stats: &RttStats,
    ) -> Bandwidth {
        Bandwidth::from_bytes_per_second(
            (self.bytes_per_second as f64 / self.ack_rate) as u64,
        )
    }

    fn bandwidth_estimate(&self, _rtt_stats: &RttStats) -> Bandwidth {
        Bandwidth::from_bytes_per_second(self.bytes_per_second)
    }

    fn max_bandwidth(&self) -> Bandwidth {
        Bandwidth::from_bytes_per_second(self.bytes_per_second)
    }

    fn update_mss(&mut self, new_mss: usize) {
        self.mss = new_mss;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: usize = 1200;
    const BPS: u64 = 12_500_000; // 100 Mbit/s

    fn rtt(ms: u64) -> RttStats {
        let mut r = RttStats::new(Duration::from_millis(333), Duration::ZERO);
        r.update_rtt(
            Duration::from_millis(ms),
            Duration::ZERO,
            Instant::now(),
            true,
        );
        r
    }

    fn event(
        b: &mut Brutal, t: Instant, acked: usize, lost: usize, r: &RttStats,
    ) {
        let a: Vec<Acked> = (0..acked as u64)
            .map(|i| Acked {
                pkt_num: i,
                time_sent: t,
            })
            .collect();
        let l: Vec<Lost> = (0..lost as u64)
            .map(|i| Lost {
                packet_number: i,
                bytes_lost: MSS,
            })
            .collect();
        b.on_congestion_event(
            true,
            0,
            0,
            t,
            &a,
            &l,
            0,
            r,
            &mut RecoveryStats::default(),
        );
    }

    #[test]
    fn no_loss_rate_and_cwnd_follow_target() {
        let r = rtt(50);
        let mut b = Brutal::new(BPS, MSS);
        assert_eq!(b.get_congestion_window(), INITIAL_CWND);
        event(&mut b, Instant::now(), 100, 0, &r);
        assert_eq!(b.pacing_rate(0, &r).to_bytes_per_second(), BPS);
        // 12.5 MB/s * 0.05 s * 2
        assert_eq!(b.get_congestion_window(), 1_250_000);
    }

    #[test]
    fn loss_scales_rate_and_cwnd_by_ack_rate() {
        let r = rtt(50);
        let mut b = Brutal::new(BPS, MSS);
        event(&mut b, Instant::now(), 95, 5, &r); // ack rate 0.95
        let expect = (BPS as f64 / 0.95) as u64;
        assert_eq!(b.pacing_rate(0, &r).to_bytes_per_second(), expect);
        assert_eq!(
            b.get_congestion_window(),
            (BPS as f64 * 0.05 * 2.0 / 0.95) as usize
        );
    }

    #[test]
    fn ack_rate_floor_and_min_samples() {
        let r = rtt(50);
        let mut b = Brutal::new(BPS, MSS);
        event(&mut b, Instant::now(), 10, 30, &r); // 40 < 50 samples
        assert_eq!(b.ack_rate_factor(), 1.0);
        let mut b = Brutal::new(BPS, MSS);
        event(&mut b, Instant::now(), 20, 80, &r); // 0.2 -> floor 0.8
        assert_eq!(b.ack_rate_factor(), 0.8);
        assert_eq!(
            b.pacing_rate(0, &r).to_bytes_per_second(),
            (BPS as f64 / 0.8) as u64
        );
    }

    #[test]
    fn old_slots_expire_after_five_seconds() {
        let r = rtt(50);
        let mut b = Brutal::new(BPS, MSS);
        let t0 = Instant::now();
        event(&mut b, t0, 80, 20, &r);
        assert_eq!(b.ack_rate_factor(), 0.8);
        event(&mut b, t0 + Duration::from_secs(7), 100, 0, &r);
        assert_eq!(b.ack_rate_factor(), 1.0);
    }

    #[test]
    fn cwnd_rtt_is_floored() {
        let mut b = Brutal::new(BPS, MSS);
        event(&mut b, Instant::now(), 100, 0, &rtt(0)); // sub-ms path
        // 12.5 MB/s * 2 ms * 2
        assert_eq!(b.get_congestion_window(), 50_000);
    }

    #[test]
    fn cwnd_is_at_least_one_datagram() {
        let r = rtt(1);
        let mut b = Brutal::new(1000, MSS);
        event(&mut b, Instant::now(), 1, 0, &r);
        assert_eq!(b.get_congestion_window(), MSS);
    }
}
