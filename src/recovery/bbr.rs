use crate::minmax::Minmax;
use crate::packet;
use crate::rand;
use crate::recovery::Acked;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;
use std::f64::consts::LN_2;
use std::time::Duration;
use std::time::Instant;

const HIGH_GAIN: f64 = 2.0 / LN_2;
const RTT_WINDOW: Duration = Duration::from_secs(10);
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
const BW_WINDOW: u32 = 10;
const MIN_PIPE_CWND: usize = 4;
const PROBE_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

pub static BBR: CongestionControlOps = CongestionControlOps {
    on_packet_sent,
    on_packet_acked,
    congestion_event,
    collapse_cwnd,
    checkpoint,
    rollback,
    has_custom_pacing,
};

pub struct State {
    mode: Mode,

    // Bottleneck bandwidth
    bw_filter: Minmax<u32, u64>,
    bw_max: u64,

    // Round counting
    next_round_delivered: usize,
    round_start: bool,
    round_count: u32,

    // RTT
    rtt_min: Duration,
    rtt_stamp: Instant,
    rtt_expired: bool,
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,

    // Pacing
    pacing_rate: u64,
    pacing_gain: f64,

    // Filled pipe
    filled_pipe: bool,
    full_bw: u64,
    full_bw_count: u64,

    // Quantum
    send_quantum: usize,

    // CWND
    target_cwnd: usize,
    saved_cwnd: usize,
    cwnd_gain: f64,

    // BW Probing
    probe_gain_idx: usize,
    cycle_stamp: Instant,

    // Idle restart
    idle_restart: bool,

    // Loss tracking
    bytes_lost: usize,
    bytes_last_lost: usize,
    bytes_newly_lost: usize,

    // Packet conservation
    conservation: PacketConservation,
    end_conservation: usize,
}

impl Default for State {
    fn default() -> Self {
        State {
            bw_filter: Minmax::new(0, 0),
            bw_max: 0,
            mode: Mode::Startup,
            next_round_delivered: 0,
            round_start: false,
            round_count: 0,
            rtt_min: crate::recovery::INITIAL_RTT,
            rtt_stamp: Instant::now(),
            rtt_expired: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            pacing_rate: 0,
            pacing_gain: HIGH_GAIN,
            filled_pipe: false,
            full_bw: 0,
            full_bw_count: 0,
            send_quantum: 0,
            target_cwnd: 0,
            saved_cwnd: 0,
            cwnd_gain: HIGH_GAIN,
            probe_gain_idx: 0,
            cycle_stamp: Instant::now(),
            idle_restart: false,
            bytes_lost: 0,
            bytes_last_lost: 0,
            bytes_newly_lost: 0,
            conservation: PacketConservation::Normal,
            end_conservation: 0,
        }
    }
}

#[derive(PartialEq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(PartialEq)]
enum PacketConservation {
    Conservation,
    Growth,
    Normal,
}

pub fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, _now: Instant) {
    handle_restart_from_idle(r);
    r.bytes_in_flight += sent_bytes;
}

fn on_packet_acked(
    r: &mut Recovery, packet: &Acked, _epoch: packet::Epoch, now: Instant,
) {
    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(packet.size);

    r.bbr_state.bytes_newly_lost =
        r.bbr_state.bytes_lost - r.bbr_state.bytes_last_lost;
    r.bbr_state.bytes_last_lost = r.bbr_state.bytes_lost;

    update_bw(r, packet);
    check_cycle_phase(r, packet, now);
    check_full_pipe(r, packet);
    check_drain(r);
    update_rtt(r, now);
    check_probe_rtt(r, now);

    set_pacing_rate(r);
    set_send_quantum(r);
    set_cwnd(r, packet);
}

fn congestion_event(
    r: &mut Recovery, lost_bytes: usize, _time_sent: Instant,
    _epoch: packet::Epoch, _now: Instant,
) {
    r.bbr_state.bytes_lost += lost_bytes;

    if lost_bytes > 0 {
        r.bbr_state.end_conservation = r.delivery_rate.delivered();

        if r.bbr_state.conservation == PacketConservation::Normal {
            save_cwnd(r);
            r.bbr_state.conservation = PacketConservation::Conservation;
            r.congestion_window = r.bytes_in_flight + lost_bytes;
            r.bbr_state.next_round_delivered = r.delivery_rate.delivered();
        }
    }
}

pub fn collapse_cwnd(_r: &mut Recovery) {
    // TODO: Implement loss recovery
}

fn has_custom_pacing() -> bool {
    true
}

fn checkpoint(_r: &mut Recovery) {
    // TODO: Implement loss recovery
}

fn save_cwnd(r: &mut Recovery) {
    r.bbr_state.saved_cwnd = if r.bbr_state.conservation ==
        PacketConservation::Normal &&
        r.bbr_state.mode != Mode::ProbeRtt
    {
        r.congestion_window
    } else {
        std::cmp::max(r.bbr_state.saved_cwnd, r.congestion_window)
    }
}

fn rollback(_r: &mut Recovery) {
    // TODO: Implement loss recovery
}

fn restore_cwnd(r: &mut Recovery) {
    r.congestion_window =
        std::cmp::max(r.congestion_window, r.bbr_state.saved_cwnd);
}

fn update_bw(r: &mut Recovery, packet: &Acked) {
    update_round(r, packet);

    let rate = r.delivery_rate();
    if rate >= r.bbr_state.bw_max || !packet.is_app_limited {
        r.bbr_state.bw_max = r.bbr_state.bw_filter.running_max(
            BW_WINDOW,
            r.bbr_state.round_count,
            rate,
        );
    }
}

fn update_round(r: &mut Recovery, packet: &Acked) {
    if packet.delivered >= r.bbr_state.next_round_delivered {
        r.bbr_state.next_round_delivered = r.delivery_rate.delivered();
        r.bbr_state.round_count += 1;
        r.bbr_state.round_start = true;

        if r.bbr_state.conservation == PacketConservation::Conservation {
            r.bbr_state.conservation = PacketConservation::Growth;
        }
    } else {
        r.bbr_state.round_start = false;
    }

    if packet.delivered >= r.bbr_state.end_conservation {
        r.bbr_state.conservation = PacketConservation::Normal;
        restore_cwnd(r);
    }
}

fn update_rtt(r: &mut Recovery, now: Instant) {
    r.bbr_state.rtt_expired = now > r.bbr_state.rtt_stamp + RTT_WINDOW;

    if r.latest_rtt <= r.bbr_state.rtt_min || r.bbr_state.rtt_expired {
        r.bbr_state.rtt_min = r.latest_rtt;
        r.bbr_state.rtt_stamp = now;
    }
}

fn set_pacing_rate(r: &mut Recovery) {
    set_pacing_rate_gain(r, r.bbr_state.pacing_gain);
}

fn set_pacing_rate_gain(r: &mut Recovery, gain: f64) {
    let rate = (gain * r.bbr_state.bw_max as f64) as u64;

    if r.bbr_state.filled_pipe || rate > r.bbr_state.pacing_rate {
        r.bbr_state.pacing_rate = rate;
        r.pacing_rate = rate;
    }
}

fn set_send_quantum(r: &mut Recovery) {
    const LOW_THRESH: u64 = 157286; // 1.2 Mbps in MBps
    const HIGH_THRESH: u64 = 3145728; // 24 Mbps in MBps
    const HIGH_QUANTUM: usize = 65536; // 64KB

    r.bbr_state.send_quantum = if r.bbr_state.pacing_rate < LOW_THRESH {
        r.max_datagram_size()
    } else if r.bbr_state.pacing_rate < HIGH_THRESH {
        2 * r.max_datagram_size()
    } else {
        std::cmp::min((r.bbr_state.pacing_rate / 1000) as usize, HIGH_QUANTUM)
    };
}

fn inflight(r: &Recovery, gain: f64) -> usize {
    let quanta = 3 * r.bbr_state.send_quantum;
    let estimated_bdp =
        r.bbr_state.bw_max as f64 * r.bbr_state.rtt_min.as_secs_f64();
    (gain * estimated_bdp) as usize + quanta
}

fn update_target_cwnd(r: &mut Recovery) {
    r.bbr_state.target_cwnd = inflight(r, r.bbr_state.cwnd_gain);
}

fn modulate_cwnd_for_probe_rtt(r: &mut Recovery) {
    if r.bbr_state.mode == Mode::ProbeRtt {
        r.congestion_window = std::cmp::min(
            r.congestion_window,
            MIN_PIPE_CWND * r.max_datagram_size(),
        );
    }
}

fn modulate_cwnd_for_recovery(r: &mut Recovery) {
    if r.bbr_state.bytes_newly_lost > 0 {
        r.congestion_window = std::cmp::max(
            r.congestion_window - r.bbr_state.bytes_newly_lost,
            MIN_PIPE_CWND * r.max_datagram_size(),
        );
    }
}

fn set_cwnd(r: &mut Recovery, packet: &Acked) {
    update_target_cwnd(r);

    if r.bbr_state.conservation != PacketConservation::Normal {
        modulate_cwnd_for_recovery(r);
    }

    if r.bbr_state.conservation != PacketConservation::Conservation {
        if r.bbr_state.filled_pipe {
            r.congestion_window = std::cmp::min(
                r.congestion_window + packet.size,
                r.bbr_state.target_cwnd,
            );
        } else if r.congestion_window < r.bbr_state.target_cwnd ||
            r.delivery_rate.delivered() < MIN_PIPE_CWND * r.max_datagram_size()
        {
            r.congestion_window += packet.size;
        }

        r.congestion_window = std::cmp::max(
            r.congestion_window,
            MIN_PIPE_CWND * r.max_datagram_size(),
        );
    }

    modulate_cwnd_for_probe_rtt(r);
}

fn check_full_pipe(r: &mut Recovery, packet: &Acked) {
    if r.bbr_state.filled_pipe ||
        !r.bbr_state.round_start ||
        packet.is_app_limited
    {
        return;
    }

    // Check if BW still growing by more than 25%
    if r.bbr_state.bw_max >= (r.bbr_state.full_bw * 5) / 4 {
        r.bbr_state.full_bw = r.bbr_state.bw_max;
        r.bbr_state.full_bw_count = 0;
        return;
    }

    r.bbr_state.full_bw_count += 1;

    if r.bbr_state.full_bw_count >= 3 {
        r.bbr_state.filled_pipe = true;
    }
}

fn enter_startup(r: &mut Recovery) {
    r.bbr_state.mode = Mode::Startup;
    r.bbr_state.pacing_gain = HIGH_GAIN;
    r.bbr_state.cwnd_gain = HIGH_GAIN;
}

fn enter_drain(r: &mut Recovery) {
    r.bbr_state.mode = Mode::Drain;
    r.bbr_state.pacing_gain = 1.0 / HIGH_GAIN;
    r.bbr_state.cwnd_gain = HIGH_GAIN;
}

fn check_drain(r: &mut Recovery) {
    if r.bbr_state.mode == Mode::Startup && r.bbr_state.filled_pipe {
        enter_drain(r);
    }

    if r.bbr_state.mode == Mode::Drain && r.bytes_in_flight <= inflight(r, 1.0) {
        enter_probe_bw(r);
    }
}

fn enter_probe_bw(r: &mut Recovery) {
    r.bbr_state.mode = Mode::ProbeBw;
    r.bbr_state.pacing_gain = 1.0;
    r.bbr_state.cwnd_gain = 2.0;
    r.bbr_state.probe_gain_idx =
        PROBE_GAINS.len() - 1 - rand::rand_u64_uniform(7) as usize;
}

fn check_cycle_phase(r: &mut Recovery, packet: &Acked, now: Instant) {
    if r.bbr_state.mode == Mode::ProbeBw && is_next_cycle_phase(r, packet, now) {
        advance_cycle_phase(r, now);
    }
}

fn is_next_cycle_phase(r: &mut Recovery, packet: &Acked, now: Instant) -> bool {
    let is_full_length = now - r.bbr_state.cycle_stamp > r.bbr_state.rtt_min;
    let prior_inflight = r.bytes_in_flight + packet.size;

    if r.bbr_state.pacing_gain == 1.0 {
        is_full_length
    } else if r.bbr_state.pacing_gain > 1.0 {
        is_full_length &&
            (r.bbr_state.bytes_newly_lost > 0 ||
                prior_inflight >= inflight(r, r.bbr_state.pacing_gain))
    } else {
        is_full_length || prior_inflight <= inflight(r, 1.0)
    }
}

fn advance_cycle_phase(r: &mut Recovery, now: Instant) {
    r.bbr_state.cycle_stamp = now;
    r.bbr_state.probe_gain_idx =
        (r.bbr_state.probe_gain_idx + 1) % PROBE_GAINS.len();
    r.bbr_state.pacing_gain = PROBE_GAINS[r.bbr_state.probe_gain_idx];
}

fn handle_restart_from_idle(r: &mut Recovery) {
    if r.bytes_in_flight == 0 && r.app_limited() {
        r.bbr_state.idle_restart = true;
        if r.bbr_state.mode == Mode::ProbeBw {
            set_pacing_rate_gain(r, 1.0);
        }
    }
}

fn check_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr_state.mode != Mode::ProbeRtt &&
        r.bbr_state.rtt_expired &&
        !r.bbr_state.idle_restart
    {
        enter_probe_rtt(r);
        save_cwnd(r);
        r.bbr_state.probe_rtt_done_stamp = None;
    }

    if r.bbr_state.mode == Mode::ProbeRtt {
        handle_probe_rtt(r, now);
    }

    r.bbr_state.idle_restart = false;
}

fn enter_probe_rtt(r: &mut Recovery) {
    r.bbr_state.mode = Mode::ProbeRtt;
    r.bbr_state.pacing_gain = 1.0;
    r.bbr_state.cwnd_gain = 1.0;
}

fn handle_probe_rtt(r: &mut Recovery, now: Instant) {
    if r.bbr_state.probe_rtt_done_stamp.is_none() &&
        r.bytes_in_flight <= MIN_PIPE_CWND * r.max_datagram_size()
    {
        r.bbr_state.probe_rtt_done_stamp = Some(now + PROBE_RTT_TIME);
        r.bbr_state.probe_rtt_round_done = false;
        r.bbr_state.next_round_delivered = r.delivery_rate.delivered();
    } else if let Some(probe_rtt_done_stamp) = r.bbr_state.probe_rtt_done_stamp {
        if r.bbr_state.round_start {
            r.bbr_state.probe_rtt_round_done = true;
        }

        if r.bbr_state.probe_rtt_round_done && now > probe_rtt_done_stamp {
            r.bbr_state.rtt_stamp = now;
            restore_cwnd(r);
            exit_probe_rtt(r);
        }
    }
}

fn exit_probe_rtt(r: &mut Recovery) {
    if r.bbr_state.filled_pipe {
        enter_probe_bw(r);
    } else {
        enter_startup(r);
    }
}
