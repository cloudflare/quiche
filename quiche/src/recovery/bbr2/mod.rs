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

//! BBR v2 Congestion Control
//!
//! This implementation is based on the following draft:
//! <https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-02>

use crate::minmax::Minmax;
use crate::packet;
use crate::recovery::*;

use std::time::Duration;
use std::time::Instant;

pub static BBR2: CongestionControlOps = CongestionControlOps {
    on_init,
    reset,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    collapse_cwnd,
    checkpoint,
    rollback,
    has_custom_pacing,
    debug_fmt,
};

/// The static discount factor of 1% used to scale BBR.bw to produce
/// BBR.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 0.01;

/// A constant specifying the minimum gain value
/// for calculating the pacing rate that will allow the sending rate to
/// double each round (4*ln(2) ~=2.77 ) BBRStartupPacingGain; used in
/// Startup mode for BBR.pacing_gain.
const STARTUP_PACING_GAIN: f64 = 2.77;

/// A constant specifying the pacing gain value for Probe Down mode.
const PROBE_DOWN_PACING_GAIN: f64 = 3_f64 / 4_f64;

/// A constant specifying the pacing gain value for Probe Up mode.
const PROBE_UP_PACING_GAIN: f64 = 5_f64 / 4_f64;

/// A constant specifying the pacing gain value for Probe Refill, Probe RTT,
/// Cruise mode.
const PACING_GAIN: f64 = 1.0;

/// A constant specifying the minimum gain value for the cwnd in the Startup
/// phase
const STARTUP_CWND_GAIN: f64 = 2.77;

/// A constant specifying the minimum gain value for
/// calculating the cwnd that will allow the sending rate to double each
/// round (2.0); used in Probe and Drain mode for BBR.cwnd_gain.
const CWND_GAIN: f64 = 2.0;

/// The maximum tolerated per-round-trip packet loss rate
/// when probing for bandwidth (the default is 2%).
const LOSS_THRESH: f64 = 0.02;

/// Exit startup if the number of loss marking events is >=FULL_LOSS_COUNT
const FULL_LOSS_COUNT: u32 = 8;

/// The default multiplicative decrease to make upon each round
/// trip during which the connection detects packet loss (the value is
/// 0.7).
const BETA: f64 = 0.7;

/// The multiplicative factor to apply to BBR.inflight_hi
/// when attempting to leave free headroom in the path (e.g. free space
/// in the bottleneck buffer or free time slots in the bottleneck link)
/// that can be used by cross traffic (the value is 0.85).
const HEADROOM: f64 = 0.85;

/// The minimal cwnd value BBR targets, to allow
/// pipelining with TCP endpoints that follow an "ACK every other packet"
/// delayed-ACK policy: 4 * SMSS.
const MIN_PIPE_CWND_PKTS: usize = 4;

// To do: Tune window for expiry of Max BW measurement
// The filter window length for BBR.MaxBwFilter = 2 (representing up to 2
// ProbeBW cycles, the current cycle and the previous full cycle).
// const MAX_BW_FILTER_LEN: Duration = Duration::from_secs(2);

// To do: Tune window for expiry of ACK aggregation measurement
// The window length of the BBR.ExtraACKedFilter max filter window: 10 (in
// units of packet-timed round trips).
// const EXTRA_ACKED_FILTER_LEN: Duration = Duration::from_secs(10);

/// A constant specifying the length of the BBR.min_rtt min filter window,
/// MinRTTFilterLen is 10 secs.
const MIN_RTT_FILTER_LEN: u32 = 1;

/// A constant specifying the gain value for calculating the cwnd during
/// ProbeRTT: 0.5 (meaning that ProbeRTT attempts to reduce in-flight data to
/// 50% of the estimated BDP).
const PROBE_RTT_CWND_GAIN: f64 = 0.5;

/// A constant specifying the minimum duration for which ProbeRTT state holds
/// inflight to BBRMinPipeCwnd or fewer packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// ProbeRTTInterval: A constant specifying the minimum time interval between
/// ProbeRTT states. To do: investigate probe duration. Set arbitrarily high for
/// now.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(86400);

/// Threshold for checking a full bandwidth growth during Startup.
const MAX_BW_GROWTH_THRESHOLD: f64 = 1.25;

/// Threshold for determining maximum bandwidth of network during Startup.
const MAX_BW_COUNT: usize = 3;

/// BBR2 Internal State Machine.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum BBR2StateMachine {
    Startup,
    Drain,
    ProbeBWDOWN,
    ProbeBWCRUISE,
    ProbeBWREFILL,
    ProbeBWUP,
    ProbeRTT,
}

/// BBR2 Ack Phases.
#[derive(Debug, PartialEq, Eq)]
enum BBR2AckPhase {
    Init,
    ProbeFeedback,
    ProbeStarting,
    ProbeStopping,
    Refilling,
}

/// BBR2 Specific State Variables.
pub struct State {
    // 2.3.  Per-ACK Rate Sample State
    // It's stored in rate sample but we keep in BBR state here.

    // The volume of data that was estimated to be in
    // flight at the time of the transmission of the packet that has just
    // been ACKed.
    tx_in_flight: usize,

    // The volume of data that was declared lost between the
    // transmission and acknowledgement of the packet that has just been
    // ACKed.
    lost: usize,

    // The volume of data cumulatively or selectively acknowledged upon the ACK
    // that was just received.  (This quantity is referred to as "DeliveredData"
    // in [RFC6937].)
    newly_acked_bytes: usize,

    // The volume of data newly marked lost upon the ACK that was just received.
    newly_lost_bytes: usize,

    // 2.4.  Output Control Parameters
    // The current pacing rate for a BBR2 flow, which controls inter-packet
    // spacing.
    pacing_rate: u64,

    // Save initial pacing rate so we can update when more reliable bytes
    // delivered and RTT samples are available
    init_pacing_rate: u64,

    // 2.5.  Pacing State and Parameters
    // The dynamic gain factor used to scale BBR.bw to
    // produce BBR.pacing_rate.
    pacing_gain: f64,

    // 2.6.  cwnd State and Parameters
    // The dynamic gain factor used to scale the estimated BDP to produce a
    // congestion window (cwnd).
    cwnd_gain: f64,

    // A boolean indicating whether BBR is currently using packet conservation
    // dynamics to bound cwnd.
    packet_conservation: bool,

    // 2.7.  General Algorithm State
    // The current state of a BBR2 flow in the BBR2 state machine.
    state: BBR2StateMachine,

    // Count of packet-timed round trips elapsed so far.
    round_count: u64,

    // A boolean that BBR2 sets to true once per packet-timed round trip,
    // on ACKs that advance BBR2.round_count.
    round_start: bool,

    // packet.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: usize,

    // A boolean that is true if and only if a connection is restarting after
    // being idle.
    idle_restart: bool,

    // 2.9.1.  Data Rate Network Path Model Parameters
    // The windowed maximum recent bandwidth sample - obtained using the BBR
    // delivery rate sampling algorithm
    // [draft-cheng-iccrg-delivery-rate-estimation] - measured during the current
    // or previous bandwidth probing cycle (or during Startup, if the flow is
    // still in that state).  (Part of the long-term model.)
    max_bw: u64,

    // The long-term maximum sending bandwidth that the algorithm estimates will
    // produce acceptable queue pressure, based on signals in the current or
    // previous bandwidth probing cycle, as measured by loss.  (Part of the
    // long-term model.)
    bw_hi: u64,

    // The short-term maximum sending bandwidth that the algorithm estimates is
    // safe for matching the current network path delivery rate, based on any
    // loss signals in the current bandwidth probing cycle.  This is generally
    // lower than max_bw or bw_hi (thus the name).  (Part of the short-term
    // model.)
    bw_lo: u64,

    // The maximum sending bandwidth that the algorithm estimates is appropriate
    // for matching the current network path delivery rate, given all available
    // signals in the model, at any time scale.  It is the min() of max_bw,
    // bw_hi, and bw_lo.
    bw: u64,

    // 2.9.2.  Data Volume Network Path Model Parameters
    // The windowed minimum round-trip time sample measured over the last
    // MinRTTFilterLen = 10 seconds.  This attempts to estimate the two-way
    // propagation delay of the network path when all connections sharing a
    // bottleneck are using BBR, but also allows BBR to estimate the value
    // required for a bdp estimate that allows full throughput if there are
    // legacy loss-based Reno or CUBIC flows sharing the bottleneck.
    min_rtt: Duration,

    // The estimate of the network path's BDP (Bandwidth-Delay Product), computed
    // as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: usize,

    // A volume of data that is the estimate of the recent degree of aggregation
    // in the network path.
    extra_acked: usize,

    // The estimate of the minimum volume of data necessary to achieve full
    // throughput when using sender (TSO/GSO) and receiver (LRO, GRO) host
    // offload mechanisms.
    offload_budget: usize,

    // The estimate of the volume of in-flight data required to fully utilize the
    // bottleneck bandwidth available to the flow, based on the BDP estimate
    // (BBR.bdp), the aggregation estimate (BBR.extra_acked), the offload budget
    // (BBR.offload_budget), and BBRMinPipeCwnd.
    max_inflight: usize,

    // Analogous to BBR.bw_hi, the long-term maximum volume of in-flight data
    // that the algorithm estimates will produce acceptable queue pressure, based
    // on signals in the current or previous bandwidth probing cycle, as measured
    // by loss.  That is, if a flow is probing for bandwidth, and observes that
    // sending a particular volume of in-flight data causes a loss rate higher
    // than the loss rate objective, it sets inflight_hi to that volume of data.
    // (Part of the long-term model.)
    inflight_hi: usize,

    // Analogous to BBR.bw_lo, the short-term maximum volume of in-flight data
    // that the algorithm estimates is safe for matching the current network path
    // delivery process, based on any loss signals in the current bandwidth
    // probing cycle.  This is generally lower than max_inflight or inflight_hi
    // (thus the name).  (Part of the short-term model.)
    inflight_lo: usize,

    // 2.10.  State for Responding to Congestion
    // a 1-round-trip max of delivered bandwidth (rs.delivery_rate).
    bw_latest: u64,

    // a 1-round-trip max of delivered volume of data (rs.delivered).
    inflight_latest: usize,

    // 2.11.  Estimating BBR.max_bw
    // The filter for tracking the maximum recent rs.delivery_rate sample, for
    // estimating BBR.max_bw.
    max_bw_filter: Minmax<u64>,

    // The virtual time used by the BBR.max_bw filter window.  Note that
    // BBR.cycle_count only needs to be tracked with a single bit, since the
    // BBR.MaxBwFilter only needs to track samples from two time slots: the
    // previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: u64,

    // 2.12.  Estimating BBR.extra_acked
    // the start of the time interval for estimating the excess amount of data
    // acknowledged due to aggregation effects.
    extra_acked_interval_start: Instant,

    // the volume of data marked as delivered since
    // BBR.extra_acked_interval_start.
    extra_acked_delivered: usize,

    // BBR.ExtraACKedFilter: the max filter tracking the recent maximum degree of
    // aggregation in the path.
    extra_acked_filter: Minmax<usize>,

    // 2.13.  Startup Parameters and State
    // A boolean that records whether BBR estimates that it has ever fully
    // utilized its available bandwidth ("filled the pipe").
    filled_pipe: bool,

    // A recent baseline BBR.max_bw to estimate if BBR has "filled the pipe" in
    // Startup.
    full_bw: u64,

    // The number of non-app-limited round trips without large increases in
    // BBR.full_bw.
    full_bw_count: usize,

    // 2.14.1.  Parameters for Estimating BBR.min_rtt
    // The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: Instant,

    // 2.14.2.  Parameters for Scheduling ProbeRTT
    // The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: Duration,

    // The wall clock time at which the current BBR.probe_rtt_min_delay sample
    // was obtained.
    probe_rtt_min_stamp: Instant,

    // A boolean recording whether the BBR.probe_rtt_min_delay has expired and is
    // due for a refresh with an application idle period or a transition into
    // ProbeRTT state.
    probe_rtt_expired: bool,

    // Others
    // A state indicating we are in the recovery.
    in_recovery: bool,

    // Start time of the connection.
    start_time: Instant,

    // Saved cwnd before loss recovery.
    prior_cwnd: usize,

    // Whether we have a bandwidth probe samples.
    bw_probe_samples: bool,

    // Others
    probe_up_cnt: usize,

    prior_bytes_in_flight: usize,

    probe_rtt_done_stamp: Option<Instant>,

    probe_rtt_round_done: bool,

    bw_probe_wait: Duration,

    rounds_since_probe: usize,

    cycle_stamp: Instant,

    ack_phase: BBR2AckPhase,

    bw_probe_up_rounds: usize,

    bw_probe_up_acks: usize,

    loss_round_start: bool,

    loss_round_delivered: usize,

    loss_in_round: bool,

    loss_events_in_round: usize,
}

impl State {
    pub fn new() -> Self {
        let now = Instant::now();

        State {
            tx_in_flight: 0,

            lost: 0,

            newly_acked_bytes: 0,

            newly_lost_bytes: 0,

            pacing_rate: 0,

            init_pacing_rate: 0,

            pacing_gain: 0.0,

            cwnd_gain: 0.0,

            packet_conservation: false,

            state: BBR2StateMachine::Startup,

            round_count: 0,

            round_start: false,

            next_round_delivered: 0,

            idle_restart: false,

            max_bw: 0,

            bw_hi: u64::MAX,

            bw_lo: u64::MAX,

            bw: 0,

            min_rtt: Duration::MAX,

            bdp: 0,

            extra_acked: 0,

            offload_budget: 0,

            max_inflight: 0,

            inflight_hi: usize::MAX,

            inflight_lo: usize::MAX,

            bw_latest: 0,

            inflight_latest: 0,

            max_bw_filter: Minmax::new(0),

            cycle_count: 0,

            extra_acked_interval_start: now,

            extra_acked_delivered: 0,

            extra_acked_filter: Minmax::new(0),

            filled_pipe: false,

            full_bw: 0,

            full_bw_count: 0,

            min_rtt_stamp: now,

            probe_rtt_min_delay: Duration::MAX,

            probe_rtt_min_stamp: now,

            probe_rtt_expired: false,

            in_recovery: false,

            start_time: now,

            prior_cwnd: 0,

            bw_probe_samples: false,

            probe_up_cnt: 0,

            prior_bytes_in_flight: 0,

            probe_rtt_done_stamp: None,

            probe_rtt_round_done: false,

            bw_probe_wait: Duration::ZERO,

            rounds_since_probe: 0,

            cycle_stamp: now,

            ack_phase: BBR2AckPhase::Init,

            bw_probe_up_rounds: 0,

            bw_probe_up_acks: 0,

            loss_round_start: false,

            loss_round_delivered: 0,

            loss_in_round: false,

            loss_events_in_round: 0,
        }
    }
}

// When entering the recovery episode.
fn bbr2_enter_recovery(r: &mut Recovery, now: Instant) {
    r.bbr2_state.prior_cwnd = per_ack::bbr2_save_cwnd(r);

    r.congestion_window = r.bytes_in_flight +
        r.bbr2_state.newly_acked_bytes.max(r.max_datagram_size);
    r.congestion_recovery_start_time = Some(now);

    r.bbr2_state.packet_conservation = true;
    r.bbr2_state.in_recovery = true;

    // Start round now.
    r.bbr2_state.next_round_delivered = r.delivery_rate.delivered();
}

// When exiting the recovery episode.
fn bbr2_exit_recovery(r: &mut Recovery) {
    r.congestion_recovery_start_time = None;

    r.bbr2_state.packet_conservation = false;
    r.bbr2_state.in_recovery = false;

    per_ack::bbr2_restore_cwnd(r);
}

// Congestion Control Hooks.
//
fn on_init(r: &mut Recovery) {
    init::bbr2_init(r);
}

fn reset(r: &mut Recovery) {
    r.bbr2_state = State::new();

    init::bbr2_init(r);
}

fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, now: Instant) {
    r.bytes_in_flight += sent_bytes;

    per_transmit::bbr2_on_transmit(r, now);
}

fn on_packets_acked(
    r: &mut Recovery, packets: &mut Vec<Acked>, _epoch: packet::Epoch,
    now: Instant,
) {
    r.bbr2_state.newly_acked_bytes = 0;

    let time_sent = packets.last().map(|pkt| pkt.time_sent);

    for p in packets.drain(..) {
        r.bbr2_state.prior_bytes_in_flight = r.bytes_in_flight;

        per_ack::bbr2_update_model_and_state(r, &p, now);

        if r.bytes_in_flight < p.size {
            trace!("BBR2 on_packets_acked subtraction overflow");
            r.bytes_in_flight = 0;
        } else {
            r.bytes_in_flight -= p.size
        }
        r.bbr2_state.newly_acked_bytes += p.size;
    }

    if let Some(ts) = time_sent {
        if !r.in_congestion_recovery(ts) {
            // Upon exiting loss recovery.
            bbr2_exit_recovery(r);
        }
    }

    per_ack::bbr2_update_control_parameters(r, now);

    r.bbr2_state.newly_lost_bytes = 0;
}

fn congestion_event(
    r: &mut Recovery, lost_bytes: usize, largest_lost_pkt: &Sent,
    _epoch: packet::Epoch, now: Instant,
) {
    r.bbr2_state.newly_lost_bytes = lost_bytes;

    per_loss::bbr2_update_on_loss(r, largest_lost_pkt, now);

    // Upon entering Fast Recovery.
    if !r.in_congestion_recovery(largest_lost_pkt.time_sent) {
        // Upon entering Fast Recovery.
        bbr2_enter_recovery(r, now);
    }
}

fn collapse_cwnd(r: &mut Recovery) {
    // BBROnEnterRTO()
    r.bbr2_state.prior_cwnd = per_ack::bbr2_save_cwnd(r);

    r.congestion_window = r.bytes_in_flight + r.max_datagram_size;
}

fn checkpoint(_r: &mut Recovery) {}

fn rollback(_r: &mut Recovery) -> bool {
    false
}

fn has_custom_pacing() -> bool {
    true
}

// rate -> kbit/sec. if inf, return -1
fn rate_kbps(rate: u64) -> isize {
    if rate == u64::MAX {
        -1
    } else {
        (rate * 8 / 1000) as isize
    }
}

fn debug_fmt(r: &Recovery, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let bbr = &r.bbr2_state;

    write!(f, "bbr2={{ ")?;
    write!(
        f,
        "state={:?} in_recovery={} ack_phase={:?} filled_pipe={} full_bw_count={} loss_events_in_round={} ",
        bbr.state, bbr.in_recovery, bbr.ack_phase, bbr.filled_pipe, bbr.full_bw_count, bbr.loss_events_in_round
    )?;
    write!(
        f,
        "send_quantum={} extra_acked={} min_rtt={:?} round_start={} ",
        r.send_quantum, bbr.extra_acked, bbr.min_rtt, bbr.round_start
    )?;
    write!(
        f,
        "max_bw={}kbps bw_lo={}kbps bw={}kbps bw_hi={}kbps full_bw={}kbps ",
        rate_kbps(bbr.max_bw),
        rate_kbps(bbr.bw_lo),
        rate_kbps(bbr.bw),
        rate_kbps(bbr.bw_hi),
        rate_kbps(bbr.full_bw)
    )?;
    write!(
        f,
        "inflight_lo={} inflight_hi={} max_inflight={} ",
        bbr.inflight_lo, bbr.inflight_hi, bbr.max_inflight
    )?;
    write!(
        f,
        "probe_up_cnt={} bw_probe_samples={} ",
        bbr.probe_up_cnt, bbr.bw_probe_samples
    )?;
    write!(f, "}}")
}

// TODO: write more tests
#[cfg(test)]
mod tests {
    use super::*;

    use smallvec::smallvec;

    use crate::recovery;

    #[test]
    fn bbr_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR2);

        let mut r = Recovery::new(&cfg);

        // on_init() is called in Connection::new(), so it need to be
        // called manually here.
        r.on_init();

        assert_eq!(
            r.cwnd(),
            r.max_datagram_size * r.initial_congestion_window_packets
        );
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.bbr2_state.state, BBR2StateMachine::Startup);
    }

    #[test]
    fn bbr2_send() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR2);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();

        r.on_init();
        r.on_packet_sent_cc(1000, now);

        assert_eq!(r.bytes_in_flight, 1000);
    }

    #[test]
    fn bbr2_startup() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR2);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        r.on_init();

        // Send 5 packets.
        for pn in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;
        let cwnd_prev = r.cwnd();

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..5);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            )
            .is_ok());

        assert_eq!(r.bbr2_state.state, BBR2StateMachine::Startup);
        assert_eq!(r.cwnd(), cwnd_prev + mss * 5);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(
            r.delivery_rate(),
            ((mss * 5) as f64 / rtt.as_secs_f64()) as u64
        );
        assert_eq!(r.bbr2_state.full_bw, r.delivery_rate());
    }

    #[test]
    fn bbr2_congestion_event() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR2);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        r.on_init();

        // Send 5 packets.
        for pn in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        // Make a packet loss to trigger a congestion event.
        let mut acked = ranges::RangeSet::default();
        acked.insert(4..5);

        // 2 acked, 2 x MSS lost.
        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            )
            .is_ok());

        assert!(r.bbr2_state.in_recovery);

        // Still in flight: 2, 3.
        assert_eq!(r.bytes_in_flight, mss * 2);

        assert_eq!(r.bbr2_state.newly_acked_bytes, mss);

        assert_eq!(r.cwnd(), mss * 3);
    }

    #[test]
    fn bbr2_probe_bw() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR2);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        r.on_init();

        let mut pn = 0;

        // Stop right before filled_pipe=true.
        for _ in 0..3 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;

            let rtt = Duration::from_millis(50);

            let now = now + rtt;

            let mut acked = ranges::RangeSet::default();
            acked.insert(0..pn);

            assert!(r
                .on_ack_received(
                    &acked,
                    25,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    "",
                    &mut Vec::new(),
                )
                .is_ok());
        }

        // Stop at right before filled_pipe=true.
        for _ in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();

        // We sent 5 packets, but ack only one, to stay
        // in Drain state.
        acked.insert(0..pn - 4);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            )
            .is_ok());

        assert_eq!(r.bbr2_state.state, BBR2StateMachine::Drain);
        assert!(r.bbr2_state.filled_pipe);
        assert!(r.bbr2_state.pacing_gain < 1.0);
    }

    #[test]
    fn bbr2_probe_rtt() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR2);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        r.on_init();

        let mut pn = 0;

        // At 4th roundtrip, filled_pipe=true and switch to Drain,
        // but move to ProbeBW immediately because bytes_in_flight is
        // smaller than BBRInFlight(1).
        for _ in 0..4 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;

            let rtt = Duration::from_millis(50);
            let now = now + rtt;

            let mut acked = ranges::RangeSet::default();
            acked.insert(0..pn);

            assert!(r
                .on_ack_received(
                    &acked,
                    25,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    "",
                    &mut Vec::new(),
                )
                .is_ok());
        }

        // Now we are in ProbeBW state.
        assert_eq!(r.bbr2_state.state, BBR2StateMachine::ProbeBWCRUISE);

        // After RTPROP_FILTER_LEN (10s), switch to ProbeRTT.
        let now = now + PROBE_RTT_INTERVAL;

        let pkt = Sent {
            pkt_num: pn,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: r.delivery_rate.delivered(),
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
        };

        r.on_packet_sent(
            pkt,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        pn += 1;

        // Don't update rtprop by giving larger rtt than before.
        // If rtprop is updated, rtprop expiry check is reset.
        let rtt = Duration::from_millis(100);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..pn);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                &mut Vec::new(),
            )
            .is_ok());

        assert_eq!(r.bbr2_state.state, BBR2StateMachine::ProbeRTT);
        assert_eq!(r.bbr2_state.pacing_gain, 1.0);
    }
}

mod init;
mod pacing;
mod per_ack;
mod per_loss;
mod per_transmit;
