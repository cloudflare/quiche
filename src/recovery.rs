// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::cmp;

use std::str::FromStr;

use std::time::Duration;
use std::time::Instant;

use std::collections::VecDeque;

use crate::Config;
use crate::Error;
use crate::Result;

use crate::frame;
use crate::minmax;
use crate::packet;
use crate::ranges;

// Loss Recovery
const PACKET_THRESHOLD: u64 = 3;

const TIME_THRESHOLD: f64 = 9.0 / 8.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const INITIAL_RTT: Duration = Duration::from_millis(500);

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

const RTT_WINDOW: Duration = Duration::from_secs(300);

// Congestion Control
const INITIAL_WINDOW_PACKETS: usize = 10;

const INITIAL_WINDOW: usize = INITIAL_WINDOW_PACKETS * MAX_DATAGRAM_SIZE;

const MINIMUM_WINDOW: usize = 2 * MAX_DATAGRAM_SIZE;

const MAX_DATAGRAM_SIZE: usize = 1452;

const LOSS_REDUCTION_FACTOR: f64 = 0.5;

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    pto_count: u32,

    time_of_last_sent_ack_eliciting_pkt: [Option<Instant>; packet::EPOCH_COUNT],

    largest_acked_pkt: [u64; packet::EPOCH_COUNT],

    largest_sent_pkt: [u64; packet::EPOCH_COUNT],

    latest_rtt: Duration,

    smoothed_rtt: Option<Duration>,

    rttvar: Duration,

    minmax_filter: minmax::Minmax<Duration>,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: [Option<Instant>; packet::EPOCH_COUNT],

    sent: [VecDeque<Sent>; packet::EPOCH_COUNT],

    pub lost: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub acked: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub lost_count: usize,

    pub loss_probes: [usize; packet::EPOCH_COUNT],

    app_limited: bool,

    delivery_rate: delivery_rate::Rate,

    // Congestion control.
    cc_ops: &'static CongestionControlOps,

    congestion_window: usize,

    bytes_in_flight: usize,

    ssthresh: usize,

    congestion_recovery_start_time: Option<Instant>,

    cubic_state: cubic::State,

    // HyStart++.
    hystart: hystart::Hystart,
}

impl Recovery {
    pub fn new(config: &Config) -> Self {
        Recovery {
            loss_detection_timer: None,

            pto_count: 0,

            time_of_last_sent_ack_eliciting_pkt: [None; packet::EPOCH_COUNT],

            largest_acked_pkt: [std::u64::MAX; packet::EPOCH_COUNT],

            largest_sent_pkt: [0; packet::EPOCH_COUNT],

            latest_rtt: Duration::new(0, 0),

            smoothed_rtt: None,

            minmax_filter: minmax::Minmax::new(Duration::new(0, 0)),

            min_rtt: Duration::new(0, 0),

            rttvar: Duration::new(0, 0),

            max_ack_delay: Duration::from_millis(25),

            loss_time: [None; packet::EPOCH_COUNT],

            sent: [VecDeque::new(), VecDeque::new(), VecDeque::new()],

            lost: [Vec::new(), Vec::new(), Vec::new()],

            acked: [Vec::new(), Vec::new(), Vec::new()],

            lost_count: 0,

            loss_probes: [0; packet::EPOCH_COUNT],

            congestion_window: INITIAL_WINDOW,

            bytes_in_flight: 0,

            ssthresh: std::usize::MAX,

            congestion_recovery_start_time: None,

            cc_ops: config.cc_algorithm.into(),

            delivery_rate: delivery_rate::Rate::default(),

            cubic_state: cubic::State::default(),

            app_limited: false,

            hystart: hystart::Hystart::new(config.hystart),
        }
    }

    pub fn on_packet_sent(
        &mut self, mut pkt: Sent, epoch: packet::Epoch,
        handshake_completed: bool, now: Instant, trace_id: &str,
    ) {
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let sent_bytes = pkt.size;
        let pkt_num = pkt.pkt_num;

        self.delivery_rate.on_packet_sent(&mut pkt, now);

        self.largest_sent_pkt[epoch] =
            cmp::max(self.largest_sent_pkt[epoch], pkt_num);

        self.sent[epoch].push_back(pkt);

        if in_flight {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_pkt[epoch] = Some(now);
            }

            self.app_limited =
                (self.bytes_in_flight + sent_bytes) < self.congestion_window;

            self.on_packet_sent_cc(sent_bytes, now);

            self.set_loss_detection_timer(handshake_completed);
        }

        // HyStart++: Start of the round in a slow start.
        if self.hystart.enabled() &&
            epoch == packet::EPOCH_APPLICATION &&
            self.congestion_window < self.ssthresh
        {
            self.hystart.start_round(pkt_num);
        }

        trace!("{} {:?}", trace_id, self);
    }

    fn on_packet_sent_cc(&mut self, sent_bytes: usize, now: Instant) {
        (self.cc_ops.on_packet_sent)(self, sent_bytes, now);
    }

    pub fn on_ack_received(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_completed: bool, now: Instant,
        trace_id: &str,
    ) -> Result<()> {
        let largest_acked = ranges.last().unwrap();

        // If the largest packet number acked exceeds any packet number we have
        // sent, then the ACK is obviously invalid, so there's no need to
        // continue further.
        if largest_acked > self.largest_sent_pkt[epoch] {
            if cfg!(feature = "fuzzing") {
                return Ok(());
            }

            return Err(Error::InvalidPacket);
        }

        if self.largest_acked_pkt[epoch] == std::u64::MAX {
            self.largest_acked_pkt[epoch] = largest_acked;
        } else {
            self.largest_acked_pkt[epoch] =
                cmp::max(self.largest_acked_pkt[epoch], largest_acked);
        }

        let mut has_ack_eliciting = false;

        let mut largest_newly_acked_pkt_num = 0;
        let mut largest_newly_acked_sent_time = now;

        let mut newly_acked = Vec::new();

        // Detect and mark acked packets, without removing them from the sent
        // packets list.
        for r in ranges.iter() {
            let lowest_acked = r.start;
            let largest_acked = r.end - 1;

            let unacked_iter = self.sent[epoch]
                .iter_mut()
                // Skip packets that precede the lowest acked packet in the block.
                .skip_while(|p| p.pkt_num < lowest_acked)
                // Skip packets that follow the largest acked packet in the block.
                .take_while(|p| p.pkt_num <= largest_acked)
                // Skip packets that have already been acked or lost.
                .filter(|p| p.time_acked.is_none() && p.time_lost.is_none());

            for unacked in unacked_iter {
                unacked.time_acked = Some(now);

                if unacked.ack_eliciting {
                    has_ack_eliciting = true;
                }

                largest_newly_acked_pkt_num = unacked.pkt_num;
                largest_newly_acked_sent_time = unacked.time_sent;

                self.acked[epoch].append(&mut unacked.frames);

                if unacked.in_flight {
                    self.delivery_rate.on_packet_acked(&unacked, now);
                }

                newly_acked.push(Acked {
                    pkt_num: unacked.pkt_num,

                    time_sent: unacked.time_sent,

                    size: unacked.size,
                });

                trace!("{} packet newly acked {}", trace_id, unacked.pkt_num);
            }
        }

        self.delivery_rate.estimate();

        if newly_acked.is_empty() {
            return Ok(());
        }

        if largest_newly_acked_pkt_num == largest_acked && has_ack_eliciting {
            let latest_rtt = now - largest_newly_acked_sent_time;

            let ack_delay = if epoch == packet::EPOCH_APPLICATION {
                Duration::from_micros(ack_delay)
            } else {
                Duration::from_micros(0)
            };

            self.update_rtt(latest_rtt, ack_delay, now);
        }

        // Detect and mark lost packets without removing them from the sent
        // packets list.
        self.detect_lost_packets(epoch, now, trace_id);

        self.on_packets_acked(newly_acked, epoch, now);

        self.pto_count = 0;

        self.set_loss_detection_timer(handshake_completed);

        self.drain_packets(epoch);

        trace!("{} {:?}", trace_id, self);

        Ok(())
    }

    pub fn on_loss_detection_timeout(
        &mut self, handshake_completed: bool, now: Instant, trace_id: &str,
    ) {
        let (earliest_loss_time, epoch) =
            self.earliest_loss_time(self.loss_time, handshake_completed);

        if earliest_loss_time.is_some() {
            self.detect_lost_packets(epoch, now, trace_id);
            self.set_loss_detection_timer(handshake_completed);

            trace!("{} {:?}", trace_id, self);
            return;
        }

        // TODO: handle client without 1-RTT keys case.

        let (_, epoch) = self.earliest_loss_time(
            self.time_of_last_sent_ack_eliciting_pkt,
            handshake_completed,
        );

        self.loss_probes[epoch] = 2;

        self.pto_count += 1;

        self.set_loss_detection_timer(handshake_completed);

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_completed: bool,
    ) {
        let unacked_bytes = self.sent[epoch]
            .iter()
            .filter(|p| {
                p.in_flight && p.time_acked.is_none() && p.time_lost.is_none()
            })
            .fold(0, |acc, p| acc + p.size);

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(unacked_bytes);

        self.sent[epoch].clear();
        self.lost[epoch].clear();
        self.acked[epoch].clear();

        self.time_of_last_sent_ack_eliciting_pkt[epoch] = None;
        self.loss_time[epoch] = None;
        self.loss_probes[epoch] = 0;

        self.set_loss_detection_timer(handshake_completed);
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    pub fn cwnd(&self) -> usize {
        self.congestion_window
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.loss_probes.iter().any(|&x| x > 0) {
            return std::usize::MAX;
        }

        self.congestion_window.saturating_sub(self.bytes_in_flight)
    }

    pub fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(INITIAL_RTT)
    }

    pub fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rttvar * 4, GRANULARITY) + self.max_ack_delay
    }

    pub fn delivery_rate(&self) -> u64 {
        self.delivery_rate.delivery_rate()
    }

    fn update_rtt(
        &mut self, latest_rtt: Duration, ack_delay: Duration, now: Instant,
    ) {
        self.latest_rtt = latest_rtt;

        match self.smoothed_rtt {
            // First RTT sample.
            None => {
                self.min_rtt = self.minmax_filter.reset(now, latest_rtt);

                self.smoothed_rtt = Some(latest_rtt);

                self.rttvar = latest_rtt / 2;
            },

            Some(srtt) => {
                self.min_rtt =
                    self.minmax_filter.running_min(RTT_WINDOW, now, latest_rtt);

                let ack_delay = cmp::min(self.max_ack_delay, ack_delay);

                // Adjust for ack delay if plausible.
                let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
                    latest_rtt - ack_delay
                } else {
                    latest_rtt
                };

                self.rttvar = self.rttvar.mul_f64(3.0 / 4.0) +
                    sub_abs(srtt, adjusted_rtt).mul_f64(1.0 / 4.0);

                self.smoothed_rtt = Some(
                    srtt.mul_f64(7.0 / 8.0) + adjusted_rtt.mul_f64(1.0 / 8.0),
                );
            },
        }
    }

    fn earliest_loss_time(
        &mut self, times: [Option<Instant>; packet::EPOCH_COUNT],
        handshake_completed: bool,
    ) -> (Option<Instant>, packet::Epoch) {
        let mut epoch = packet::EPOCH_INITIAL;
        let mut time = times[epoch];

        // Iterate over all packet number spaces starting from Handshake.
        #[allow(clippy::needless_range_loop)]
        for e in packet::EPOCH_HANDSHAKE..packet::EPOCH_COUNT {
            let new_time = times[e];

            if e == packet::EPOCH_APPLICATION && !handshake_completed {
                continue;
            }

            if new_time.is_some() && (time.is_none() || new_time < time) {
                time = new_time;
                epoch = e;
            }
        }

        (time, epoch)
    }

    fn set_loss_detection_timer(&mut self, handshake_completed: bool) {
        let (earliest_loss_time, _) =
            self.earliest_loss_time(self.loss_time, handshake_completed);

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = earliest_loss_time;
            return;
        }

        if self.bytes_in_flight == 0 {
            // TODO: check if peer is awaiting address validation.
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let timeout = match self.smoothed_rtt {
            None => INITIAL_RTT * 2,

            Some(_) => self.pto(),
        };

        let timeout = timeout * 2_u32.pow(self.pto_count);

        let (sent_time, _) = self.earliest_loss_time(
            self.time_of_last_sent_ack_eliciting_pkt,
            handshake_completed,
        );

        if let Some(sent_time) = sent_time {
            self.loss_detection_timer = Some(sent_time + timeout);
        }
    }

    fn detect_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
    ) {
        let largest_acked = self.largest_acked_pkt[epoch];

        self.loss_time[epoch] = None;

        let loss_delay =
            cmp::max(self.latest_rtt, self.rtt()).mul_f64(TIME_THRESHOLD);

        // Minimum time of kGranularity before packets are deemed lost.
        let loss_delay = cmp::max(loss_delay, GRANULARITY);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now - loss_delay;

        let mut lost_bytes = 0;

        let mut largest_lost_pkt = None;

        let unacked_iter = self.sent[epoch]
            .iter_mut()
            // Skip packets that follow the largest acked packet.
            .take_while(|p| p.pkt_num <= largest_acked)
            // Skip packets that have already been acked or lost.
            .filter(|p| p.time_acked.is_none() && p.time_lost.is_none());

        for unacked in unacked_iter {
            // Mark packet as lost, or set time when it should be marked.
            if unacked.time_sent <= lost_send_time ||
                largest_acked >= unacked.pkt_num + PACKET_THRESHOLD
            {
                self.lost[epoch].append(&mut unacked.frames);

                unacked.time_lost = Some(now);

                if unacked.in_flight {
                    lost_bytes += unacked.size;

                    // Frames have already been removed from the packet, so
                    // cloning the whole packet should be relatively cheap.
                    largest_lost_pkt = Some(unacked.clone());

                    trace!(
                        "{} packet {} lost on epoch {}",
                        trace_id,
                        unacked.pkt_num,
                        epoch
                    );
                }

                self.lost_count += 1;
            } else {
                let loss_time = match self.loss_time[epoch] {
                    None => unacked.time_sent + loss_delay,

                    Some(loss_time) =>
                        cmp::min(loss_time, unacked.time_sent + loss_delay),
                };

                self.loss_time[epoch] = Some(loss_time);
            }
        }

        if let Some(pkt) = largest_lost_pkt {
            self.on_packets_lost(lost_bytes, &pkt, epoch, now);
        }

        self.drain_packets(epoch);
    }

    fn drain_packets(&mut self, epoch: packet::Epoch) {
        let mut lowest_non_expired_pkt_index = self.sent[epoch].len();

        // In order to avoid removing elements from the middle of the list
        // (which would require copying other elements to compact the list),
        // we only remove a contiguous range of elements from the start of the
        // list.
        //
        // This means that acked or lost elements coming after this will not
        // be removed at this point, but their removal is delayed for a later
        // time, once the gaps have been filled.

        // First, find the first element that is neither acked nor lost.
        for (i, pkt) in self.sent[epoch].iter().enumerate() {
            if pkt.time_acked.is_none() && pkt.time_lost.is_none() {
                lowest_non_expired_pkt_index = i;
                break;
            }
        }

        // Then remove elements up to the previously found index.
        self.sent[epoch].drain(..lowest_non_expired_pkt_index);
    }

    fn on_packets_acked(
        &mut self, acked: Vec<Acked>, epoch: packet::Epoch, now: Instant,
    ) {
        for pkt in acked {
            (self.cc_ops.on_packet_acked)(self, &pkt, epoch, now);
        }
    }

    fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(congestion_recovery_start_time) =>
                sent_time <= congestion_recovery_start_time,

            None => false,
        }
    }

    fn in_persistent_congestion(&mut self, _largest_lost_pkt_num: u64) -> bool {
        let _congestion_period = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;

        // TODO: properly detect persistent congestion
        false
    }

    fn on_packets_lost(
        &mut self, lost_bytes: usize, largest_lost_pkt: &Sent,
        epoch: packet::Epoch, now: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        self.congestion_event(largest_lost_pkt.time_sent, epoch, now);

        if self.in_persistent_congestion(largest_lost_pkt.pkt_num) {
            self.collapse_cwnd();
        }
    }

    fn congestion_event(
        &mut self, time_sent: Instant, epoch: packet::Epoch, now: Instant,
    ) {
        (self.cc_ops.congestion_event)(self, time_sent, epoch, now);
    }

    fn collapse_cwnd(&mut self) {
        (self.cc_ops.collapse_cwnd)(self);
    }

    pub fn rate_check_app_limited(&mut self) {
        if self.app_limited {
            self.delivery_rate.check_app_limited(self.bytes_in_flight)
        }
    }

    fn hystart_on_packet_acked(
        &mut self, packet: &Acked, now: Instant,
    ) -> (usize, usize) {
        self.hystart.on_packet_acked(
            packet,
            self.latest_rtt,
            self.congestion_window,
            self.ssthresh,
            now,
        )
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.app_limited = v;
    }

    pub fn app_limited(&mut self) -> bool {
        self.app_limited
    }

    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self) -> qlog::event::Event {
        // QVis can't use all these fields and they can be large.
        qlog::event::Event::metrics_updated(
            Some(self.min_rtt.as_millis() as u64),
            Some(self.rtt().as_millis() as u64),
            Some(self.latest_rtt.as_millis() as u64),
            Some(self.rttvar.as_millis() as u64),
            None, // delay
            None, // probe_count
            Some(self.cwnd() as u64),
            Some(self.bytes_in_flight as u64),
            None, // ssthresh
            None, // packets_in_flight
            None, // in_recovery
            None, // pacing_rate
        )
    }
}

/// Available congestion control algorithms.
///
/// This enum provides currently available list of congestion control
/// algorithms.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CongestionControlAlgorithm {
    /// Reno congestion control algorithm. `reno` in a string form.
    Reno  = 0,
    /// CUBIC congestion control algorithm (default). `cubic` in a string form.
    CUBIC = 1,
}

impl FromStr for CongestionControlAlgorithm {
    type Err = crate::Error;

    /// Converts a string to `CongestionControlAlgorithm`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "reno" => Ok(CongestionControlAlgorithm::Reno),
            "cubic" => Ok(CongestionControlAlgorithm::CUBIC),

            _ => Err(crate::Error::CongestionControl),
        }
    }
}

pub struct CongestionControlOps {
    pub on_packet_sent: fn(r: &mut Recovery, sent_bytes: usize, now: Instant),

    pub on_packet_acked:
        fn(r: &mut Recovery, packet: &Acked, epoch: packet::Epoch, now: Instant),

    pub congestion_event: fn(
        r: &mut Recovery,
        time_sent: Instant,
        epoch: packet::Epoch,
        now: Instant,
    ),

    pub collapse_cwnd: fn(r: &mut Recovery),
}

impl From<CongestionControlAlgorithm> for &'static CongestionControlOps {
    fn from(algo: CongestionControlAlgorithm) -> Self {
        match algo {
            CongestionControlAlgorithm::Reno => &reno::RENO,
            CongestionControlAlgorithm::CUBIC => &cubic::CUBIC,
        }
    }
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.loss_detection_timer {
            Some(v) => {
                let now = Instant::now();

                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "timer={:?} ", d)?;
                } else {
                    write!(f, "timer=exp ")?;
                }
            },

            None => {
                write!(f, "timer=none ")?;
            },
        };

        write!(f, "latest_rtt={:?} ", self.latest_rtt)?;
        write!(f, "srtt={:?} ", self.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", self.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rttvar)?;
        write!(f, "loss_time={:?} ", self.loss_time)?;
        write!(f, "loss_probes={:?} ", self.loss_probes)?;
        write!(f, "cwnd={} ", self.congestion_window)?;
        write!(f, "ssthresh={} ", self.ssthresh)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight)?;
        write!(f, "app_limited={} ", self.app_limited)?;
        write!(
            f,
            "congestion_recovery_start_time={:?} ",
            self.congestion_recovery_start_time
        )?;
        write!(f, "{:?} ", self.delivery_rate)?;

        if self.hystart.enabled() {
            write!(f, "hystart={:?} ", self.hystart)?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct Sent {
    pub pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    pub time_sent: Instant,

    pub time_acked: Option<Instant>,

    pub time_lost: Option<Instant>,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub recent_delivered_packet_sent_time: Instant,

    pub is_app_limited: bool,
}

impl std::fmt::Debug for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pkt_num={:?} ", self.pkt_num)?;
        write!(f, "pkt_sent_time={:?} ", self.time_sent.elapsed())?;
        write!(f, "pkt_size={:?} ", self.size)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        write!(f, "delivered_time ={:?} ", self.delivered_time.elapsed())?;
        write!(
            f,
            "recent_delivered_packet_sent_time={:?} ",
            self.recent_delivered_packet_sent_time.elapsed()
        )?;
        write!(f, "is_app_limited={:?} ", self.is_app_limited)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct Acked {
    pub pkt_num: u64,

    pub time_sent: Instant,

    pub size: usize,
}

fn sub_abs(lhs: Duration, rhs: Duration) -> Duration {
    if lhs > rhs {
        lhs - rhs
    } else {
        rhs - lhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_cc_algo_ok() {
        let algo = CongestionControlAlgorithm::from_str("reno").unwrap();
        assert_eq!(algo, CongestionControlAlgorithm::Reno);
    }

    #[test]
    fn lookup_cc_algo_bad() {
        assert_eq!(
            CongestionControlAlgorithm::from_str("???"),
            Err(Error::CongestionControl)
        );
    }

    #[test]
    fn collapse_cwnd() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        // cwnd will be reset.
        r.collapse_cwnd();
        assert_eq!(r.cwnd(), MINIMUM_WINDOW);
    }

    #[test]
    fn loss_on_pto() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: 2,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 3,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::EPOCH_APPLICATION,
                true,
                now,
                ""
            ),
            Ok(())
        );

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // PTO.
        r.on_loss_detection_timeout(true, now, "");
        assert_eq!(r.loss_probes[packet::EPOCH_APPLICATION], 2);
        assert_eq!(r.lost_count, 0);
        assert_eq!(r.pto_count, 1);

        let p = Sent {
            pkt_num: 4,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 5,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);
        assert_eq!(r.lost_count, 0);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // PTO packets are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(4..6);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::EPOCH_APPLICATION,
                true,
                now,
                ""
            ),
            Ok(())
        );

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 2);
    }

    #[test]
    fn loss_on_timer() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: 2,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 3,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets and the last one are acked.
        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);
        acked.insert(3..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::EPOCH_APPLICATION,
                true,
                now,
                ""
            ),
            Ok(())
        );

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 2);
        assert_eq!(r.bytes_in_flight, 1000);
        assert_eq!(r.lost_count, 0);

        // Wait until loss detection timer expires.
        now = r.loss_detection_timer().unwrap();

        // Packet is declared lost.
        r.on_loss_detection_timeout(true, now, "");
        assert_eq!(r.loss_probes[packet::EPOCH_APPLICATION], 0);

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.lost_count, 1);
    }

    #[test]
    fn loss_on_reordering() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 0);

        // Start by sending a few packets.
        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 1);
        assert_eq!(r.bytes_in_flight, 1000);

        let p = Sent {
            pkt_num: 1,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 2);
        assert_eq!(r.bytes_in_flight, 2000);

        let p = Sent {
            pkt_num: 2,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 3);
        assert_eq!(r.bytes_in_flight, 3000);

        let p = Sent {
            pkt_num: 3,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: 1000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        r.on_packet_sent(p, packet::EPOCH_APPLICATION, true, now, "");
        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 4);
        assert_eq!(r.bytes_in_flight, 4000);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // ACKs are reordered.
        let mut acked = ranges::RangeSet::default();
        acked.insert(2..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::EPOCH_APPLICATION,
                true,
                now,
                ""
            ),
            Ok(())
        );

        now += Duration::from_millis(10);

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::EPOCH_APPLICATION,
                true,
                now,
                ""
            ),
            Ok(())
        );

        assert_eq!(r.sent[packet::EPOCH_APPLICATION].len(), 0);
        assert_eq!(r.bytes_in_flight, 0);

        // Spurious loss.
        assert_eq!(r.lost_count, 1);
    }
}

mod cubic;
mod delivery_rate;
mod hystart;
mod reno;
