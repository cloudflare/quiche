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

use std::time::Duration;
use std::time::Instant;

use std::collections::BTreeMap;

use crate::Config;
use crate::Error;
use crate::Result;

use crate::cc;
use crate::frame;
use crate::packet;
use crate::ranges;

// Loss Recovery
const PACKET_THRESHOLD: u64 = 3;

const TIME_THRESHOLD: f64 = 9.0 / 8.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const INITIAL_RTT: Duration = Duration::from_millis(500);

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

pub struct Sent {
    pub pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    pub time: Instant,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub recent_delivered_packet_sent_time: Instant,

    pub is_app_limited: bool,
}

// Rate estimation
// https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-00
#[derive(Default)]
pub struct RateSample {
    delivery_rate: f64,

    is_app_limited: bool,

    interval: Duration,

    delivered: usize,

    prior_delivered: usize,

    prior_time: Option<Instant>,

    send_elapsed: Duration,

    ack_elapsed: Duration,
}

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    pto_count: u32,

    time_of_last_sent_ack_eliciting_pkt: [Option<Instant>; packet::EPOCH_COUNT],

    largest_acked_pkt: [u64; packet::EPOCH_COUNT],

    largest_sent_pkt: [u64; packet::EPOCH_COUNT],

    latest_rtt: Duration,

    smoothed_rtt: Option<Duration>,

    rttvar: Duration,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: [Option<Instant>; packet::EPOCH_COUNT],

    sent: [BTreeMap<u64, Sent>; packet::EPOCH_COUNT],

    pub lost: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub acked: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub lost_count: usize,

    pub loss_probes: [usize; packet::EPOCH_COUNT],

    pub cc: Box<dyn cc::CongestionControl>,

    app_limited: bool,

    delivered: usize,

    delivered_time: Option<Instant>,

    recent_delivered_packet_sent_time: Option<Instant>,

    app_limited_at_pkt: usize,

    rate_sample: RateSample,
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

            min_rtt: Duration::new(0, 0),

            rttvar: Duration::new(0, 0),

            max_ack_delay: Duration::from_millis(25),

            loss_time: [None; packet::EPOCH_COUNT],

            sent: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],

            lost: [Vec::new(), Vec::new(), Vec::new()],

            acked: [Vec::new(), Vec::new(), Vec::new()],

            lost_count: 0,

            loss_probes: [0; packet::EPOCH_COUNT],

            cc: cc::new_congestion_control(config.cc_algorithm),

            app_limited: false,

            delivered: 0,

            delivered_time: None,

            recent_delivered_packet_sent_time: None,

            app_limited_at_pkt: 0,

            rate_sample: RateSample::default(),
        }
    }

    pub fn on_packet_sent(
        &mut self, mut pkt: Sent, epoch: packet::Epoch,
        handshake_completed: bool, now: Instant, trace_id: &str,
    ) {
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let sent_bytes = pkt.size;

        self.rate_on_packet_sent(&mut pkt, now);

        self.largest_sent_pkt[epoch] =
            cmp::max(self.largest_sent_pkt[epoch], pkt.pkt_num);

        self.sent[epoch].insert(pkt.pkt_num, pkt);

        if in_flight {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_pkt[epoch] = Some(now);
            }

            self.app_limited =
                (self.cc.bytes_in_flight() + sent_bytes) < self.cc.cwnd();

            // OnPacketSentCC
            self.cc.on_packet_sent_cc(sent_bytes, now, trace_id);

            self.set_loss_detection_timer(handshake_completed);
        }

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_ack_received(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_completed: bool, now: Instant,
        trace_id: &str,
    ) -> Result<()> {
        let largest_acked = ranges.largest().unwrap();

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

        if let Some(pkt) = self.sent[epoch].get(&self.largest_acked_pkt[epoch]) {
            if pkt.ack_eliciting {
                let latest_rtt = now - pkt.time;

                let ack_delay = if epoch == packet::EPOCH_APPLICATION {
                    Duration::from_micros(ack_delay)
                } else {
                    Duration::from_micros(0)
                };

                self.update_rtt(latest_rtt, ack_delay);
            }
        }

        let mut has_newly_acked = false;

        // Processing acked packets in reverse order (from largest to smallest)
        // appears to be faster, possibly due to the BTreeMap implementation.
        for pn in ranges.flatten().rev() {
            // If the acked packet number is lower than the lowest unacked packet
            // number it means that the packet is not newly acked, so return
            // early.
            //
            // Since we process acked packets from largest to lowest, this means
            // that as soon as we see an already-acked packet number
            // all following packet numbers will also be already
            // acked.
            if let Some(lowest) = self.sent[epoch].values().nth(0) {
                if pn < lowest.pkt_num {
                    break;
                }
            }

            let newly_acked = self.on_packet_acked(pn, epoch, now, trace_id);
            has_newly_acked = cmp::max(has_newly_acked, newly_acked);

            if newly_acked {
                trace!("{} packet newly acked {}", trace_id, pn);
            }
        }

        self.rate_estimate();
        if !has_newly_acked {
            return Ok(());
        }

        self.detect_lost_packets(epoch, now, trace_id);

        self.pto_count = 0;

        self.set_loss_detection_timer(handshake_completed);

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

    pub fn drop_unacked_data(&mut self, epoch: packet::Epoch) {
        let mut unacked_bytes = 0;

        for p in self.sent[epoch].values_mut().filter(|p| p.in_flight) {
            unacked_bytes += p.size;
        }

        self.cc.decrease_bytes_in_flight(unacked_bytes);

        self.loss_time[epoch] = None;
        self.loss_probes[epoch] = 0;
        self.time_of_last_sent_ack_eliciting_pkt[epoch] = None;

        self.sent[epoch].clear();
        self.lost[epoch].clear();
        self.acked[epoch].clear();
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.loss_probes.iter().any(|&x| x > 0) {
            return std::usize::MAX;
        }

        self.cc.cwnd().saturating_sub(self.cc.bytes_in_flight())
    }

    pub fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(INITIAL_RTT)
    }

    pub fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rttvar * 4, GRANULARITY) + self.max_ack_delay
    }

    pub fn delivery_rate(&self) -> f64 {
        self.rate_sample.delivery_rate
    }

    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = latest_rtt;

        match self.smoothed_rtt {
            // First RTT sample.
            None => {
                self.min_rtt = latest_rtt;

                self.smoothed_rtt = Some(latest_rtt);

                self.rttvar = latest_rtt / 2;
            },

            Some(srtt) => {
                self.min_rtt = cmp::min(self.min_rtt, latest_rtt);

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

        if self.cc.bytes_in_flight() == 0 {
            // TODO: check if peer is awaiting address validation.
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let timeout = match self.smoothed_rtt {
            None => INITIAL_RTT * 2,

            Some(_) => self.pto() * 2_u32.pow(self.pto_count),
        };

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

        let mut lost_pkt: Vec<u64> = Vec::new();

        self.loss_time[epoch] = None;

        let loss_delay =
            cmp::max(self.latest_rtt, self.rtt()).mul_f64(TIME_THRESHOLD);

        // Minimum time of kGranularity before packets are deemed lost.
        let loss_delay = cmp::max(loss_delay, GRANULARITY);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now - loss_delay;

        for (_, unacked) in self.sent[epoch].range(..=largest_acked) {
            // Mark packet as lost, or set time when it should be marked.
            if unacked.time <= lost_send_time ||
                largest_acked >= unacked.pkt_num + PACKET_THRESHOLD
            {
                if unacked.in_flight {
                    trace!(
                        "{} packet {} lost on epoch {}",
                        trace_id,
                        unacked.pkt_num,
                        epoch
                    );
                }

                // We can't remove the lost packet from |self.sent| here, so
                // simply keep track of the number so it can be removed later.
                lost_pkt.push(unacked.pkt_num);
            } else {
                let loss_time = match self.loss_time[epoch] {
                    None => unacked.time + loss_delay,

                    Some(loss_time) =>
                        cmp::min(loss_time, unacked.time + loss_delay),
                };

                self.loss_time[epoch] = Some(loss_time);
            }
        }

        if !lost_pkt.is_empty() {
            self.on_packets_lost(lost_pkt, epoch, now, trace_id);
        }
    }

    fn on_packet_acked(
        &mut self, pkt_num: u64, epoch: packet::Epoch, now: Instant,
        trace_id: &str,
    ) -> bool {
        // Check if packet is newly acked.
        if let Some(mut p) = self.sent[epoch].remove(&pkt_num) {
            self.acked[epoch].append(&mut p.frames);

            if p.in_flight {
                // OnPacketAckedCC(acked_packet)
                self.cc.on_packet_acked_cc(
                    &p,
                    self.rtt(),
                    self.min_rtt,
                    self.app_limited,
                    now,
                    trace_id,
                );

                self.rate_on_ack_received(p, now);
            }

            return true;
        }

        // Is not newly acked.
        false
    }

    // TODO: move to Congestion Control and implement draft 24
    fn in_persistent_congestion(&mut self, _largest_lost_pkt: &Sent) -> bool {
        let _congestion_period = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;

        // TODO: properly detect persistent congestion
        false
    }

    // TODO: move to Congestion Control
    fn on_packets_lost(
        &mut self, lost_pkt: Vec<u64>, epoch: packet::Epoch, now: Instant,
        trace_id: &str,
    ) {
        // Differently from OnPacketsLost(), we need to handle both
        // in-flight and non-in-flight packets, so need to keep track
        // of whether we saw any lost in-flight packet to trigger the
        // congestion event later.
        let mut largest_lost_pkt: Option<Sent> = None;

        for lost in lost_pkt {
            let mut p = self.sent[epoch].remove(&lost).unwrap();

            self.lost_count += 1;

            if !p.in_flight {
                continue;
            }

            self.cc.decrease_bytes_in_flight(p.size);

            self.lost[epoch].append(&mut p.frames);

            largest_lost_pkt = Some(p);
        }

        if let Some(largest_lost_pkt) = largest_lost_pkt {
            // CongestionEvent
            self.cc
                .congestion_event(largest_lost_pkt.time, now, trace_id);

            if self.in_persistent_congestion(&largest_lost_pkt) {
                self.cc.collapse_cwnd();
            }
        }
    }

    fn rate_on_packet_sent(&mut self, pkt: &mut Sent, now: Instant) {
        if self.delivered_time.is_none() {
            self.delivered_time = Some(now);
        }

        if self.recent_delivered_packet_sent_time.is_none() {
            self.recent_delivered_packet_sent_time = Some(now);
        }

        pkt.delivered = self.delivered;
        pkt.delivered_time = self.delivered_time.unwrap();

        pkt.recent_delivered_packet_sent_time =
            self.recent_delivered_packet_sent_time.unwrap();

        pkt.is_app_limited = self.app_limited_at_pkt > 0;
    }

    fn rate_on_ack_received(&mut self, pkt: Sent, now: Instant) {
        self.rate_sample.prior_time = Some(pkt.delivered_time);

        self.delivered += pkt.size;
        self.delivered_time = Some(now);

        if pkt.delivered > self.rate_sample.prior_delivered {
            self.rate_sample.prior_delivered = pkt.delivered;
            self.rate_sample.is_app_limited = pkt.is_app_limited;

            self.rate_sample.send_elapsed =
                pkt.time - pkt.recent_delivered_packet_sent_time;

            self.rate_sample.ack_elapsed = self
                .delivered_time
                .unwrap()
                .duration_since(pkt.delivered_time);

            self.recent_delivered_packet_sent_time = Some(pkt.time);
        }
    }

    fn rate_estimate(&mut self) {
        if (self.app_limited_at_pkt > 0) &&
            (self.delivered > self.app_limited_at_pkt)
        {
            self.app_limited_at_pkt = 0;
        }

        match self.rate_sample.prior_time {
            Some(_) => {
                self.rate_sample.delivered =
                    self.delivered - self.rate_sample.prior_delivered;

                self.rate_sample.interval = cmp::max(
                    self.rate_sample.send_elapsed,
                    self.rate_sample.ack_elapsed,
                );
            },
            None => return,
        }

        if self.rate_sample.interval.as_secs_f64() > 0.0 {
            self.rate_sample.delivery_rate = self.rate_sample.delivered as f64 /
                self.rate_sample.interval.as_secs_f64();
        }
    }

    pub fn rate_check_app_limited(&mut self) {
        if self.app_limited {
            let limited = self.delivered + self.cc.bytes_in_flight();
            self.app_limited_at_pkt = if limited > 0 { limited } else { 1 };
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
        write!(f, "{:?} ", self.cc)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        if let Some(t) = self.delivered_time {
            write!(f, "delivered_time={:?}", t.elapsed())?;
        }
        if let Some(t) = self.recent_delivered_packet_sent_time {
            write!(f, "recent_delivered_packet_sent_time={:?} ", t.elapsed())?;
        }
        write!(f, "app_limited_at_pkt={:?} ", self.app_limited_at_pkt)?;

        Ok(())
    }
}

impl std::fmt::Debug for RateSample {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "delivery_rate={:?} ", self.delivery_rate)?;
        write!(f, "interval={:?} ", self.interval)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        write!(f, "prior_delivered={:?} ", self.prior_delivered)?;
        write!(f, "send_elapsed={:?} ", self.send_elapsed)?;
        write!(f, "ack_elapsed={:?} ", self.ack_elapsed)?;
        if let Some(t) = self.prior_time {
            write!(f, "prior_time={:?} ", t.elapsed())?;
        }

        Ok(())
    }
}

impl std::fmt::Debug for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pkt_num={:?} ", self.pkt_num)?;
        write!(f, "pkt_sent_time={:?} ", self.time.elapsed())?;
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
    fn rate_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut recovery = Recovery::new(&config);

        let mut pkt_1 = Sent {
            pkt_num: 0,
            frames: vec![],
            time: Instant::now(),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
        };

        recovery.rate_on_packet_sent(&mut pkt_1, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recovery.rate_on_ack_received(pkt_1, Instant::now());

        let mut pkt_2 = Sent {
            pkt_num: 1,
            frames: vec![],
            time: Instant::now(),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
        };

        recovery.rate_on_packet_sent(&mut pkt_2, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recovery.rate_on_ack_received(pkt_2, Instant::now());
        recovery.rate_estimate();

        assert!(recovery.rate_sample.delivery_rate > 0.0);
    }

    #[test]
    fn app_limited_check() {
        let config = Config::new(0xbabababa).unwrap();
        let mut recvry = Recovery::new(&config);

        let mut pkt_1 = Sent {
            pkt_num: 0,
            frames: vec![],
            time: Instant::now(),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
        };

        recvry.rate_on_packet_sent(&mut pkt_1, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recvry.rate_on_ack_received(pkt_1, Instant::now());

        let mut pkt_2 = Sent {
            pkt_num: 1,
            frames: vec![],
            time: Instant::now(),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: Instant::now(),
            recent_delivered_packet_sent_time: Instant::now(),
            is_app_limited: false,
        };

        recvry.app_limited = true;
        recvry.rate_check_app_limited();
        recvry.rate_on_packet_sent(&mut pkt_2, Instant::now());
        std::thread::sleep(Duration::from_millis(50));
        recvry.rate_on_ack_received(pkt_2, Instant::now());
        recvry.rate_estimate();

        assert_eq!(recvry.app_limited_at_pkt, 0);
    }
}
