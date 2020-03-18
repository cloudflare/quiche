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

use std::str::FromStr;

use std::time::Duration;
use std::time::Instant;

use crate::cc;
use crate::recovery::Sent;

pub const INITIAL_WINDOW_PACKETS: usize = 10;

pub const INITIAL_WINDOW: usize = INITIAL_WINDOW_PACKETS * MAX_DATAGRAM_SIZE;

pub const MINIMUM_WINDOW: usize = 2 * MAX_DATAGRAM_SIZE;

pub const MAX_DATAGRAM_SIZE: usize = 1452;

pub const LOSS_REDUCTION_FACTOR: f64 = 0.5;

/// Available congestion control algorithms.
///
/// This enum provides currently available list of congestion control
/// algorithms.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Algorithm {
    /// Reno congestion control algorithm (default). `reno` in a string form.
    Reno = 0,
}

impl FromStr for Algorithm {
    type Err = crate::Error;

    /// Converts a string to `CongestionControlAlgorithm`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "reno" => Ok(Algorithm::Reno),
            _ => Err(crate::Error::CongestionControl),
        }
    }
}

/// Congestion control algorithm.
pub trait CongestionControl:
    CCCommon + CCOnPacketSent + CCOnPacketAcked + CCCongestionEvent
where
    Self: std::fmt::Debug,
{
    fn new() -> Self
    where
        Self: Sized;
}

/// Congestion Control Hook OnPacketSentCC().
pub trait CCOnPacketSent {
    fn on_packet_sent_cc(
        &mut self, bytes_sent: usize, now: Instant, trace_id: &str,
    );
}

/// Congestion Control Hook OnPacketAckedCC().
pub trait CCOnPacketAcked {
    fn on_packet_acked_cc(
        &mut self, packet: &Sent, srtt: Duration, min_rtt: Duration,
        app_limited: bool, now: Instant, trace_id: &str,
    );
}

/// Congestion Control Hook CongestionEvent().
pub trait CCCongestionEvent {
    fn congestion_event(
        &mut self, time_sent: Instant, now: Instant, trace_id: &str,
    );
}

/// Commonly used methods in Congestion Control.
pub trait CCCommon {
    fn cwnd(&self) -> usize;

    fn bytes_in_flight(&self) -> usize;

    fn decrease_bytes_in_flight(&mut self, bytes_in_flight: usize);

    /// Returns when the current recovery episode started.
    /// None if currently not in the recovery.
    fn congestion_recovery_start_time(&self) -> Option<Instant>;

    /// Resets the congestion window to the minimum size.
    fn collapse_cwnd(&mut self);

    /// Returns true if currently in the recovery episode.
    fn in_congestion_recovery(&self, sent_time: Instant) -> bool;
}

macro_rules! impl_cc_common {
    ($name:ident) => {
        impl cc::CCCommon for $name {
            fn cwnd(&self) -> usize {
                self.congestion_window
            }

            fn bytes_in_flight(&self) -> usize {
                self.bytes_in_flight
            }

            fn decrease_bytes_in_flight(&mut self, bytes_in_flight: usize) {
                self.bytes_in_flight =
                    self.bytes_in_flight.saturating_sub(bytes_in_flight);
            }

            fn congestion_recovery_start_time(&self) -> Option<Instant> {
                self.congestion_recovery_start_time
            }

            fn collapse_cwnd(&mut self) {
                self.congestion_window = cc::MINIMUM_WINDOW;
            }

            fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
                match self.congestion_recovery_start_time() {
                    Some(congestion_recovery_start_time) =>
                        sent_time <= congestion_recovery_start_time,

                    None => false,
                }
            }
        }
    };
}

macro_rules! impl_cc_on_packet_sent_reno {
    ($name:ident) => {
        impl cc::CCOnPacketSent for $name {
            fn on_packet_sent_cc(
                &mut self, bytes_sent: usize, _now: Instant, _trace_id: &str,
            ) {
                self.bytes_in_flight += bytes_sent;
            }
        }
    };
}

macro_rules! impl_cc_on_packet_acked_reno {
    ($name:ident) => {
        impl cc::CCOnPacketAcked for $name {
            fn on_packet_acked_cc(
                &mut self, packet: &Sent, _srtt: Duration, _min_rtt: Duration,
                app_limited: bool, _now: Instant, _trace_id: &str,
            ) {
                self.bytes_in_flight -= packet.size;

                if self.in_congestion_recovery(packet.time) {
                    return;
                }

                if app_limited {
                    return;
                }

                if self.congestion_window < self.ssthresh {
                    // Slow start.
                    self.congestion_window += packet.size;
                } else {
                    // Congestion avoidance.
                    self.congestion_window += (cc::MAX_DATAGRAM_SIZE *
                        packet.size) /
                        self.congestion_window;
                }
            }
        }
    };
}

macro_rules! impl_cc_congestion_event_reno {
    ($name:ident) => {
        impl cc::CCCongestionEvent for $name {
            fn congestion_event(
                &mut self, time_sent: Instant, now: Instant, _trace_id: &str,
            ) {
                // Start a new congestion event if packet was sent after the
                // start of the previous congestion recovery period.
                if !self.in_congestion_recovery(time_sent) {
                    self.congestion_recovery_start_time = Some(now);

                    self.congestion_window = (self.congestion_window as f64 *
                        cc::LOSS_REDUCTION_FACTOR)
                        as usize;
                    self.congestion_window =
                        std::cmp::max(self.congestion_window, cc::MINIMUM_WINDOW);
                    self.ssthresh = self.congestion_window;
                }
            }
        }
    };
}

/// Instances a congestion control implementation based on the CC algorithm ID.
pub fn new_congestion_control(algo: Algorithm) -> Box<dyn CongestionControl> {
    trace!("Initializing congestion control: {:?}", algo);
    match algo {
        Algorithm::Reno => Box::new(cc::reno::Reno::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cc() {
        let cc = new_congestion_control(Algorithm::Reno);

        assert!(cc.cwnd() > 0);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn lookup_cc_algo_ok() {
        let algo = Algorithm::from_str("reno").unwrap();

        assert_eq!(algo, Algorithm::Reno);
    }

    #[test]
    fn lookup_cc_algo_bad() {
        assert_eq!(
            Algorithm::from_str("???"),
            Err(crate::Error::CongestionControl)
        );
    }
}

mod reno;
