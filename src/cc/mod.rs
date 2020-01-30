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
use crate::Config;

pub const INITIAL_WINDOW_PACKETS: usize = 10;

pub const MINIMUM_WINDOW_PACKETS: usize = 2;

pub const LOSS_REDUCTION_FACTOR: f64 = 0.5;

/// Maximum datagram size used for congestion control.
pub const MAX_DATAGRAM_SIZE: usize = 1200;

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

/// Parameters for congestion control.
#[derive(Copy, Clone)]
pub struct CongestionControlParams {
    initial_window_packets: usize,

    initial_window: usize,

    minimum_window_packets: usize,

    minimum_window: usize,

    max_datagram_size: usize,
}

impl Default for CongestionControlParams {
    fn default() -> Self {
        CongestionControlParams {
            initial_window_packets: cc::INITIAL_WINDOW_PACKETS,
            initial_window: cc::INITIAL_WINDOW_PACKETS * cc::MAX_DATAGRAM_SIZE,
            minimum_window_packets: cc::MINIMUM_WINDOW_PACKETS,
            minimum_window: cc::MINIMUM_WINDOW_PACKETS * cc::MAX_DATAGRAM_SIZE,
            max_datagram_size: cc::MAX_DATAGRAM_SIZE,
        }
    }
}

impl CongestionControlParams {
    fn max_datagram_size(&mut self, max_datagram_size: usize) {
        self.max_datagram_size = max_datagram_size;

        self.initial_window =
            self.initial_window_packets * self.max_datagram_size;
        self.minimum_window =
            self.minimum_window_packets * self.max_datagram_size;
    }
}

/// Congestion control algorithm.
pub trait CongestionControl
where
    Self: std::fmt::Debug,
{
    fn new(params: CongestionControlParams) -> Self
    where
        Self: Sized;

    fn cwnd(&self) -> usize;

    fn bytes_in_flight(&self) -> usize;

    fn decrease_bytes_in_flight(&mut self, bytes_in_flight: usize);

    fn congestion_recovery_start_time(&self) -> Option<Instant>;

    /// Resets the congestion window to the minimum size.
    fn collapse_cwnd(&mut self);

    /// OnPacketSentCC(bytes_sent)
    fn on_packet_sent_cc(&mut self, bytes_sent: usize, trace_id: &str);

    /// InCongestionRecovery(sent_time)
    fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time() {
            Some(congestion_recovery_start_time) =>
                sent_time <= congestion_recovery_start_time,

            None => false,
        }
    }

    /// OnPacketAckedCC(packet)
    fn on_packet_acked_cc(
        &mut self, packet: &Sent, srtt: Duration, min_rtt: Duration,
        app_limited: bool, trace_id: &str,
    );

    /// CongestionEvent(time_sent)
    fn congestion_event(
        &mut self, time_sent: Instant, now: Instant, trace_id: &str,
    );

    /// Update max_datagram_size.
    fn set_max_datagram_size(&mut self, max_datagram_size: usize);

    fn max_datagram_size(&self) -> usize;
}

/// Instances a congestion control implementation based on the CC algorithm ID.
pub fn new_congestion_control(config: &Config) -> Box<dyn CongestionControl> {
    let mut cc_params = cc::CongestionControlParams::default();

    cc_params.max_datagram_size(config.max_datagram_size);

    trace!("Initializing congestion control: {:?}", config.cc_algorithm);

    match config.cc_algorithm {
        Algorithm::Reno => Box::new(cc::reno::Reno::new(cc_params)),
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    #[test]
    fn new_cc() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config.set_cc_algorithm(Algorithm::Reno);

        let cc = cc::new_congestion_control(&config);

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
        assert_eq!(Algorithm::from_str("???"), Err(Error::CongestionControl));
    }

    #[test]
    fn max_datagram_size() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config.set_cc_algorithm(Algorithm::Reno);
        config.set_max_datagram_size(5000);

        let cc = cc::new_congestion_control(&config);

        assert_eq!(cc.cwnd(), 5000 * cc::INITIAL_WINDOW_PACKETS);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn min_datagram_size() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config.set_cc_algorithm(Algorithm::Reno);
        config.set_max_datagram_size(500);

        let cc = cc::new_congestion_control(&config);

        assert_eq!(cc.max_datagram_size(), 1200);
    }
}

mod reno;
