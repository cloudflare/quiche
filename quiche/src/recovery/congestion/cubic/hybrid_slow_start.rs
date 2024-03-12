// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright (C) 2023, Cloudflare, Inc.
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

use std::time::Duration;

const HYBRID_START_MIN_SAMPLES: usize = 8;
const HYBRID_START_DELAY_FACTOR_EXP: usize = 3;
const HYBRID_START_LOW_WINDOW: usize = 16;
const HYBRID_START_DELAY_MIN_THRESHOLD_US: u128 = 4000;
const HYBRID_START_DELAY_MAX_THRESHOLD_US: u128 = 16000;

#[derive(Default, Debug)]
pub(crate) struct HybridSlowStart {
    /// Whether the hybrid slow start has been started.
    pub(crate) started: bool,
    /// Whether a condition for exiting slow start has been found.
    found: bool,
    /// Last packet number sent which was CWND limited.
    last_sent_packet_number: u64,
    /// End of the receive round.
    end_packet_number: Option<u64>,
    /// Number of rtt samples in the current round.
    rtt_sample_count: usize,
    // a/ The minimum rtt of current round.
    current_min_rtt: Duration,
}

impl HybridSlowStart {
    #[inline]
    pub(crate) fn restart(&mut self) {
        self.started = false;
        self.found = false;
    }

    #[inline]
    pub(crate) fn on_packet_sent(&mut self, packet_number: u64) {
        self.last_sent_packet_number = packet_number;
    }

    #[inline]
    pub(crate) fn on_packet_acked(&mut self, acked_packet_number: u64) {
        // OnPacketAcked gets invoked after ShouldExitSlowStart, so it's best to
        // end the round when the final packet of the burst is received
        // and start it on the next incoming ack.
        if self.is_end_of_round(acked_packet_number) {
            self.started = false;
        }
    }

    #[inline]
    pub(crate) fn start_receive_round(&mut self, last_sent: u64) {
        self.end_packet_number = Some(last_sent);
        self.current_min_rtt = Duration::from_micros(0);
        self.rtt_sample_count = 0;
        self.started = true;
    }

    #[inline]
    pub(crate) fn is_end_of_round(&self, ack: u64) -> bool {
        match self.end_packet_number {
            None => true,
            Some(num) => num <= ack,
        }
    }

    #[inline]
    pub(crate) fn should_exit_slow_start(
        &mut self, latest_rtt: Duration, min_rtt: Duration,
        congestion_window: usize,
    ) -> bool {
        if !self.started {
            // Time to start the hybrid slow start.
            self.start_receive_round(self.last_sent_packet_number);
        }

        if self.found {
            return true;
        }
        // Second detection parameter - delay increase detection.
        // Compare the minimum delay (current_min_rtt_) of the current
        // burst of packets relative to the minimum delay during the session.
        // Note: we only look at the first few(8) packets in each burst, since we
        // only want to compare the lowest RTT of the burst relative to previous
        // bursts.
        self.rtt_sample_count += 1;
        if self.rtt_sample_count <= HYBRID_START_MIN_SAMPLES &&
            (self.current_min_rtt.is_zero() ||
                self.current_min_rtt > latest_rtt)
        {
            self.current_min_rtt = latest_rtt;
        }
        // We only need to check this once per round.
        if self.rtt_sample_count == HYBRID_START_MIN_SAMPLES {
            // Divide min_rtt by 8 to get a rtt increase threshold for exiting.
            let min_rtt_increase_threshold_us =
                min_rtt.as_micros() >> HYBRID_START_DELAY_FACTOR_EXP;
            // Ensure the rtt threshold is never less than 2ms or more than 16ms.
            let min_rtt_increase_threshold_us = min_rtt_increase_threshold_us
                .min(HYBRID_START_DELAY_MAX_THRESHOLD_US);
            let min_rtt_increase_threshold = Duration::from_micros(
                min_rtt_increase_threshold_us
                    .max(HYBRID_START_DELAY_MIN_THRESHOLD_US)
                    as u64,
            );

            if self.current_min_rtt > min_rtt + min_rtt_increase_threshold {
                self.found = true;
            }
        }

        // Exit from slow start if the cwnd is greater than 16 and
        // increasing delay is found.
        congestion_window >= HYBRID_START_LOW_WINDOW && self.found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() {
        let mut slow_start = HybridSlowStart::default();
        let mut packet_number = 1;
        let end_packet_number = 3;

        slow_start.start_receive_round(end_packet_number);
        assert!(!slow_start.is_end_of_round(packet_number));
        packet_number += 1;
        // Test duplicates.
        assert!(!slow_start.is_end_of_round(packet_number));
        assert!(!slow_start.is_end_of_round(packet_number));
        packet_number += 1;
        assert!(slow_start.is_end_of_round(packet_number));
        packet_number += 1;
        // Test without a new registered end_packet_number;
        assert!(slow_start.is_end_of_round(packet_number));
        packet_number += 1;
        let end_packet_number = 20;

        slow_start.start_receive_round(end_packet_number);
        for packet_number in packet_number..end_packet_number {
            assert!(!slow_start.is_end_of_round(packet_number));
        }
        assert!(slow_start.is_end_of_round(end_packet_number));
    }

    #[test]
    fn delay() {
        // We expect to detect the increase at +1/8 of the RTT; hence at a typical
        // RTT of 60ms the detection will happen at 67.5 ms.
        let mut slow_start = HybridSlowStart::default();
        let mut end_packet_number = 1;
        let rtt = Duration::from_millis(60);

        slow_start.start_receive_round(end_packet_number);
        end_packet_number += 1;

        // Will not trigger since our lowest RTT in our burst is the same as the
        // long term RTT provided.
        for n in 0..HYBRID_START_MIN_SAMPLES as u64 {
            assert!(!slow_start.should_exit_slow_start(
                rtt + Duration::from_millis(n),
                rtt,
                100
            ));
        }

        slow_start.start_receive_round(end_packet_number);

        for n in 1..HYBRID_START_MIN_SAMPLES as u64 {
            assert!(!slow_start.should_exit_slow_start(
                rtt + Duration::from_millis(n + 10),
                rtt,
                100
            ));
        }

        // Expect to trigger since all packets in this burst was above the long
        // term RTT provided.
        assert!(slow_start.should_exit_slow_start(
            rtt + Duration::from_millis(HYBRID_START_MIN_SAMPLES as u64 + 10),
            rtt,
            100
        ));
    }
}
