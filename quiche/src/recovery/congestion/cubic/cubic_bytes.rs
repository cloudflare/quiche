// Copyright (c) 2015 The Chromium Authors. All rights reserved.
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
use std::time::Instant;

use super::DEFAULT_NUM_CONNECTIONS;

// Constants based on TCP defaults.
// The following constants are in 2^10 fractions of a second instead of ms to
// allow a 10 shift right to divide.
const CUBE_SCALE: usize = 40; // 1024*1024^3 (first 1024 is from 0.100^3)
                              // where 0.100 is 100 ms which is the scaling
                              // round trip time.
const CUBE_CONGESTION_WINDOW_SCALE: usize = 410;

const DEFAULT_CUBIC_BACKOFF_FACTOR: f32 = 0.7;

// Additional backoff factor when loss occurs in the concave part of the Cubic
// curve. This additional backoff factor is expected to give up bandwidth to
// new concurrent flows and speed up convergence.
const BETA_LAST_MAX: f32 = 0.85;

#[derive(Debug)]
pub(super) struct CubicBytes {
    /// Number of connections to simulate.
    pub(super) num_connections: usize,
    /// Time when this cycle started, after last loss event.
    epoch: Option<Instant>,
    /// Max congestion window used just before last loss event.
    /// Note: to improve fairness to other streams an additional back off is
    /// applied to this value if the new value is below our latest value.
    last_max_congestion_window: usize,
    /// Number of acked bytes since the cycle started (epoch).
    acked_bytes_count: usize,
    /// TCP Reno equivalent congestion window in packets.
    estimated_tcp_congestion_window: usize,
    /// Origin point of cubic function.
    origin_point_congestion_window: usize,
    /// Time to origin point of cubic function in 2^10 fractions of a second.
    time_to_origin_point: u64,
    /// Last congestion window in packets computed by cubic function.
    last_target_congestion_window: usize,
    pub(super) mss: usize,
}

impl CubicBytes {
    pub(super) fn new(mss: usize) -> Self {
        CubicBytes {
            num_connections: DEFAULT_NUM_CONNECTIONS,
            epoch: None,
            last_max_congestion_window: 0,
            acked_bytes_count: 0,
            estimated_tcp_congestion_window: 0,
            origin_point_congestion_window: 0,
            time_to_origin_point: 0,
            last_target_congestion_window: 0,
            mss,
        }
    }

    #[inline]
    pub(super) fn on_app_limited(&mut self) {
        self.epoch = None;
    }

    fn cube_factor(&self) -> u64 {
        (1u64 << CUBE_SCALE) /
            CUBE_CONGESTION_WINDOW_SCALE as u64 /
            (self.mss as u64)
    }

    #[inline]
    pub(super) fn alpha(&self) -> f32 {
        // TCPFriendly alpha is described in Section 3.3 of the CUBIC paper. Note
        // that beta here is a cwnd multiplier, and is equal to 1-beta
        // from the paper. We derive the equivalent alpha for an
        // N-connection emulation as:
        let beta = self.beta();
        let num_connections = self.num_connections as f32;
        3. * num_connections * num_connections * (1. - beta) / (1. + beta)
    }

    #[inline]
    pub(super) fn beta(&self) -> f32 {
        // kNConnectionBeta is the backoff factor after loss for our N-connection
        // emulation, which emulates the effective backoff of an ensemble of N
        // TCP-Reno connections on a single loss event. The effective multiplier
        // is computed as:
        let num_connections = self.num_connections as f32;
        (num_connections - 1. + DEFAULT_CUBIC_BACKOFF_FACTOR) / num_connections
    }

    #[inline]
    pub(super) fn beta_last_max(&self) -> f32 {
        // BetaLastMax is the additional backoff factor after loss for our
        // N-connection emulation, which emulates the additional backoff of
        // an ensemble of N TCP-Reno connections on a single loss event. The
        // effective multiplier is computed as:
        let num_connections = self.num_connections as f32;
        (num_connections - 1. + BETA_LAST_MAX) / num_connections
    }

    #[inline]
    pub(super) fn reset(&mut self) {
        self.epoch = None; // Reset time.
        self.last_max_congestion_window = 0;
        self.acked_bytes_count = 0;
        self.estimated_tcp_congestion_window = 0;
        self.origin_point_congestion_window = 0;
        self.time_to_origin_point = 0;
        self.last_target_congestion_window = 0;
    }

    pub(super) fn congestion_window_after_ack(
        &mut self, acked_bytes: usize, current_congestion_window: usize,
        delay_min: Duration, event_time: Instant,
    ) -> usize {
        self.acked_bytes_count += acked_bytes;

        if self.epoch.is_none() {
            self.epoch = Some(event_time);
            self.acked_bytes_count = acked_bytes;

            // Reset estimated_tcp_congestion_window_ to be in sync with cubic.
            self.estimated_tcp_congestion_window = current_congestion_window;
            if self.last_max_congestion_window <= current_congestion_window {
                self.time_to_origin_point = 0;
                self.origin_point_congestion_window = current_congestion_window;
            } else {
                self.time_to_origin_point = f32::cbrt(
                    (self.cube_factor() *
                        (self.last_max_congestion_window as u64 -
                            current_congestion_window as u64))
                        as f32,
                ) as u64;

                self.origin_point_congestion_window =
                    self.last_max_congestion_window;
            }
        }
        // Change the time unit from microseconds to 2^10 fractions per second.
        // Take the round trip time in account. This is done to allow us
        // to use shift as a divide operator.
        let elapsed_time = (((event_time + delay_min - self.epoch.unwrap())
            .as_micros() as u64) <<
            10) /
            1_000_000;

        // Right-shifts of negative, signed numbers have implementation-dependent
        // behavior, so force the offset to be positive, as is done in the kernel.
        let offset = self.time_to_origin_point.abs_diff(elapsed_time) as usize;

        let delta_congestion_window = ((CUBE_CONGESTION_WINDOW_SCALE as u64 *
            offset as u64 *
            offset as u64 *
            offset as u64 *
            self.mss as u64) >>
            CUBE_SCALE as u64) as usize;

        let add_delta = elapsed_time > self.time_to_origin_point;

        let mut target_congestion_window = if add_delta {
            self.origin_point_congestion_window + delta_congestion_window
        } else {
            self.origin_point_congestion_window - delta_congestion_window
        };
        // Limit the CWND increase to half the acked bytes.
        target_congestion_window = target_congestion_window
            .min(current_congestion_window + self.acked_bytes_count / 2);
        // Increase the window by approximately Alpha * 1 MSS of bytes every
        // time we ack an estimated tcp window of bytes.  For small
        // congestion windows (less than 25), the formula below will
        // increase slightly slower than linearly per estimated tcp window
        // of bytes.

        // Using assign instead of += because the way C++ handles casting order is
        // it first converts the lhs to a float, performs the addition and then
        // converts to integer
        let inc = self.acked_bytes_count as f32 *
            (self.alpha() * self.mss as f32) /
            self.estimated_tcp_congestion_window as f32;

        #[cfg(not(test))]
        let inc = inc.max(9.);

        self.estimated_tcp_congestion_window =
            (self.estimated_tcp_congestion_window as f32 + inc) as usize;

        self.acked_bytes_count = 0;

        // We have a new cubic congestion window.
        self.last_target_congestion_window = target_congestion_window;

        // Compute target congestion_window based on cubic target and estimated
        // TCP congestion_window, use highest (fastest).
        target_congestion_window =
            target_congestion_window.max(self.estimated_tcp_congestion_window);

        target_congestion_window
    }

    pub(super) fn congestion_window_after_loss(
        &mut self, current_congestion_window: usize,
    ) -> usize {
        // Since bytes-mode Reno mode slightly under-estimates the cwnd, we
        // may never reach precisely the last cwnd over the course of an
        // RTT.  Do not interpret a slight under-estimation as competing traffic.
        if current_congestion_window + self.mss < self.last_max_congestion_window
        {
            // We never reached the old max, so assume we are competing with
            // another flow. Use our extra back off factor to allow the other
            // flow to go up.
            self.last_max_congestion_window = (self.beta_last_max() *
                current_congestion_window as f32)
                as usize;
        } else {
            self.last_max_congestion_window = current_congestion_window;
        }
        self.epoch = None; // Reset time.
        (current_congestion_window as f32 * self.beta()) as usize
    }
}

#[cfg(test)]
mod tests {
    const MAX_SEGMENT_SIZE: usize = 1460;

    use super::*;

    const HUNDRED_MS: Duration = Duration::from_millis(100);

    const BETA: f32 = 0.7;
    const NUM_CONNECTIONS: usize = DEFAULT_NUM_CONNECTIONS;
    const N_CONNECTION_BETA: f32 =
        (NUM_CONNECTIONS as f32 - 1. + BETA) / NUM_CONNECTIONS as f32;
    const N_CONNECTION_ALPHA: f32 = (3 * NUM_CONNECTIONS * NUM_CONNECTIONS)
        as f32 *
        (1. - N_CONNECTION_BETA) /
        (1. + N_CONNECTION_BETA);
    const N_CONNECTION_BETA_LAST_MAX: f32 =
        (NUM_CONNECTIONS as f32 - 1. + BETA_LAST_MAX) / NUM_CONNECTIONS as f32;

    const MAX_CUBIC_TIME_INTERVAL: Duration = Duration::from_millis(30);

    fn reno_cwnd_in_bytes(current_cwnd: usize) -> usize {
        let mss = MAX_SEGMENT_SIZE as f32;
        let ccwnd = current_cwnd as f32;
        (ccwnd + mss * (N_CONNECTION_ALPHA * mss) / ccwnd) as usize
    }

    fn cubic_convex_cwnd_in_bytes(
        initial_cwnd: usize, rtt: Duration, elapsed_time: Duration,
    ) -> usize {
        let offset = (((elapsed_time + rtt).as_micros() as u64) << 10) / 1000000;
        let delta_congestion_window =
            ((410 * offset * offset * offset) * MAX_SEGMENT_SIZE as u64) >> 40;
        initial_cwnd + delta_congestion_window as usize
    }

    #[test]
    fn above_origin_with_tighter_bounds() {
        let mut cubic = CubicBytes::new(MAX_SEGMENT_SIZE);
        let mut clock = Instant::now();

        // Convex growth.
        let rtt_min = HUNDRED_MS;
        let rtt_min_ms = rtt_min.as_millis();
        let rtt_min_s = rtt_min_ms as f32 / 1000.0;
        let mut current_cwnd = 10 * MAX_SEGMENT_SIZE;
        let initial_cwnd = current_cwnd;

        let initial_time = clock;
        let expected_first_cwnd = reno_cwnd_in_bytes(current_cwnd);
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            initial_time,
        );
        assert_eq!(expected_first_cwnd, current_cwnd);

        // Normal TCP phase.
        // The maximum number of expected Reno RTTs is calculated by
        // finding the point where the cubic curve and the reno curve meet.
        let max_reno_rtts = (N_CONNECTION_ALPHA /
            (0.4 * rtt_min_s * rtt_min_s * rtt_min_s))
            .sqrt() -
            2.;

        for _ in 0..max_reno_rtts as usize {
            // Alternatively, we expect it to increase by one, every time we
            // receive current_cwnd/Alpha acks back.  (This is another way of
            // saying we expect cwnd to increase by approximately Alpha once
            // we receive current_cwnd number ofacks back).
            let num_acks_this_epoch = ((current_cwnd / MAX_SEGMENT_SIZE) as f32 /
                N_CONNECTION_ALPHA)
                as usize;
            let initial_cwnd_this_epoch = current_cwnd;
            for _ in 0..num_acks_this_epoch {
                // Call once per ACK.
                let expected_next_cwnd = reno_cwnd_in_bytes(current_cwnd);
                current_cwnd = cubic.congestion_window_after_ack(
                    MAX_SEGMENT_SIZE,
                    current_cwnd,
                    rtt_min,
                    clock,
                );

                assert_eq!(expected_next_cwnd, current_cwnd);
            }
            // Our byte-wise Reno implementation is an estimate.  We expect
            // the cwnd to increase by approximately one MSS every
            // cwnd/MAX_SEGMENT_SIZE/Alpha acks, but it may be off by as much as
            // half a packet for smaller values of current_cwnd.
            let cwnd_change_this_epoch = current_cwnd - initial_cwnd_this_epoch;
            assert!(
                cwnd_change_this_epoch.abs_diff(MAX_SEGMENT_SIZE) <
                    MAX_SEGMENT_SIZE / 2
            );
            clock += HUNDRED_MS;
        }

        for _ in 0..54 {
            let max_acks_this_epoch = current_cwnd / MAX_SEGMENT_SIZE;
            let interval = Duration::from_micros(
                HUNDRED_MS.as_micros() as u64 / max_acks_this_epoch as u64,
            );
            for _ in 0..max_acks_this_epoch {
                clock += interval;
                current_cwnd = cubic.congestion_window_after_ack(
                    MAX_SEGMENT_SIZE,
                    current_cwnd,
                    rtt_min,
                    clock,
                );
                let expected_cwnd = cubic_convex_cwnd_in_bytes(
                    initial_cwnd,
                    rtt_min,
                    clock - initial_time,
                );
                // If we allow per-ack updates, every update is a small cubic
                // update.
                assert_eq!(expected_cwnd, current_cwnd);
            }
        }

        let expected_cwnd = cubic_convex_cwnd_in_bytes(
            initial_cwnd,
            rtt_min,
            clock - initial_time,
        );
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            clock,
        );
        assert_eq!(expected_cwnd, current_cwnd);
    }

    // Constructs an artificial scenario to ensure that cubic-convex
    // increases are truly fine-grained:
    //
    // - After starting the epoch, this test advances the elapsed time
    // sufficiently far that cubic will do small increases at less than
    // MaxCubicTimeInterval() intervals.
    //
    // - Sets an artificially large initial cwnd to prevent Reno from the
    // convex increases on every ack.
    #[test]
    fn above_origin_fine_grained_cubing() {
        let mut cubic = CubicBytes::new(MAX_SEGMENT_SIZE);
        let mut clock = Instant::now();

        // Start the test with an artificially large cwnd to prevent Reno
        // from over-taking cubic.
        let mut current_cwnd = 1000 * MAX_SEGMENT_SIZE;
        let initial_cwnd = current_cwnd;
        let rtt_min = HUNDRED_MS;
        let initial_time = clock;

        // Start the epoch and then artificially advance the time.
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            clock,
        );

        clock += Duration::from_millis(600);
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            clock,
        );

        // We expect the algorithm to perform only non-zero, fine-grained cubic
        // increases on every ack in this case.
        for _ in 0..100 {
            clock += Duration::from_millis(10);

            let expected_cwnd = cubic_convex_cwnd_in_bytes(
                initial_cwnd,
                rtt_min,
                clock - initial_time,
            );
            let next_cwnd = cubic.congestion_window_after_ack(
                MAX_SEGMENT_SIZE,
                current_cwnd,
                rtt_min,
                clock,
            );
            // Make sure we are performing cubic increases.
            assert_eq!(expected_cwnd, next_cwnd);
            // Make sure that these are non-zero, less-than-packet sized
            // increases.
            assert!(next_cwnd > current_cwnd);
            let cwnd_delta = next_cwnd - current_cwnd;
            assert!(MAX_SEGMENT_SIZE / 10 > cwnd_delta);
            current_cwnd = next_cwnd;
        }
    }

    // Constructs an artificial scenario to show what happens when we
    // allow per-ack updates, rather than limititing update freqency.  In
    // this scenario, the first two acks of the epoch produce the same
    // cwnd.  When we limit per-ack updates, this would cause the
    // cessation of cubic updates for 30ms.  When we allow per-ack
    // updates, the window continues to grow on every ack.
    #[test]
    fn per_ack_updates() {
        let mut cubic = CubicBytes::new(MAX_SEGMENT_SIZE);
        let mut clock = Instant::now();

        // Start the test with a large cwnd and RTT, to force the first
        // increase to be a cubic increase.
        let initial_cwnd_packets = 150;
        let mut current_cwnd = initial_cwnd_packets * MAX_SEGMENT_SIZE;
        let rtt_min = Duration::from_millis(350);

        // Keep track of the growth of the reno-equivalent cwnd.
        let mut reno_cwnd = reno_cwnd_in_bytes(current_cwnd);
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            clock,
        );
        let initial_cwnd = current_cwnd;

        // Simulate the return of cwnd packets in less than
        // MaxCubicInterval() time.
        let max_acks = (initial_cwnd_packets as f32 / N_CONNECTION_ALPHA) as u64;
        let interval = Duration::from_micros(
            MAX_CUBIC_TIME_INTERVAL.as_micros() as u64 / (max_acks + 1),
        );

        // In this scenario, the first increase is dictated by the cubic
        // equation, but it is less than one byte, so the cwnd doesn't
        // change.  Normally, without per-ack increases, any cwnd plateau
        // will cause the cwnd to be pinned for MaxCubicTimeInterval().  If
        // we enable per-ack updates, the cwnd will continue to grow,
        // regardless of the temporary plateau.
        clock += interval;
        reno_cwnd = reno_cwnd_in_bytes(reno_cwnd);
        assert_eq!(
            current_cwnd,
            cubic.congestion_window_after_ack(
                MAX_SEGMENT_SIZE,
                current_cwnd,
                rtt_min,
                clock
            )
        );
        for _ in 1..max_acks {
            clock += interval;
            let next_cwnd = cubic.congestion_window_after_ack(
                MAX_SEGMENT_SIZE,
                current_cwnd,
                rtt_min,
                clock,
            );
            reno_cwnd = reno_cwnd_in_bytes(reno_cwnd);
            // The window shoud increase on every ack.
            assert!(current_cwnd < next_cwnd);
            assert_eq!(reno_cwnd, next_cwnd);
            current_cwnd = next_cwnd;
        }

        // After all the acks are returned from the epoch, we expect the
        // cwnd to have increased by nearly one packet.  (Not exactly one
        // packet, because our byte-wise Reno algorithm is always a slight
        // under-estimation).  Without per-ack updates, the current_cwnd
        // would otherwise be unchanged.
        let minimum_expected_increase = MAX_SEGMENT_SIZE * 9 / 10;
        assert!(minimum_expected_increase + initial_cwnd < current_cwnd)
    }

    #[test]
    fn loss_events() {
        let mut cubic = CubicBytes::new(MAX_SEGMENT_SIZE);
        let clock = Instant::now();

        let rtt_min = HUNDRED_MS;
        let mut current_cwnd = 422 * MAX_SEGMENT_SIZE;
        // Without the signed-integer, cubic-convex fix, we mistakenly
        // increment cwnd after only one_ms_ and a single ack.
        let mut expected_cwnd = reno_cwnd_in_bytes(current_cwnd);
        assert_eq!(
            expected_cwnd,
            cubic.congestion_window_after_ack(
                MAX_SEGMENT_SIZE,
                current_cwnd,
                rtt_min,
                clock
            )
        );

        // On the first loss, the last max congestion window is set to the
        // congestion window before the loss.
        let mut pre_loss_cwnd = current_cwnd;
        assert_eq!(0, cubic.last_max_congestion_window);

        expected_cwnd = (current_cwnd as f32 * N_CONNECTION_BETA) as usize;
        assert_eq!(
            expected_cwnd,
            cubic.congestion_window_after_loss(current_cwnd)
        );
        assert_eq!(pre_loss_cwnd, cubic.last_max_congestion_window);
        current_cwnd = expected_cwnd;

        // On the second loss, the current congestion window has not yet
        // reached the last max congestion window.  The last max congestion
        // window will be reduced by an additional backoff factor to allow
        // for competition.
        pre_loss_cwnd = current_cwnd;
        expected_cwnd = (current_cwnd as f32 * N_CONNECTION_BETA) as usize;
        assert_eq!(
            expected_cwnd,
            cubic.congestion_window_after_loss(current_cwnd)
        );
        current_cwnd = expected_cwnd;

        assert!(pre_loss_cwnd > cubic.last_max_congestion_window);

        let mut expected_last_max =
            (pre_loss_cwnd as f32 * N_CONNECTION_BETA_LAST_MAX) as usize;
        assert_eq!(expected_last_max, cubic.last_max_congestion_window);
        assert!(expected_cwnd < cubic.last_max_congestion_window);
        // Simulate an increase, and check that we are below the origin.
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            clock,
        );
        assert!(cubic.last_max_congestion_window > current_cwnd);

        // On the final loss, simulate the condition where the congestion
        // window had a chance to grow nearly to the last congestion window.
        current_cwnd = cubic.last_max_congestion_window - 1;
        pre_loss_cwnd = current_cwnd;
        expected_cwnd = (current_cwnd as f32 * N_CONNECTION_BETA) as usize;
        assert_eq!(
            expected_cwnd,
            cubic.congestion_window_after_loss(current_cwnd)
        );
        expected_last_max = pre_loss_cwnd;
        assert_eq!(expected_last_max, cubic.last_max_congestion_window);
    }

    #[test]
    fn below_origin() {
        let mut cubic = CubicBytes::new(MAX_SEGMENT_SIZE);
        let mut clock = Instant::now();

        // Concave growth.
        let rtt_min = HUNDRED_MS;
        let mut current_cwnd = 422 * MAX_SEGMENT_SIZE;
        // Without the signed-integer, cubic-convex fix, we mistakenly
        // increment cwnd after only one_ms_ and a single ack.
        let mut expected_cwnd = reno_cwnd_in_bytes(current_cwnd);
        assert_eq!(
            expected_cwnd,
            cubic.congestion_window_after_ack(
                MAX_SEGMENT_SIZE,
                current_cwnd,
                rtt_min,
                clock
            )
        );
        expected_cwnd = (current_cwnd as f32 * N_CONNECTION_BETA) as usize;
        assert_eq!(
            expected_cwnd,
            cubic.congestion_window_after_loss(current_cwnd)
        );
        current_cwnd = expected_cwnd;
        // First update after loss to initialize the epoch.
        current_cwnd = cubic.congestion_window_after_ack(
            MAX_SEGMENT_SIZE,
            current_cwnd,
            rtt_min,
            clock,
        );
        // Cubic phase.
        for _ in 0..40 {
            clock += HUNDRED_MS;
            current_cwnd = cubic.congestion_window_after_ack(
                MAX_SEGMENT_SIZE,
                current_cwnd,
                rtt_min,
                clock,
            );
        }
        expected_cwnd = 553632;
        assert_eq!(expected_cwnd, current_cwnd);
    }
}
