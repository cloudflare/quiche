// Copyright (C) 2025, Cloudflare, Inc.
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

use foundations::telemetry::metrics::Gauge;

use std::collections::VecDeque;
use std::ops::Div;
use std::ops::Sub;
use std::time::Duration;
use std::time::Instant;

use crate::quic::QuicheConnection;

const EST_WIN: usize = 10;

/// [`BandwidthReporter`] is responsible to track the bandwidth estimate for the
/// connection
pub(super) struct BandwidthReporter {
    /// Time of last update
    last_update: Instant,
    /// Period between update (set using rtt)
    update_period: Duration,
    /// Estimate at last update
    last_bandwidth: u64,
    /// Bytes sent at last update
    last_sent: u64,
    /// Bytes lost at last update
    last_lost: u64,
    /// Bytes acked at last update
    last_acked: u64,
    /// Max recorded bandwidth
    pub(super) max_bandwidth: u64,
    /// Loss at max recorded bandwidth
    pub(super) max_loss_pct: f32,

    estimator: MaxUtilizedBandwidthEstimator,

    gauge: Gauge,
}

impl BandwidthReporter {
    pub(super) fn new(gauge: Gauge) -> Self {
        BandwidthReporter {
            last_update: Instant::now(),
            update_period: Duration::from_millis(50),

            last_bandwidth: 0,

            last_sent: 0,
            last_lost: 0,
            last_acked: 0,

            max_bandwidth: 0,
            max_loss_pct: 0.,

            estimator: MaxUtilizedBandwidthEstimator::new(),

            gauge,
        }
    }

    #[inline]
    pub(super) fn update(&mut self, quiche: &QuicheConnection, now: Instant) {
        if now.duration_since(self.last_update) < self.update_period {
            return;
        }

        let stats = quiche.stats();

        let bytes_sent = stats.sent_bytes - self.last_sent;
        let bytes_lost = stats.lost_bytes - self.last_lost;
        let bytes_acked = stats.acked_bytes - self.last_acked;

        self.estimator.new_round(
            self.last_update,
            bytes_sent,
            bytes_lost,
            bytes_acked,
        );

        self.last_sent = stats.sent_bytes;
        self.last_lost = stats.lost_bytes;
        self.last_acked = stats.acked_bytes;

        self.last_update = now;

        let bw_estimate = self.estimator.get();

        if self.last_bandwidth != bw_estimate.bandwidth {
            self.gauge.dec_by(self.last_bandwidth);

            self.last_bandwidth = bw_estimate.bandwidth;

            self.gauge.inc_by(self.last_bandwidth);

            self.max_bandwidth = self.max_bandwidth.max(self.last_bandwidth);
            self.max_loss_pct = self.max_loss_pct.max(bw_estimate.loss);
        }

        if let Some(p) = quiche.path_stats().find(|s| s.active) {
            self.update_period = p.rtt;
        }
    }
}

impl Drop for BandwidthReporter {
    fn drop(&mut self) {
        self.gauge.dec_by(self.last_bandwidth);
    }
}

#[derive(Clone, Copy, Default)]
pub struct Estimate {
    pub bandwidth: u64,
    pub loss: f32,
}

impl PartialEq for Estimate {
    fn eq(&self, other: &Self) -> bool {
        self.bandwidth == other.bandwidth
    }
}

impl Eq for Estimate {}

impl PartialOrd for Estimate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Estimate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bandwidth.cmp(&other.bandwidth)
    }
}

struct Round {
    bytes_sent: u64,
    bytes_acked: u64,
    bytes_lost: u64,
    start: Instant,
}

pub(super) struct MaxUtilizedBandwidthEstimator {
    rounds: VecDeque<Round>,
    estimate: WindowedFilter<Estimate, Instant, Duration>,
    bytes_sent_prev_round: u64,
}

impl MaxUtilizedBandwidthEstimator {
    fn new() -> Self {
        let rounds = VecDeque::with_capacity(EST_WIN);

        MaxUtilizedBandwidthEstimator {
            rounds,
            estimate: WindowedFilter::new(Duration::from_secs(120)),
            bytes_sent_prev_round: 0,
        }
    }

    fn new_round(
        &mut self, time: Instant, bytes_sent: u64, bytes_lost: u64,
        bytes_acked: u64,
    ) {
        if self.rounds.len() == EST_WIN {
            let _ = self.rounds.pop_front();
        }

        self.rounds.push_back(Round {
            bytes_sent: self.bytes_sent_prev_round,
            bytes_acked,
            bytes_lost,
            start: time,
        });

        // Unlike acked and lost count, sent count is computed over a window 1 rtt
        // in the past.
        self.bytes_sent_prev_round = bytes_sent;

        let bytes_acked = self.rounds.iter().map(|v| v.bytes_acked).sum::<u64>();
        let bytes_lost = self.rounds.iter().map(|v| v.bytes_lost).sum::<u64>();
        let bytes_sent = self.rounds.iter().map(|v| v.bytes_sent).sum::<u64>();

        let loss = if bytes_lost == 0 {
            0.
        } else {
            bytes_lost as f32 / bytes_sent as f32
        };

        let time_delta = time.duration_since(self.rounds.front().unwrap().start);

        if bytes_acked > 0 {
            let ack_rate =
                bandwidth_from_bytes_and_time_delta(bytes_acked, time_delta);
            let send_rate =
                bandwidth_from_bytes_and_time_delta(bytes_sent, time_delta);
            let estimate = Estimate {
                bandwidth: ack_rate.min(send_rate),
                loss,
            };

            if self.rounds.len() < EST_WIN / 2 {
                self.estimate.reset(estimate, time)
            } else {
                self.estimate.update(estimate, time)
            }
        }
    }

    pub(super) fn get(&self) -> Estimate {
        // Too few rounds
        if self.rounds.len() < EST_WIN / 2 {
            return Default::default();
        }

        self.estimate.get_best().unwrap_or_default()
    }
}

/// Bandwidth in bits per second from bytes and time period
fn bandwidth_from_bytes_and_time_delta(bytes: u64, time_delta: Duration) -> u64 {
    if bytes == 0 {
        return 0;
    }

    let mut nanos = time_delta.as_nanos();
    if nanos == 0 {
        nanos = 1;
    }

    let num_nano_bits = 8 * bytes as u128 * 1_000_000_000;
    if num_nano_bits < nanos {
        return 1;
    }

    (num_nano_bits / nanos) as u64
}

/// Below is windowed filter implementation from quiche
#[derive(Clone, Copy)]
struct Sample<T, I> {
    sample: T,
    time: I,
}

pub struct WindowedFilter<T, I, D> {
    window_length: D,
    estimates: [Option<Sample<T, I>>; 3],
}

impl<T, I, D> WindowedFilter<T, I, D>
where
    T: Ord + Copy,
    I: Sub<I, Output = D> + Copy,
    D: Ord + Div<u32, Output = D> + Copy,
{
    pub fn new(window_length: D) -> Self {
        WindowedFilter {
            window_length,
            estimates: [None, None, None],
        }
    }

    pub fn reset(&mut self, new_sample: T, new_time: I) {
        let sample = Some(Sample {
            sample: new_sample,
            time: new_time,
        });

        self.estimates = [sample, sample, sample];
    }

    pub fn get_best(&self) -> Option<T> {
        self.estimates[0].as_ref().map(|e| e.sample)
    }

    pub fn update(&mut self, new_sample: T, new_time: I) {
        // Reset all estimates if they have not yet been initialized, if new
        // sample is a new best, or if the newest recorded estimate is too
        // old.
        if match &self.estimates[0] {
            None => true,
            Some(best) if new_sample > best.sample => true,
            _ =>
                new_time - self.estimates[2].as_ref().unwrap().time >
                    self.window_length,
        } {
            return self.reset(new_sample, new_time);
        }

        if new_sample > self.estimates[1].unwrap().sample {
            self.estimates[1] = Some(Sample {
                sample: new_sample,
                time: new_time,
            });
            self.estimates[2] = self.estimates[1];
        } else if new_sample > self.estimates[2].unwrap().sample {
            self.estimates[2] = Some(Sample {
                sample: new_sample,
                time: new_time,
            });
        }

        // Expire and update estimates as necessary.
        if new_time - self.estimates[0].unwrap().time > self.window_length {
            // The best estimate hasn't been updated for an entire window, so
            // promote second and third best estimates.
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = Some(Sample {
                sample: new_sample,
                time: new_time,
            });
            // Need to iterate one more time. Check if the new best estimate is
            // outside the window as well, since it may also have been recorded a
            // long time ago. Don't need to iterate once more since we cover that
            // case at the beginning of the method.
            if new_time - self.estimates[0].unwrap().time > self.window_length {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }

        if self.estimates[1].unwrap().sample == self.estimates[0].unwrap().sample &&
            new_time - self.estimates[1].unwrap().time > self.window_length / 4
        {
            // A quarter of the window has passed without a better sample, so the
            // second-best estimate is taken from the second quarter of the
            // window.
            self.estimates[1] = Some(Sample {
                sample: new_sample,
                time: new_time,
            });
            self.estimates[2] = self.estimates[1];
            return;
        }

        if self.estimates[2].unwrap().sample == self.estimates[1].unwrap().sample &&
            new_time - self.estimates[2].unwrap().time > self.window_length / 2
        {
            // We've passed a half of the window without a better estimate, so
            // take a third-best estimate from the second half of the
            // window.
            self.estimates[2] = Some(Sample {
                sample: new_sample,
                time: new_time,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate() {
        let mut now = Instant::now();

        let mut estimator = MaxUtilizedBandwidthEstimator::new();

        assert_eq!(estimator.get().bandwidth, 0);
        assert!(estimator.estimate.get_best().is_none());

        // First round send 30M, nothing gets acked
        estimator.new_round(now, 30_000_000, 0, 0);

        assert_eq!(estimator.get().bandwidth, 0); // Not enough rounds for estimate yet
        assert!(estimator.estimate.get_best().is_none());

        now += Duration::from_secs(30);

        // Send 60M, previous 30M gets acked
        estimator.new_round(now, 60_000_000, 0, 30_000_000);

        // 30M over 30s = 1MBps = 8Mbps
        assert_eq!(estimator.get().bandwidth, 0); // Not enough rounds for estimate yet
        assert_eq!(estimator.estimate.get_best().unwrap().bandwidth, 8_000_000);

        now += Duration::from_secs(30);

        // Send 90M, previous 60M gets acked
        estimator.new_round(now, 90_000_000, 0, 60_000_000);

        // 90M over 60s = 1.5MBps = 12Mbps
        assert_eq!(estimator.get().bandwidth, 0); // Not enough rounds for estimate yet
        assert_eq!(estimator.estimate.get_best().unwrap().bandwidth, 12_000_000);

        now += Duration::from_secs(30);

        // Send 10M, previous 90M gets acked
        estimator.new_round(now, 30_000_000, 0, 90_000_000);

        // 180M over 90s = 2MBps = 16Mbps
        assert_eq!(estimator.get().bandwidth, 0); // Not enough rounds for estimate yet
        assert_eq!(estimator.estimate.get_best().unwrap().bandwidth, 16_000_000);

        for _ in 0..4 {
            now += Duration::from_secs(30);
            // Send another 10M, previous 10M gets acked
            estimator.new_round(now, 30_000_000, 0, 30_000_000);
            // The bandwidth is lower but it doesn't matter, we record highest
            // bandwidth, so it remains as before for two minutes
            assert_eq!(estimator.get().bandwidth, 16_000_000);
        }

        // After two minutes the filter is updated, and the max bandwidth is
        // reduced
        now += Duration::from_secs(30);
        // Send another 10M, previous 10M gets acked
        estimator.new_round(now, 30_000_000, 0, 30_000_000);

        assert!(estimator.get().bandwidth < 8 * 2_000_000);
    }
}
