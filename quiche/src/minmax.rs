// Copyright (C) 2020, Cloudflare, Inc.
// Copyright (C) 2017, Google, Inc.
//
// Use of this source code is governed by the following BSD-style license:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// lib/minmax.c: windowed min/max tracker
//
// Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// value of a data stream over some fixed time interval.  (E.g.,
// the minimum RTT over the past five minutes.) It uses constant
// space and constant time per update yet almost always delivers
// the same minimum as an implementation that has to keep all the
// data in the window.
//
// The algorithm keeps track of the best, 2nd best & 3rd best min
// values, maintaining an invariant that the measurement time of
// the n'th best >= n-1'th best. It also makes sure that the three
// values are widely separated in the time window since that bounds
// the worse case error when that data is monotonically increasing
// over the window.
//
// Upon getting a new min, we can forget everything earlier because
// it has no value - the new min is <= everything else in the window
// by definition and it's the most recent. So we restart fresh on
// every new min and overwrites 2nd & 3rd choices. The same property
// holds for 2nd & 3rd best.

use std::time::Duration;
use std::time::Instant;

#[derive(Copy, Clone)]
struct MinmaxSample<T> {
    time: Instant,
    value: T,
}

pub struct Minmax<T> {
    estimate: [MinmaxSample<T>; 3],
}

impl<T: PartialOrd + Copy> Minmax<T> {
    pub fn new(val: T) -> Self {
        Minmax {
            estimate: [MinmaxSample {
                time: Instant::now(),
                value: val,
            }; 3],
        }
    }

    /// Resets the estimates to the given value.
    pub fn reset(&mut self, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        for i in self.estimate.iter_mut() {
            *i = val;
        }

        self.estimate[0].value
    }

    /// Updates the min estimate based on the given measurement, and returns it.
    pub fn running_min(&mut self, win: Duration, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        let delta_time = time.duration_since(self.estimate[2].time);

        // Reset if there's nothing in the window or a new min value is found.
        if val.value <= self.estimate[0].value || delta_time > win {
            return self.reset(time, meas);
        }

        if val.value <= self.estimate[1].value {
            self.estimate[2] = val;
            self.estimate[1] = val;
        } else if val.value <= self.estimate[2].value {
            self.estimate[2] = val;
        }

        self.subwin_update(win, time, meas)
    }

    /// Updates the max estimate based on the given measurement, and returns it.
    pub fn running_max(&mut self, win: Duration, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        let delta_time = time.duration_since(self.estimate[2].time);

        // Reset if there's nothing in the window or a new max value is found.
        if val.value >= self.estimate[0].value || delta_time > win {
            return self.reset(time, meas);
        }

        if val.value >= self.estimate[1].value {
            self.estimate[2] = val;
            self.estimate[1] = val;
        } else if val.value >= self.estimate[2].value {
            self.estimate[2] = val
        }

        self.subwin_update(win, time, meas)
    }

    /// As time advances, update the 1st, 2nd and 3rd estimates.
    fn subwin_update(&mut self, win: Duration, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        let delta_time = time.duration_since(self.estimate[0].time);

        if delta_time > win {
            // Passed entire window without a new val so make 2nd estimate the
            // new val & 3rd estimate the new 2nd choice. we may have to iterate
            // this since our 2nd estimate may also be outside the window (we
            // checked on entry that the third estimate was in the window).
            self.estimate[0] = self.estimate[1];
            self.estimate[1] = self.estimate[2];
            self.estimate[2] = val;

            if time.duration_since(self.estimate[0].time) > win {
                self.estimate[0] = self.estimate[1];
                self.estimate[1] = self.estimate[2];
                self.estimate[2] = val;
            }
        } else if self.estimate[1].time == self.estimate[0].time &&
            delta_time > win.div_f32(4.0)
        {
            // We've passed a quarter of the window without a new val so take a
            // 2nd estimate from the 2nd quarter of the window.
            self.estimate[2] = val;
            self.estimate[1] = val;
        } else if self.estimate[2].time == self.estimate[1].time &&
            delta_time > win.div_f32(2.0)
        {
            // We've passed half the window without finding a new val so take a
            // 3rd estimate from the last half of the window.
            self.estimate[2] = val;
        }

        self.estimate[0].value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_filter_rtt() {
        let mut f = Minmax::new(Duration::ZERO);
        let now = Instant::now();
        let rtt = Duration::from_millis(50);

        let rtt_min = f.reset(now, rtt);
        assert_eq!(rtt_min, rtt);

        assert_eq!(f.estimate[0].time, now);
        assert_eq!(f.estimate[0].value, rtt);

        assert_eq!(f.estimate[1].time, now);
        assert_eq!(f.estimate[1].value, rtt);

        assert_eq!(f.estimate[2].time, now);
        assert_eq!(f.estimate[2].value, rtt);
    }

    #[test]
    fn reset_filter_bandwidth() {
        let mut f = Minmax::new(0);
        let now = Instant::now();
        let bw = 2000;

        let bw_min = f.reset(now, bw);
        assert_eq!(bw_min, bw);

        assert_eq!(f.estimate[0].time, now);
        assert_eq!(f.estimate[0].value, bw);

        assert_eq!(f.estimate[1].time, now);
        assert_eq!(f.estimate[1].value, bw);

        assert_eq!(f.estimate[2].time, now);
        assert_eq!(f.estimate[2].value, bw);
    }

    #[test]
    fn get_windowed_min_rtt() {
        let mut f = Minmax::new(Duration::ZERO);
        let rtt_25 = Duration::from_millis(25);
        let rtt_24 = Duration::from_millis(24);
        let win = Duration::from_millis(500);
        let mut time = Instant::now();

        let mut rtt_min = f.reset(time, rtt_25);
        assert_eq!(rtt_min, rtt_25);

        time += Duration::from_millis(250);
        rtt_min = f.running_min(win, time, rtt_24);
        assert_eq!(rtt_min, rtt_24);
        assert_eq!(f.estimate[1].value, rtt_24);
        assert_eq!(f.estimate[2].value, rtt_24);

        time += Duration::from_millis(600);
        rtt_min = f.running_min(win, time, rtt_25);
        assert_eq!(rtt_min, rtt_25);
        assert_eq!(f.estimate[1].value, rtt_25);
        assert_eq!(f.estimate[2].value, rtt_25);
    }

    #[test]
    fn get_windowed_min_bandwidth() {
        let mut f = Minmax::new(0);
        let bw_200 = 200;
        let bw_500 = 500;
        let win = Duration::from_millis(500);
        let mut time = Instant::now();

        let mut bw_min = f.reset(time, bw_500);
        assert_eq!(bw_min, bw_500);

        time += Duration::from_millis(250);
        bw_min = f.running_min(win, time, bw_200);
        assert_eq!(bw_min, bw_200);
        assert_eq!(f.estimate[1].value, bw_200);
        assert_eq!(f.estimate[2].value, bw_200);

        time += Duration::from_millis(600);
        bw_min = f.running_min(win, time, bw_500);
        assert_eq!(bw_min, bw_500);
        assert_eq!(f.estimate[1].value, bw_500);
        assert_eq!(f.estimate[2].value, bw_500);
    }

    #[test]
    fn get_windowed_max_rtt() {
        let mut f = Minmax::new(Duration::ZERO);
        let rtt_25 = Duration::from_millis(25);
        let rtt_24 = Duration::from_millis(24);
        let win = Duration::from_millis(500);
        let mut time = Instant::now();

        let mut rtt_max = f.reset(time, rtt_24);
        assert_eq!(rtt_max, rtt_24);

        time += Duration::from_millis(250);
        rtt_max = f.running_max(win, time, rtt_25);
        assert_eq!(rtt_max, rtt_25);
        assert_eq!(f.estimate[1].value, rtt_25);
        assert_eq!(f.estimate[2].value, rtt_25);

        time += Duration::from_millis(600);
        rtt_max = f.running_max(win, time, rtt_24);
        assert_eq!(rtt_max, rtt_24);
        assert_eq!(f.estimate[1].value, rtt_24);
        assert_eq!(f.estimate[2].value, rtt_24);
    }

    #[test]
    fn get_windowed_max_bandwidth() {
        let mut f = Minmax::new(0);
        let bw_200 = 200;
        let bw_500 = 500;
        let win = Duration::from_millis(500);
        let mut time = Instant::now();

        let mut bw_max = f.reset(time, bw_200);
        assert_eq!(bw_max, bw_200);

        time += Duration::from_millis(5000);
        bw_max = f.running_max(win, time, bw_500);
        assert_eq!(bw_max, bw_500);
        assert_eq!(f.estimate[1].value, bw_500);
        assert_eq!(f.estimate[2].value, bw_500);

        time += Duration::from_millis(600);
        bw_max = f.running_max(win, time, bw_200);
        assert_eq!(bw_max, bw_200);
        assert_eq!(f.estimate[1].value, bw_200);
        assert_eq!(f.estimate[2].value, bw_200);
    }

    #[test]
    fn get_windowed_min_estimates_rtt() {
        let mut f = Minmax::new(Duration::ZERO);
        let rtt_25 = Duration::from_millis(25);
        let rtt_24 = Duration::from_millis(24);
        let rtt_23 = Duration::from_millis(23);
        let rtt_22 = Duration::from_millis(22);
        let win = Duration::from_secs(1);
        let mut time = Instant::now();

        let mut rtt_min = f.reset(time, rtt_23);
        assert_eq!(rtt_min, rtt_23);

        time += Duration::from_millis(300);
        rtt_min = f.running_min(win, time, rtt_24);
        assert_eq!(rtt_min, rtt_23);
        assert_eq!(f.estimate[1].value, rtt_24);
        assert_eq!(f.estimate[2].value, rtt_24);

        time += Duration::from_millis(300);
        rtt_min = f.running_min(win, time, rtt_25);
        assert_eq!(rtt_min, rtt_23);
        assert_eq!(f.estimate[1].value, rtt_24);
        assert_eq!(f.estimate[2].value, rtt_25);

        time += Duration::from_millis(300);
        rtt_min = f.running_min(win, time, rtt_22);
        assert_eq!(rtt_min, rtt_22);
        assert_eq!(f.estimate[1].value, rtt_22);
        assert_eq!(f.estimate[2].value, rtt_22);
    }

    #[test]
    fn get_windowed_min_estimates_bandwidth() {
        let mut f = Minmax::new(0);
        let bw_500 = 500;
        let bw_400 = 400;
        let bw_300 = 300;
        let bw_200 = 200;
        let win = Duration::from_secs(1);
        let mut time = Instant::now();

        let mut bw_min = f.reset(time, bw_300);
        assert_eq!(bw_min, bw_300);

        time += Duration::from_millis(300);
        bw_min = f.running_min(win, time, bw_400);
        assert_eq!(bw_min, bw_300);
        assert_eq!(f.estimate[1].value, bw_400);
        assert_eq!(f.estimate[2].value, bw_400);

        time += Duration::from_millis(300);
        bw_min = f.running_min(win, time, bw_500);
        assert_eq!(bw_min, bw_300);
        assert_eq!(f.estimate[1].value, bw_400);
        assert_eq!(f.estimate[2].value, bw_500);

        time += Duration::from_millis(300);
        bw_min = f.running_min(win, time, bw_200);
        assert_eq!(bw_min, bw_200);
        assert_eq!(f.estimate[1].value, bw_200);
        assert_eq!(f.estimate[2].value, bw_200);
    }

    #[test]
    fn get_windowed_max_estimates_rtt() {
        let mut f = Minmax::new(Duration::ZERO);
        let rtt_25 = Duration::from_millis(25);
        let rtt_24 = Duration::from_millis(24);
        let rtt_23 = Duration::from_millis(23);
        let rtt_26 = Duration::from_millis(26);
        let win = Duration::from_secs(1);
        let mut time = Instant::now();

        let mut rtt_max = f.reset(time, rtt_25);
        assert_eq!(rtt_max, rtt_25);

        time += Duration::from_millis(300);
        rtt_max = f.running_max(win, time, rtt_24);
        assert_eq!(rtt_max, rtt_25);
        assert_eq!(f.estimate[1].value, rtt_24);
        assert_eq!(f.estimate[2].value, rtt_24);

        time += Duration::from_millis(300);
        rtt_max = f.running_max(win, time, rtt_23);
        assert_eq!(rtt_max, rtt_25);
        assert_eq!(f.estimate[1].value, rtt_24);
        assert_eq!(f.estimate[2].value, rtt_23);

        time += Duration::from_millis(300);
        rtt_max = f.running_max(win, time, rtt_26);
        assert_eq!(rtt_max, rtt_26);
        assert_eq!(f.estimate[1].value, rtt_26);
        assert_eq!(f.estimate[2].value, rtt_26);
    }

    #[test]
    fn get_windowed_max_estimates_bandwidth() {
        let mut f = Minmax::new(0);
        let bw_500 = 500;
        let bw_400 = 400;
        let bw_300 = 300;
        let bw_600 = 600;
        let win = Duration::from_secs(1);
        let mut time = Instant::now();

        let mut bw_max = f.reset(time, bw_500);
        assert_eq!(bw_max, bw_500);

        time += Duration::from_millis(300);
        bw_max = f.running_max(win, time, bw_400);
        assert_eq!(bw_max, bw_500);
        assert_eq!(f.estimate[1].value, bw_400);
        assert_eq!(f.estimate[2].value, bw_400);

        time += Duration::from_millis(300);
        bw_max = f.running_max(win, time, bw_300);
        assert_eq!(bw_max, bw_500);
        assert_eq!(f.estimate[1].value, bw_400);
        assert_eq!(f.estimate[2].value, bw_300);

        time += Duration::from_millis(300);
        bw_max = f.running_max(win, time, bw_600);
        assert_eq!(bw_max, bw_600);
        assert_eq!(f.estimate[1].value, bw_600);
        assert_eq!(f.estimate[2].value, bw_600);
    }
}
