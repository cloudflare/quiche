// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. (E.g.,
// the minimum RTT over the past five minutes.) The algorithm keeps track of
// the best, second best, and third best min (or max) estimates, maintaining an
// invariant that the measurement time of the n'th best >= n-1'th best.

// The algorithm works as follows. On a reset, all three estimates are set to
// the same sample. The second best estimate is then recorded in the second
// quarter of the window, and a third best estimate is recorded in the second
// half of the window, bounding the worst case error when the true min is
// monotonically increasing (or true max is monotonically decreasing) over the
// window.
//
// A new best sample replaces all three estimates, since the new best is lower
// (or higher) than everything else in the window and it is the most recent.
// The window thus effectively gets reset on every new min. The same property
// holds true for second best and third best estimates. Specifically, when a
// sample arrives that is better than the second best but not better than the
// best, it replaces the second and third best estimates but not the best
// estimate. Similarly, a sample that is better than the third best estimate
// but not the other estimates replaces only the third best estimate.
//
// Finally, when the best expires, it is replaced by the second best, which in
// turn is replaced by the third best. The newest sample replaces the third
// best.

use std::ops::Div;
use std::ops::Sub;

#[derive(Debug, Clone, Copy)]
struct Sample<T, I> {
    sample: T,
    time: I,
}

#[derive(Debug)]
pub struct WindowedFilter<T, I, D> {
    window_length: D,
    estimates: [Option<Sample<T, I>>; 3],
}

impl<T, I, D> WindowedFilter<T, I, D>
where
    T: Ord + Copy,
    I: Sub<I, Output = D> + Copy,
    D: Ord + Div<usize, Output = D> + Copy,
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

    pub fn get_second_best(&self) -> Option<T> {
        self.estimates[1].as_ref().map(|e| e.sample)
    }

    pub fn get_third_best(&self) -> Option<T> {
        self.estimates[2].as_ref().map(|e| e.sample)
    }

    pub fn clear(&mut self) {
        self.estimates = [None, None, None];
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
