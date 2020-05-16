// Copyright (C) 2020, Cloudflare, Inc.
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

// When autotune the receiver window, how much we increase the window.
const WINDOW_INCREASE_FACTOR: u64 = 2;

// When autotune the receiver window, check if the last update is within RTT *
// this constant.
const WINDOW_TRIGGER_FACTOR: u32 = 2;

#[derive(Default, Debug)]
pub struct FlowControl {
    /// Flow control limit.
    max_data: u64,

    /// The maximum receive window. This value is used for updating
    /// flow control limit.
    window: u64,

    /// Last update time of max_data for autotuning the window.
    last_update: Option<Instant>,
}

impl FlowControl {
    pub fn new(max_data: u64, window: u64) -> Self {
        Self {
            max_data,

            window,

            last_update: None,
        }
    }

    /// Returns the current window.
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Returns the current max_data limit.
    pub fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Returns true if the flow control needs to update max_data.
    ///
    /// This happens when the available window is smaller than the half
    /// of the current window.
    pub fn should_update_max_data(&self, consumed: u64) -> bool {
        let available_window = self.max_data - consumed;

        available_window < (self.window / 2)
    }

    /// Returns the new max_data limit.
    pub fn max_data_next(&mut self, consumed: u64) -> u64 {
        let available_window = self.max_data - consumed;

        self.max_data + (self.window - available_window)
    }

    /// Commits the new max_data limit.
    pub fn update_max_data(&mut self, consumed: u64, now: Instant) {
        self.max_data = self.max_data_next(consumed);
        self.last_update = Some(now);
    }

    /// Make sure the lower bound of the current window.
    /// Returns true if the current window changed.
    pub fn ensure_window_lower_bound(&mut self, min_window: u64) -> bool {
        if min_window > self.window {
            self.window = min_window;

            return true;
        }

        false
    }

    /// Autotune the window size. When there is an another update
    /// within RTT x 2, bump connection window x 1.5, capped by
    /// max(stream window).
    pub fn autotune_window(
        &mut self, now: Instant, rtt: Duration, max_window: u64,
    ) {
        if let Some(last_update) = self.last_update {
            if now - last_update < rtt * WINDOW_TRIGGER_FACTOR {
                self.window = std::cmp::min(
                    self.window * WINDOW_INCREASE_FACTOR,
                    max_window,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_data() {
        let fc = FlowControl::new(100, 20);

        assert_eq!(fc.max_data(), 100);
    }

    #[test]
    fn should_update_max_data() {
        let fc = FlowControl::new(100, 20);

        assert_eq!(fc.should_update_max_data(85), false);
        assert_eq!(fc.should_update_max_data(95), true);
    }

    #[test]
    fn max_data_next() {
        let mut fc = FlowControl::new(100, 20);
        let consumed = 95;

        assert_eq!(fc.should_update_max_data(consumed), true);
        assert_eq!(fc.max_data_next(consumed), consumed + 20);
    }

    #[test]
    fn update_max_data() {
        let mut fc = FlowControl::new(100, 20);
        let consumed = 95;

        assert_eq!(fc.should_update_max_data(consumed), true);

        let max_data_next = fc.max_data_next(consumed);
        assert_eq!(max_data_next, consumed + 20);

        fc.update_max_data(consumed, Instant::now());
        assert_eq!(fc.max_data(), max_data_next);
    }

    #[test]
    fn ensure_window_lower_bound() {
        let w = 20;
        let mut fc = FlowControl::new(100, w);

        // Lower than current window x 1.5 (30).
        assert_eq!(fc.ensure_window_lower_bound(w), false);

        // Higher than current window x 1.5 (30).
        assert_eq!(fc.ensure_window_lower_bound(w * 2), true);
    }

    #[test]
    fn autotune_window() {
        let w = 20;
        let mut fc = FlowControl::new(100, w);
        let consumed = 95;

        assert_eq!(fc.should_update_max_data(consumed), true);

        let max_data_next = fc.max_data_next(consumed);
        assert_eq!(max_data_next, consumed + w);

        fc.update_max_data(consumed, Instant::now());
        assert_eq!(fc.max_data(), max_data_next);

        // Window size should be doubled.
        fc.autotune_window(Instant::now(), Duration::from_millis(100), 100);

        let w = w * 2;
        let consumed = 110;

        assert_eq!(fc.should_update_max_data(consumed), true);

        let max_data_next = fc.max_data_next(consumed);
        assert_eq!(max_data_next, consumed + w);
    }
}
