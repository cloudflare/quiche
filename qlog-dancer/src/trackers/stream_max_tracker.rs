// Copyright (C) 2026, Cloudflare, Inc.
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

use std::collections::BTreeMap;

/// Tracks monotonically increasing per-stream values with efficient sum
/// calculation. Handles out-of-order events by taking max value seen per
/// stream.
#[derive(Debug, Default)]
pub struct StreamMaxTracker {
    /// Full time series per stream.
    pub per_stream: BTreeMap<u64, Vec<(f64, u64)>>,

    /// Current maximum per stream.
    pub flat: BTreeMap<u64, u64>,

    /// Cumulative sum time series.
    pub sum_series: Vec<(f64, u64)>,

    /// Running sum for O(1) updates.
    running_sum: u64,
}

impl StreamMaxTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates stream value, returns Some((old_max, new_max)) if changed.
    pub fn update(
        &mut self, stream_id: u64, new_value: u64, ev_time: f64, init_val: u64,
    ) -> Option<(u64, u64)> {
        let entry = self
            .per_stream
            .entry(stream_id)
            .or_insert_with(|| vec![(0.0, init_val)]);
        entry.push((ev_time, new_value));

        let old_max = self.flat.get(&stream_id).copied().unwrap_or(0);
        let new_max = old_max.max(new_value);

        let result = if new_max > old_max {
            self.flat.insert(stream_id, new_max);
            self.running_sum += new_max - old_max;
            Some((old_max, new_max))
        } else {
            None
        };

        self.sum_series.push((ev_time, self.running_sum));

        result
    }

    pub fn get_stream_max(&self, stream_id: u64) -> Option<u64> {
        self.flat.get(&stream_id).copied()
    }

    pub fn current_sum(&self) -> u64 {
        self.running_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_empty() {
        let tracker = StreamMaxTracker::new();
        assert_eq!(tracker.current_sum(), 0);
        assert_eq!(tracker.get_stream_max(0), None);
        assert!(tracker.sum_series.is_empty());
        assert!(tracker.flat.is_empty());
    }

    #[test]
    fn test_tracker_single_stream_in_order() {
        let mut tracker = StreamMaxTracker::new();

        let result = tracker.update(0, 1000, 10.0, 0);
        assert_eq!(result, Some((0, 1000)));
        assert_eq!(tracker.get_stream_max(0), Some(1000));
        assert_eq!(tracker.current_sum(), 1000);
        assert_eq!(tracker.sum_series, vec![(10.0, 1000)]);

        let result = tracker.update(0, 2000, 20.0, 0);
        assert_eq!(result, Some((1000, 2000)));
        assert_eq!(tracker.get_stream_max(0), Some(2000));
        assert_eq!(tracker.current_sum(), 2000);
        assert_eq!(tracker.sum_series, vec![(10.0, 1000), (20.0, 2000)]);
    }

    #[test]
    fn test_tracker_out_of_order_events() {
        let mut tracker = StreamMaxTracker::new();

        let result = tracker.update(0, 2000, 20.0, 0);
        assert_eq!(result, Some((0, 2000)));
        assert_eq!(tracker.get_stream_max(0), Some(2000));
        assert_eq!(tracker.current_sum(), 2000);

        let result = tracker.update(0, 1000, 10.0, 0);
        assert_eq!(result, None);
        assert_eq!(tracker.get_stream_max(0), Some(2000));
        assert_eq!(tracker.current_sum(), 2000);

        assert_eq!(tracker.sum_series, vec![(20.0, 2000), (10.0, 2000)]);

        let result = tracker.update(0, 3000, 30.0, 0);
        assert_eq!(result, Some((2000, 3000)));
        assert_eq!(tracker.get_stream_max(0), Some(3000));
        assert_eq!(tracker.current_sum(), 3000);
    }

    #[test]
    fn test_tracker_multiple_streams() {
        let mut tracker = StreamMaxTracker::new();

        tracker.update(0, 1000, 10.0, 0);
        assert_eq!(tracker.current_sum(), 1000);

        tracker.update(1, 500, 15.0, 0);
        assert_eq!(tracker.current_sum(), 1500);

        tracker.update(0, 1500, 20.0, 0);
        assert_eq!(tracker.current_sum(), 2000);

        tracker.update(2, 300, 25.0, 0);
        assert_eq!(tracker.current_sum(), 2300);

        assert_eq!(tracker.get_stream_max(0), Some(1500));
        assert_eq!(tracker.get_stream_max(1), Some(500));
        assert_eq!(tracker.get_stream_max(2), Some(300));
        assert_eq!(tracker.get_stream_max(999), None);
    }

    #[test]
    fn test_tracker_duplicate_values() {
        let mut tracker = StreamMaxTracker::new();

        let result = tracker.update(0, 1000, 10.0, 0);
        assert_eq!(result, Some((0, 1000)));

        let result = tracker.update(0, 1000, 20.0, 0);
        assert_eq!(result, None);

        assert_eq!(tracker.get_stream_max(0), Some(1000));
        assert_eq!(tracker.current_sum(), 1000);

        assert_eq!(tracker.sum_series.len(), 2);
        assert_eq!(tracker.sum_series, vec![(10.0, 1000), (20.0, 1000)]);
    }

    #[test]
    fn test_tracker_running_sum_correctness() {
        let mut tracker = StreamMaxTracker::new();

        tracker.update(0, 1000, 1.0, 0);
        tracker.update(1, 2000, 2.0, 0);
        tracker.update(2, 1500, 3.0, 0);
        tracker.update(0, 1200, 4.0, 0);

        let manual_sum: u64 = tracker.flat.values().sum();

        assert_eq!(tracker.current_sum(), manual_sum);
        assert_eq!(tracker.current_sum(), 4700);
    }

    #[test]
    fn test_tracker_complex_interleaving() {
        let mut tracker = StreamMaxTracker::new();

        let updates = vec![
            (0, 1000, 10.0),
            (1, 500, 12.0),
            (0, 800, 8.0),
            (2, 2000, 15.0),
            (1, 1000, 18.0),
            (0, 1500, 20.0),
        ];

        for (stream_id, value, time) in updates {
            tracker.update(stream_id, value, time, 0);
        }

        assert_eq!(tracker.get_stream_max(0), Some(1500));
        assert_eq!(tracker.get_stream_max(1), Some(1000));
        assert_eq!(tracker.get_stream_max(2), Some(2000));
        assert_eq!(tracker.current_sum(), 4500);

        assert_eq!(tracker.sum_series.len(), 6);
    }

    #[test]
    fn test_tracker_init_value() {
        let mut tracker = StreamMaxTracker::new();

        tracker.update(0, 1000, 10.0, 500);

        let stream_data = tracker.per_stream.get(&0).unwrap();
        assert_eq!(stream_data.len(), 2);
        assert_eq!(stream_data[0], (0.0, 500));
        assert_eq!(stream_data[1], (10.0, 1000));

        tracker.update(0, 1500, 20.0, 500);
        let stream_data = tracker.per_stream.get(&0).unwrap();
        assert_eq!(stream_data.len(), 3);
        assert_eq!(stream_data[0], (0.0, 500));
        assert_eq!(stream_data[1], (10.0, 1000));
        assert_eq!(stream_data[2], (20.0, 1500));
    }
}
