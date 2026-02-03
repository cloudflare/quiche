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

//! Smart series data container with auto-computed statistics.
//!
//! This addresses the improvement suggestion from Antonio Vicente:
//! > There's potential for improvement here by adding a struct that holds
//! > the Vec and max. This would simplify the adds by pushing into the
//! > struct also computing the max and other possibly useful stats like min.

use std::fmt::Debug;

/// A smart container for time-series data that automatically tracks statistics.
///
/// Instead of manually tracking `max_pacing_rate`, `max_delivery_rate`, etc.
/// separately from their data vectors, this struct encapsulates both the data
/// and its computed statistics.
#[derive(Debug, Clone)]
pub struct SeriesData<T>
where
    T: PartialOrd + Copy + Debug,
{
    /// The underlying data points (x=time, y=value)
    data: Vec<(f32, T)>,
    /// Label for this series (used in legends)
    label: String,
    /// Maximum Y value observed
    y_max: Option<T>,
    /// Minimum Y value observed
    y_min: Option<T>,
    /// Maximum X value observed (time)
    x_max: Option<f32>,
    /// Minimum X value observed (time)
    x_min: Option<f32>,
}

impl<T> SeriesData<T>
where
    T: PartialOrd + Copy + Debug,
{
    /// Create a new empty series with the given label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            data: Vec::new(),
            label: label.into(),
            y_max: None,
            y_min: None,
            x_max: None,
            x_min: None,
        }
    }

    /// Create a new series with pre-allocated capacity.
    pub fn with_capacity(label: impl Into<String>, capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            label: label.into(),
            y_max: None,
            y_min: None,
            x_max: None,
            x_min: None,
        }
    }

    /// Push a new data point, automatically updating statistics.
    pub fn push(&mut self, x: f32, y: T) {
        // Update Y statistics
        self.y_max = Some(match self.y_max {
            Some(current) if current >= y => current,
            _ => y,
        });
        self.y_min = Some(match self.y_min {
            Some(current) if current <= y => current,
            _ => y,
        });

        // Update X statistics
        self.x_max = Some(match self.x_max {
            Some(current) if current >= x => current,
            _ => x,
        });
        self.x_min = Some(match self.x_min {
            Some(current) if current <= x => current,
            _ => x,
        });

        self.data.push((x, y));
    }

    /// Push with interpolation (step function behavior).
    /// Inserts a point at (new_x, previous_y) before the new point.
    pub fn push_interp(&mut self, x: f32, y: T) {
        if let Some((_, prev_y)) = self.data.last() {
            // Insert step: horizontal line to new x at previous y
            self.push(x, *prev_y);
        }
        self.push(x, y);
    }

    /// Get the label for this series.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the maximum Y value, if any data exists.
    pub fn y_max(&self) -> Option<T> {
        self.y_max
    }

    /// Get the minimum Y value, if any data exists.
    pub fn y_min(&self) -> Option<T> {
        self.y_min
    }

    /// Get the maximum X value (time), if any data exists.
    pub fn x_max(&self) -> Option<f32> {
        self.x_max
    }

    /// Get the minimum X value (time), if any data exists.
    pub fn x_min(&self) -> Option<f32> {
        self.x_min
    }

    /// Get the underlying data as a slice.
    pub fn data(&self) -> &[(f32, T)] {
        &self.data
    }

    /// Get the number of data points.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the series is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Iterate over the data points.
    pub fn iter(&self) -> impl Iterator<Item = &(f32, T)> {
        self.data.iter()
    }

    /// Extend the line to a given x value (for "line should cover full width").
    /// This adds a final point at (x_end, last_y) if the series has data.
    pub fn extend_to_x(&mut self, x_end: f32) {
        if let Some((last_x, last_y)) = self.data.last().copied() {
            if x_end > last_x {
                self.push(x_end, last_y);
            }
        }
    }
}

impl<T> Default for SeriesData<T>
where
    T: PartialOrd + Copy + Debug,
{
    fn default() -> Self {
        Self::new("")
    }
}

/// Convenience type aliases for common series types
pub type SeriesDataU64 = SeriesData<u64>;
pub type SeriesDataF32 = SeriesData<f32>;

/// A collection of related series that share axis bounds.
///
/// Useful for plots that overlay multiple series (e.g., pacing rate,
/// delivery rate, send rate on the same chart).
#[derive(Debug, Clone)]
pub struct SeriesGroup<T>
where
    T: PartialOrd + Copy + Debug,
{
    series: Vec<SeriesData<T>>,
    name: String,
}

impl<T> SeriesGroup<T>
where
    T: PartialOrd + Copy + Debug,
{
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            series: Vec::new(),
            name: name.into(),
        }
    }

    pub fn add_series(&mut self, series: SeriesData<T>) {
        self.series.push(series);
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn series(&self) -> &[SeriesData<T>] {
        &self.series
    }

    /// Get the global Y max across all series in the group.
    pub fn global_y_max(&self) -> Option<T> {
        self.series
            .iter()
            .filter_map(|s| s.y_max())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the global Y min across all series in the group.
    pub fn global_y_min(&self) -> Option<T> {
        self.series
            .iter()
            .filter_map(|s| s.y_min())
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the global X max across all series in the group.
    pub fn global_x_max(&self) -> Option<f32> {
        self.series.iter().filter_map(|s| s.x_max()).fold(
            None,
            |acc, x| match acc {
                Some(current) if current >= x => Some(current),
                _ => Some(x),
            },
        )
    }

    /// Get the global X min across all series in the group.
    pub fn global_x_min(&self) -> Option<f32> {
        self.series.iter().filter_map(|s| s.x_min()).fold(
            None,
            |acc, x| match acc {
                Some(current) if current <= x => Some(current),
                _ => Some(x),
            },
        )
    }

    /// Extend all series to the global x_max (for full-width lines).
    pub fn extend_all_to_global_x_max(&mut self) {
        if let Some(x_max) = self.global_x_max() {
            for series in &mut self.series {
                series.extend_to_x(x_max);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_series_data_push_updates_stats() {
        let mut series: SeriesDataU64 = SeriesData::new("test");

        series.push(0.0, 100);
        assert_eq!(series.y_max(), Some(100));
        assert_eq!(series.y_min(), Some(100));

        series.push(1.0, 200);
        assert_eq!(series.y_max(), Some(200));
        assert_eq!(series.y_min(), Some(100));

        series.push(2.0, 50);
        assert_eq!(series.y_max(), Some(200));
        assert_eq!(series.y_min(), Some(50));
        assert_eq!(series.x_max(), Some(2.0));
        assert_eq!(series.x_min(), Some(0.0));
    }

    #[test]
    fn test_series_data_push_interp() {
        let mut series: SeriesDataU64 = SeriesData::new("test");

        series.push(0.0, 100);
        series.push_interp(2.0, 200);

        // Should have 3 points: (0,100), (2,100), (2,200)
        assert_eq!(series.len(), 3);
        let data = series.data();
        assert_eq!(data[0], (0.0, 100));
        assert_eq!(data[1], (2.0, 100));
        assert_eq!(data[2], (2.0, 200));
    }

    #[test]
    fn test_series_group_global_stats() {
        let mut group: SeriesGroup<u64> = SeriesGroup::new("rates");

        let mut s1 = SeriesData::new("pacing_rate");
        s1.push(0.0, 100);
        s1.push(1.0, 300);

        let mut s2 = SeriesData::new("delivery_rate");
        s2.push(0.5, 50);
        s2.push(2.0, 250);

        group.add_series(s1);
        group.add_series(s2);

        assert_eq!(group.global_y_max(), Some(300));
        assert_eq!(group.global_y_min(), Some(50));
        assert_eq!(group.global_x_max(), Some(2.0));
        assert_eq!(group.global_x_min(), Some(0.0));
    }

    #[test]
    fn test_extend_to_x() {
        let mut series: SeriesDataU64 = SeriesData::new("test");
        series.push(0.0, 100);
        series.push(1.0, 200);

        series.extend_to_x(3.0);

        assert_eq!(series.len(), 3);
        assert_eq!(series.data()[2], (3.0, 200));
    }
}
