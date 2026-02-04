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

//! Pacer plot module - demonstrates the new config-driven plotting pattern.
//!
//! This module shows how to:
//! 1. Use SeriesData for automatic stat tracking (replaces manual
//!    max_pacing_rate, etc.)
//! 2. Use SeriesGroup for related series with shared axis bounds
//! 3. Apply PlotTheme from config.toml
//! 4. Extend lines to full plot width (FLPROTO-5244 requirement)
//!
//! Based on the pacing.rs from quiche esteban/qlog branch which plots:
//! - pacing_rate, delivery_rate (cf_delivery_rate), send_rate (cf_send_rate),
//!   ack_rate (cf_ack_rate)

use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::*;

use crate::poc_plots::config::PlotConfig;
use crate::poc_plots::series_data::SeriesData;
use crate::poc_plots::series_data::SeriesDataU64;
use crate::poc_plots::series_data::SeriesGroup;
use crate::poc_plots::theme::parse_legend_position;
use crate::poc_plots::theme::PlotTheme;
use crate::seriesstore::SeriesStore;

/// Parameters for the pacer plot.
#[derive(Debug, Clone)]
pub struct PacerPlotParams {
    /// Optional clamp for x-axis start
    pub x_start: Option<f32>,
    /// Optional clamp for x-axis end
    pub x_end: Option<f32>,
    /// Optional override for y-axis max
    pub y_max_override: Option<u64>,
    /// Whether to extend lines to full width
    pub extend_to_full_width: bool,
}

impl Default for PacerPlotParams {
    fn default() -> Self {
        Self {
            x_start: None,
            x_end: None,
            y_max_override: None,
            extend_to_full_width: true,
        }
    }
}

/// Data container for pacer-related series using the new SeriesData pattern.
///
/// This replaces the old pattern from SeriesStore:
/// ```ignore
/// pub local_pacing_rate: Vec<QlogPointu64>,
/// pub max_pacing_rate: u64,
/// pub max_delivery_rate: u64,
/// pub max_send_rate: u64,
/// pub max_ack_rate: u64,
/// ```
///
/// With SeriesData, each series auto-tracks its own max/min stats.
#[derive(Debug, Clone)]
pub struct PacerSeriesStore {
    /// Pacing rate series with auto-tracked max/min
    pub pacing_rate: SeriesDataU64,
    /// Delivery rate (cf_delivery_rate in sqlog)
    pub delivery_rate: SeriesDataU64,
    /// Send rate (cf_send_rate in sqlog)
    pub send_rate: SeriesDataU64,
    /// Ack rate (cf_ack_rate in sqlog)
    pub ack_rate: SeriesDataU64,
}

impl PacerSeriesStore {
    pub fn new() -> Self {
        Self {
            pacing_rate: SeriesData::new("Pacing Rate"),
            delivery_rate: SeriesData::new("Delivery Rate"),
            send_rate: SeriesData::new("Send Rate"),
            ack_rate: SeriesData::new("Ack Rate"),
        }
    }

    /// Create a SeriesGroup from the non-empty series for unified axis scaling.
    pub fn as_group(&self) -> SeriesGroup<u64> {
        let mut group = SeriesGroup::new("Rates");

        if !self.pacing_rate.is_empty() {
            group.add_series(self.pacing_rate.clone());
        }
        if !self.delivery_rate.is_empty() {
            group.add_series(self.delivery_rate.clone());
        }
        if !self.send_rate.is_empty() {
            group.add_series(self.send_rate.clone());
        }
        if !self.ack_rate.is_empty() {
            group.add_series(self.ack_rate.clone());
        }

        group
    }

    /// Get the global max across all rate series (for y-axis scaling).
    /// Computes directly from pre-tracked y_max values without cloning data.
    pub fn global_y_max(&self) -> Option<u64> {
        [
            self.pacing_rate.y_max(),
            self.delivery_rate.y_max(),
            self.send_rate.y_max(),
            self.ack_rate.y_max(),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    /// Get the global x_max across all series.
    /// Computes directly from pre-tracked x_max values without cloning data.
    pub fn global_x_max(&self) -> Option<f32> {
        [
            self.pacing_rate.x_max(),
            self.delivery_rate.x_max(),
            self.send_rate.x_max(),
            self.ack_rate.x_max(),
        ]
        .into_iter()
        .flatten()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the global x_min across all series.
    /// Computes directly from pre-tracked x_min values without cloning data.
    pub fn global_x_min(&self) -> Option<f32> {
        [
            self.pacing_rate.x_min(),
            self.delivery_rate.x_min(),
            self.send_rate.x_min(),
            self.ack_rate.x_min(),
        ]
        .into_iter()
        .flatten()
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Populate from raw qlog data points (all four rate series).
    pub fn populate_from_raw(
        &mut self, pacing_rate: &[(f32, u64)], delivery_rate: &[(f32, u64)],
        send_rate: &[(f32, u64)], ack_rate: &[(f32, u64)],
    ) {
        for &(x, y) in pacing_rate {
            self.pacing_rate.push_interp(x, y);
        }
        for &(x, y) in delivery_rate {
            self.delivery_rate.push_interp(x, y);
        }
        for &(x, y) in send_rate {
            self.send_rate.push_interp(x, y);
        }
        for &(x, y) in ack_rate {
            self.ack_rate.push_interp(x, y);
        }
    }

    /// Extend all series to the global x_max (requirement: "line should cover
    /// full width").
    pub fn extend_to_full_width(&mut self) {
        if let Some(x_max) = self.global_x_max() {
            self.pacing_rate.extend_to_x(x_max);
            self.delivery_rate.extend_to_x(x_max);
            self.send_rate.extend_to_x(x_max);
            self.ack_rate.extend_to_x(x_max);
        }
    }
}

impl Default for PacerSeriesStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PacerSeriesStore {
    /// Create a PacerSeriesStore from an existing SeriesStore.
    /// This bridges the existing qlog-dancer infrastructure with the new POC.
    pub fn from_series_store(ss: &SeriesStore) -> Self {
        let mut store = Self::new();

        // Copy rate data from SeriesStore's Vec<(f32, u64)> format
        for &(x, y) in &ss.local_pacing_rate {
            store.pacing_rate.push(x, y);
        }
        for &(x, y) in &ss.local_delivery_rate {
            store.delivery_rate.push(x, y);
        }
        for &(x, y) in &ss.local_send_rate {
            store.send_rate.push(x, y);
        }
        for &(x, y) in &ss.local_ack_rate {
            store.ack_rate.push(x, y);
        }

        store
    }
}

/// Draw the pacer plot using the new config-driven approach.
#[allow(clippy::type_complexity)]
pub fn draw_pacer_plot<'a, DB: DrawingBackend + 'a>(
    config: &PlotConfig, params: &PacerPlotParams, store: &PacerSeriesStore,
    plot: &DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
    DrawingAreaErrorKind<DB::ErrorType>,
> {
    let theme = PlotTheme::from_config(config);

    // Determine axis ranges with right padding
    let x_min = params
        .x_start
        .unwrap_or_else(|| store.global_x_min().unwrap_or(0.0));
    let x_max_raw = params
        .x_end
        .unwrap_or_else(|| store.global_x_max().unwrap_or(1.0));
    // Add 5% right padding so plot doesn't end abruptly
    let x_max = x_max_raw + (x_max_raw - x_min) * 0.05;

    let y_max = params.y_max_override.unwrap_or_else(|| {
        let max = store.global_y_max().unwrap_or(1);
        // Add 10% margin
        max + max / 10
    });

    // Build the chart with right margin so lines don't end at frame edge
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(40)
        .y_label_area_size(60)
        .margin_right(20);

    if theme.display_title {
        builder.caption(
            "Pacing Rate",
            ("sans-serif", theme.title_fontsize)
                .into_font()
                .color(&theme.caption),
        );
    }

    let mut chart = builder.build_cartesian_2d(x_min..x_max, 0u64..y_max)?;

    // Configure mesh/grid with frame
    chart
        .configure_mesh()
        .axis_style(theme.axis)
        .set_all_tick_mark_size(3)
        .x_desc("Time (ms)")
        .y_desc("Rate (MB/s)")
        .x_label_formatter(&|x| format!("{:.0}", x))
        .y_label_formatter(&|y| format!("{:.1}", *y as f64 / 1_000_000.0))
        .bold_line_style(theme.bold_line.mix(0.5))
        .light_line_style(theme.light_line.mix(0.2))
        .axis_desc_style(
            ("sans-serif", config.xlabel.fontsize)
                .into_font()
                .color(&theme.caption),
        )
        .label_style(
            ("sans-serif", config.xticks.labels.fontsize)
                .into_font()
                .color(&theme.caption),
        )
        .draw()?;

    // Draw frame/border around plot area based on axes.spines config
    // Use the root drawing area with pixel coordinates
    {
        let plotting_area = chart.plotting_area();
        let (x0, y0) = plotting_area.get_base_pixel();
        let (x1, y1) = (
            x0 + plotting_area.dim_in_pixel().0 as i32,
            y0 + plotting_area.dim_in_pixel().1 as i32,
        );
        let frame_style = ShapeStyle::from(theme.axis).stroke_width(1);

        if config.axes.spines.top {
            plot.draw(&PathElement::new(vec![(x0, y0), (x1, y0)], frame_style))?;
        }
        if config.axes.spines.bottom {
            plot.draw(&PathElement::new(vec![(x0, y1), (x1, y1)], frame_style))?;
        }
        if config.axes.spines.left {
            plot.draw(&PathElement::new(vec![(x0, y0), (x0, y1)], frame_style))?;
        }
        if config.axes.spines.right {
            plot.draw(&PathElement::new(vec![(x1, y0), (x1, y1)], frame_style))?;
        }
    }

    // Draw series with colors from the theme's color cycle
    let mut color_cycle = theme.color_cycle.clone();

    // Draw pacing rate
    if !store.pacing_rate.is_empty() {
        let color = color_cycle.next_color();
        let series_data: Vec<(f32, u64)> = store.pacing_rate.data().to_vec();

        chart
            .draw_series(LineSeries::new(
                series_data,
                color.stroke_width(theme.line_width),
            ))?
            .label(store.pacing_rate.label())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 20, y)], color)
            });
    }

    // Draw delivery rate if present
    if !store.delivery_rate.is_empty() {
        let color = color_cycle.next_color();
        let series_data: Vec<(f32, u64)> = store.delivery_rate.data().to_vec();

        chart
            .draw_series(LineSeries::new(
                series_data,
                color.stroke_width(theme.line_width),
            ))?
            .label(store.delivery_rate.label())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 20, y)], color)
            });
    }

    // Draw send rate if present
    if !store.send_rate.is_empty() {
        let color = color_cycle.next_color();
        let series_data: Vec<(f32, u64)> = store.send_rate.data().to_vec();

        chart
            .draw_series(LineSeries::new(
                series_data,
                color.stroke_width(theme.line_width),
            ))?
            .label(store.send_rate.label())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 20, y)], color)
            });
    }

    // Draw ack rate if present
    if !store.ack_rate.is_empty() {
        let color = color_cycle.next_color();
        let series_data: Vec<(f32, u64)> = store.ack_rate.data().to_vec();

        chart
            .draw_series(LineSeries::new(
                series_data,
                color.stroke_width(theme.line_width),
            ))?
            .label(store.ack_rate.label())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 20, y)], color)
            });
    }

    // Draw legend if enabled
    if theme.display_legend {
        chart
            .configure_series_labels()
            .label_font(
                ("sans-serif", theme.label_fontsize)
                    .into_font()
                    .color(&theme.caption),
            )
            .background_style(theme.fill.mix(0.8))
            .border_style(theme.axis)
            .position(parse_legend_position(&config.legend.position))
            .draw()?;
    }

    Ok(chart)
}

/// Convenience function to render pacer plot to a PNG file.
#[cfg(not(target_arch = "wasm32"))]
pub fn render_pacer_to_png(
    config: &PlotConfig, params: &PacerPlotParams, store: &PacerSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height = (config.figure.figsize[1] * config.figure.dpi as f32) as u32;

    let root =
        BitMapBackend::new(output_path, (width, height)).into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_pacer_plot(config, params, store, &root)?;

    root.present()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pacer_series_store_stats() {
        let mut store = PacerSeriesStore::new();

        // Simulate pushing pacing rate data
        store.pacing_rate.push(0.0, 1000);
        store.pacing_rate.push(1.0, 2000);
        store.pacing_rate.push(2.0, 1500);

        // Stats should be auto-tracked
        assert_eq!(store.pacing_rate.y_max(), Some(2000));
        assert_eq!(store.pacing_rate.y_min(), Some(1000));
        assert_eq!(store.pacing_rate.x_max(), Some(2.0));
        assert_eq!(store.pacing_rate.x_min(), Some(0.0));

        // Global max should work
        assert_eq!(store.global_y_max(), Some(2000));
    }

    #[test]
    fn test_pacer_series_store_multiple_series() {
        let mut store = PacerSeriesStore::new();

        store.pacing_rate.push(0.0, 1000);
        store.pacing_rate.push(1.0, 2000);

        store.delivery_rate.push(0.5, 500);
        store.delivery_rate.push(1.5, 3000); // Higher than pacing rate

        // Global max should be from delivery_rate
        assert_eq!(store.global_y_max(), Some(3000));
        assert_eq!(store.global_x_max(), Some(1.5));
        assert_eq!(store.global_x_min(), Some(0.0));
    }

    #[test]
    fn test_extend_to_full_width() {
        let mut store = PacerSeriesStore::new();

        store.pacing_rate.push(0.0, 1000);
        store.pacing_rate.push(1.0, 2000);

        store.delivery_rate.push(0.0, 500);
        store.delivery_rate.push(2.0, 1500); // Extends further

        store.extend_to_full_width();

        // Pacing rate should now extend to x=2.0
        let pacing_data = store.pacing_rate.data();
        let last_point = pacing_data.last().unwrap();
        assert_eq!(last_point.0, 2.0);
        assert_eq!(last_point.1, 2000); // Same y value as before
    }

    #[test]
    fn test_populate_from_raw() {
        let mut store = PacerSeriesStore::new();

        let pacing = vec![(0.0, 1000u64), (1.0, 2000), (2.0, 1500)];
        let delivery = vec![(0.0, 900u64), (1.0, 1800)];
        let send = vec![];
        let ack = vec![];
        store.populate_from_raw(&pacing, &delivery, &send, &ack);

        // Should have interpolated points (step function)
        assert!(store.pacing_rate.len() > pacing.len());
        assert_eq!(store.pacing_rate.y_max(), Some(2000));
        assert_eq!(store.delivery_rate.y_max(), Some(1800));
    }
}
