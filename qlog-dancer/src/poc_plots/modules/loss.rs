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

//! Loss plot module — visualizes packet loss events over time.
//!
//! E.C. (FLPROTO-4770 & FLPROTO-4282)
//!
//! This module shows:
//! 1. Per-event loss spikes (delta packets/bytes lost per detection event)
//! 2. Cumulative loss count over time
//!
//! **Important distinction**: CCA "recovery" state != packet loss.
//! This plot shows **actual detected packet losses**, not CCA state transitions.
//!
//! Uses the config-driven POC pattern (PlotTheme, SeriesData, config.toml).

use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::*;

use crate::datastore::Datastore;
use crate::poc_plots::config::PlotConfig;
use crate::poc_plots::series_data::SeriesData;
use crate::poc_plots::series_data::SeriesDataU64;
use crate::poc_plots::theme::parse_legend_position;
use crate::poc_plots::theme::PlotTheme;

/// Parameters for the loss plot.
#[derive(Debug, Clone)]
pub struct LossPlotParams {
    /// Optional clamp for x-axis start
    pub x_start: Option<f32>,
    /// Optional clamp for x-axis end
    pub x_end: Option<f32>,
    /// Optional override for y-axis max
    pub y_max_override: Option<u64>,
    /// Whether to show cumulative loss line alongside spikes
    pub show_cumulative: bool,
}

impl Default for LossPlotParams {
    fn default() -> Self {
        Self {
            x_start: None,
            x_end: None,
            y_max_override: None,
            show_cumulative: true,
        }
    }
}

/// Data container for loss-related series using the SeriesData pattern.
///
/// Populated from `cf_lost_packets`, `cf_lost_bytes`, `cf_lost_packets_delta`,
/// `cf_lost_bytes_delta` in MetricsUpdated ex_data.
#[derive(Debug, Clone)]
pub struct LossSeriesStore {
    /// Cumulative lost packet count over time
    pub lost_packets: SeriesDataU64,
    /// Cumulative lost bytes over time
    pub lost_bytes: SeriesDataU64,
    /// Per-event lost packet delta (spikes)
    pub lost_packets_delta: SeriesDataU64,
    /// Per-event lost bytes delta (spikes)
    pub lost_bytes_delta: SeriesDataU64,
}

impl LossSeriesStore {
    pub fn new() -> Self {
        Self {
            lost_packets: SeriesData::new("Lost Packets (cumulative)"),
            lost_bytes: SeriesData::new("Lost Bytes (cumulative)"),
            lost_packets_delta: SeriesData::new("Detected Losses (per event)"),
            lost_bytes_delta: SeriesData::new("Lost Bytes (per event)"),
        }
    }

    /// Get the global y_max across delta series (for spike plot scaling).
    pub fn delta_y_max(&self) -> Option<u64> {
        [
            self.lost_packets_delta.y_max(),
            self.lost_bytes_delta.y_max(),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    /// Get the y_max for cumulative lost packets.
    pub fn cumulative_y_max(&self) -> Option<u64> {
        self.lost_packets.y_max()
    }

    /// Get the global x_max across all series.
    pub fn global_x_max(&self) -> Option<f32> {
        [
            self.lost_packets.x_max(),
            self.lost_bytes.x_max(),
            self.lost_packets_delta.x_max(),
            self.lost_bytes_delta.x_max(),
        ]
        .into_iter()
        .flatten()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the global x_min across all series.
    pub fn global_x_min(&self) -> Option<f32> {
        [
            self.lost_packets.x_min(),
            self.lost_bytes.x_min(),
            self.lost_packets_delta.x_min(),
            self.lost_bytes_delta.x_min(),
        ]
        .into_iter()
        .flatten()
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Whether any loss data is available.
    pub fn has_data(&self) -> bool {
        !self.lost_packets_delta.is_empty() || !self.lost_packets.is_empty()
    }

    /// Create a LossSeriesStore from a Datastore.
    pub fn from_datastore(ds: &Datastore) -> Self {
        let mut store = Self::new();

        for &(x, y) in &ds.local_lost_packets {
            store.lost_packets.push(x, y);
        }
        for &(x, y) in &ds.local_lost_bytes {
            store.lost_bytes.push(x, y);
        }
        for &(x, y) in &ds.local_lost_packets_delta {
            store.lost_packets_delta.push(x, y);
        }
        for &(x, y) in &ds.local_lost_bytes_delta {
            store.lost_bytes_delta.push(x, y);
        }

        store
    }
}

impl Default for LossSeriesStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Draw the loss plot using the config-driven approach.
///
/// Shows per-event loss spikes as vertical bars, with an optional
/// cumulative loss line overlay.
#[allow(clippy::type_complexity)]
pub fn draw_loss_plot<'a, DB: DrawingBackend + 'a>(
    config: &PlotConfig, params: &LossPlotParams, store: &LossSeriesStore,
    plot: &DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
    DrawingAreaErrorKind<DB::ErrorType>,
> {
    let theme = PlotTheme::from_config(config);

    // Determine axis ranges
    let x_min = params
        .x_start
        .unwrap_or_else(|| store.global_x_min().unwrap_or(0.0));
    let x_max_raw = params
        .x_end
        .unwrap_or_else(|| store.global_x_max().unwrap_or(1.0));
    let x_max = x_max_raw + (x_max_raw - x_min) * 0.05;

    // Y-axis: use delta max for spikes, or cumulative if showing that
    let y_max = params.y_max_override.unwrap_or_else(|| {
        let spike_max = store.lost_packets_delta.y_max().unwrap_or(1);
        let cum_max = if params.show_cumulative {
            store.cumulative_y_max().unwrap_or(0)
        } else {
            0
        };
        let max = spike_max.max(cum_max);
        // Add 10% margin
        max + max / 10 + 1
    });

    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(40)
        .y_label_area_size(60)
        .margin_right(20);

    if theme.display_title {
        builder.caption(
            "Packet Loss",
            ("sans-serif", theme.title_fontsize)
                .into_font()
                .color(&theme.caption),
        );
    }

    let mut chart = builder.build_cartesian_2d(x_min..x_max, 0u64..y_max)?;

    chart
        .configure_mesh()
        .axis_style(theme.axis)
        .set_all_tick_mark_size(3)
        .x_desc("Time (ms)")
        .y_desc("Packets Lost")
        .x_label_formatter(&|x| format!("{:.0}", x))
        .y_label_formatter(&|y| format!("{}", y))
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

    // Draw frame/border around plot area
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

    let mut color_cycle = theme.color_cycle.clone();

    // Draw per-event loss spikes as vertical bars from baseline
    if !store.lost_packets_delta.is_empty() {
        let color = color_cycle.next_color();
        let spike_data: Vec<(f32, u64)> =
            store.lost_packets_delta.data().to_vec();

        // Draw vertical lines from y=0 to y=delta for each spike
        chart.draw_series(spike_data.iter().map(|&(x, y)| {
            PathElement::new(
                vec![(x, 0u64), (x, y)],
                color.stroke_width(theme.line_width),
            )
        }))?
        .label(store.lost_packets_delta.label())
        .legend(move |(x, y)| {
            PathElement::new(vec![(x, y), (x + 20, y)], color)
        });

        // Draw circle markers at spike tops
        let marker_color = color;
        chart.draw_series(spike_data.iter().map(|&(x, y)| {
            Circle::new((x, y), 3, marker_color.filled())
        }))?;
    }

    // Draw cumulative lost packets as a step function
    if params.show_cumulative && !store.lost_packets.is_empty() {
        let color = color_cycle.next_color();
        let raw_data = store.lost_packets.data();

        // Build step-function points: for each transition, insert a
        // horizontal segment at the previous y before stepping up.
        let mut step_data: Vec<(f32, u64)> = Vec::new();
        for (i, &(x, y)) in raw_data.iter().enumerate() {
            if i > 0 {
                let prev_y = raw_data[i - 1].1;
                step_data.push((x, prev_y));
            }
            step_data.push((x, y));
        }

        // Extend cumulative line to end of trace
        if let Some(x_end) = params.x_end {
            if let Some(&(last_x, last_y)) = step_data.last() {
                if x_end > last_x {
                    step_data.push((x_end, last_y));
                }
            }
        }

        chart
            .draw_series(LineSeries::new(
                step_data,
                color.stroke_width(theme.line_width),
            ))?
            .label(store.lost_packets.label())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 20, y)], color)
            });
    }

    // Draw legend
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

/// Convenience function to render loss plot to a PNG file.
#[cfg(not(target_arch = "wasm32"))]
pub fn render_loss_to_png(
    config: &PlotConfig, params: &LossPlotParams, store: &LossSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height = (config.figure.figsize[1] * config.figure.dpi as f32) as u32;

    let root =
        BitMapBackend::new(output_path, (width, height)).into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_loss_plot(config, params, store, &root)?;

    root.present()?;
    Ok(())
}

/// Convenience function to render loss plot to an SVG file.
#[cfg(not(target_arch = "wasm32"))]
pub fn render_loss_to_svg(
    config: &PlotConfig, params: &LossPlotParams, store: &LossSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height = (config.figure.figsize[1] * config.figure.dpi as f32) as u32;

    let root = SVGBackend::new(output_path, (width, height)).into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_loss_plot(config, params, store, &root)?;

    root.present()?;
    Ok(())
}

/// Convenience function to render loss plot to a PDF file.
/// Requires the `cairo` feature and system Cairo libraries.
#[cfg(all(not(target_arch = "wasm32"), feature = "cairo"))]
pub fn render_loss_to_pdf(
    config: &PlotConfig, params: &LossPlotParams, store: &LossSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use cairo::Context;
    use cairo::PdfSurface;
    use plotters_cairo::CairoBackend;

    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height = (config.figure.figsize[1] * config.figure.dpi as f32) as u32;

    let surface = PdfSurface::new(width as f64, height as f64, output_path)?;
    let cr = Context::new(&surface)?;
    let root = CairoBackend::new(&cr, (width, height))?.into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_loss_plot(config, params, store, &root)?;

    root.present()?;
    surface.finish();
    Ok(())
}

/// Convenience function to render loss plot to an EPS file.
/// Requires the `cairo` feature and system Cairo libraries.
#[cfg(all(not(target_arch = "wasm32"), feature = "cairo"))]
pub fn render_loss_to_eps(
    config: &PlotConfig, params: &LossPlotParams, store: &LossSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use cairo::Context;
    use cairo::PsSurface;
    use plotters_cairo::CairoBackend;

    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height = (config.figure.figsize[1] * config.figure.dpi as f32) as u32;

    let surface = PsSurface::new(width as f64, height as f64, output_path)?;
    surface.set_eps(true);
    let cr = Context::new(&surface)?;
    let root = CairoBackend::new(&cr, (width, height))?.into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_loss_plot(config, params, store, &root)?;

    root.present()?;
    surface.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loss_series_store_stats() {
        let mut store = LossSeriesStore::new();

        store.lost_packets_delta.push(100.0, 3);
        store.lost_packets_delta.push(200.0, 7);
        store.lost_packets_delta.push(300.0, 1);

        assert_eq!(store.lost_packets_delta.y_max(), Some(7));
        assert_eq!(store.lost_packets_delta.y_min(), Some(1));
        assert_eq!(store.lost_packets_delta.x_max(), Some(300.0));
        assert_eq!(store.lost_packets_delta.x_min(), Some(100.0));
        assert!(store.has_data());
    }

    #[test]
    fn test_loss_series_store_cumulative() {
        let mut store = LossSeriesStore::new();

        store.lost_packets.push(100.0, 3);
        store.lost_packets.push(200.0, 10);
        store.lost_packets.push(300.0, 11);

        assert_eq!(store.cumulative_y_max(), Some(11));
    }

    #[test]
    fn test_loss_series_store_empty() {
        let store = LossSeriesStore::new();
        assert!(!store.has_data());
        assert_eq!(store.delta_y_max(), None);
        assert_eq!(store.cumulative_y_max(), None);
        assert_eq!(store.global_x_max(), None);
    }

    #[test]
    fn test_loss_series_store_global_range() {
        let mut store = LossSeriesStore::new();

        store.lost_packets_delta.push(50.0, 2);
        store.lost_packets.push(100.0, 5);
        store.lost_bytes_delta.push(300.0, 1500);

        assert_eq!(store.global_x_min(), Some(50.0));
        assert_eq!(store.global_x_max(), Some(300.0));
    }
}
