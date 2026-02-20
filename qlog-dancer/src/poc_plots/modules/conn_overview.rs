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

//! Connection overview — config-driven POC pattern.
//!
//! E.C. (FLPROTO-4770 & FLPROTO-4282)
//!
//! Combines four subplots on a shared time axis:
//! 1. Stream sends (cumulative buffer writes/dropped, MAX_DATA,
//!    MAX_STREAM_DATA)
//! 2. Loss spikes (per-event detected losses + cumulative step function)
//! 3. Congestion (cwnd, bytes-in-flight, ssthresh)
//! 4. RTT (min, smoothed, latest)
//!
//! This allows correlating stream activity with loss events, cwnd drops,
//! and RTT spikes in one chart.

use plotters::coord::Shift;
use plotters::prelude::*;

use crate::datastore::Datastore;
use crate::poc_plots::config::PlotConfig;
use crate::poc_plots::series_data::SeriesData;
use crate::poc_plots::series_data::SeriesDataU64;
use crate::poc_plots::theme::parse_legend_position;
use crate::poc_plots::theme::PlotTheme;

use super::loss::LossSeriesStore;

/// Stream sends series (cumulative views of data flowing through streams).
#[derive(Debug, Clone, Default)]
pub struct StreamSendsSeriesStore {
    pub cumulative_buffer_writes: SeriesDataU64,
    pub cumulative_buffer_dropped: SeriesDataU64,
    pub received_max_data: SeriesDataU64,
    pub cumulative_received_stream_max_data: SeriesDataU64,
}

impl StreamSendsSeriesStore {
    pub fn global_x_max(&self) -> Option<f32> {
        [
            self.cumulative_buffer_writes.x_max(),
            self.cumulative_buffer_dropped.x_max(),
            self.received_max_data.x_max(),
            self.cumulative_received_stream_max_data.x_max(),
        ]
        .into_iter()
        .flatten()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    pub fn global_x_min(&self) -> Option<f32> {
        [
            self.cumulative_buffer_writes.x_min(),
            self.received_max_data.x_min(),
        ]
        .into_iter()
        .flatten()
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    pub fn global_y_max(&self) -> Option<u64> {
        [
            self.cumulative_buffer_writes.y_max(),
            self.cumulative_buffer_dropped.y_max(),
            self.received_max_data.y_max(),
            self.cumulative_received_stream_max_data.y_max(),
        ]
        .into_iter()
        .flatten()
        .max()
    }
}

/// Congestion-related series.
#[derive(Debug, Clone, Default)]
pub struct CongestionSeriesStore {
    pub cwnd: SeriesDataU64,
    pub bytes_in_flight: SeriesDataU64,
    pub ssthresh: SeriesDataU64,
}

/// RTT-related series (f32 values in ms).
#[derive(Debug, Clone, Default)]
pub struct RttSeriesStore {
    pub min_rtt: SeriesData<f32>,
    pub smoothed_rtt: SeriesData<f32>,
    pub latest_rtt: SeriesData<f32>,
}

/// All data needed for the combined overview plot.
#[derive(Debug, Clone, Default)]
pub struct OverviewSeriesStore {
    pub stream_sends: StreamSendsSeriesStore,
    pub loss: LossSeriesStore,
    pub congestion: CongestionSeriesStore,
    pub rtt: RttSeriesStore,
}

impl OverviewSeriesStore {
    pub fn new() -> Self {
        Self {
            stream_sends: StreamSendsSeriesStore {
                cumulative_buffer_writes: SeriesData::new(
                    "Cumulative stream buffer writes",
                ),
                cumulative_buffer_dropped: SeriesData::new(
                    "Cumulative stream buffer dropped",
                ),
                received_max_data: SeriesData::new("Received MAX_DATA"),
                cumulative_received_stream_max_data: SeriesData::new(
                    "Cumulative received MAX_STREAM_DATA",
                ),
            },
            loss: LossSeriesStore::new(),
            congestion: CongestionSeriesStore {
                cwnd: SeriesData::new("cwnd"),
                bytes_in_flight: SeriesData::new("bytes_in_flight"),
                ssthresh: SeriesData::new("ssthresh"),
            },
            rtt: RttSeriesStore {
                min_rtt: SeriesData::new("min RTT"),
                smoothed_rtt: SeriesData::new("smoothed RTT"),
                latest_rtt: SeriesData::new("latest RTT"),
            },
        }
    }

    /// Global x_max across all subplots.
    pub fn global_x_max(&self) -> f32 {
        let candidates = [
            self.stream_sends.global_x_max(),
            self.congestion.cwnd.x_max(),
            self.congestion.bytes_in_flight.x_max(),
            self.rtt.min_rtt.x_max(),
            self.rtt.smoothed_rtt.x_max(),
            self.loss.global_x_max(),
        ];
        candidates
            .into_iter()
            .flatten()
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(1.0)
    }

    /// Global x_min across all subplots.
    pub fn global_x_min(&self) -> f32 {
        let candidates = [
            self.stream_sends.global_x_min(),
            self.congestion.cwnd.x_min(),
            self.rtt.min_rtt.x_min(),
            self.loss.global_x_min(),
        ];
        candidates
            .into_iter()
            .flatten()
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0)
    }

    /// Populate from a Datastore.
    pub fn from_datastore(ds: &Datastore) -> Self {
        let mut store = Self::new();

        // Stream sends - use tracker pattern from upstream refactor
        for &(x, y) in &ds.stream_buffer_writes_tracker.sum_series {
            store.stream_sends.cumulative_buffer_writes.push(x, y);
        }
        for &(x, y) in &ds.stream_buffer_dropped_tracker.sum_series {
            store.stream_sends.cumulative_buffer_dropped.push(x, y);
        }
        for &(x, y) in &ds.received_max_data {
            store.stream_sends.received_max_data.push(x, y);
        }
        for &(x, y) in &ds.received_stream_max_data_tracker.sum_series {
            store
                .stream_sends
                .cumulative_received_stream_max_data
                .push(x, y);
        }

        // Congestion
        for &(x, y) in &ds.local_cwnd {
            store.congestion.cwnd.push(x, y);
        }
        for &(x, y) in &ds.local_bytes_in_flight {
            store.congestion.bytes_in_flight.push(x, y);
        }
        for &(x, y) in &ds.local_ssthresh {
            store.congestion.ssthresh.push(x, y);
        }

        // RTT
        for &(x, y) in &ds.local_min_rtt {
            store.rtt.min_rtt.push(x, y);
        }
        for &(x, y) in &ds.local_smoothed_rtt {
            store.rtt.smoothed_rtt.push(x, y);
        }
        for &(x, y) in &ds.local_latest_rtt {
            store.rtt.latest_rtt.push(x, y);
        }

        // Loss
        store.loss = LossSeriesStore::from_datastore(ds);
        store
    }
}

/// Parameters for the overview plot.
#[derive(Debug, Clone)]
pub struct OverviewPlotParams {
    pub x_start: Option<f32>,
    pub x_end: Option<f32>,
}

impl Default for OverviewPlotParams {
    fn default() -> Self {
        Self {
            x_start: None,
            x_end: None,
        }
    }
}

/// Draw the combined overview plot with 4 vertically stacked subplots.
#[cfg(not(target_arch = "wasm32"))]
pub fn draw_overview_plot<DB: DrawingBackend>(
    config: &PlotConfig, params: &OverviewPlotParams,
    store: &OverviewSeriesStore, root: &DrawingArea<DB, Shift>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    let theme = PlotTheme::from_config(config);

    let x_min = params.x_start.unwrap_or_else(|| store.global_x_min());
    let x_max_raw = params.x_end.unwrap_or_else(|| store.global_x_max());
    let x_max = x_max_raw + (x_max_raw - x_min) * 0.05;

    // Split into 4 equal-height subplots.
    let areas = root.split_evenly((4, 1));

    draw_stream_sends_subplot(config, &theme, x_min, x_max, store, &areas[0])?;
    draw_loss_subplot(config, &theme, x_min, x_max, store, &areas[1])?;
    draw_congestion_subplot(config, &theme, x_min, x_max, store, &areas[2])?;
    draw_rtt_subplot(config, &theme, x_min, x_max, store, &areas[3])?;

    Ok(())
}

fn draw_congestion_subplot<DB: DrawingBackend>(
    config: &PlotConfig, theme: &PlotTheme, x_min: f32, x_max: f32,
    store: &OverviewSeriesStore, area: &DrawingArea<DB, Shift>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    // Exclude ssthresh from y_max: it often starts at u64::MAX as a sentinel
    // and would swamp the chart.
    let y_max = [
        store.congestion.cwnd.y_max(),
        store.congestion.bytes_in_flight.y_max(),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(1)
        .saturating_add(1);
    let y_max = y_max.saturating_add(y_max / 10);

    let mut chart = ChartBuilder::on(area)
        .x_label_area_size(25)
        .y_label_area_size(55)
        .margin_right(15)
        .caption(
            "Congestion",
            ("sans-serif", theme.title_fontsize * 0.75)
                .into_font()
                .color(&theme.caption),
        )
        .build_cartesian_2d(x_min..x_max, 0u64..y_max)?;

    chart
        .configure_mesh()
        .axis_style(theme.axis)
        .set_all_tick_mark_size(2)
        .x_label_formatter(&|x| format!("{:.0}", x))
        .y_label_formatter(&|y| format!("{:.0}K", *y as f64 / 1000.0))
        .bold_line_style(theme.bold_line.mix(0.3))
        .light_line_style(theme.light_line.mix(0.1))
        .label_style(
            ("sans-serif", config.xticks.labels.fontsize * 0.85)
                .into_font()
                .color(&theme.caption),
        )
        .draw()?;

    let mut cc = theme.color_cycle.clone();

    if !store.congestion.cwnd.is_empty() {
        let color = cc.next_color();
        chart
            .draw_series(LineSeries::new(
                store.congestion.cwnd.data().to_vec(),
                color.stroke_width(theme.line_width),
            ))?
            .label("cwnd")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }
    if !store.congestion.bytes_in_flight.is_empty() {
        let color = cc.next_color();
        // Use thin line (stroke_width 1) because bytes_in_flight has very
        // dense data with rapid oscillation that otherwise looks filled.
        chart
            .draw_series(LineSeries::new(
                store.congestion.bytes_in_flight.data().to_vec(),
                color.stroke_width(1),
            ))?
            .label("bytes_in_flight")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }
    if !store.congestion.ssthresh.is_empty() {
        let color = cc.next_color();
        chart
            .draw_series(LineSeries::new(
                store.congestion.ssthresh.data().to_vec(),
                color.stroke_width(theme.line_width),
            ))?
            .label("ssthresh")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }

    if theme.display_legend {
        chart
            .configure_series_labels()
            .label_font(
                ("sans-serif", theme.label_fontsize * 0.85)
                    .into_font()
                    .color(&theme.caption),
            )
            .background_style(theme.fill.mix(0.8))
            .border_style(theme.axis)
            .position(parse_legend_position(&config.legend.position))
            .draw()?;
    }

    Ok(())
}

fn draw_rtt_subplot<DB: DrawingBackend>(
    config: &PlotConfig, theme: &PlotTheme, x_min: f32, x_max: f32,
    store: &OverviewSeriesStore, area: &DrawingArea<DB, Shift>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    let y_max = [
        store.rtt.min_rtt.y_max(),
        store.rtt.smoothed_rtt.y_max(),
        store.rtt.latest_rtt.y_max(),
    ]
    .into_iter()
    .flatten()
    .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    .unwrap_or(1.0);
    let y_max = y_max + y_max * 0.05;

    let y_min = [
        store.rtt.min_rtt.y_min(),
        store.rtt.smoothed_rtt.y_min(),
        store.rtt.latest_rtt.y_min(),
    ]
    .into_iter()
    .flatten()
    .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    .unwrap_or(0.0);
    let y_min = (y_min - y_min * 0.05).max(0.0);

    let mut chart = ChartBuilder::on(area)
        .x_label_area_size(25)
        .y_label_area_size(55)
        .margin_right(15)
        .caption(
            "RTT",
            ("sans-serif", theme.title_fontsize * 0.75)
                .into_font()
                .color(&theme.caption),
        )
        .build_cartesian_2d(x_min..x_max, y_min..y_max)?;

    chart
        .configure_mesh()
        .axis_style(theme.axis)
        .set_all_tick_mark_size(2)
        .x_label_formatter(&|x| format!("{:.0}", x))
        .y_label_formatter(&|y| format!("{:.1}", y))
        .bold_line_style(theme.bold_line.mix(0.3))
        .light_line_style(theme.light_line.mix(0.1))
        .label_style(
            ("sans-serif", config.xticks.labels.fontsize * 0.85)
                .into_font()
                .color(&theme.caption),
        )
        .draw()?;

    let mut cc = theme.color_cycle.clone();

    if !store.rtt.min_rtt.is_empty() {
        let color = cc.next_color();
        let raw = store.rtt.min_rtt.data();

        // Step function: hold previous value until next update.
        let mut step_data: Vec<(f32, f32)> = Vec::new();
        for (i, &(x, y)) in raw.iter().enumerate() {
            if i > 0 {
                step_data.push((x, raw[i - 1].1));
            }
            step_data.push((x, y));
        }
        // Extend to end of x-axis.
        if let Some(&(_last_x, last_y)) = step_data.last() {
            if x_max > _last_x {
                step_data.push((x_max, last_y));
            }
        }

        chart
            .draw_series(LineSeries::new(
                step_data,
                color.stroke_width(theme.line_width),
            ))?
            .label("min RTT")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }
    if !store.rtt.smoothed_rtt.is_empty() {
        let color = cc.next_color();
        chart
            .draw_series(LineSeries::new(
                store.rtt.smoothed_rtt.data().to_vec(),
                color.stroke_width(theme.line_width),
            ))?
            .label("smoothed RTT")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }
    if !store.rtt.latest_rtt.is_empty() {
        let color = cc.next_color();
        chart
            .draw_series(LineSeries::new(
                store.rtt.latest_rtt.data().to_vec(),
                color.stroke_width(theme.line_width),
            ))?
            .label("latest RTT")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }

    if theme.display_legend {
        chart
            .configure_series_labels()
            .label_font(
                ("sans-serif", theme.label_fontsize * 0.85)
                    .into_font()
                    .color(&theme.caption),
            )
            .background_style(theme.fill.mix(0.8))
            .border_style(theme.axis)
            .position(parse_legend_position(&config.legend.position))
            .draw()?;
    }

    Ok(())
}

fn draw_stream_sends_subplot<DB: DrawingBackend>(
    config: &PlotConfig, theme: &PlotTheme, x_min: f32, x_max: f32,
    store: &OverviewSeriesStore, area: &DrawingArea<DB, Shift>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    // Exclude received_max_data / cumulative_received_stream_max_data from
    // y_max: flow-control limits can be enormous and would squish actual data.
    let y_max = [
        store.stream_sends.cumulative_buffer_writes.y_max(),
        store.stream_sends.cumulative_buffer_dropped.y_max(),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(1);
    let y_max = y_max.saturating_add(y_max / 10);

    let mut chart = ChartBuilder::on(area)
        .x_label_area_size(25)
        .y_label_area_size(55)
        .margin_right(15)
        .caption(
            "Stream sends",
            ("sans-serif", theme.title_fontsize * 0.75)
                .into_font()
                .color(&theme.caption),
        )
        .build_cartesian_2d(x_min..x_max, 0u64..y_max)?;

    chart
        .configure_mesh()
        .axis_style(theme.axis)
        .set_all_tick_mark_size(2)
        .x_label_formatter(&|x| format!("{:.0}", x))
        .y_label_formatter(&|y| format!("{:.0}K", *y as f64 / 1000.0))
        .bold_line_style(theme.bold_line.mix(0.3))
        .light_line_style(theme.light_line.mix(0.1))
        .label_style(
            ("sans-serif", config.xticks.labels.fontsize * 0.85)
                .into_font()
                .color(&theme.caption),
        )
        .draw()?;

    let mut cc = theme.color_cycle.clone();

    let series_list: [(&SeriesDataU64, &str); 4] = [
        (
            &store.stream_sends.cumulative_buffer_writes,
            "Cumulative stream buffer writes",
        ),
        (
            &store.stream_sends.cumulative_buffer_dropped,
            "Cumulative stream buffer dropped",
        ),
        (
            &store.stream_sends.received_max_data,
            "Received MAX_DATA",
        ),
        (
            &store.stream_sends.cumulative_received_stream_max_data,
            "Cumulative received MAX_STREAM_DATA",
        ),
    ];

    for (series, label) in series_list {
        if !series.is_empty() {
            let color = cc.next_color();
            chart
                .draw_series(LineSeries::new(
                    series.data().to_vec(),
                    color.stroke_width(theme.line_width),
                ))?
                .label(label)
                .legend(move |(x, y)| {
                    PathElement::new(vec![(x, y), (x + 15, y)], color)
                });
        }
    }

    if theme.display_legend {
        chart
            .configure_series_labels()
            .label_font(
                ("sans-serif", theme.label_fontsize * 0.85)
                    .into_font()
                    .color(&theme.caption),
            )
            .background_style(theme.fill.mix(0.8))
            .border_style(theme.axis)
            .position(parse_legend_position(&config.legend.position))
            .draw()?;
    }

    Ok(())
}

fn draw_loss_subplot<DB: DrawingBackend>(
    config: &PlotConfig, theme: &PlotTheme, x_min: f32, x_max: f32,
    store: &OverviewSeriesStore, area: &DrawingArea<DB, Shift>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    let spike_max = store.loss.lost_packets_delta.y_max().unwrap_or(0);
    let cum_max = store.loss.cumulative_y_max().unwrap_or(0);
    let y_max = spike_max.max(cum_max) + spike_max.max(cum_max) / 10 + 1;

    let mut chart = ChartBuilder::on(area)
        .x_label_area_size(25)
        .y_label_area_size(55)
        .margin_right(15)
        .caption(
            "Packet Loss",
            ("sans-serif", theme.title_fontsize * 0.75)
                .into_font()
                .color(&theme.caption),
        )
        .build_cartesian_2d(x_min..x_max, 0u64..y_max)?;

    chart
        .configure_mesh()
        .axis_style(theme.axis)
        .set_all_tick_mark_size(2)
        .x_label_formatter(&|x| format!("{:.0}", x))
        .y_label_formatter(&|y| format!("{}", y))
        .bold_line_style(theme.bold_line.mix(0.3))
        .light_line_style(theme.light_line.mix(0.1))
        .label_style(
            ("sans-serif", config.xticks.labels.fontsize * 0.85)
                .into_font()
                .color(&theme.caption),
        )
        .draw()?;

    let mut cc = theme.color_cycle.clone();

    // Loss spikes as vertical lines (thin stems)
    if !store.loss.lost_packets_delta.is_empty() {
        let color = cc.next_color();
        let data: Vec<(f32, u64)> =
            store.loss.lost_packets_delta.data().to_vec();

        chart
            .draw_series(data.iter().map(|&(x, y)| {
                PathElement::new(
                    vec![(x, 0u64), (x, y)],
                    color.stroke_width(theme.line_width),
                )
            }))?
            .label("Detected losses")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }

    // Cumulative line as step function
    if !store.loss.lost_packets.is_empty() {
        let color = cc.next_color();
        let raw_data = store.loss.lost_packets.data();

        // Build step-function points
        let mut step_data: Vec<(f32, u64)> = Vec::new();
        for (i, &(x, y)) in raw_data.iter().enumerate() {
            if i > 0 {
                let prev_y = raw_data[i - 1].1;
                step_data.push((x, prev_y));
            }
            step_data.push((x, y));
        }

        // Extend cumulative line to end of x-axis
        if let Some(&(last_x, last_y)) = step_data.last() {
            if x_max > last_x {
                step_data.push((x_max, last_y));
            }
        }

        chart
            .draw_series(LineSeries::new(
                step_data,
                color.stroke_width(theme.line_width),
            ))?
            .label("Cumulative lost")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 15, y)], color)
            });
    }

    if theme.display_legend {
        chart
            .configure_series_labels()
            .label_font(
                ("sans-serif", theme.label_fontsize * 0.85)
                    .into_font()
                    .color(&theme.caption),
            )
            .background_style(theme.fill.mix(0.8))
            .border_style(theme.axis)
            .position(parse_legend_position(&config.legend.position))
            .draw()?;
    }

    Ok(())
}

/// Render overview to PNG.
#[cfg(not(target_arch = "wasm32"))]
pub fn render_overview_to_png(
    config: &PlotConfig, params: &OverviewPlotParams,
    store: &OverviewSeriesStore, output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use taller figure for 4 equal-height subplots.
    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height =
        (config.figure.figsize[1] * 2.5 * config.figure.dpi as f32) as u32;

    let root =
        BitMapBackend::new(output_path, (width, height)).into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_overview_plot(config, params, store, &root)?;

    root.present()?;
    Ok(())
}

/// Render overview to SVG.
#[cfg(not(target_arch = "wasm32"))]
pub fn render_overview_to_svg(
    config: &PlotConfig, params: &OverviewPlotParams,
    store: &OverviewSeriesStore, output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let width = (config.figure.figsize[0] * config.figure.dpi as f32) as u32;
    let height =
        (config.figure.figsize[1] * 2.5 * config.figure.dpi as f32) as u32;

    let root = SVGBackend::new(output_path, (width, height)).into_drawing_area();
    let theme = PlotTheme::from_config(config);
    root.fill(&theme.fill)?;

    draw_overview_plot(config, params, store, &root)?;

    root.present()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overview_series_store_global_range() {
        let mut store = OverviewSeriesStore::new();

        store.congestion.cwnd.push(10.0, 12000);
        store.rtt.min_rtt.push(5.0, 15.0);
        store.loss.lost_packets_delta.push(50.0, 3);
        store
            .stream_sends
            .cumulative_buffer_writes
            .push(100.0, 500000);

        assert_eq!(store.global_x_min(), 5.0);
        assert_eq!(store.global_x_max(), 100.0);
    }

    #[test]
    fn test_overview_series_store_empty() {
        let store = OverviewSeriesStore::new();
        assert_eq!(store.global_x_min(), 0.0);
        assert_eq!(store.global_x_max(), 1.0);
    }
}
