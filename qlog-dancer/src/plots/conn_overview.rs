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

use full_palette::PURPLE_500;
use minmax::XMinMax;
use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::*;

use crate::plots::colors::*;
use crate::plots::*;

#[cfg(not(target_arch = "wasm32"))]
use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

#[cfg(not(target_arch = "wasm32"))]
use super::congestion_control::draw_congestion_plot;
#[cfg(not(target_arch = "wasm32"))]
use super::rtt::draw_rtt_plot;

struct XYMinMax {
    pub x: XMinMax,
    pub y_min: u64,
    pub y_max: u64,
}

impl XYMinMax {
    fn init(params: &PlotParameters, ss: &SeriesStore, y_max: u64) -> Self {
        let x = XMinMax::new(
            ss.sent_x_min,
            ss.sent_x_max,
            params.clamp.start,
            params.clamp.end,
        );

        Self { x, y_min: 0, y_max }
    }

    fn y_range(&self) -> std::ops::Range<u64> {
        self.y_min..self.y_max
    }
}

#[derive(Clone, Debug)]
pub enum OverviewChartOutputType {
    Png {
        output_dir: String,
        cwnd_y_max: Option<u64>,
        stream_y_max: Option<u64>,
    },

    Canvas {
        main_plot_canvas_id: String,
        congestion_plot_canvas_id: String,
        rtt_plot_canvas_id: String,
    },
}

impl From<OverviewChartOutputType> for ChartOutputType {
    fn from(val: OverviewChartOutputType) -> Self {
        match val {
            OverviewChartOutputType::Png {
                output_dir,
                cwnd_y_max,
                stream_y_max,
            } => ChartOutputType::Png {
                output_dir,
                cwnd_y_max,
                stream_y_max,
            },

            // Where we use this type in this module, this variant is a no-op,
            // so we can put anything in the output TBH
            OverviewChartOutputType::Canvas {
                main_plot_canvas_id,
                ..
            } => ChartOutputType::Canvas {
                canvas_id: main_plot_canvas_id,
            },
        }
    }
}

fn draw_sent_max_data<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(
        &ss.sent_max_data,
        Some("Sent MAX_DATA"),
        BLACK,
        stream_chart,
    );
}

fn draw_cumulative_sent_max_data<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(
        &ss.sum_sent_stream_max_data,
        Some("Cumulative sent MAX_STREAM_DATA"),
        CYAN,
        stream_chart,
    );
}

fn draw_sent_max_stream_data<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let mut label = Some("Sent MAX_STREAM_DATA");

    let streams = &ss.sent_stream_max_data;
    for series in streams {
        draw_line(series.1, label, BLUE, stream_chart);
        label = None;
    }
}

fn draw_buffer_reads<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let mut label = Some("Stream buffer read");

    let streams = &ss.stream_buffer_reads;
    for series in streams {
        draw_line(series.1, label, FOREST_GREEN, stream_chart);
        label = None;
    }
}

fn draw_cumulative_buffer_reads<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(
        &ss.sum_stream_buffer_reads,
        Some("Cumulative stream buffer read"),
        GREEN,
        stream_chart,
    );
}

fn draw_buffer_writes<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let mut label = Some("Stream buffer write");

    let streams = &ss.stream_buffer_writes;
    for series in streams {
        draw_line(series.1, label, MAGENTA, stream_chart);
        label = None;
    }
}

fn draw_cumulative_buffer_writes<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let data = &ss.sum_stream_buffer_writes;
    let label = Some("Cumulative stream buffer writes");

    draw_line(data, label, RGBColor(255, 0, 0), stream_chart);
}

fn draw_buffer_dropped<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let mut label = Some("Stream buffer dropped");

    let streams = &ss.stream_buffer_dropped;
    for series in streams {
        draw_line(series.1, label, ORANGE, stream_chart);
        label = None;
    }
}

fn draw_cumulative_buffer_dropped<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let data = &ss.sum_stream_buffer_dropped;
    let label = Some("Cumulative stream buffer dropped");

    draw_line(data, label, RGBColor(0, 0, 255), stream_chart);
}

fn draw_sent_stream_data<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let mut label = Some("Sent stream data");

    let streams = &ss.sent_stream_frames_series;
    for series in streams {
        draw_line(series.1, label, PURPLE_500, stream_chart);
        label = None;
    }
}

fn draw_received_max_data<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(
        &ss.received_max_data,
        Some("Cumulative received MAX_DATA"),
        MID_GREY,
        stream_chart,
    );
}

fn draw_cumulative_received_stream_max_data<DB: DrawingBackend>(
    ss: &SeriesStore,
    stream_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(
        &ss.sum_received_stream_max_data,
        Some("Cumulative received MAX_STREAM_DATA"),
        MUSTARD,
        stream_chart,
    );
}

#[cfg(target_arch = "wasm32")]
fn draw_main_plot<'a, DB: DrawingBackend + 'a>(
    filename: &str, params: &PlotParameters, axis: XYMinMax, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        let caption = format!("{} Connection overview", filename);
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        params.display_minor_lines,
        &mut chart,
    );

    draw_sent_max_data(ss, &mut chart);
    draw_cumulative_sent_max_data(ss, &mut chart);
    draw_sent_max_stream_data(ss, &mut chart);
    draw_buffer_reads(ss, &mut chart);
    draw_cumulative_buffer_reads(ss, &mut chart);
    draw_buffer_writes(ss, &mut chart);
    draw_cumulative_buffer_writes(ss, &mut chart);
    draw_buffer_dropped(ss, &mut chart);
    draw_cumulative_buffer_dropped(ss, &mut chart);
    draw_sent_stream_data(ss, &mut chart);
    draw_received_max_data(ss, &mut chart);
    draw_cumulative_received_stream_max_data(ss, &mut chart);

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()
            .unwrap();
    }

    chart
}

fn draw_stream_send_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: XYMinMax, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Stream sends",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        false,
        &mut chart,
    );

    draw_cumulative_buffer_writes(ss, &mut chart);
    draw_cumulative_buffer_dropped(ss, &mut chart);
    draw_buffer_writes(ss, &mut chart);
    draw_buffer_dropped(ss, &mut chart);
    draw_sent_stream_data(ss, &mut chart);
    draw_received_max_data(ss, &mut chart);
    draw_cumulative_received_stream_max_data(ss, &mut chart);

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()
            .unwrap();
    }

    chart
}

fn draw_stream_recv_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: XYMinMax, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Stream receives",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        false,
        &mut chart,
    );

    draw_sent_max_data(ss, &mut chart);
    draw_cumulative_sent_max_data(ss, &mut chart);
    draw_sent_max_stream_data(ss, &mut chart);
    draw_buffer_reads(ss, &mut chart);
    draw_cumulative_buffer_reads(ss, &mut chart);

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()
            .unwrap();
    }

    chart
}

#[cfg(not(target_arch = "wasm32"))]
pub fn plot_connection_overview(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &OverviewChartOutputType,
) {
    let chart_config = ChartConfig {
        title: "conn-overview".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone().into(),
    };

    chart_config.init_chart_dir();

    let chart_path = chart_config.chart_filepath();

    let root = make_chart_bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    );

    let (top_margin, bottom) = root.split_vertically((5).percent());
    let (stream_plots, cwnd_rtt_area) = bottom.split_vertically((60).percent());
    let (stream_send_plot, stream_recv_plot) =
        stream_plots.split_vertically((50).percent());
    let (congestion_plot, rtt_plot) =
        cwnd_rtt_area.split_vertically((60).percent());

    let stream_send_y_max = if let Some(y_max) = params.clamp.stream_y_max {
        y_max
    } else {
        ss.y_max_stream_send_plot
    };

    let stream_recv_y_max = if let Some(y_max) = params.clamp.stream_y_max {
        y_max
    } else {
        ss.y_max_stream_recv_plot
    };

    let stream_send_axis = XYMinMax::init(params, ss, stream_send_y_max);
    let stream_recv_axis = XYMinMax::init(params, ss, stream_recv_y_max);

    let cwnd_y_max = if let Some(y_max) = params.cwnd_y_max {
        y_max
    } else {
        // add a bit of margin
        ss.y_max_congestion_plot + ss.y_max_congestion_plot / 10
    };

    let common_axis = super::minmax::XYMinMax::init(
        ss.sent_x_min..ss.sent_x_max,
        params.clamp.start,
        params.clamp.end,
        0..cwnd_y_max,
    );

    top_margin
        .draw_text(
            format!("{} Connection overview", filename).as_str(),
            &chart_title_style(&params.colors.caption),
            (0, 0),
        )
        .unwrap();
    draw_stream_send_plot(params, stream_send_axis, ss, &stream_send_plot);
    draw_stream_recv_plot(params, stream_recv_axis, ss, &stream_recv_plot);
    draw_congestion_plot(params, &common_axis, ss, ds, &congestion_plot);
    draw_rtt_plot(params, &common_axis, ss, &rtt_plot);
}

#[cfg(target_arch = "wasm32")]
pub fn plot_main_plot<'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordu64>>
{
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, params.chart_margin);

    let stream_y_max = if let Some(y_max) = params.clamp.stream_y_max {
        y_max
    } else {
        ss.y_max_stream_send_plot.max(ss.y_max_stream_recv_plot)
    };

    let stream_axis = XYMinMax::init(params, ss, stream_y_max);

    draw_main_plot(filename, params, stream_axis, ss, &root)
}
