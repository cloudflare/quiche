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

use minmax::XMinMax;
use plotters::chart::ChartContext;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::prelude::Cartesian2d;
use plotters::prelude::*;

use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

const Y_WIGGLE: f64 = 1.2;

struct XYMinMax {
    pub x: XMinMax,
    pub y_min: u64,
    pub y_max: u64,
}

impl XYMinMax {
    fn init(params: &PlotParameters, ss: &SeriesStore, ds: &Datastore) -> Self {
        let x = XMinMax::new(
            ss.received_x_min,
            ss.received_x_max,
            params.clamp.start,
            params.clamp.end,
        );

        Self {
            x,
            y_min: 0,
            y_max: Self::y_max(ss, &ds.application_proto),
        }
    }

    fn y_range(&self) -> std::ops::Range<u64> {
        self.y_min..self.y_max
    }

    fn y_max(ss: &SeriesStore, proto: &ApplicationProto) -> u64 {
        let y = match proto {
            ApplicationProto::Http2 =>
                *(ss.h2_send_window_absolute_max.get(&0).unwrap_or(&0)),
            ApplicationProto::Http3 =>
                ss.netlog_quic_stream_received_connection_cumulative
                    .last()
                    .unwrap_or(&(0.0, 0))
                    .1,
        };

        (y as f64 * Y_WIGGLE) as u64
    }
}

fn blocked_lines<DB: DrawingBackend>(
    ds: &Datastore, y_max: u64,
    chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) {
    if let Some(blocked) = ds.netlog_quic_server_window_blocked.get(&-1).cloned()
    {
        let blocked_lines = blocked
            .iter()
            .map(|t| PathElement::new([(*t, 0), (*t, y_max)], GREEN));

        chart
            .draw_series(blocked_lines)
            .unwrap()
            .label("server conn blocked")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], GREEN));
    }
}

fn received_data<DB: DrawingBackend>(
    ss: &SeriesStore, proto: &ApplicationProto,
    chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) {
    let points = match proto {
        ApplicationProto::Http2 =>
            ss.netlog_h2_stream_received_connection_cumulative.clone(),
        ApplicationProto::Http3 =>
            ss.netlog_quic_stream_received_connection_cumulative.clone(),
    };

    chart
        .draw_series(LineSeries::new(points, ORANGE))
        .unwrap()
        .label("cumulative received stream data")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], ORANGE));
}

fn window_updates<DB: DrawingBackend>(
    ss: &SeriesStore, ds: &Datastore,
    chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) {
    let points = match ds.application_proto {
        ApplicationProto::Http2 => {
            if let Some(conn_win_updates) =
                ss.h2_send_window_series_absolute.get(&0).cloned()
            {
                conn_win_updates
            } else {
                return;
            }
        },

        ApplicationProto::Http3 => {
            if let Some(conn_win_updates) =
                ss.netlog_quic_client_side_window_updates.get(&-1).cloned()
            {
                conn_win_updates
            } else {
                return;
            }
        },
    };

    // Help us see the exact time a window update happened.
    let circles: Vec<Circle<(f64, u64), i32>> = points
        .iter()
        .map(|point| Circle::new(*point, 2, BLUE))
        .collect();

    chart
        .draw_series(LineSeries::new(points, BLUE))
        .unwrap()
        .label("sent window updates")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart.draw_series(circles).unwrap();
}

fn draw_series<'a, DB: DrawingBackend + 'a>(
    chart: &mut ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore, axis: XYMinMax,
) {
    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Bytes",
        params.display_minor_lines,
        chart,
    );

    // Draw the series
    blocked_lines(ds, axis.y_max, chart);
    received_data(ss, &ds.application_proto, chart);
    window_updates(ss, ds, chart);

    if params.display_legend {
        // Draw the series legend
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::LowerRight)
            .draw()
            .unwrap();
    }
}

#[cfg(target_arch = "wasm32")]
pub fn plot_conn_flow_control_canvas<'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>
{
    let chart_config =
        make_chart_config("flow_control", params, filename, ds, ty);

    let canvas_id: String = chart_config.canvas_id().unwrap_or_default();
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, params.chart_margin);

    let axis = XYMinMax::init(params, ss, ds);

    let mut builder = ChartBuilder::on(&root);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        let caption = format!("{} Connection Flow Control timeline", filename);
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut fc_chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_series(&mut fc_chart, params, ss, ds, axis);

    fc_chart
}

#[cfg(not(target_arch = "wasm32"))]
pub fn plot_conn_flow_control(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) {
    let chart_config =
        make_chart_config("flow_control", params, filename, ds, ty);
    let chart_path = chart_config.chart_filepath();

    let root = make_chart_bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    );

    let axis = XYMinMax::init(params, ss, ds);

    let mut builder = ChartBuilder::on(&root);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        let caption = format!("{} Connection Flow Control timeline", filename);
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut fc_chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Bytes",
        params.display_minor_lines,
        &mut fc_chart,
    );

    draw_series(&mut fc_chart, params, ss, ds, axis);
}
