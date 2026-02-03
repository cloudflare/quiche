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

use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::*;

use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

use super::minmax::XYMinMax;

#[cfg(not(target_arch = "wasm32"))]
use crate::plots::make_chart_bitmap_area;

pub fn draw_pacing_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax<u64>, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Pacing Rate vs Delivery Rate",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let y_max = ss
        .max_pacing_rate
        .max(ss.max_delivery_rate)
        .max(ss.max_send_rate)
        .max(ss.max_ack_rate);

    let extended_y = axis.y_range.start..y_max + (y_max / 10);

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), extended_y)
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Rate (bytes/sec)",
        false,
        &mut chart,
    );

    draw_line(&ss.local_pacing_rate, Some("pacing rate"), PURPLE, &mut chart);
    draw_line(&ss.local_delivery_rate, Some("delivery rate"), TEAL, &mut chart);
    draw_line(&ss.local_send_rate, Some("send rate"), ORANGE, &mut chart);
    draw_line(&ss.local_ack_rate, Some("ack rate"), BLUE, &mut chart);

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


fn make_pacing_axis(params: &PlotParameters, ss: &SeriesStore) -> XYMinMax<u64> {
    let y_max = ss
        .max_pacing_rate
        .max(ss.max_delivery_rate)
        .max(ss.max_send_rate)
        .max(ss.max_ack_rate);

    let rates_y_max = if y_max > 0 { y_max + y_max / 10 } else { 1 };

    XYMinMax::init(
        ss.sent_x_min..ss.sent_x_max,
        params.clamp.start,
        params.clamp.end,
        0..rates_y_max,
    )
}

#[cfg(not(target_arch = "wasm32"))]
pub fn plot_pacing(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) {
    let chart_config = make_chart_config("pacing", params, filename, ds, ty);

    chart_config.init_chart_dir();

    let chart_path = chart_config.chart_filepath();

    let root = make_chart_bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    );

    let axis = make_pacing_axis(params, ss);
    draw_pacing_plot(params, &axis, ss, &root);
}

#[cfg(target_arch = "wasm32")]
pub fn plot_pacing_canvas<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordu64>>
{
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, params.chart_margin);

    let axis = make_pacing_axis(params, ss);
    draw_pacing_plot(params, &axis, ss, &root)
}
