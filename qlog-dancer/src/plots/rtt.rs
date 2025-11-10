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

use minmax::XYMinMax;
use plotters::coord::types::RangedCoordf32;

use plotters::coord::Shift;
use plotters::prelude::*;

use crate::plots::colors::*;
use crate::plots::*;

use crate::seriesstore::SeriesStore;

fn draw_rtt_series<DB: DrawingBackend>(
    data: &[(f32, f32)], label: &str, colour: RGBColor,
    rtt_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
) {
    rtt_chart
        .draw_series(LineSeries::new(data.to_vec(), colour))
        .unwrap()
        .label(label)
        .legend(move |(x, y)| {
            PathElement::new(vec![(x, y), (x + 20, y)], colour)
        });
}

fn draw_min_rtt<DB: DrawingBackend>(
    data: &[(f32, f32)],
    rtt_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
) {
    draw_rtt_series(data, "Min RTT", SOFT_PINK, rtt_chart);
}

fn draw_latest_rtt<DB: DrawingBackend>(
    data: &[(f32, f32)],
    rtt_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
) {
    draw_rtt_series(data, "Latest RTT", ORANGE, rtt_chart);
}

fn draw_smoothed_rtt<DB: DrawingBackend>(
    data: &[(f32, f32)],
    rtt_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
) {
    draw_rtt_series(data, "Smoothed RTT", BROWN, rtt_chart);
}

pub fn draw_rtt_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax<u64>, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordf32>> {
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption("RTT", chart_subtitle_style(&params.colors.caption));
    }
    let mut chart = builder
        .build_cartesian_2d(
            axis.x.range(),
            0.0..(ss.y_max_rtt_plot + ss.y_max_rtt_plot / 10.0),
        )
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "RTT (ms)",
        false,
        &mut chart,
    );

    draw_min_rtt(&ss.local_min_rtt, &mut chart);
    draw_latest_rtt(&ss.local_latest_rtt, &mut chart);
    draw_smoothed_rtt(&ss.local_smoothed_rtt, &mut chart);

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

#[cfg(target_arch = "wasm32")]
pub fn plot_rtt_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordf32>>
{
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, params.chart_margin);

    let cwnd_y_max = if let Some(y_max) = params.cwnd_y_max {
        y_max
    } else {
        // add a bit of margin
        ss.y_max_congestion_plot + ss.y_max_congestion_plot / 10
    };

    // TODO set minimum
    let axis = super::minmax::XYMinMax::init(
        ss.sent_x_min..ss.sent_x_max,
        params.clamp.start,
        params.clamp.end,
        0..cwnd_y_max,
    );

    draw_rtt_plot(params, &axis, ss, &root)
}
