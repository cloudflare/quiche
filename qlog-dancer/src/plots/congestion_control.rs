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
use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::*;

use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

use super::minmax::XYMinMax;

pub fn draw_congestion_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax<u64>, ss: &SeriesStore,
    ds: &Datastore, plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder
            .caption("Congestion", chart_subtitle_style(&params.colors.caption));
    }

    let extended_y =
        axis.y_range.start..axis.y_range.end + (axis.y_range.end / 10) * 5;

    let mut plot = builder
        .build_cartesian_2d(axis.x.range(), extended_y.clone())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        params.display_minor_lines,
        &mut plot,
    );

    draw_cc_updates(
        &ds.congestion_state_updates,
        axis.y_range.clone(),
        extended_y,
        &mut plot,
    );
    draw_bytes_in_flight(&ss.local_bytes_in_flight, &mut plot);
    draw_cwnd(&ss.local_cwnd, &mut plot);
    draw_ssthresh(&ss.local_ssthresh, &mut plot);

    if params.display_legend {
        plot.configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()
            .unwrap();
    }

    plot
}

#[cfg(target_arch = "wasm32")]
pub fn plot_cc_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordu64>>
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

    draw_congestion_plot(params, &axis, ss, ds, &root)
}

fn draw_cc_updates<DB: DrawingBackend>(
    data: &[(f32, u64, String)], y_range: std::ops::Range<u64>,
    y_range_extended: std::ops::Range<u64>,
    congestion_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    let my_label = |x: f32, y: u64, name: &str| {
        let color = cc_state_to_color(name);
        let text_width = name.len() as i32 * 6; // Rough estimate
        let text_height = 12;

        return EmptyElement::at((x, y))
            //+ Circle::new((0, 0), 1, ShapeStyle::from(color).filled())
            + Rectangle::new([(1, -2), (1 + text_width, text_height)],
                        WHITE.mix(0.7).filled()) // 0.7 alpha for transparency
            + Text::new(
                name.to_owned(),
                (1, 0),
                ("sans-serif", 12.0).into_font().color(&color),
            );
    };

    let mut woggle = vec![0];

    for i in 1..5 {
        woggle.push((y_range.end / 10) * i);
    }

    // Add labels from right to left, to ensure the z-ordering doesn't add lines
    // over the labels
    let iter = data.iter().rev();
    for cc_state in iter {
        let color = cc_state_to_color(&cc_state.2);
        let x = cc_state.0;

        let line_coords =
            [(x, y_range_extended.start), (x, y_range_extended.end)];

        congestion_chart
            .draw_series(LineSeries::new(line_coords, color))
            .unwrap();

        let area = congestion_chart.plotting_area();

        // control the vertical position of the text label to avoid overlaps.
        let y = y_range.end + woggle[0];
        area.draw(&my_label(x, y, &cc_state.2)).unwrap();

        woggle.rotate_left(1);
    }
}

fn draw_bytes_in_flight<DB: DrawingBackend>(
    data: &[(f32, u64)],
    congestion_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(data, Some("bytes in flight"), TAUPE, congestion_chart);
}

fn draw_cwnd<DB: DrawingBackend>(
    data: &[(f32, u64)],
    congestion_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(data, Some("cwnd"), PURPLE_500, congestion_chart);
}

fn draw_ssthresh<DB: DrawingBackend>(
    data: &[(f32, u64)],
    congestion_chart: &mut ChartContext<
        DB,
        Cartesian2d<RangedCoordf32, RangedCoordu64>,
    >,
) {
    draw_line(data, Some("ssthresh"), ORANGE, congestion_chart);
}

// Colors from ColorCycle list
fn cc_state_to_color(cc_state: &str) -> RGBColor {
    match cc_state {
        // Cubic and Reno
        "slow_start" => RGBColor(204, 81, 81),
        "recovery" => RGBColor(127, 51, 51),
        "congestion_avoidance" => RGBColor(81, 204, 204),

        // BBR
        "bbr_startup" => RGBColor(204, 81, 81),
        "bbr_drain" => RGBColor(127, 51, 51),
        "bbr_probe_bw" => RGBColor(81, 204, 204),
        "bbr_probe_rtt" => RGBColor(51, 127, 127),

        _ => BLACK,
    }
}
