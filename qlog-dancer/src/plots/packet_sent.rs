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

use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::*;

use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

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

const Y_WIGGLE: f32 = 1.1;

pub fn draw_packet_sent_received_plot<'a, DB: DrawingBackend + 'a>(
    is_sent: bool, filename: &str, params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let (caption, y_max) = if is_sent {
        let y_max = (ss.y_max_onertt_pkt_sent_plot as f32 * Y_WIGGLE) as u64;

        (format!("{} Packet Sent timeline", filename), y_max)
    } else {
        let y_max = (ss.y_max_onertt_pkt_received_plot as f32 * Y_WIGGLE) as u64;

        (format!("{} Packet Received timeline", filename), y_max)
    };

    let axis = XYMinMax::init(params, ss, y_max);

    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Packet Number",
        params.display_minor_lines,
        &mut chart,
    );

    if is_sent {
        chart
            .draw_series(LineSeries::new(ss.onertt_packet_created.clone(), GREEN))
            .unwrap()
            .label("packet created")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], GREEN));

        chart
            .draw_series(LineSeries::new(ss.onertt_packet_sent.clone(), ORANGE))
            .unwrap()
            .label("packet sent (packet number)")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], ORANGE));

        let packet_losses = ss
            .onertt_packet_lost_hacky
            .iter()
            .map(|point| Cross::new(*point, 2, PURPLE));

        chart
            .draw_series(packet_losses)
            .unwrap()
            .label("packet lost (packet number)")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], PURPLE));
    } else {
        let missing_packets_line = ss
            .netlog_missing_packets
            .iter()
            .map(|t| PathElement::new([(*t, 0), (*t, y_max)], BLUE));

        chart
            .draw_series(missing_packets_line)
            .unwrap()
            .label("missing packets")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

        chart
            .draw_series(LineSeries::new(
                ss.onertt_packet_received.clone(),
                ORANGE,
            ))
            .unwrap()
            .label("packet received")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], ORANGE));
    }

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

pub fn draw_packet_sent_lost_delivered_count_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let caption = "Packet sent/lost/delivered counts";

    let y_max = (ss.y_max_onertt_pkt_sent_plot as f32 * Y_WIGGLE) as u64;

    let axis = XYMinMax::init(params, ss, y_max);

    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(caption, chart_subtitle_style(&params.colors.caption));
    }

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Packet Count",
        params.display_minor_lines,
        &mut chart,
    );

    chart
        .draw_series(LineSeries::new(
            ss.onertt_packet_sent_aggregate_count.clone(),
            TAUPE,
        ))
        .unwrap()
        .label("packet sent count")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], TAUPE));

    chart
        .draw_series(LineSeries::new(
            ss.onertt_packet_delivered_aggregate_count.clone(),
            BLUE,
        ))
        .unwrap()
        .label("packet delivered count")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .draw_series(LineSeries::new(
            ss.onertt_packet_lost_aggregate_count.clone(),
            SOFT_PINK,
        ))
        .unwrap()
        .label("packet lost count")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], SOFT_PINK));

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

fn draw_delta_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordu64, RangedCoordf32>> {
    let y_range = ss.y_min_onertt_packet_created_sent_delta..
        (ss.y_max_onertt_packet_created_sent_delta * Y_WIGGLE);

    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Packet created/sent Delta timing",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder
        .build_cartesian_2d(0..ss.y_max_onertt_pkt_sent_plot, y_range)
        .unwrap();

    draw_mesh(
        &params.colors,
        "Packet Number",
        "Delta time (ms)",
        params.display_minor_lines,
        &mut chart,
    );

    // Draw the series

    // not sure best way to render these, lines or points?
    let lines =
        LineSeries::new(ss.onertt_packet_created_sent_delta.clone(), BLUE);

    let _crosses = ss
        .onertt_packet_created_sent_delta
        .iter()
        .map(|point| Cross::new(*point, 2, BLUE));

    chart
        .draw_series(lines)
        .unwrap()
        .label("packet created/sent delta")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLACK));

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::MiddleMiddle)
            .draw()
            .unwrap();
    }

    chart
}

fn draw_pacing_rate_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> ChartContext<'a, DB, Cartesian2d<RangedCoordf32, RangedCoordu64>> {
    let y_max = (ss.max_pacing_rate as f32 * Y_WIGGLE) as u64;
    let axis = XYMinMax::init(params, ss, y_max);
    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder
            .caption("Pacing rate", chart_subtitle_style(&params.colors.caption));
    }

    let mut chart = builder
        .build_cartesian_2d(axis.x.range(), axis.y_range())
        .unwrap();

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Pacing Rate",
        params.display_minor_lines,
        &mut chart,
    );

    // Draw the series
    chart
        .draw_series(LineSeries::new(ds.local_pacing_rate.clone(), RED))
        .unwrap()
        .label("pacing rate")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], RED));

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

pub fn plot_packet_sent(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) {
    let chart_config = make_chart_config("packet-sent", params, filename, ds, ty);

    chart_config.init_chart_dir();

    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let root = make_chart_bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    );

    #[cfg(target_arch = "wasm32")]
    let canvas_id: String = chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, params.chart_margin);
    let (raw_timings, remainder) = root.split_vertically((33).percent());
    let (counts, remainder) = remainder.split_vertically((33).percent());

    let (delta_timings, pacing_rate) = remainder.split_vertically((50).percent());

    draw_packet_sent_received_plot(true, filename, params, ss, &raw_timings);
    draw_packet_sent_lost_delivered_count_plot(params, ss, &counts);
    draw_delta_plot(params, ss, &delta_timings);
    draw_pacing_rate_plot(params, ss, ds, &pacing_rate);
}

#[cfg(target_arch = "wasm32")]
pub fn plot_packet_sent_plot_canvas<'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordu64>>
{
    let root =
        make_chart_canvas_area(canvas_id, params.colors, params.chart_margin);

    draw_packet_sent_received_plot(true, filename, params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
pub fn plot_packet_sent_lost_delivered_count_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordu64>>
{
    let root =
        make_chart_canvas_area(canvas_id, params.colors, params.chart_margin);

    draw_packet_sent_lost_delivered_count_plot(params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
pub fn plot_packet_sent_delta_plot_canvas<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordu64, RangedCoordf32>>
{
    let root =
        make_chart_canvas_area(canvas_id, params.colors, params.chart_margin);

    draw_delta_plot(params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
pub fn plot_packet_sent_pacing_rate_plot_canvas<'a>(
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore, canvas_id: &str,
) -> ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf32, RangedCoordu64>>
{
    let root =
        make_chart_canvas_area(canvas_id, params.colors, params.chart_margin);

    draw_pacing_rate_plot(params, ss, ds, &root)
}
