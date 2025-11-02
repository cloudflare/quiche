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

//! Pending charts
//! A single image file containing a view of pending vs. in-flight requests

use plotters::prelude::*;

use crate::datastore::{
    self,
};

use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

#[derive(Debug, Default)]
pub struct PendingPlotParams {
    pub clamp: ClampParams,
    pub chart_size: ChartSize,
    pub colors: PlotColors,
    pub display_chart_title: bool,
}

struct PendingStack {
    pub time: f32,
    pub pending: i32,
    pub in_flight: i32,
}

pub fn plot_pending(
    params: &PendingPlotParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) {
    // TODO: put some stuff in series store
    let x_max = match ds.vantage_point {
        datastore::VantagePoint::Client => ss.received_x_max,
        datastore::VantagePoint::Server => ss.sent_x_max,
    };

    let mut y_max = 0;

    let chart_config = ChartConfig {
        title: "pending".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone(),
    };

    chart_config.init_chart_dir();

    let mut x = 0f32;
    let step_size = 1f32;

    let mut series = vec![];

    while x < x_max {
        let mut pending = 0;
        let mut in_flight = 0;

        for req in ds.http_requests.values() {
            match (
                req.time_discovery,
                req.time_first_headers_tx,
                req.time_fin_rx,
            ) {
                (Some(dt), Some(hdrs_tx), Some(fin)) => {
                    if x >= dt && x < hdrs_tx && x < fin {
                        pending += 1;
                    } else if x >= hdrs_tx && x < fin {
                        in_flight += 1;
                    }
                },

                (Some(dt), None, None) =>
                    if x >= dt {
                        pending += 1;
                    },

                (Some(dt), Some(hdrs_tx), None) =>
                    if x >= dt {
                        pending += 1;
                    } else if x >= hdrs_tx {
                        in_flight += 1;
                    },

                _ => (),
            }
        }
        series.push(PendingStack {
            time: x,
            pending,
            in_flight,
        });
        x += step_size;

        y_max = y_max.max(pending + in_flight);
    }

    // let size = ChartSize{ width: 1600, height: 600};

    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let root = make_chart_bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        ChartMargin::default(),
    );

    #[cfg(target_arch = "wasm32")]
    let canvas_id: String = chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, ChartMargin::default());

    let mut builder = ChartBuilder::on(&root);
    builder
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40);

    if params.display_chart_title {
        let caption =
            format!("{} Pending vs. In-flight requests (stacked)", filename);
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut ctx = builder.build_cartesian_2d(0f32..x_max, 0..y_max).unwrap();

    ctx.configure_mesh()
        .axis_style(params.colors.axis)
        .bold_line_style(params.colors.bold_line.mix(0.5))
        .light_line_style(params.colors.light_line.mix(0.2))
        .label_style(chart_label_style(&params.colors.caption))
        .draw()
        .unwrap();

    ctx.draw_series(series.iter().map(|stack| {
        // make sure bars are narrow enough that they don't bleed over each
        // step. If we don't we'll miss periods where there's no requests in
        // flight.
        let shrink = step_size / 4f32;
        let x0 = stack.time + shrink;
        let x1 = x0 + (step_size - shrink);

        // Clippy wants to remove the variable assignment that helps understand
        // WTF this stuff is doing, screw clippy.
        #[allow(clippy::let_and_return)]
        let in_flight_bar = Rectangle::new(
            [(x0, 0), (x1, stack.in_flight)],
            colors::FOREST_GREEN.filled(),
        );
        in_flight_bar
    }))
    .unwrap()
    .label("In-flight requests")
    .legend(|(x, y)| {
        PathElement::new(vec![(x, y), (x + 20, y)], colors::FOREST_GREEN)
    });

    ctx.draw_series(series.iter().map(|stack| {
        // make sure bars are narrow enough that they don't bleed over each
        // step. If we don't we'll miss periods where there's no requests in
        // flight.
        let shrink = step_size / 3f32;
        let x0 = stack.time + shrink;
        let x1 = x0 + (step_size - shrink);

        // pending is stack on top of in-flight
        // Clippy wants to remove the variable assignment that helps understand
        // WTF this stuff is doing, screw clippy.
        #[allow(clippy::let_and_return)]
        let pending_bar = Rectangle::new(
            [(x0, stack.in_flight), (x1, stack.in_flight + stack.pending)],
            colors::ORANGE.filled(),
        );
        pending_bar
    }))
    .unwrap()
    .label("Pending requests")
    .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], colors::ORANGE));

    ctx.configure_series_labels()
        .label_font(chart_label_style(&params.colors.caption))
        .background_style(params.colors.fill.mix(0.8))
        .border_style(params.colors.axis)
        .position(SeriesLabelPosition::UpperRight)
        .draw()
        .unwrap();
}
