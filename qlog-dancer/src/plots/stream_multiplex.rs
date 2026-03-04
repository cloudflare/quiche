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

//! Multiplexing charts
//! A single image file containing various renderings of stream and H3 DATA

use log::warn;
use plotters::prelude::*;

use crate::datastore::VantagePoint;
use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

pub struct MultiplexPlotsParams {
    pub clamp: ClampParams,
    pub bidi_only: bool,
    pub width: u32,
    pub y_spacer: u32,
    pub right_shrink_margin: u32,
    pub combined_plot_height: u32,
    pub frame_swimlane_height: u32,
    pub bubbles_swimlane_height: u32,
    pub colors: PlotColors,
    pub area_margin: AreaMargin,
}

impl Default for MultiplexPlotsParams {
    fn default() -> Self {
        Self {
            bidi_only: true,
            width: 4000,
            y_spacer: 20,
            right_shrink_margin: 50,
            combined_plot_height: 300,
            frame_swimlane_height: 60,
            bubbles_swimlane_height: 100,
            clamp: Default::default(),
            colors: Default::default(),
            area_margin: AreaMargin { x: 40, y: 0 },
        }
    }
}

pub fn plot_stream_multiplexing(
    params: &MultiplexPlotsParams, filename: &str, ss: &SeriesStore,
    ds: &Datastore, ty: &ChartOutputType,
) {
    let (mut x_min, mut x_max) = match ds.vantage_point {
        VantagePoint::Client => (ss.received_x_min, ss.received_x_max),
        VantagePoint::Server => (ss.sent_x_min, ss.sent_x_max),
    };

    // Clamp plot x-axis if the user told us.
    if let Some(s) = params.clamp.start {
        x_min = s;
    }

    if let Some(e) = params.clamp.end {
        x_max = x_max.min(e);
    }

    let http_requests = match ds.vantage_point {
        VantagePoint::Client => &ds.http_requests,
        VantagePoint::Server => &ds.http_requests,
    };

    let y_spacer = 50;

    let data_frames_all_combined_x = params.width - params.right_shrink_margin;
    let data_frames_all_combined_y: i32 = params.combined_plot_height as i32;

    let data_frames_mini_offset_y = data_frames_all_combined_y + y_spacer;
    let data_frames_mini_x = params.width - params.right_shrink_margin;
    let data_frames_mini_y = params.frame_swimlane_height;

    let bubbles_x = params.width - params.right_shrink_margin;
    let bubbles_y = params.bubbles_swimlane_height;
    let bubbles_offset_y =
        data_frames_mini_offset_y + (http_requests.len() * 25) as i32;

    let stream_frames_all_combined_x = params.width - params.right_shrink_margin;
    let stream_frames_all_combined_y = params.combined_plot_height;
    let stream_frames_all_combined_offset_y =
        bubbles_offset_y + (http_requests.len() * 70) as i32;

    let stream_frames_mini_offset_y = stream_frames_all_combined_offset_y +
        stream_frames_all_combined_y as i32 +
        y_spacer;
    let stream_frames_mini_x = params.width - params.right_shrink_margin;
    let stream_frames_mini_y = params.frame_swimlane_height;

    #[cfg(not(target_arch = "wasm32"))]
    let full_y =
        stream_frames_mini_offset_y as u32 + (http_requests.len() * 25) as u32;

    let chart_config = ChartConfig {
        title: "stream-multiplexing".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone(),
    };

    chart_config.init_chart_dir();

    let margin = ChartMargin {
        top: 20,
        bottom: 20,
        left: 20,
        right: 20,
    };

    #[cfg(not(target_arch = "wasm32"))]
    let size = ChartSize {
        width: params.width,
        height: full_y,
    };

    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let root = make_chart_bitmap_area(&chart_path, size, params.colors, margin);

    #[cfg(target_arch = "wasm32")]
    let canvas_id: String = chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let root = make_chart_canvas_area(&canvas_id, params.colors, margin);

    let stream_frame_series = match ds.vantage_point {
        VantagePoint::Client => &ss.received_stream_frames_series,
        VantagePoint::Server => &ss.sent_stream_frames_series,
    };

    //// Plot the data frames first
    let mut color_cyle = ColorCycle::default();

    color_cyle.reset();

    let data_frames_all_combined_temp_root = root.clone().shrink(
        (0, 0),
        (data_frames_all_combined_x, data_frames_all_combined_y),
    );

    let mut data_frames_all_combined_chart =
        ChartBuilder::on(&data_frames_all_combined_temp_root)
            .caption(
                "DATA frame events",
                chart_title_style(&params.colors.caption),
            )
            .x_label_area_size(params.area_margin.x)
            .y_label_area_size(params.area_margin.y)
            .build_cartesian_2d(x_min..x_max, 0..2)
            .unwrap();

    data_frames_all_combined_chart
        .configure_mesh()
        .disable_mesh()
        .axis_style(params.colors.axis)
        .label_style(chart_label_style(&params.colors.caption))
        .draw()
        .unwrap();

    for (id, stub) in http_requests {
        if params.bidi_only && (id & 0x2) != 0 {
            continue;
        }

        let data_frames = match ds.vantage_point {
            VantagePoint::Client => &stub.time_data_rx_set,
            VantagePoint::Server => &stub.time_data_tx_set,
        };

        let style = color_cyle.next_color();

        let lines = data_frames
            .iter()
            .map(|point| PathElement::new([(point.0, 2), (point.0, 0)], style));

        data_frames_all_combined_chart
            .draw_series(lines.clone())
            .unwrap();
    }

    //// Now plot the stream frames combined
    color_cyle.reset();

    let data_frames_all_combined_temp_root = root.clone().shrink(
        (0, stream_frames_all_combined_offset_y),
        (stream_frames_all_combined_x, stream_frames_all_combined_y),
    );

    let mut stream_frames_all_combined_chart =
        ChartBuilder::on(&data_frames_all_combined_temp_root)
            .caption(
                "STREAM frame events",
                chart_title_style(&params.colors.caption),
            )
            .x_label_area_size(params.area_margin.x)
            .y_label_area_size(params.area_margin.y)
            .build_cartesian_2d(x_min..x_max, 0..1)
            .unwrap();

    stream_frames_all_combined_chart
        .configure_mesh()
        .disable_mesh()
        .axis_style(params.colors.axis)
        .label_style(chart_label_style(&params.colors.caption))
        .draw()
        .unwrap();

    for (id, stream_frames) in stream_frame_series {
        if params.bidi_only && (id & 0x2) != 0 {
            continue;
        }

        let style = color_cyle.next_color();

        let lines = stream_frames
            .iter()
            .map(|point| PathElement::new([(point.0, 2), (point.0, 0)], style));

        stream_frames_all_combined_chart.draw_series(lines).unwrap();
    }

    //// now the mini charts
    color_cyle.reset();

    let mut upper_y = 0;
    let mut bubbles_upper_y = 0;
    let mini_chart_axis_y_range = 0..4;
    let marker_y = 2;
    let marker_size = 5;

    let max_data_len = match ds.vantage_point {
        VantagePoint::Client => ds.largest_data_frame_rx_length_global,
        VantagePoint::Server => ds.largest_data_frame_tx_length_global,
    };

    if max_data_len == 0 {
        warn!("max_data_len = 0, skipping remaining charts");
        return;
    }

    for (id, stub) in http_requests {
        if params.bidi_only && (id & 0x2) != 0 {
            continue;
        }

        let data_frames = match ds.vantage_point {
            VantagePoint::Client => &stub.time_data_rx_set,
            VantagePoint::Server => &stub.time_data_tx_set,
        };

        let headers_init = match ds.vantage_point {
            VantagePoint::Client => stub.time_first_headers_tx,
            VantagePoint::Server => stub.time_first_headers_rx,
        };

        let headers_actioned = match ds.vantage_point {
            VantagePoint::Client => stub.time_first_headers_rx,
            VantagePoint::Server => stub.time_first_headers_tx,
        };

        let data_frames_temp_root = root.clone().shrink(
            (0, upper_y + data_frames_mini_offset_y),
            (data_frames_mini_x, data_frames_mini_y),
        );

        let stream_frames_temp_root = root.clone().shrink(
            (0, upper_y + stream_frames_mini_offset_y),
            (stream_frames_mini_x, stream_frames_mini_y),
        );

        upper_y += 20;

        let mut data_frames_mini_independent_chart =
            ChartBuilder::on(&data_frames_temp_root)
                .x_label_area_size(params.area_margin.x)
                .y_label_area_size(params.area_margin.y)
                .build_cartesian_2d(x_min..x_max, mini_chart_axis_y_range.clone())
                .unwrap();

        data_frames_mini_independent_chart
            .configure_mesh()
            .disable_y_mesh()
            .disable_y_axis()
            .axis_style(params.colors.axis)
            .draw()
            .unwrap();

        // let's jump ahead here and plot the mini chart header events, to avoid
        // having to loop again later
        let mut stream_frames_mini_independent_chart =
            ChartBuilder::on(&stream_frames_temp_root)
                .x_label_area_size(params.area_margin.x)
                .y_label_area_size(params.area_margin.y)
                .build_cartesian_2d(x_min..x_max, mini_chart_axis_y_range.clone())
                .unwrap();

        stream_frames_mini_independent_chart
            .configure_mesh()
            .disable_y_mesh()
            .disable_y_axis()
            .axis_style(params.colors.axis)
            .draw()
            .unwrap();

        let style = color_cyle.next_color();

        if let Some(h) = headers_init {
            data_frames_mini_independent_chart
                .draw_series([TriangleMarker::new(
                    (h, marker_y),
                    marker_size,
                    style,
                )])
                .unwrap();

            stream_frames_mini_independent_chart
                .draw_series([TriangleMarker::new(
                    (h, marker_y),
                    marker_size,
                    style,
                )])
                .unwrap();
        }

        if let Some(h) = headers_actioned {
            data_frames_mini_independent_chart
                .draw_series([TriangleMarker::new(
                    (h, marker_y),
                    marker_size,
                    style,
                )])
                .unwrap();

            stream_frames_mini_independent_chart
                .draw_series([TriangleMarker::new(
                    (h, marker_y),
                    marker_size,
                    style,
                )])
                .unwrap();
        }

        let lines = data_frames
            .iter()
            .map(|point| PathElement::new([(point.0, 2), (point.0, 0)], style));

        data_frames_mini_independent_chart
            .draw_series(lines.clone())
            .unwrap();

        if let Some(stream_frames) = stream_frame_series.get(id) {
            let lines = stream_frames.iter().map(|point| {
                PathElement::new([(point.0, 2), (point.0, 0)], style)
            });

            stream_frames_mini_independent_chart
                .draw_series(lines.clone())
                .unwrap();
        }

        let bubbles_temp_root = root.clone().shrink(
            (0, bubbles_upper_y + bubbles_offset_y),
            (bubbles_x, bubbles_y),
        );

        bubbles_upper_y += 70;

        let mut bubbles_mini_chart = ChartBuilder::on(&bubbles_temp_root)
            .x_label_area_size(params.area_margin.x)
            .y_label_area_size(params.area_margin.y)
            .build_cartesian_2d(
                x_min..x_max,
                0..max_data_len, /*0..30*/ /*mini_chart_axis_y_range.clone()*/
            )
            .unwrap();

        bubbles_mini_chart
            .configure_mesh()
            .disable_y_mesh()
            .disable_y_axis()
            .axis_style(params.colors.axis)
            .draw()
            .unwrap();

        // Integer conversion will floor, so when hardly any DATA is transferred
        // avoid 0, which would cause a divide-by-0 later.
        let bucket_size = if max_data_len >= 5 {
            max_data_len / 5
        } else {
            1
        };

        let mut bubbles: Vec<Circle<(f64, i32), i32>> = vec![];
        let mut lines: Vec<PathElement<(f64, i32)>> = vec![];
        let mut lines2: Vec<PathElement<(f64, u64)>> = vec![];

        let bubble_sizes = [1, 6, 11, 16, 21, 26, 31];

        for (time, length) in data_frames {
            // TODO: replace with div_ceil once stablized- https://github.com/rust-lang/rust/issues/88581
            let i: usize = (length / bucket_size) as usize +
                usize::from(length % bucket_size != 0);
            let i = i.saturating_sub(1);

            // TODO: there seems to be a bug if the bubble is greater th x_max it
            // would still apear. So let's just avoid that.
            if time > &x_max {
                continue;
            }

            lines.push(PathElement::new(
                [(*time, 2), (*time, 2 + bubble_sizes[i])],
                style,
            ));

            lines2.push(PathElement::new([(*time, 0), (*time, *length)], style));

            bubbles.push(Circle::new((*time, 2), bubble_sizes[i], style));
        }

        // bubbles_mini_chart.draw_series(bubbles).unwrap();
        bubbles_mini_chart.draw_series(lines2).unwrap();
    }
}
