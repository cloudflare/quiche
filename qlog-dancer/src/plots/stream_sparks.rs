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

//! Spark charts
//! These are a single image file containing a grid of mini plots. Each plot
//! represents a single stream, so it is easier to see how they all compare
//! at a glance.

// TODO: this seems to be required to overcome a transient error in nightly; see
// https://github.com/rust-lang/rust/issues/147648#issuecomment-3482917926
#![allow(unused_assignments)]

use full_palette::PURPLE_500;
use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::prelude::*;

use tabled::Tabled;

use crate::datastore::ApplicationProto;
use crate::datastore::VantagePoint;
use crate::plots::colors::*;
use crate::plots::*;
use crate::request_stub::HttpRequestStub;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

#[allow(unused_assignments)]
pub enum TransmissionType {
    Upload,
    Download,
}

#[derive(Debug)]
pub struct SparkPlotsParams {
    pub clamp: ClampParams,
    pub bidi_only: bool,
    pub label_area_width: u32,
    pub label_area_height: u32,
    pub caption_area_height: u32,
    pub caption_area_width: u32,
    pub spark_offset_x: u32,
    pub spark_offset_y: u32,
    pub spark_dimension_x: u32,
    pub spark_dimension_y: u32,
    pub sparks_per_row: u32,
    pub captions_on_top: bool,
    pub colors: PlotColors,
}

impl Default for SparkPlotsParams {
    fn default() -> Self {
        Self {
            clamp: Default::default(),
            bidi_only: true,
            label_area_width: 20,
            label_area_height: 20,
            caption_area_height: 100,
            caption_area_width: 0,
            spark_offset_x: 50,
            spark_offset_y: 30,
            spark_dimension_x: 150,
            spark_dimension_y: 150,
            sparks_per_row: 10,
            captions_on_top: true,
            colors: Default::default(),
        }
    }
}

#[derive(Tabled)]
enum SparkCaption {
    UniStream {
        summary: String,
    },

    RequestAtServer {
        summary: String,
        method: String,
        path: String,
        client_content_length: String,
        server_content_length: String,
        client_pri_hdr: String,
        server_pri_hdr: String,
        duration_rx_hdr_tx_hdr: String,
        duration_rx_hdr_tx_first_data: String,
        duration_rx_hdr_tx_last_data: String,
        duration_tx_first_data_tx_last_data: String,
    },

    RequestAtClient {
        summary: String,
        method: String,
        path: String,
        client_content_length: String,
        server_content_length: String,
        client_pri_hdr: String,
        client_pri_update: String,
        server_pri_hdr: String,
        duration_tx_hdr_rx_hdr: String,
        duration_tx_hdr_rx_first_data: String,
        duration_tx_hdr_rx_last_data: String,
        duration_tx_first_data_tx_last_data: String,
    },
}

impl SparkCaption {
    fn request_at_client_from_stub(
        application_proto: ApplicationProto, req: &HttpRequestStub,
    ) -> Self {
        let summary = format!(
            "ID= {}, status= {}, proto= {:?}",
            req.stream_id, req.status, application_proto
        );
        let empty = &"".to_string();

        let duration_tx_hdr_rx_hdr =
            match req.at_client_deltas.as_ref().unwrap().tx_hdr_rx_hdr.inner {
                Some(t) => format!("d_tx_hdr_rx_hdr:               {:.2}ms", t),

                None => empty.to_owned(),
            };

        let duration_tx_hdr_rx_first_data = match req
            .at_client_deltas
            .as_ref()
            .unwrap()
            .tx_hdr_rx_first_data
            .inner
        {
            Some(t) => format!("d_tx_hdr_rx_data_first:        {:.2}ms", t),

            None => empty.to_owned(),
        };

        let duration_tx_hdr_rx_last_data = match req
            .at_client_deltas
            .as_ref()
            .unwrap()
            .tx_hdr_rx_last_data
            .inner
        {
            Some(t) => format!("d_tx_hdr_rx_data_last:         {:.2}ms", t),

            None => empty.to_owned(),
        };

        let duration_tx_first_data_tx_last_data = match req
            .at_client_deltas
            .as_ref()
            .unwrap()
            .tx_first_data_tx_last_data
            .inner
        {
            Some(t) => format!("d_tx_data_first_tx_data_last:  {:.2}ms", t),

            None => empty.to_owned(),
        };

        SparkCaption::RequestAtClient {
            summary,
            method: format!("method= {}", req.method),
            path: format!("path= {}", req.path),

            client_content_length: format!(
                "client content length: {}",
                req.client_content_length
            ),
            server_content_length: format!(
                "server content length: {}",
                req.server_content_length
            ),

            client_pri_hdr: format!(
                "client pri hdr:         {}",
                req.client_pri_hdr
            ),

            client_pri_update: format!(
                "client pri updates:     {:?}",
                req.priority_updates
            ),

            server_pri_hdr: format!(
                "server pri hdr:         {}",
                req.server_pri_hdr
            ),

            duration_tx_hdr_rx_hdr,

            duration_tx_hdr_rx_first_data,

            duration_tx_hdr_rx_last_data,

            duration_tx_first_data_tx_last_data,
        }
    }

    fn request_at_server_from_stub(
        stream_id: u64, req: &HttpRequestStub,
    ) -> Self {
        let summary = format!("ID= {}, status= {}", stream_id, req.status);
        let empty = &"".to_string();

        let duration_rx_hdr_tx_hdr =
            match req.at_server_deltas.as_ref().unwrap().rx_hdr_tx_hdr.inner {
                Some(t) => format!("d_rx_hdr_tx_hdr:               {:.2}ms", t),

                None => empty.to_owned(),
            };

        let duration_rx_hdr_tx_first_data = match req
            .at_server_deltas
            .as_ref()
            .unwrap()
            .rx_hdr_tx_first_data
            .inner
        {
            Some(t) => format!("d_rx_hdr_tx_data_first:        {:.2}ms", t),

            None => empty.to_owned(),
        };

        let duration_rx_hdr_tx_last_data = match req
            .at_server_deltas
            .as_ref()
            .unwrap()
            .rx_hdr_tx_last_data
            .inner
        {
            Some(t) => format!("d_rx_hdr_tx_data_last:         {:.2}ms", t),

            None => empty.to_owned(),
        };

        let duration_tx_first_data_tx_last_data = match req
            .at_server_deltas
            .as_ref()
            .unwrap()
            .tx_first_data_tx_last_data
            .inner
        {
            Some(t) => format!("d_tx_data_first_tx_data_last:  {:.2}ms", t),

            None => empty.to_owned(),
        };

        SparkCaption::RequestAtServer {
            summary,
            method: format!("method= {}", req.method),
            path: format!("path= {}", req.path),

            client_content_length: format!(
                "client content length: {}",
                req.client_content_length
            ),
            server_content_length: format!(
                "server content length: {}",
                req.server_content_length
            ),

            client_pri_hdr: format!(
                "client pri hdr:         {}",
                req.client_pri_hdr
            ),

            server_pri_hdr: format!(
                "server pri hdr:         {}",
                req.server_pri_hdr
            ),

            duration_rx_hdr_tx_hdr,

            duration_rx_hdr_tx_first_data,

            duration_rx_hdr_tx_last_data,

            duration_tx_first_data_tx_last_data,
        }
    }

    fn from_data_store(ds: &Datastore, stream_id: u64) -> Option<Self> {
        let is_request = match ds.application_proto {
            ApplicationProto::Http3 => stream_id.is_multiple_of(4),
            ApplicationProto::Http2 => true,
        };

        if is_request {
            if let Some(req) = ds.http_requests.get(&stream_id) {
                match ds.vantage_point {
                    VantagePoint::Client =>
                        Some(SparkCaption::request_at_client_from_stub(
                            ds.application_proto,
                            req,
                        )),
                    VantagePoint::Server => Some(
                        SparkCaption::request_at_server_from_stub(stream_id, req),
                    ),
                }
            } else {
                None
            }
        } else {
            let summary = format!("ID= {}", stream_id);
            Some(SparkCaption::UniStream { summary })
        }
    }

    fn draw<DB: DrawingBackend>(
        &self, color: &RGBColor, root: &DrawingArea<DB, plotters::coord::Shift>,
        x: i32, y: i32,
    ) {
        let style = &("monospace", 12).into_text_style(root).color(color);

        let newline_offset = 10;
        let x = x + 20;

        match self {
            SparkCaption::UniStream { summary } => {
                root.draw_text(summary, style, (x, y)).unwrap();
            },

            SparkCaption::RequestAtServer {
                summary,
                method,
                path,
                client_content_length,
                server_content_length,
                client_pri_hdr,
                server_pri_hdr,
                duration_rx_hdr_tx_hdr,
                duration_rx_hdr_tx_first_data,
                duration_rx_hdr_tx_last_data,
                duration_tx_first_data_tx_last_data,
                ..
            } => {
                root.draw_text(summary, style, (x, y)).unwrap();

                root.draw_text(method, style, (x, y + newline_offset))
                    .unwrap();

                root.draw_text(path, style, (x, y + newline_offset * 2))
                    .unwrap();

                root.draw_text(
                    client_content_length,
                    style,
                    (x, y + newline_offset * 3),
                )
                .unwrap();

                root.draw_text(
                    server_content_length,
                    style,
                    (x, y + newline_offset * 4),
                )
                .unwrap();

                root.draw_text(
                    client_pri_hdr,
                    style,
                    (x, y + newline_offset * 6),
                )
                .unwrap();

                root.draw_text(
                    server_pri_hdr,
                    style,
                    (x, y + newline_offset * 7),
                )
                .unwrap();

                root.draw_text(
                    duration_rx_hdr_tx_hdr,
                    style,
                    (x, y + newline_offset * 8),
                )
                .unwrap();

                root.draw_text(
                    duration_rx_hdr_tx_first_data,
                    style,
                    (x, y + newline_offset * 9),
                )
                .unwrap();

                root.draw_text(
                    duration_rx_hdr_tx_last_data,
                    style,
                    (x, y + newline_offset * 10),
                )
                .unwrap();

                root.draw_text(
                    duration_tx_first_data_tx_last_data,
                    style,
                    (x, y + newline_offset * 11),
                )
                .unwrap();
            },

            SparkCaption::RequestAtClient {
                summary,
                method,
                path,
                client_content_length,
                server_content_length,
                client_pri_hdr,
                client_pri_update,
                server_pri_hdr,
                duration_tx_hdr_rx_hdr,
                duration_tx_hdr_rx_first_data,
                duration_tx_hdr_rx_last_data,
                duration_tx_first_data_tx_last_data,
                ..
            } => {
                root.draw_text(summary, style, (x, y)).unwrap();

                root.draw_text(method, style, (x, y + newline_offset))
                    .unwrap();
                root.draw_text(path, style, (x, y + newline_offset * 2))
                    .unwrap();

                root.draw_text(
                    client_content_length,
                    style,
                    (x, y + newline_offset * 3),
                )
                .unwrap();

                root.draw_text(
                    server_content_length,
                    style,
                    (x, y + newline_offset * 4),
                )
                .unwrap();

                root.draw_text(
                    client_pri_hdr,
                    style,
                    (x, y + newline_offset * 6),
                )
                .unwrap();

                root.draw_text(
                    client_pri_update,
                    style,
                    (x, y + newline_offset * 7),
                )
                .unwrap();

                root.draw_text(
                    server_pri_hdr,
                    style,
                    (x, y + newline_offset * 8),
                )
                .unwrap();

                root.draw_text(
                    duration_tx_hdr_rx_hdr,
                    style,
                    (x, y + newline_offset * 9),
                )
                .unwrap();

                root.draw_text(
                    duration_tx_hdr_rx_first_data,
                    style,
                    (x, y + newline_offset * 10),
                )
                .unwrap();

                root.draw_text(
                    duration_tx_hdr_rx_last_data,
                    style,
                    (x, y + newline_offset * 11),
                )
                .unwrap();

                root.draw_text(
                    duration_tx_first_data_tx_last_data,
                    style,
                    (x, y + newline_offset * 12),
                )
                .unwrap();
            },
        }
    }
}

fn plot_legend<DB: DrawingBackend>(
    color: &RGBColor, root: &DrawingArea<DB, plotters::coord::Shift>, x: i32,
    y: i32, params: &SparkPlotsParams, transmission_type: TransmissionType,
) {
    // TODO: only considers vert layout, needs to consider grid layout too
    let style = &("monospace", 12).into_text_style(root).color(color);
    let x: i32 = x + params.spark_dimension_x as i32 + 300;
    let y: i32 = y;
    let line_len: i32 = 50;
    let nl_off: i32 = 20;

    root.draw_text("Legend", style, (x, y)).unwrap();

    // stream data
    let label = match transmission_type {
        TransmissionType::Download => "Stream data read",
        TransmissionType::Upload => "Stream data sent",
    };
    root.draw(&PathElement::new(
        vec![(x, y + nl_off), (x + line_len, y + nl_off)],
        PURPLE_500,
    ))
    .unwrap();
    root.draw_text(label, style, (x + line_len + 10, y + (nl_off) - 5))
        .unwrap();

    // stream data buffered
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 2), (x + line_len, y + nl_off * 2)],
        MAGENTA,
    ))
    .unwrap();
    root.draw_text(
        "Stream data buffered",
        style,
        (x + line_len + 10, y + (nl_off * 2) - 5),
    )
    .unwrap();

    // max stream data
    let label = match transmission_type {
        TransmissionType::Download => "Max stream data sent",
        TransmissionType::Upload => "Max stream data received",
    };

    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 3), (x + line_len, y + nl_off * 3)],
        MUSTARD,
    ))
    .unwrap();
    root.draw_text(label, style, (x + line_len + 10, y + (nl_off * 3) - 5))
        .unwrap();

    // headers transmitted
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 4), (x + line_len, y + nl_off * 4)],
        CYAN,
    ))
    .unwrap();
    root.draw_text(
        "Request headers sent",
        style,
        (x + line_len + 10, y + (nl_off * 4) - 5),
    )
    .unwrap();

    // first data frame
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 5), (x + line_len, y + nl_off * 5)],
        ORANGE,
    ))
    .unwrap();
    root.draw_text(
        "First data frame read",
        style,
        (x + line_len + 10, y + (nl_off * 5) - 5),
    )
    .unwrap();

    // last data frame
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 6), (x + line_len, y + nl_off * 6)],
        BROWN,
    ))
    .unwrap();
    root.draw_text(
        "Last data frame read",
        style,
        (x + line_len + 10, y + (nl_off * 6) - 5),
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
pub fn plot_sparks(
    params: &SparkPlotsParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    abs_dl_ty: &ChartOutputType, rel_dl_ty: &ChartOutputType,
    abs_ul_ty: &ChartOutputType, rel_ul_ty: &ChartOutputType,
) {
    let (stream_frame_dl_series_to_plot, stream_frame_ul_series_to_plot) =
        match (ds.vantage_point, ds.application_proto) {
            (VantagePoint::Client, ApplicationProto::Http3) => (
                &ss.received_stream_frames_series,
                &ss.sent_stream_frames_series,
            ),
            (VantagePoint::Server, ApplicationProto::Http3) => (
                &ss.sent_stream_frames_series,
                &ss.received_stream_frames_series,
            ),
            (VantagePoint::Client, ApplicationProto::Http2) =>
                (&ss.received_data_frames_series, &ss.sent_data_frames_series),
            _ => unimplemented!(),
        };

    #[cfg(not(target_arch = "wasm32"))]
    let (total_dl_sparks, total_ul_sparks) =
        if params.bidi_only && ds.application_proto == ApplicationProto::Http3 {
            let total_dl = stream_frame_dl_series_to_plot
                .iter()
                .filter(|(k, _)| (*k & 0x2) == 0)
                .count() as u32;

            let total_ul = stream_frame_ul_series_to_plot
                .iter()
                .filter(|(k, _)| (*k & 0x2) == 0)
                .count() as u32;

            (total_dl, total_ul)
        } else {
            (
                stream_frame_dl_series_to_plot.len() as u32,
                stream_frame_ul_series_to_plot.len() as u32,
            )
        };

    // TODO: replace with div_ceil once stablized- https://github.com/rust-lang/rust/issues/88581
    #[cfg(not(target_arch = "wasm32"))]
    let total_dl_rows: u32 = total_dl_sparks / params.sparks_per_row +
        u32::from(total_dl_sparks % params.sparks_per_row != 0);
    #[cfg(not(target_arch = "wasm32"))]
    let total_ul_rows: u32 = total_ul_sparks / params.sparks_per_row +
        u32::from(total_ul_sparks % params.sparks_per_row != 0);

    #[cfg(not(target_arch = "wasm32"))]
    let caption_area_width = if params.captions_on_top {
        0
    } else {
        params.caption_area_width
    };

    let caption_area_height = if params.captions_on_top {
        params.caption_area_height
    } else {
        0
    };

    #[cfg(not(target_arch = "wasm32"))]
    let spark_and_captions_width = params.spark_dimension_x +
        (params.spark_offset_x as f32 * 1.2) as u32 +
        caption_area_width;
    #[cfg(not(target_arch = "wasm32"))]
    let spark_and_captions_height = params.spark_dimension_y +
        params.spark_offset_y +
        (params.label_area_height) +
        caption_area_height;

    #[cfg(not(target_arch = "wasm32"))]
    let root_width: u32 = params.sparks_per_row * spark_and_captions_width;

    #[cfg(not(target_arch = "wasm32"))]
    let dl_root_height: u32 = total_dl_rows * spark_and_captions_height;

    #[cfg(not(target_arch = "wasm32"))]
    let ul_root_height: u32 = total_ul_rows * spark_and_captions_height;

    let mut x_min = match ds.vantage_point {
        VantagePoint::Client => ss.received_x_min,
        VantagePoint::Server => ss.sent_x_min,
    };

    let mut x_max = match ds.vantage_point {
        VantagePoint::Client => ss.received_x_max,
        VantagePoint::Server => ss.sent_x_max,
    };

    // Clamp plot x-axis if the user told us.
    if let Some(s) = params.clamp.start {
        x_min = s;
    }

    if let Some(e) = params.clamp.end {
        x_max = x_max.min(e);
    }

    let abs_dl_chart_config = ChartConfig {
        title: "stream-spark-dl-absolute".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: abs_dl_ty.clone(),
    };
    abs_dl_chart_config.init_chart_dir();

    let rel_dl_chart_config = ChartConfig {
        title: "stream-spark-dl-relative".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: rel_dl_ty.clone(),
    };
    rel_dl_chart_config.init_chart_dir();

    let abs_ul_chart_config = ChartConfig {
        title: "stream-spark-ul-absolute".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: abs_ul_ty.clone(),
    };
    abs_ul_chart_config.init_chart_dir();

    let rel_ul_chart_config = ChartConfig {
        title: "stream-spark-ul-relative".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: rel_ul_ty.clone(),
    };
    rel_ul_chart_config.init_chart_dir();

    #[cfg(not(target_arch = "wasm32"))]
    let dl_size = ChartSize {
        width: root_width,
        height: dl_root_height,
    };

    #[cfg(not(target_arch = "wasm32"))]
    let ul_size = ChartSize {
        width: root_width,
        height: ul_root_height,
    };
    let margin = ChartMargin::default();

    #[cfg(not(target_arch = "wasm32"))]
    let abs_dl_chart_path = abs_dl_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let rel_dl_chart_path = rel_dl_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let abs_ul_chart_path = abs_ul_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let rel_ul_chart_path = rel_ul_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let abs_dl_root = make_chart_bitmap_area(
        &abs_dl_chart_path,
        dl_size,
        params.colors,
        margin,
    );

    #[cfg(not(target_arch = "wasm32"))]
    let rel_dl_root = make_chart_bitmap_area(
        &rel_dl_chart_path,
        dl_size,
        params.colors,
        margin,
    );

    #[cfg(not(target_arch = "wasm32"))]
    let abs_ul_root = make_chart_bitmap_area(
        &abs_ul_chart_path,
        ul_size,
        params.colors,
        margin,
    );

    #[cfg(not(target_arch = "wasm32"))]
    let rel_ul_root = make_chart_bitmap_area(
        &rel_ul_chart_path,
        ul_size,
        params.colors,
        margin,
    );

    #[cfg(target_arch = "wasm32")]
    let abs_dl_canvas_id = abs_dl_chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let rel_dl_canvas_id = rel_dl_chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let abs_ul_canvas_id = abs_ul_chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let rel_ul_canvas_id = rel_ul_chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let abs_dl_root =
        make_chart_canvas_area(&abs_dl_canvas_id, params.colors, margin);
    #[cfg(target_arch = "wasm32")]
    let rel_dl_root =
        make_chart_canvas_area(&rel_dl_canvas_id, params.colors, margin);
    #[cfg(target_arch = "wasm32")]
    let abs_ul_root =
        make_chart_canvas_area(&abs_ul_canvas_id, params.colors, margin);
    #[cfg(target_arch = "wasm32")]
    let rel_ul_root =
        make_chart_canvas_area(&rel_ul_canvas_id, params.colors, margin);

    let mut upper_x = params.spark_offset_x;
    let mut dl_upper_y = params.spark_offset_y;
    let mut ul_upper_y = params.spark_offset_y;

    plot_legend(
        &params.colors.caption,
        &abs_dl_root,
        upper_x as i32,
        dl_upper_y as i32,
        params,
        TransmissionType::Download,
    );
    plot_legend(
        &params.colors.caption,
        &rel_dl_root,
        upper_x as i32,
        dl_upper_y as i32,
        params,
        TransmissionType::Download,
    );
    plot_legend(
        &params.colors.caption,
        &abs_ul_root,
        upper_x as i32,
        ul_upper_y as i32,
        params,
        TransmissionType::Upload,
    );
    plot_legend(
        &params.colors.caption,
        &rel_ul_root,
        upper_x as i32,
        ul_upper_y as i32,
        params,
        TransmissionType::Upload,
    );

    let mut dl_layout_count = 0;
    let mut ul_layout_count = 0;

    for (stream_id, dl_stream_frames) in stream_frame_dl_series_to_plot {
        if ds.application_proto == ApplicationProto::Http3 &&
            params.bidi_only &&
            (stream_id & 0x2) != 0
        {
            continue;
        }

        let abs_dl_small_area = abs_dl_root.clone().shrink(
            (upper_x, dl_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let rel_dl_small_area = rel_dl_root.clone().shrink(
            (upper_x, dl_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let abs_ul_small_area = abs_ul_root.clone().shrink(
            (upper_x, ul_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let rel_ul_small_area = rel_ul_root.clone().shrink(
            (upper_x, ul_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let dl_zoom_x_min = dl_stream_frames.first().unwrap().0;
        let dl_zoom_x_max = dl_stream_frames.last().unwrap().0;

        let dl_zoom_y_max = if let Some(y_max) = params.clamp.stream_y_max {
            y_max
        } else {
            dl_stream_frames.last().unwrap().1
        };

        let mut abs_dl_chart = ChartBuilder::on(&abs_dl_small_area)
            .set_label_area_size(LabelAreaPosition::Left, params.label_area_width)
            .set_label_area_size(
                LabelAreaPosition::Bottom,
                params.label_area_height,
            )
            .build_cartesian_2d(x_min..x_max, 0..dl_zoom_y_max)
            .unwrap();
        draw_mesh(&params.colors, &mut abs_dl_chart);

        let mut rel_dl_chart = ChartBuilder::on(&rel_dl_small_area)
            .set_label_area_size(LabelAreaPosition::Left, params.label_area_width)
            .set_label_area_size(
                LabelAreaPosition::Bottom,
                params.label_area_height,
            )
            .build_cartesian_2d(dl_zoom_x_min..dl_zoom_x_max, 0..dl_zoom_y_max)
            .unwrap();
        draw_mesh(&params.colors, &mut rel_dl_chart);

        dl_layout_count += 1;

        let ul_stream_frames = stream_frame_ul_series_to_plot.get(stream_id);

        // TODO upload window
        let ul_h2_send_window =
            ss.h2_send_window_series_balanced.get(&(*stream_id as u32));
        let ul_h2_send_window_max =
            ss.h2_send_window_balanced_max.get(&(*stream_id as u32));

        let (abs_ul_chart, rel_ul_chart) = match ul_stream_frames {
            Some(frames) => {
                let ul_zoom_x_min = frames.first().unwrap().0;
                let ul_zoom_x_max = frames.last().unwrap().0;

                // let ul_zoom_x_min_send_window =
                //     ul_send_window.unwrap().first().unwrap().0;
                // let ul_zoom_x_max_send_window =
                //     ul_send_window.unwrap().last().unwrap().0;

                let ul_zoom_y_max = if let Some(y_max) = params.clamp.stream_y_max
                {
                    y_max
                } else {
                    frames.last().unwrap().1
                };

                // TODO: this is a hack because the underlying chart types make
                // it hard to support optional secondary axis. And that axis
                // only makes sense for HTTP/2.
                let ul_h2_send_window_y_max = ul_h2_send_window_max.unwrap_or(&0);

                let mut abs_ul_chart = ChartBuilder::on(&abs_ul_small_area)
                    .set_label_area_size(
                        LabelAreaPosition::Left,
                        params.label_area_width,
                    )
                    .set_label_area_size(
                        LabelAreaPosition::Bottom,
                        params.label_area_height,
                    )
                    .build_cartesian_2d(x_min..x_max, 0..ul_zoom_y_max)
                    .unwrap()
                    .set_secondary_coord(
                        x_min..x_max,
                        0i32..*ul_h2_send_window_y_max,
                    );

                draw_mesh(&params.colors, &mut abs_ul_chart);

                if ul_h2_send_window_max.is_some() {
                    abs_ul_chart.configure_secondary_axes().draw().unwrap();
                }

                let mut rel_ul_chart = ChartBuilder::on(&rel_ul_small_area)
                    .set_label_area_size(
                        LabelAreaPosition::Left,
                        params.label_area_width,
                    )
                    .set_label_area_size(
                        LabelAreaPosition::Bottom,
                        params.label_area_height,
                    )
                    .right_y_label_area_size(params.label_area_width)
                    .build_cartesian_2d(
                        ul_zoom_x_min..ul_zoom_x_max,
                        0..ul_zoom_y_max,
                    )
                    .unwrap()
                    .set_secondary_coord(
                        ul_zoom_x_min..ul_zoom_x_max,
                        0i32..*ul_h2_send_window_y_max,
                    );
                draw_mesh(&params.colors, &mut rel_ul_chart);

                if ul_h2_send_window_max.is_some() {
                    rel_ul_chart
                        .configure_secondary_axes()
                        .y_labels(5)
                        .draw()
                        .unwrap();
                }

                ul_layout_count += 1;

                (Some(abs_ul_chart), Some(rel_ul_chart))
            },

            None => (None, None),
        };

        draw_captions(
            &abs_dl_root,
            &rel_dl_root,
            &abs_ul_root,
            &rel_ul_root,
            params,
            ds,
            *stream_id,
            ul_stream_frames.is_some(),
            upper_x,
            dl_upper_y,
            ul_upper_y,
        );

        upper_x += params.spark_dimension_x + params.spark_offset_x;

        // new row needed?
        if dl_layout_count == params.sparks_per_row {
            upper_x = params.spark_offset_x;

            let y_offset = if params.captions_on_top {
                params.caption_area_height
            } else {
                0
            };

            dl_upper_y +=
                params.spark_dimension_y + params.spark_offset_y + y_offset;

            dl_layout_count = 0;
        }

        if ul_layout_count == params.sparks_per_row {
            upper_x = params.spark_offset_x;

            let y_offset = if params.captions_on_top {
                params.caption_area_height
            } else {
                0
            };

            ul_upper_y +=
                params.spark_dimension_y + params.spark_offset_y + y_offset;

            ul_layout_count = 0;
        }

        draw_stream_frames_line(
            dl_stream_frames,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        );

        if let (Some(mut abs), Some(mut rel), Some(frames)) =
            (abs_ul_chart, rel_ul_chart, ul_stream_frames)
        {
            if let Some(v) = ul_h2_send_window {
                abs.draw_secondary_series(LineSeries::new(v.to_vec(), ORANGE))
                    .unwrap();

                rel.draw_secondary_series(LineSeries::new(v.to_vec(), ORANGE))
                    .unwrap();
            } else {
                draw_stream_max_line(
                    *stream_id,
                    ss,
                    &ds.vantage_point,
                    TransmissionType::Upload,
                    &mut abs,
                    &mut rel,
                );
            }

            draw_stream_frames_line(frames, &mut abs, &mut rel);
        }

        draw_buffered_data_line(
            *stream_id,
            ss,
            &ds.vantage_point,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        );

        draw_stream_max_line(
            *stream_id,
            ss,
            &ds.vantage_point,
            TransmissionType::Download,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        );

        draw_request_timing_lines(
            ds,
            *stream_id,
            ss.y_max_stream_plot,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        );
    }
}

fn draw_mesh<XT, YT, X, Y, DB: DrawingBackend>(
    colors: &PlotColors, chart: &mut ChartContext<DB, Cartesian2d<X, Y>>,
) where
    X: Ranged<ValueType = XT> + ValueFormatter<XT>,
    Y: Ranged<ValueType = YT> + ValueFormatter<YT>,
{
    chart
        .configure_mesh()
        .disable_mesh()
        .x_labels(5)
        .y_labels(5)
        .axis_style(colors.axis)
        .label_style(chart_label_style(&colors.caption))
        .draw()
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn draw_captions<DB: DrawingBackend>(
    abs_dl_root: &DrawingArea<DB, plotters::coord::Shift>,
    rel_dl_root: &DrawingArea<DB, plotters::coord::Shift>,
    abs_ul_root: &DrawingArea<DB, plotters::coord::Shift>,
    rel_ul_root: &DrawingArea<DB, plotters::coord::Shift>,
    params: &SparkPlotsParams, ds: &Datastore, stream_id: u64, upload_data: bool,
    upper_x: u32, dl_upper_y: u32, ul_upper_y: u32,
) {
    if let Some(captions) = SparkCaption::from_data_store(ds, stream_id) {
        let x_offset = if params.captions_on_top {
            0
        } else if ds.application_proto == ApplicationProto::Http2 {
            params.spark_dimension_x + 30
        } else {
            params.spark_dimension_x
        };

        captions.draw(
            &params.colors.caption,
            abs_dl_root,
            (upper_x + x_offset) as i32,
            dl_upper_y as i32,
        );
        captions.draw(
            &params.colors.caption,
            rel_dl_root,
            (upper_x + x_offset) as i32,
            dl_upper_y as i32,
        );

        if upload_data {
            captions.draw(
                &params.colors.caption,
                abs_ul_root,
                (upper_x + x_offset) as i32,
                ul_upper_y as i32,
            );
            captions.draw(
                &params.colors.caption,
                rel_ul_root,
                (upper_x + x_offset) as i32,
                ul_upper_y as i32,
            );
        }
    }
}

fn draw_stream_frames_line<DB: DrawingBackend>(
    stream_frames: &[(f32, u64)],
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
) {
    abs_chart
        .draw_series(LineSeries::new(stream_frames.to_vec(), PURPLE_500))
        .unwrap();

    rel_chart
        .draw_series(LineSeries::new(stream_frames.to_vec(), PURPLE_500))
        .unwrap();

    let circles: Vec<Circle<(f32, u64), i32>> = stream_frames
        .iter()
        .map(|point| Circle::new(*point, 2, PURPLE_500))
        .collect();
    rel_chart.draw_series(circles).unwrap();
}

fn draw_buffered_data_line<DB: DrawingBackend>(
    stream_id: u64, ss: &SeriesStore, vantage_point: &VantagePoint,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
) {
    let buffered_data_to_plot = match vantage_point {
        VantagePoint::Client => ss.stream_buffer_reads.get(&stream_id),
        VantagePoint::Server => ss.stream_buffer_writes.get(&stream_id),
    };

    if let Some(buffered_data) = buffered_data_to_plot {
        abs_chart
            .draw_series(LineSeries::new(buffered_data.clone(), MAGENTA))
            .unwrap();

        rel_chart
            .draw_series(LineSeries::new(buffered_data.clone(), MAGENTA))
            .unwrap();

        rel_chart
            .draw_series(
                buffered_data
                    .iter()
                    .map(|point| TriangleMarker::new(*point, 3, MAGENTA)),
            )
            .unwrap();
    }
}

fn draw_stream_max_line<DB: DrawingBackend>(
    stream_id: u64, ss: &SeriesStore, vantage_point: &VantagePoint,
    transmission_type: TransmissionType,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
) {
    let stream_max_data_to_plot = match (vantage_point, transmission_type) {
        (VantagePoint::Client, TransmissionType::Download) =>
            ss.sent_stream_max_data.get(&stream_id),
        (VantagePoint::Client, TransmissionType::Upload) =>
            ss.received_stream_max_data.get(&stream_id),
        (VantagePoint::Server, TransmissionType::Download) =>
            ss.received_stream_max_data.get(&stream_id),
        (VantagePoint::Server, TransmissionType::Upload) =>
            ss.sent_stream_max_data.get(&stream_id),
    };

    if let Some(stream_max_data) = stream_max_data_to_plot {
        abs_chart
            .draw_series(LineSeries::new(stream_max_data.clone(), MUSTARD))
            .unwrap();

        rel_chart
            .draw_series(LineSeries::new(stream_max_data.clone(), MUSTARD))
            .unwrap();
    }
}

fn draw_request_timing_lines<DB: DrawingBackend>(
    ds: &Datastore, stream_id: u64, y_max: u64,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
) {
    if let Some(req) = ds.http_requests.get(&stream_id) {
        if let Some(h) = req.time_first_headers_rx {
            let points = vec![(h, 0), (h, y_max)];
            abs_chart
                .draw_series(LineSeries::new(points, GREEN))
                .unwrap();

            // don't care about rx events on the relative spark chart
        }

        if let Some(h) = req.time_first_headers_tx {
            let points = vec![(h, 0), (h, y_max)];
            abs_chart
                .draw_series(LineSeries::new(points.clone(), CYAN))
                .unwrap();
            rel_chart
                .draw_series(LineSeries::new(points, CYAN))
                .unwrap();
        }

        let (first_data_to_plot, last_data_to_plot) = match ds.vantage_point {
            VantagePoint::Client =>
                (req.time_first_data_rx, req.time_last_data_rx),
            VantagePoint::Server =>
                (req.time_first_data_tx, req.time_last_data_tx),
        };

        if let Some(t) = first_data_to_plot {
            let points = vec![(t, 0), (t, y_max)];
            abs_chart
                .draw_series(LineSeries::new(points.clone(), ORANGE))
                .unwrap();
            rel_chart
                .draw_series(LineSeries::new(points, ORANGE))
                .unwrap();
        }

        if let Some(t) = last_data_to_plot {
            let points = vec![(t, 0), (t, y_max)];
            abs_chart
                .draw_series(LineSeries::new(points.clone(), BROWN))
                .unwrap();
            rel_chart
                .draw_series(LineSeries::new(points, BROWN))
                .unwrap();
        }
    }
}
