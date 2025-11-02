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

use crate::config::AppConfig;
use crate::plots::congestion_control::plot_cc_plot;
use crate::plots::conn_flow_control::plot_conn_flow_control_canvas;
use crate::plots::conn_overview::plot_main_plot;
use crate::plots::packet_received::plot_packet_received;
use crate::plots::packet_sent::plot_packet_sent_delta_plot_canvas;
use crate::plots::packet_sent::plot_packet_sent_lost_delivered_count_plot;
use crate::plots::packet_sent::plot_packet_sent_pacing_rate_plot_canvas;
use crate::plots::packet_sent::plot_packet_sent_plot_canvas;
use crate::plots::pending::plot_pending;
use crate::plots::pending::PendingPlotParams;
use crate::plots::rtt::plot_rtt_plot;
use crate::plots::stream_multiplex::plot_stream_multiplexing;
use crate::plots::stream_multiplex::MultiplexPlotsParams;
use crate::plots::stream_sparks::plot_sparks;
use crate::plots::stream_sparks::SparkPlotsParams;
use crate::plots::AreaMargin;
use crate::plots::ChartMargin;
use crate::plots::ChartOutputType;
use crate::plots::ChartSize;
use crate::plots::ClampParams;
use crate::plots::PlotParameters;
use crate::reports::html::event_list_html_from_sqlog;

use crate::datastore::Datastore;
use crate::datastore::VantagePoint;

use plotters::chart::ChartContext;
use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::prelude::Cartesian2d;
use plotters_canvas::CanvasBackend;
use wasm_bindgen::prelude::*;

use crate::seriesstore::SeriesStore;

use serde::Deserialize;
use serde::Serialize;

use web_sys::Document;
use web_sys::Element;
use web_sys::Window;

const AREA_MARGIN: AreaMargin = AreaMargin { x: 50, y: 100 };
const CHART_MARGIN: ChartMargin = ChartMargin {
    top: 20,
    bottom: 20,
    left: 20,
    right: 20,
};
const CHART_MARGIN_TIGHT: ChartMargin = ChartMargin {
    top: 10,
    bottom: 2,
    left: 5,
    right: 5,
};

#[wasm_bindgen]
pub struct Pointu64 {
    pub x: f32,
    pub y: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct ChartBounds {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PlotRanges<T, U> {
    pub x_min: T,
    pub x_max: T,
    pub y_min: U,
    pub y_max: U,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct ChartInfo<T, U> {
    pub chart_bounds: ChartBounds,
    pub plot_ranges: PlotRanges<T, U>,
}

impl<T, U> ChartInfo<T, U> {
    pub fn with_f32_u64(
        chart: &ChartContext<
            CanvasBackend,
            Cartesian2d<RangedCoordf32, RangedCoordu64>,
        >,
    ) -> ChartInfo<f32, u64> {
        let plotting_area = chart.plotting_area();
        let pixel_range = plotting_area.get_pixel_range();

        let chart_bounds = ChartBounds {
            left: pixel_range.0.start,
            top: pixel_range.1.start,
            width: pixel_range.0.end - pixel_range.0.start,
            height: pixel_range.1.end - pixel_range.1.start,
        };

        let plot_ranges = PlotRanges {
            x_min: chart.x_range().start,
            x_max: chart.x_range().end,
            y_min: chart.y_range().start,
            y_max: chart.y_range().end,
        };

        ChartInfo {
            chart_bounds,
            plot_ranges,
        }
    }

    pub fn with_f32_f32(
        chart: &ChartContext<
            CanvasBackend,
            Cartesian2d<RangedCoordf32, RangedCoordf32>,
        >,
    ) -> ChartInfo<f32, f32> {
        let plotting_area = chart.plotting_area();
        let pixel_range = plotting_area.get_pixel_range();

        let chart_bounds = ChartBounds {
            left: pixel_range.0.start,
            top: pixel_range.1.start,
            width: pixel_range.0.end - pixel_range.0.start,
            height: pixel_range.1.end - pixel_range.1.start,
        };

        let plot_ranges = PlotRanges {
            x_min: chart.x_range().start,
            x_max: chart.x_range().end,
            y_min: chart.y_range().start,
            y_max: chart.y_range().end,
        };

        ChartInfo {
            chart_bounds,
            plot_ranges,
        }
    }

    pub fn with_u64_f32(
        chart: &ChartContext<
            CanvasBackend,
            Cartesian2d<RangedCoordu64, RangedCoordf32>,
        >,
    ) -> ChartInfo<u64, f32> {
        let plotting_area = chart.plotting_area();
        let pixel_range = plotting_area.get_pixel_range();

        let chart_bounds = ChartBounds {
            left: pixel_range.0.start,
            top: pixel_range.1.start,
            width: pixel_range.0.end - pixel_range.0.start,
            height: pixel_range.1.end - pixel_range.1.start,
        };

        let plot_ranges = PlotRanges {
            x_min: chart.x_range().start,
            x_max: chart.x_range().end,
            y_min: chart.y_range().start,
            y_max: chart.y_range().end,
        };

        ChartInfo {
            chart_bounds,
            plot_ranges,
        }
    }
}

impl<T, U> Into<JsValue> for ChartInfo<T, U>
where
    T: serde::Serialize,
    U: serde::Serialize,
{
    fn into(self) -> JsValue {
        serde_wasm_bindgen::to_value(&(self.chart_bounds, self.plot_ranges))
            .unwrap()
    }
}

#[wasm_bindgen]
/// Creates a QlogDancerWeb object to interact with logs.
///
/// The `display_name` parameter is reflected into drawn plots.
pub fn new_qlog_dancer(display_name: &str) -> QlogDancerWeb {
    let ds = Datastore {
        total_sent_stream_frame_count: 0,
        vantage_point: VantagePoint::Server,
        ..Default::default()
    };

    QlogDancerWeb {
        ds,
        ss: None,
        display_name: display_name.into(),
        partial: vec![],
        log_info: None,
        qlog_events: vec![],

        mp_chart_info: None,
        cc_chart_info: None,
        rtt_chart_info: None,
        fc_chart_info: None,
        pkt_rx_chart_info: None,
        pkt_tx_chart_info: None,
        pkt_tx_counts_chart_info: None,
        pkt_tx_delta_chart_info: None,
        pkt_tx_pacing_chart_info: None,
    }
}

#[wasm_bindgen]
pub struct QlogDancerWeb {
    display_name: String,
    ds: Datastore,
    ss: Option<SeriesStore>,
    partial: Vec<u8>,
    log_info: Option<Vec<u8>>,
    qlog_events: Vec<qlog::reader::Event>,

    mp_chart_info: Option<ChartInfo<f32, u64>>,
    cc_chart_info: Option<ChartInfo<f32, u64>>,
    rtt_chart_info: Option<ChartInfo<f32, f32>>,
    fc_chart_info: Option<ChartInfo<f32, u64>>,
    pkt_rx_chart_info: Option<ChartInfo<f32, u64>>,
    pkt_tx_chart_info: Option<ChartInfo<f32, u64>>,
    pkt_tx_counts_chart_info: Option<ChartInfo<f32, u64>>,
    pkt_tx_delta_chart_info: Option<ChartInfo<u64, f32>>,
    pkt_tx_pacing_chart_info: Option<ChartInfo<f32, u64>>,
}

#[wasm_bindgen]
impl QlogDancerWeb {
    #[wasm_bindgen]
    pub fn process_chunk(&mut self, chunk: &[u8]) {
        let mut s = chunk.split(|f| *f == b'');

        if self.log_info.is_none() {
            // null value, ignore it
            s.next();

            if let Some(info) = s.next() {
                self.log_info = Some(info.to_vec());
            }
        }

        for obj in s {
            if !self.partial.is_empty() {
                self.partial.extend_from_slice(obj);

                // ignore result as we'll give up either way.
                // TODO: clone needed to appease borrow checker
                let _ = self.try_read_event(&self.partial.clone());

                self.partial.clear();
            } else {
                // Try to parse the bytes we have. This might fail because
                // the event is unknown, or because the reader only gave us
                // a partial string. Always try to recover from partial
                // strings by storing it and retrying later when we have
                // more data available.
                if self.try_read_event(obj).is_err() && !obj.ends_with(b"}}") {
                    self.partial = obj.to_vec();
                };
            }
        }
    }

    #[wasm_bindgen]
    /// Consume a ReadableStream as if it were a sqlog file.
    /// TODO: support other log formats
    pub async fn read_stream(&mut self, readable: web_sys::ReadableStream) {
        use futures_util::StreamExt;

        let mut a =
            wasm_streams::ReadableStream::from_raw(readable).into_stream();

        while let Some(Ok(chunk)) = a.next().await {
            let b = js_sys::Uint8Array::new(&chunk).to_vec();

            self.process_chunk(&b);
        }
    }

    pub fn try_read_event(&mut self, buf: &[u8]) -> Result<(), String> {
        let r: serde_json::Result<qlog::events::Event> =
            serde_json::from_slice(buf);

        if let Ok(event) = r {
            self.qlog_events.push(qlog::reader::Event::Qlog(event));
            return Ok(());
        }

        let r: serde_json::Result<qlog::events::JsonEvent> =
            serde_json::from_slice(buf);

        if let Ok(event) = r {
            self.qlog_events.push(qlog::reader::Event::Json(event));
            return Ok(());
        }

        Err("not read".to_string())
    }

    #[wasm_bindgen]
    /// Returns the total count of packets sent in a parsed file.
    ///
    /// A simple function to demonstrate how to access basic information from
    /// parsed log files.
    pub fn total_packets_sent(&self) -> usize {
        let mut ret = 0;
        for v in self.ds.packet_sent.values() {
            ret += v.len();
        }

        ret
    }

    #[wasm_bindgen]
    pub fn populate_datastore(&mut self) {
        for event in &self.qlog_events {
            match event {
                qlog::reader::Event::Qlog(ev) => {
                    self.ds.consume_qlog_event(ev, true);
                },

                qlog::reader::Event::Json(_) => {
                    // This will be handled elsewhere
                },
            }
        }

        // Always finish off the datastore regardless of readable stream type.
        self.ds.hydrate_http_requests();
        self.ds.finalize();
    }

    #[wasm_bindgen]
    /// Run through the internal datastore to prepare data for plotting
    ///
    /// Some use cases don't need plots, so you can avoid calling this function
    /// if that's the case.
    pub fn populate_seriesstore(&mut self) {
        self.ss = Some(SeriesStore::from_datastore(&self.ds));
    }

    #[wasm_bindgen]
    pub fn get_chart_info(&self, canvas_id: &str) -> JsValue {
        match canvas_id {
            "overview_canvas" =>
                self.mp_chart_info.expect("canvas exists").into(),
            "rtt_canvas" => self.rtt_chart_info.expect("canvas exists").into(),
            "cc_canvas" => self.cc_chart_info.expect("canvas exists").into(),
            "flow_control_canvas" =>
                self.fc_chart_info.expect("canvas exists").into(),
            "pkt-rx-canvas" =>
                self.pkt_rx_chart_info.expect("canvas exists").into(),
            "pkt-tx-canvas" =>
                self.pkt_tx_chart_info.expect("canvas exists").into(),
            "pkt-tx-counts-canvas" =>
                self.pkt_tx_chart_info.expect("canvas exists").into(),
            "pkt-tx-delta-canvas" =>
                self.pkt_tx_delta_chart_info.expect("canvas exists").into(),
            "pkt-tx-pacing-canvas" =>
                self.pkt_tx_pacing_chart_info.expect("canvas exists").into(),
            _ => JsValue::null(),
        }
    }

    #[wasm_bindgen]
    #[cfg(target_arch = "wasm32")]
    /// Draws the multi-panel connection overview plot into the provided
    /// canvas_id.
    pub fn draw_connection_overview(
        &mut self, mp_canvas_id: &str, display_legend: bool,
        x_start: Option<f32>, x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AREA_MARGIN,
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart =
                plot_main_plot(&params, &self.display_name, ss, &mp_canvas_id);

            self.mp_chart_info =
                Some(ChartInfo::<f32, u64>::with_f32_u64(&chart));
        }
    }

    #[wasm_bindgen]
    #[cfg(target_arch = "wasm32")]
    /// Draws the congestion plot into the provided canvas_id.
    pub fn draw_cc_plot(
        &mut self, cc_canvas_id: &str, display_legend: bool,
        x_start: Option<f32>, x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AREA_MARGIN,
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart = plot_cc_plot(&params, ss, &self.ds, &cc_canvas_id);

            self.cc_chart_info =
                Some(ChartInfo::<f32, u64>::with_f32_u64(&chart));
        }
    }

    #[wasm_bindgen]
    #[cfg(target_arch = "wasm32")]
    /// Draws the rtt plot into the provided canvas_id.
    pub fn draw_rtt_plot(
        &mut self, rtt_canvas_id: &str, display_legend: bool,
        x_start: Option<f32>, x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AREA_MARGIN,
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart = plot_rtt_plot(&params, ss, &rtt_canvas_id);
            self.rtt_chart_info =
                Some(ChartInfo::<f32, f32>::with_f32_f32(&chart));
        }
    }

    #[wasm_bindgen]
    /// Draws the flow control plot into the provided canvas_id.
    pub fn draw_flow_control(&mut self, canvas_id: &str, display_legend: bool) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            let chart = plot_conn_flow_control_canvas(
                &params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            );
            self.fc_chart_info =
                Some(ChartInfo::<f32, f32>::with_f32_u64(&chart));
        }
    }

    #[wasm_bindgen]
    /// Draws the stream sparks plot into the provided canvas_id.
    pub fn draw_sparks(
        &mut self, abs_dl_canvas_id: &str, abs_ul_canvas_id: &str,
        rel_dl_canvas_id: &str, rel_ul_canvas_id: &str,
    ) {
        if let Some(ss) = &self.ss {
            let spark_params = SparkPlotsParams {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                colors: AppConfig::colors(false),
                sparks_per_row: 1,
                captions_on_top: false,
                spark_dimension_x: 600,
                caption_area_width: 600,
                label_area_height: 1,
                ..Default::default()
            };

            plot_sparks(
                &spark_params,
                &self.display_name,
                ss,
                &self.ds,
                &ChartOutputType::Canvas {
                    canvas_id: abs_dl_canvas_id.to_string(),
                },
                &ChartOutputType::Canvas {
                    canvas_id: rel_dl_canvas_id.to_string(),
                },
                &ChartOutputType::Canvas {
                    canvas_id: abs_ul_canvas_id.to_string(),
                },
                &ChartOutputType::Canvas {
                    canvas_id: rel_ul_canvas_id.to_string(),
                },
            );
        }
    }

    #[wasm_bindgen]
    /// Draws the packet received plot into the provided canvas_id.
    pub fn draw_packet_received(
        &mut self, canvas_id: &str, display_legend: bool,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            plot_packet_received(
                &params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            );
        }
    }

    #[wasm_bindgen]
    /// Draws the stream pending plot into the provided canvas_id.
    pub fn draw_pending(&mut self, canvas_id: &str) {
        if let Some(ss) = &self.ss {
            let pending_params = PendingPlotParams {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                chart_size: ChartSize {
                    width: 1042,
                    height: 600,
                },
                colors: AppConfig::colors(false),
                display_chart_title: false,
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            plot_pending(
                &pending_params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            );
        }
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_plot(
        &mut self, pkt_tx_canvas_id: &str, display_legend: bool,
        x_start: Option<f32>, x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart = plot_packet_sent_plot_canvas(
                &params,
                &self.display_name,
                ss,
                pkt_tx_canvas_id,
            );

            self.pkt_tx_chart_info =
                Some(ChartInfo::<f32, u64>::with_f32_u64(&chart));
        }
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_lost_delivered_count_plot(
        &mut self, canvas_id: &str, display_legend: bool, x_start: Option<f32>,
        x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart = plot_packet_sent_lost_delivered_count_plot(
                &params, ss, canvas_id,
            );

            self.pkt_tx_counts_chart_info =
                Some(ChartInfo::<f32, u64>::with_f32_u64(&chart));
        }
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_delta_plot(
        &mut self, pkt_tx_delta_canvas_id: &str, display_legend: bool,
        x_start: Option<f32>, x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 5 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart = plot_packet_sent_delta_plot_canvas(
                &params,
                ss,
                pkt_tx_delta_canvas_id,
            );

            self.pkt_tx_delta_chart_info =
                Some(ChartInfo::<f32, u64>::with_u64_f32(&chart));
        }
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_pacing_plot(
        &mut self, pkt_tx_pacing_canvas_id: &str, display_legend: bool,
        x_start: Option<f32>, x_end: Option<f32>,
    ) {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart = plot_packet_sent_pacing_rate_plot_canvas(
                &params,
                ss,
                &self.ds,
                pkt_tx_pacing_canvas_id,
            );

            self.pkt_tx_pacing_chart_info =
                Some(ChartInfo::<f32, u64>::with_f32_u64(&chart));
        }
    }

    #[wasm_bindgen]
    /// Draws the stream multiplexing plot into the provided canvas_id.
    pub fn draw_stream_multiplexing(&mut self, canvas_id: &str) {
        if let Some(ss) = &self.ss {
            let multiplex_params = MultiplexPlotsParams {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                colors: AppConfig::colors(false),
                ..Default::default()
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            plot_stream_multiplexing(
                &multiplex_params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            );
        }
    }

    #[wasm_bindgen]
    pub fn populate_event_table(&self, event_div_id: &str) {
        let window: Window = web_sys::window().unwrap();
        let document: Document = window.document().unwrap();

        let target_div: Element =
            document.get_element_by_id(event_div_id).unwrap();

        let event_table = event_list_html_from_sqlog(&self.qlog_events);
        target_div.set_inner_html(&event_table);
    }

    #[wasm_bindgen]
    /// TODO: example of accessing richer data from a parsed log
    pub fn packet_sent(&self) -> Vec<Pointu64> {
        let v = vec![Pointu64 { x: 0.1, y: 1 }];
        v
    }
}
