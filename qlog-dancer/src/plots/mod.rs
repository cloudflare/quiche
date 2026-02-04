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

use crate::datastore::ApplicationProto;
use crate::datastore::Datastore;
use colors::PlotColors;
use plotters::coord::ranged1d::ValueFormatter;
use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordu64;
use plotters::prelude::*;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;

#[derive(Clone, Debug)]
pub enum ChartOutputType {
    Png {
        output_dir: String,
        cwnd_y_max: Option<u64>,
        stream_y_max: Option<u64>,
    },

    Canvas {
        canvas_id: String,
    },
}

#[derive(Clone, Debug)]
struct ChartConfig {
    pub title: String,
    pub input_filename: String,
    // pub size: ChartSize,
    // pub margin: ChartMargin,
    // pub colors: PlotColors,
    pub clamp: ClampParams,
    pub ty: ChartOutputType,
    pub app_proto: ApplicationProto,
    pub host: Option<String>,
    pub session_id: Option<i64>,
}

impl ChartConfig {
    pub fn chart_name(&self) -> String {
        let proto = match self.app_proto {
            ApplicationProto::Http2 => "h2",
            ApplicationProto::Http3 => "h3",
        };

        let host = match (&self.host, &self.ty) {
            (Some(h), ChartOutputType::Png { .. }) => {
                // Hosts might include a port number and putting a colon in
                // filenames might upset some systems.
                format!("-{}", h.replace(":", "_"))
            },

            (Some(h), ChartOutputType::Canvas { .. }) => h.to_string(),

            _ => "".to_string(),
        };

        let session = if let Some(s) = self.session_id {
            format!("-session{}", s)
        } else {
            "".to_string()
        };

        let start = if let Some(s) = self.clamp.start {
            format!("-s{}", s)
        } else {
            "".to_string()
        };

        let end = if let Some(e) = self.clamp.end {
            format!("-e{}", e)
        } else {
            "".to_string()
        };

        match self.ty {
            ChartOutputType::Png {
                cwnd_y_max,
                stream_y_max,
                ..
            } => {
                let mut name = format!(
                    "{}-{}{}{}-{}{}{}",
                    self.input_filename,
                    proto,
                    host,
                    session,
                    self.title,
                    start,
                    end,
                );

                if let Some(y_max) = stream_y_max {
                    name.push_str(&format!("-stream_max_y{}", y_max));
                }

                if let Some(y_max) = cwnd_y_max {
                    name.push_str(&format!("-cwnd_max_y{}", y_max));
                }

                name
            },

            ChartOutputType::Canvas { .. } => format!(
                "{}-{}{}{}-{}{}{}",
                self.input_filename, proto, host, session, self.title, start, end
            ),
        }
    }

    pub fn chart_filepath(&self) -> String {
        match &self.ty {
            ChartOutputType::Png { output_dir, .. } => {
                format!("{}/{}.png", output_dir, self.chart_name())
            },

            // Canvas doesn't have a file
            ChartOutputType::Canvas { .. } => self.chart_name(),
        }
    }

    fn init_chart_dir(&self) {
        match &self.ty {
            ChartOutputType::Png { .. } => {
                let output_filename = self.chart_filepath();
                let path = std::path::Path::new(&output_filename);
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).unwrap();
                }
            },

            // Canvas doesn't have a file
            ChartOutputType::Canvas { .. } => (),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn canvas_id(&self) -> Option<String> {
        match &self.ty {
            ChartOutputType::Canvas { canvas_id } => Some(canvas_id.clone()),
            ChartOutputType::Png { .. } => None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn make_chart_bitmap_area(
    path: &str, size: ChartSize, colors: PlotColors, margin: ChartMargin,
) -> DrawingArea<plotters::prelude::BitMapBackend<'_>, plotters::coord::Shift> {
    let backend = BitMapBackend::new(path, (size.width, size.height));
    let area = backend.into_drawing_area();
    area.fill(&colors.fill).unwrap();
    area.margin(margin.top, margin.bottom, margin.left, margin.right)
}

#[cfg(target_arch = "wasm32")]
pub fn make_chart_canvas_area(
    canvas_id: &str, colors: PlotColors, margin: ChartMargin,
) -> plotters::drawing::DrawingArea<CanvasBackend, plotters::coord::Shift> {
    let backend = CanvasBackend::new(canvas_id)
        .unwrap_or_else(|| panic!("cannot find canvas {}", canvas_id));
    let area = backend.into_drawing_area();
    area.fill(&colors.fill).unwrap();
    area.margin(margin.top, margin.bottom, margin.left, margin.right)
}

fn make_chart_config(
    title: &str, params: &PlotParameters, filename: &str, ds: &Datastore,
    ty: &ChartOutputType,
) -> ChartConfig {
    let chart_config = ChartConfig {
        title: title.into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone(),
    };

    chart_config.init_chart_dir();

    chart_config
}

pub fn chart_title_style(color: &RGBColor) -> TextStyle<'_> {
    TextStyle::from(("sans-serif", 40).into_font()).color(color)
}

pub fn chart_subtitle_style(color: &RGBColor) -> TextStyle<'_> {
    TextStyle::from(("sans-serif", 20).into_font()).color(color)
}

pub fn chart_label_style(color: &RGBColor) -> TextStyle<'_> {
    TextStyle::from(("sans-serif", 15).into_font()).color(color)
}

fn draw_mesh<XT, YT, X, Y, DB: DrawingBackend>(
    colors: &PlotColors, x_desc: &str, y_desc: &str, draw_minor_lines: bool,
    chart: &mut ChartContext<DB, Cartesian2d<X, Y>>,
) where
    X: Ranged<ValueType = XT> + ValueFormatter<XT>,
    Y: Ranged<ValueType = YT> + ValueFormatter<YT>,
{
    let mut mesh = chart.configure_mesh();

    mesh.axis_style(colors.axis)
        .x_desc(x_desc)
        .y_desc(y_desc)
        .bold_line_style(colors.bold_line.mix(0.5));

    // TODO: bizarre! From the docs, state the correct way to do this is to set
    // number of light lines to zero. However, that causes the drawing to spin
    // indefinatly. Perhaps some bug in plotters...
    if !draw_minor_lines {
        mesh.light_line_style(colors.bold_line.mix(0.0));
        // mesh.x_max_light_lines(0);
        // mesh.y_max_light_lines(0);
    } else {
        mesh.light_line_style(colors.light_line.mix(0.2));
    }

    mesh.label_style(chart_label_style(&colors.caption))
        .draw()
        .unwrap();
}

#[derive(Clone, Default, Debug)]
pub struct ClampParams {
    pub start: Option<f32>,
    pub end: Option<f32>,
    pub stream_y_max: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChartSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChartMargin {
    pub top: u32,
    pub bottom: u32,
    pub left: u32,
    pub right: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AreaMargin {
    pub x: u32,
    pub y: u32,
}

pub struct PlotParameters {
    pub clamp: ClampParams,
    pub cwnd_y_max: Option<u64>,
    pub chart_size: ChartSize,
    pub colors: PlotColors,
    pub chart_margin: ChartMargin,
    pub area_margin: AreaMargin,
    pub display_chart_title: bool,
    pub display_legend: bool,
    pub display_minor_lines: bool,
}

fn draw_line<DB: DrawingBackend>(
    data: &[(f32, u64)], label: Option<&str>, colour: RGBColor,
    chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf32, RangedCoordu64>>,
) {
    let c = chart
        .draw_series(LineSeries::new(data.to_vec(), colour))
        .unwrap();

    if let Some(l) = label {
        c.label(l).legend(move |(x, y)| {
            PathElement::new(vec![(x, y), (x + 20, y)], colour)
        });
    }
}

pub mod colors;
pub mod congestion_control;
pub mod conn_flow_control;
pub mod conn_overview;
pub mod minmax;
pub mod packet_received;
pub mod packet_sent;
pub mod pending;
pub mod rtt;
pub mod stream_multiplex;
pub mod stream_sparks;
