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

use std::collections::HashSet;

use clap::Arg;
use clap::ArgAction;
use clap::Command;

use crate::datastore::PrintStatsConfig;
use crate::plots::colors::PlotColors;
use crate::plots::colors::DARK_MODE;
use crate::plots::colors::LIGHT_MODE;
use crate::plots::stream_sparks::SparkPlotsParams;
use crate::plots::ClampParams;
use crate::SerializationFormat;

#[derive(Debug)]
pub struct AppConfig {
    pub file: String,
    pub filename: String,

    pub charts_dir: String,
    pub plot_conn_overview: bool,
    pub plot_pkt_sent: bool,
    pub plot_pkt_received: bool,
    pub plot_conn_flow_control: bool,
    pub plot_sparks: bool,
    pub plot_multiplex: bool,
    pub plot_pending: bool,
    pub sparks_layout: SparkPlotsParams,

    pub report_text: bool,
    pub report_omit_upload: bool,
    pub report_omit_priorities: bool,
    pub report_text_csv: bool,
    pub report_html: bool,

    pub dark_mode: bool,

    pub start: Option<f32>,
    pub end: Option<f32>,

    pub stream_y_max: Option<u64>,
    pub cwnd_y_max: Option<u64>,

    pub netlog_filter: HashSet<String>,
    pub qlog_wirefilter: Option<String>,

    pub stats_config: PrintStatsConfig,
    pub ignore_acks: bool,

    pub log_format: SerializationFormat,
}

impl AppConfig {
    pub fn colors(dark_mode: bool) -> PlotColors {
        if dark_mode {
            DARK_MODE
        } else {
            LIGHT_MODE
        }
    }

    pub fn from_clap() -> std::result::Result<Self, String> {
        let mut matches = Command::new("qlog-dancer")
        .version("v0.1.0")
        .about("dances with qlog (and more!)")
        .arg(
            Arg::new("LOG FILE")
                .help("Sets the input log file to use")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("charts")
                .long("charts")
                .help("Type of charts to plot")
                .value_parser([
                    "all",
                    "overview",
                    "pkt-rx",
                    "sparks",
                    "multiplex",
                    "pending",
                    "conn-flow",
                    "none",
                ])
                .default_value("none"),
        )
        .arg(
            Arg::new("charts_directory")
                .long("charts-directory")
                .help("Sets the output directory for charts"),
        )
        .arg(
            Arg::new("sparks_layout")
                .long("sparks-layout")
                .help("Layout of spark charts")
                .value_parser(["grid", "vert"])
                .default_value("vert"),
        )
        .arg(
            Arg::new("start")
                .short('s')
                .help("Relative start time for plots")
        )
        .arg(
            Arg::new("end")
                .short('e')
                .help("Relative end time for plots")
        )
        .arg(
            Arg::new("stream_y_axis_max")
                .long("stream-y-axis_max")
                .help("Maximum value of Y axis on stream-related charts")
        )
        .arg(
            Arg::new("cwnd_y_axis_max")
                .long("cwnd-y-axis-max")
                .help("Maximum value of Y axis on cwnd-related charts")
        )
        .arg(
            Arg::new("netlog_filter")
                .long("netlog-filter")
                .help("A comma-seperated list of hostnames to filter in to netlog analysis. By default, all hostname are analysed.")
        )
        .arg(
            Arg::new("qlog_wirefilter")
                .long("qlog-wirefilter")
                .help("A Wirefilter expression for Wireshark-like matching of qlog events.")
        )
        .arg(
            Arg::new("dark_mode")
                .long("dark_mode")
                .help("Generate outputs in a dark mode style")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print_stats")
                .long("print-stats")
                .help("Print stats about qlog events")
                .value_parser(["all", "stream", "packets", "none"])
                .default_value("none"),
        )
        .arg(
            Arg::new("report_text")
                .long("report-text")
                .help("Generate log reports in text format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_html")
                .long("report-html")
                .help("Generate log reports in HTML format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_omit_upload")
                .long("report-omit-upload")
                .help("Omit printing columns about HTTP uploads")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_omit_priorities")
                .long("report-omit-priorities")
                .help("Omit printing columns about HTTP priorities")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_text_csv")
                .long("report-text-csv")
                .help("Tables printed in a CSV-compatible format")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

        let file = matches.remove_one::<String>("LOG FILE").unwrap();
        let filename = std::path::Path::new(&file)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();

        let charts_dir = matches
            .remove_one::<String>("charts_directory")
            .unwrap_or(format!("{filename}-charts"));

        let start = matches.remove_one::<f32>("start");
        let end = matches.remove_one::<f32>("end");

        if end.is_some() && end < start {
            return Err("End time cannot be earlier than start time.".into());
        }

        if let Some(start) = start {
            if start < 0.0 {
                return Err("Start time cannot be less than 0.0.".into());
            }
        }

        if let Some(end) = end {
            if end < 0.0 {
                return Err("End time cannot be less than 0.0.".into());
            }
        }

        let stream_y_max =
            matches.remove_one::<i64>("stream_y_axis_max").unwrap_or(-1);
        let stream_y_max = if stream_y_max == -1 {
            None
        } else {
            Some(stream_y_max as u64)
        };

        let cwnd_y_max =
            matches.remove_one::<i64>("cwnd_y_axis_max").unwrap_or(-1);
        let cwnd_y_max = if cwnd_y_max == -1 {
            None
        } else {
            Some(cwnd_y_max as u64)
        };

        let dark_mode = matches.get_flag("dark_mode");

        let charts = matches.remove_one::<String>("charts").unwrap();
        let (
            plot_conn_overview,
            plot_pkt_sent,
            plot_pkt_received,
            plot_sparks,
            plot_multiplex,
            plot_pending,
            plot_conn_flow_control,
        ) = match charts.as_str() {
            "all" => (true, true, true, true, true, true, true),

            "overview" => (true, true, false, false, false, false, false),

            "pkt-rx" => (false, false, true, false, false, false, false),

            "sparks" => (false, false, false, true, false, false, false),

            "multiplex" => (false, false, false, false, true, false, false),

            "pending" => (false, false, false, false, false, true, false),

            "conn-flow" => (false, false, false, false, false, false, true),

            "none" => (false, false, false, false, false, false, false),

            _ => unreachable!(),
        };

        let sparks_layout =
            matches.remove_one::<String>("sparks_layout").unwrap();
        let sparks_layout = if sparks_layout == "grid" {
            SparkPlotsParams {
                clamp: ClampParams {
                    start,
                    end,
                    stream_y_max,
                },
                colors: Self::colors(dark_mode),
                ..Default::default()
            }
        } else {
            SparkPlotsParams {
                clamp: ClampParams {
                    start,
                    end,
                    stream_y_max,
                },
                colors: Self::colors(dark_mode),
                sparks_per_row: 1,
                captions_on_top: false,
                spark_dimension_x: 600,
                caption_area_width: 600,
                label_area_height: 1,
                ..Default::default()
            }
        };

        let netlog_filter = match matches.remove_one::<String>("netlog_filter") {
            Some(filter_string) => filter_string
                .split(',')
                .map(|v| v.to_string())
                .collect::<HashSet<String>>(),

            None => HashSet::new(),
        };

        let qlog_wirefilter = matches.remove_one::<String>("qlog_wirefilter");

        let report_text = matches.get_flag("report_text");
        let report_omit_upload = matches.get_flag("report_omit_upload");
        let report_omit_priorities = matches.get_flag("report_omit_priorities");
        let report_text_csv = matches.get_flag("report_text_csv");
        let report_html = matches.get_flag("report_html");

        let print_stats = matches.remove_one::<String>("print_stats").unwrap();
        let stats_config = match print_stats.as_str() {
            "all" => PrintStatsConfig {
                rx_flow_control: true,
                tx_flow_control: true,
                reset_streams: true,
                stream_buffering: true,
                tx_stream_frames: true,
                packet_stats: true,
            },

            "stream" => PrintStatsConfig {
                rx_flow_control: true,
                tx_flow_control: true,
                reset_streams: true,
                stream_buffering: true,
                tx_stream_frames: true,
                packet_stats: false,
            },

            "packets" => PrintStatsConfig {
                rx_flow_control: false,
                tx_flow_control: false,
                reset_streams: false,
                stream_buffering: false,
                tx_stream_frames: false,
                packet_stats: true,
            },

            "none" => PrintStatsConfig {
                rx_flow_control: false,
                tx_flow_control: false,
                reset_streams: false,
                stream_buffering: false,
                tx_stream_frames: false,
                packet_stats: false,
            },

            _ => unreachable!(),
        };

        let ignore_acks = false;

        let qlog_ext = std::path::Path::new(&file)
            .extension()
            .unwrap()
            .to_str()
            .unwrap();
        let log_format = SerializationFormat::from_file_extension(qlog_ext);

        let config = Self {
            file: file.to_string(),
            filename: filename.to_string(),
            charts_dir: charts_dir.to_string(),
            plot_conn_overview,
            plot_pkt_sent,
            plot_pkt_received,
            plot_conn_flow_control,
            plot_sparks,
            plot_multiplex,
            plot_pending,
            sparks_layout,
            report_text,
            report_omit_upload,
            report_omit_priorities,
            report_text_csv,
            report_html,
            dark_mode,
            start,
            end,
            stream_y_max,
            cwnd_y_max,
            netlog_filter,
            qlog_wirefilter,
            stats_config,
            ignore_acks,
            log_format,
        };

        Ok(config)
    }
}
