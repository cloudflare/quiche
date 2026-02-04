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

extern crate clap;

use std::process::exit;

use log::debug;
use log::error;
use log::info;
use log::warn;
use qlog_dancer::config::AppConfig;
use qlog_dancer::parse_log_file;
use qlog_dancer::plots;
use qlog_dancer::plots::conn_flow_control;
use qlog_dancer::plots::conn_overview;
use qlog_dancer::plots::conn_overview::OverviewChartOutputType;
use qlog_dancer::plots::packet_received;
use qlog_dancer::plots::packet_sent;
use qlog_dancer::plots::pending::PendingPlotParams;
use qlog_dancer::plots::stream_multiplex;
use qlog_dancer::plots::stream_multiplex::MultiplexPlotsParams;
use qlog_dancer::plots::stream_sparks;
use qlog_dancer::plots::AreaMargin;
use qlog_dancer::plots::ChartMargin;
use qlog_dancer::plots::ChartOutputType;
use qlog_dancer::plots::ChartSize;
use qlog_dancer::plots::ClampParams;
use qlog_dancer::plots::PlotParameters;
use qlog_dancer::reports::report;
use qlog_dancer::seriesstore::SeriesStore;
use qlog_dancer::SerializationFormat;

fn main() {
    let rc = run();

    exit(rc);
}

fn run() -> i32 {
    env_logger::builder().init();

    let mut config = match AppConfig::from_clap() {
        Ok(v) => v,

        Err(e) => {
            error!("Error loading configuration, exiting: {}", e);
            return 1;
        },
    };

    let mut log_file = match parse_log_file(&config) {
        Ok(v) => v,

        Err(_) => {
            // Failed, so try a fallback once
            match config.log_format {
                SerializationFormat::QlogJson => {
                    warn!("Failed to parse as qlog, trying sqlog");
                    config.log_format = SerializationFormat::QlogJsonSeq;
                    parse_log_file(&config).unwrap()
                },

                SerializationFormat::QlogJsonSeq => {
                    warn!("Failed to parse as sqlog, trying qlog");
                    config.log_format = SerializationFormat::QlogJson;
                    parse_log_file(&config).unwrap()
                },

                _ => {
                    error!("Can't parse your file sorry. Check the extension");
                    return -1;
                },
            }
        },
    };

    println!();
    println!("== Log details ==");
    println!("  Format: {}", log_file.details.log_format);
    println!("  Version: {}", log_file.details.log_version);
    println!(
        "  Vantage point type: {}",
        log_file.details.qlog_vantage_point_type
    );
    println!();

    if config.plot_conn_overview ||
        config.plot_pkt_sent ||
        config.plot_pkt_received ||
        config.plot_sparks ||
        config.plot_multiplex ||
        config.plot_pending
    {
        if log_file.data.is_empty() {
            error!("File exists but trace information was empty or invalid. If you used a netlog-filter, check it exactly matched session host in the file.");
            return 1;
        }

        let mut series_store = vec![];
        info!("populating plot series data...");
        let mark = std::time::Instant::now();
        for data in log_file.data.iter_mut() {
            let ss = SeriesStore::from_datastore(&data.datastore);
            series_store.push(ss);
        }
        debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

        let plot_params = PlotParameters {
            clamp: ClampParams {
                start: config.start,
                end: config.end,
                stream_y_max: config.stream_y_max,
            },
            cwnd_y_max: config.cwnd_y_max,
            chart_size: ChartSize {
                width: 1600,
                height: 1200,
            },
            colors: AppConfig::colors(config.dark_mode),
            chart_margin: ChartMargin {
                top: 20,
                bottom: 20,
                left: 20,
                right: 20,
            },
            area_margin: AreaMargin { x: 40, y: 80 },
            display_chart_title: true,
            display_legend: true,
            display_minor_lines: true,
        };

        let overview_chart_config = OverviewChartOutputType::Png {
            output_dir: config.charts_dir.clone(),
            cwnd_y_max: plot_params.cwnd_y_max,
            stream_y_max: plot_params.clamp.stream_y_max,
        };

        let chart_config = ChartOutputType::Png {
            output_dir: config.charts_dir.clone(),
            cwnd_y_max: plot_params.cwnd_y_max,
            stream_y_max: plot_params.clamp.stream_y_max,
        };

        let zipper = log_file.data.iter().zip(series_store.iter());
        for (data, ss) in zipper {
            let label = format!(
                "session ID: {:?}, app proto: {:?} host: {:?}",
                data.datastore.session_id,
                data.datastore.application_proto,
                data.datastore.host
            );

            if config.plot_conn_overview {
                let mark = std::time::Instant::now();
                info!("drawing overview for {}...", label);

                conn_overview::plot_connection_overview(
                    &plot_params,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &overview_chart_config,
                );

                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }

            if config.plot_pkt_sent {
                let mark = std::time::Instant::now();
                info!("drawing packet sent chart for {}...", label);
                packet_sent::plot_packet_sent(
                    &plot_params,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &chart_config,
                );

                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }

            if config.plot_pkt_received {
                let mark = std::time::Instant::now();
                info!("drawing packet received chart for {}...", label);
                packet_received::plot_packet_received(
                    &plot_params,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &chart_config,
                );

                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }

            if config.plot_conn_flow_control {
                let mark = std::time::Instant::now();
                info!("drawing connection flow control chart for {}...", label);
                conn_flow_control::plot_conn_flow_control(
                    &plot_params,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &chart_config,
                );
                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }

            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            if config.plot_sparks {
                let mark = std::time::Instant::now();
                info!("drawing sparks for {}...", label);

                stream_sparks::plot_sparks(
                    &config.sparks_layout,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &chart_config,
                    &chart_config,
                    &chart_config,
                    &chart_config,
                );

                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }

            if config.plot_multiplex {
                let multiplex_params = MultiplexPlotsParams {
                    clamp: ClampParams {
                        start: config.start,
                        end: config.end,
                        stream_y_max: config.stream_y_max,
                    },
                    colors: AppConfig::colors(config.dark_mode),
                    ..Default::default()
                };
                let mark = std::time::Instant::now();
                info!("drawing multiplex for {}...", label);
                stream_multiplex::plot_stream_multiplexing(
                    &multiplex_params,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &chart_config,
                );
                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }

            if config.plot_pending {
                let pending_params = PendingPlotParams {
                    clamp: ClampParams {
                        start: config.start,
                        end: config.end,
                        stream_y_max: config.stream_y_max,
                    },
                    chart_size: ChartSize {
                        width: 1600,
                        height: 600,
                    },
                    colors: AppConfig::colors(config.dark_mode),
                    display_chart_title: true,
                };

                info!("drawing pending chart for {}...", label);
                let mark = std::time::Instant::now();

                plots::pending::plot_pending(
                    &pending_params,
                    &config.filename,
                    ss,
                    &data.datastore,
                    &chart_config,
                );

                debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);
            }
        }
    }

    println!();

    report(&log_file, &config);

    print!("input logs parsed successfully, check output(s)");

    0
}
