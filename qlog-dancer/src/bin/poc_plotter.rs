// Copyright (C) 2026, Cloudflare, Inc.
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

//! POC Plotter - Demonstrates the new config-driven plotting approach.
//!
//! Usage:
//!   cargo run --bin poc_plotter -- [OPTIONS]
//!
//! Options:
//!   --input <PATH>     Path to sqlog file (required unless --demo)
//!   --config <PATH>    Path to config.toml (default: uses embedded defaults)
//!   --output <PATH>    Output PNG path (default: pacer_plot.png)
//!   --palette <NAME>   Override palette: "qvis" or "matplotlib"
//!   --demo             Generate demo data instead of reading qlog
//!   --extend           Extend lines to full plot width

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;

use clap::Arg;
use clap::Command;
use qlog::reader::QlogSeqReader;
use qlog_dancer::datastore::Datastore;
use qlog_dancer::poc_plots::config::PlotConfig;
#[cfg(feature = "cairo")]
use qlog_dancer::poc_plots::modules::pacer::render_pacer_to_eps;
#[cfg(feature = "cairo")]
use qlog_dancer::poc_plots::modules::pacer::render_pacer_to_pdf;
use qlog_dancer::poc_plots::modules::pacer::render_pacer_to_png;
use qlog_dancer::poc_plots::modules::pacer::render_pacer_to_svg;
use qlog_dancer::poc_plots::modules::pacer::PacerPlotParams;
use qlog_dancer::poc_plots::modules::pacer::PacerSeriesStore;

#[cfg(feature = "cairo")]
use qlog_dancer::poc_plots::modules::loss::render_loss_to_eps;
#[cfg(feature = "cairo")]
use qlog_dancer::poc_plots::modules::loss::render_loss_to_pdf;
use qlog_dancer::poc_plots::modules::loss::render_loss_to_png;
use qlog_dancer::poc_plots::modules::loss::render_loss_to_svg;
use qlog_dancer::poc_plots::modules::loss::LossPlotParams;
use qlog_dancer::poc_plots::modules::loss::LossSeriesStore;

use qlog_dancer::poc_plots::modules::conn_overview::render_overview_to_png;
use qlog_dancer::poc_plots::modules::conn_overview::render_overview_to_svg;
use qlog_dancer::poc_plots::modules::conn_overview::OverviewPlotParams;
use qlog_dancer::poc_plots::modules::conn_overview::OverviewSeriesStore;
use qlog_dancer::seriesstore::SeriesStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("poc_plotter")
        .version("0.1.0")
        .about("POC: Config-driven qlog plotting with matplotlib-style configuration")
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .help("Path to sqlog file")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .help("Path to config.toml file")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Output file path (format detected from extension: .png, .svg, .pdf, .eps)")
                .default_value("pacer_plot.png"),
        )
        .arg(
            Arg::new("palette")
                .long("palette")
                .short('p')
                .help("Override color palette")
                .value_parser(["qvis", "matplotlib", "palette99", "palette9999"]),
        )
        .arg(
            Arg::new("plot")
                .long("plot")
                .help("Plot type to render")
                .value_parser(["pacer", "loss", "overview"])
                .default_value("pacer"),
        )
        .arg(
            Arg::new("demo")
                .long("demo")
                .help("Generate demo data")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("extend")
                .long("extend")
                .help("Extend lines to full plot width")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // Load config
    let mut config =
        if let Some(config_path) = matches.get_one::<PathBuf>("config") {
            println!("Loading config from: {}", config_path.display());
            PlotConfig::from_file(config_path)?
        } else {
            println!("Using default config (embedded from config.toml)");
            PlotConfig::default()
        };

    // Override palette if specified
    if let Some(palette) = matches.get_one::<String>("palette") {
        config.lines.palette = palette.clone();
        println!("Using palette: {}", palette);
    }

    let output_path = matches.get_one::<String>("output").unwrap();
    let extend_lines = matches.get_flag("extend");
    let input_path = matches.get_one::<PathBuf>("input");
    let use_demo = matches.get_flag("demo");
    let plot_type = matches.get_one::<String>("plot").unwrap();

    match plot_type.as_str() {
        "loss" => {
            run_loss_plot(
                &config, input_path, use_demo, output_path,
            )?;
        },
        "overview" => {
            run_overview_plot(
                &config, input_path, use_demo, output_path,
            )?;
        },
        _ => {
            run_pacer_plot(
                &config, input_path, use_demo, extend_lines, output_path,
            )?;
        },
    }

    println!("Done!");
    Ok(())
}

fn run_pacer_plot(
    config: &PlotConfig, input_path: Option<&PathBuf>, use_demo: bool,
    extend_lines: bool, output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = if let Some(sqlog_path) = input_path {
        println!("Loading sqlog from: {}", sqlog_path.display());
        load_pacer_from_sqlog(sqlog_path)?
    } else if use_demo {
        println!("Generating demo data...");
        let mut s = PacerSeriesStore::new();
        generate_pacer_demo_data(&mut s);
        s
    } else {
        eprintln!("Error: Must specify --input <sqlog_file> or --demo");
        std::process::exit(1);
    };

    if extend_lines {
        println!("Extending lines to full plot width...");
        store.extend_to_full_width();
    }

    println!("\n=== Series Statistics (auto-tracked) ===");
    println!(
        "Pacing Rate: {} points, max={:?}, min={:?}",
        store.pacing_rate.len(),
        store.pacing_rate.y_max(),
        store.pacing_rate.y_min()
    );
    println!(
        "Delivery Rate: {} points, max={:?}, min={:?}",
        store.delivery_rate.len(),
        store.delivery_rate.y_max(),
        store.delivery_rate.y_min()
    );
    println!(
        "Send Rate: {} points, max={:?}, min={:?}",
        store.send_rate.len(),
        store.send_rate.y_max(),
        store.send_rate.y_min()
    );
    println!("Global Y Max: {:?}", store.global_y_max());
    println!(
        "Global X Range: {:?} - {:?}",
        store.global_x_min(),
        store.global_x_max()
    );

    let params = PacerPlotParams {
        extend_to_full_width: extend_lines,
        ..Default::default()
    };

    println!("\nRendering pacer plot to: {}", output_path);
    render_pacer_to_format(config, &params, &store, output_path)?;
    Ok(())
}

fn run_loss_plot(
    config: &PlotConfig, input_path: Option<&PathBuf>, use_demo: bool,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (store, last_event_time) = if let Some(sqlog_path) = input_path {
        println!("Loading sqlog from: {}", sqlog_path.display());
        load_loss_from_sqlog(sqlog_path)?
    } else if use_demo {
        println!("Generating loss demo data...");
        let mut s = LossSeriesStore::new();
        generate_loss_demo_data(&mut s);
        (s, None)
    } else {
        eprintln!("Error: Must specify --input <sqlog_file> or --demo");
        std::process::exit(1);
    };

    println!("\n=== Loss Statistics (auto-tracked) ===");
    println!(
        "Loss Spikes: {} events, max={:?}",
        store.lost_packets_delta.len(),
        store.lost_packets_delta.y_max()
    );
    println!(
        "Cumulative Lost: {} points, total={:?}",
        store.lost_packets.len(),
        store.cumulative_y_max()
    );
    println!(
        "X Range: {:?} - {:?}",
        store.global_x_min(),
        last_event_time.or(store.global_x_max())
    );

    let params = LossPlotParams {
        x_end: last_event_time,
        ..Default::default()
    };

    println!("\nRendering loss plot to: {}", output_path);
    render_loss_to_format(config, &params, &store, output_path)?;
    Ok(())
}

fn run_overview_plot(
    config: &PlotConfig, input_path: Option<&PathBuf>, use_demo: bool,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = if let Some(sqlog_path) = input_path {
        println!("Loading sqlog from: {}", sqlog_path.display());
        load_overview_from_sqlog(sqlog_path)?
    } else if use_demo {
        println!("Generating overview demo data...");
        generate_overview_demo_data()
    } else {
        eprintln!("Error: Must specify --input <sqlog_file> or --demo");
        std::process::exit(1);
    };

    println!("\n=== Overview Statistics ===");
    println!(
        "stream sends: {} points, loss spikes: {}, cwnd: {} points, RTT: {} points",
        store.stream_sends.cumulative_buffer_writes.len(),
        store.loss.lost_packets_delta.len(),
        store.congestion.cwnd.len(),
        store.rtt.smoothed_rtt.len(),
    );
    println!(
        "X Range: {:.0} - {:.0}",
        store.global_x_min(),
        store.global_x_max()
    );

    let params = OverviewPlotParams::default();

    println!("\nRendering overview plot to: {}", output_path);
    render_overview_to_format(config, &params, &store, output_path)?;
    Ok(())
}

/// Render overview to the appropriate format based on file extension.
fn render_overview_to_format(
    config: &PlotConfig, params: &OverviewPlotParams,
    store: &OverviewSeriesStore, output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = Path::new(output_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png")
        .to_lowercase();

    match ext.as_str() {
        "svg" => {
            println!("Format: SVG (vector)");
            render_overview_to_svg(config, params, store, output_path)
        },
        _ => {
            println!("Format: PNG (raster)");
            render_overview_to_png(config, params, store, output_path)
        },
    }
}

/// Render pacer plot to the appropriate format based on file extension.
fn render_pacer_to_format(
    config: &PlotConfig, params: &PacerPlotParams, store: &PacerSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = Path::new(output_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png")
        .to_lowercase();

    match ext.as_str() {
        "svg" => {
            println!("Format: SVG (vector)");
            render_pacer_to_svg(config, params, store, output_path)
        },
        #[cfg(feature = "cairo")]
        "pdf" => {
            println!("Format: PDF (vector, Cairo)");
            render_pacer_to_pdf(config, params, store, output_path)
        },
        #[cfg(feature = "cairo")]
        "eps" => {
            println!("Format: EPS (vector, Cairo)");
            render_pacer_to_eps(config, params, store, output_path)
        },
        #[cfg(not(feature = "cairo"))]
        "pdf" | "eps" => {
            eprintln!(
                "Error: PDF/EPS output requires the 'cairo' feature.\n\
                 Rebuild with: cargo build --features cairo\n\
                 System dependencies:\n\
                   - Linux: sudo apt install libcairo2-dev libpango1.0-dev\n\
                   - macOS: brew install cairo pango"
            );
            std::process::exit(1);
        },
        _ => {
            println!("Format: PNG (raster)");
            render_pacer_to_png(config, params, store, output_path)
        },
    }
}

/// Render loss plot to the appropriate format based on file extension.
fn render_loss_to_format(
    config: &PlotConfig, params: &LossPlotParams, store: &LossSeriesStore,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = Path::new(output_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png")
        .to_lowercase();

    match ext.as_str() {
        "svg" => {
            println!("Format: SVG (vector)");
            render_loss_to_svg(config, params, store, output_path)
        },
        #[cfg(feature = "cairo")]
        "pdf" => {
            println!("Format: PDF (vector, Cairo)");
            render_loss_to_pdf(config, params, store, output_path)
        },
        #[cfg(feature = "cairo")]
        "eps" => {
            println!("Format: EPS (vector, Cairo)");
            render_loss_to_eps(config, params, store, output_path)
        },
        #[cfg(not(feature = "cairo"))]
        "pdf" | "eps" => {
            eprintln!(
                "Error: PDF/EPS output requires the 'cairo' feature.\n\
                 Rebuild with: cargo build --features cairo\n\
                 System dependencies:\n\
                   - Linux: sudo apt install libcairo2-dev libpango1.0-dev\n\
                   - macOS: brew install cairo pango"
            );
            std::process::exit(1);
        },
        _ => {
            println!("Format: PNG (raster)");
            render_loss_to_png(config, params, store, output_path)
        },
    }
}

/// Generate demo data simulating pacing rate behavior.
fn generate_pacer_demo_data(store: &mut PacerSeriesStore) {
    // Simulate a connection with varying pacing rate
    // Starts slow (slow start), ramps up, then stabilizes

    // Pacing rate: starts at 10KB/s, ramps to 1MB/s, then fluctuates
    let pacing_points = vec![
        (0.0, 10_000u64),
        (100.0, 50_000),
        (200.0, 150_000),
        (300.0, 400_000),
        (400.0, 800_000),
        (500.0, 1_000_000),
        (600.0, 950_000),
        (700.0, 1_100_000),
        (800.0, 900_000),
        (900.0, 1_050_000),
        (1000.0, 1_000_000),
    ];

    for (x, y) in pacing_points {
        store.pacing_rate.push_interp(x, y);
    }

    // Delivery rate: slightly lower than pacing rate (realistic)
    let delivery_points = vec![
        (0.0, 8_000u64),
        (100.0, 45_000),
        (200.0, 140_000),
        (300.0, 380_000),
        (400.0, 750_000),
        (500.0, 920_000),
        (600.0, 900_000),
        (700.0, 1_000_000),
        (800.0, 850_000),
        (900.0, 980_000),
        (1000.0, 950_000),
    ];

    for (x, y) in delivery_points {
        store.delivery_rate.push_interp(x, y);
    }

    // Send rate: tracks pacing rate closely
    let send_points = vec![
        (0.0, 9_500u64),
        (100.0, 48_000),
        (200.0, 148_000),
        (300.0, 395_000),
        (400.0, 790_000),
        (500.0, 990_000),
        (600.0, 940_000),
        (700.0, 1_090_000),
        (800.0, 890_000),
        (900.0, 1_040_000),
        (1000.0, 990_000),
    ];

    for (x, y) in send_points {
        store.send_rate.push_interp(x, y);
    }
}

/// Generate demo data simulating packet loss events.
fn generate_loss_demo_data(store: &mut LossSeriesStore) {
    // Simulate a connection with sporadic loss events
    // Early phase: no loss
    // Mid phase: some loss bursts (congestion)
    // Late phase: occasional single losses

    let loss_events: Vec<(f32, u64, u64)> = vec![
        // (time_ms, packets_delta, cumulative)
        (150.0, 2, 2),
        (300.0, 5, 7),    // burst
        (310.0, 3, 10),   // burst continues
        (500.0, 1, 11),
        (650.0, 8, 19),   // large burst
        (660.0, 4, 23),
        (800.0, 1, 24),
        (950.0, 2, 26),
    ];

    for (time, delta, cumulative) in loss_events {
        store.lost_packets_delta.push(time, delta);
        store.lost_packets.push(time, cumulative);
        store.lost_bytes_delta.push(time, delta * 1250);
        store.lost_bytes.push(time, cumulative * 1250);
    }
}

/// Load pacing data from an sqlog file.
fn load_pacer_from_sqlog(
    path: &Path,
) -> Result<PacerSeriesStore, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let sqlog_reader = QlogSeqReader::new(Box::new(reader))?;
    let vantage_point = sqlog_reader.qlog.trace.vantage_point.ty.clone();

    let events: Vec<qlog::reader::Event> = sqlog_reader.into_iter().collect();
    let datastore =
        Datastore::with_sqlog_reader_events(&events, &vantage_point, true);

    let series_store = SeriesStore::from_datastore(&datastore);

    let pacer_store = PacerSeriesStore::from_series_store(&series_store);

    println!(
        "  Loaded {} pacing rate points from sqlog",
        pacer_store.pacing_rate.len()
    );

    Ok(pacer_store)
}

/// Load loss data from an sqlog file.
fn load_loss_from_sqlog(
    path: &Path,
) -> Result<(LossSeriesStore, Option<f32>), Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let sqlog_reader = QlogSeqReader::new(Box::new(reader))?;
    let vantage_point = sqlog_reader.qlog.trace.vantage_point.ty.clone();

    let events: Vec<qlog::reader::Event> = sqlog_reader.into_iter().collect();
    let datastore =
        Datastore::with_sqlog_reader_events(&events, &vantage_point, true);

    let last_event_time = datastore.last_event_time;
    let loss_store = LossSeriesStore::from_datastore(&datastore);

    println!(
        "  Loaded {} loss spike events from sqlog (trace duration: {:.0}ms)",
        loss_store.lost_packets_delta.len(),
        last_event_time
    );

    Ok((loss_store, Some(last_event_time)))
}

/// Generate demo data for the combined overview plot.
fn generate_overview_demo_data() -> OverviewSeriesStore {
    let mut store = OverviewSeriesStore::new();

    // Stream sends: cumulative buffer writes ramping up
    let write_points: Vec<(f32, u64)> = vec![
        (0.0, 0),
        (50.0, 15_000),
        (100.0, 60_000),
        (200.0, 180_000),
        (300.0, 250_000),
        (400.0, 350_000),
        (500.0, 500_000),
        (600.0, 650_000),
        (700.0, 750_000),
        (800.0, 900_000),
        (900.0, 1_000_000),
        (1000.0, 1_100_000),
    ];
    for (x, y) in &write_points {
        store.stream_sends.cumulative_buffer_writes.push(*x, *y);
    }

    // Received MAX_DATA: flow control window
    let max_data_points: Vec<(f32, u64)> = vec![
        (0.0, 100_000),
        (200.0, 300_000),
        (400.0, 600_000),
        (600.0, 900_000),
        (800.0, 1_200_000),
    ];
    for (x, y) in max_data_points {
        store.stream_sends.received_max_data.push(x, y);
    }

    // Loss events at 300ms and 650ms (matching cwnd drops)
    let loss_events: Vec<(f32, u64, u64)> = vec![
        (300.0, 5, 5),
        (310.0, 3, 8),
        (650.0, 8, 16),
        (660.0, 4, 20),
        (800.0, 1, 21),
    ];
    for (time, delta, cumulative) in loss_events {
        store.loss.lost_packets_delta.push(time, delta);
        store.loss.lost_packets.push(time, cumulative);
    }

    // Congestion: cwnd ramps up, drops on loss, recovers
    let cwnd_points: Vec<(f32, u64)> = vec![
        (0.0, 14_720),
        (50.0, 29_440),
        (100.0, 58_880),
        (150.0, 117_760),
        (200.0, 200_000),
        (250.0, 280_000),
        (300.0, 140_000),
        (350.0, 160_000),
        (400.0, 200_000),
        (500.0, 280_000),
        (600.0, 320_000),
        (650.0, 160_000),
        (700.0, 180_000),
        (800.0, 240_000),
        (900.0, 300_000),
        (1000.0, 340_000),
    ];
    for (x, y) in cwnd_points {
        store.congestion.cwnd.push(x, y);
    }

    // bytes_in_flight
    let bif_points: Vec<(f32, u64)> = vec![
        (0.0, 10_000),
        (100.0, 50_000),
        (200.0, 180_000),
        (300.0, 130_000),
        (400.0, 170_000),
        (500.0, 250_000),
        (600.0, 300_000),
        (650.0, 150_000),
        (700.0, 160_000),
        (800.0, 220_000),
        (900.0, 270_000),
        (1000.0, 310_000),
    ];
    for (x, y) in bif_points {
        store.congestion.bytes_in_flight.push(x, y);
    }

    // RTT: relatively stable with spikes during loss
    let rtt_points: Vec<(f32, f32)> = vec![
        (0.0, 15.0),
        (50.0, 14.5),
        (100.0, 15.2),
        (150.0, 16.0),
        (200.0, 18.0),
        (250.0, 22.0),
        (300.0, 45.0),
        (350.0, 20.0),
        (400.0, 16.0),
        (500.0, 15.5),
        (600.0, 17.0),
        (650.0, 38.0),
        (700.0, 18.0),
        (800.0, 15.5),
        (900.0, 15.0),
        (1000.0, 15.2),
    ];
    for (x, y) in &rtt_points {
        store.rtt.smoothed_rtt.push(*x, *y);
        store.rtt.latest_rtt.push(*x, y * 1.1);
        store.rtt.min_rtt.push(*x, 14.0f32.min(*y));
    }

    store
}

/// Load overview data from an sqlog file.
fn load_overview_from_sqlog(
    path: &Path,
) -> Result<OverviewSeriesStore, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let sqlog_reader = QlogSeqReader::new(Box::new(reader))?;
    let vantage_point = sqlog_reader.qlog.trace.vantage_point.ty.clone();

    let events: Vec<qlog::reader::Event> = sqlog_reader.into_iter().collect();
    let datastore =
        Datastore::with_sqlog_reader_events(&events, &vantage_point, true);

    let store = OverviewSeriesStore::from_datastore(&datastore);

    println!(
        "  Loaded overview: stream_sends={}, loss={}, cwnd={}, rtt={}",
        store.stream_sends.cumulative_buffer_writes.len(),
        store.loss.lost_packets_delta.len(),
        store.congestion.cwnd.len(),
        store.rtt.smoothed_rtt.len(),
    );

    Ok(store)
}
