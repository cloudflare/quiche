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

    // Create series store and populate with data
    let mut store = if let Some(sqlog_path) = input_path {
        println!("Loading sqlog from: {}", sqlog_path.display());
        load_from_sqlog(sqlog_path)?
    } else if use_demo {
        println!("Generating demo data...");
        let mut s = PacerSeriesStore::new();
        generate_demo_data(&mut s);
        s
    } else {
        eprintln!("Error: Must specify --input <sqlog_file> or --demo");
        std::process::exit(1);
    };

    // Extend lines to full width if requested
    if extend_lines {
        println!("Extending lines to full plot width...");
        store.extend_to_full_width();
    }

    // Print stats (demonstrating the auto-tracked statistics)
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

    // Render the plot
    let params = PacerPlotParams {
        extend_to_full_width: extend_lines,
        ..Default::default()
    };

    println!("\nRendering plot to: {}", output_path);
    render_to_format(&config, &params, &store, output_path)?;

    println!("Done!");
    Ok(())
}

/// Render to the appropriate format based on file extension.
fn render_to_format(
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

/// Generate demo data simulating pacing rate behavior.
fn generate_demo_data(store: &mut PacerSeriesStore) {
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

/// Load pacing data from an sqlog file.
fn load_from_sqlog(
    path: &Path,
) -> Result<PacerSeriesStore, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    // Parse the sqlog - need Box for QlogSeqReader
    let sqlog_reader = QlogSeqReader::new(Box::new(reader))?;
    let vantage_point = sqlog_reader.qlog.trace.vantage_point.ty.clone();

    // Collect events and build datastore
    let events: Vec<qlog::reader::Event> = sqlog_reader.into_iter().collect();
    let datastore =
        Datastore::with_sqlog_reader_events(&events, &vantage_point, true);

    // Build SeriesStore from Datastore (existing infrastructure)
    let series_store = SeriesStore::from_datastore(&datastore);

    // Bridge to PacerSeriesStore (new POC infrastructure)
    let pacer_store = PacerSeriesStore::from_series_store(&series_store);

    println!(
        "  Loaded {} pacing rate points from sqlog",
        pacer_store.pacing_rate.len()
    );

    Ok(pacer_store)
}
