// Copyright (C) 2024, Cloudflare, Inc.
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

use std::env;
use std::io::BufReader;
use std::result::Result;
use std::time;
use std::time::Instant;

use h3i::actions::h3::Action;
use h3i::client::connection_summary::ConnectionSummary;
use h3i::client::ClientError;
use h3i::prompts::h3::Prompter;
use h3i::recordreplay::qlog::QlogEvent;
use h3i::recordreplay::qlog::*;
use qlog::reader::QlogSeqReader;

use clap::App;
use clap::Arg;

fn main() -> Result<(), ClientError> {
    let mut log_builder = env_logger::builder();
    if env::var_os("RUST_LOG").is_none() {
        log_builder.filter_level(log::LevelFilter::Info);
    }

    log_builder.default_format_timestamp_nanos(true).init();

    let config = match config_from_clap() {
        Ok(v) => v,

        Err(e) => {
            log::error!("Error loading configuration, exiting: {}", e);
            return Err(ClientError::Other("Invalid configuration".into()));
        },
    };

    let actions = match &config.qlog_input {
        Some(v) => read_qlog(v),
        None => prompt_frames(&config),
    };

    match sync_client(&config, &actions) {
        Ok(summary) => {
            log::debug!(
                "received connection_summary: {}",
                serde_json::to_string_pretty(&summary)
                    .unwrap_or_else(|e| e.to_string())
            );
        },

        Err(e) => {
            log::error!("error: {:?}", e);
        },
    }

    Ok(())
}

struct Config {
    library_config: h3i::config::Config,
    pub qlog_input: Option<String>,
    pub qlog_actions_output: bool,
}

fn config_from_clap() -> std::result::Result<Config, String> {
    let matches = App::new("h3i")
        .version("v0.1.0")
        .about("Interactive HTTP/3 console debugger")
        .arg(
            Arg::with_name("host:port")
                .help("Hostname and port of the HTTP/3 server")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("omit-sni")
                .long("omit-sni")
                .help("Omit the SNI from the TLS handshake")
                // Requires an OsStr, so we can parse to empty later on
                .takes_value(false)
        )
        .arg(
            Arg::with_name("connect-to")
                .long("connect-to")
                .help("Set a specific IP address to connect to, rather than use DNS resolution")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("no-verify")
                .long("no-verify")
                .help("Don't verify server's certificate."),
        )
        .arg(
            Arg::with_name("no-qlog-actions-output")
                .long("no-qlog-actions-output")
                .help("Don't output action sequence as qlog."),
        )
        .arg(
            Arg::with_name("qlog-input")
                .long("qlog-input")
                .help("Drive connection via qlog rather than cli.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("idle-timeout")
                .long("idle-timeout")
                .help("The QUIC idle timeout value in milliseconds.")
                .takes_value(true)
                .default_value("5000"),
        )
        .arg(
            Arg::with_name("max-data")
                .long("max-data")
                .help("Flow control limit for the connection in bytes")
                .takes_value(true)
                .default_value("10000000"),
        )
        .arg(
            Arg::with_name("max-stream-data-bidi-local")
                .long("max-stream-data-bidi-local")
                .help("Flow control limit for locally-initiated bidirectional streams in bytes.")
                .takes_value(true)
                .default_value("1000000"),
        )
        .arg(
            Arg::with_name("max-stream-data-bidi-remote")
                .long("max-stream-data-bidi-remote")
                .help("Flow control limit for remotely-initiated bidirectional streams in bytes.")
                .takes_value(true)
                .default_value("1000000"),
        )
        .arg(
            Arg::with_name("max-stream-data-uni")
                .long("max-stream-data-uni")
                .help("Flow control limit for unidirectional streams in bytes.")
                .takes_value(true)
                .default_value("1000000"),
        )
        .arg(
            Arg::with_name("max-streams-bidi")
                .long("max-streams-bidi")
                .help("Maximum count for concurrent remotely-initiated bidirectional streams.")
                .takes_value(true)
                .default_value("100"),
        )
        .arg(
            Arg::with_name("max-streams-uni")
                .long("max-streams-uni")
                .help("Maximum count for concurrent remotely-initiated unidirectional streams.")
                .takes_value(true)
                .default_value("100"),
        )
        .arg(
            Arg::with_name("max-window")
                .long("max-window")
                .help("Receiver window limit for the connection in bytes.")
                .takes_value(true)
                .default_value("25165824"),
        )
        .arg(
            Arg::with_name("max-stream-window")
                .long("max-stream-window")
                .help("Receiver window limit for a stream in bytes.")
                .takes_value(true)
                .default_value("16777216"),
        )
        .get_matches();

    let host_port = matches.value_of("host:port").unwrap().to_string();
    let omit_sni = matches.is_present("omit-sni");
    let connect_to: Option<String> =
        matches.value_of("connect-to").map(|s| s.to_string());
    let verify_peer = !matches.is_present("no-verify");
    let idle_timeout = matches
        .value_of("idle-timeout")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("idle-timeout input error {}", e))?;

    let max_data = matches
        .value_of("max-data")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-data input error {}", e))?;

    let max_stream_data_bidi_local = matches
        .value_of("max-stream-data-bidi-local")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-stream-data-bidi-local input error {}", e))?;

    let max_stream_data_bidi_remote = matches
        .value_of("max-stream-data-bidi-remote")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-stream-data-bidi-remote input error {}", e))?;

    let max_stream_data_uni = matches
        .value_of("max-stream-data-uni")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-stream-data-uni input error {}", e))?;

    let max_streams_bidi = matches
        .value_of("max-streams-bidi")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-streams-bidi input error {}", e))?;

    let max_streams_uni = matches
        .value_of("max-streams-uni")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-streams-uni input error {}", e))?;

    let max_window = matches
        .value_of("max-window")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-window input error {}", e))?;

    let max_stream_window = matches
        .value_of("max-stream-window")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| format!("max-stream-window input error {}", e))?;

    let qlog_actions_output = !matches.is_present("no-qlog-actions-output");
    let qlog_input = matches.value_of("qlog-input").and_then(|q| {
        std::path::Path::new(q)
            .file_name()
            .unwrap()
            .to_str()
            .map(|s| s.to_string())
    });

    let library_config = h3i::config::Config {
        host_port,
        omit_sni,
        connect_to,
        source_port: 0,
        verify_peer,
        idle_timeout,
        max_data,
        max_stream_data_bidi_local,
        max_stream_data_bidi_remote,
        max_stream_data_uni,
        max_streams_bidi,
        max_streams_uni,
        max_window,
        max_stream_window,
    };

    Ok(Config {
        qlog_input,
        qlog_actions_output,
        library_config,
    })
}

fn sync_client(
    config: &Config, actions: &[Action],
) -> Result<ConnectionSummary, ClientError> {
    h3i::client::sync_client::connect(&config.library_config, actions)
}

fn read_qlog(filename: &str) -> Vec<Action> {
    let file = std::fs::File::open(filename).expect("failed to open file");
    let reader = BufReader::new(file);

    let qlog_reader = QlogSeqReader::new(Box::new(reader)).unwrap();
    let mut actions = vec![];

    for event in qlog_reader {
        match event {
            qlog::reader::Event::Qlog(ev) => {
                let ac: H3Actions = (ev).into();
                actions.extend(ac.0);
            },

            qlog::reader::Event::Json(ev) => {
                let ac: H3Actions = (ev).into();
                actions.extend(ac.0);
            },
        }
    }

    actions
}

fn prompt_frames(config: &Config) -> Vec<Action> {
    let mut prompter = Prompter::with_config(&config.library_config);
    let actions = prompter.prompt();

    if !actions.is_empty() && config.qlog_actions_output {
        let writer = make_qlog_writer();
        let mut streamer = make_streamer(std::boxed::Box::new(writer));

        for action in &actions {
            let events: QlogEvents = action.into();
            for event in events {
                match event {
                    QlogEvent::Event { data, ex_data } => {
                        streamer.add_event_data_ex_now(*data, ex_data).ok();
                    },

                    QlogEvent::JsonEvent(mut ev) => {
                        // need to rewrite the event time
                        ev.time = Instant::now()
                            .duration_since(streamer.start_time())
                            .as_secs_f32() *
                            1000.0;
                        streamer.add_event(ev).ok();
                    },
                }
            }
        }
    }

    actions
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer() -> std::io::BufWriter<std::fs::File> {
    let mut path = std::env::current_dir().unwrap();
    let now = time::SystemTime::now();
    let filename = format!(
        "{}-qlog.sqlog",
        now.duration_since(time::UNIX_EPOCH).unwrap().as_millis()
    );
    path.push(filename.clone());

    log::info!("Session will be recorded to {}", filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

pub fn make_streamer(
    writer: Box<dyn std::io::Write + Send + Sync>,
) -> qlog::streamer::QlogStreamer {
    let vp = qlog::VantagePointType::Client;

    let trace = qlog::TraceSeq::new(
        qlog::VantagePoint {
            name: None,
            ty: vp,
            flow: None,
        },
        Some("h3i".into()),
        Some("h3i".into()),
        Some(qlog::Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        None,
    );

    let mut streamer = qlog::streamer::QlogStreamer::new(
        qlog::QLOG_VERSION.to_string(),
        Some("h3i".into()),
        Some("h3i".into()),
        None,
        time::Instant::now(),
        trace,
        qlog::events::EventImportance::Extra,
        writer,
    );

    streamer.start_log().ok();

    streamer
}
