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

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use config::AppConfig;
use datastore::Datastore;
use datastore::NetlogSession;
use log::debug;
use log::error;

use qlog::reader::QlogSeqReader;
use qlog::Qlog;

use serde::ser::Serialize;

use crate::wirefilter::filter_sqlog_events;

pub type QlogPointu64 = (f32, u64);
pub type QlogPointf32 = (f32, f32);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Copy, Clone)]
pub enum PacketType {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
    VersionNegotiation,
    Unknown,
}

impl PacketType {
    pub fn from_qlog_packet_type(ty: &qlog::events::quic::PacketType) -> Self {
        match ty {
            qlog::events::quic::PacketType::Initial => PacketType::Initial,
            qlog::events::quic::PacketType::Handshake => PacketType::Handshake,
            qlog::events::quic::PacketType::ZeroRtt => PacketType::ZeroRtt,
            qlog::events::quic::PacketType::OneRtt => PacketType::OneRtt,
            qlog::events::quic::PacketType::Retry => PacketType::Retry,
            qlog::events::quic::PacketType::VersionNegotiation =>
                PacketType::VersionNegotiation,
            qlog::events::quic::PacketType::Unknown => PacketType::Unknown,
        }
    }

    pub fn from_netlog_packet_header(
        header_format: &str, long_header_type: &Option<String>,
    ) -> Self {
        match header_format {
            "IETF_QUIC_LONG_HEADER_PACKET" => match long_header_type {
                Some(v) => match v.as_str() {
                    "INITIAL" => PacketType::Initial,
                    "HANDSHAKE" => PacketType::Handshake,
                    _ => PacketType::Unknown,
                },

                None => PacketType::Unknown,
            },

            "IETF_QUIC_SHORT_HEADER_PACKET" => PacketType::OneRtt,

            _ => PacketType::Unknown,
        }
    }

    pub fn from_netlog_encryption_level(encryption_level: &str) -> Self {
        match encryption_level {
            "ENCRYPTION_INITIAL" => PacketType::Initial,

            "ENCRYPTION_HANDSHAKE" => PacketType::Handshake,

            "ENCRYPTION_ZERO_RTT" => PacketType::ZeroRtt,

            "ENCRYPTION_FORWARD_SECURE" => PacketType::OneRtt,

            _ => PacketType::Unknown,
        }
    }
}

#[derive(Debug)]
pub enum SerializationFormat {
    QlogJson,
    QlogJsonSeq,
    NetlogJson,
    Unknown,
}

impl SerializationFormat {
    pub fn from_file_extension(extension: &str) -> Self {
        match extension {
            "qlog" => SerializationFormat::QlogJson,
            "sqlog" => SerializationFormat::QlogJsonSeq,
            "json" => Self::NetlogJson,
            _ => SerializationFormat::Unknown,
        }
    }
}

pub struct VantagePointTypeShim {
    pub inner: qlog::VantagePointType,
}

impl Default for VantagePointTypeShim {
    fn default() -> Self {
        VantagePointTypeShim {
            inner: qlog::VantagePointType::Unknown,
        }
    }
}

impl std::fmt::Display for VantagePointTypeShim {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

pub struct LogFileDetails {
    pub log_version: String,
    pub log_format: String,
    pub qlog_vantage_point_type: VantagePointTypeShim,
    pub sessions: BTreeMap<i64, NetlogSession>,
}

pub enum RawLogEvents {
    QlogJson { events: Vec<qlog::events::Event> },
    QlogJsonSeq { events: Vec<qlog::reader::Event> },
    Netlog,
}

pub struct LogFileData {
    pub datastore: Datastore,
    pub raw: RawLogEvents,
}

pub struct LogFileParseResult {
    pub details: LogFileDetails,
    pub data: Vec<LogFileData>,
}

pub fn parse_log_file(
    config: &AppConfig,
) -> Result<LogFileParseResult, Box<dyn Error>> {
    match config.log_format {
        SerializationFormat::QlogJson => {
            println!("parsing qlog as JSON...");
            let mark = std::time::Instant::now();
            let qlog = read_qlog_from_file(config.file.clone())?;
            let details = LogFileDetails {
                log_version: qlog.qlog_version.clone(),
                log_format: qlog.qlog_format.clone(),
                qlog_vantage_point_type: VantagePointTypeShim {
                    inner: qlog.traces[0].vantage_point.ty.clone(),
                },
                sessions: BTreeMap::new(),
            };
            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            println!("populating datastore...");
            let mark = std::time::Instant::now();
            // TODO: support more than one trace in a file
            let datastore = Datastore::with_qlog_events(
                &qlog.traces[0].events,
                &details.qlog_vantage_point_type.inner,
                !config.ignore_acks,
            );
            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            let raw = RawLogEvents::QlogJson {
                events: qlog.traces[0].events.clone(),
            };

            Ok(LogFileParseResult {
                details,
                data: vec![LogFileData { datastore, raw }],
            })
        },

        SerializationFormat::QlogJsonSeq => {
            println!("parsing qlog as JSON-SEQ...");
            let mark = std::time::Instant::now();

            let (qlog_reader, details) = qlog_seq_reader(config)?;

            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            println!("populating datastore...");
            let mark = std::time::Instant::now();
            let events: Vec<qlog::reader::Event> =
                qlog_reader.into_iter().collect();
            let datastore: Datastore = Datastore::with_sqlog_reader_events(
                &events,
                &details.qlog_vantage_point_type.inner,
                !config.ignore_acks,
            );
            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            let events = if let Some(filter) = &config.qlog_wirefilter {
                filter_sqlog_events(events, filter)
            } else {
                events
            };

            let raw = RawLogEvents::QlogJsonSeq { events };

            Ok(LogFileParseResult {
                details,
                data: vec![LogFileData { datastore, raw }],
            })
        },

        SerializationFormat::NetlogJson => {
            println!("setting up parsing file as netlog...");
            let mark = std::time::Instant::now();

            let file = std::fs::File::open(config.file.clone())?;
            let mut reader = BufReader::new(file);

            let constants = netlog_with_reader(&mut reader).unwrap();

            // trace!("{:?}", constants);
            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            println!("parsing file ...");
            println!("Filtering on hostnames: {:#?}", config.netlog_filter);
            let mark = std::time::Instant::now();

            let (data, sessions) = datastore::with_netlog_reader(
                &mut reader,
                config.netlog_filter.clone(),
                &constants,
            );
            debug!("\tcomplete in {:?}", std::time::Instant::now() - mark);

            let details = LogFileDetails {
                log_version: constants.log_format_version.to_string(),
                log_format: "Chrome netlog".to_string(),
                qlog_vantage_point_type: VantagePointTypeShim {
                    inner: qlog::VantagePointType::Client,
                },
                sessions,
            };

            Ok(LogFileParseResult { details, data })
        },

        _ => {
            error!("Unknown log file format for {}", config.filename);
            Err("total fail".into())
        },
    }
}

pub fn read_qlog_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<Qlog, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let qlog = serde_json::from_reader(reader)?;

    Ok(qlog)
}

pub fn qlog_seq_reader(
    config: &AppConfig,
) -> Result<(QlogSeqReader<'_>, LogFileDetails), Box<dyn Error>> {
    let file = std::fs::File::open(config.file.clone())?;
    let reader = BufReader::new(file);

    let qlog_reader = QlogSeqReader::new(Box::new(reader))
        .map_err(|e| {
            std::io::Error::other(format!("problem reading file! {}", e))
        })
        .unwrap();
    let log_file_details = LogFileDetails {
        log_version: qlog_reader.qlog.qlog_version.clone(),
        log_format: qlog_reader.qlog.qlog_format.clone(),
        qlog_vantage_point_type: VantagePointTypeShim {
            inner: qlog_reader.qlog.trace.vantage_point.ty.clone(),
        },
        sessions: BTreeMap::new(),
    };

    Ok((qlog_reader, log_file_details))
}

pub fn netlog_with_reader<R: std::io::BufRead>(
    reader: &mut R,
) -> Result<netlog::constants::Constants, Box<dyn Error>> {
    // Netlog format is sort of newline-delimited. It starts off creating a JSON
    // object, within that is an object containing constants, followed by an
    // array of line-delimited events. This franken-JSON needs a bit of molding
    // to fit serde parsing.
    let mut buf = Vec::<u8>::new();

    // read the constants line
    let len = reader.read_until(b'\n', &mut buf).unwrap();

    // replace the trailing comma (,) with a brace (}) to close the object and
    // make it parseable.
    buf[len - 2] = b'}';

    let res: Result<netlog::constants::ConstantsLine, serde_json::Error> =
        serde_json::from_slice(&buf);

    match res {
        Ok(mut line) => {
            line.constants.populate_id_keyed();

            Ok(line.constants)
        },

        Err(e) => {
            error!("Error deserializing: {}", e);

            // Just swallow the failure and move on

            Err(e.into())
        },
    }
}

pub fn stringify_last<T>(src: &[T]) -> String
where
    T: std::fmt::Debug,
{
    if src.len() == 1 {
        "n/a".to_string()
    } else {
        format!("{:?}", src.last().unwrap())
    }
}

// slight hack: duplicate the previous point so
// that no misleading line interpolation occurs
fn push_interp<X: Clone, Y: Clone>(collection: &mut Vec<(X, Y)>, value: (X, Y)) {
    let prev = collection.last().cloned();
    let new_time = value.0.clone();

    if let Some((_, y)) = prev {
        collection.push((new_time, y));
    }

    collection.push(value)
}

fn create_file_recursive(filename: &str) -> std::io::Result<File> {
    let path = std::path::Path::new(filename);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    File::create(filename)
}

pub fn category_and_type_from_name(name: &str) -> (String, String) {
    let mut category = "".to_string();
    let mut ty = "".to_string();

    let split: Vec<&str> = name.split(':').collect();
    if let Some(cat) = split.first() {
        category = cat.to_string();
    }
    if let Some(t) = split.get(1) {
        ty = t.to_string();
    }

    (category, ty)
}
pub fn category_and_type_from_event<T: Serialize>(ev: &T) -> (String, String) {
    let name = serde_json::to_value(ev).unwrap()["name"]
        .to_string()
        .replace("\"", "");
    category_and_type_from_name(&name)
}

pub mod config;
pub mod datastore;
pub mod plots;
pub mod reports;
pub mod request_stub;
pub mod seriesstore;
#[cfg(target_arch = "wasm32")]
pub mod web;
pub mod wirefilter;
