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

//! The netlog crate is a reverse-engineered deserializer for the Chrome
//! [netlog] format. It supports QUIC and HTTP(/2 and /3) events.
//!
//! # Overview
//!
//! Chromium-based browsers allow users to enable detailed logging, netlog,
//! which is useful for debugging interoperability or performance issues. A
//! netlog file uses a kind of line-delimited JSON format. The first line
//! contains "constants", which are specific to the version of the software used
//! to generate the log. These constants are used for a form of compressed
//! encoding for the netlog events that appear on each subsequent newline.
//!
//! This crate supports parsing a netlog file and converting a subset of netlog
//! events into Rust structures, via Serde.
//!
//! # Example usage
//!
//! Assuming a netlog file name of `chrome-net-export-log-error.json`, the first
//! task is to create a `BufReader` for the file and initialize the netlog
//! constants.
//!
//! ```no_run
//! use netlog::read_netlog_constants;
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let mut reader =
//!     BufReader::new(File::open("chrome-net-export-log-error.json").unwrap());
//!
//! let constants = read_netlog_constants(&mut reader).unwrap();
//! ```
//!
//! Then move on to parsing the netlog file until the end.
//!
//! ```no_run
//! # use std::io::BufReader;
//! # use std::fs::File;
//! # use netlog::read_netlog_constants;
//! use netlog::read_netlog_record;
//! use netlog::EventHeader;
//! use netlog::h2::Http2SessionEvent;
//! use netlog::quic::QuicSessionEvent;
//! # let mut reader =
//! #    BufReader::new(File::open("chrome-net-export-log-error.json").unwrap());
//! # let constants = read_netlog_constants(&mut reader).unwrap();
//! // The second line of a netlog is `"events" [`, which can be skipped over.
//! read_netlog_record(&mut reader);
//!
//! while let Some(record) = read_netlog_record(&mut reader) {
//!     let res: Result<EventHeader, serde_json::Error> =
//!         serde_json::from_slice(&record);
//!
//!     match res {
//!         Ok(mut event_hdr) => {
//!             event_hdr.populate_strings(&constants);
//!             event_hdr.time_num = event_hdr.time.parse::<u64>().unwrap();
//!
//!             // Netlogs can hold many different sessions.
//!             // Application might want to track these separately
//!             if event_hdr.phase_string == "PHASE_BEGIN" {
//!                 match event_hdr.ty_string.as_str() {
//!                     "HTTP2_SESSION" => {
//!                         let ev: Http2SessionEvent =
//!                             serde_json::from_slice(&record).unwrap();
//!                         // Handle new session event ...
//!                     },
//!                     "QUIC_SESSION" => {
//!                         let ev: QuicSessionEvent =
//!                             serde_json::from_slice(&record).unwrap();
//!                         // Handle new session event ...
//!                     },
//!
//!                     // Ignore others
//!                     _ => (),
//!                 }
//!             }
//!
//!             // Try to parse other events.
//!             if let Some(ev) = netlog::parse_event(&event_hdr, &record) {
//!                 // Handle parsed event.
//!             }
//!         },
//!
//!         Err(e) => {
//!             println!("Error deserializing: {}", e);
//!             println!("input value {}", String::from_utf8_lossy(&record));
//!         },
//!     }
//! }
//! ```
//!
//! [netlog]:
//! (https://www.chromium.org/developers/design-documents/network-stack/netlog/)
use std::io::BufRead;

use serde::Deserialize;

use crate::constants::Constants;
use crate::constants::ConstantsLine;

#[derive(Deserialize, Debug, Default)]
pub struct EventSource {
    #[serde(skip)]
    pub start_time_int: u64,

    pub id: i64,
    pub start_time: String,
    #[serde(rename = "type")]
    pub ty: i64,
}

#[derive(Deserialize, Debug, Default)]
pub struct EventHeader {
    #[serde(skip)]
    pub ty_string: String,
    #[serde(skip)]
    pub phase_string: String,
    #[serde(skip)]
    pub time_num: u64,

    pub phase: i64,
    pub source: EventSource,
    pub time: String,
    #[serde(rename = "type")]
    pub ty: i64,
}

impl EventHeader {
    /// Populate the event details based on the provided netlog file constants.
    pub fn populate_strings(&mut self, constants: &constants::Constants) {
        self.ty_string = constants.log_event_types_id_keyed[&self.ty].clone();
        self.phase_string =
            constants.log_event_phase_id_keyed[&self.phase].clone();
    }
}

#[derive(Deserialize, Debug, Default)]
pub struct SourceDependency {
    pub id: i64,
    #[serde(rename = "type")]
    pub ty: i64,
}

/// The core netlog event type with several domain-specific variants.
#[derive(Debug)]
pub enum Event {
    Http(http::Event),
    H2(h2::Event),
    H3(h3::Event),
    Quic(quic::Event),
}

/// Read the netlog constants from a netlog file accessed by a BufRead.
pub fn read_netlog_constants<R: BufRead>(
    reader: &mut R,
) -> Result<Constants, serde_json::Error> {
    let mut buf = Vec::<u8>::new();

    // Read the constants line and replace the trailing comma (,) with a brace
    // (}) to close the object and make it parseable.
    let len = reader.read_until(b'\n', &mut buf).unwrap();
    buf[len - 2] = b'}';

    let res: Result<ConstantsLine, serde_json::Error> =
        serde_json::from_slice(&buf);

    match res {
        Ok(mut line) => {
            line.constants.populate_id_keyed();

            Ok(line.constants)
        },

        Err(e) => {
            log::error!("Error deserializing constants: {}", e);

            Err(e)
        },
    }
}

/// Reads a single record from a netlog file accessed by a BufRead.
pub fn read_netlog_record<R: BufRead>(reader: &mut R) -> Option<Vec<u8>> {
    let mut buf = Vec::<u8>::new();
    let size = reader.read_until(b'\n', &mut buf).unwrap();

    if size <= 1 {
        return None;
    }

    // After netlog events, line holds polledData struct. Ignore it and return
    if buf[0] != b'{' {
        return None;
    }

    // Remove trailing comma and newline
    buf.truncate(buf.len() - 2);

    // Last line of events closes array. Lets ignore it.
    if buf[buf.len() - 1] == b']' {
        buf.truncate(buf.len() - 1);
    }

    log::trace!(
        "read record={}",
        String::from_utf8(buf.clone()).expect("from_utf8 failed")
    );

    Some(buf)
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
pub fn parse_event(event_hdr: &EventHeader, event: &[u8]) -> Option<Event> {
    if event_hdr.ty_string.starts_with("HTTP_") {
        return http::parse_event(event_hdr, event);
    } else if event_hdr.ty_string.starts_with("HTTP2_") {
        return h2::parse_event(event_hdr, event);
    } else if event_hdr.ty_string.starts_with("HTTP3_") {
        return h3::parse_event(event_hdr, event);
    } else if event_hdr.ty_string.starts_with("QUIC") {
        return quic::parse_event(event_hdr, event);
    }

    None
}

pub mod constants;
pub mod h2;
pub mod h3;
pub mod http;
pub mod quic;
