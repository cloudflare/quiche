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

//! Reporting (tables etc.)

use events::sqlog_event_list;
use tabled::settings::Style;

use crate::config::AppConfig;
use crate::LogFileParseResult;

pub fn report(log_file: &LogFileParseResult, config: &AppConfig) {
    if config.report_text {
        for data in &log_file.data {
            if let Some(table) = text::request_timing_table(data, config) {
                println!(
                    "Request timing table for session ID: {:?}, app proto: {:?}, host: {:?}",
                    &data.datastore.session_id.unwrap_or(-1),
                    &data.datastore.application_proto,
                    &data.datastore
                        .host
                        .clone()
                        .unwrap_or("ERROR UNKNOWN".to_string())
                );
                println!("{}", table);
                println!();
            }

            text::print_stats(&data.datastore, &config.stats_config);
            println!();

            match &data.raw {
                crate::RawLogEvents::QlogJson { events: _ } => todo!(),
                crate::RawLogEvents::QlogJsonSeq { events } => {
                    let mut table = sqlog_event_list(events).build();
                    table.with(Style::sharp());
                    println!("Qlog events");
                    println!("{}", table);
                },
                crate::RawLogEvents::Netlog => todo!(),
            }
        }

        // TODO: make this more configurable
        text::print_packet_loss(&log_file.data);
        text::print_flow_control(&log_file.data);
    }

    if config.report_html {
        html::overview(log_file, config);
        html::closures(log_file, config);
        html::requests(log_file, config);
        html::event_list(log_file, config);
    }
}

mod events;
pub mod html;
mod text;
