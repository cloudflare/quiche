// Copyright (C) 2026, MokiMeow.
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
use std::io::Cursor;

const LOG: &str = include_str!("fixtures/reader.json");

fn check_log(line_ending: &str) {
    let contents = LOG.replace("\r\n", "\n").replace('\n', line_ending);
    let mut reader = Cursor::new(contents.as_bytes());
    let constants = qlog_dancer::netlog_with_reader(&mut reader).unwrap();
    assert_eq!(constants.log_event_types_id_keyed[&1], "HTTP2_SESSION");

    assert!(netlog::read_netlog_record(&mut reader).is_none());
    let record = netlog::read_netlog_record(&mut reader).unwrap();
    let event: netlog::EventHeader = serde_json::from_slice(&record).unwrap();
    assert_eq!(event.time, "42");

    let mut reader = Cursor::new(contents.as_bytes());
    let constants = qlog_dancer::netlog_with_reader(&mut reader).unwrap();
    let (data, sessions) = qlog_dancer::datastore::with_netlog_reader(
        &mut reader,
        HashSet::new(),
        &constants,
    );
    assert_eq!(data.len(), 1);
    assert_eq!(sessions.len(), 1);
    assert!(sessions.contains_key(&1));
}

#[test]
fn reads_lf_netlog_constants() {
    check_log("\n");
}

#[test]
fn reads_crlf_netlog_constants() {
    check_log("\r\n");
}
