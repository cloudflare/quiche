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

use table_to_html::html::Attribute;
use table_to_html::html::HtmlElement;
use table_to_html::html::HtmlValue;
use table_to_html::html::HtmlVisitorMut;
use table_to_html::HtmlTable;
use tabled::Table;

use crate::create_file_recursive;
use crate::reports::events::sqlog_event_list;
use crate::reports::text::request_timing_table;
use crate::AppConfig;
use crate::LogFileParseResult;
use std::io::Write;

const HTML_INCLUDES: &str = r#"
<script src="https://code.jquery.com/jquery-3.7.0.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
"#;

const TABLE_INIT_SCRIPT: &str = r#"
<script type="text/javascript">
    window.addEventListener("load", (event) => {

        let prefers = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        let html = document.querySelector('html');

        html.classList.add(prefers);
        html.setAttribute('data-bs-theme', prefers);

        new DataTable('table.log-dancer-table',
        {
            paging: false,
            dom: '<"center" flpti  >'
        });

        let loading = document.getElementById("loading");
        loading.style.visibility = 'hidden';

        let tables = document.getElementById("tables");
        tables.style.visibility = 'visible';
    });
</script>
"#;

const REQUEST_TABLE_INIT_SCRIPT: &str = r#"
<script type="text/javascript">
    window.addEventListener("load", (event) => {

        let prefers = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        let html = document.querySelector('html');

        html.classList.add(prefers);
        html.setAttribute('data-bs-theme', prefers);

        new DataTable('table.log-dancer-table',
        {
            paging: false,
            dom: '<"center" flpti  >',
            columnDefs: [
                {targets: [0,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19], type: 'html-num'}
            ]
        });

        let loading = document.getElementById("loading");
        loading.style.visibility = 'hidden';

        let tables = document.getElementById("tables");
        tables.style.visibility = 'visible';
    });
</script>
"#;

const SESSIONS_STYLES: &str = r#"
<style>
    .center {
  margin: auto;
  width: 90%;
  padding: 10px;
}

.yellow {
    color: yellow
}

.red {
    color: red
}

.green {
    color: limegreen
}
</style>
"#;

fn inject_table_id_class(
    input: &HtmlTable, id: Option<String>, class: Option<String>,
) -> String {
    let id = if let Some(i) = id {
        format!("id='{i}'")
    } else {
        "".to_string()
    };
    let class = if let Some(c) = class {
        format!("class='{c}'")
    } else {
        "".to_string()
    };
    let replaced = format!("<table {id} {class}>");

    input.to_string().replace("<table>", &replaced)
}

pub fn overview(log_file: &LogFileParseResult, config: &AppConfig) {
    let mut h2 = vec![];
    let mut quic = vec![];

    for data in &log_file.data {
        if let Some(h2_close) = &data.datastore.h2_session_close {
            h2.push(h2_close);
        }

        if let Some(quic_close) = &data.datastore.quic_session_close {
            quic.push(quic_close);
        }
    }

    let filename = format!("{}-reports/overview.html", config.filename);
    let mut file = create_file_recursive(&filename).unwrap();

    file.write_all(HTML_INCLUDES.as_bytes()).unwrap();
    file.write_all(TABLE_INIT_SCRIPT.as_bytes()).unwrap();
    file.write_all(SESSIONS_STYLES.as_bytes()).unwrap();
    file.write_all(r#"<html>
    <head><head>
    <body>
        <div>
            <h1 class="center">Session Overview</h1>
            <p class="center">This page lists all the sessions (aka connections)
            that were present in a log file. It is possible to filter only specific
            SNIs for analysis using the qlog-dancer `--netlog-filter` option.</p>
            <p class ="center">Analysed session detailed information is presented in
            <a href="closures.html">session terminations</a>
            and <a href="requests.html">requests breakdown</a>.</p>
            "#.as_bytes()).unwrap();

    let all_table = HtmlTable::with_header(Vec::<Vec<String>>::from(
        Table::builder(log_file.details.sessions.values()),
    ));
    file.write_all(
        inject_table_id_class(
            &all_table,
            Some("all_sessions".to_string()),
            Some(
                "log-dancer-table cell-border hover compact order-column"
                    .to_string(),
            ),
        )
        .as_bytes(),
    )
    .unwrap();

    file.write_all(
        r#"
        </div>
    </body>
    <html>"#
            .as_bytes(),
    )
    .unwrap();
}

pub fn closures(log_file: &LogFileParseResult, config: &AppConfig) {
    let mut h2 = vec![];
    let mut quic = vec![];

    for data in &log_file.data {
        if let Some(h2_close) = &data.datastore.h2_session_close {
            h2.push(h2_close);
        }

        if let Some(quic_close) = &data.datastore.quic_session_close {
            quic.push(quic_close);
        }
    }

    let filename = format!("{}-reports/closures.html", config.filename);
    let mut file = create_file_recursive(&filename).unwrap();

    file.write_all(HTML_INCLUDES.as_bytes()).unwrap();
    file.write_all(TABLE_INIT_SCRIPT.as_bytes()).unwrap();
    file.write_all(SESSIONS_STYLES.as_bytes()).unwrap();
    file.write_all(r#"<html>
    <head><head>
    <body>
        <div>
            <h1 class="center">Session Overview</h1>
            <p class="center">This page lists all the sessions (aka connections)
            that were present in a log file and filtered into analysis using the
            `--netlog-filter` option. Connections are split by HTTP version. A single SNI might
            have multiple sessions, and it might use multiple HTTP versions. The reason that
            each session is closed is also captured in the Error column (and subsequent columns).
            A log that is closed before a session is terminated will not show any value in the
            columns.</p>
            <h2 class="center">HTTP/2 Connections</h2>"#.as_bytes()).unwrap();

    let mut h2_html_table =
        HtmlTable::with_header(Vec::<Vec<String>>::from(Table::builder(h2)));
    h2_html_table.visit_mut(H2ClosureTableDecorator { i: 0 });

    file.write_all(
        inject_table_id_class(
            &h2_html_table,
            Some("h2_close".to_string()),
            Some(
                "log-dancer-table cell-border hover compact order-column"
                    .to_string(),
            ),
        )
        .as_bytes(),
    )
    .unwrap();

    file.write_all(
        r#"
            <h2 class="center">HTTP/3 & QUIC Connections</h2>"#
            .as_bytes(),
    )
    .unwrap();

    let mut quic_html_table =
        HtmlTable::with_header(Vec::<Vec<String>>::from(Table::builder(quic)));
    quic_html_table.visit_mut(QUICClosureTableDecorator { i: 0 });
    file.write_all(
        inject_table_id_class(
            &quic_html_table,
            Some("quic_close".to_string()),
            Some(
                "log-dancer-table cell-border hover compact order-column"
                    .to_string(),
            ),
        )
        .as_bytes(),
    )
    .unwrap();

    file.write_all(
        r#"
        </div>
    </body>
    <html>"#
            .as_bytes(),
    )
    .unwrap();
}

pub fn requests(log_file: &LogFileParseResult, config: &AppConfig) {
    let filename = format!("{}-reports/requests.html", config.filename);

    let mut file = create_file_recursive(&filename).unwrap();

    file.write_all(HTML_INCLUDES.as_bytes()).unwrap();
    file.write_all(REQUEST_TABLE_INIT_SCRIPT.as_bytes())
        .unwrap();
    file.write_all(SESSIONS_STYLES.as_bytes()).unwrap();
    file.write_all(
        r#"<html>
    <head><head>
    <body>
        <h1 class="center">Summary of All HTTP Requests</h1>
        <div class="center" id="loading">
            <strong>Loading data...</strong>
            <div class="spinner-border" role="status">
            </div>
        </div>
        <div class="center">
            <p>This page provides information about the requests & responses in a connection.</p>
            <p> Each individual table represents an HTTP session with a unique ID. Each session is bound
            to an SNI and has a version. There can be multiple connections to the same SNI depending on the
            client's behaviour.</p>
            <p>In each table, a single row represents a request & response. The columns expressing different properties:</p>
            <details>
                <Summary>Click to expand</Summary>
                <p>
                <ul>
                    <li><strong>ID</strong> - the stream ID of the request & response</li>
                    <li><strong>Method</strong> - the request Method</li>
                    <li><strong>Host</strong> - the request Host (or authority). Due to connection coalescing, this value can be dfifferent from the session SNI</li>
                    <li><strong>Path</strong> - the request Path</li>
                    <li><strong>Status</strong> - the response Status</li>
                    <li><strong>Response Content-Length</strong> - for downloads; the value of the response Content-Length, if any. A response can omit this header. </li>
                    <li><strong>Response Transferred</strong> - for downloads; the actual number of bytes of response that were received. This can be less than Response Content-Length, indicating that the request or connection was terminated early.</li>
                    <li><strong>Download Duration (d2d) (ms)</strong> - the time duration between receiving the first and last DATA frame. This can be 0 for various reasons.</li>
                    <li><strong>Download Rate (d2d) (Mbps)</strong> - the download rate, in megabits/s, between first and last DATA frames. This number has caveats - can be very high if data size or durations are small.</li>
                    <li><strong>Download Duration (h2d) (ms)</strong> - the time duration between receiving the first HEADERS and last DATA frame. This can be 0 for various reasons.</li>
                    <li><strong>Dowload Rate (h2d) (Mbps)</strong> - the download rate, in megabits/s, between first HEADERS and last DATA frames. This number has caveats - can be very high if data size or durations are small.</li>
                    <li><strong>Client Tx Hdr, Rx First Data</strong> - the duration between the client sending a HEADERS frame, and the first DATA frame being received. This is analagous to TTFB.</li>
                    <li><strong>Client Tx Hdr, Rx Last Data</strong> - the duration between the client sending a HEADERS frame, and the last DATA frame being received. This is analagous to TTLB.</li>
                    <li><strong>Request Content-Length</strong> - for uploads; the value of the request Content-Length, if any. A request can omit this header. </li>
                    <li><strong>Request Transferred</strong> - for uploads; the actual number of bytes of request that were sent. This can be less than Request Content-Length, indicating that the request or connection was terminated early.</li>
                    <li><strong>Upload Duration (ms)</strong> - the time duration between sending the first and last DATA frame. This can be 0 for various reasons.</li>
                    <li><strong>Upload Rate (Mbps)</strong> - the upload rate, in megabits/s, between first and last DATA frames. This number has caveats - can be very high if data size or durations are small.</li>
                    <li><strong>Client Priority Header</strong> - the value of the RFC 9218 request Priority header, if any.</li>
                    <li><strong>Server Priority Header</strong> - the value of the RFC 9218 response Priority header, if any.</li>
                    <li><strong>Reset Stream Sent</strong> - the value of the error code in a Reset Stream, if sent.</li>
                    <li><strong>Reset Stream Received</strong> - the value of the error code in a Reset Stream, if received.</li>
                    <li><strong>Stop Sending Sent</strong> - the value of the error code in a Stop Sending, if sent.</li>
                </ul>
                </p>
            </details>
        </div>
        <div id="tables" style="visibility: hidden;">
            "#
            .as_bytes(),
    )
    .unwrap();

    for data in &log_file.data {
        file.write_all(
            format!(
                "<h2 class=\"center\">Session ID: {:?}, {:?}, {:?}</h2>",
                data.datastore.session_id.unwrap_or(-1),
                data.datastore
                    .host
                    .clone()
                    .unwrap_or("ERROR UNKNOWN".to_string()),
                data.datastore.application_proto
            )
            .as_bytes(),
        )
        .unwrap();

        // This is a bit weird, we need to get our actual Table and then convert
        // it back to a builder to pass to HtmlTable.
        let table: tabled::builder::Builder =
            request_timing_table(data, config).unwrap().into();
        let mut reqs = HtmlTable::with_header(Vec::<Vec<String>>::from(table));

        // colorize the table
        reqs.visit_mut(RequestTableDecorator { i: 0 });

        file.write_all(
            inject_table_id_class(
                &reqs,
                None,
                Some(
                    "log-dancer-table cell-border hover compact order-column"
                        .to_string(),
                ),
            )
            .as_bytes(),
        )
        .unwrap();
    }

    file.write_all(
        r#"
        </div>
    </body>
    <html>"#
            .as_bytes(),
    )
    .unwrap();
}

pub fn event_list_html_from_sqlog(events: &[qlog::reader::Event]) -> String {
    let table = sqlog_event_list(events);
    let table = HtmlTable::with_header(Vec::<Vec<String>>::from(table));
    inject_table_id_class(
        &table,
        None,
        Some(
            "log-dancer-table cell-border hover compact order-column".to_string(),
        ),
    )
}

pub fn event_list(log_file: &LogFileParseResult, config: &AppConfig) {
    let filename = format!("{}-reports/event-list.html", config.filename);
    let mut file = create_file_recursive(&filename).unwrap();

    file.write_all(HTML_INCLUDES.as_bytes()).unwrap();
    file.write_all(TABLE_INIT_SCRIPT.as_bytes()).unwrap();
    file.write_all(SESSIONS_STYLES.as_bytes()).unwrap();
    file.write_all(
        r#"<html>
    <head><head>
    <body>
        <div>
            <h1 class="center">List of events</h1>
            <p class="center">This page lists all the events
            that were present in a log file.</p>
            "#
        .as_bytes(),
    )
    .unwrap();

    for data in &log_file.data {
        match &data.raw {
            crate::RawLogEvents::QlogJson { events: _ } => {
                println!("Support for event list of contained qlog is TODO")
            },
            crate::RawLogEvents::QlogJsonSeq { events } => {
                let table = event_list_html_from_sqlog(events);

                file.write_all(table.as_bytes()).unwrap();
            },
            crate::RawLogEvents::Netlog => {
                println!("Support for event list of netlog is TODO")
            },
        }
    }

    file.write_all(
        r#"
        </div>
    </body>
    <html>"#
            .as_bytes(),
    )
    .unwrap();
}

fn table_cell_value(cell: &HtmlElement) -> Option<String> {
    if cell.tag() == "td" {
        if let Some(HtmlValue::Elements(elems)) = cell.value() {
            if let Some(val) = elems.first() {
                if let Some(HtmlValue::Elements(p)) = val.value() {
                    if let Some(p_val) = p.first() {
                        if let Some(HtmlValue::Content(inner)) = p_val.value() {
                            return Some(inner.clone());
                        }
                    }
                }
            }
        }
    }

    None
}

struct H2ClosureTableDecorator {
    i: usize,
}

impl HtmlVisitorMut for H2ClosureTableDecorator {
    fn visit_element_mut(&mut self, e: &mut HtmlElement) -> bool {
        if e.tag() == "tr" {
            if self.i == 0 {
                self.i += 1;
                return true;
            }

            let mut mark_red = false;
            let mut mark_yellow = false;
            let mut mark_green = false;

            if let Some(HtmlValue::Elements(kids)) = e.value() {
                if let Some(error) = kids.get(2) {
                    if let Some(err) = table_cell_value(error) {
                        if let Ok(val) = err.parse::<i32>() {
                            // Aborted
                            if val == -3 {
                                mark_yellow = true;
                            } else if val < 0 {
                                mark_red = true;
                            } else if val == 0 {
                                mark_green = true;
                            }
                        }
                    }
                }
            }

            if mark_yellow {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "yellow".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            } else if mark_red {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "red".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            } else if mark_green {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "green".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            }
        }

        true
    }
}

struct QUICClosureTableDecorator {
    i: usize,
}

impl HtmlVisitorMut for QUICClosureTableDecorator {
    fn visit_element_mut(&mut self, e: &mut HtmlElement) -> bool {
        if e.tag() == "tr" {
            if self.i == 0 {
                self.i += 1;
                return true;
            }

            let mut mark_red = false;
            let mut mark_yellow = false;
            let mut mark_green = false;

            if let Some(HtmlValue::Elements(kids)) = e.value() {
                if let Some(error) = kids.get(2) {
                    if let Some(err) = table_cell_value(error) {
                        if let Ok(val) = err.parse::<i32>() {
                            // Aborted
                            if val == 25 {
                                mark_green = true;
                            } else if val == 70 {
                                mark_yellow = true;
                            } else if val == 199 {
                                mark_red = true;
                            }
                        }
                    }
                }
            }

            if mark_yellow {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "yellow".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            } else if mark_red {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "red".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            } else if mark_green {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "green".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            }
        }

        true
    }
}

struct RequestTableDecorator {
    i: usize,
}

impl HtmlVisitorMut for RequestTableDecorator {
    fn visit_element_mut(&mut self, e: &mut HtmlElement) -> bool {
        if e.tag() == "tr" {
            if self.i == 0 {
                self.i += 1;
                return true;
            }

            let mut mark_red = false;
            let mut mark_yellow = false;
            let mut mark_green = false;

            if let Some(HtmlValue::Elements(kids)) = e.value() {
                if let Some(reset_sent) = kids.get(24) {
                    if table_cell_value(reset_sent) != Some("n/a".to_string()) {
                        mark_yellow = true;
                    }
                }

                if let Some(reset_received) = kids.get(25) {
                    if table_cell_value(reset_received) != Some("n/a".to_string())
                    {
                        mark_red = true;
                    }
                }

                if let Some(status_code) = kids.get(4) {
                    if let Some(val) = table_cell_value(status_code) {
                        // if the status code is unknown, we probably got no
                        // response

                        if let Ok(val) = val.parse::<u16>() {
                            if val >= 400 {
                                mark_red = true;
                            }
                        } else {
                            // if the status code is unknown or mangled, we
                            // probably got no response
                            mark_red = true;
                        }
                    }
                }
                let response_content_length = kids.get(5);
                let response_content_transferred = kids.get(6);

                if let (Some(cl), Some(tx)) =
                    (response_content_length, response_content_transferred)
                {
                    let cl = table_cell_value(cl);
                    let tx = table_cell_value(tx);

                    if let (Some(length), Some(actual)) = (cl, tx) {
                        // If there is no content-length, we can't verify
                        // it was receivd ok.
                        if length == "n/a" || length == actual {
                            mark_green = true;
                        } else {
                            mark_red = true;
                        }
                    }
                }
            }

            if mark_yellow {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "yellow".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            } else if mark_red {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "red".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            } else if mark_green {
                let mut attrs = e.attrs().to_vec();
                attrs.push(Attribute::new("class", "green".to_string()));
                *e = HtmlElement::new("tr", attrs, e.value().cloned());
            }
        }

        true
    }
}
