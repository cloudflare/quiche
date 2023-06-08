// Copyright (C) 2020, Cloudflare, Inc.
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

//! Quiche application utilities.
//!
//! This module provides some utility functions that are common to quiche
//! applications.

use std::io::prelude::*;

use std::collections::HashMap;

#[cfg(feature = "sfv")]
use std::convert::TryFrom;

use std::fmt::Write as _;

use std::rc::Rc;

use std::cell::RefCell;

use std::path;

use ring::rand::SecureRandom;

use quiche::ConnectionId;

use quiche::h3::NameValue;
use quiche::h3::Priority;

pub fn stdout_sink(out: String) {
    print!("{out}");
}

const H3_MESSAGE_ERROR: u64 = 0x10E;

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
    pub const HTTP_3: [&[u8]; 1] = [b"h3"];
}

pub struct PartialRequest {
    pub req: Vec<u8>,
}

pub struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,
    pub priority: Option<quiche::h3::Priority>,

    pub body: Vec<u8>,

    pub written: usize,
}

pub type ClientId = u64;

pub struct Client {
    pub conn: quiche::Connection,

    pub http_conn: Option<Box<dyn HttpConn>>,

    pub client_id: ClientId,

    pub app_proto_selected: bool,

    pub partial_requests: std::collections::HashMap<u64, PartialRequest>,

    pub partial_responses: std::collections::HashMap<u64, PartialResponse>,

    pub max_datagram_size: usize,

    pub loss_rate: f64,

    pub max_send_burst: usize,
}

pub type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
pub type ClientMap = HashMap<ClientId, Client>;

/// Makes a buffered writer for a resource with a target URL.
///
/// The file will have the same name as the resource's last path segment value.
/// Multiple requests for the same URL are indicated by the value of `cardinal`,
/// any value "N" greater than 1, will cause ".N" to be appended to the
/// filename.
fn make_resource_writer(
    url: &url::Url, target_path: &Option<String>, cardinal: u64,
) -> Option<std::io::BufWriter<std::fs::File>> {
    if let Some(tp) = target_path {
        let resource =
            url.path_segments().map(|c| c.collect::<Vec<_>>()).unwrap();

        let mut path = format!("{}/{}", tp, resource.iter().last().unwrap());

        if cardinal > 1 {
            path = format!("{path}.{cardinal}");
        }

        match std::fs::File::create(&path) {
            Ok(f) => return Some(std::io::BufWriter::new(f)),

            Err(e) => panic!(
                "Error creating file for {}, attempted path was {}: {}",
                url, path, e
            ),
        }
    }

    None
}

fn autoindex(path: path::PathBuf, index: &str) -> path::PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.ends_with('/') {
            let path_str = format!("{path_str}{index}");
            return path::PathBuf::from(&path_str);
        }
    }

    path
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

fn dump_json(reqs: &[Http3Request], output_sink: &mut dyn FnMut(String)) {
    let mut out = String::new();

    writeln!(out, "{{").unwrap();
    writeln!(out, "  \"entries\": [").unwrap();
    let mut reqs = reqs.iter().peekable();

    while let Some(req) = reqs.next() {
        writeln!(out, "  {{").unwrap();
        writeln!(out, "    \"request\":{{").unwrap();
        writeln!(out, "      \"headers\":[").unwrap();

        let mut req_hdrs = req.hdrs.iter().peekable();
        while let Some(h) = req_hdrs.next() {
            writeln!(out, "        {{").unwrap();
            writeln!(
                out,
                "          \"name\": \"{}\",",
                std::str::from_utf8(h.name()).unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "          \"value\": \"{}\"",
                std::str::from_utf8(h.value()).unwrap().replace('"', "\\\"")
            )
            .unwrap();

            if req_hdrs.peek().is_some() {
                writeln!(out, "        }},").unwrap();
            } else {
                writeln!(out, "        }}").unwrap();
            }
        }
        writeln!(out, "      ]}},").unwrap();

        writeln!(out, "    \"response\":{{").unwrap();
        writeln!(out, "      \"headers\":[").unwrap();

        let mut response_hdrs = req.response_hdrs.iter().peekable();
        while let Some(h) = response_hdrs.next() {
            writeln!(out, "        {{").unwrap();
            writeln!(
                out,
                "          \"name\": \"{}\",",
                std::str::from_utf8(h.name()).unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "          \"value\": \"{}\"",
                std::str::from_utf8(h.value()).unwrap().replace('"', "\\\"")
            )
            .unwrap();

            if response_hdrs.peek().is_some() {
                writeln!(out, "        }},").unwrap();
            } else {
                writeln!(out, "        }}").unwrap();
            }
        }
        writeln!(out, "      ],").unwrap();
        writeln!(out, "      \"body\": {:?}", req.response_body).unwrap();
        writeln!(out, "    }}").unwrap();

        if reqs.peek().is_some() {
            writeln!(out, "}},").unwrap();
        } else {
            writeln!(out, "}}").unwrap();
        }
    }
    writeln!(out, "]").unwrap();
    writeln!(out, "}}").unwrap();

    output_sink(out);
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

/// Construct a priority field value from quiche apps custom query string.
pub fn priority_field_value_from_query_string(url: &url::Url) -> Option<String> {
    let mut priority = "".to_string();
    for param in url.query_pairs() {
        if param.0 == "u" {
            write!(priority, "{}={},", param.0, param.1).ok();
        }

        if param.0 == "i" && param.1 == "1" {
            priority.push_str("i,");
        }
    }

    if !priority.is_empty() {
        // remove trailing comma
        priority.pop();

        Some(priority)
    } else {
        None
    }
}

/// Construct a Priority from quiche apps custom query string.
pub fn priority_from_query_string(url: &url::Url) -> Option<Priority> {
    let mut urgency = None;
    let mut incremental = None;
    for param in url.query_pairs() {
        if param.0 == "u" {
            urgency = Some(param.1.parse::<u8>().unwrap());
        }

        if param.0 == "i" && param.1 == "1" {
            incremental = Some(true);
        }
    }

    match (urgency, incremental) {
        (Some(u), Some(i)) => Some(Priority::new(u, i)),

        (Some(u), None) => Some(Priority::new(u, false)),

        (None, Some(i)) => Some(Priority::new(3, i)),

        (None, None) => None,
    }
}

pub trait HttpConn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    );

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    );

    fn report_incomplete(&self, start: &std::time::Instant) -> bool;

    fn handle_requests(
        &mut self, conn: &mut quiche::Connection,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()>;

    fn handle_writable(
        &mut self, conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    );
}

/// Represents an HTTP/0.9 formatted request.
pub struct Http09Request {
    url: url::Url,
    cardinal: u64,
    request_line: String,
    stream_id: Option<u64>,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

/// Represents an HTTP/3 formatted request.
struct Http3Request {
    url: url::Url,
    cardinal: u64,
    stream_id: Option<u64>,
    hdrs: Vec<quiche::h3::Header>,
    priority: Option<Priority>,
    response_hdrs: Vec<quiche::h3::Header>,
    response_body: Vec<u8>,
    response_body_max: usize,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

type Http3ResponseBuilderResult = std::result::Result<
    (Vec<quiche::h3::Header>, Vec<u8>, Vec<u8>),
    (u64, String),
>;

pub struct Http09Conn {
    stream_id: u64,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs: Vec<Http09Request>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
}

impl Default for Http09Conn {
    fn default() -> Self {
        Http09Conn {
            stream_id: Default::default(),
            reqs_sent: Default::default(),
            reqs_complete: Default::default(),
            reqs: Default::default(),
            output_sink: Rc::new(RefCell::new(stdout_sink)),
        }
    }
}

impl Http09Conn {
    pub fn with_urls(
        urls: &[url::Url], reqs_cardinal: u64,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> Box<dyn HttpConn> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let request_line = format!("GET {}\r\n", url.path());
                reqs.push(Http09Request {
                    url: url.clone(),
                    cardinal: i,
                    request_line,
                    stream_id: None,
                    response_writer: None,
                });
            }
        }

        let h_conn = Http09Conn {
            stream_id: 0,
            reqs_sent: 0,
            reqs_complete: 0,
            reqs,
            output_sink,
        };

        Box::new(h_conn)
    }
}

impl HttpConn for Http09Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    ) {
        let mut reqs_done = 0;

        for req in self.reqs.iter_mut().skip(self.reqs_sent) {
            match conn.stream_send(
                self.stream_id,
                req.request_line.as_bytes(),
                true,
            ) {
                Ok(v) => v,

                Err(quiche::Error::StreamLimit) => {
                    debug!("not enough stream credits, retry later...");
                    break;
                },

                Err(e) => {
                    error!("failed to send request {:?}", e);
                    break;
                },
            };

            debug!("sending HTTP request {:?}", req.request_line);

            req.stream_id = Some(self.stream_id);
            req.response_writer =
                make_resource_writer(&req.url, target_path, req.cardinal);

            self.stream_id += 4;

            reqs_done += 1;
        }

        self.reqs_sent += reqs_done;
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                trace!("received {} bytes", read);

                let stream_buf = &buf[..read];

                trace!(
                    "stream {} has {} bytes (fin? {})",
                    s,
                    stream_buf.len(),
                    fin
                );

                let req = self
                    .reqs
                    .iter_mut()
                    .find(|r| r.stream_id == Some(s))
                    .unwrap();

                match &mut req.response_writer {
                    Some(rw) => {
                        rw.write_all(&buf[..read]).ok();
                    },

                    None => {
                        self.output_sink.borrow_mut()(unsafe {
                            String::from_utf8_unchecked(stream_buf.to_vec())
                        });
                    },
                }

                // The server reported that it has no more data to send on
                // a client-initiated
                // bidirectional stream, which means
                // we got the full response. If all responses are received
                // then close the connection.
                if &s % 4 == 0 && fin {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();

                    debug!(
                        "{}/{} responses received",
                        self.reqs_complete, reqs_count
                    );

                    if self.reqs_complete == reqs_count {
                        info!(
                            "{}/{} response(s) received in {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
                }
            }
        }
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self, conn: &mut quiche::Connection,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                trace!("{} received {} bytes", conn.trace_id(), read);

                let stream_buf = &buf[..read];

                trace!(
                    "{} stream {} has {} bytes (fin? {})",
                    conn.trace_id(),
                    s,
                    stream_buf.len(),
                    fin
                );

                let stream_buf =
                    if let Some(partial) = partial_requests.get_mut(&s) {
                        partial.req.extend_from_slice(stream_buf);

                        if !partial.req.ends_with(b"\r\n") {
                            return Ok(());
                        }

                        &partial.req
                    } else {
                        if !stream_buf.ends_with(b"\r\n") {
                            let request = PartialRequest {
                                req: stream_buf.to_vec(),
                            };

                            partial_requests.insert(s, request);
                            return Ok(());
                        }

                        stream_buf
                    };

                if stream_buf.starts_with(b"GET ") {
                    let uri = &stream_buf[4..stream_buf.len() - 2];
                    let uri = String::from_utf8(uri.to_vec()).unwrap();
                    let uri = String::from(uri.lines().next().unwrap());
                    let uri = path::Path::new(&uri);
                    let mut path = path::PathBuf::from(root);

                    partial_requests.remove(&s);

                    for c in uri.components() {
                        if let path::Component::Normal(v) = c {
                            path.push(v)
                        }
                    }

                    path = autoindex(path, index);

                    info!(
                        "{} got GET request for {:?} on stream {}",
                        conn.trace_id(),
                        path,
                        s
                    );

                    let body = std::fs::read(path.as_path())
                        .unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

                    info!(
                        "{} sending response of size {} on stream {}",
                        conn.trace_id(),
                        body.len(),
                        s
                    );

                    let written = match conn.stream_send(s, &body, true) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => 0,

                        Err(e) => {
                            error!(
                                "{} stream send failed {:?}",
                                conn.trace_id(),
                                e
                            );
                            return Err(From::from(e));
                        },
                    };

                    if written < body.len() {
                        let response = PartialResponse {
                            headers: None,
                            priority: None,
                            body,
                            written,
                        };

                        partial_responses.insert(s, response);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_writable(
        &mut self, conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        trace!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();
        let body = &resp.body[resp.written..];

        let written = match conn.stream_send(stream_id, body, true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                partial_responses.remove(&stream_id);

                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_responses.remove(&stream_id);
        }
    }
}

pub struct Http3DgramSender {
    dgram_count: u64,
    pub dgram_content: String,
    pub flow_id: u64,
    pub dgrams_sent: u64,
}

impl Http3DgramSender {
    pub fn new(dgram_count: u64, dgram_content: String, flow_id: u64) -> Self {
        Self {
            dgram_count,
            dgram_content,
            flow_id,
            dgrams_sent: 0,
        }
    }
}

fn make_h3_config(
    max_field_section_size: Option<u64>, qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
) -> quiche::h3::Config {
    let mut config = quiche::h3::Config::new().unwrap();

    if let Some(v) = max_field_section_size {
        config.set_max_field_section_size(v);
    }

    if let Some(v) = qpack_max_table_capacity {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_max_table_capacity(v.clamp(0, 0));
    }

    if let Some(v) = qpack_blocked_streams {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_blocked_streams(v.clamp(0, 0));
    }

    config
}

pub struct Http3Conn {
    h3_conn: quiche::h3::Connection,
    reqs_hdrs_sent: usize,
    reqs_complete: usize,
    largest_processed_request: u64,
    reqs: Vec<Http3Request>,
    body: Option<Vec<u8>>,
    sent_body_bytes: HashMap<u64, usize>,
    dump_json: bool,
    dgram_sender: Option<Http3DgramSender>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
}

impl Http3Conn {
    #[allow(clippy::too_many_arguments)]
    pub fn with_urls(
        conn: &mut quiche::Connection, urls: &[url::Url], reqs_cardinal: u64,
        req_headers: &[String], body: &Option<Vec<u8>>, method: &str,
        send_priority_update: bool, max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>, dump_json: Option<usize>,
        dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> Box<dyn HttpConn> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let authority = match url.port() {
                    Some(port) => format!("{}:{}", url.host_str().unwrap(), port),

                    None => url.host_str().unwrap().to_string(),
                };

                let mut hdrs = vec![
                    quiche::h3::Header::new(b":method", method.as_bytes()),
                    quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
                    quiche::h3::Header::new(b":authority", authority.as_bytes()),
                    quiche::h3::Header::new(
                        b":path",
                        url[url::Position::BeforePath..].as_bytes(),
                    ),
                    quiche::h3::Header::new(b"user-agent", b"quiche"),
                ];

                let priority = if send_priority_update {
                    priority_from_query_string(url)
                } else {
                    None
                };

                // Add custom headers to the request.
                for header in req_headers {
                    let header_split: Vec<&str> =
                        header.splitn(2, ": ").collect();

                    if header_split.len() != 2 {
                        panic!("malformed header provided - \"{}\"", header);
                    }

                    hdrs.push(quiche::h3::Header::new(
                        header_split[0].as_bytes(),
                        header_split[1].as_bytes(),
                    ));
                }

                if body.is_some() {
                    hdrs.push(quiche::h3::Header::new(
                        b"content-length",
                        body.as_ref().unwrap().len().to_string().as_bytes(),
                    ));
                }

                reqs.push(Http3Request {
                    url: url.clone(),
                    cardinal: i,
                    hdrs,
                    priority,
                    response_hdrs: Vec::new(),
                    response_body: Vec::new(),
                    response_body_max: dump_json.unwrap_or_default(),
                    stream_id: None,
                    response_writer: None,
                });
            }
        }

        let h_conn = Http3Conn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &make_h3_config(
                    max_field_section_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                ),
            ).expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            reqs_hdrs_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs,
            body: body.as_ref().map(|b| b.to_vec()),
            sent_body_bytes: HashMap::new(),
            dump_json: dump_json.is_some(),
            dgram_sender,
            output_sink,
        };

        Box::new(h_conn)
    }

    pub fn with_conn(
        conn: &mut quiche::Connection, max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> std::result::Result<Box<dyn HttpConn>, String> {
        let h3_conn = quiche::h3::Connection::with_transport(
            conn,
            &make_h3_config(
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            ),
        ).map_err(|_| "Unable to create HTTP/3 connection, check the client's uni stream limit and window size")?;

        let h_conn = Http3Conn {
            h3_conn,
            reqs_hdrs_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs: Vec::new(),
            body: None,
            sent_body_bytes: HashMap::new(),
            dump_json: false,
            dgram_sender,
            output_sink,
        };

        Ok(Box::new(h_conn))
    }

    /// Builds an HTTP/3 response given a request.
    fn build_h3_response(
        root: &str, index: &str, request: &[quiche::h3::Header],
    ) -> Http3ResponseBuilderResult {
        let mut file_path = path::PathBuf::from(root);
        let mut scheme = None;
        let mut authority = None;
        let mut host = None;
        let mut path = None;
        let mut method = None;
        let mut priority = vec![];

        // Parse some of the request headers.
        for hdr in request {
            match hdr.name() {
                b":scheme" => {
                    if scheme.is_some() {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":scheme cannot be duplicated".to_string(),
                        ));
                    }

                    scheme = Some(std::str::from_utf8(hdr.value()).unwrap());
                },

                b":authority" => {
                    if authority.is_some() {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":authority cannot be duplicated".to_string(),
                        ));
                    }

                    authority = Some(std::str::from_utf8(hdr.value()).unwrap());
                },

                b":path" => {
                    if path.is_some() {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":path cannot be duplicated".to_string(),
                        ));
                    }

                    path = Some(std::str::from_utf8(hdr.value()).unwrap())
                },

                b":method" => {
                    if method.is_some() {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":method cannot be duplicated".to_string(),
                        ));
                    }

                    method = Some(std::str::from_utf8(hdr.value()).unwrap())
                },

                b":protocol" => {
                    return Err((
                        H3_MESSAGE_ERROR,
                        ":protocol not supported".to_string(),
                    ));
                },

                b"priority" => priority = hdr.value().to_vec(),

                b"host" => host = Some(std::str::from_utf8(hdr.value()).unwrap()),

                _ => (),
            }
        }

        let decided_method = match method {
            Some(method) => {
                match method {
                    "" =>
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":method value cannot be empty".to_string(),
                        )),

                    "CONNECT" => {
                        // not allowed
                        let headers = vec![
                            quiche::h3::Header::new(
                                b":status",
                                "405".to_string().as_bytes(),
                            ),
                            quiche::h3::Header::new(b"server", b"quiche"),
                        ];

                        return Ok((headers, b"".to_vec(), Default::default()));
                    },

                    _ => method,
                }
            },

            None =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":method cannot be missing".to_string(),
                )),
        };

        let decided_scheme = match scheme {
            Some(scheme) => {
                if scheme != "http" && scheme != "https" {
                    let headers = vec![
                        quiche::h3::Header::new(
                            b":status",
                            "400".to_string().as_bytes(),
                        ),
                        quiche::h3::Header::new(b"server", b"quiche"),
                    ];

                    return Ok((
                        headers,
                        b"Invalid scheme".to_vec(),
                        Default::default(),
                    ));
                }

                scheme
            },

            None =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":scheme cannot be missing".to_string(),
                )),
        };

        let decided_host = match (authority, host) {
            (None, Some("")) =>
                return Err((
                    H3_MESSAGE_ERROR,
                    "host value cannot be empty".to_string(),
                )),

            (Some(""), None) =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority value cannot be empty".to_string(),
                )),

            (Some(""), Some("")) =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority and host value cannot be empty".to_string(),
                )),

            (None, None) =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority and host missing".to_string(),
                )),

            // Any other combo, prefer :authority
            (..) => authority.unwrap(),
        };

        let decided_path = match path {
            Some("") =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":path value cannot be empty".to_string(),
                )),

            None =>
                return Err((
                    H3_MESSAGE_ERROR,
                    ":path cannot be missing".to_string(),
                )),

            Some(path) => path,
        };

        let url = format!("{decided_scheme}://{decided_host}{decided_path}");
        let url = url::Url::parse(&url).unwrap();

        let pathbuf = path::PathBuf::from(url.path());
        let pathbuf = autoindex(pathbuf, index);

        // Priority query string takes precedence over the header.
        // So replace the header with one built here.
        let query_priority = priority_field_value_from_query_string(&url);

        if let Some(p) = query_priority {
            priority = p.as_bytes().to_vec();
        }

        let (status, body) = match decided_method {
            "GET" => {
                for c in pathbuf.components() {
                    if let path::Component::Normal(v) = c {
                        file_path.push(v)
                    }
                }

                match std::fs::read(file_path.as_path()) {
                    Ok(data) => (200, data),

                    Err(_) => (404, b"Not Found!".to_vec()),
                }
            },

            _ => (405, Vec::new()),
        };

        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"quiche"),
            quiche::h3::Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ),
        ];

        Ok((headers, body, priority))
    }
}

impl HttpConn for Http3Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    ) {
        let mut reqs_done = 0;

        // First send headers.
        for req in self.reqs.iter_mut().skip(self.reqs_hdrs_sent) {
            let s = match self.h3_conn.send_request(
                conn,
                &req.hdrs,
                self.body.is_none(),
            ) {
                Ok(v) => v,

                Err(quiche::h3::Error::TransportError(
                    quiche::Error::StreamLimit,
                )) => {
                    debug!("not enough stream credits, retry later...");
                    break;
                },

                Err(quiche::h3::Error::StreamBlocked) => {
                    debug!("stream is blocked, retry later...");
                    break;
                },

                Err(e) => {
                    error!("failed to send request {:?}", e);
                    break;
                },
            };

            debug!("Sent HTTP request {:?}", &req.hdrs);

            if let Some(priority) = &req.priority {
                // If sending the priority fails, don't try again.
                self.h3_conn
                    .send_priority_update_for_request(conn, s, priority)
                    .ok();
            }

            req.stream_id = Some(s);
            req.response_writer =
                make_resource_writer(&req.url, target_path, req.cardinal);
            self.sent_body_bytes.insert(s, 0);

            reqs_done += 1;
        }
        self.reqs_hdrs_sent += reqs_done;

        // Then send any remaining body.
        if let Some(body) = &self.body {
            for (stream_id, sent_bytes) in self.sent_body_bytes.iter_mut() {
                if *sent_bytes == body.len() {
                    continue;
                }

                // Always try to send all remaining bytes, so always set fin to
                // true.
                let sent = match self.h3_conn.send_body(
                    conn,
                    *stream_id,
                    &body[*sent_bytes..],
                    true,
                ) {
                    Ok(v) => v,

                    Err(quiche::h3::Error::Done) => 0,

                    Err(e) => {
                        error!("failed to send request body {:?}", e);
                        continue;
                    },
                };

                *sent_bytes += sent;
            }
        }

        // And finally any DATAGRAMS.
        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;

            for _ in ds.dgrams_sent..ds.dgram_count {
                info!(
                    "sending HTTP/3 DATAGRAM on flow_id={} with data {:?}",
                    ds.flow_id,
                    ds.dgram_content.as_bytes()
                );

                match self.h3_conn.send_dgram(
                    conn,
                    0,
                    ds.dgram_content.as_bytes(),
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);
                        break;
                    },
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    debug!(
                        "got response headers {:?} on stream id {}",
                        hdrs_to_strings(&list),
                        stream_id
                    );

                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|r| r.stream_id == Some(stream_id))
                        .unwrap();

                    req.response_hdrs = list;
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    while let Ok(read) =
                        self.h3_conn.recv_body(conn, stream_id, buf)
                    {
                        debug!(
                            "got {} bytes of response data on stream {}",
                            read, stream_id
                        );

                        let req = self
                            .reqs
                            .iter_mut()
                            .find(|r| r.stream_id == Some(stream_id))
                            .unwrap();

                        let len = std::cmp::min(
                            read,
                            req.response_body_max - req.response_body.len(),
                        );
                        req.response_body.extend_from_slice(&buf[..len]);

                        match &mut req.response_writer {
                            Some(rw) => {
                                rw.write_all(&buf[..read]).ok();
                            },

                            None =>
                                if !self.dump_json {
                                    self.output_sink.borrow_mut()(unsafe {
                                        String::from_utf8_unchecked(
                                            buf[..read].to_vec(),
                                        )
                                    });
                                },
                        }
                    }
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();

                    debug!(
                        "{}/{} responses received",
                        self.reqs_complete, reqs_count
                    );

                    if self.reqs_complete == reqs_count {
                        info!(
                            "{}/{} response(s) received in {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        if self.dump_json {
                            dump_json(
                                &self.reqs,
                                &mut *self.output_sink.borrow_mut(),
                            );
                        }

                        match conn.close(true, 0x100, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
                },

                Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                    error!("request was reset by peer with {}, closing...", e);

                    match conn.close(true, 0x100, b"kthxbye") {
                        // Already closed.
                        Ok(_) | Err(quiche::Error::Done) => (),

                        Err(e) => panic!("error closing conn: {:?}", e),
                    }

                    break;
                },

                Ok((_flow_id, quiche::h3::Event::Datagram)) => {
                    while let Ok((len, flow_id, flow_id_len)) =
                        self.h3_conn.recv_dgram(conn, buf)
                    {
                        info!(
                            "Received DATAGRAM flow_id={} len={} data={:?}",
                            flow_id,
                            len,
                            buf[flow_id_len..len].to_vec()
                        );
                    }
                },

                Ok((
                    prioritized_element_id,
                    quiche::h3::Event::PriorityUpdate,
                )) => {
                    info!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        conn.trace_id(),
                        prioritized_element_id
                    );
                },

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    info!(
                        "{} got GOAWAY with ID {} ",
                        conn.trace_id(),
                        goaway_id
                    );
                },

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("HTTP/3 processing failed: {:?}", e);

                    break;
                },
            }
        }
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            if self.dump_json {
                dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
            }

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self, conn: &mut quiche::Connection,
        _partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process HTTP events.
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!(
                        "{} got request {:?} on stream id {}",
                        conn.trace_id(),
                        hdrs_to_strings(&list),
                        stream_id
                    );

                    self.largest_processed_request =
                        std::cmp::max(self.largest_processed_request, stream_id);

                    // We decide the response based on headers alone, so
                    // stop reading the request stream so that any body
                    // is ignored and pointless Data events are not
                    // generated.
                    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                        .unwrap();

                    let (mut headers, body, mut priority) =
                        match Http3Conn::build_h3_response(root, index, &list) {
                            Ok(v) => v,

                            Err((error_code, _)) => {
                                conn.stream_shutdown(
                                    stream_id,
                                    quiche::Shutdown::Write,
                                    error_code,
                                )
                                .unwrap();
                                continue;
                            },
                        };

                    match self.h3_conn.take_last_priority_update(stream_id) {
                        Ok(v) => {
                            priority = v;
                        },

                        Err(quiche::h3::Error::Done) => (),

                        Err(e) => error!(
                            "{} error taking PRIORITY_UPDATE {}",
                            conn.trace_id(),
                            e
                        ),
                    }

                    if !priority.is_empty() {
                        headers.push(quiche::h3::Header::new(
                            b"priority",
                            priority.as_slice(),
                        ));
                    }

                    #[cfg(feature = "sfv")]
                    let priority =
                        match quiche::h3::Priority::try_from(priority.as_slice())
                        {
                            Ok(v) => v,
                            Err(_) => quiche::h3::Priority::default(),
                        };

                    #[cfg(not(feature = "sfv"))]
                    let priority = quiche::h3::Priority::default();

                    info!(
                        "{} prioritizing response on stream {} as {:?}",
                        conn.trace_id(),
                        stream_id,
                        priority
                    );

                    match self.h3_conn.send_response_with_priority(
                        conn, stream_id, &headers, &priority, false,
                    ) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::StreamBlocked) => {
                            let response = PartialResponse {
                                headers: Some(headers),
                                priority: Some(priority),
                                body,
                                written: 0,
                            };

                            partial_responses.insert(stream_id, response);
                            continue;
                        },

                        Err(e) => {
                            error!(
                                "{} stream send failed {:?}",
                                conn.trace_id(),
                                e
                            );

                            break;
                        },
                    }

                    let written = match self
                        .h3_conn
                        .send_body(conn, stream_id, &body, true)
                    {
                        Ok(v) => v,

                        Err(quiche::h3::Error::Done) => 0,

                        Err(e) => {
                            error!(
                                "{} stream send failed {:?}",
                                conn.trace_id(),
                                e
                            );

                            break;
                        },
                    };

                    if written < body.len() {
                        let response = PartialResponse {
                            headers: None,
                            priority: None,
                            body,
                            written,
                        };

                        partial_responses.insert(stream_id, response);
                    }
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!(
                        "{} got data on stream id {}",
                        conn.trace_id(),
                        stream_id
                    );
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                Ok((_, quiche::h3::Event::Datagram)) => {
                    while let Ok((len, flow_id, flow_id_len)) =
                        self.h3_conn.recv_dgram(conn, buf)
                    {
                        info!(
                            "Received DATAGRAM flow_id={} len={} data={:?}",
                            flow_id,
                            len,
                            buf[flow_id_len..len].to_vec()
                        );
                    }
                },

                Ok((
                    prioritized_element_id,
                    quiche::h3::Event::PriorityUpdate,
                )) => {
                    info!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        conn.trace_id(),
                        prioritized_element_id
                    );
                },

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    trace!(
                        "{} got GOAWAY with ID {} ",
                        conn.trace_id(),
                        goaway_id
                    );
                    self.h3_conn
                        .send_goaway(conn, self.largest_processed_request)?;
                },

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", conn.trace_id(), e);

                    return Err(e);
                },
            }
        }

        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;

            for _ in ds.dgrams_sent..ds.dgram_count {
                info!(
                    "sending HTTP/3 DATAGRAM on flow_id={} with data {:?}",
                    ds.flow_id,
                    ds.dgram_content.as_bytes()
                );

                match self.h3_conn.send_dgram(
                    conn,
                    0,
                    ds.dgram_content.as_bytes(),
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {:?}", e);
                        break;
                    },
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }

        Ok(())
    }

    fn handle_writable(
        &mut self, conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        debug!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();

        if let (Some(headers), Some(priority)) = (&resp.headers, &resp.priority) {
            match self.h3_conn.send_response_with_priority(
                conn, stream_id, headers, priority, false,
            ) {
                Ok(_) => (),

                Err(quiche::h3::Error::StreamBlocked) => {
                    return;
                },

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                },
            }
        }

        resp.headers = None;
        resp.priority = None;

        let body = &resp.body[resp.written..];

        let written = match self.h3_conn.send_body(conn, stream_id, body, true) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => 0,

            Err(e) => {
                partial_responses.remove(&stream_id);

                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_responses.remove(&stream_id);
        }
    }
}
