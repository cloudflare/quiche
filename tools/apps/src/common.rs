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

use std::fmt::Write as _;

use std::rc::Rc;

use std::cell::RefCell;

use std::path;

use quiche::ConnectionId;

use quiche::h3::NameValue;

pub fn stdout_sink(out: String) {
    print!("{}", out);
}

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&str; 5] =
        ["hq-interop", "hq-29", "hq-28", "hq-27", "http/0.9"];
    pub const HTTP_3: [&str; 4] = ["h3", "h3-29", "h3-28", "h3-27"];
    pub const SIDUCK: [&str; 2] = ["siduck", "siduck-00"];

    pub fn length_prefixed(alpns: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();

        for s in alpns {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }

        out
    }
}

pub struct PartialRequest {
    pub req: Vec<u8>,
}

pub struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,

    pub body: Vec<u8>,

    pub written: usize,
}

pub struct Client {
    pub conn: std::pin::Pin<Box<quiche::Connection>>,

    pub http_conn: Option<Box<dyn HttpConn>>,

    pub siduck_conn: Option<SiDuckConn>,

    pub app_proto_selected: bool,

    pub partial_requests: std::collections::HashMap<u64, PartialRequest>,

    pub partial_responses: std::collections::HashMap<u64, PartialResponse>,

    pub max_datagram_size: usize,
}

pub type ClientMap = HashMap<ConnectionId<'static>, Client>;

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
            path = format!("{}.{}", path, cardinal);
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
            let path_str = format!("{}{}", path_str, index);
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
    let filename = format!("{}-{}.qlog", role, id);
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
                std::str::from_utf8(h.value())
                    .unwrap()
                    .replace("\"", "\\\"")
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
                std::str::from_utf8(h.value())
                    .unwrap()
                    .replace("\"", "\\\"")
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
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()>;

    fn handle_writable(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    );
}

pub struct SiDuckConn {
    quacks_to_make: u64,
    quack_contents: String,
    quacks_sent: u64,
    quacks_acked: u64,
}

impl SiDuckConn {
    pub fn new(quacks_to_make: u64, quack_contents: String) -> Self {
        Self {
            quacks_to_make,
            quack_contents,
            quacks_sent: 0,
            quacks_acked: 0,
        }
    }

    pub fn send_quacks(&mut self, conn: &mut quiche::Connection) {
        trace!("sending quacks");
        let mut quacks_done = 0;

        for _ in self.quacks_sent..self.quacks_to_make {
            info!("sending QUIC DATAGRAM with data {:?}", self.quack_contents);

            match conn.dgram_send(self.quack_contents.as_bytes()) {
                Ok(v) => v,

                Err(e) => {
                    error!("failed to send dgram {:?}", e);

                    break;
                },
            }

            quacks_done += 1;
        }

        self.quacks_sent += quacks_done;
    }

    pub fn handle_quacks(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        loop {
            match conn.dgram_recv(buf) {
                Ok(len) => {
                    let data =
                        unsafe { std::str::from_utf8_unchecked(&buf[..len]) };
                    info!("Received DATAGRAM data {:?}", data);

                    // TODO
                    if data != "quack" {
                        match conn.close(true, 0x101, b"only quacks echo") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }

                    match conn.dgram_send(format!("{}-ack", data).as_bytes()) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => (),

                        Err(e) => {
                            error!("failed to send quack ack {:?}", e);
                            return Err(From::from(e));
                        },
                    }
                },

                Err(quiche::Error::Done) => break,

                Err(e) => {
                    error!("failure receiving DATAGRAM failure {:?}", e);

                    return Err(From::from(e));
                },
            }
        }

        Ok(())
    }

    pub fn handle_quack_acks(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        start: &std::time::Instant,
    ) {
        trace!("handle_quack_acks");

        loop {
            match conn.dgram_recv(buf) {
                Ok(len) => {
                    let data =
                        unsafe { std::str::from_utf8_unchecked(&buf[..len]) };

                    info!("Received DATAGRAM data {:?}", data);
                    self.quacks_acked += 1;

                    debug!(
                        "{}/{} quacks acked",
                        self.quacks_acked, self.quacks_to_make
                    );

                    if self.quacks_acked == self.quacks_to_make {
                        info!(
                            "{}/{} dgrams(s) received in {:?}, closing...",
                            self.quacks_acked,
                            self.quacks_to_make,
                            start.elapsed()
                        );

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
                },

                Err(quiche::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("failure receiving DATAGRAM failure {:?}", e);

                    break;
                },
            }
        }
    }

    pub fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.quacks_acked != self.quacks_to_make {
            error!(
                "connection timed out after {:?} and only received {}/{} quack-acks",
                start.elapsed(),
                self.quacks_acked,
                self.quacks_to_make
            );

            return true;
        }

        false
    }
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
    response_hdrs: Vec<quiche::h3::Header>,
    response_body: Vec<u8>,
    response_body_max: usize,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

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
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
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
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        trace!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();
        let body = &resp.body[resp.written..];

        let written = match conn.stream_send(stream_id, &body, true) {
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
        dump_json: Option<usize>, dgram_sender: Option<Http3DgramSender>,
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
                        &url[url::Position::BeforePath..].as_bytes(),
                    ),
                    quiche::h3::Header::new(b"user-agent", b"quiche"),
                ];

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
                &quiche::h3::Config::new().unwrap(),
            )
            .unwrap(),
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
        conn: &mut quiche::Connection, dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> Box<dyn HttpConn> {
        let h_conn = Http3Conn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &quiche::h3::Config::new().unwrap(),
            )
            .unwrap(),
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

        Box::new(h_conn)
    }

    /// Builds an HTTP/3 response given a request.
    fn build_h3_response(
        root: &str, index: &str, request: &[quiche::h3::Header],
    ) -> (Vec<quiche::h3::Header>, Vec<u8>, String) {
        let mut file_path = path::PathBuf::from(root);
        let mut scheme = "";
        let mut host = "";
        let mut path = "";
        let mut method = "";
        let mut priority = "";

        // Parse some of the request headers.
        for hdr in request {
            match hdr.name() {
                b":scheme" => scheme = std::str::from_utf8(hdr.value()).unwrap(),

                b":authority" | b"host" =>
                    host = std::str::from_utf8(hdr.value()).unwrap(),

                b":path" => path = std::str::from_utf8(hdr.value()).unwrap(),

                b":method" => method = std::str::from_utf8(hdr.value()).unwrap(),

                b"priority" =>
                    priority = std::str::from_utf8(hdr.value()).unwrap(),

                _ => (),
            }
        }

        if scheme != "http" && scheme != "https" {
            let headers = vec![
                quiche::h3::Header::new(b":status", "400".to_string().as_bytes()),
                quiche::h3::Header::new(b"server", b"quiche"),
            ];

            return (headers, b"Invalid scheme".to_vec(), priority.to_string());
        }

        let url = format!("{}://{}{}", scheme, host, path);
        let url = url::Url::parse(&url).unwrap();

        let pathbuf = path::PathBuf::from(url.path());
        let pathbuf = autoindex(pathbuf, index);

        // Priority query string takes precedence over the header.
        // So replace the header with one built here.
        let mut query_priority = "".to_string();
        for param in url.query_pairs() {
            if param.0 == "u" {
                query_priority.push_str(&format!("{}={},", param.0, param.1));
            }

            if param.0 == "i" && param.1 == "1" {
                query_priority.push_str("i,");
            }
        }

        if !query_priority.is_empty() {
            priority = &query_priority;
        }

        let (status, body) = match method {
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

        let mut headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"quiche"),
            quiche::h3::Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ),
        ];

        if !priority.is_empty() {
            headers
                .push(quiche::h3::Header::new(b"priority", priority.as_bytes()));
        }

        (headers, body, priority.to_string())
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

            debug!("Sent HTTP request {:?}", req.hdrs);

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
                        list, stream_id
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

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
                },

                Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                    error!("request was reset by peer with {}, closing...", e);

                    match conn.close(true, 0x00, b"kthxbye") {
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
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
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
                        &list,
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

                    let (headers, body, priority) =
                        Http3Conn::build_h3_response(root, index, &list);

                    match self.h3_conn.send_response_with_priority(
                        conn, stream_id, &headers, &priority, false,
                    ) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::StreamBlocked) => {
                            let response = PartialResponse {
                                headers: Some(headers),
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
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        debug!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();

        if let Some(ref headers) = resp.headers {
            match self.h3_conn.send_response(conn, stream_id, &headers, false) {
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
