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

#[macro_use]
extern crate log;

use std::io::prelude::*;

use std::collections::HashMap;

use std::net;

/// Returns a String containing a pretty printed version of the `buf` slice.
pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&str; 4] = ["hq-25", "hq-24", "hq-23", "http/0.9"];
    pub const HTTP_3: [&str; 3] = ["h3-25", "h3-24", "h3-23"];

    pub fn length_prefixed(alpns: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();

        for s in alpns {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }

        out
    }
}

pub trait Args {
    fn with_docopt(docopt: &docopt::Docopt) -> Self;
}

/// Contains commons arguments for creating a quiche QUIC connection.
pub struct CommonArgs {
    pub alpns: Vec<u8>,
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub dump_packet_path: Option<String>,
    pub no_grease: bool,
}

/// Creates a new `CommonArgs` structure using the provided [`Docopt`].
///
/// The `Docopt` usage String needs to include the following:
///
/// --http-version VERSION   HTTP version to use
/// --max-data BYTES         Connection-wide flow control limit.
/// --max-stream-data BYTES  Per-stream flow control limit.
/// --max-streams-bidi STREAMS  Number of allowed concurrent streams.
/// --max-streams-uni STREAMS   Number of allowed concurrent streams.
/// --dump-packets PATH         Dump the incoming packets as files in the
/// given directory. --no-grease                 Don't send GREASE.
///
/// [`Docopt`]: https://docs.rs/docopt/1.1.0/docopt/
impl Args for CommonArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let http_version = args.get_str("--http-version");
        let alpns = match http_version {
            "HTTP/0.9" => alpns::length_prefixed(&alpns::HTTP_09),

            "HTTP/3" => alpns::length_prefixed(&alpns::HTTP_3),

            "all" => [
                alpns::length_prefixed(&alpns::HTTP_3),
                alpns::length_prefixed(&alpns::HTTP_09),
            ]
            .concat(),

            _ => panic!("Unsupported HTTP version"),
        };

        let max_data = args.get_str("--max-data");
        let max_data = u64::from_str_radix(max_data, 10).unwrap();

        let max_stream_data = args.get_str("--max-stream-data");
        let max_stream_data = u64::from_str_radix(max_stream_data, 10).unwrap();

        let max_streams_bidi = args.get_str("--max-streams-bidi");
        let max_streams_bidi = u64::from_str_radix(max_streams_bidi, 10).unwrap();

        let max_streams_uni = args.get_str("--max-streams-uni");
        let max_streams_uni = u64::from_str_radix(max_streams_uni, 10).unwrap();

        let dump_packet_path = if args.get_str("--dump-packets") != "" {
            Some(args.get_str("--dump-packets").to_string())
        } else {
            None
        };

        let no_grease = args.get_bool("--no-grease");

        CommonArgs {
            alpns,
            max_data,
            max_stream_data,
            max_streams_bidi,
            max_streams_uni,
            dump_packet_path,
            no_grease,
        }
    }
}

pub struct PartialResponse {
    pub body: Vec<u8>,

    pub written: usize,
}

pub struct Client {
    pub conn: std::pin::Pin<Box<quiche::Connection>>,

    pub http_conn: Option<Box<dyn crate::HttpConn>>,

    pub partial_responses: std::collections::HashMap<u64, PartialResponse>,
}

pub type ClientMap = HashMap<Vec<u8>, (net::SocketAddr, Client)>;

/// Makes a buffered writer for a resource with a target URL.
///
/// The file will have the same name as the resource's last path segment value.
/// Multiple requests for the same URL are indicated by the value of `cardinal`,
/// any value "N" greater than 1, will cause ".N" to be appended to the
/// filename.
fn make_writer(
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

            Err(e) => panic!("Bad times: {}", e),
        }
    }

    None
}

pub trait HttpConn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    );

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    );

    fn report_incomplete(&self, start: &std::time::Instant);

    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        buf: &mut [u8],
    ) -> quiche::h3::Result<()>;

    fn handle_writable(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
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
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

#[derive(Default)]
pub struct Http09Conn {
    stream_id: u64,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs: Vec<Http09Request>,
}

impl Http09Conn {
    pub fn with_urls(urls: &[url::Url], reqs_cardinal: u64) -> Box<dyn HttpConn> {
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
            info!("sending HTTP request {:?}", req.request_line);

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

            req.stream_id = Some(self.stream_id);
            req.response_writer =
                make_writer(&req.url, target_path, req.cardinal);

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
                debug!("received {} bytes", read);

                let stream_buf = &buf[..read];

                debug!(
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
                        print!("{}", unsafe {
                            std::str::from_utf8_unchecked(&stream_buf)
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

    fn report_incomplete(&self, start: &std::time::Instant) {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );
        }
    }

    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                debug!("{} received {} bytes", conn.trace_id(), read);

                let stream_buf = &buf[..read];

                debug!(
                    "{} stream {} has {} bytes (fin? {})",
                    conn.trace_id(),
                    s,
                    stream_buf.len(),
                    fin
                );

                if stream_buf.len() > 4 && &stream_buf[..4] == b"GET " {
                    let uri = &buf[4..stream_buf.len()];
                    let uri = String::from_utf8(uri.to_vec()).unwrap();
                    let uri = String::from(uri.lines().next().unwrap());
                    let uri = std::path::Path::new(&uri);
                    let mut path = std::path::PathBuf::from(root);

                    for c in uri.components() {
                        if let std::path::Component::Normal(v) = c {
                            path.push(v)
                        }
                    }

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
                        let response = PartialResponse { body, written };
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
        debug!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();
        let body = &resp.body[resp.written..];

        let written = match conn.stream_send(stream_id, &body, true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
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

pub struct Http3Conn {
    h3_conn: quiche::h3::Connection,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs: Vec<Http3Request>,
    body: Option<Vec<u8>>,
}

impl Http3Conn {
    pub fn with_urls(
        conn: &mut quiche::Connection, urls: &[url::Url], reqs_cardinal: u64,
        req_headers: &[String], body: &Option<Vec<u8>>, method: &str,
    ) -> Box<dyn HttpConn> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let mut hdrs = vec![
                    quiche::h3::Header::new(":method", &method),
                    quiche::h3::Header::new(":scheme", url.scheme()),
                    quiche::h3::Header::new(
                        ":authority",
                        url.host_str().unwrap(),
                    ),
                    quiche::h3::Header::new(
                        ":path",
                        &url[url::Position::BeforePath..],
                    ),
                    quiche::h3::Header::new("user-agent", "quiche"),
                ];

                // Add custom headers to the request.
                for header in req_headers {
                    let header_split: Vec<&str> =
                        header.splitn(2, ": ").collect();
                    if header_split.len() != 2 {
                        panic!("malformed header provided - \"{}\"", header);
                    }

                    hdrs.push(quiche::h3::Header::new(
                        header_split[0],
                        header_split[1],
                    ));
                }

                if body.is_some() {
                    hdrs.push(quiche::h3::Header::new(
                        "content-length",
                        &body.as_ref().unwrap().len().to_string(),
                    ));
                }

                reqs.push(Http3Request {
                    url: url.clone(),
                    cardinal: i,
                    hdrs,
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
            reqs_sent: 0,
            reqs_complete: 0,
            reqs,
            body: None,
        };

        Box::new(h_conn)
    }

    pub fn with_conn(conn: &mut quiche::Connection) -> Box<dyn HttpConn> {
        let h_conn = Http3Conn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &quiche::h3::Config::new().unwrap(),
            )
            .unwrap(),
            reqs_sent: 0,
            reqs_complete: 0,
            reqs: Vec::new(),
            body: None,
        };

        Box::new(h_conn)
    }

    /// Builds an HTTP/3 response given a request.
    fn build_h3_response(
        root: &str, request: &[quiche::h3::Header],
    ) -> (Vec<quiche::h3::Header>, Vec<u8>) {
        let mut file_path = std::path::PathBuf::from(root);
        let mut path = std::path::Path::new("");
        let mut method = "";

        // Look for the request's path and method.
        for hdr in request {
            match hdr.name() {
                ":path" => {
                    path = std::path::Path::new(hdr.value());
                },

                ":method" => {
                    method = hdr.value();
                },

                _ => (),
            }
        }

        let (status, body) = match method {
            "GET" => {
                for c in path.components() {
                    if let std::path::Component::Normal(v) = c {
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
            quiche::h3::Header::new(":status", &status.to_string()),
            quiche::h3::Header::new("server", "quiche"),
            quiche::h3::Header::new("content-length", &body.len().to_string()),
        ];

        (headers, body)
    }
}

impl HttpConn for Http3Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: &Option<String>,
    ) {
        let mut reqs_done = 0;

        for req in self.reqs.iter_mut().skip(self.reqs_sent) {
            info!("sending HTTP request {:?}", req.hdrs);

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

                Err(e) => {
                    error!("failed to send request {:?}", e);
                    break;
                },
            };

            req.stream_id = Some(s);
            req.response_writer =
                make_writer(&req.url, target_path, req.cardinal);

            if let Some(body) = &self.body {
                if let Err(e) = self.h3_conn.send_body(conn, s, body, true) {
                    error!("failed to send request body {:?}", e);
                    break;
                }
            }

            reqs_done += 1;
        }

        self.reqs_sent += reqs_done;
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!(
                        "got response headers {:?} on stream id {}",
                        list, stream_id
                    );
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    if let Ok(read) = self.h3_conn.recv_body(conn, stream_id, buf)
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

                        match &mut req.response_writer {
                            Some(rw) => {
                                rw.write_all(&buf[..read]).ok();
                            },

                            None => {
                                print!("{}", unsafe {
                                    std::str::from_utf8_unchecked(&buf[..read])
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

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    }
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

    fn report_incomplete(&self, start: &std::time::Instant) {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );
        }
    }

    fn handle_requests(
        &mut self, conn: &mut std::pin::Pin<Box<quiche::Connection>>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        _buf: &mut [u8],
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

                    // We decide the response based on headers alone, so
                    // stop reading the request stream so that any body
                    // is ignored and pointless Data events are not
                    // generated.
                    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                        .unwrap();

                    let (headers, body) =
                        Http3Conn::build_h3_response(root, &list);

                    if let Err(e) = self
                        .h3_conn
                        .send_response(conn, stream_id, &headers, false)
                    {
                        error!("{} stream send failed {:?}", conn.trace_id(), e);
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
                        let response = PartialResponse { body, written };
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

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", conn.trace_id(), e);

                    return Err(e);
                },
            }
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
        let body = &resp.body[resp.written..];

        let written = match self.h3_conn.send_body(conn, stream_id, body, true) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => 0,

            Err(e) => {
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
