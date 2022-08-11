// Copyright (C) 2019, Cloudflare, Inc.
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

//! 🔧 HTTP/3 integration test utilities.
//!
//! This crate provides utilities to help integration tests against HTTP/3
//! endpoints. Structures and methods can be combined with a [`quiche`]
//! HTTP/3 client to run tests against a server. This client could be a
//! binary or run as part of cargo test.
//!
//! ## Creating a test
//!
//! A test is an instance of [`Http3Test`], which consists of a set of
//! [`Http3Req`] and a single [`Http3Assert`].
//!
//!
//! Creating a single request:
//!
//! ```no_run
//! let mut url = url::Url::parse("https://cloudflare-quic.com/b/get").unwrap();
//! let mut reqs = Vec::new();
//!
//! reqs.push(http3_test::Http3Req::new(b"GET", &url, None, None));
//! ```
//!
//! Assertions are used to check the received response headers and body
//! against expectations. Each test has a [`Http3Assert`] which
//! can access the received data. For example, to check the response
//! status code is a 200 we could write the function:
//!
//! ```no_run
//! fn assert_status(reqs: &[http3_test::Http3Req]) {
//!     let status = reqs[0]
//!         .resp_hdrs
//!         .iter()
//!         .find(|&x| x.name() == ":status")
//!         .unwrap();
//!     assert_eq!(status.value(), "200");
//! }
//! ```
//!
//! However, because checking response headers is so common, for convenience
//! the expected headers can be provided during [`Http3Assert`] construction:
//!
//! ```no_run
//! let mut url = url::Url::parse("https://cloudflare-quic.com/b/get").unwrap();
//! let mut reqs = Vec::new();
//!
//! let expect_hdrs = Some(vec![quiche::h3::Header::new(b":status", "200")]);
//! reqs.push(http3_test::Http3Req::new(b"GET", &url, None, expect_hdrs));
//! ```
//!
//! The [`assert_headers!`] macro can be used to validate the received headers,
//! this means we can write a much simpler assertion:
//!
//! ```no_run
//! fn assert_status(reqs: &[http3_test::Http3Req]) {
//!     http3_test::assert_headers!(reqs[0]);
//! }
//! ```
//!
//! Whatever methods you choose to use, once the requests and assertions are
//! made we can create the test:
//!
//! ```no_run
//! let mut url = url::Url::parse("https://cloudflare-quic.com/b/get").unwrap();
//! let mut reqs = Vec::new();
//!
//! let expect_hdrs = Some(vec![quiche::h3::Header::new(b":status", "200")]);
//! reqs.push(http3_test::Http3Req::new(b"GET", &url, None, expect_hdrs));
//!
//! // Using a closure...
//! let assert =
//!     |reqs: &[http3_test::Http3Req]| http3_test::assert_headers!(reqs[0]);
//!
//! let mut test = http3_test::Http3Test::new(url, reqs, assert, true);
//! ```
//!
//! ## Sending test requests
//!
//! Testing a server requires a quiche connection and an HTTP/3 connection.
//!
//! Request are issued with the [`send_requests()`] method. The concurrency
//! of requests within a single Http3Test is set in [`new()`]. If concurrency is
//! disabled [`send_requests()`] will to send a single request and return.
//! So call the method multiple times to issue more requests. Once all
//! requests have been sent, further calls will return `quiche::h3:Error::Done`.
//!
//! Example:
//! ```no_run
//! # let mut url = url::Url::parse("https://cloudflare-quic.com/b/get").unwrap();
//! # let mut reqs = Vec::new();
//! # let expect_hdrs = Some(vec![quiche::h3::Header::new(b":status", "200")]);
//! # reqs.push(http3_test::Http3Req::new(b"GET", &url, None, expect_hdrs));
//! # // Using a closure...
//! # let assert = |reqs: &[http3_test::Http3Req]| {
//! #   http3_test::assert_headers!(reqs[0]);
//! # };
//! let mut test = http3_test::Http3Test::new(url, reqs, assert, true);
//!
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! let scid = [0xba; 16];
//! let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! let h3_config = quiche::h3::Config::new()?;
//! let mut http3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//!
//! test.send_requests(&mut conn, &mut http3_conn).unwrap();
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Handling responses
//!
//! Response data is used to validate test cases so it is important to
//! store received data in the test object. This can be done with the
//! [`add_response_headers()`] and [`add_response_body()`] methods. Note
//! that the stream ID is used to correlate the response with the correct
//! request.
//!
//! For example, when handling HTTP/3 connection events using `poll()`:
//!
//! ```no_run
//! # let mut url = url::Url::parse("https://cloudflare-quic.com/b/get").unwrap();
//! # let mut reqs = Vec::new();
//! # let expect_hdrs = Some(vec![quiche::h3::Header::new(b":status", "200")]);
//! # reqs.push(http3_test::Http3Req::new(b"GET", &url, None, expect_hdrs));
//! # // Using a closure...
//! # let assert = |reqs: &[http3_test::Http3Req]| {
//! #   http3_test::assert_headers!(reqs[0]);
//! # };
//! # let mut test = http3_test::Http3Test::new(url, reqs, assert, true);
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new()?;
//! # let mut http3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! match http3_conn.poll(&mut conn) {
//!     Ok((stream_id, quiche::h3::Event::Headers{list, has_body})) => {
//!         test.add_response_headers(stream_id, &list);
//!     },
//!
//!     Ok((stream_id, quiche::h3::Event::Data)) => {
//!         let mut buf = [0; 65535];
//!         if let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf)
//!         {
//!             test.add_response_body(stream_id, &buf, read);
//!         }
//!     },
//!
//!     _ => ()
//! }
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Tests assertion
//!
//! The [`assert()`] method executes the provided test assertion using the
//! entire set of [`Http3Req`]s. Calling this prematurely is likely to result
//! in failure, so it is important to store response data and track the number
//! of completed requests matches the total for a test.
//!
//! ```no_run
//! # let mut url = url::Url::parse("https://cloudflare-quic.com/b/get").unwrap();
//! # let mut reqs = Vec::new();
//! # let expect_hdrs = Some(vec![quiche::h3::Header::new(b":status", "200")]);
//! # reqs.push(http3_test::Http3Req::new(b"GET", &url, None, expect_hdrs));
//! # // Using a closure...
//! # let assert = |reqs: &[http3_test::Http3Req]| {
//! #   http3_test::assert_headers!(reqs[0]);
//! # };
//! # let mut test = http3_test::Http3Test::new(url, reqs, assert, true);
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new()?;
//! # let mut http3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let mut requests_complete = 0;
//! let request_count = test.requests_count();
//! match http3_conn.poll(&mut conn) {
//!     Ok((_stream_id, quiche::h3::Event::Finished)) => {
//!         requests_complete += 1;
//!         if requests_complete == request_count {
//!             test.assert()
//!         }
//!     },
//!     _ => ()
//! }
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! [`quiche`]: https://github.com/cloudflare/quiche/
//! [test]: struct.Http3Test.html
//! [`Http3Test`]: struct.Http3Test.html
//! [`Http3Assert`]: struct.Http3Assert.html
//! [`Http3req`]: struct.Http3Req.html
//! [`assert_headers!`]: macro.assert_headers.html
//! [`new()`]: struct.Http3Test.html#method.new
//! [`send_requests()`]: struct.Http3Test.html#method.send_requests
//! [`requests_count()`]: struct.Http3Test.html#method.requests_count
//! [`assert()`]: struct.Http3Test.html#method.assert
//! [`add_response_headers()`]:
//! struct.Http3Test.html#method.add_response_headers [`add_response_body()`]:
//! struct.Http3Test.html#method.add_response_body

#[macro_use]
extern crate log;

use std::collections::HashMap;

use quiche::h3::Header;

pub const USER_AGENT: &[u8] = b"quiche-http3-integration-client";

/// Stores the request, the expected response headers, and the actual response.
///
/// The assert_headers! macro is provided for convenience to validate the
/// received headers match the expected headers.
#[derive(Clone)]
pub struct Http3Req {
    pub url: url::Url,
    pub hdrs: Vec<Header>,
    pub body: Option<Vec<u8>>,
    pub expect_resp_hdrs: Option<Vec<Header>>,
    pub resp_hdrs: Vec<Header>,
    pub resp_body: Vec<u8>,
    pub reset_stream_code: Option<u64>,
}

impl Http3Req {
    pub fn new(
        method: &str, url: &url::Url, body: Option<Vec<u8>>,
        expect_resp_hdrs: Option<Vec<Header>>,
    ) -> Http3Req {
        let mut path = String::from(url.path());
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let mut hdrs = vec![
            Header::new(b":method", method.as_bytes()),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        if let Some(body) = &body {
            hdrs.push(Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ));
        }

        Http3Req {
            url: url.clone(),
            hdrs,
            body,
            expect_resp_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        }
    }
}

/// Asserts that the Http3Req received response headers match the expected
/// response headers.
///
/// Header values are compared with [`assert_eq!`] and this macro will panic
/// similarly.
///
/// If an expected header is not present this macro will panic and print the
/// missing header name.AsMut
///
/// [`assert_eq!`]: std/macro.assert.html
#[macro_export]
macro_rules! assert_headers {
    ($req:expr) => ({
        if let Some(expect_hdrs) = &$req.expect_resp_hdrs {
            for hdr in expect_hdrs {
                match $req.resp_hdrs.iter().find(|&x| x.name() == hdr.name()) {
                    Some(h) => assert_eq!(hdr.value(), h.value()),

                    None =>
                        panic!("assertion failed: expected response header field {} not present!", std::str::from_utf8(hdr.name()).unwrap()),
                }
            }
        }
    });
    ($req:expr,) => ({ $crate::assert_headers!($req)});
    ($req:expr, $($arg:tt)+) => ({
        if let Some(expect_hdrs) = &$req.expect_resp_hdrs {
            for hdr in expect_hdrs {
                match $req.resp_hdrs.iter().find(|&x| x.name() == hdr.name()) {
                    Some(h) => { assert_eq!(hdr.value(), h.value(), $($arg)+);},

                    None => {
                        panic!("assertion failed: expected response header field {} not present! {}", hdr.name(), $($arg)+);
                    }
                }
            }
        }
    });
}

/// A helper function pointer type for assertions.
///
/// Each test assertion can check the set of Http3Req
/// however they like.
pub type Http3Assert = fn(&[Http3Req]);

#[derive(Debug, PartialEq, Eq)]
pub enum Http3TestError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub struct ArbitraryStreamData {
    pub stream_id: u64,
    pub data: Vec<u8>,
    pub fin: bool,
}

/// The main object for getting things done.
///
/// The factory method new() is used to set up a vector of Http3Req objects and
/// map them to a test assertion function. The public functions are used to send
/// requests and store response data. Internally we track some other state to
/// make sure everything goes smoothly.
///
/// Many tests have similar inputs or assertions, so utility functions help
/// cover many of the common cases like testing different status codes or
/// checking that a response body is echoed back.
pub struct Http3Test {
    endpoint: url::Url,
    reqs: Vec<Http3Req>,
    stream_data: Option<Vec<ArbitraryStreamData>>,
    assert: Http3Assert,
    issued_reqs: HashMap<u64, usize>,
    concurrent: bool,
    current_idx: usize,
}

impl Http3Test {
    pub fn new(
        endpoint: url::Url, reqs: Vec<Http3Req>, assert: Http3Assert,
        concurrent: bool,
    ) -> Http3Test {
        Http3Test {
            endpoint,
            reqs,
            stream_data: None,
            assert,
            issued_reqs: HashMap::new(),
            concurrent,
            current_idx: 0,
        }
    }

    pub fn with_stream_data(
        endpoint: url::Url, reqs: Vec<Http3Req>,
        stream_data: Vec<ArbitraryStreamData>, assert: Http3Assert,
        concurrent: bool,
    ) -> Http3Test {
        Http3Test {
            endpoint,
            reqs,
            stream_data: Some(stream_data),
            assert,
            issued_reqs: HashMap::new(),
            concurrent,
            current_idx: 0,
        }
    }

    /// Returns the total number of requests in a test.
    pub fn requests_count(&mut self) -> usize {
        self.reqs.len()
    }

    pub fn endpoint(&self) -> url::Url {
        self.endpoint.clone()
    }

    /// Send one or more requests based on test type and the concurrency
    /// property. If any send fails, a quiche::h3::Error is returned.
    pub fn send_requests(
        &mut self, conn: &mut quiche::Connection,
        h3_conn: &mut quiche::h3::Connection,
    ) -> quiche::h3::Result<()> {
        if let Some(stream_data) = &self.stream_data {
            for d in stream_data {
                match conn.stream_send(d.stream_id, &d.data, d.fin) {
                    Ok(_) => (),

                    Err(e) => {
                        error!(
                            "failed to send data on stream {}: {:?}",
                            d.stream_id, e
                        );
                        return Err(From::from(e));
                    },
                }
            }
        }

        if self.reqs.len() - self.current_idx == 0 {
            return Err(quiche::h3::Error::Done);
        }

        let reqs_to_make = if self.concurrent {
            self.reqs.len() - self.current_idx
        } else {
            1
        };

        for _ in 0..reqs_to_make {
            let req = &self.reqs[self.current_idx];

            info!("sending HTTP request {:?}", req.hdrs);

            let s =
                match h3_conn.send_request(conn, &req.hdrs, req.body.is_none()) {
                    Ok(stream_id) => stream_id,

                    Err(e) => {
                        error!("failed to send request {:?}", e);
                        return Err(e);
                    },
                };

            self.issued_reqs.insert(s, self.current_idx);

            if let Some(body) = &req.body {
                info!("sending body {:?}", body);

                if let Err(e) = h3_conn.send_body(conn, s, body, true) {
                    error!("failed to send request body {:?}", e);
                    return Err(e);
                }
            }

            self.current_idx += 1;
        }

        Ok(())
    }

    /// Append response headers for an issued request.
    pub fn add_response_headers(&mut self, stream_id: u64, headers: &[Header]) {
        let i = self.issued_reqs.get(&stream_id).unwrap();
        self.reqs[*i].resp_hdrs.extend_from_slice(headers);
    }

    /// Append data to the response body for an issued request.
    pub fn add_response_body(
        &mut self, stream_id: u64, data: &[u8], data_len: usize,
    ) {
        let i = self.issued_reqs.get(&stream_id).unwrap();
        self.reqs[*i].resp_body.extend_from_slice(&data[..data_len]);
    }

    /// Sets the error code when a RESET_STREAM was received for an issued
    /// request.
    pub fn set_reset_stream_error(&mut self, stream_id: u64, error: u64) {
        let i = self.issued_reqs.get(&stream_id).unwrap();
        self.reqs[*i].reset_stream_code = Some(error);
    }

    /// Execute the test assertion(s).
    pub fn assert(&mut self) {
        (self.assert)(&self.reqs);
    }
}

pub mod runner;
