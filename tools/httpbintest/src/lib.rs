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

//! 🗑️ HTTP/3 httpbin test client helper.
//!
//! This crate provides an API to build httpbin test requests and expected
//! outcomes. These can be used with the [quiche] HTTP/3 module to
//! communicate with an httpbin test server.
//!
//! ## Creating a test
//!
//! A test is an instance of [`HttpBinTest`], which consists of a set of
//! [`HttpBinReq`] and a single [`HttpBinTestAssert`].
//!
//! Each [`HttpBinReq`] is constructed with an HTTP request to a target
//! httpbin server and a test path, for example https://httpbin.org/get.
//!
//! Creating a single request:
//!
//! ```no_run
//! let server = "https://cloudflare-quic.com/b";
//! let mut url = url::Url::parse(server).unwrap();
//! let mut reqs = Vec::new();
//!
//! let path = format!("{}/{}", url.path(), "get");
//! url.set_path(&path);
//! reqs.push(httpbintest::HttpBinReq::new("GET", &url, None, None));
//! ```
//!
//! Assertions are used to check the received response headers and body
//! against expectations. Each test has a [`HttpBinTestAssert`] which
//! can access the received data. For example, to check the response
//! status code is a 200 we could write the function:
//!
//! ```no_run
//! fn assert_status(reqs: &[httpbintest::HttpBinReq]) {
//!     let status = reqs[0].resp_hdrs.iter().find(|&x| x.name() == ":status").unwrap();
//!     assert_eq!(status.value(), "200");
//! }
//! ```
//!
//! However, because checking response headers is so common, for convenience
//! the expected headers can be provided during [`HttpBinTestAssert`]
//! construction:
//!
//! ```no_run
//! # let server = "https://cloudflare-quic.com/b";
//! # let mut url = url::Url::parse(server).unwrap();
//! # let mut reqs = Vec::new();
//!
//! # let path = format!("{}/{}", url.path(), "get");
//! # url.set_path(&path);
//!
//! let expect_hdrs = Some(vec![quiche::h3::Header::new(":status", "200")]);
//! reqs.push(httpbintest::HttpBinReq::new("GET", &url, None, expect_hdrs));
//! ```
//!
//! The [`assert_hdrs()`] method can be used to validate the received headers,
//! this means we can write a much simpler assertion:
//!
//! ```no_run
//! fn assert_status(reqs: &[httpbintest::HttpBinReq]) {
//!     reqs[0].assert_hdrs();
//! }
//! ```
//!
//! Whatever methods you choose to use, once the requests and assertions are
//! made we can create the test:
//!
//! ```no_run
//! let server = "https://cloudflare-quic.com/b";
//! let mut url = url::Url::parse(server).unwrap();
//! let mut reqs = Vec::new();
//!
//! let path = format!("{}/{}", url.path(), "get");
//! url.set_path(&path);
//!
//! let expect_hdrs = Some(vec![quiche::h3::Header::new(":status", "200")]);
//! reqs.push(httpbintest::HttpBinReq::new("GET", &url, None, expect_hdrs));
//!
//! // Using a closure...
//! let assert = |reqs: &[httpbintest::HttpBinReq]| reqs[0].assert_hdrs();
//!
//! let mut test = httpbintest::HttpBinTest::new(url, reqs, assert, true);
//! ```
//!
//! ## Sending test requests
//!
//! Testing a httpbin server requires a quiche connection and a HTTP/3
//! connection.
//!
//! Request are issued with the [`send_request()`] method. By default, all
//! requests are made concurrently. This can be disabled with the
//! [`set_concurrency()`] method, which causes  [`send_request()`] to send a
//! single request and return. Call the method multiple times to issue all more
//! test requests. Once all requests have been sent, further calls will return
//! `quiche::h3:Error::Done`.
//!
//! Example:
//! ```no_run
//! # let server = "https://cloudflare-quic.com/b";
//! # let mut url = url::Url::parse(server).unwrap();
//! # let mut reqs = Vec::new();
//!
//! # let path = format!("{}/{}", url.path(), "get");
//! # url.set_path(&path);
//!
//! # let expect_hdrs = Some(vec![quiche::h3::Header::new(":status", "200")]);
//! # reqs.push(httpbintest::HttpBinReq::new("GET", &url, None, expect_hdrs));
//!
//! # // Using a closure...
//! # let assert = |reqs: &[httpbintest::HttpBinReq]| {
//! #   reqs[0].assert_hdrs()
//! # };
//!
//! let mut test = httpbintest::HttpBinTest::new(url, reqs, assert, true);
//!
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! let scid = [0xba; 16];
//! let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
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
//! # let server = "https://cloudflare-quic.com/b";
//! # let mut url = url::Url::parse(server).unwrap();
//! # let mut reqs = Vec::new();
//!
//! # let path = format!("{}/{}", url.path(), "get");
//! # url.set_path(&path);
//!
//! # let expect_hdrs = Some(vec![quiche::h3::Header::new(":status", "200")]);
//! # reqs.push(httpbintest::HttpBinReq::new("GET", &url, None, expect_hdrs));
//!
//! # // Using a closure...
//! # let assert = |reqs: &[httpbintest::HttpBinReq]| {
//! #   reqs[0].assert_hdrs()
//! # };
//!
//! # let mut test = httpbintest::HttpBinTest::new(url, reqs, assert, true);
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! # let mut http3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! match http3_conn.poll(&mut conn) {
//!     Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
//!         test.add_response_headers(stream_id, &headers);
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
//! entire set of [`HttpBinReq`]s. Calling this prematurely is likely to result
//! in failure, so it is important to store response data and track the number
//! of completed requests matches the total for a test.
//!
//! ```no_run
//! # let server = "https://cloudflare-quic.com/b";
//! # let mut url = url::Url::parse(server).unwrap();
//! # let mut reqs = Vec::new();
//!
//! # let path = format!("{}/{}", url.path(), "get");
//! # url.set_path(&path);
//!
//! # let expect_hdrs = Some(vec![quiche::h3::Header::new(":status", "200")]);
//! # reqs.push(httpbintest::HttpBinReq::new("GET", &url, None, expect_hdrs));
//!
//! # // Using a closure...
//! # let assert = |reqs: &[httpbintest::HttpBinReq]| {
//! #   reqs[0].assert_hdrs()
//! # };
//!
//! # let mut test = httpbintest::HttpBinTest::new(url, reqs, assert, true);
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
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
//! [quiche]: https://github.com/cloudflare/quiche/
//! [test]: struct.HttpBinTest.html
//! [`HttpBinTest`]: struct.HttpBinTest.html
//! [`assert_hdrs()`]: struct.HttpBinTest.html#method.assert_hdrs
//! [`requests_count()`]: struct.HttpBinTest.html#method.requests_count
//! [`set_concurrency()`]: struct.HttpBinTest.html#method.set_concurrency
//! [`add_response_headers()`]: struct.HttpBinTest.html#method.add_response_headers
//! [`add_response_body()`]: struct.HttpBinTest.html#method.add_response_body
//! [`assert()`]: struct.HttpBinTest.html#method.assert

#[macro_use]
extern crate log;

use std::collections::HashMap;

use quiche::h3::Header;

const USER_AGENT: &str = "quiche-http3bin";

// Stores the request, the expected response headers, and the actual response.
// The assert_hdrs() method is provided for convenience to validate the received
// headers match the expected headers.
#[derive(Clone)]
pub struct HttpBinReq {
    url: url::Url,
    hdrs: Vec<Header>,
    body: Option<Vec<u8>>,
    expect_resp_hdrs: Option<Vec<Header>>,
    pub resp_hdrs: Vec<Header>,
    resp_body: Vec<u8>,
}

impl HttpBinReq {
    pub fn new(
        method: &str, url: &url::Url, body: Option<Vec<u8>>,
        expect_resp_hdrs: Option<Vec<Header>>,
    ) -> HttpBinReq {
        let mut path = String::from(url.path());
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let mut hdrs = vec![
            Header::new(":method", method),
            Header::new(":scheme", url.scheme()),
            Header::new(":authority", url.host_str().unwrap()),
            Header::new(":path", &path),
            Header::new("user-agent", USER_AGENT),
        ];

        if let Some(body) = &body {
            hdrs.push(Header::new("content-length", &body.len().to_string()));
        }

        HttpBinReq {
            url: url.clone(),
            hdrs,
            body,
            expect_resp_hdrs: expect_resp_hdrs.clone(),
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
        }
    }

    pub fn assert_hdrs(&self) {
        if let Some(expect_hdrs) = &self.expect_resp_hdrs {
            for hdr in expect_hdrs {
                match self.resp_hdrs.iter().find(|&x| x.name() == hdr.name()) {
                    Some(h) => { assert_eq!(hdr.value(), h.value());},

                    None => { panic!(format!("Response header field {} not found!", hdr.name()));}
                }
            }
        }
    }
}

// A rudimentary structure to hold httpbin response data
#[derive(Debug, serde::Deserialize)]
struct HttpBinResponseBody {
    args: Option<HashMap<String, String>>,
    data: Option<String>,
    files: Option<HashMap<String, String>>,
    form: Option<HashMap<String, String>>,
    headers: Option<HashMap<String, String>>,
    json: Option<HashMap<String, String>>,
    #[serde(rename = "user-agent")]
    user_agent: Option<String>,
    server: Option<String>,
    #[serde(rename = "content-type")]
    content_type: Option<Vec<String>>,
    origin: Option<String>,
    url: Option<String>,
}

// A helper function pointer type for assertions.
// Each test assertion can check the set of HttpBinReq
// however they like.
type HttpBinTestAssert = fn(&[HttpBinReq]);

// The main object for getting things done. The factory method
// new() is used to set up a vector of HttpBinReq objects
// and map them to a test assertion function. The public functions
// are used to send requests and store response data. Internally
// we track some other state to make sure everything goes smoothly.
//
// Many tests have similar inputs or assertions, so utility functions
// help cover many of the common cases like testing different status
// codes or checking that a response body is echoed back.
pub struct HttpBinTest {
    endpoint: url::Url,
    reqs: Vec<HttpBinReq>,
    assert: HttpBinTestAssert,
    issued_reqs: HashMap<u64, usize>,
    concurrent: bool,
    current_idx: usize,
}

impl HttpBinTest {
    pub fn new(
        endpoint: url::Url, reqs: Vec<HttpBinReq>, assert: HttpBinTestAssert,
        concurrent: bool,
    ) -> HttpBinTest {
        HttpBinTest {
            endpoint,
            reqs,
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

    /// Execute the test assertion(s).
    pub fn assert(&mut self) {
        (self.assert)(&self.reqs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn run_test<T>(test: T) -> ()
    where
        T: FnOnce() -> () + std::panic::UnwindSafe,
    {
        INIT.call_once(|| {
            env_logger::builder()
                .default_format_timestamp_nanos(true)
                .init()
        });

        let result = std::panic::catch_unwind(|| test());

        assert!(result.is_ok())
    }

    fn endpoint(testpoint: Option<&str>) -> url::Url {
        let endpoint = match std::env::var_os("HTTPBIN_ENDPOINT") {
            Some(val) => val.into_string().unwrap(),

            None => String::from("https://cloudflare-quic.com/b"),
        };

        let mut url = url::Url::parse(&endpoint).unwrap();

        if let Some(testpoint) = testpoint {
            let path = format!("{}/{}", url.path(), &testpoint);
            url.set_path(&path);
        }

        url
    }

    fn jsonify(data: &[u8]) -> HttpBinResponseBody {
        serde_json::from_slice(&data).unwrap()
    }

    fn do_test(
        reqs: Vec<HttpBinReq>, assert: HttpBinTestAssert, concurrent: bool,
    ) {
        let mut test = HttpBinTest::new(endpoint(None), reqs, assert, concurrent);
        crate::runner::run(&mut test);
    }

    // Build a single request and expected response with status code
    fn request_check_status(testpoint: &str, status: usize) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", &status.to_string())]);

        let url = endpoint(Some(testpoint));

        vec![HttpBinReq::new("GET", &url, None, expect_hdrs)]
    }

    // Build a single request with a simple JSON body using the provided method
    fn request_with_body(method: &str) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some(&method.to_ascii_lowercase()));

        let req_body = serde_json::json!({"key1": "value1", "key2": "value2"});

        let mut req = HttpBinReq::new(
            &method.to_ascii_uppercase(),
            &url,
            Some(req_body.to_string().into_bytes()),
            expect_hdrs,
        );

        req.hdrs
            .push(Header::new("content-type", "application/json"));

        vec![req]
    }

    fn assert_request_body(reqs: &[HttpBinReq]) {
        reqs[0].assert_hdrs();

        let json = jsonify(&reqs[0].resp_body).json.unwrap();

        assert_eq!(json["key1"], "value1");
        assert_eq!(json["key2"], "value2");
    }

    fn assert_headers_only(reqs: &[HttpBinReq]) {
        for req in reqs {
            req.assert_hdrs();
        }
    }

    #[test]
    fn get() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let mut url = endpoint(Some("get"));

        // Request 1
        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs.clone()));

        // Request 2
        url.set_query(Some("key1=value1&key2=value2"));
        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();
            reqs[1].assert_hdrs();

            let json = jsonify(&reqs[1].resp_body);
            if let Some(args) = json.args {
                assert_eq!(args["key1"], "value1");
                assert_eq!(args["key2"], "value2");
            }
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn ip() {
        let reqs = request_check_status("ip", 200);

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();

            let json = jsonify(&reqs[0].resp_body);
            assert!(json.origin.is_some());
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn useragent() {
        let reqs = request_check_status("user-agent", 200);

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();

            let json = jsonify(&reqs[0].resp_body);
            assert_eq!(json.user_agent, Some(USER_AGENT.to_string()));
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn headers() {
        let reqs = request_check_status("headers", 200);

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();

            let json = jsonify(&reqs[0].resp_body);
            if let Some(args) = json.args {
                assert_eq!(args["Host"], reqs[0].url.host_str().unwrap());
            }
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn post() {
        let reqs = request_with_body("post");

        run_test(|| {
            do_test(reqs, assert_request_body, true);
        })
    }

    #[test]
    fn put() {
        let reqs = request_with_body("put");

        run_test(|| {
            do_test(reqs, assert_request_body, true);
        })
    }

    #[test]
    fn patch() {
        let reqs = request_with_body("patch");
        run_test(|| {
            do_test(reqs, assert_request_body, true);
        })
    }

    #[test]
    fn delete() {
        let reqs = request_with_body("delete");
        run_test(|| {
            do_test(reqs, assert_request_body, true);
        })
    }

    #[test]
    fn encode_utf8() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-type", "text/html; charset=utf-8"),
        ]);

        let url = endpoint(Some("encoding/utf8"));

        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn gzip() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-encoding", "gzip"),
        ]);

        let url = endpoint(Some("gzip"));

        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept-encoding", "gzip"));

        reqs.push(req);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn deflate() {
        let mut reqs = Vec::new();

        // Not all servers actually take up the deflate option,
        // so don't check content-type response header.
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("deflate"));

        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept-encoding", "deflate"));

        reqs.push(req);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn status() {
        let mut reqs = Vec::new();

        for i in (200..600).step_by(100) {
            for j in 0..5 {
                let expect_hdrs =
                    Some(vec![Header::new(":status", &(i + j).to_string())]);

                let testpoint = format!("{}/{}", "status", i + j);
                let url = endpoint(Some(&testpoint));

                reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));
            }
        }

        run_test(|| {
            do_test(reqs, assert_headers_only, false);
        })
    }

    #[test]
    fn response_headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let mut url = endpoint(Some("response-headers"));
        url.set_query(Some(
            "content-type=text/plain;+charset=UTF-8&server=httpbin",
        ));
        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();
            let json = jsonify(&reqs[0].resp_body);

            let server = json.server.unwrap();
            assert_eq!(server, "httpbin");

            let content_type = json.content_type.unwrap();
            assert_eq!(content_type[0], "application/json");
            assert_eq!(content_type[1], "text/plain; charset=UTF-8");
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn redirect() {
        let mut reqs = Vec::new();
        let mut url = endpoint(Some("redirect-to"));

        // Request 1
        let expect_hdrs = Some(vec![
            Header::new(":status", "302"),
            Header::new("location", "https://example.com"),
        ]);

        url.set_query(Some("url=https://example.com"));

        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "307"),
            Header::new("location", "https://example.com"),
        ]);
        url.set_query(Some("url=https://example.com&status_code=307"));

        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        // Request 3
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);
        let url = endpoint(Some("relative-redirect/3"));
        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn cookies() {
        // Tests cookie redirect cases since the client ignores cookies
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);
        let mut url = endpoint(Some("cookies/set"));
        url.set_query(Some("k1=v1"));

        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);

        let mut url = endpoint(Some("cookies/set"));
        url.set_query(Some("k1=v1"));

        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn basic_auth() {
        let mut reqs = Vec::new();
        let url = endpoint(Some("basic-auth/user/passwd"));

        let expect_hdrs = Some(vec![
            Header::new(":status", "401"),
            Header::new("www-authenticate", "Basic realm=\"Fake Realm\""),
        ]);

        reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn stream() {
        let mut reqs = Vec::new();

        let sizes = [1, 50, 100];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let testpoint = format!("{}/{}", "stream", size.to_string());

            let url = endpoint(Some(&testpoint));

            reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));
        }

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();
            reqs[1].assert_hdrs();
            reqs[2].assert_hdrs();

            let line_count = std::str::from_utf8(&reqs[0].resp_body)
                .unwrap()
                .matches('\n')
                .count();
            assert_eq!(line_count, 1);

            let line_count = std::str::from_utf8(&reqs[1].resp_body)
                .unwrap()
                .matches('\n')
                .count();
            assert_eq!(line_count, 50);

            let line_count = std::str::from_utf8(&reqs[2].resp_body)
                .unwrap()
                .matches('\n')
                .count();
            assert_eq!(line_count, 100);
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn delay() {
        let mut reqs = Vec::new();

        let delays = [1, 10, 30];

        for delay in &delays {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let testpoint = format!("{}/{}", "delay", delay);
            let url = endpoint(Some(&testpoint));

            reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));
        }

        run_test(|| {
            do_test(reqs, assert_headers_only, false);
        })
    }

    #[test]
    fn drip() {
        let mut reqs = Vec::new();

        let durations = [1, 10, 30];

        for duration in &durations {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let mut url = endpoint(Some("drip"));
            url.set_query(Some(&format!(
                "duration={}&numbytes=5&code=200",
                duration
            )));

            reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));
        }

        run_test(|| {
            do_test(reqs, assert_headers_only, false);
        })
    }

    #[test]
    fn range() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("range/102400"));

        let req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "206"),
            Header::new("content-range", "bytes 0-49/102400"),
        ]);

        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("range", "bytes=0-49"));
        reqs.push(req);

        // Request 3
        let expect_hdrs = Some(vec![
            Header::new(":status", "206"),
            Header::new("content-range", "bytes 100-10000/102400"),
        ]);
        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("range", "bytes=100-10000"));
        reqs.push(req);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn cache() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("cache"));

        let req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![Header::new(":status", "304")]);

        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        ));
        reqs.push(req);

        // Request 3
        let expect_hdrs = Some(vec![Header::new(":status", "304")]);
        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("if-none-match", "*"));
        reqs.push(req);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn bytes() {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-length", &size.to_string()),
            ]);

            let testpoint = format!("{}/{}", "bytes", size.to_string());
            let url = endpoint(Some(&testpoint));

            reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));
        }

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn stream_bytes() {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let testpoint = format!("{}/{}", "stream-bytes", size.to_string());
            let url = endpoint(Some(&testpoint));

            reqs.push(HttpBinReq::new("GET", &url, None, expect_hdrs));
        }

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn image() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "406")]);

        let url = endpoint(Some("image"));

        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept", "*/*"));
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-type", "image/png"),
        ]);
        let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept", "image/*"));
        reqs.push(req);

        // Multiple requests based on accept
        let formats = ["image/webp", "image/svg+xml", "image/jpeg", "image/png"];
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-type", &format),
            ]);

            let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
            req.hdrs.push(Header::new("accept", &format));
            reqs.push(req);
        }

        // Multiple requests based on path
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-type", &format),
            ]);

            let testpoint = if format == &"image/svg+xml" {
                "image/svg"
            } else {
                format
            };

            let url = endpoint(Some(&testpoint));
            let mut req = HttpBinReq::new("GET", &url, None, expect_hdrs);
            req.hdrs.push(Header::new("accept", &format));
            reqs.push(req);
        }

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn form() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("post"));

        let req_body = "custname=dave&custtel=1234&custemail=dave@example.com&size=large&topping=bacon&delivery=&comments=pronto";

        let mut req = HttpBinReq::new(
            "POST",
            &url,
            Some(req_body.to_string().into_bytes()),
            expect_hdrs,
        );

        req.hdrs.push(Header::new(
            "content-type",
            "application/x-www-form-urlencoded",
        ));
        reqs.push(req);

        let assert = |reqs: &[HttpBinReq]| {
            reqs[0].assert_hdrs();

            let json = jsonify(&reqs[0].resp_body);
            if let Some(form) = json.form {
                assert_eq!(form["custname"], "dave");
                assert_eq!(form["custtel"], "1234");
                assert_eq!(form["custemail"], "dave@example.com");
                assert_eq!(form["size"], "large");
                assert_eq!(form["topping"], "bacon");
                assert_eq!(form["delivery"], "");
                assert_eq!(form["comments"], "pronto");
            }
        };

        run_test(|| {
            do_test(reqs, assert, true);
        })
    }

    #[test]
    fn html() {
        let reqs = request_check_status("html", 200);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn xml() {
        let reqs = request_check_status("xml", 200);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn robots() {
        let reqs = request_check_status("robots.txt", 200);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }

    #[test]
    fn links() {
        let reqs = request_check_status("links/10", 302);

        run_test(|| {
            do_test(reqs, assert_headers_only, true);
        })
    }
}

mod runner;
