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
//! Tests are run against a target httpbin server and a test path,
//! for example https://httpbin.org/get.
//!
//! To create a [test]:
//!
//! ```
//! let server = "https://cloudflare-quic.com/b";
//! let url = url::Url::parse(server);
//! let test = "get"
//! let mut httpbin_test = http3bin_client::HttpBinTest::new(&mut url, test);
//! ```
//!
//! ## Test request count and concurrency
//!
//! A test may need to send one or more requests in order to fully
//! excersise all cases. Once a test is created you can query the
//! request count with the [`request_count()`] method.
//!
//! By default, all requests in a test are made concurrently. This
//! can be changed with the [`set_concurrent()`] method.
//!
//! Example:
//!
//! ```
//! let request_count = httpbin_test.request_count();
//! htttpbin_test.set_concurrent(false);
//! ```
//!
//! ## Sending test requests
//!
//! To issue a request, you can use the [`send_request()`] method. If
//! concurrency is enabled (the default) all requests will be made at the same
//! time. If disabled, the method will send a single request and return. Call
//! the method multiple times to issue all more test requests. Once completed,
//! the method will return `quiche::h3:Error::Done`.
//!
//! Example:
//!
//! ```
//! let mut conn = quiche::connect(/*..*/);
//! let mut http3_conn =
//!     quiche::h3::Connection::with_transport(&mut conn /* .. */);
//!
//! // Create test as described above, then
//! httpbin_test
//!     .send_requests(&mut conn, &mut http3_conn)
//!     .unwrap();
//! ```
//!
//! ## Handling responses
//!
//! Response data is used to validate test cases so it is important to
//! store received data in the test obejct. This can be done with the
//! [`add_response_headers()`] and [`add_response_body()`] methods. Note
//! that the stream ID is used to correlate the response with the correct
//! request.
//!
//! For example, when handling HTTP/3 connection events using `poll()`:
//!
//! ```
//! match http3_conn.poll() {
//!     Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
//!         httpbin_test.add_response_headers(stream_id, &headers);
//!     },
//!
//!     Ok((stream_id, quiche::h3::Event::Data)) => {
//!         let mut buf = [0; 65535];
//!         if let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf)
//!         {
//!             httpbin_test.add_response_body(stream_id, &buf, read);
//!         }
//!     },
//! }
//! ```
//!
//! ## Tests assertion
//!
//! Each test has a set of built-in validation steps that are performed across
//! all requests. Once all responses have been received and their data stored,
//! the [`assert()`] method can be used to validate. It returns `true` if
//! everything was fine or otherwise false.
//!
//! Calling [`assert()`] prematurely will always return false. So it helps to
//! track requests as so:
//!
//! ```
//! let mut requests_complete = 0;
//! let request_count = httpbin_test.request_count();
//! match http3_conn.poll() {
//!     Ok((_stream_id, quiche::h3::Event::Finished)) => {
//!         requests_complete += 1;
//!         if requests_complete == request_count {
//!             if !bin_test.assert() {
//!                 // handle test failure
//!             }
//!         }
//! }
//! ```
//!
//! [quiche]: https://github.com/cloudflare/quiche/
//! [test]: struct.HttpBinTest.html
//! [`request_count()`]: struct.HttpBinTest.html#method.request_count
//! [`set_concurrent()`]: struct.HttpBinTest.html#method.set_concurrent
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
struct HttpBinReq {
    url: url::Url,
    hdrs: Vec<Header>,
    body: Option<Vec<u8>>,
    expect_resp_hdrs: Option<Vec<Header>>,
    resp_hdrs: Vec<Header>,
    resp_body: Vec<u8>,
}

impl HttpBinReq {
    pub fn new(
        method: &str, url: &url::Url, body: Option<Vec<u8>>,
        expect_resp_hdrs: &Option<Vec<Header>>,
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

    pub fn assert_hdrs(&self) -> bool {
        let mut ok = true;

        if let Some(expect_hdrs) = &self.expect_resp_hdrs {
            for hdr in expect_hdrs {
                if let Some(h) =
                    self.resp_hdrs.iter().find(|&x| x.name() == hdr.name())
                {
                    ok &= hdr.value() == h.value();
                    continue;
                }

                ok &= false;
            }
        }

        ok
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
// Each test takes a vector of HttpBinReq for validation
// and must return a pass or fail.
type HttpBinTestAssert = (fn(&[HttpBinReq]) -> bool);

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
    reqs: Vec<HttpBinReq>,
    assert: HttpBinTestAssert,
    issued_reqs: HashMap<u64, usize>,
    concurrent: bool,
    current_idx: usize,
}

impl HttpBinTest {
    /// A factory method for building the test cases and assertions 
    /// for a particular httpbin server and test path. 
    pub fn new(mut url: &mut url::Url, test: &str) -> HttpBinTest {
        match test {
            "get" => Self::new_test(Self::test_get(url), Self::assert_get),

            "ip" => Self::new_test(
                Self::test_response_code(&mut url, test, 200),
                Self::assert_ip,
            ),

            "useragent" => Self::new_test(
                Self::test_response_code(&mut url, "user-agent", 200),
                Self::assert_useragent,
            ),

            "headers" => Self::new_test(
                Self::test_response_code(&mut url, test, 200),
                Self::assert_headers,
            ),

            "post" => Self::new_test(
                Self::test_request_body(&mut url, test),
                Self::assert_request_body,
            ),

            "put" => Self::new_test(
                Self::test_request_body(&mut url, test),
                Self::assert_request_body,
            ),

            "patch" => Self::new_test(
                Self::test_request_body(&mut url, test),
                Self::assert_request_body,
            ),

            "delete" => Self::new_test(
                Self::test_request_body(&mut url, test),
                Self::assert_request_body,
            ),

            "encode-utf8" => Self::new_test(
                Self::test_encode_utf8(&mut url),
                Self::assert_headers_only,
            ),

            "gzip" => Self::new_test(
                Self::test_gzip(&mut url),
                Self::assert_headers_only,
            ),

            "deflate" => Self::new_test(
                Self::test_deflate(&mut url),
                Self::assert_headers_only,
            ),

            "status" =>
                Self::new_test(Self::test_status(&mut url), Self::assert_status),

            "response-headers" => Self::new_test(
                Self::test_response_headers(&mut url),
                Self::assert_response_headers,
            ),

            "redirect" => Self::new_test(
                Self::test_redirect(&mut url),
                Self::assert_headers_only,
            ),

            "cookies" => Self::new_test(
                Self::test_cookies(&mut url),
                Self::assert_headers_only,
            ),

            "basic-auth" => Self::new_test(
                Self::test_basic_auth(&mut url),
                Self::assert_headers_only,
            ),

            "stream" =>
                Self::new_test(Self::test_stream(&mut url), Self::assert_stream),

            "delay" => Self::new_test(
                Self::test_delay(&mut url),
                Self::assert_headers_only,
            ),

            "drip" => Self::new_test(
                Self::test_drip(&mut url),
                Self::assert_headers_only,
            ),

            "range" => Self::new_test(
                Self::test_range(&mut url),
                Self::assert_headers_only,
            ),

            "cache" => Self::new_test(
                Self::test_cache(&mut url),
                Self::assert_headers_only,
            ),

            "bytes" => Self::new_test(
                Self::test_bytes(&mut url),
                Self::assert_headers_only,
            ),

            "stream-bytes" => Self::new_test(
                Self::test_stream_bytes(&mut url),
                Self::assert_headers_only,
            ),

            "image" => Self::new_test(
                Self::test_image(&mut url),
                Self::assert_headers_only,
            ),

            "form" =>
                Self::new_test(Self::test_form(&mut url), Self::assert_form),

            "html" | "xml" => Self::new_test(
                Self::test_response_code(&mut url, test, 200),
                Self::assert_headers_only,
            ),

            "robots" => Self::new_test(
                Self::test_response_code(&mut url, "robots.txt", 200),
                Self::assert_headers_only,
            ),

            "links" => Self::new_test(
                Self::test_response_code(&mut url, "links/10", 302),
                Self::assert_headers_only,
            ),

            _ => panic!("unknown test name \"{}\"", test),
        }
    }

    fn new_test(reqs: Vec<HttpBinReq>, assert: HttpBinTestAssert) -> HttpBinTest {
        HttpBinTest {
            reqs,
            assert,
            issued_reqs: HashMap::new(),
            concurrent: true,
            current_idx: 0,
        }
    }

    /// Set test request concurrency
    pub fn set_concurrency(&mut self, concurrent: bool) {
        self.concurrent = concurrent;
    }

    /// Returns the total number of requests in a test.
    pub fn requests_count(&mut self) -> usize {
        self.reqs.len()
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
    pub fn assert(&mut self) -> bool {
        (self.assert)(&self.reqs)
    }

    fn jsonify(data: &[u8]) -> HttpBinResponseBody {
        serde_json::from_slice(&data).unwrap()
    }

    fn test_get(url: &mut url::Url) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        // Request 1
        let path = format!("{}/{}", url.path(), "get");
        url.set_path(&path);

        let mut reqs = vec![HttpBinReq::new("GET", url, None, &expect_hdrs)];

        // Request 2
        url.set_query(Some("key1=value1&key2=value2"));
        reqs.push(HttpBinReq::new("GET", url, None, &expect_hdrs));

        reqs
    }

    fn assert_get(reqs: &[HttpBinReq]) -> bool {
        let mut ok = reqs[0].assert_hdrs();
        ok &= reqs[1].assert_hdrs();

        let json = Self::jsonify(&reqs[1].resp_body);
        if let Some(args) = json.args {
            ok &= args["key1"] == "value1";
            ok &= args["key2"] == "value2";
        }

        ok
    }

    fn assert_ip(reqs: &[HttpBinReq]) -> bool {
        let ok = reqs[0].assert_hdrs();

        let json = Self::jsonify(&reqs[0].resp_body);
        ok && json.origin.is_some()
    }

    fn assert_useragent(reqs: &[HttpBinReq]) -> bool {
        let ok = reqs[0].assert_hdrs();

        let json = Self::jsonify(&reqs[0].resp_body);
        ok && json.user_agent == Some(USER_AGENT.to_string())
    }

    fn assert_headers(reqs: &[HttpBinReq]) -> bool {
        let ok = reqs[0].assert_hdrs();

        let json = Self::jsonify(&reqs[0].resp_body);
        match json.headers {
            Some(args) => ok && args["Host"] == reqs[0].url.host_str().unwrap(),

            None => false,
        }
    }

    // Send a single request with a simple JSON body using the provided method
    fn test_request_body(url: &mut url::Url, method: &str) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let path = format!("{}/{}", url.path(), method.to_ascii_lowercase());
        url.set_path(&path);

        let req_body = serde_json::json!({"key1": "value1", "key2": "value2"});

        let mut req = HttpBinReq::new(
            &method.to_ascii_uppercase(),
            url,
            Some(req_body.to_string().into_bytes()),
            &expect_hdrs,
        );

        req.hdrs
            .push(Header::new("content-type", "application/json"));

        vec![req]
    }

    fn assert_request_body(reqs: &[HttpBinReq]) -> bool {
        let mut ok = reqs[0].assert_hdrs();

        let json = Self::jsonify(&reqs[0].resp_body);

        match json.json {
            Some(json) => {
                ok &= json["key1"] == "value1";
                ok && json["key2"] == "value2"
            },

            None => false,
        }
    }

    fn test_encode_utf8(url: &mut url::Url) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-type", "text/html; charset=utf-8"),
        ]);

        let path = format!("{}/{}", url.path(), "encoding/utf8");
        url.set_path(&path);

        vec![HttpBinReq::new("GET", url, None, &expect_hdrs)]
    }

    fn test_gzip(url: &mut url::Url) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-encoding", "gzip"),
        ]);

        let path = format!("{}/{}", url.path(), "gzip");
        url.set_path(&path);

        let mut req = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req.hdrs.push(Header::new("accept-encoding", "gzip"));

        vec![req]
    }

    fn test_deflate(url: &mut url::Url) -> Vec<HttpBinReq> {
        // Not all servers actually take up the deflate option,
        // so don't check content-type response header.
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let path = format!("{}/{}", url.path(), "deflate");
        url.set_path(&path);

        let mut req = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req.hdrs.push(Header::new("accept-encoding", "deflate"));

        vec![req]
    }

    /// Test a limited range of status codes
    fn test_status(url: &mut url::Url) -> Vec<HttpBinReq> {
        let mut reqs = Vec::new();

        for i in (200..600).step_by(100) {
            for j in 0..5 {
                let expect_hdrs =
                    Some(vec![Header::new(":status", &(i + j).to_string())]);

                let path = format!("{}/{}/{}", url.path(), "status", i + j);
                let mut url = url.clone();
                url.set_path(&path);

                reqs.push(HttpBinReq::new("GET", &url, None, &expect_hdrs));
            }
        }

        reqs
    }

    fn assert_status(reqs: &[HttpBinReq]) -> bool {
        let mut ok = true;

        for req in reqs {
            ok &= req.assert_hdrs()
        }

        ok
    }

    /// Tests that special query params are reflected back into the response
    /// body.
    fn test_response_headers(url: &mut url::Url) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let path = format!("{}/{}", url.path(), "response-headers");
        url.set_path(&path);
        url.set_query(Some(
            "content-type=text/plain;+charset=UTF-8&server=httpbin",
        ));

        vec![HttpBinReq::new("GET", url, None, &expect_hdrs)]
    }

    fn assert_response_headers(reqs: &[HttpBinReq]) -> bool {
        let mut ok = reqs[0].assert_hdrs();

        let json = Self::jsonify(&reqs[0].resp_body);
        match json.server {
            Some(server) => {
                ok &= server == "httpbin";
            },

            None => {
                return false;
            },
        }

        match json.content_type {
            Some(content_type) => {
                ok &= content_type[0] == "application/json";
                ok &= content_type[1] == "text/plain; charset=UTF-8";
            },

            None => {
                return false;
            },
        }

        ok
    }

    /// Tests several redirect cases
    fn test_redirect(url: &mut url::Url) -> Vec<HttpBinReq> {
        let original_url = url.clone();
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![
            Header::new(":status", "302"),
            Header::new("location", "https://example.com"),
        ]);

        let path =
            format!("{}/{}", String::from(original_url.path()), "redirect-to");
        url.set_path(&path);
        url.set_query(Some("url=https://example.com"));

        reqs.push(HttpBinReq::new("GET", url, None, &expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "307"),
            Header::new("location", "https://example.com"),
        ]);
        url.set_query(Some("url=https://example.com&status_code=307"));

        reqs.push(HttpBinReq::new("GET", url, None, &expect_hdrs));

        // Request 3
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);
        let path = format!(
            "{}/{}",
            String::from(original_url.path()),
            "relative-redirect/3"
        );
        let mut req3_url = original_url.clone();
        req3_url.set_path(&path);
        reqs.push(HttpBinReq::new("GET", &req3_url, None, &expect_hdrs));

        reqs
    }

    /// Tests cookie redirect cases since the client ignores cookies
    fn test_cookies(url: &mut url::Url) -> Vec<HttpBinReq> {
        let original_url = url.clone();
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);

        let path =
            format!("{}/{}", String::from(original_url.path()), "cookies/set");
        url.set_path(&path);
        url.set_query(Some("k1=v1"));

        reqs.push(HttpBinReq::new("GET", url, None, &expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);
        let path =
            format!("{}/{}", String::from(original_url.path()), "cookies/delete");
        let mut req2_url = original_url.clone();
        req2_url.set_path(&path);
        req2_url.set_query(Some("k1=v1"));

        reqs.push(HttpBinReq::new("GET", &req2_url, None, &expect_hdrs));

        reqs
    }

    fn test_basic_auth(url: &mut url::Url) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![
            Header::new(":status", "401"),
            Header::new("www-authenticate", "Basic realm=\"Fake Realm\""),
        ]);

        let path = format!("{}/{}", url.path(), "basic-auth/user/passwd");
        url.set_path(&path);

        vec![HttpBinReq::new("GET", url, None, &expect_hdrs)]
    }

    /// Test a limited range of content sizes streamed from origin
    fn test_stream(url: &mut url::Url) -> Vec<HttpBinReq> {
        let mut reqs = Vec::new();

        let sizes = [1, 50, 100];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let path =
                format!("{}/{}/{}", url.path(), "stream", size.to_string());
            let mut url = url.clone();
            url.set_path(&path);

            reqs.push(HttpBinReq::new("GET", &url, None, &expect_hdrs));
        }

        reqs
    }

    fn assert_stream(reqs: &[HttpBinReq]) -> bool {
        let mut ok = true;

        ok &= reqs[0].assert_hdrs();
        ok &= reqs[1].assert_hdrs();
        ok &= reqs[2].assert_hdrs();

        if std::str::from_utf8(&reqs[0].resp_body)
            .unwrap()
            .matches('\n')
            .count() !=
            1
        {
            return false;
        }

        if std::str::from_utf8(&reqs[1].resp_body)
            .unwrap()
            .matches('\n')
            .count() !=
            50
        {
            return false;
        }

        if std::str::from_utf8(&reqs[2].resp_body)
            .unwrap()
            .matches('\n')
            .count() !=
            100
        {
            return false;
        }

        ok
    }

    fn test_delay(url: &mut url::Url) -> Vec<HttpBinReq> {
        let mut reqs = Vec::new();

        let delays = [1, 10, 30];

        for delay in &delays {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let path = format!("{}/{}/{}", url.path(), "delay", delay);
            let mut url = url.clone();
            url.set_path(&path);

            reqs.push(HttpBinReq::new("GET", &url, None, &expect_hdrs));
        }

        reqs
    }

    fn test_drip(url: &mut url::Url) -> Vec<HttpBinReq> {
        let mut reqs = Vec::new();

        let durations = [1, 10, 30];

        for duration in &durations {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let path = format!("{}/{}", url.path(), "drip");
            let mut url = url.clone();
            url.set_path(&path);
            url.set_query(Some(&format!(
                "duration={}&numbytes=5&code=200",
                duration
            )));

            reqs.push(HttpBinReq::new("GET", &url, None, &expect_hdrs));
        }

        reqs
    }

    fn test_range(url: &mut url::Url) -> Vec<HttpBinReq> {
        let original_url = url.clone();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let path = format!("{}/{}", original_url.path(), "range/102400");
        url.set_path(&path);

        let req_1 = HttpBinReq::new("GET", url, None, &expect_hdrs);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "206"),
            Header::new("content-range", "bytes 0-49/102400"),
        ]);

        let mut req_2 = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req_2.hdrs.push(Header::new("range", "bytes=0-49"));

        // Request 3
        let expect_hdrs = Some(vec![
            Header::new(":status", "206"),
            Header::new("content-range", "bytes 100-10000/102400"),
        ]);
        let mut req_3 = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req_3.hdrs.push(Header::new("range", "bytes=100-10000"));

        vec![req_1, req_2, req_3]
    }

    fn test_cache(url: &mut url::Url) -> Vec<HttpBinReq> {
        let original_url = url.clone();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let path = format!("{}/{}", String::from(original_url.path()), "cache");
        url.set_path(&path);

        let req_1 = HttpBinReq::new("GET", url, None, &expect_hdrs);

        // Request 2
        let expect_hdrs = Some(vec![Header::new(":status", "304")]);
        let mut req_2 = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req_2.hdrs.push(Header::new(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        ));

        // request 3
        let expect_hdrs = Some(vec![Header::new(":status", "304")]);
        let mut req_3 = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req_3.hdrs.push(Header::new("if-none-match", "*"));

        vec![req_1, req_2, req_3]
    }

    fn test_bytes(url: &mut url::Url) -> Vec<HttpBinReq> {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-length", &size.to_string()),
            ]);

            let path = format!("{}/{}/{}", url.path(), "bytes", size.to_string());
            let mut url = url.clone();
            url.set_path(&path);

            reqs.push(HttpBinReq::new("GET", &url, None, &expect_hdrs));
        }

        reqs
    }

    fn test_stream_bytes(url: &mut url::Url) -> Vec<HttpBinReq> {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let path =
                format!("{}/{}/{}", url.path(), "stream-bytes", size.to_string());
            let mut url = url.clone();
            url.set_path(&path);

            reqs.push(HttpBinReq::new("GET", &url, None, &expect_hdrs));
        }

        reqs
    }

    fn test_image(url: &mut url::Url) -> Vec<HttpBinReq> {
        let original_url = url.clone();
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "406")]);

        let path = format!("{}/{}", String::from(original_url.path()), "image");
        url.set_path(&path);

        let mut req_1 = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req_1.hdrs.push(Header::new("accept", "*/*"));
        reqs.push(req_1);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-type", "image/png"),
        ]);
        let mut req_2 = HttpBinReq::new("GET", url, None, &expect_hdrs);
        req_2.hdrs.push(Header::new("accept", "image/*"));
        reqs.push(req_2);

        // Multiple requests based on accept
        let formats = ["image/webp", "image/svg+xml", "image/jpeg", "image/png"];
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-type", &format),
            ]);

            let path =
                format!("{}/{}", String::from(original_url.path()), "image");
            url.set_path(&path);
            let mut req = HttpBinReq::new("GET", url, None, &expect_hdrs);
            req.hdrs.push(Header::new("accept", &format));
            reqs.push(req);
        }

        // Multiple requests based on path
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-type", &format),
            ]);

            let path = if format == &"image/svg+xml" {
                format!("{}/{}", original_url.path(), "image/svg")
            } else {
                format!("{}/{}", original_url.path(), format)
            };

            url.set_path(&path);
            let mut req = HttpBinReq::new("GET", url, None, &expect_hdrs);
            req.hdrs.push(Header::new("accept", &format));
            reqs.push(req);
        }

        reqs
    }

    // Send a single request with a simple JSON body using the provided method
    fn test_form(url: &mut url::Url) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let path = format!("{}/{}", url.path(), "post");
        url.set_path(&path);

        let req_body = "custname=dave&custtel=1234&custemail=dave@example.com&size=large&topping=bacon&delivery=&comments=pronto";

        let mut req = HttpBinReq::new(
            "POST",
            url,
            Some(req_body.to_string().into_bytes()),
            &expect_hdrs,
        );

        req.hdrs.push(Header::new(
            "content-type",
            "application/x-www-form-urlencoded",
        ));

        vec![req]
    }

    fn assert_form(reqs: &[HttpBinReq]) -> bool {
        let mut ok = reqs[0].assert_hdrs();

        let json = Self::jsonify(&reqs[0].resp_body);
        if let Some(form) = json.form {
            ok &= form["custname"] == "dave";
            ok &= form["custtel"] == "1234";
            ok &= form["custemail"] == "dave@example.com";
            ok &= form["size"] == "large";
            ok &= form["topping"] == "bacon";
            ok &= form["delivery"] == "";
            ok &= form["comments"] == "pronto";
        }

        ok
    }

    // Make a single request and check the provided response code
    fn test_response_code(
        url: &mut url::Url, testpoint: &str, status: usize,
    ) -> Vec<HttpBinReq> {
        let expect_hdrs = Some(vec![Header::new(":status", &status.to_string())]);

        let path = format!("{}/{}", url.path(), &testpoint);
        url.set_path(&path);

        vec![HttpBinReq::new("GET", &url, None, &expect_hdrs)]
    }

    fn assert_headers_only(reqs: &[HttpBinReq]) -> bool {
        let mut ok = true;

        for req in reqs {
            ok &= req.assert_hdrs();
        }

        ok
    }
}
