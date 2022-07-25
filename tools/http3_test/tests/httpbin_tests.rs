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

mod httpbin_tests {
    use std::collections::HashMap;
    use std::net::ToSocketAddrs;

    use http3_test::Http3TestError::*;
    use http3_test::*;
    use quiche::h3::*;

    use std::sync::Once;

    static INIT: Once = Once::new();

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

    fn host() -> std::net::SocketAddr {
        let url = match std::env::var_os("HTTPBIN_HOST") {
            Some(val) => {
                let host = val.into_string().unwrap();
                let url = format!("{}{}", "https://", host);

                url::Url::parse(&url).unwrap()
            },

            None => endpoint(None),
        };

        url.to_socket_addrs().unwrap().next().unwrap()
    }

    fn verify_peer() -> bool {
        match std::env::var_os("VERIFY_PEER") {
            Some(val) => match val.to_str().unwrap() {
                "false" => {
                    return false;
                },

                _ => {
                    return true;
                },
            },

            None => {
                return true;
            },
        };
    }

    fn idle_timeout() -> u64 {
        match std::env::var_os("IDLE_TIMEOUT") {
            Some(val) =>
                u64::from_str_radix(&val.into_string().unwrap(), 10).unwrap(),

            None => 60000,
        }
    }

    fn extra_headers() -> Option<serde_json::Map<String, serde_json::Value>> {
        if let Some(val) = std::env::var_os("EXTRA_HEADERS") {
            let json_string = val.into_string().unwrap();
            let parsed: serde_json::Value =
                serde_json::from_str(&json_string).unwrap();
            return Some(parsed.as_object().unwrap().clone());
        }

        return None;
    }

    fn expect_req_headers() -> Option<serde_json::Map<String, serde_json::Value>>
    {
        if let Some(val) = std::env::var_os("EXPECT_REQ_HEADERS") {
            let json_string = val.into_string().unwrap();
            let parsed: serde_json::Value =
                serde_json::from_str(&json_string).unwrap();
            return Some(parsed.as_object().unwrap().clone());
        }

        return None;
    }

    fn max_data() -> u64 {
        match std::env::var_os("MAX_DATA") {
            Some(val) =>
                u64::from_str_radix(&val.into_string().unwrap(), 10).unwrap(),

            None => 1_000_000,
        }
    }

    fn early_data() -> bool {
        match std::env::var_os("EARLY_DATA") {
            Some(val) => match val.to_str().unwrap() {
                "true" => {
                    return true;
                },

                _ => {
                    return false;
                },
            },

            None => {
                return false;
            },
        };
    }

    fn session_file() -> Option<String> {
        if let Some(val) = std::env::var_os("SESSION_FILE") {
            Some(val.into_string().unwrap())
        } else {
            None
        }
    }

    // A rudimentary structure to hold httpbin response data
    #[derive(Debug, serde::Deserialize)]
    struct HttpBinResponseBody {
        args: Option<HashMap<String, String>>,
        #[allow(dead_code)]
        data: Option<String>,
        #[allow(dead_code)]
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
        #[allow(dead_code)]
        url: Option<String>,
    }

    fn jsonify(data: &[u8]) -> HttpBinResponseBody {
        serde_json::from_slice(&data).unwrap()
    }

    fn do_test(
        reqs: Vec<Http3Req>, assert: Http3Assert, concurrent: bool,
    ) -> std::result::Result<(), Http3TestError> {
        INIT.call_once(|| {
            env_logger::builder()
                .default_format_timestamp_nanos(true)
                .init()
        });

        let mut test = Http3Test::new(endpoint(None), reqs, assert, concurrent);
        runner::run(
            &mut test,
            host(),
            verify_peer(),
            idle_timeout(),
            max_data(),
            early_data(),
            session_file(),
        )
    }

    fn do_test_with_stream_data(
        reqs: Vec<Http3Req>, stream_data: Vec<ArbitraryStreamData>,
        assert: Http3Assert, concurrent: bool,
    ) -> std::result::Result<(), Http3TestError> {
        INIT.call_once(|| {
            env_logger::builder()
                .default_format_timestamp_nanos(true)
                .init()
        });

        let mut test = Http3Test::with_stream_data(
            endpoint(None),
            reqs,
            stream_data,
            assert,
            concurrent,
        );
        runner::run(
            &mut test,
            host(),
            verify_peer(),
            idle_timeout(),
            max_data(),
            early_data(),
            session_file(),
        )
    }

    // Build a single request and expected response with status code
    fn request_check_status(testpoint: &str, status: usize) -> Vec<Http3Req> {
        let expect_hdrs =
            Some(vec![Header::new(b":status", status.to_string().as_bytes())]);

        let url = endpoint(Some(testpoint));

        vec![Http3Req::new("GET", &url, None, expect_hdrs)]
    }

    // Build a single request with a simple JSON body using the provided method
    fn request_with_body(method: &str) -> Vec<Http3Req> {
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let url = endpoint(Some(&method.to_ascii_lowercase()));

        let req_body = serde_json::json!({"key1": "value1", "key2": "value2"});

        let mut req = Http3Req::new(
            &method.to_ascii_uppercase(),
            &url,
            Some(req_body.to_string().into_bytes()),
            expect_hdrs,
        );

        req.hdrs
            .push(Header::new(b"content-type", b"application/json"));

        vec![req]
    }

    fn assert_request_body(reqs: &[Http3Req]) {
        assert_headers!(reqs[0]);

        let json = jsonify(&reqs[0].resp_body).json.unwrap();

        assert_eq!(json["key1"], "value1");
        assert_eq!(json["key2"], "value2");
    }

    fn assert_headers_only(reqs: &[Http3Req]) {
        for req in reqs {
            assert_headers!(req);
        }
    }

    #[test]
    fn get() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let mut url = endpoint(Some("get"));

        // Request 1
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        // Request 2
        url.set_query(Some("key1=value1&key2=value2"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
            assert_headers!(reqs[1]);

            let json = jsonify(&reqs[1].resp_body);
            if let Some(args) = json.args {
                assert_eq!(args["key1"], "value1");
                assert_eq!(args["key2"], "value2")
            }
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn req_no_method() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            expect_resp_hdrs: expect_hdrs,
            body: None,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn req_empty_method() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b""),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_invalid_method() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"$GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_no_scheme() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn req_empty_scheme() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b""),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_invalid_scheme() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"$fail"),
            Header::new(b":path", path.as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_no_authority() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn req_empty_authority() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":authority", b""),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_no_path() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn req_empty_path() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":path", b""),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_invalid_pseudoheader_name() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":$method", b"GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_duplicate_pseudoheader_bad_order() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"400")]);

        let url = endpoint(Some("get"));
        let path = String::from(url.path());

        let hdrs = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", url.scheme().as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            Header::new(b"user-agent", USER_AGENT),
            Header::new(b":method", b"GET"),
        ];

        let req = Http3Req {
            url: url.clone(),
            hdrs,
            body: None,
            expect_resp_hdrs: expect_hdrs,
            resp_hdrs: Vec::new(),
            resp_body: Vec::new(),
            reset_stream_code: None,
        };

        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn req_too_large_headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        // This test explicitly tries to exceed the server's
        // MAX_FIELD_SECTION_SIZE setting. Therefore, it is expected that
        // the invoker supplies an additional header to this test
        // via the EXTRA_HEADERS environment variable.
        if let Some(headers) = &extra_headers() {
            for (name, val) in headers {
                println!("{}: {}", name, val);
                reqs[0].hdrs.push(Header::new(
                    name.as_bytes(),
                    val.as_str().unwrap().as_bytes(),
                ));
            }
        };

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        assert_eq!(Err(HttpFail), do_test(reqs, assert, true));
    }

    #[test]
    fn frames_duplicate_settings() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let mut stream_data = Vec::new();

        // A buffer holding a valid SETTINGS frame encoded in wire format.
        let d = vec![
            4, 16, 213, 164, 106, 24, 4, 152, 223, 76, 209, 101, 114, 237, 239,
            178, 71, 46,
        ];

        let data_frame = ArbitraryStreamData {
            stream_id: 0,
            data: d,
            fin: false,
        };

        stream_data.push(data_frame);

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn frames_max_push_on_request() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let mut stream_data = Vec::new();

        // A buffer containing a valid MAX_PUSH_ID frame encoded in wire format.
        let d = vec![13, 1, 4];

        let data_frame = ArbitraryStreamData {
            stream_id: 0,
            data: d,
            fin: false,
        };

        stream_data.push(data_frame);

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn frames_data_on_control() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let mut stream_data = Vec::new();

        // A buffer containing a 0-length DATA frame encoded in wire format.
        let d = vec![0; 2];

        let data_frame = ArbitraryStreamData {
            stream_id: 0,
            data: d,
            fin: false,
        };

        stream_data.push(data_frame);

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn frames_data_before_headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let mut stream_data = Vec::new();

        // A buffer containing a 0-length DATA frame encoded in wire format.
        let d = vec![0; 2];

        let data_frame = ArbitraryStreamData {
            stream_id: 0,
            data: d,
            fin: false,
        };

        stream_data.push(data_frame);

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn frames_too_small_headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let mut stream_data = Vec::new();

        // A buffer of containing an invalid HEADERS frame encoded in wire format.
        let d = vec![1, 3, 1, 1, 1];

        let data_frame = ArbitraryStreamData {
            stream_id: 4,
            data: d,
            fin: false,
        };

        stream_data.push(data_frame);

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn stream_close_control() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let stream_data = vec![ArbitraryStreamData {
            stream_id: 2,
            data: b"".to_vec(),
            fin: true,
        }];

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn stream_close_qpack_enc() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let stream_data = vec![ArbitraryStreamData {
            stream_id: 6,
            data: b"".to_vec(),
            fin: true,
        }];

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn stream_close_qpack_dec() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let url = endpoint(Some("get"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
        };

        let stream_data = vec![ArbitraryStreamData {
            stream_id: 10,
            data: b"".to_vec(),
            fin: true,
        }];

        assert_eq!(
            Err(HttpFail),
            do_test_with_stream_data(reqs, stream_data, assert, true)
        );
    }

    #[test]
    fn ip() {
        let reqs = request_check_status("ip", 200);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            let json = jsonify(&reqs[0].resp_body);
            assert!(json.origin.is_some())
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn useragent() {
        let reqs = request_check_status("user-agent", 200);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            let json = jsonify(&reqs[0].resp_body);
            assert_eq!(
                json.user_agent,
                String::from_utf8(USER_AGENT.to_vec()).ok()
            );
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let mut url = endpoint(Some("headers"));
        url.set_query(Some("show_env=1")); // reveal X-Forwarded-* headers
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs.clone()));

        if let Some(headers) = &extra_headers() {
            for (name, val) in headers {
                reqs[0].hdrs.push(Header::new(
                    name.as_bytes(),
                    val.as_str().unwrap().as_bytes(),
                ));
            }
        };

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            let json = jsonify(&reqs[0].resp_body);
            assert_ne!(json.headers, None);
            if let Some(headers) = json.headers {
                if let Some(expected_headers) = &expect_req_headers() {
                    for (name, val) in expected_headers {
                        if let Some(expected_value) = val.as_str() {
                            assert_eq!(
                                headers.get(name),
                                Some(&String::from(expected_value)),
                                "Header '{}' doesn't match",
                                name
                            );
                        } else {
                            assert_eq!(
                                headers.get(name),
                                None,
                                "Header '{}' exists",
                                name
                            );
                        }
                    }
                }
            }
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn post() {
        let reqs = request_with_body("post");
        assert_eq!(Ok(()), do_test(reqs, assert_request_body, true));
    }

    #[test]
    fn put() {
        let reqs = request_with_body("put");
        assert_eq!(Ok(()), do_test(reqs, assert_request_body, true));
    }

    #[test]
    fn patch() {
        let reqs = request_with_body("patch");
        assert_eq!(Ok(()), do_test(reqs, assert_request_body, true));
    }

    #[test]
    fn delete() {
        let reqs = request_with_body("delete");
        assert_eq!(Ok(()), do_test(reqs, assert_request_body, true));
    }

    #[test]
    fn encode_utf8() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![
            Header::new(b":status", b"200"),
            Header::new(b"content-type", b"text/html; charset=utf-8"),
        ]);

        let url = endpoint(Some("encoding/utf8"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn gzip() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![
            Header::new(b":status", b"200"),
            Header::new(b"content-encoding", b"gzip"),
        ]);

        let url = endpoint(Some("gzip"));

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"accept-encoding", b"gzip"));

        reqs.push(req);

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn deflate() {
        let mut reqs = Vec::new();

        // Not all servers actually take up the deflate option,
        // so don't check content-type response header.
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let url = endpoint(Some("deflate"));

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"accept-encoding", b"deflate"));
        reqs.push(req);

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn status() {
        let mut reqs = Vec::new();

        for i in (200..600).step_by(100) {
            for j in 0..5 {
                let expect_hdrs = Some(vec![Header::new(
                    b":status",
                    (i + j).to_string().as_bytes(),
                )]);

                let testpoint = format!("{}/{}", "status", i + j);
                let url = endpoint(Some(&testpoint));

                reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
            }
        }

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, false));
    }

    #[test]
    fn response_headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let mut url = endpoint(Some("response-headers"));
        url.set_query(Some(
            "content-type=text/plain;+charset=UTF-8&server=httpbin",
        ));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
            let json = jsonify(&reqs[0].resp_body);

            let server = json.server.unwrap();
            assert_eq!(server, "httpbin");

            let content_type = json.content_type.unwrap();
            assert_eq!(content_type[0], "application/json");
            assert_eq!(content_type[1], "text/plain; charset=UTF-8");
        };

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn redirect() {
        let mut reqs = Vec::new();
        let mut url = endpoint(Some("redirect-to"));

        // Request 1
        let expect_hdrs = Some(vec![
            Header::new(b":status", b"302"),
            Header::new(b"location", b"https://example.com"),
        ]);

        url.set_query(Some("url=https://example.com"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(b":status", b"307"),
            Header::new(b"location", b"https://example.com"),
        ]);
        url.set_query(Some("url=https://example.com&status_code=307"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        // Request 3
        let expect_hdrs = Some(vec![Header::new(b":status", b"302")]);
        let url = endpoint(Some("relative-redirect/3"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn cookies() {
        // Tests cookie redirect cases since the client ignores cookies
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(b":status", b"302")]);
        let mut url = endpoint(Some("cookies/set"));
        url.set_query(Some("k1=v1"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![Header::new(b":status", b"302")]);

        let mut url = endpoint(Some("cookies/set"));
        url.set_query(Some("k1=v1"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn basic_auth() {
        let mut reqs = Vec::new();
        let url = endpoint(Some("basic-auth/user/passwd"));

        let expect_hdrs = Some(vec![
            Header::new(b":status", b"401"),
            Header::new(b"www-authenticate", b"Basic realm=\"Fake Realm\""),
        ]);

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn stream() {
        let mut reqs = Vec::new();

        let sizes = [1, 50, 100];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

            let testpoint = format!("{}/{}", "stream", size.to_string());

            let url = endpoint(Some(&testpoint));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);
            assert_headers!(reqs[1]);
            assert_headers!(reqs[2]);

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

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn delay() {
        let mut reqs = Vec::new();

        let delays = [1, 10, 30];

        for delay in &delays {
            let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

            let testpoint = format!("{}/{}", "delay", delay);
            let url = endpoint(Some(&testpoint));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, false));
    }

    #[test]
    fn drip() {
        let mut reqs = Vec::new();

        let durations = [1, 10, 30];

        for duration in &durations {
            let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

            let mut url = endpoint(Some("drip"));
            url.set_query(Some(&format!(
                "duration={}&numbytes=5&code=200",
                duration
            )));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, false));
    }

    #[test]
    #[cfg(feature = "test_resets")]
    fn drip_delay_reset() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);
        let mut url = endpoint(Some("drip"));
        url.set_query(Some("duration=30&numbytes=2&delay=1"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            assert_eq!(reqs[0].reset_stream_code, Some(256));
        };

        assert_eq!(Ok(()), do_test(reqs, assert, false));
    }

    #[test]
    fn range() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let url = endpoint(Some("range/102400"));

        let req = Http3Req::new("GET", &url, None, expect_hdrs);
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(b":status", b"206"),
            Header::new(b"content-range", b"bytes 0-49/102400"),
        ]);

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"range", b"bytes=0-49"));
        reqs.push(req);

        // Request 3
        let expect_hdrs = Some(vec![
            Header::new(b":status", b"206"),
            Header::new(b"content-range", b"bytes 100-10000/102400"),
        ]);
        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"range", b"bytes=100-10000"));
        reqs.push(req);

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn cache() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let url = endpoint(Some("cache"));

        let req = Http3Req::new("GET", &url, None, expect_hdrs);
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![Header::new(b":status", b"304")]);

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(
            b"if-modified-since",
            b"Wed, 21 Oct 2015 07:28:00 GMT",
        ));
        reqs.push(req);

        // Request 3
        let expect_hdrs = Some(vec![Header::new(b":status", b"304")]);
        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"if-none-match", b"*"));
        reqs.push(req);

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn bytes() {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![
                Header::new(b":status", b"200"),
                Header::new(b"content-length", size.to_string().as_bytes()),
            ]);

            let testpoint = format!("{}/{}", "bytes", size.to_string());
            let url = endpoint(Some(&testpoint));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn stream_bytes() {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

            let testpoint = format!("{}/{}", "stream-bytes", size.to_string());
            let url = endpoint(Some(&testpoint));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn image() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(b":status", b"406")]);

        let url = endpoint(Some("image"));

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"accept", b"*/*"));
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(b":status", b"200"),
            Header::new(b"content-type", b"image/png"),
        ]);
        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(b"accept", b"image/*"));
        reqs.push(req);

        // Multiple requests based on accept
        let formats = ["image/webp", "image/svg+xml", "image/jpeg", "image/png"];
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(b":status", b"200"),
                Header::new(b"content-type", format.as_bytes()),
            ]);

            let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
            req.hdrs.push(Header::new(b"accept", format.as_bytes()));
            reqs.push(req);
        }

        // Multiple requests based on path
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(b":status", b"200"),
                Header::new(b"content-type", format.as_bytes()),
            ]);

            let testpoint = if format == &"image/svg+xml" {
                "image/svg"
            } else {
                format
            };

            let url = endpoint(Some(&testpoint));
            let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
            req.hdrs.push(Header::new(b"accept", format.as_bytes()));
            reqs.push(req);
        }

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn form() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let url = endpoint(Some("post"));

        let req_body = "custname=dave&custtel=1234&custemail=dave@example.com&size=large&topping=bacon&delivery=&comments=pronto";

        let mut req = Http3Req::new(
            "POST",
            &url,
            Some(req_body.to_string().into_bytes()),
            expect_hdrs,
        );

        req.hdrs.push(Header::new(
            b"content-type",
            b"application/x-www-form-urlencoded",
        ));
        reqs.push(req);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

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

        assert_eq!(Ok(()), do_test(reqs, assert, true));
    }

    #[test]
    fn html() {
        let reqs = request_check_status("html", 200);
        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn xml() {
        let reqs = request_check_status("xml", 200);
        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn robots() {
        let reqs = request_check_status("robots.txt", 200);
        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn links() {
        let reqs = request_check_status("links/10", 302);
        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }

    #[test]
    fn zero_length_body() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![Header::new(b":status", b"200")]);

        let url = endpoint(Some("stream/0"));

        let req = Http3Req::new("GET", &url, None, expect_hdrs);
        reqs.push(req.clone());
        reqs.push(req);

        assert_eq!(Ok(()), do_test(reqs, assert_headers_only, true));
    }
}
