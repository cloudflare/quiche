mod httpbin_tests {
    use std::collections::HashMap;
    use std::net::ToSocketAddrs;

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

    fn jsonify(data: &[u8]) -> HttpBinResponseBody {
        serde_json::from_slice(&data).unwrap()
    }

    fn do_test(reqs: Vec<Http3Req>, assert: Http3Assert, concurrent: bool) {
        INIT.call_once(|| {
            env_logger::builder()
                .default_format_timestamp_nanos(true)
                .init()
        });

        let mut test = Http3Test::new(endpoint(None), reqs, assert, concurrent);
        runner::run(&mut test, host(), verify_peer());
    }

    // Build a single request and expected response with status code
    fn request_check_status(testpoint: &str, status: usize) -> Vec<Http3Req> {
        let expect_hdrs = Some(vec![Header::new(":status", &status.to_string())]);

        let url = endpoint(Some(testpoint));

        vec![Http3Req::new("GET", &url, None, expect_hdrs)]
    }

    // Build a single request with a simple JSON body using the provided method
    fn request_with_body(method: &str) -> Vec<Http3Req> {
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some(&method.to_ascii_lowercase()));

        let req_body = serde_json::json!({"key1": "value1", "key2": "value2"});

        let mut req = Http3Req::new(
            &method.to_ascii_uppercase(),
            &url,
            Some(req_body.to_string().into_bytes()),
            expect_hdrs,
        );

        req.hdrs
            .push(Header::new("content-type", "application/json"));

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
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

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

        do_test(reqs, assert, true);
    }

    #[test]
    fn ip() {
        let reqs = request_check_status("ip", 200);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            let json = jsonify(&reqs[0].resp_body);
            assert!(json.origin.is_some())
        };

        do_test(reqs, assert, true);
    }

    #[test]
    fn useragent() {
        let reqs = request_check_status("user-agent", 200);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            let json = jsonify(&reqs[0].resp_body);
            assert_eq!(json.user_agent, Some(USER_AGENT.to_string()));
        };

        do_test(reqs, assert, true);
    }

    #[test]
    fn headers() {
        let reqs = request_check_status("headers", 200);

        let assert = |reqs: &[Http3Req]| {
            assert_headers!(reqs[0]);

            let json = jsonify(&reqs[0].resp_body);
            if let Some(args) = json.args {
                assert_eq!(args["Host"], reqs[0].url.host_str().unwrap());
            }
        };

        do_test(reqs, assert, true);
    }

    #[test]
    fn post() {
        let reqs = request_with_body("post");
        do_test(reqs, assert_request_body, true);
    }

    #[test]
    fn put() {
        let reqs = request_with_body("put");
        do_test(reqs, assert_request_body, true);
    }

    #[test]
    fn patch() {
        let reqs = request_with_body("patch");
        do_test(reqs, assert_request_body, true);
    }

    #[test]
    fn delete() {
        let reqs = request_with_body("delete");
        do_test(reqs, assert_request_body, true);
    }

    #[test]
    fn encode_utf8() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-type", "text/html; charset=utf-8"),
        ]);

        let url = endpoint(Some("encoding/utf8"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn gzip() {
        let mut reqs = Vec::new();

        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-encoding", "gzip"),
        ]);

        let url = endpoint(Some("gzip"));

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept-encoding", "gzip"));

        reqs.push(req);

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn deflate() {
        let mut reqs = Vec::new();

        // Not all servers actually take up the deflate option,
        // so don't check content-type response header.
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("deflate"));

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept-encoding", "deflate"));
        reqs.push(req);

        do_test(reqs, assert_headers_only, true);
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

                reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
            }
        }

        do_test(reqs, assert_headers_only, false);
    }

    #[test]
    fn response_headers() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

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

        do_test(reqs, assert, true);
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

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "307"),
            Header::new("location", "https://example.com"),
        ]);
        url.set_query(Some("url=https://example.com&status_code=307"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        // Request 3
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);
        let url = endpoint(Some("relative-redirect/3"));
        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn cookies() {
        // Tests cookie redirect cases since the client ignores cookies
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);
        let mut url = endpoint(Some("cookies/set"));
        url.set_query(Some("k1=v1"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        // Request 2
        let expect_hdrs = Some(vec![Header::new(":status", "302")]);

        let mut url = endpoint(Some("cookies/set"));
        url.set_query(Some("k1=v1"));

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn basic_auth() {
        let mut reqs = Vec::new();
        let url = endpoint(Some("basic-auth/user/passwd"));

        let expect_hdrs = Some(vec![
            Header::new(":status", "401"),
            Header::new("www-authenticate", "Basic realm=\"Fake Realm\""),
        ]);

        reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn stream() {
        let mut reqs = Vec::new();

        let sizes = [1, 50, 100];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

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

        do_test(reqs, assert, true);
    }

    #[test]
    fn delay() {
        let mut reqs = Vec::new();

        let delays = [1, 10, 30];

        for delay in &delays {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let testpoint = format!("{}/{}", "delay", delay);
            let url = endpoint(Some(&testpoint));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        do_test(reqs, assert_headers_only, false);
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

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        do_test(reqs, assert_headers_only, false);
    }

    #[test]
    fn range() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("range/102400"));

        let req = Http3Req::new("GET", &url, None, expect_hdrs);
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "206"),
            Header::new("content-range", "bytes 0-49/102400"),
        ]);

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("range", "bytes=0-49"));
        reqs.push(req);

        // Request 3
        let expect_hdrs = Some(vec![
            Header::new(":status", "206"),
            Header::new("content-range", "bytes 100-10000/102400"),
        ]);
        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("range", "bytes=100-10000"));
        reqs.push(req);

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn cache() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("cache"));

        let req = Http3Req::new("GET", &url, None, expect_hdrs);
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![Header::new(":status", "304")]);

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        ));
        reqs.push(req);

        // Request 3
        let expect_hdrs = Some(vec![Header::new(":status", "304")]);
        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("if-none-match", "*"));
        reqs.push(req);

        do_test(reqs, assert_headers_only, true);
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

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn stream_bytes() {
        let mut reqs = Vec::new();

        let sizes = [10, 100, 1000, 10000, 100_000];

        for size in &sizes {
            let expect_hdrs = Some(vec![Header::new(":status", "200")]);

            let testpoint = format!("{}/{}", "stream-bytes", size.to_string());
            let url = endpoint(Some(&testpoint));

            reqs.push(Http3Req::new("GET", &url, None, expect_hdrs));
        }

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn image() {
        let mut reqs = Vec::new();

        // Request 1
        let expect_hdrs = Some(vec![Header::new(":status", "406")]);

        let url = endpoint(Some("image"));

        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept", "*/*"));
        reqs.push(req);

        // Request 2
        let expect_hdrs = Some(vec![
            Header::new(":status", "200"),
            Header::new("content-type", "image/png"),
        ]);
        let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
        req.hdrs.push(Header::new("accept", "image/*"));
        reqs.push(req);

        // Multiple requests based on accept
        let formats = ["image/webp", "image/svg+xml", "image/jpeg", "image/png"];
        for format in &formats {
            let expect_hdrs = Some(vec![
                Header::new(":status", "200"),
                Header::new("content-type", &format),
            ]);

            let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
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
            let mut req = Http3Req::new("GET", &url, None, expect_hdrs);
            req.hdrs.push(Header::new("accept", &format));
            reqs.push(req);
        }

        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn form() {
        let mut reqs = Vec::new();
        let expect_hdrs = Some(vec![Header::new(":status", "200")]);

        let url = endpoint(Some("post"));

        let req_body = "custname=dave&custtel=1234&custemail=dave@example.com&size=large&topping=bacon&delivery=&comments=pronto";

        let mut req = Http3Req::new(
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

        do_test(reqs, assert, true);
    }

    #[test]
    fn html() {
        let reqs = request_check_status("html", 200);
        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn xml() {
        let reqs = request_check_status("xml", 200);
        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn robots() {
        let reqs = request_check_status("robots.txt", 200);
        do_test(reqs, assert_headers_only, true);
    }

    #[test]
    fn links() {
        let reqs = request_check_status("links/10", 302);
        do_test(reqs, assert_headers_only, true);
    }
}
