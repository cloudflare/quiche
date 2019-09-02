This crate provides an API to build httpbin test requests and expected
outcomes. These can be used with the quiche HTTP/3 module to
communicate with an httpbin test server.

Building
--------

```bash
 $ cargo build
```

Running
--------
We use cargo test to execute different httpbin tests. By default this points to https://cloudflare-quic.com/b

```bash
 $ cargo test
```

To test a different server, use the HTTPBIN_ENDPOINT environment variable

```bash
 $ HTTPBIN_ENDPOINT=https://<some_other_endpoint> cargo test
```
