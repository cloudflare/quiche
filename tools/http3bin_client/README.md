Building
--------

```bash
 $ cargo build
```

Running
--------
Several option here


```bash
 $ RUST_LOG=info ./target/debug/http3bin-client --test get https://cloudflare-quic.com/b
```

```bash
 $ ./test_http3bin.sh https://cloudflare-quic.com/b 2>&1 | grep -i "Completed test"
```

```bash
 $ pytest -q test_httpbin.py
```