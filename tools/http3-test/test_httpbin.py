#!/usr/bin/env python

import pytest
import subprocess

HTTPBIN_ENDPOINT = 'https://cloudflare-quic.com/b'

def cargo_test(test):
    p = subprocess.Popen(["cargo", "test", test])
    output, _ = p.communicate()

    return p.returncode

def test_get():
    assert cargo_test("get") == 0

def test_useragent():
    assert cargo_test("useragent") == 0

def test_headers():
    assert cargo_test("headers") == 0

def test_post():
    assert cargo_test("post") == 0

def test_patch():
    assert cargo_test("patch") == 0

def test_put():
    assert cargo_test("put") == 0

def test_delete():
    assert cargo_test("delete") == 0

def test_encode_utf8():
    assert cargo_test("encode-utf8") == 0

def test_gzip():
    assert cargo_test("gzip") == 0

def test_deflate():
    assert cargo_test("deflate") == 0

def test_status():
    assert cargo_test("status") == 0

def test_response_headers():
    assert cargo_test("response-headers") == 0

def test_redirect():
    assert cargo_test("redirect") == 0

def test_cookies():
    assert cargo_test("cookies") == 0

def test_basic_auth():
    assert cargo_test("basic-auth") == 0

def test_stream():
    assert cargo_test("stream") == 0

def test_delay():
    assert cargo_test("delay") == 0

def test_drip():
    assert cargo_test("drip") == 0

def test_range():
    assert cargo_test("range") == 0

def test_html():
    assert cargo_test("html") == 0

def test_robots():
    assert cargo_test("robots") == 0

def test_cache():
    assert cargo_test("cache") == 0

def test_bytes():
    assert cargo_test("bytes") == 0

def test_stream_bytes():
    assert cargo_test("stream-bytes") == 0

def test_links():
    assert cargo_test("links") == 0

def test_image():
    assert cargo_test("image") == 0

def test_form():
    assert cargo_test("form") == 0

def test_xml():
    assert cargo_test("xml") == 0