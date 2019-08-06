#!/usr/bin/env python

import pytest
import subprocess

HTTPBIN_HOST = 'cloudflare-quic.com'
HTTPBIN_PATH = '/b'
HTTPBIN_BASE_URL = 'https://' + HTTPBIN_HOST + HTTPBIN_PATH
HTTPBIN_CLIENT = "./target/release/http3bin-client"

def do_test(test, concurrent=True):
    p = subprocess.Popen([HTTPBIN_CLIENT, "--no-verify", "--test", test, HTTPBIN_BASE_URL]) if concurrent else subprocess.Popen([http3bin_client, "--no-verify", "--test", test, "--no-concurrent", HTTPBIN_BASE_URL])
    output, _ = p.communicate()

    return p.returncode

def test_get(): 
    assert do_test("get") == 0

def test_useragent(): 
    assert do_test("useragent") == 0

def test_headers(): 
    assert do_test("headers") == 0

def test_post(): 
    assert do_test("post") == 0

def test_patch(): 
    assert do_test("patch") == 0

def test_put(): 
    assert do_test("put") == 0

def test_delete(): 
    assert do_test("delete") == 0

def test_encode_utf8(): 
    assert do_test("encode-utf8") == 0

def test_gzip(): 
    assert do_test("gzip") == 0

def test_deflate(): 
    assert do_test("deflate") == 0

def test_status(): 
    assert do_test("status", False) == 0

def test_response_headers():
    assert do_test("response-headers") == 0

def test_redirect(): 
    assert do_test("redirect") == 0

def test_cookies(): 
    assert do_test("cookies") == 0

def test_basic_auth(): 
    assert do_test("basic-auth") == 0

def test_stream(): 
    assert do_test("stream") == 0

def test_delay(): 
    assert do_test("delay", False) == 0

def test_drip(): 
    assert do_test("drip", False) == 0

def test_range(): 
    assert do_test("range") == 0

def test_html(): 
    assert do_test("html") == 0

def test_robots(): 
    assert do_test("robots") == 0

def test_cache(): 
    assert do_test("cache") == 0

def test_bytes(): 
    assert do_test("bytes") == 0

def test_stream_bytes(): 
    assert do_test("stream-bytes") == 0

def test_links(): 
    assert do_test("links") == 0

def test_image(): 
    assert do_test("image") == 0

def test_form(): 
    assert do_test("form") == 0

def test_xml(): 
    assert do_test("xml") == 0