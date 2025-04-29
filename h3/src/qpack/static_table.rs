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

/// This table maps the statically encoded QPACK entries to their
/// index. The mapping is from name length to a list of names of this
/// length, with the list of possible values for that name and the proper
/// encoding for this name: value pair.
type HeaderName = &'static [u8];
type HeaderValue = &'static [u8];
type HeaderValueEncPairs = &'static [(HeaderValue, u64)];
pub const STATIC_ENCODE_TABLE: &[&[(HeaderName, HeaderValueEncPairs)]] = &[
    // Headers of len 0
    &[],
    // Headers of len 1
    &[],
    // Headers of len 2
    &[],
    // Headers of len 3
    &[(b"age", &[(b"0", 2)])],
    // Headers of len 4
    &[
        (b"etag", &[(b"", 7)]),
        (b"date", &[(b"", 6)]),
        (b"link", &[(b"", 11)]),
        (b"vary", &[(b"accept-encoding", 59), (b"origin", 60)]),
    ],
    // Headers of len 5
    &[(b"range", &[(b"bytes=0-", 55)]), (b":path", &[(b"/", 1)])],
    // Headers of len 6
    &[
        (b"cookie", &[(b"", 5)]),
        (b"origin", &[(b"", 90)]),
        (b"server", &[(b"", 92)]),
        (b"accept", &[(b"*/*", 29), (b"application/dns-message", 30)]),
    ],
    // Headers of len 7
    &[
        (b"purpose", &[(b"prefetch", 91)]),
        (b"referer", &[(b"", 13)]),
        (b"alt-svc", &[(b"clear", 83)]),
        (b":status", &[
            (b"103", 24),
            (b"200", 25),
            (b"304", 26),
            (b"404", 27),
            (b"503", 28),
            (b"100", 63),
            (b"204", 64),
            (b"206", 65),
            (b"302", 66),
            (b"400", 67),
            (b"403", 68),
            (b"421", 69),
            (b"425", 70),
            (b"500", 71),
        ]),
        (b":scheme", &[(b"http", 22), (b"https", 23)]),
        (b":method", &[
            (b"CONNECT", 15),
            (b"DELETE", 16),
            (b"GET", 17),
            (b"HEAD", 18),
            (b"OPTIONS", 19),
            (b"POST", 20),
            (b"PUT", 21),
        ]),
    ],
    // Headers of len 8
    &[(b"location", &[(b"", 12)]), (b"if-range", &[(b"", 89)])],
    // Headers of len 9
    &[(b"expect-ct", &[(b"", 87)]), (b"forwarded", &[(b"", 88)])],
    // Headers of len 10
    &[
        (b"user-agent", &[(b"", 95)]),
        (b":authority", &[(b"", 0)]),
        (b"set-cookie", &[(b"", 14)]),
        (b"early-data", &[(b"1", 86)]),
    ],
    // Headers of len 11
    &[],
    // Headers of len 12
    &[(b"content-type", &[
        (b"application/dns-message", 44),
        (b"application/javascript", 45),
        (b"application/json", 46),
        (b"application/x-www-form-urlencoded", 47),
        (b"image/gif", 48),
        (b"image/jpeg", 49),
        (b"image/png", 50),
        (b"text/css", 51),
        (b"text/html; charset=utf-8", 52),
        (b"text/plain", 53),
        (b"text/plain;charset=utf-8", 54),
    ])],
    // Headers of len 13
    &[
        (b"last-modified", &[(b"", 10)]),
        (b"accept-ranges", &[(b"bytes", 32)]),
        (b"authorization", &[(b"", 84)]),
        (b"if-none-match", &[(b"", 9)]),
        (b"cache-control", &[
            (b"max-age=0", 36),
            (b"max-age=2592000", 37),
            (b"max-age=604800", 38),
            (b"no-cache", 39),
            (b"no-store", 40),
            (b"public, max-age=31536000", 41),
        ]),
    ],
    // Headers of len 14
    &[(b"content-length", &[(b"0", 4)])],
    // Headers of len 15
    &[
        (b"accept-encoding", &[(b"gzip, deflate, br", 31)]),
        (b"x-forwarded-for", &[(b"", 96)]),
        (b"accept-language", &[(b"", 72)]),
        (b"x-frame-options", &[(b"deny", 97), (b"sameorigin", 98)]),
    ],
    // Headers of len 16
    &[
        (b"content-encoding", &[(b"br", 42), (b"gzip", 43)]),
        (b"x-xss-protection", &[(b"1; mode=block", 62)]),
    ],
    // Headers of len 17
    &[(b"if-modified-since", &[(b"", 8)])],
    // Headers of len 18
    &[],
    // Headers of len 19
    &[
        (b"content-disposition", &[(b"", 3)]),
        (b"timing-allow-origin", &[(b"*", 93)]),
    ],
    // Headers of len 20
    &[],
    // Headers of len 21
    &[],
    // Headers of len 22
    &[(b"x-content-type-options", &[(b"nosniff", 61)])],
    // Headers of len 23
    &[(b"content-security-policy", &[(
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
        85,
    )])],
    // Headers of len 24
    &[],
    // Headers of len 25
    &[
        (b"upgrade-insecure-requests", &[(b"1", 94)]),
        (b"strict-transport-security", &[
            (b"max-age=31536000", 56),
            (b"max-age=31536000; includesubdomains", 57),
            (b"max-age=31536000; includesubdomains; preload", 58),
        ]),
    ],
    // Headers of len 26
    &[],
    // Headers of len 27
    &[(b"access-control-allow-origin", &[(b"*", 35)])],
    // Headers of len 28
    &[
        (b"access-control-allow-methods", &[
            (b"get", 76),
            (b"get, post, options", 77),
            (b"options", 78),
        ]),
        (b"access-control-allow-headers", &[
            (b"cache-control", 33),
            (b"content-type", 34),
            (b"*", 75),
        ]),
    ],
    // Headers of len 29
    &[
        (b"access-control-expose-headers", &[(b"content-length", 79)]),
        (b"access-control-request-method", &[
            (b"get", 81),
            (b"post", 82),
        ]),
    ],
    // Headers of len 30
    &[(b"access-control-request-headers", &[(b"content-type", 80)])],
    // Headers of len 31
    &[],
    // Headers of len 32
    &[(b"access-control-allow-credentials", &[
        (b"FALSE", 73),
        (b"TRUE", 74),
    ])],
];

pub const STATIC_DECODE_TABLE: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];
