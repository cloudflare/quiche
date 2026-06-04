// Copyright (C) 2026, Cloudflare, Inc.
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

#![cfg(feature = "huffman_hpack")]

use octets::huffman_encoding_len;
use octets::BufferTooShortError;
use octets::Octets;
use octets::OctetsMut;
use octets::OctetsWriter;
use octets::Result;

#[test]
fn invalid_huffman() {
    // Extra non-zero padding byte at the end.
    let mut b =
        Octets::with_slice(b"\x00\x85\xf2\xb2\x4a\x84\xff\x84\x49\x50\x9f\xff");
    assert!(b.get_huffman_decoded().is_err());

    // Zero padded.
    let mut b =
        Octets::with_slice(b"\x00\x85\xf2\xb2\x4a\x84\xff\x83\x49\x50\x90");
    assert!(b.get_huffman_decoded().is_err());

    // Non-final EOS symbol.
    let mut b = Octets::with_slice(
        b"\x00\x85\xf2\xb2\x4a\x84\xff\x87\x49\x51\xff\xff\xff\xfa\x7f",
    );
    assert!(b.get_huffman_decoded().is_err());
}

#[test]
fn octets_writer_huffman_matches_rfc_vectors() {
    assert_octets_writer_huffman_matches::<false>(
        b"www.example.com",
        b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
    );

    assert_octets_writer_huffman_matches::<false>(
        b"no-cache",
        b"\xa8\xeb\x10\x64\x9c\xbf",
    );

    assert_octets_writer_huffman_matches::<false>(
        b"custom-key",
        b"\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f",
    );

    assert_octets_writer_huffman_matches::<false>(
        b"custom-value",
        b"\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf",
    );

    assert_octets_writer_huffman_matches::<true>(
        b"WWW.EXAMPLE.COM",
        b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
    );
}

fn assert_octets_writer_huffman_matches<const LOWER_CASE: bool>(
    input: &[u8], expected: &[u8],
) {
    assert_eq!(
        huffman_encoding_len::<LOWER_CASE>(input).unwrap(),
        expected.len()
    );

    let mut actual = [0u8; 64];
    let len = {
        let mut sink = ByteAtATimeSink::new(&mut actual);
        sink.put_huffman_encoded::<LOWER_CASE>(input).unwrap();
        sink.off
    };

    assert_eq!(len, expected.len());
    assert_eq!(&actual[..len], expected);

    let mut actual = [0u8; 64];
    let len = {
        let mut buf = OctetsMut::with_slice(&mut actual);
        buf.put_huffman_encoded::<LOWER_CASE>(input).unwrap();
        buf.off()
    };

    assert_eq!(len, expected.len());
    assert_eq!(&actual[..len], expected);
}

struct ByteAtATimeSink<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> ByteAtATimeSink<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, off: 0 }
    }
}

impl OctetsWriter for ByteAtATimeSink<'_> {
    type Error = BufferTooShortError;

    fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        for &b in v {
            if self.off == self.buf.len() {
                return Err(BufferTooShortError);
            }

            self.buf[self.off] = b;
            self.off += 1;
        }

        Ok(())
    }
}

#[test]
fn octets_writer_huffman_propagates_sink_error() {
    #[derive(Debug, PartialEq, Eq)]
    struct SinkError;

    struct FailingSink;

    impl OctetsWriter for FailingSink {
        type Error = SinkError;

        fn put_bytes(
            &mut self, _v: &[u8],
        ) -> std::result::Result<(), Self::Error> {
            Err(SinkError)
        }
    }

    let mut sink = FailingSink;
    let err = sink.put_huffman_encoded::<false>(b"abcdefghijklmnopqrstuvwxyz");

    assert_eq!(err, Err(SinkError));
}
