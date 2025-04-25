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

use super::Error;
use super::Result;

use self::table::DECODE_TABLE;
use self::table::ENCODE_TABLE;

pub fn decode(b: &mut octets::Octets) -> Result<Vec<u8>> {
    // Max compression ratio is >= 0.5
    let mut out = Vec::with_capacity(b.len() << 1);

    let mut decoder = Decoder::new();

    while b.cap() > 0 {
        let byte = b.get_u8()?;

        if let Some(b) = decoder.decode4(byte >> 4)? {
            out.push(b);
        }

        if let Some(b) = decoder.decode4(byte & 0xf)? {
            out.push(b);
        }
    }

    if !decoder.is_final() {
        return Err(Error::InvalidHuffmanEncoding);
    }

    Ok(out)
}

pub fn encode<const LOWER_CASE: bool>(
    src: &[u8], out: &mut octets::OctetsMut,
) -> Result<()> {
    let mut bits: u64 = 0;
    let mut pending = 0;

    for &b in src {
        let b = if LOWER_CASE {
            b.to_ascii_lowercase()
        } else {
            b
        };
        let (nbits, code) = ENCODE_TABLE[b as usize];

        pending += nbits;

        if pending < 64 {
            // Have room for the new token
            bits |= code << (64 - pending);
            continue;
        }

        pending -= 64;
        // Take only the bits that fit
        bits |= code >> pending;
        out.put_u64(bits)?;

        bits = if pending == 0 {
            0
        } else {
            code << (64 - pending)
        };
    }

    if pending == 0 {
        return Ok(());
    }

    bits |= u64::MAX >> pending;
    // TODO: replace with `next_multiple_of(8)` when stable
    pending = (pending + 7) & !7; // Round up to a byte
    bits >>= 64 - pending;

    if pending >= 32 {
        pending -= 32;
        out.put_u32((bits >> pending) as u32)?;
    }

    while pending > 0 {
        pending -= 8;
        out.put_u8((bits >> pending) as u8)?;
    }

    Ok(())
}

pub fn encode_output_length<const LOWER_CASE: bool>(src: &[u8]) -> Result<usize> {
    let mut bits: usize = 0;

    for &b in src {
        let b = if LOWER_CASE {
            b.to_ascii_lowercase()
        } else {
            b
        };

        let (nbits, _) = ENCODE_TABLE[b as usize];
        bits += nbits;
    }

    let mut len = bits / 8;

    if bits & 7 != 0 {
        len += 1;
    }

    if len > src.len() {
        return Err(Error::InflatedHuffmanEncoding);
    }

    Ok(len)
}

struct Decoder {
    state: usize,
    maybe_eos: bool,
}

impl Decoder {
    fn new() -> Decoder {
        Decoder {
            state: 0,
            maybe_eos: false,
        }
    }

    // Decodes 4 bits
    fn decode4(&mut self, input: u8) -> Result<Option<u8>> {
        const MAYBE_EOS: u8 = 1;
        const DECODED: u8 = 2;
        const ERROR: u8 = 4;

        // (next-state, byte, flags)
        let (next, byte, flags) = DECODE_TABLE[self.state][input as usize];

        if flags & ERROR == ERROR {
            // Data followed the EOS marker
            return Err(Error::InvalidHuffmanEncoding);
        }

        let ret = if flags & DECODED == DECODED {
            Some(byte)
        } else {
            None
        };

        self.state = next;
        self.maybe_eos = flags & MAYBE_EOS == MAYBE_EOS;

        Ok(ret)
    }

    fn is_final(&self) -> bool {
        self.state == 0 || self.maybe_eos
    }
}

mod table;
