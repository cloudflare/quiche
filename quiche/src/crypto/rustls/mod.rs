// Copyright (C) 2025, Cloudflare, Inc.
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

use crate::crypto::Algorithm;
use crate::Error;
use crate::Result;

pub struct PacketKey {}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        todo!()
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        todo!()
    }
}

pub struct Open {}

impl Open {
    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        todo!()
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        todo!()
    }

    pub fn alg(&self) -> Algorithm {
        // self.alg
        todo!()
    }

    pub fn derive_next_packet_key(&self) -> Result<Open> {
        todo!()
    }
}

pub struct Seal {}

impl Seal {
    pub const ENCRYPT: u32 = 1;

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        todo!()
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        todo!()
    }

    pub fn alg(&self) -> Algorithm {
        // self.alg
        todo!()
    }

    pub fn derive_next_packet_key(&self) -> Result<Seal> {
        todo!()
    }
}

pub fn derive_initial_key_material(
    cid: &[u8], version: u32, is_server: bool, did_reset: bool,
) -> Result<(Open, Seal)> {
    let open = Open {};
    let seal = Seal {};

    Ok((open, seal))
}

pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::CryptoFail);
    }

    match a == b {
        true => Ok(()),
        false => Err(Error::CryptoFail),
    }
}
