// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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
extern crate ring;

use ring::rand::{
    SecureRandom,
    SystemRandom,
};

fn rng() -> &'static dyn SecureRandom {
    use std::ops::Deref;

    lazy_static! {
        static ref RANDOM: SystemRandom = SystemRandom::new();
    }

    RANDOM.deref()
}

pub fn rand_bytes(mut buf: &mut [u8]) {
    rng().fill(&mut buf).unwrap();
}

pub fn rand_u8() -> u8 {
    let mut buf = [0; 1];
    rng().fill(&mut buf).unwrap();

    buf[0]
}

pub fn rand_u64() -> u64 {
    let mut buf = [0; 8];
    rng().fill(&mut buf).unwrap();

    u64::from_ne_bytes(buf)
}
