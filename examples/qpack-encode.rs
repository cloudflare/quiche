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

#[macro_use]
extern crate log;

use std::fs::File;

use std::io::prelude::*;
use std::io::BufReader;

use quiche::h3;

const USAGE: &str = "Usage:
  qpack-encode [options] FILE
  qpack-encode -h | --help

Options:
  -h --help  Show this screen.
";

fn main() {
    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let file = File::open(args.get_str("FILE")).unwrap();
    let file = BufReader::new(&file);

    let mut enc = h3::qpack::Encoder::new();

    let mut headers: Vec<h3::Header> = Vec::new();

    let mut stream_id = 1u64;

    for line in file.lines().map(Result::unwrap) {
        if line.starts_with('#') {
            continue;
        }

        if line.is_empty() {
            let mut out = [0u8; 65535];

            let len = enc.encode(&headers, &mut out).unwrap();

            debug!("Writing header block stream={} len={}", stream_id, len);

            std::io::stdout()
                .write_all(&stream_id.to_be_bytes())
                .unwrap();
            std::io::stdout()
                .write_all(&(len as u32).to_be_bytes())
                .unwrap();
            std::io::stdout().write_all(&out[..len]).unwrap();

            stream_id += 1;

            headers.clear();

            continue;
        }

        let name = line.split('\t').nth(0).unwrap();
        let value = line.split('\t').last().unwrap();

        headers.push(h3::Header::new(name, value));
    }
}
