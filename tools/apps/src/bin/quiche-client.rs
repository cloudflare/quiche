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

use quiche_apps::common::*;

use quiche_apps::client::*;

const USAGE: &str = "Usage:
  quiche-client [options] URL...
  quiche-client -h | --help

Options:
  --method METHOD          Use the given HTTP request method [default: GET].
  --body FILE              Send the given file as request body.
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT   Idle timeout in milliseconds [default: 30000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --http-version VERSION   HTTP version to use [default: all].
  --dgram-proto PROTO      DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT      Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA        Data to send for certain types of DATAGRAM application protocol [default: quack].
  --dump-packets PATH      Dump the incoming packets as files in the given directory.
  --dump-responses PATH    Dump response payload as files in the given directory.
  --dump-json              Dump response headers and payload to stdout in JSON format.
  --max-json-payload BYTES  Per-response payload limit when dumping JSON [default: 10000].
  --connect-to ADDRESS     Override ther server's address.
  --no-verify              Don't verify server's certificate.
  --no-grease              Don't send GREASE.
  --cc-algorithm NAME      Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart        Disable HyStart++.
  -H --header HEADER ...   Add a request header.
  -n --requests REQUESTS   Send the given number of identical requests [default: 1].
  -h --help                Show this screen.
";

fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = ClientArgs::with_docopt(&docopt);

    match connect(args, conn_args, stdout_sink) {
        Err(ClientError::HandshakeFail) => std::process::exit(-1),
        Err(ClientError::HttpFail) => std::process::exit(-2),
        Err(ClientError::Other(e)) => panic!(e),
        Ok(_) => (),
    }
}
