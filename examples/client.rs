// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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
extern crate mio;
extern crate url;
extern crate rand;
extern crate docopt;
extern crate quiche;
extern crate env_logger;

use std::io;
use std::net;
use std::time;

use docopt::Docopt;

use rand::Rng;

use url::Url;

const LOCAL_CONN_ID_LEN: usize = 16;

const HTTP_REQ_STREAM_ID: u64 = 4;

const TRANSPORT_PARAMS: quiche::TransportParams = quiche::TransportParams {
    idle_timeout: 30,
    initial_max_data: 10_000_000,
    initial_max_bidi_streams: 100,
    initial_max_uni_streams: 100,
    max_packet_size: 1500,
    ack_delay_exponent: 3,
    disable_migration: true,
    max_ack_delay: 25,
    initial_max_stream_data_bidi_local: 1_000_000,
    initial_max_stream_data_bidi_remote: 1_000_000,
    initial_max_stream_data_uni: 1_000_000,
    stateless_reset_token_present: true,
    stateless_reset_token: [0xba; 16],
};

const USAGE: &str = "Usage: client [options] URL

Options:
  -h --help          Show this screen.
  --no-verify        Don't verify server's certificate.
";

fn main() {
    let mut buf = [0; TRANSPORT_PARAMS.max_packet_size as usize];
    let mut out = [0; TRANSPORT_PARAMS.max_packet_size as usize];

    env_logger::init();

    let args = Docopt::new(USAGE)
                      .and_then(|dopt| dopt.parse())
                      .unwrap_or_else(|e| e.exit());

    let url = Url::parse(args.get_str("URL")).unwrap();

    let socket = net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(&url).unwrap();

    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(&socket, mio::Token(0),
                  mio::Ready::readable(),
                  mio::PollOpt::edge()).unwrap();

    let mut scid: [u8; LOCAL_CONN_ID_LEN] = [0; LOCAL_CONN_ID_LEN];
    rand::thread_rng().fill(&mut scid[..]);

    let mut config = quiche::Config::new(0xbabababa, &TRANSPORT_PARAMS).unwrap();
    config.verify_peer(true);

    if args.get_bool("--no-verify") {
        config.verify_peer(false);
    }

    let mut conn = quiche::connect(url.domain(), &scid, &mut config).unwrap();

    let write = match conn.send(&mut out) {
        Ok(v) => v,

        Err(e) => panic!("{} initial send failed: {:?}", conn.trace_id(), e),
    };

    socket.send(&out[..write]).unwrap();

    debug!("{} written {}", conn.trace_id(), write);

    let mut req_sent = false;

    loop {
        let now = time::Instant::now();

        let timeout = match conn.timeout() {
            Some(v) => {
                let timeout = if v < now {
                    time::Duration::new(0, 0)
                } else {
                    v.duration_since(now)
                };

                Some(timeout)
            },

            None => None,
        };

        poll.poll(&mut events, timeout).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("{} got {} bytes", conn.trace_id(), len);

            let buf = &mut buf[..len];

            let mut left = len;

            // Process potentially coalesced packets.
            while left > 0 {
                let read = match conn.recv(&mut buf[len - left..len]) {
                    Ok(v)  => v,

                    Err(quiche::Error::NothingToDo) => {
                        debug!("{} done reading", conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} recv failed: {:?}", conn.trace_id(), e);
                        conn.close(false, e.to_wire(), b"fail").unwrap();
                        break 'read;
                    },
                };

                left -= read;
            }
        }

        if conn.is_closed() {
            debug!("{} connection closed", conn.trace_id());
            break;
        }

        if conn.is_established() && !req_sent {
            info!("{} sending HTTP request for {}", conn.trace_id(), url.path());

            let req = format!("GET {}\r\n", url.path());
            conn.stream_send(HTTP_REQ_STREAM_ID, req.as_bytes(), true).unwrap();

            req_sent = true;
        }

        let streams: Vec<u64> = conn.stream_iter().collect();
        for s in streams {
            let data = conn.stream_recv(s).unwrap();

            info!("{} stream {} has {} bytes (fin? {})",
                  conn.trace_id(), s, data.len(), data.fin());

            if s == HTTP_REQ_STREAM_ID && data.fin() {
                conn.close(true, 0x00, b"kthxbye").unwrap();
            }
        }

        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::NothingToDo) => {
                    debug!("{} done writing", conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} send failed: {:?}", conn.trace_id(), e);
                    conn.close(false, e.to_wire(), b"fail").unwrap();
                    break;
                },
            };

            // TODO: coalesce packets.
            socket.send(&out[..write]).unwrap();

            debug!("{} written {}", conn.trace_id(), write);
        }

        if conn.is_closed() {
            debug!("{} connection closed", conn.trace_id());
            break;
        }
    }
}
