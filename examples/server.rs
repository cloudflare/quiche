// Copyright (c) 2018, Alessandro Ghedini
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
extern crate docopt;
extern crate quiche;
extern crate env_logger;

use std::fs;
use std::net;
use std::path;
use std::collections::hash_map;
use std::collections::HashMap;

use docopt::Docopt;

use quiche::packet;
use quiche::rand;

const LOCAL_CONN_ID_LEN: usize = 16;

const TRANSPORT_PARAMS: quiche::TransportParams = quiche::TransportParams {
    idle_timeout: 30,
    initial_max_data: 10000000,
    initial_max_bidi_streams: 100,
    initial_max_uni_streams: 100,
    max_packet_size: 1500,
    ack_delay_exponent: 3,
    disable_migration: true,
    max_ack_delay: 25,
    initial_max_stream_data_bidi_local: 1000000,
    initial_max_stream_data_bidi_remote: 1000000,
    initial_max_stream_data_uni: 1000000,
    stateless_reset_token_present: true,
    stateless_reset_token: [0xba; 16],
};

const USAGE: &'static str = "Usage: server [options]

Options:
  -h --help         Show this screen.
  --listen <addr>   Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>     TLS certificate path [default: examples/cert.crt]
  --key <file>      TLS certificate key path [default: examples/cert.key]
  --root <dir>      Root directory [default: examples/root/]
  --name <str>      Name of the server [default: quic.tech]
";

fn main() {
    let mut buf = [0; TRANSPORT_PARAMS.max_packet_size as usize];
    let mut out = [0; TRANSPORT_PARAMS.max_packet_size as usize];

    env_logger::init();

    let args = Docopt::new(USAGE)
                      .and_then(|dopt| dopt.parse())
                      .unwrap_or_else(|e| e.exit());

    let socket = net::UdpSocket::bind(args.get_str("--listen")).unwrap();

    let mut connections: HashMap<net::SocketAddr, Box<quiche::Conn>> = HashMap::new();

    loop {
        let (len, src) = socket.recv_from(&mut buf).unwrap();
        debug!("Got {} bytes from {}", len, src);

        let buf = &mut buf[..len];

        let hdr = if packet::has_long_header(buf[0]) {
            packet::Header::decode_long(buf)
        } else {
            packet::Header::decode_short(buf, LOCAL_CONN_ID_LEN)
        };

        let hdr = match hdr {
            Ok(v) => v,

            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                continue
            }
        };

        let conn = match connections.entry(src) {
            hash_map::Entry::Vacant(v) =>{
                if hdr.version != quiche::VERSION_DRAFT15 {
                    warn!("Doing version negotiation");

                    let len = packet::negotiate_version(&hdr, &mut out).unwrap();
                    let out = &out[..len];

                    socket.send_to(out, &src).unwrap();
                    continue;
                }

                if hdr.ty != packet::Type::Initial {
                    error!("Packet is not Initial");
                    continue;
                }

                let mut scid: [u8; LOCAL_CONN_ID_LEN] = [0; LOCAL_CONN_ID_LEN];
                rand::rand_bytes(&mut scid[..]);

                let config = quiche::Config {
                    version: quiche::VERSION_DRAFT15,

                    local_conn_id: &scid,

                    local_transport_params: &TRANSPORT_PARAMS,

                    tls_server_name: args.get_str("--name"),
                    tls_certificate: args.get_str("--cert"),
                    tls_certificate_key: args.get_str("--key"),
                };

                debug!("New connection: dcid={} scid={} lcid={}",
                       hex_dump(&hdr.dcid),
                       hex_dump(&hdr.scid),
                       hex_dump(&scid));

                let conn = quiche::Conn::new(config, true).unwrap();

                v.insert(conn)
            },

            hash_map::Entry::Occupied(v) => v.into_mut(),
        };

        let mut left = len;

        // Process potentially coalesced packets.
        while left > 0 {
            let read = match conn.recv(&mut buf[len - left..len]) {
                Ok(v)  => v,
                Err(e) => panic!("{} recv failed: {:?}",
                                 conn.local_conn_id_hex(), e),
            };

            left -= read;

            debug!("{} read {} bytes", conn.local_conn_id_hex(), read);
        }

        let streams: Vec<u64> = conn.stream_iter().collect();
        for s in streams {
            info!("{} stream {} is readable", conn.local_conn_id_hex(), s);
            handle_stream(conn, s, &args);
        }

        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::NothingToDo) => {
                    debug!("{} done writing", conn.local_conn_id_hex());
                    break;
                },

                Err(e) => panic!("{} socket send failed: {:?}",
                                 conn.local_conn_id_hex(), e),
            };

            // TODO: coalesce packets.
            socket.send_to(&out[..write], &src).unwrap();

            debug!("{} written {} bytes", conn.local_conn_id_hex(), write);
        }
    }
}

fn handle_stream(conn: &mut quiche::Conn, stream: u64, args: &docopt::ArgvMap) {
    let stream_data = match conn.stream_recv(stream) {
        Ok(v) => v,
        Err(e) => panic!("{} stream recv failed {:?}",
                         conn.local_conn_id_hex(), e),
    };

    if &stream_data[..4] == b"GET " {
        let uri = &stream_data[4..stream_data.len()];
        let uri = String::from_utf8(uri.to_vec()).unwrap();
        let uri = String::from(uri.lines().next().unwrap());
        let uri = path::Path::new(&uri);
        let mut path = path::PathBuf::from(args.get_str("--root"));

        for c in uri.components() {
            match c {
                path::Component::Normal(v) => path.push(v),
                _ => (),
            }
        }

        info!("{} got GET request for {:?} on stream {}",
              conn.local_conn_id_hex(), path, stream);

        let data = fs::read(path.as_path()).unwrap_or(
            Vec::from(String::from("Not Found!"))
        );

        info!("{} sending response of size {} on stream {}",
              conn.local_conn_id_hex(), data.len(), stream);

        if let Err(e) = conn.stream_send(stream, &data, true) {
            panic!("{} stream send failed {:?}",
                   conn.local_conn_id_hex(), e);
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter()
                              .map(|b| format!("{:02x}", b))
                              .collect();

    vec.join("")
}
