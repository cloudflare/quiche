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

extern crate quiche;

use std::net::UdpSocket;

use quiche::packet;
use quiche::rand;

static TRANSPORT_PARAMS: quiche::TransportParams = quiche::TransportParams {
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

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; 65535];

    let socket = UdpSocket::bind("127.0.0.1:4433").unwrap();

    let mut conn: Option<Box<quiche::Conn>> = None;

    loop {
        let (len, src) = socket.recv_from(&mut buf).unwrap();
        println!("Got {} bytes from {}", len, src);

        let buf = &mut buf[..len];

        if conn.is_none() {
            let hdr = packet::parse_long_header(buf).unwrap();

            if hdr.version != quiche::VERSION_DRAFT15 {
                println!("VERSION NEGOTIATION");

                let len = packet::negotiate_version(&hdr, &mut out).unwrap();
                let out = &out[..len];

                socket.send_to(out, &src).unwrap();
                continue;
            }

            if hdr.ty != packet::Type::Initial {
                println!("NOT INITIAL PACKET");
                continue;
            }

            let mut scid: [u8; 16] = [0; 16];
            rand::rand_bytes(&mut scid[..]);

            let config = quiche::Config {
                version: quiche::VERSION_DRAFT15,

                local_conn_id: &scid,

                local_transport_params: &TRANSPORT_PARAMS,

                tls_server_name: "quic.tech",
                tls_certificate: "examples/cert.crt",
                tls_certificate_key: "examples/cert.key",
            };

            conn = quiche::accept(config).ok();
        }

        let conn = match conn {
            Some(ref mut v) => v,
            None => {
                println!("CONNECTION IS NOT INITIALIZED");
                break;
            },
        };

        let mut left = len;

        // Process potentially coalesced packets.
        while left > 0 {
            let read = match conn.recv(&mut buf[len - left..len]) {
                Ok(v)  => v,
                Err(e) => panic!("RECV FAILED: {:?}", e),
            };

            left -= read;
        }

        let streams: Vec<u64> = conn.stream_iter().collect();
        for s in streams {
            let stream_data = match conn.stream_recv(s) {
                Ok(v) => v,
                Err(e) => panic!("STREAM RECV FAILED {:?}", e),
            };

            let woot = String::from_utf8_lossy(&stream_data);
            println!("RECV {} BYTES FROM STREAM {} FIN:{}: {}",
                     stream_data.len(), s, stream_data.fin(), woot);

            let mut resp: [u8; 25] = *b"WOOOO0000000000000000000T";
            let write = match conn.stream_send(s, &mut resp, true) {
                Ok(v) => v,
                Err(e) => panic!("STREAM SEND FAILED {:?}", e),
            };

            println!("STREAM {} AT OFFSET {}", s, write);
        }

        loop {
            let write = match conn.send(&mut out) {
                Ok(v)   => v,
                Err(quiche::Error::NothingToDo) => {
                    println!("DONE WRITING");
                    break;
                },
                Err(e)  => panic!("SEND FAILED: {:?}", e),
            };

            // TODO: coalesce packets.
            socket.send_to(&out[..write], &src).unwrap();

            println!("WRITTEN {}", write);
        }
    }
}
