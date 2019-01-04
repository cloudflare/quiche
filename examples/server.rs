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

use std::net;

use std::collections::hash_map;
use std::collections::HashMap;

use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const USAGE: &str = "Usage: server [options]

Options:
  -h --help         Show this screen.
  --listen <addr>   Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>     TLS certificate path [default: examples/cert.crt]
  --key <file>      TLS certificate key path [default: examples/cert.key]
  --root <dir>      Root directory [default: examples/root/]
  --name <str>      Name of the server [default: quic.tech]
";

fn main() {
    let mut buf = [0; 1500];
    let mut out = [0; 1500];

    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
                      .and_then(|dopt| dopt.parse())
                      .unwrap_or_else(|e| e.exit());

    let socket = net::UdpSocket::bind(args.get_str("--listen")).unwrap();

    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(&socket, mio::Token(0),
                  mio::Ready::readable(),
                  mio::PollOpt::edge()).unwrap();

    let mut connections: HashMap<net::SocketAddr, Box<quiche::Connection>> =
        HashMap::new();

    let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();

    config.load_cert_chain_from_pem_file(args.get_str("--cert")).unwrap();
    config.load_priv_key_from_pem_file(args.get_str("--key")).unwrap();

    config.set_idle_timeout(30);
    config.set_max_packet_size(1460);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_disable_migration(true);

    loop {
        // TODO: use event loop that properly supports timers
        let timeout = connections.values()
                                 .filter_map(|c| c.timeout())
                                 .min();

        poll.poll(&mut events, timeout).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                connections.values_mut().for_each(|c| c.on_timeout());

                break 'read;
            }

            let (len, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let buf = &mut buf[..len];

            let hdr = match quiche::Header::from_slice(buf, LOCAL_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue
                }
            };

            if hdr.ty == quiche::Type::VersionNegotiation {
                error!("Version negotiation invalid on the server");
                continue;
            }

            let conn = match connections.entry(src) {
                hash_map::Entry::Vacant(v) => {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue;
                    }

                    if hdr.version != quiche::VERSION_DRAFT17 {
                        warn!("Doing version negotiation");

                        let len = quiche::negotiate_version(&hdr, &mut out).unwrap();
                        let out = &out[..len];

                        socket.send_to(out, &src).unwrap();
                        continue;
                    }

                    let mut scid: [u8; LOCAL_CONN_ID_LEN] = [0; LOCAL_CONN_ID_LEN];
                    SystemRandom::new().fill(&mut scid[..]).unwrap();

                    debug!("New connection: dcid={} scid={} lcid={}",
                           hex_dump(&hdr.dcid),
                           hex_dump(&hdr.scid),
                           hex_dump(&scid));

                    let conn = quiche::accept(&scid, &mut config).unwrap();

                    v.insert(conn)
                },

                hash_map::Entry::Occupied(v) => v.into_mut(),
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(buf) {
                Ok(v)  => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", conn.trace_id(), e);
                    conn.close(false, e.to_wire(), b"fail").unwrap();
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", conn.trace_id(), read);

            let streams: Vec<u64> = conn.readable().collect();
            for s in streams {
                info!("{} stream {} is readable", conn.trace_id(), s);
                handle_stream(conn, s, &args);
            }
        }

        for (src, conn) in &mut connections {
            loop {
                let write = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
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
                socket.send_to(&out[..write], &src).unwrap();

                debug!("{} written {} bytes", conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        connections.retain(|_, ref mut c| {
            debug!("Collecting garbage");

            if c.is_closed() {
                debug!("{} connection collected", c.trace_id());
            }

            !c.is_closed()
        });
    }
}

fn handle_stream(conn: &mut quiche::Connection, stream: u64, args: &docopt::ArgvMap) {
    let stream_data = match conn.stream_recv(stream) {
        Ok(v) => v,

        Err(quiche::Error::Done) => return,

        Err(e) => panic!("{} stream recv failed {:?}",
                         conn.trace_id(), e),
    };

    info!("{} stream {} has {} bytes (fin? {})", conn.trace_id(),
          stream, stream_data.len(), stream_data.fin());

    if stream_data.len() > 4 && &stream_data[..4] == b"GET " {
        let uri = &stream_data[4..stream_data.len()];
        let uri = String::from_utf8(uri.to_vec()).unwrap();
        let uri = String::from(uri.lines().next().unwrap());
        let uri = std::path::Path::new(&uri);
        let mut path = std::path::PathBuf::from(args.get_str("--root"));

        for c in uri.components() {
            if let std::path::Component::Normal(v) = c {
                path.push(v)
            }
        }

        info!("{} got GET request for {:?} on stream {}",
              conn.trace_id(), path, stream);

        let data = std::fs::read(path.as_path())
                    .unwrap_or_else(|_| Vec::from(String::from("Not Found!\r\n")));

        info!("{} sending response of size {} on stream {}",
              conn.trace_id(), data.len(), stream);

        if let Err(e) = conn.stream_send(stream, &data, true) {
            error!("{} stream send failed {:?}", conn.trace_id(), e);
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter()
                              .map(|b| format!("{:02x}", b))
                              .collect();

    vec.join("")
}
