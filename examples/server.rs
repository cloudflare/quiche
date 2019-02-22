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

#[macro_use]
extern crate log;

use std::net;

use std::collections::HashMap;

use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1452;

const USAGE: &str = "Usage:
  server [options]
  server -h | --help

Options:
  --listen <addr>   Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>     TLS certificate path [default: examples/cert.crt]
  --key <file>      TLS certificate key path [default: examples/cert.key]
  --root <dir>      Root directory [default: examples/root/]
  --name <str>      Name of the server [default: quic.tech]
  -h --help         Show this screen.
";

type ConnMap = HashMap<Vec<u8>, (net::SocketAddr, Box<quiche::Connection>)>;

fn main() -> Result<(), Box<std::error::Error>> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let socket = net::UdpSocket::bind(args.get_str("--listen"))?;

    let poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket)?;
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    let mut connections = ConnMap::new();

    let mut config = quiche::Config::new(quiche::VERSION_DRAFT18)?;

    config.load_cert_chain_from_pem_file(args.get_str("--cert"))?;
    config.load_priv_key_from_pem_file(args.get_str("--key"))?;

    config.set_application_protos(&[b"h3-18", b"hq-18", b"http/0.9"])?;

    config.set_idle_timeout(30);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.set_disable_migration(true);

    loop {
        // TODO: use event loop that properly supports timers
        let timeout = connections.values().filter_map(|(_, c)| c.timeout()).min();

        poll.poll(&mut events, timeout)?;

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                connections.values_mut().for_each(|(_, c)| c.on_timeout());

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

            let pkt_buf = &mut buf[..len];

            let hdr = match quiche::Header::from_slice(pkt_buf, LOCAL_CONN_ID_LEN)
            {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue;
                },
            };

            trace!("got packet {:?}", hdr);

            if hdr.ty == quiche::Type::VersionNegotiation {
                error!("Version negotiation invalid on the server");
                continue;
            }

            let (_, conn) = if !connections.contains_key(&hdr.dcid) {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue;
                }

                if hdr.version != quiche::VERSION_DRAFT18 {
                    warn!("Doing version negotiation");

                    let len = quiche::negotiate_version(
                        &hdr.scid, &hdr.dcid, &mut out,
                    )?;

                    let out = &out[..len];

                    socket.send_to(out, &src)?;
                    continue;
                }

                let mut scid = [0; LOCAL_CONN_ID_LEN];
                SystemRandom::new().fill(&mut scid[..])?;

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &src);

                    let len = quiche::retry(
                        &hdr.scid, &hdr.dcid, &scid, &new_token, &mut out,
                    )?;

                    let out = &out[..len];

                    socket.send_to(out, &src)?;
                    continue;
                }

                let odcid = validate_token(&src, token);

                if odcid == None {
                    error!("Invalid address validation token");
                    continue;
                }

                debug!(
                    "New connection: dcid={} scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&hdr.scid)
                );

                let conn = quiche::accept(&hdr.dcid, odcid, &mut config)?;

                connections.insert(hdr.dcid.to_vec(), (src, conn));

                connections.get_mut(&hdr.dcid).unwrap()
            } else {
                connections.get_mut(&hdr.dcid).unwrap()
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(pkt_buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", conn.trace_id(), e);
                    conn.close(false, e.to_wire(), b"fail")?;
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", conn.trace_id(), read);

            let streams: Vec<u64> = conn.readable().collect();
            for s in streams {
                while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                    debug!("{} received {} bytes", conn.trace_id(), read);

                    let stream_buf = &buf[..read];

                    debug!(
                        "{} stream {} has {} bytes (fin? {})",
                        conn.trace_id(),
                        s,
                        stream_buf.len(),
                        fin
                    );

                    handle_stream(conn, s, stream_buf, args.get_str("--root"));
                }
            }
        }

        for (peer, conn) in connections.values_mut() {
            loop {
                let write = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", conn.trace_id(), e);
                        conn.close(false, e.to_wire(), b"fail")?;
                        break;
                    },
                };

                // TODO: coalesce packets.
                socket.send_to(&out[..write], &peer)?;

                debug!("{} written {} bytes", conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        connections.retain(|_, (_, ref mut c)| {
            debug!("Collecting garbage");

            if c.is_closed() {
                info!("{} connection collected {:?}", c.trace_id(), c.stats());
            }

            !c.is_closed()
        });
    }
}

fn handle_stream(
    conn: &mut quiche::Connection, stream: u64, buf: &[u8], root: &str,
) {
    if buf.len() > 4 && &buf[..4] == b"GET " {
        let uri = &buf[4..buf.len()];
        let uri = String::from_utf8(uri.to_vec()).unwrap();
        let uri = String::from(uri.lines().next().unwrap());
        let uri = std::path::Path::new(&uri);
        let mut path = std::path::PathBuf::from(root);

        for c in uri.components() {
            if let std::path::Component::Normal(v) = c {
                path.push(v)
            }
        }

        info!(
            "{} got GET request for {:?} on stream {}",
            conn.trace_id(),
            path,
            stream
        );

        let data = std::fs::read(path.as_path())
            .unwrap_or_else(|_| Vec::from(String::from("Not Found!\r\n")));

        info!(
            "{} sending response of size {} on stream {}",
            conn.trace_id(),
            data.len(),
            stream
        );

        if let Err(e) = conn.stream_send(stream, &data, true) {
            error!("{} stream send failed {:?}", conn.trace_id(), e);
        }
    }
}

fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<&'a [u8]> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    let token = &token[addr.len()..];

    Some(&token[..])
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
