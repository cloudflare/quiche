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

use std::net;

use std::collections::HashMap;

use quiche::h3::qpack::Header;
use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1452;

const USAGE: &str = "Usage:
  h3server [options]
  h3server -h | --help

Options:
  --listen <addr>   Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>     TLS certificate path [default: examples/cert.crt]
  --key <file>      TLS certificate key path [default: examples/cert.key]
  --root <dir>      Root directory [default: examples/root/]
  --name <str>      Name of the server [default: quic.tech]
  -h --help         Show this screen.
";
struct HTTP3Client {
    quiche_conn: Box<quiche::Connection>,
    http3_conn: Option<quiche::h3::Connection>,
}

type HTTP3ClientMap = HashMap<Vec<u8>, (net::SocketAddr, HTTP3Client)>;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let socket = net::UdpSocket::bind(args.get_str("--listen")).unwrap();

    let root_dir = args.get_str("--root");

    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    let mut clients = HTTP3ClientMap::new();

    let mut quiche_config = quiche::Config::new(quiche::VERSION_DRAFT18).unwrap();

    quiche_config
        .load_cert_chain_from_pem_file(args.get_str("--cert"))
        .unwrap();
    quiche_config
        .load_priv_key_from_pem_file(args.get_str("--key"))
        .unwrap();

    quiche_config.set_application_protos(&[b"h3-18"]).unwrap();

    quiche_config.set_idle_timeout(30);
    quiche_config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    quiche_config.set_initial_max_data(10_000_000);
    quiche_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quiche_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quiche_config.set_initial_max_streams_bidi(100);
    quiche_config.set_initial_max_streams_uni(100);
    quiche_config.set_disable_migration(true);

    loop {
        // TODO: use event loop that properly supports timers
        let timeout = clients
            .values()
            .filter_map(|(_, c)| c.quiche_conn.timeout())
            .min();

        poll.poll(&mut events, timeout).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                clients
                    .values_mut()
                    .for_each(|(_, c)| c.quiche_conn.on_timeout());

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
                    continue;
                },
            };

            if hdr.ty == quiche::Type::VersionNegotiation {
                error!("Version negotiation invalid on the server");
                continue;
            }

            let (_, client) = if !clients.contains_key(&hdr.dcid) {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue;
                }

                if hdr.version != quiche::VERSION_DRAFT18 {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();
                    let out = &out[..len];

                    socket.send_to(out, &src).unwrap();
                    continue;
                }

                let mut scid: [u8; LOCAL_CONN_ID_LEN] = [0; LOCAL_CONN_ID_LEN];
                SystemRandom::new().fill(&mut scid[..]).unwrap();

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &src);

                    let len = quiche::retry(
                        &hdr.scid, &hdr.dcid, &scid, &new_token, &mut out,
                    )
                    .unwrap();
                    let out = &out[..len];

                    socket.send_to(out, &src).unwrap();
                    continue;
                }

                let odcid = validate_token(&src, token);

                if odcid == None {
                    error!("Invalid address validation token");
                    continue;
                }

                debug!(
                    "New connection: dcid={} scid={} lcid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&hdr.scid),
                    hex_dump(&scid)
                );

                let q = quiche::accept(&scid, odcid, &mut quiche_config).unwrap();

                let client = HTTP3Client {
                    quiche_conn: q,
                    http3_conn: None,
                };

                clients.insert(scid.to_vec(), (src, client));

                clients.get_mut(&scid[..]).unwrap()
            } else {
                clients.get_mut(&hdr.dcid).unwrap()
            };

            // Process potentially coalesced packets.
            let read = match client.quiche_conn.recv(buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", client.quiche_conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!(
                        "{} recv failed: {:?}",
                        client.quiche_conn.trace_id(),
                        e
                    );
                    client
                        .quiche_conn
                        .close(false, e.to_wire(), b"fail")
                        .unwrap();
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", client.quiche_conn.trace_id(), read);

            if client.quiche_conn.is_established() {
                if client.quiche_conn.application_proto() != b"h3-18" {
                    // TODO a better error code?
                    client
                        .quiche_conn
                        .close(false, 0x0, b"I don't support your ALPNs")
                        .unwrap();
                    break;
                }

                let h3_config =
                    quiche::h3::Config::new(16, 1024, 0, 0).unwrap();

                if client.http3_conn.is_none() {
                    debug!(
                        "{} QUIC handshake completed, now trying HTTP/3",
                        client.quiche_conn.trace_id()
                    );
                    let h3_conn = quiche::h3::accept(
                        &mut client.quiche_conn,
                        &h3_config,
                    )
                    .unwrap();

                    // TODO some sanity checking that H3 conn is ok before
                    // adding it to the collection
                    client.http3_conn = Some(h3_conn);
                }
            }

            if let Some(http3_conn) = &mut client.http3_conn {
                match http3_conn.process(client.quiche_conn.as_mut()) {
                    Ok(quiche::h3::Event::OnHeaders { stream_id, value }) => {
                        info!(
                            "got request {:?} on stream id {}",
                            value, stream_id
                        );

                        send_response(&mut client.quiche_conn, http3_conn, root_dir, &value, stream_id);
                    },
                    Ok(quiche::h3::Event::OnPayloadData { stream_id, value }) => {
                        info!(
                            "Got request data of length {} in stream id {}",
                            value.len(),
                            stream_id
                        );
                    },
                    Err(quiche::h3::Error::Done) => {
                        // TODO
                    },
                    Err(e) => {
                        error!(
                            "{} HTTP/3 error {:?}",
                            client.quiche_conn.trace_id(),
                            e
                        );

                        client
                            .quiche_conn
                            .close(false, 0x0, b"HTTP/3 Failed")
                            .unwrap();
                        break;
                    },
                }
            }
        }

        for (peer, client) in clients.values_mut() {
            loop {
                let write = match client.quiche_conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.quiche_conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!(
                            "{} send failed: {:?}",
                            client.quiche_conn.trace_id(),
                            e
                        );
                        client
                            .quiche_conn
                            .close(false, e.to_wire(), b"fail")
                            .unwrap();
                        break;
                    },
                };

                // TODO: coalesce packets.
                socket.send_to(&out[..write], &peer).unwrap();

                debug!(
                    "{} written {} bytes",
                    client.quiche_conn.trace_id(),
                    write
                );
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, (_, ref mut c)| {
            debug!("Collecting garbage");

            if c.quiche_conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.quiche_conn.trace_id(),
                    c.quiche_conn.stats()
                );
            }

            !c.quiche_conn.is_closed()
        });
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

fn send_response(
    quic_conn: &mut quiche::Connection,
    http3_conn: &mut quiche::h3::Connection,
    root_dir: &str,
    request: &[Header],
    stream_id: u64
) {
    let mut file_path = std::path::PathBuf::from(root_dir);

    let mut method = None;

    for hdr in request {
        match hdr.name() {
            ":path:" => {
                file_path.push(hdr.value());
            },
            ":method:" => {
                method = Some(hdr.value());
            },
            _ => { 
                //TODO 
            }
        }
    }
    
    if method != Some("GET") {
        return ;
    }

    let mut status = 404;
    let mut body = Vec::from(String::from("Not Found!"));
    match std::fs::read(file_path.as_path()) {
        Ok(data) => {
            status = 200;
            body = data;
        },
        Err(e) => {
            error!("{:?} {}. Returning a 404.", file_path, e);
        },
    }

    let headers = vec![
        Header::new(":status:", &status.to_string()),
        Header::new("Server:", "quiche-http/3"),
        Header::new("Content-Length", &body.len().to_string()),
    ];

    match http3_conn.send_response(
        quic_conn,
        stream_id,
        &headers,
        Some(body)
    ) {
        Ok(()) => {
            info!(
                "{} Sent response on stream {}",
                quic_conn.trace_id(),
                stream_id
            );
        },
        Err(e) => {
            error!(
                "{} HTTP/3 error {:?}",
                quic_conn.trace_id(),
                e
            );
        }
    }
}
