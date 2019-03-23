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

use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1350;

const USAGE: &str = "Usage:
  http3-server [options]
  http3-server -h | --help

Options:
  --listen <addr>   Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>     TLS certificate path [default: examples/cert.crt]
  --key <file>      TLS certificate key path [default: examples/cert.key]
  --root <dir>      Root directory [default: examples/root/]
  --name <str>      Name of the server [default: quic.tech]
  --no-retry        Disable stateless retry.
  --no-grease       Don't send GREASE.
  -h --help         Show this screen.
";

struct Client {
    conn: Box<quiche::Connection>,
    http3_conn: Option<quiche::h3::Connection>,
}

type ClientMap = HashMap<Vec<u8>, (net::SocketAddr, Client)>;

fn main() -> Result<(), Box<std::error::Error>> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

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

    let mut clients = ClientMap::new();

    let mut config = quiche::Config::new(quiche::VERSION_DRAFT19)?;

    config.load_cert_chain_from_pem_file(args.get_str("--cert"))?;
    config.load_priv_key_from_pem_file(args.get_str("--key"))?;

    config.set_application_protos(b"\x05h3-19")?;

    config.set_idle_timeout(5000);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.set_disable_migration(true);

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }

    if args.get_bool("--no-grease") {
        config.grease(false);
    }

    loop {
        // TODO: use event loop that properly supports timers
        let timeout =
            clients.values().filter_map(|(_, c)| c.conn.timeout()).min();

        poll.poll(&mut events, timeout)?;

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                clients.values_mut().for_each(|(_, c)| c.conn.on_timeout());

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

            let (_, client) = if !clients.contains_key(&hdr.dcid) {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue;
                }

                if hdr.version != quiche::VERSION_DRAFT19 {
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

                let mut odcid = None;

                if !args.get_bool("--no-retry") {
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

                    odcid = validate_token(&src, token);

                    if odcid == None {
                        error!("Invalid address validation token");
                        continue;
                    }

                    scid.copy_from_slice(&hdr.dcid);
                }

                debug!(
                    "New connection: dcid={} scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&scid)
                );

                let conn = quiche::accept(&scid, odcid, &mut config)?;

                let client = Client {
                    conn,
                    http3_conn: None,
                };

                clients.insert(scid.to_vec(), (src, client));

                clients.get_mut(&scid[..]).unwrap()
            } else {
                clients.get_mut(&hdr.dcid).unwrap()
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", client.conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    client.conn.close(false, e.to_wire(), b"fail")?;
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", client.conn.trace_id(), read);

            if client.conn.is_established() && client.http3_conn.is_none() {
                if client.conn.application_proto() != b"h3-19" {
                    // TODO a better error code?
                    client.conn.close(
                        false,
                        0x0,
                        b"I don't support your ALPNs",
                    )?;

                    break;
                }

                debug!(
                    "{} QUIC handshake completed, now trying HTTP/3",
                    client.conn.trace_id()
                );

                let h3_config = quiche::h3::Config::new(16, 1024, 0, 0)?;

                let h3_conn = match quiche::h3::Connection::with_transport(
                    &mut client.conn,
                    &h3_config,
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to create HTTP/3 connection: {}", e);
                        break 'read;
                    },
                };

                // TODO: sanity check h3 connection before adding to map
                client.http3_conn = Some(h3_conn);
            }

            if let Some(http3_conn) = &mut client.http3_conn {
                match http3_conn.poll(client.conn.as_mut()) {
                    Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
                        handle_request(
                            &mut client.conn,
                            http3_conn,
                            stream_id,
                            &headers,
                            args.get_str("--root"),
                        );
                    },

                    Ok((stream_id, quiche::h3::Event::Data(data))) => {
                        info!(
                            "{} got request data of length {} in stream id {}",
                            client.conn.trace_id(),
                            data.len(),
                            stream_id
                        );
                    },

                    Err(quiche::h3::Error::Done) => {},

                    Err(e) => {
                        error!("{} HTTP/3 error {:?}", client.conn.trace_id(), e);
                        break;
                    },
                }
            }
        }

        for (peer, client) in clients.values_mut() {
            loop {
                let write = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);
                        client.conn.close(false, e.to_wire(), b"fail")?;
                        break;
                    },
                };

                // TODO: coalesce packets.
                socket.send_to(&out[..write], &peer)?;

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, (_, ref mut c)| {
            debug!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
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

fn handle_request(
    conn: &mut quiche::Connection, http3_conn: &mut quiche::h3::Connection,
    stream_id: u64, headers: &[quiche::h3::Header], root: &str,
) {
    info!(
        "{} got request {:?} on stream id {}",
        conn.trace_id(),
        headers,
        stream_id
    );

    match build_response(root, headers) {
        Ok((headers, body)) => {
            if let Err(e) =
                http3_conn.send_response(conn, stream_id, &headers, false)
            {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
            }

            if let Err(e) = http3_conn.send_body(conn, stream_id, &body, true) {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
            }
        },

        Err(e) => {
            error!("{} failed to build response {:?}", conn.trace_id(), e);
        },
    }
}

fn build_response(
    root: &str, request: &[quiche::h3::Header],
) -> Result<(std::vec::Vec<quiche::h3::Header>, std::vec::Vec<u8>), ()> {
    let mut file_path = std::path::PathBuf::from(root);
    let mut path = std::path::Path::new("");

    for hdr in request {
        match hdr.name() {
            ":path" => {
                path = std::path::Path::new(hdr.value());
            },

            ":method" =>
                if hdr.value() != "GET" {
                    return Err(());
                },

            _ => (),
        }
    }

    for c in path.components() {
        if let std::path::Component::Normal(v) = c {
            file_path.push(v)
        }
    }

    let (status, body) = match std::fs::read(file_path.as_path()) {
        Ok(data) => (200, data),
        Err(_) => (404, b"Not Found!".to_vec()),
    };

    Ok((
        vec![
            quiche::h3::Header::new(":status", &status.to_string()),
            quiche::h3::Header::new("server", "quiche"),
            quiche::h3::Header::new("content-length", &body.len().to_string()),
        ],
        body,
    ))
}
