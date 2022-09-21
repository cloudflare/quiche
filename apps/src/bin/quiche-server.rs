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

#[macro_use]
extern crate log;

use std::io;

use std::net;

use std::io::prelude::*;

use std::collections::HashMap;

use std::rc::Rc;

use std::cell::RefCell;

use ring::rand::*;

use quiche_apps::args::*;

use quiche_apps::common::*;

use quiche_apps::sendto::*;

const MAX_BUF_SIZE: usize = 65507;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];
    let mut pacing = false;

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = ServerArgs::with_docopt(&docopt);

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(args.listen.parse().unwrap()).unwrap();

    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.
    match set_txtime_sockopt(&socket) {
        Ok(_) => {
            pacing = true;
            debug!("successfully set SO_TXTIME socket option");
        },
        Err(e) => debug!("setsockopt failed {:?}", e),
    };

    info!("listening on {:}", socket.local_addr().unwrap());

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enable_gso = if args.disable_gso {
        false
    } else {
        detect_gso(&socket, max_datagram_size)
    };

    trace!("GSO detected: {}", enable_gso);

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file(&args.cert).unwrap();
    config.load_priv_key_from_pem_file(&args.key).unwrap();

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    let mut pkt_count = 0;

    let mut continue_write = false;

    let local_addr = socket.local_addr().unwrap();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),

            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() && !continue_write {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                let path = format!("{}/{}.pkt", target_path, pkt_count);

                if let Ok(f) = std::fs::File::create(&path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(pkt_buf).ok();
                }
            }

            pkt_count += 1;

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients_ids.contains_key(&hdr.dcid) &&
                !clients_ids.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if !args.no_retry {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOGDIR") {
                        let id = format!("{:?}", &scid);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    http_conn: None,
                    client_id,
                    partial_requests: HashMap::new(),
                    partial_responses: HashMap::new(),
                    siduck_conn: None,
                    app_proto_selected: false,
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_BUF_SIZE,
                };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;

                clients.get_mut(&client_id).unwrap()
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients_ids.get(&conn_id).unwrap(),
                };

                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new application protocol session as soon as the QUIC
            // connection is established.
            if !client.app_proto_selected &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established())
            {
                // At this stage the ALPN negotiation succeeded and selected a
                // single application protocol name. We'll use this to construct
                // the correct type of HttpConn but `application_proto()`
                // returns a slice, so we have to convert it to a str in order
                // to compare to our lists of protocols. We `unwrap()` because
                // we need the value and if something fails at this stage, there
                // is not much anyone can do to recover.
                let app_proto = client.conn.application_proto();

                if alpns::HTTP_09.contains(&app_proto) {
                    client.http_conn = Some(Box::new(Http09Conn::default()));

                    client.app_proto_selected = true;
                } else if alpns::HTTP_3.contains(&app_proto) {
                    let dgram_sender = if conn_args.dgrams_enabled {
                        Some(Http3DgramSender::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                            1,
                        ))
                    } else {
                        None
                    };

                    client.http_conn = match Http3Conn::with_conn(
                        &mut client.conn,
                        conn_args.max_field_section_size,
                        conn_args.qpack_max_table_capacity,
                        conn_args.qpack_blocked_streams,
                        dgram_sender,
                        Rc::new(RefCell::new(stdout_sink)),
                    ) {
                        Ok(v) => Some(v),

                        Err(e) => {
                            trace!("{} {}", client.conn.trace_id(), e);
                            None
                        },
                    };

                    client.app_proto_selected = true;
                } else if alpns::SIDUCK.contains(&app_proto) {
                    client.siduck_conn = Some(SiDuckConn::new(
                        conn_args.dgram_count,
                        conn_args.dgram_data.clone(),
                    ));

                    client.app_proto_selected = true;
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size =
                    client.conn.max_send_udp_payload_size();
            }

            if client.http_conn.is_some() {
                let conn = &mut client.conn;
                let http_conn = client.http_conn.as_mut().unwrap();
                let partial_responses = &mut client.partial_responses;

                // Handle writable streams.
                for stream_id in conn.writable() {
                    http_conn.handle_writable(conn, partial_responses, stream_id);
                }

                if http_conn
                    .handle_requests(
                        conn,
                        &mut client.partial_requests,
                        partial_responses,
                        &args.root,
                        &args.index,
                        &mut buf,
                    )
                    .is_err()
                {
                    continue 'read;
                }
            }

            // If we have a siduck connection, handle the quacks.
            if client.siduck_conn.is_some() {
                let conn = &mut client.conn;
                let si_conn = client.siduck_conn.as_mut().unwrap();

                if si_conn.handle_quacks(conn, &mut buf).is_err() {
                    continue 'read;
                }
            }

            handle_path_events(client);

            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = client.conn.retired_scid_next() {
                info!("Retiring source CID {:?}", retired_scid);
                clients_ids.remove(&retired_scid);
            }

            // Provides as many CIDs as possible.
            while client.conn.source_cids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client
                    .conn
                    .new_source_cid(&scid, reset_token, false)
                    .is_err()
                {
                    break;
                }

                clients_ids.insert(scid, client.client_id);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate =
                client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimun bound of 10xMSS.
                client.max_send_burst =
                    client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst =
                client.conn.send_quantum().min(client.max_send_burst) /
                    client.max_datagram_size *
                    client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info = None;

            while total_write < max_send_burst {
                let (write, send_info) = match client
                    .conn
                    .send(&mut out[total_write..max_send_burst])
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                break;
            }

            if let Err(e) = send_to(
                &socket,
                &out[..total_write],
                &dst_info.unwrap(),
                client.max_datagram_size,
                pacing,
                enable_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send_to() failed: {:?}", e);
            }

            trace!("{} written {} bytes", client.conn.trace_id(), total_write);

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                continue_write = true;
                break;
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
            }

            !c.conn.is_closed()
        });

        clients_ids.retain(|_, client_id| clients.contains_key(client_id));
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
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

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
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

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .expect("cannot probe");
            },

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            },

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },
        }
    }
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option is set only on linux platforms.
#[cfg(target_os = "linux")]
fn set_txtime_sockopt(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::unix::io::AsRawFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(sock.as_raw_fd(), TxTime, &config)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_txtime_sockopt(_: &mio::net::UdpSocket) -> io::Result<()> {
    use std::io::Error;
    use std::io::ErrorKind;

    Err(Error::new(
        ErrorKind::Other,
        "Not supported on this platform",
    ))
}
