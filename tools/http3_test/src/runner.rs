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

use quiche::h3::NameValue;

use ring::rand::*;

use crate::Http3TestError;

pub fn run(
    test: &mut crate::Http3Test, peer_addr: std::net::SocketAddr,
    verify_peer: bool, idle_timeout: u64, max_data: u64, early_data: bool,
    session_file: Option<String>,
) -> Result<(), Http3TestError> {
    const MAX_DATAGRAM_SIZE: usize = 1350;

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let max_stream_data = max_data;

    let version = if let Some(v) = std::env::var_os("QUIC_VERSION") {
        match v.to_str() {
            Some("current") => quiche::PROTOCOL_VERSION,

            Some(v) => u32::from_str_radix(v, 16).unwrap(),

            _ => 0xbaba_baba,
        }
    } else {
        0xbaba_baba
    };

    let mut reqs_count = 0;

    let mut reqs_complete = 0;

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    info!("connecting to {:}", peer_addr);

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(version).unwrap();

    config.verify_peer(verify_peer);

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_idle_timeout(idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(max_data);
    config.set_initial_max_stream_data_bidi_local(max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(max_stream_data);
    config.set_initial_max_stream_data_uni(max_stream_data);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    if early_data {
        config.enable_early_data();
        debug!("early data enabled");
    }

    let mut http3_conn = None;

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let url = &test.endpoint();

    let local_addr = socket.local_addr().unwrap();

    let mut conn =
        quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
            .unwrap();

    if let Some(session_file) = &session_file {
        if let Ok(session) = std::fs::read(session_file) {
            conn.set_session(&session).ok();
        }
    }

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        return Err(Http3TestError::Other(format!("send() failed: {:?}", e)));
    }

    debug!("written {}", write);

    let req_start = std::time::Instant::now();

    loop {
        if !conn.is_in_early_data() || http3_conn.is_some() {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    return Err(Http3TestError::Other(format!(
                        "recv() failed: {:?}",
                        e
                    )));
                },
            };

            debug!("got {} bytes", len);

            let recv_info = quiche::RecvInfo {
                from,
                to: local_addr,
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done reading");
                    break;
                },

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    break 'read;
                },
            };

            debug!("processed {} bytes", read);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());

            if !conn.is_established() {
                error!("connection timed out after {:?}", req_start.elapsed(),);

                return Err(Http3TestError::HandshakeFail);
            }

            if reqs_complete != reqs_count {
                error!("Client timed out after {:?} and only completed {}/{} requests",
                req_start.elapsed(), reqs_complete, reqs_count);
                return Err(Http3TestError::HttpFail);
            }

            if let Some(session_file) = session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, &session).ok();
                }
            }

            break;
        }

        // Create a new HTTP/3 connection and end an HTTP request as soon as
        // the QUIC connection is established.
        if (conn.is_established() || conn.is_in_early_data()) &&
            http3_conn.is_none()
        {
            let h3_config = quiche::h3::Config::new().unwrap();

            let mut h3_conn =
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap();

            reqs_count = test.requests_count();

            match test.send_requests(&mut conn, &mut h3_conn) {
                Ok(_) => (),

                Err(quiche::h3::Error::Done) => (),

                Err(e) => {
                    return Err(Http3TestError::Other(format!(
                        "error sending: {:?}",
                        e
                    )));
                },
            };

            http3_conn = Some(h3_conn);
        }

        if let Some(http3_conn) = &mut http3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "got response headers {:?} on stream id {}",
                            hdrs_to_strings(&list),
                            stream_id
                        );

                        test.add_response_headers(stream_id, &list);
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) =
                            http3_conn.recv_body(&mut conn, stream_id, &mut buf)
                        {
                            info!(
                                "got {} bytes of response data on stream {}",
                                read, stream_id
                            );

                            test.add_response_body(stream_id, &buf, read);
                        }
                    },

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        reqs_complete += 1;

                        info!(
                            "{}/{} responses received",
                            reqs_complete, reqs_count
                        );

                        if reqs_complete == reqs_count {
                            info!(
                                "Completed test run. {}/{} response(s) received in {:?}, closing...",
                                reqs_complete,
                                reqs_count,
                                req_start.elapsed()
                            );

                            match conn.close(true, 0x00, b"kthxbye") {
                                // Already closed.
                                Ok(_) | Err(quiche::Error::Done) => (),

                                Err(e) => {
                                    return Err(Http3TestError::Other(format!(
                                        "error closing conn: {:?}",
                                        e
                                    )));
                                },
                            }

                            test.assert();

                            break;
                        }

                        match test.send_requests(&mut conn, http3_conn) {
                            Ok(_) => (),
                            Err(quiche::h3::Error::Done) => (),
                            Err(e) => {
                                return Err(Http3TestError::Other(format!(
                                    "error sending request: {:?}",
                                    e
                                )));
                            },
                        }
                    },

                    Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                        reqs_complete += 1;

                        info!("request was reset by peer with {}", e);
                        test.set_reset_stream_error(stream_id, e);

                        if reqs_complete == reqs_count {
                            info!(
                                "Completed test run. {}/{} response(s) received in {:?}, closing...",
                                reqs_complete,
                                reqs_count,
                                req_start.elapsed()
                            );

                            match conn.close(true, 0x00, b"kthxbye") {
                                // Already closed.
                                Ok(_) | Err(quiche::Error::Done) => (),

                                Err(e) => {
                                    return Err(Http3TestError::Other(format!(
                                        "error closing conn: {:?}",
                                        e
                                    )));
                                },
                            }

                            test.assert();

                            break;
                        }
                    },

                    Ok((_flow_id, quiche::h3::Event::Datagram)) => (),

                    Ok((_, quiche::h3::Event::PriorityUpdate)) => (),

                    Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                    Err(quiche::h3::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("HTTP/3 processing failed: {:?}", e);

                        break;
                    },
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);
                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                return Err(Http3TestError::Other(format!(
                    "send() failed: {:?}",
                    e
                )));
            }

            debug!("written {}", write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());

            if reqs_complete != reqs_count {
                error!("Client timed out after {:?} and only completed {}/{} requests",
                req_start.elapsed(), reqs_complete, reqs_count);
                return Err(Http3TestError::HttpFail);
            }

            if let Some(session_file) = session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, &session).ok();
                }
            }

            break;
        }
    }

    Ok(())
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
