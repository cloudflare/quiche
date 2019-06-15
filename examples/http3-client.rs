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

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const USAGE: &str = "Usage:
  http3-client [options] URL
  http3-client -h | --help

Options:
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --no-verify              Don't verify server's certificate.
  --no-grease              Don't send GREASE.
  -h --help                Show this screen.
";

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let max_data = args.get_str("--max-data");
    let max_data = u64::from_str_radix(max_data, 10).unwrap();

    let max_stream_data = args.get_str("--max-stream-data");
    let max_stream_data = u64::from_str_radix(max_stream_data, 10).unwrap();

    let version = args.get_str("--wire-version");
    let version = u32::from_str_radix(version, 16).unwrap();

    let url = url::Url::parse(args.get_str("URL")).unwrap();

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
    socket.connect(&url).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(version).unwrap();

    config.verify_peer(true);

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_idle_timeout(5000);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(max_data);
    config.set_initial_max_stream_data_bidi_local(max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(max_stream_data);
    config.set_initial_max_stream_data_uni(max_stream_data);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_migration(true);

    let mut http3_conn = None;

    if args.get_bool("--no-verify") {
        config.verify_peer(false);
    }

    if args.get_bool("--no-grease") {
        config.grease(false);
    }

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(url.domain(), &scid, &mut config).unwrap();

    let write = match conn.send(&mut out) {
        Ok(v) => v,

        Err(e) => panic!("{} initial send failed: {:?}", conn.trace_id(), e),
    };

    socket.send(&out[..write]).unwrap();

    debug!("{} written {}", conn.trace_id(), write);

    let req_start = std::time::Instant::now();

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

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

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("{} got {} bytes", conn.trace_id(), len);

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", conn.trace_id(), e);
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", conn.trace_id(), read);
        }

        if conn.is_closed() {
            info!("{} connection closed, {:?}", conn.trace_id(), conn.stats());
            break;
        }

        // Create a new HTTP/3 connection and end an HTTP request as soon as
        // the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();

            let mut h3_conn =
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap();

            let mut path = String::from(url.path());

            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }

            let req = vec![
                quiche::h3::Header::new(":method", "GET"),
                quiche::h3::Header::new(":scheme", url.scheme()),
                quiche::h3::Header::new(":authority", url.host_str().unwrap()),
                quiche::h3::Header::new(":path", &path),
                quiche::h3::Header::new("user-agent", "quiche"),
            ];

            info!("{} sending HTTP request {:?}", conn.trace_id(), req);

            if let Err(e) = h3_conn.send_request(&mut conn, &req, true) {
                error!("{} failed to send request {:?}", conn.trace_id(), e);
                break;
            }

            http3_conn = Some(h3_conn);
        }

        if let Some(http3_conn) = &mut http3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
                        info!(
                            "{} got response headers {:?} on stream id {}",
                            conn.trace_id(),
                            headers,
                            stream_id
                        );
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        if let Ok(read) =
                            http3_conn.recv_body(&mut conn, stream_id, &mut buf)
                        {
                            debug!(
                                "{} got {} bytes of response data on stream {}",
                                conn.trace_id(),
                                read,
                                stream_id
                            );

                            print!("{}", unsafe {
                                std::str::from_utf8_unchecked(&buf[..read])
                            });
                        }
                    },

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!(
                            "{} response received in {:?}, closing...",
                            conn.trace_id(),
                            req_start.elapsed()
                        );

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {:?}", e),
                        }

                        break;
                    },

                    Err(quiche::h3::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!(
                            "{} HTTP/3 processing failed: {:?}",
                            conn.trace_id(),
                            e
                        );

                        break;
                    },
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done writing", conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} send failed: {:?}", conn.trace_id(), e);
                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            socket.send(&out[..write]).unwrap();

            debug!("{} written {}", conn.trace_id(), write);
        }

        if conn.is_closed() {
            info!("{} connection closed, {:?}", conn.trace_id(), conn.stats());
            break;
        }
    }
}
