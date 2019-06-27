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

#[macro_use]
extern crate clap;

use env_logger::Builder;
use ring::rand::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdout;
use std::net::ToSocketAddrs;
use std::path::Path;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let matches =
        clap_app!(http3_client =>
                  (about: "A simple QUIC client using HTTP/3")
                  (@arg no_verify: -k --("no-verify") "Don't verify server's certificate.")
                  (@arg no_grease: --("no-grease") "Don't send GREASE.")
                  (@arg show_timing: --("show-timing") "Show basic timing of the request.")
                  (@arg send_loss_n: --("send-loss") +takes_value "Make Nth sending packet lost [default: 0]")
                  (@arg recv_loss_n: --("recv-loss") +takes_value "Make N-th receiving packet lost [default: 0].")
                  (@arg dump_header: -D --("dump-header") +takes_value "Write a response header into file. Default is stdout.")
                  (@arg output: -O --output +takes_value "Write a response body into file. Default is stdout.")
                  (@arg header: ... -H --header +takes_value "Set a request header (\"Field: Value\")")
                  (@arg max_data: --("max-data") +takes_value "Connection-wide flow control limit [default: 10000000].")
                  (@arg max_stream_data: --("max-stream-data") +takes_value "Per-stream flow control limit [default: 1000000].")
                  (@arg wire_version: --("wire-version") +takes_value "The version number to send to the server [default: babababa].")
                  (@arg verbose: -v --verbose "Be verbose")
                  (@arg URL: +required ... "URL to download")
        ).get_matches();

    // init logging
    let mut log_builder = Builder::from_default_env();
    log_builder.default_format_timestamp_nanos(true);

    // verbose logging - set to info level
    if matches.is_present("verbose") {
        use log::LevelFilter;
        log_builder.filter(None, LevelFilter::Info);
    }

    log_builder.init();

    // argument processing
    let max_data = value_t!(matches.value_of("max_data"), u64).unwrap_or(1000000);
    let max_stream_data =
        value_t!(matches.value_of("max_stream_data"), u64).unwrap_or(1000000);
    let version = matches.value_of("wire_version").unwrap_or("babababa");
    let version = u32::from_str_radix(version, 16).unwrap();

    // packet loss simulation (simple)
    let send_loss_n = value_t!(matches.value_of("send_loss"), u32).unwrap_or(0);
    let recv_loss_n = value_t!(matches.value_of("recv_loss"), u32).unwrap_or(0);

    // can be multiple
    let mut req_headers: Vec<&str> = [].to_vec();

    match matches.values_of("header") {
        Some(h) => req_headers = h.collect(),
        None => {},
    }

    let urls: Vec<&str> = matches.values_of("URL").unwrap().collect();
    let url = url::Url::parse(urls[0]).unwrap();

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // packet counter
    let mut send_pkt_n = 0;
    let mut recv_pkt_n = 0;

    // write to files
    let header_path = matches.value_of("dump_header").unwrap_or("");
    let mut header_writer = match header_path {
        "" => Box::new(stdout()) as Box<Write>,
        filename => {
            let path = Path::new(filename);
            Box::new(File::create(&path).unwrap()) as Box<Write>
        },
    };

    let body_path = matches.value_of("output").unwrap_or("");
    let mut body_writer = match body_path {
        "" => Box::new(stdout()) as Box<Write>,
        filename => {
            let path = Path::new(filename);
            Box::new(File::create(&path).unwrap()) as Box<Write>
        },
    };

    // other options
    let no_verify = matches.is_present("no_verify");
    let no_grease = matches.is_present("no_grease");

    // timers
    let ts_start = std::time::Instant::now();
    let ts_dns;
    let mut ts_connect = std::time::Instant::now();
    let mut ts_req = std::time::Instant::now();
    let mut ts_resp = std::time::Instant::now();
    let ts_end;
    let mut body_len = 0;
    let mut http_status: i32 = 0;
    let show_timing = matches.is_present("show_timing");

    // Take a look at server address resolved to check if it's ipv4 or ipv6.
    // Depending on the IP family, bind_addr will be default address of
    // v4 or v6 for calling bind() later.
    // This workaround is to work with MacOS (or BSD variants which
    // doesn't allow v4 and v6 can be bind() in one socket).
    // Note that linux doesn't need this because it can handle v4 and v6 socket
    // when bind() with "::".

    // resolve server address
    let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();
    info!("* Connecting to {:?}...", peer_addr);
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // end of dns query
    ts_dns = std::time::Instant::now();

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
    socket.connect(peer_addr).unwrap();

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

    if no_verify {
        config.verify_peer(false);
    }

    if no_grease {
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

    send_pkt_n += 1;
    if send_loss_n == 0 || send_pkt_n != send_loss_n {
        socket.send(&out[..write]).unwrap();
    } else {
        info!("* {} send: lost packet# {}", conn.trace_id(), send_loss_n);
    }

    debug!("{} written {}", conn.trace_id(), write);

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
                Ok(v) => {
                    recv_pkt_n += 1;
                    v
                },

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
            recv_pkt_n += 1;
            if recv_loss_n == 0 || recv_pkt_n != recv_loss_n {
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
            } else {
                info!("* {} recv: lost packet# {}", conn.trace_id(), recv_loss_n);
            }
        }

        if conn.is_closed() {
            info!(
                "* {} connection closed, {:?}",
                conn.trace_id(),
                conn.stats()
            );
            break;
        }

        // Create a new HTTP/3 connection and end an HTTP request as soon as
        // the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            ts_connect = std::time::Instant::now();

            let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();

            let mut h3_conn =
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap();

            let mut path = String::from(url.path());

            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }

            let mut req = vec![
                quiche::h3::Header::new(":method", "GET"),
                quiche::h3::Header::new(":scheme", url.scheme()),
                quiche::h3::Header::new(":authority", url.host_str().unwrap()),
                quiche::h3::Header::new(":path", &path),
                quiche::h3::Header::new("user-agent", "quiche"),
            ];

            // construct additional headers
            for header in &req_headers {
                let h_parsed: Vec<&str> = header.split(": ").collect();
                // header field is lowercase
                let (h_field, h_value) =
                    (&h_parsed[0].to_lowercase().to_string(), h_parsed[1]);

                req.push(quiche::h3::Header::new(h_field, h_value));
            }

            info!("{} sending HTTP request", conn.trace_id());

            for h in &req {
                info!("{} request {}: {}", conn.trace_id(), h.name(), h.value());
            }

            if let Err(e) = h3_conn.send_request(&mut conn, &req, true) {
                error!("{} failed to send request {:?}", conn.trace_id(), e);
                break;
            }

            http3_conn = Some(h3_conn);
            ts_req = std::time::Instant::now();
        }

        if let Some(http3_conn) = &mut http3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
                        ts_resp = std::time::Instant::now();
                        info!(
                            "{} got response headers on stream id {}",
                            conn.trace_id(),
                            stream_id
                        );
                        for header in headers.iter() {
                            if header.name() == ":status" {
                                http_status = header.value().parse().unwrap();
                            }

                            writeln!(
                                header_writer,
                                "{}: {}",
                                header.name(),
                                header.value()
                            )
                            .unwrap();
                        }
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

                            body_len += read;

                            body_writer.write(&buf[..read]).unwrap();
                        }
                    },

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!(
                            "{} response received in {:?}, closing...",
                            conn.trace_id(),
                            ts_start.elapsed()
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

            send_pkt_n += 1;
            if send_loss_n == 0 || send_pkt_n != send_loss_n {
                socket.send(&out[..write]).unwrap();
            } else {
                info!("{} send: lost packet# {}", conn.trace_id(), send_loss_n);
            }

            debug!("{} written {}", conn.trace_id(), write);
        }

        if conn.is_closed() {
            info!("{} connection closed, {:?}", conn.trace_id(), conn.stats());
            break;
        }
    }

    // bytes/sec
    ts_end = std::time::Instant::now();

    if show_timing {
        let down_bw = ((body_len as f32) /
            (ts_end.duration_since(ts_req).as_millis() as f32 / 1000.0))
            as i32;
        println!("{{ \"url\": \"{}\", \"http_code\": {}, \"ts_dns\": {}, \"ts_connect\": {}, \"ts_req\": {}, \"ts_firstbyte\": {}, \"ts_total\": {}, \"body_len\": {}, \"bw_down\": {}, \"pkts_send\": {}, \"pkts_recv\": {} }}",
                 url.as_str(),
                 http_status,
                 ts_dns.duration_since(ts_start).as_millis() as f32 / 1000.0, // tdns
                 ts_connect.duration_since(ts_start).as_millis() as f32 / 1000.0, // tconnect
                 ts_req.duration_since(ts_start).as_millis() as f32 / 1000.0, // treq
                 ts_resp.duration_since(ts_start).as_millis() as f32 / 1000.0, // ttfb
                 ts_end.duration_since(ts_start).as_millis() as f32 / 1000.0, // ttotal
                 body_len,
                 down_bw,
                 send_pkt_n,
                 recv_pkt_n
        );
    }
}
