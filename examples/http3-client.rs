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

fn main() -> Result<(), Box<std::error::Error>> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let url = url::Url::parse(args.get_str("URL"))?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&url)?;

    let poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket)?;
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )?;

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..])?;

    let max_data = args.get_str("--max-data");
    let max_data = u64::from_str_radix(max_data, 10)?;

    let max_stream_data = args.get_str("--max-stream-data");
    let max_stream_data = u64::from_str_radix(max_stream_data, 10)?;

    let version = args.get_str("--wire-version");
    let version = u32::from_str_radix(version, 16)?;

    let mut config = quiche::Config::new(version)?;

    config.verify_peer(true);

    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

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

    let mut conn = quiche::connect(url.domain(), &scid, &mut config)?;

    let write = match conn.send(&mut out) {
        Ok(v) => v,

        Err(e) => panic!("{} initial send failed: {:?}", conn.trace_id(), e),
    };

    socket.send(&out[..write])?;

    debug!("{} written {}", conn.trace_id(), write);

    let req_start = std::time::Instant::now();

    loop {
        poll.poll(&mut events, conn.timeout())?;

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
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
                    conn.close(false, e.to_wire(), b"fail").ok();
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", conn.trace_id(), read);
        }

        if conn.is_closed() {
            info!("{} connection closed, {:?}", conn.trace_id(), conn.stats());
            break;
        }

        if conn.is_established() && http3_conn.is_none() {
            let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;

            let mut h3_conn =
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;

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

                    Ok((stream_id, quiche::h3::Event::Data(data))) => {
                        debug!(
                            "{} got response data of length {} in stream id {}",
                            conn.trace_id(),
                            data.len(),
                            stream_id
                        );

                        print!("{}", unsafe {
                            std::str::from_utf8_unchecked(&data)
                        });

                        if conn.stream_finished(stream_id) {
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
                        }
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

        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done writing", conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} send failed: {:?}", conn.trace_id(), e);
                    conn.close(false, e.to_wire(), b"fail").ok();
                    break;
                },
            };

            // TODO: coalesce packets.
            socket.send(&out[..write])?;

            debug!("{} written {}", conn.trace_id(), write);
        }

        if conn.is_closed() {
            info!("{} connection closed, {:?}", conn.trace_id(), conn.stats());
            break;
        }
    }

    Ok(())
}
