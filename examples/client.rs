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

use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1452;

const HTTP_REQ_STREAM_ID: u64 = 4;

const USAGE: &str = "Usage:
  client [options] URL
  client -h | --help

Options:
  --http1                 Send HTTP/1.1 request instead of HTTP/0.9.
  --wire-version VERSION  The version number to send to the server [default: babababa].
  --no-verify             Don't verify server's certificate.
  -h --help               Show this screen.
";

fn main() -> Result<(), Box<std::error::Error>> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::init();

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

    let mut scid = [0; LOCAL_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..])?;

    let version = args.get_str("--wire-version");
    let version = u32::from_str_radix(version, 16)?;

    let mut config = quiche::Config::new(version)?;

    config.verify_peer(true);

    config.set_application_protos(&[b"hq-18", b"http/0.9"])?;

    config.set_idle_timeout(30);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_migration(true);

    if args.get_bool("--no-verify") {
        config.verify_peer(false);
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

    let mut req_sent = false;

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
                    conn.close(false, e.to_wire(), b"fail")?;
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", conn.trace_id(), read);
        }

        if conn.is_closed() {
            info!("{} connection closed, {:?}", conn.trace_id(), conn.stats());
            break;
        }

        if conn.is_established() && !req_sent {
            info!(
                "{} sending HTTP request for {}",
                conn.trace_id(),
                url.path()
            );

            let req = if args.get_bool("--http1") {
                format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: quiche\r\n\r\n",
                    url.path(),
                    url.host().unwrap()
                )
            } else {
                format!("GET {}\r\n", url.path())
            };

            conn.stream_send(HTTP_REQ_STREAM_ID, req.as_bytes(), true)?;

            req_sent = true;
        }

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

                print!("{}", unsafe {
                    std::str::from_utf8_unchecked(&stream_buf)
                });

                if s == HTTP_REQ_STREAM_ID && fin {
                    info!("{} response received, closing...", conn.trace_id());
                    conn.close(true, 0x00, b"kthxbye")?;
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
                    conn.close(false, e.to_wire(), b"fail")?;
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
