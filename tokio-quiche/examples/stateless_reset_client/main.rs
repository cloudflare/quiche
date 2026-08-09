// Copyright (C) 2025, Cloudflare, Inc.
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

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_quiche::http3::driver::ClientH3Event;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::NewClientRequest;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::QuicCommand;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::socket::Socket;
use tokio_quiche::ClientH3Driver;
use tokio_quiche::ConnectionParams;

/// Client: hold an H3 connection until a stateless reset, or flood
/// unknown short-header packets to show the server's in-flight cap.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:5757")]
    connect_to: String,

    /// Complete one H3 GET, then PING until the connection drains.
    #[arg(long, default_value_t = false)]
    hold: bool,

    /// Send this many junk short-header packets and count replies.
    #[arg(long)]
    flood: Option<usize>,

    /// Bind a new local port for each flood packet (many 2-tuples).
    #[arg(long, default_value_t = false)]
    unique_ports: bool,
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();
    let args = Args::parse();
    let peer: SocketAddr = args.connect_to.parse().expect("invalid --connect-to");

    match (args.hold, args.flood) {
        (true, None) => hold(peer).await,
        (false, Some(n)) => flood(peer, n, args.unique_ports).await,
        _ => panic!("specify exactly one of --hold or --flood N"),
    }
}

async fn hold(peer: SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(peer).await.unwrap();
    let socket =
        Socket::<Arc<UdpSocket>, Arc<UdpSocket>>::from_udp(socket).unwrap();

    let mut settings = QuicSettings::default();
    settings.verify_peer = false;
    settings.max_idle_timeout = Some(Duration::from_secs(60));
    let params = ConnectionParams::new_client(settings, None, Hooks::default());
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());

    let _conn = tokio_quiche::quic::connect_with_config(
        socket,
        Some("test.com"),
        &params,
        driver,
    )
    .await
    .expect("handshake failed");

    log::info!("handshake complete; sending GET /");
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 1,
            headers: vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"test.com"),
                quiche::h3::Header::new(b":path", b"/"),
            ],
            body_writer: None,
        })
        .expect("driver gone");

    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    let ping = controller.cmd_sender();
    let receiver = controller.event_receiver_mut();

    loop {
        tokio::select! {
            ev = receiver.recv() => match ev {
                None => {
                    log::info!("connection closed");
                    break;
                },
                Some(ClientH3Event::Core(H3Event::IncomingHeaders(_))) => {
                    log::info!("got response headers. restart the server to reset.");
                },
                Some(ClientH3Event::Core(
                    H3Event::ConnectionError(_) |
                    H3Event::ConnectionShutdown(_),
                )) => {
                    log::info!("connection shutdown");
                    break;
                },
                Some(_) => {},
            },
            _ = ticks.tick() => {
                let _ = ping.send(QuicCommand::Custom(Box::new(|qconn| {
                    let _ = qconn.send_ack_eliciting();
                })));
            },
        }
    }
}

async fn flood(peer: SocketAddr, n: usize, unique_ports: bool) {
    let mut packet = [0u8; 43];
    packet[0] = 0x40;
    boring::rand::rand_bytes(&mut packet[1..21]).ok();

    let mut sockets = Vec::new();
    if unique_ports {
        for _ in 0..n {
            sockets.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
    } else {
        sockets.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }

    for (i, socket) in sockets.iter().enumerate() {
        let _ = socket.send_to(&packet, peer).await;
        if unique_ports && i + 1 < n {
            boring::rand::rand_bytes(&mut packet[1..21]).ok();
        }
    }

    let mut tasks = tokio::task::JoinSet::new();
    for socket in sockets {
        tasks.spawn(async move {
            let mut recvd = 0usize;
            let mut buf = [0u8; 64];
            while timeout(Duration::from_millis(200), socket.recv_from(&mut buf))
                .await
                .is_ok_and(|r| r.is_ok())
            {
                recvd += 1;
            }
            recvd
        });
    }

    let mut recvd = 0usize;
    while let Some(result) = tasks.join_next().await {
        recvd += result.unwrap_or(0);
    }

    println!("sent={n} recv={recvd} unique_ports={unique_ports}");
}
