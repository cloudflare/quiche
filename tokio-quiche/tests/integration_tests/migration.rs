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

use h3i::quiche;

use crate::fixtures::*;

#[tokio::test]
/// Tests that client can migrate passively.
///
/// This means that the client's address somehow changes, but the client is not
/// necessarily aware of it happening (e.g. due to NAT rebinding). This differs
/// from "active" migration because in that case the client would explicitly
/// provide a new connection ID that the server is then expected to use for the
/// new path.
///
/// The test simply binds a UDP socket on one address which is then used to
/// complete the handshake and send an initial HTTP/3 request, then uses a new
/// socket bound to a different port to send an additional HTTP/3 request, if
/// both requests complete that means that the client was successfully migrated
/// to the new address.
///
/// This requires using "plain" quiche as a client to properly control when and
/// where packets are sent to, which is not possible using h3i.
async fn test_passive_migration() {
    let mut quic_settings = QuicSettings::default();
    quic_settings.active_connection_id_limit = 2;
    quic_settings.disable_active_migration = true;
    quic_settings.disable_dcid_reuse = false;

    let hook = TestConnectionHook::new();

    let url = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        handle_connection,
    );

    let url = url::Url::parse(&url).unwrap();

    let server_addr = match url.host().unwrap() {
        url::Host::Ipv4(addr) => std::net::SocketAddr::new(
            std::net::IpAddr::V4(addr),
            url.port().unwrap(),
        ),

        _ => panic!("invalid server address"),
    };

    let mut client_config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.set_application_protos(&[b"h3"]).unwrap();
    client_config.set_initial_max_data(1500);
    client_config.set_initial_max_stream_data_bidi_local(1500);
    client_config.set_initial_max_stream_data_bidi_remote(1500);
    client_config.set_initial_max_stream_data_uni(1500);
    client_config.set_initial_max_streams_bidi(10);
    client_config.set_initial_max_streams_uni(3);
    client_config.set_disable_active_migration(true);
    client_config.verify_peer(false);

    let mut client_scid = [0; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut client_scid[..]).unwrap();
    let client_scid = quiche::ConnectionId::from_ref(&client_scid);
    let client_addr = "127.0.0.1:12345".parse().unwrap();

    let socket = tokio::net::UdpSocket::bind(client_addr).await.unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    // Handshake.
    while !conn.is_established() {
        emit_flight(&socket, &mut conn).await;

        process_flight(&socket, client_addr, &mut conn).await;
    }

    // Create a new HTTP/3 connection once the QUIC connection is established.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    // Client sends first request on the initial path.
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    h3_conn.send_request(&mut conn, &req, true).unwrap();
    emit_flight(&socket, &mut conn).await;
    process_flight(&socket, client_addr, &mut conn).await;

    assert_eq!(process_h3_events(&mut h3_conn, &mut conn), (true, true));

    // Client "migrates" to new address.
    let migrated_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let migrated_socket =
        tokio::net::UdpSocket::bind(migrated_addr).await.unwrap();

    // Client sends second request on the new address.
    //
    // Note that even though we use the `migrated_socket`, we still use the
    // original client address (`client_addr`) to simulate the fact that the
    // client doesn't know that the path changes (e.g. due to NAT rebinding).
    h3_conn.send_request(&mut conn, &req, true).unwrap();
    emit_flight(&migrated_socket, &mut conn).await;

    let stats = conn.stats();
    assert_eq!(stats.path_challenge_rx_count, 0);

    process_flight(&migrated_socket, client_addr, &mut conn).await;

    let stats = conn.stats();
    assert_eq!(stats.path_challenge_rx_count, 1);

    // Client responds to PATH_CHALLENGE.
    emit_flight(&migrated_socket, &mut conn).await;

    // Client receives response for the second request.
    process_flight(&migrated_socket, client_addr, &mut conn).await;

    assert_eq!(process_h3_events(&mut h3_conn, &mut conn), (true, true));
}

async fn emit_flight(
    socket: &tokio::net::UdpSocket, conn: &mut quiche::Connection,
) {
    let flight = match quiche::test_utils::emit_flight(conn) {
        Ok(v) => v,

        Err(quiche::Error::Done) => return,

        Err(e) => panic!("failed to emit flight: {e:?}"),
    };

    for p in flight {
        // We avoid using the `from` field here on purpose, as in case of
        // passive migration the client might be unaware that their address
        // changed.
        socket.send_to(&p.0, p.1.to).await.unwrap();
    }
}

async fn process_flight(
    socket: &tokio::net::UdpSocket, client_addr: std::net::SocketAddr,
    conn: &mut quiche::Connection,
) {
    let mut buf = [0; 65535];

    let mut did_recv = false;

    loop {
        if !did_recv {
            socket.readable().await.unwrap();
        }

        let (len, from) = match socket.try_recv_from(&mut buf) {
            Ok(v) => v,

            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,

            Err(e) => panic!("failed to receive packets: {e:?}"),
        };

        // We use an explicit `client_addr` here rather than the socket's
        // address to simulate cases where the client is not aware of its own
        // address changing during passive migration.
        let recv_info = quiche::RecvInfo {
            to: client_addr,
            from,
        };

        // Process potentially coalesced packets.
        let _ = conn.recv(&mut buf[..len], recv_info).unwrap();

        did_recv = true;
    }
}

fn process_h3_events(
    h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection,
) -> (bool, bool) {
    let mut buf = [0; 65535];

    let mut got_headers = false;

    loop {
        match h3_conn.poll(conn) {
            Ok((_, quiche::h3::Event::Headers { .. })) => got_headers = true,

            Ok((stream_id, quiche::h3::Event::Data)) => {
                // Drain stream and drop the data.
                while h3_conn.recv_body(conn, stream_id, &mut buf).is_ok() {}
            },

            Ok((_, quiche::h3::Event::Finished)) => {
                // Request is complete, return.
                return (got_headers, true);
            },

            _ => {},
        }
    }
}
