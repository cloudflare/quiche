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

use super::*;

use crate::range_buf::RangeBuf;

use rstest::rstest;

#[test]
fn transport_params() {
    // Server encodes, client decodes.
    let tp = TransportParams {
        original_destination_connection_id: None,
        max_idle_timeout: 30,
        stateless_reset_token: Some(u128::from_be_bytes([0xba; 16])),
        max_udp_payload_size: 23_421,
        initial_max_data: 424_645_563,
        initial_max_stream_data_bidi_local: 154_323_123,
        initial_max_stream_data_bidi_remote: 6_587_456,
        initial_max_stream_data_uni: 2_461_234,
        initial_max_streams_bidi: 12_231,
        initial_max_streams_uni: 18_473,
        ack_delay_exponent: 20,
        max_ack_delay: 2_u64.pow(14) - 1,
        disable_active_migration: true,
        active_conn_id_limit: 8,
        initial_source_connection_id: Some(b"woot woot".to_vec().into()),
        retry_source_connection_id: Some(b"retry".to_vec().into()),
        max_datagram_frame_size: Some(32),
        unknown_params: Default::default(),
    };

    let mut raw_params = [42; 256];
    let raw_params = TransportParams::encode(&tp, true, &mut raw_params).unwrap();
    assert_eq!(raw_params.len(), 94);

    let new_tp = TransportParams::decode(raw_params, false, None).unwrap();

    assert_eq!(new_tp, tp);

    // Client encodes, server decodes.
    let tp = TransportParams {
        original_destination_connection_id: None,
        max_idle_timeout: 30,
        stateless_reset_token: None,
        max_udp_payload_size: 23_421,
        initial_max_data: 424_645_563,
        initial_max_stream_data_bidi_local: 154_323_123,
        initial_max_stream_data_bidi_remote: 6_587_456,
        initial_max_stream_data_uni: 2_461_234,
        initial_max_streams_bidi: 12_231,
        initial_max_streams_uni: 18_473,
        ack_delay_exponent: 20,
        max_ack_delay: 2_u64.pow(14) - 1,
        disable_active_migration: true,
        active_conn_id_limit: 8,
        initial_source_connection_id: Some(b"woot woot".to_vec().into()),
        retry_source_connection_id: None,
        max_datagram_frame_size: Some(32),
        unknown_params: Default::default(),
    };

    let mut raw_params = [42; 256];
    let raw_params =
        TransportParams::encode(&tp, false, &mut raw_params).unwrap();
    assert_eq!(raw_params.len(), 69);

    let new_tp = TransportParams::decode(raw_params, true, None).unwrap();

    assert_eq!(new_tp, tp);
}

#[test]
fn transport_params_forbid_duplicates() {
    // Given an encoded param.
    let initial_source_connection_id = b"id";
    let initial_source_connection_id_raw = [
        15,
        initial_source_connection_id.len() as u8,
        initial_source_connection_id[0],
        initial_source_connection_id[1],
    ];

    // No error when decoding the param.
    let tp = TransportParams::decode(
        initial_source_connection_id_raw.as_slice(),
        true,
        None,
    )
    .unwrap();

    assert_eq!(
        tp.initial_source_connection_id,
        Some(initial_source_connection_id.to_vec().into())
    );

    // Duplicate the param.
    let mut raw_params = Vec::new();
    raw_params.append(&mut initial_source_connection_id_raw.to_vec());
    raw_params.append(&mut initial_source_connection_id_raw.to_vec());

    // Decoding fails.
    assert_eq!(
        TransportParams::decode(raw_params.as_slice(), true, None),
        Err(Error::InvalidTransportParam)
    );
}

#[test]
fn transport_params_unknown_zero_space() {
    let mut unknown_params: UnknownTransportParameters =
        UnknownTransportParameters {
            capacity: 0,
            parameters: vec![],
        };
    let massive_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 5,
        value: &[0xau8; 280],
    };
    assert!(unknown_params.push(massive_unknown_param).is_err());
    assert!(unknown_params.capacity == 0);
    assert!(unknown_params.parameters.is_empty());
}

#[test]
fn transport_params_unknown_max_space_respected() {
    let mut unknown_params: UnknownTransportParameters =
        UnknownTransportParameters {
            capacity: 256,
            parameters: vec![],
        };

    let massive_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 5,
        value: &[0xau8; 280],
    };
    let big_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 5,
        value: &[0xau8; 232],
    };
    let little_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 6,
        value: &[0xau8; 7],
    };

    assert!(unknown_params.push(massive_unknown_param).is_err());
    assert!(unknown_params.capacity == 256);
    assert!(unknown_params.parameters.is_empty());

    unknown_params.push(big_unknown_param).unwrap();
    assert!(unknown_params.capacity == 16);
    assert!(unknown_params.parameters.len() == 1);

    unknown_params.push(little_unknown_param.clone()).unwrap();
    assert!(unknown_params.capacity == 1);
    assert!(unknown_params.parameters.len() == 2);

    assert!(unknown_params.push(little_unknown_param).is_err());

    let mut unknown_params_iter = unknown_params.into_iter();

    let unknown_params_first = unknown_params_iter
        .next()
        .expect("Should have a 0th element.");
    assert!(
        unknown_params_first.id == 5 &&
            unknown_params_first.value == vec![0xau8; 232]
    );

    let unknown_params_second = unknown_params_iter
        .next()
        .expect("Should have a 1th element.");
    assert!(
        unknown_params_second.id == 6 &&
            unknown_params_second.value == vec![0xau8; 7]
    );
}

#[test]
fn transport_params_unknown_is_reserved() {
    let reserved_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 31 * 17 + 27,
        value: &[0xau8; 280],
    };
    let not_reserved_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 32 * 17 + 27,
        value: &[0xau8; 280],
    };

    assert!(reserved_unknown_param.is_reserved());
    assert!(!not_reserved_unknown_param.is_reserved());
}
#[test]
fn unknown_version() {
    let mut config = Config::new(0xbabababa).unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Err(Error::UnknownVersion));
}

#[test]
fn config_version_reserved() {
    Config::new(0xbabababa).unwrap();
    Config::new(0x1a2a3a4a).unwrap();
}

#[test]
fn config_version_invalid() {
    assert_eq!(
        Config::new(0xb1bababa).err().unwrap(),
        Error::UnknownVersion
    );
}

#[test]
fn version_negotiation() {
    let mut buf = [0; 65535];

    let mut config = Config::new(0xbabababa).unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();

    let (mut len, _) = pipe.client.send(&mut buf).unwrap();

    let hdr = Header::from_slice(&mut buf[..len], 0).unwrap();
    len = negotiate_version(&hdr.scid, &hdr.dcid, &mut buf).unwrap();

    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.version, PROTOCOL_VERSION);
    assert_eq!(pipe.server.version, PROTOCOL_VERSION);
}

#[test]
fn verify_custom_root() {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.verify_peer(true);
    config
        .load_verify_locations_from_file("examples/rootca.crt")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));
}

// Disable this for openssl as it seems to fail for some reason. It could be
// because of the way the get_certs API differs from bssl.
#[cfg(not(feature = "openssl"))]
#[test]
fn verify_client_invalid() {
    let mut server_config = Config::new(PROTOCOL_VERSION).unwrap();
    server_config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    server_config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    server_config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    server_config.set_initial_max_data(30);
    server_config.set_initial_max_stream_data_bidi_local(15);
    server_config.set_initial_max_stream_data_bidi_remote(15);
    server_config.set_initial_max_streams_bidi(3);

    // The server shouldn't be able to verify the client's certificate due
    // to missing CA.
    server_config.verify_peer(true);

    let mut client_config = Config::new(PROTOCOL_VERSION).unwrap();
    client_config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    client_config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    client_config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    client_config.set_initial_max_data(30);
    client_config.set_initial_max_stream_data_bidi_local(15);
    client_config.set_initial_max_stream_data_bidi_remote(15);
    client_config.set_initial_max_streams_bidi(3);

    // The client is able to verify the server's certificate with the
    // appropriate CA.
    client_config
        .load_verify_locations_from_file("examples/rootca.crt")
        .unwrap();
    client_config.verify_peer(true);

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )
    .unwrap();
    assert_eq!(pipe.handshake(), Err(Error::TlsFail));

    // Client did send a certificate.
    assert!(pipe.server.peer_cert().is_some());
}

#[test]
fn verify_client_anonymous() {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);

    // Try to validate client certificate.
    config.verify_peer(true);

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client didn't send a certificate.
    assert!(pipe.server.peer_cert().is_none());
}

#[rstest]
fn missing_initial_source_connection_id(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Reset initial_source_connection_id.
    pipe.client
        .local_transport_params
        .initial_source_connection_id = None;
    assert_eq!(pipe.client.encode_transport_params(), Ok(()));

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();

    // Server rejects transport parameters.
    assert_eq!(
        pipe.server_recv(&mut buf[..len]),
        Err(Error::InvalidTransportParam)
    );
}

#[rstest]
fn invalid_initial_source_connection_id(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Scramble initial_source_connection_id.
    pipe.client
        .local_transport_params
        .initial_source_connection_id = Some(b"bogus value".to_vec().into());
    assert_eq!(pipe.client.encode_transport_params(), Ok(()));

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();

    // Server rejects transport parameters.
    assert_eq!(
        pipe.server_recv(&mut buf[..len]),
        Err(Error::InvalidTransportParam)
    );
}

#[rstest]
fn change_idle_timeout(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(0x1).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_max_idle_timeout(999999);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.client.local_transport_params.max_idle_timeout, 999999);
    assert_eq!(pipe.client.peer_transport_params.max_idle_timeout, 0);
    assert_eq!(pipe.server.local_transport_params.max_idle_timeout, 0);
    assert_eq!(pipe.server.peer_transport_params.max_idle_timeout, 0);

    pipe.client.set_max_idle_timeout(456000).unwrap();
    pipe.server.set_max_idle_timeout(234000).unwrap();
    assert_eq!(pipe.client.local_transport_params.max_idle_timeout, 456000);
    assert_eq!(pipe.client.peer_transport_params.max_idle_timeout, 0);
    assert_eq!(pipe.server.local_transport_params.max_idle_timeout, 234000);
    assert_eq!(pipe.server.peer_transport_params.max_idle_timeout, 0);

    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.idle_timeout(),
        Some(Duration::from_millis(234000))
    );
    assert_eq!(
        pipe.server.idle_timeout(),
        Some(Duration::from_millis(234000))
    );
}

#[rstest]
fn handshake(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.application_proto(),
        pipe.server.application_proto()
    );

    assert_eq!(pipe.server.server_name(), Some("quic.tech"));
}

#[rstest]
fn handshake_done(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Disable session tickets on the server (SSL_OP_NO_TICKET) to avoid
    // triggering 1-RTT packet send with a CRYPTO frame.
    pipe.server.handshake.set_options(0x0000_4000);

    assert_eq!(pipe.handshake(), Ok(()));

    assert!(pipe.server.handshake_done_sent);
}

#[rstest]
fn handshake_confirmation(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Server sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    assert!(!pipe.client.is_established());
    assert!(!pipe.client.handshake_confirmed);

    assert!(!pipe.server.is_established());
    assert!(!pipe.server.handshake_confirmed);

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Client sends Handshake packet and completes handshake.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();

    assert!(pipe.client.is_established());
    assert!(!pipe.client.handshake_confirmed);

    assert!(!pipe.server.is_established());
    assert!(!pipe.server.handshake_confirmed);

    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Server completes and confirms handshake, and sends HANDSHAKE_DONE.
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    assert!(pipe.client.is_established());
    assert!(!pipe.client.handshake_confirmed);

    assert!(pipe.server.is_established());
    assert!(pipe.server.handshake_confirmed);

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Client acks 1-RTT packet, and confirms handshake.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();

    assert!(pipe.client.is_established());
    assert!(pipe.client.handshake_confirmed);

    assert!(pipe.server.is_established());
    assert!(pipe.server.handshake_confirmed);

    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert!(pipe.client.is_established());
    assert!(pipe.client.handshake_confirmed);

    assert!(pipe.server.is_established());
    assert!(pipe.server.handshake_confirmed);
}

#[rstest]
fn handshake_resumption(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    #[cfg(not(feature = "openssl"))]
    const SESSION_TICKET_KEY: [u8; 48] = [0xa; 48];

    // 80-byte key(AES 256)
    // TODO: We can set the default? or query the ticket size by calling
    // the same API(SSL_CTX_set_tlsext_ticket_keys) twice to fetch the size.
    #[cfg(feature = "openssl")]
    const SESSION_TICKET_KEY: [u8; 80] = [0xa; 80];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.set_ticket_key(&SESSION_TICKET_KEY).unwrap();

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());

    assert!(!pipe.client.is_resumed());
    assert!(!pipe.server.is_resumed());

    // Extract session,
    let session = pipe.client.session().unwrap();

    // Configure session on new connection and perform handshake.
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.set_ticket_key(&SESSION_TICKET_KEY).unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    assert_eq!(pipe.client.set_session(session), Ok(()));
    assert_eq!(pipe.handshake(), Ok(()));

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());

    assert!(pipe.client.is_resumed());
    assert!(pipe.server.is_resumed());
}

#[rstest]
fn handshake_alpn_mismatch(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto3\x06proto4"])
        .unwrap();
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Err(Error::TlsFail));

    assert_eq!(pipe.client.application_proto(), b"");
    assert_eq!(pipe.server.application_proto(), b"");

    // Server should only send one packet in response to ALPN mismatch.
    let (len, _) = pipe.server.send(&mut buf).unwrap();
    assert_eq!(len, 1200);

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
    assert_eq!(pipe.server.sent_count, 1);
}

#[cfg(not(feature = "openssl"))] // 0-RTT not supported when using openssl/quictls
#[rstest]
fn handshake_0rtt(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Extract session,
    let session = pipe.client.session().unwrap();

    // Configure session on new connection.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.client.set_session(session), Ok(()));

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Client sends 0-RTT packet.
    let pkt_type = Type::ZeroRTT;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, true),
    }];

    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Ok(1200)
    );

    assert_eq!(pipe.server.undecryptable_pkts.len(), 0);

    // 0-RTT stream data is readable.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));
    assert_eq!(&b[..5], b"aaaaa");
}

#[cfg(not(feature = "openssl"))] // 0-RTT not supported when using openssl/quictls
#[rstest]
fn handshake_0rtt_reordered(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Extract session,
    let session = pipe.client.session().unwrap();

    // Configure session on new connection.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.client.set_session(session), Ok(()));

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    let mut initial = buf[..len].to_vec();

    // Client sends 0-RTT packet.
    let pkt_type = Type::ZeroRTT;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, true),
    }];

    let len =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();
    let mut zrtt = buf[..len].to_vec();

    // 0-RTT packet is received before the Initial one.
    assert_eq!(pipe.server_recv(&mut zrtt), Ok(zrtt.len()));

    assert_eq!(pipe.server.undecryptable_pkts.len(), 1);
    assert_eq!(pipe.server.undecryptable_pkts[0].0.len(), zrtt.len());

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Initial packet is also received.
    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));

    // 0-RTT stream data is readable.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));
    assert_eq!(&b[..5], b"aaaaa");
}

#[cfg(not(feature = "openssl"))] // 0-RTT not supported when using openssl/quictls
#[rstest]
fn handshake_0rtt_truncated(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Extract session,
    let session = pipe.client.session().unwrap();

    // Configure session on new connection.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.client.set_session(session), Ok(()));

    // Client sends initial flight.
    pipe.client.send(&mut buf).unwrap();

    // Client sends 0-RTT packet.
    let pkt_type = Type::ZeroRTT;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, true),
    }];

    let len =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    // Simulate a truncated packet by sending one byte less.
    let mut zrtt = buf[..len - 1].to_vec();

    // 0-RTT packet is received before the Initial one.
    assert_eq!(pipe.server_recv(&mut zrtt), Err(Error::InvalidPacket));

    assert_eq!(pipe.server.undecryptable_pkts.len(), 0);

    assert!(pipe.server.is_closed());
}

#[rstest]
fn crypto_limit(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client send a 1-byte frame that starts from the crypto stream offset
    // limit.
    let frames = [frame::Frame::Crypto {
        data: RangeBuf::from(b"a", MAX_CRYPTO_STREAM_OFFSET, false),
    }];

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    let active_path = pipe.server.paths.get_active().unwrap();
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };

    assert_eq!(
        pipe.server.recv(&mut buf[..written], info),
        Err(Error::CryptoBufferExceeded)
    );

    let written = match pipe.server.send(&mut buf) {
        Ok((write, _)) => write,

        Err(_) => unreachable!(),
    };

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..written]).unwrap();
    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ConnectionClose {
            error_code: 0x0d,
            frame_type: 0,
            reason: Vec::new(),
        })
    );
}

#[rstest]
fn limit_handshake_data(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert-big.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    let client_sent = flight.iter().fold(0, |out, p| out + p.0.len());
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    let server_sent = flight.iter().fold(0, |out, p| out + p.0.len());

    assert_eq!(server_sent, client_sent * MAX_AMPLIFICATION_FACTOR);
}

#[rstest]
fn custom_limit_handshake_data(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    const CUSTOM_AMPLIFICATION_FACTOR: usize = 2;

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert-big.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_max_amplification_factor(CUSTOM_AMPLIFICATION_FACTOR);

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    let client_sent = flight.iter().fold(0, |out, p| out + p.0.len());
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    let server_sent = flight.iter().fold(0, |out, p| out + p.0.len());

    assert_eq!(server_sent, client_sent * CUSTOM_AMPLIFICATION_FACTOR);
}

#[rstest]
fn streamio(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((12, true)));
    assert_eq!(&b[..12], b"hello, world");

    assert!(pipe.server.stream_finished(4));
}

#[cfg(not(feature = "openssl"))] // 0-RTT not supported when using openssl/quictls
#[rstest]
fn zero_rtt(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Extract session,
    let session = pipe.client.session().unwrap();

    // Configure session on new connection.
    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.client.set_session(session), Ok(()));

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    let mut initial = buf[..len].to_vec();

    assert!(pipe.client.is_in_early_data());

    // Client sends 0-RTT data.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));

    let (len, _) = pipe.client.send(&mut buf).unwrap();
    let mut zrtt = buf[..len].to_vec();

    // Server receives packets.
    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));
    assert!(pipe.server.is_in_early_data());

    assert_eq!(pipe.server_recv(&mut zrtt), Ok(zrtt.len()));

    // 0-RTT stream data is readable.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((12, true)));
    assert_eq!(&b[..12], b"hello, world");
}

#[rstest]
fn stream_send_on_32bit_arch(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(2_u64.pow(32) + 5);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // In 32bit arch, send_capacity() should be min(2^32+5, cwnd),
    // not min(5, cwnd)
    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));

    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));
}

#[rstest]
fn empty_stream_frame(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, false),
    }];

    let pkt_type = Type::Short;
    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

    let mut readable = pipe.server.readable();
    assert_eq!(readable.next(), Some(4));

    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((5, false)));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"", 5, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

    let mut readable = pipe.server.readable();
    assert_eq!(readable.next(), Some(4));

    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((0, true)));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"", 15, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FinalSize)
    );
}

#[rstest]
fn update_key_request(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends message with key update request.
    assert_eq!(pipe.client_update_key(), Ok(()));
    assert_eq!(pipe.client.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Ensure server updates key and it correctly decrypts the message.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, false)));
    assert_eq!(&b[..5], b"hello");

    // Ensure ACK for key update.
    assert!(
        pipe.server.crypto_ctx[packet::Epoch::Application]
            .key_update
            .as_ref()
            .unwrap()
            .update_acked
    );

    // Server sends message with the new key.
    assert_eq!(pipe.server.stream_send(4, b"world", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Ensure update key is completed and client can decrypt packet.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);
    assert_eq!(pipe.client.stream_recv(4, &mut b), Ok((5, false)));
    assert_eq!(&b[..5], b"world");

    // Server keeps sending packets to ensure encryption still works.
    for _ in 0..10 {
        assert_eq!(pipe.server.stream_send(4, b"world", false), Ok(5));
        assert_eq!(pipe.advance(), Ok(()));

        let mut r = pipe.client.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);
        assert_eq!(pipe.client.stream_recv(4, &mut b), Ok((5, false)));
        assert_eq!(&b[..5], b"world");
    }
}

#[rstest]
fn update_key_request_twice_error(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"hello", 0, false),
    }];

    // Client sends stream frame with key update request.
    assert_eq!(pipe.client_update_key(), Ok(()));
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)
            .unwrap();

    // Server correctly decode with new key.
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // Client sends stream frame with another key update request before server
    // ACK.
    assert_eq!(pipe.client_update_key(), Ok(()));
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)
            .unwrap();

    // Check server correctly closes the connection with a key update error
    // for the peer.
    assert_eq!(pipe.server_recv(&mut buf[..written]), Err(Error::KeyUpdate));
}

#[rstest]
/// Tests that receiving a MAX_STREAM_DATA frame for a receive-only
/// unidirectional stream is forbidden.
fn max_stream_data_receive_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens unidirectional stream.
    assert_eq!(pipe.client.stream_send(2, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends MAX_STREAM_DATA on local unidirectional stream.
    let frames = [frame::Frame::MaxStreamData {
        stream_id: 2,
        max: 1024,
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidStreamState(2)),
    );
}

#[rstest]
fn empty_payload(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Send a packet with no frames.
    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &[], &mut buf),
        Err(Error::InvalidPacket)
    );
}

#[rstest]
fn min_payload(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Send a non-ack-eliciting packet.
    let frames = [frame::Frame::Padding { len: 4 }];

    let pkt_type = Type::Initial;
    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    let initial_path = pipe
        .server
        .paths
        .get_active()
        .expect("initial path not found");

    assert_eq!(initial_path.max_send_bytes, 195);

    // Force server to send a single PING frame.
    pipe.server
        .paths
        .get_active_mut()
        .expect("no active path")
        .recovery
        .inc_loss_probes(packet::Epoch::Initial);

    let initial_path = pipe
        .server
        .paths
        .get_active_mut()
        .expect("initial path not found");

    // Artificially limit the amount of bytes the server can send.
    initial_path.max_send_bytes = 60;

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
}

#[rstest]
fn flow_control_limit(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
}

#[rstest]
fn flow_control_limit_dup(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        // One byte less than stream limit.
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaa", 0, false),
        },
        // Same stream, but one byte more.
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());
}

#[rstest]
fn flow_control_update(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;

    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    pipe.server.stream_recv(0, &mut buf).unwrap();
    pipe.server.stream_recv(4, &mut buf).unwrap();

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"a", 1, false),
    }];

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    assert!(len > 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
    let mut iter = frames.iter();

    // Ignore ACK.
    iter.next().unwrap();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::MaxStreamData {
            stream_id: 0,
            max: 30
        })
    );
    assert_eq!(iter.next(), Some(&frame::Frame::MaxData { max: 61 }));
}

#[rstest]
/// Tests that flow control is properly updated even when a stream is shut
/// down.
fn flow_control_drain(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65536];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    // Set large initial max_data so we don't have to deal with MAX_DATA
    // or STREAM_MAX_DATA frames
    config.set_initial_max_data(15_000);
    config.set_initial_max_stream_data_bidi_local(15_000);
    config.set_initial_max_stream_data_bidi_remote(15_000);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.set_ack_delay_exponent(8);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens a stream and sends some data.
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    // And also sends on a different stream
    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(8, b"aaaaa", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives data, without reading it.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), Some(8));
    assert_eq!(r.next(), None);

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 20);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Helper function that sends STREAM frames to the server on stream 4
    let mut send_frame_helper =
        |pipe: &mut test_utils::Pipe, data: RangeBuf| -> Result<()> {
            let frames = [frame::Frame::Stream { stream_id: 4, data }];
            let written = test_utils::encode_pkt(
                &mut pipe.client,
                Type::Short,
                &frames,
                &mut buf,
            )?;
            assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
            Ok(())
        };

    // Client sends more data on stream 4, but with a gap.
    // server now has [0..5] and [10..15]
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 5], 10, false)).unwrap();

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Server shuts down one stream. We do not advance the pipe
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    // check flow control accounting
    // 15 bytes have been consumed, since that was the highest offset we have
    // received.
    assert_eq!(pipe.server.flow_control.consumed(), 15);
    assert_eq!(pipe.server.rx_data, 30);

    // client sends frame that partially closes the gap
    // now we have [0..8] and [10..15]
    // verify flow control. Should be no change.
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 3], 5, false)).unwrap();
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 15);

    // client sends partially overlapping data and partially new data
    // now we have [0..8] and [10..20]
    // verify flow control. we should account for an additional 5 bytes
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 10], 10, false)).unwrap();
    assert_eq!(pipe.server.rx_data, 35);
    assert_eq!(pipe.server.flow_control.consumed(), 20);

    // client sends a fin, but again with a gap
    // this should add another 5 bytes to flow control
    send_frame_helper(&mut pipe, RangeBuf::from(&[0; 0], 25, true)).unwrap();
    assert_eq!(pipe.server.rx_data, 40);
    assert_eq!(pipe.server.flow_control.consumed(), 25);
}

#[rstest]
/// Tests that flow control is properly updated when a stream receives a RESET
fn flow_control_reset_stream(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values("reset", "fin")] inconsistent_final_size_frame: &str,
) {
    let mut buf = [0; 65536];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    // Set large initial max_data so we don't have to deal with MAX_DATA
    // or STREAM_MAX_DATA frames
    config.set_initial_max_data(15_000);
    config.set_initial_max_stream_data_bidi_local(15_000);
    config.set_initial_max_stream_data_bidi_remote(15_000);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.set_ack_delay_exponent(8);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens a stream and sends some data.
    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives data, without reading it.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 5);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Helper function that sends STREAM frames to the server on stream 0
    let send_frame_helper =
        |pipe: &mut test_utils::Pipe, data: RangeBuf| -> Result<()> {
            let mut buf = [0; 65536];
            let frames = [frame::Frame::Stream { stream_id: 0, data }];
            let written = test_utils::encode_pkt(
                &mut pipe.client,
                Type::Short,
                &frames,
                &mut buf,
            )?;
            assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
            Ok(())
        };

    // Client sends more data on stream 4, but with a gap.
    // server now has [0..5] and [10..15]
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 5], 10, false)).unwrap();

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 15);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Client sends a RESET_STREAM with final size 20
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        final_size: 20,
        error_code: 42,
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)
            .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // check flow control accounting
    // 20 bytes have been consumed, since that was the final_size
    assert_eq!(pipe.server.flow_control.consumed(), 20);
    assert_eq!(pipe.server.rx_data, 20);

    // client sends more frames, some overlap, some new data
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 3], 5, false)).unwrap();
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 7], 10, false)).unwrap();
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 3], 5, false)).unwrap();

    // no change in flow control
    assert_eq!(pipe.server.flow_control.consumed(), 20);
    assert_eq!(pipe.server.rx_data, 20);

    // Send the RESET again. Nothing happens
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        final_size: 20,
        error_code: 42,
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)
            .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // no change in flow control
    assert_eq!(pipe.server.flow_control.consumed(), 20);
    assert_eq!(pipe.server.rx_data, 20);

    if inconsistent_final_size_frame == "reset" {
        // send another reset with inconsistent final size
        // Send the RESET again. Nothing happens
        let frames = [frame::Frame::ResetStream {
            stream_id: 0,
            final_size: 42,
            error_code: 42,
        }];
        let written = test_utils::encode_pkt(
            &mut pipe.client,
            Type::Short,
            &frames,
            &mut buf,
        )
        .unwrap();
        assert_eq!(pipe.server_recv(&mut buf[..written]), Err(Error::FinalSize));
    } else if inconsistent_final_size_frame == "fin" {
        let frames = [frame::Frame::Stream {
            stream_id: 0,
            data: RangeBuf::from(&[], 42, true),
        }];
        let written = test_utils::encode_pkt(
            &mut pipe.client,
            Type::Short,
            &frames,
            &mut buf,
        )
        .unwrap();
        assert_eq!(pipe.server_recv(&mut buf[..written]), Err(Error::FinalSize));
    } else {
        panic!(
            "didn't expect inconsistent_final_size_frame to be `{}`",
            inconsistent_final_size_frame
        );
    }
}

#[rstest]
fn stream_flow_control_limit_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaaaaaaaaaaaaa", 0, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
}

#[rstest]
fn stream_flow_control_limit_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 2,
        data: <RangeBuf>::from(b"aaaaaaaaaaa", 0, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
}

#[rstest]
fn stream_flow_control_update(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaaaaaa", 0, false),
    }];

    let pkt_type = Type::Short;

    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    pipe.server.stream_recv(4, &mut buf).unwrap();

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"a", 9, false),
    }];

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    assert!(len > 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
    let mut iter = frames.iter();

    // Ignore ACK.
    iter.next().unwrap();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::MaxStreamData {
            stream_id: 4,
            max: 24,
        })
    );
}

#[rstest]
fn stream_left_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(3, pipe.client.peer_streams_left_bidi());
    assert_eq!(3, pipe.server.peer_streams_left_bidi());

    pipe.server.stream_send(1, b"a", false).ok();
    assert_eq!(2, pipe.server.peer_streams_left_bidi());
    pipe.server.stream_send(5, b"a", false).ok();
    assert_eq!(1, pipe.server.peer_streams_left_bidi());

    pipe.server.stream_send(9, b"a", false).ok();
    assert_eq!(0, pipe.server.peer_streams_left_bidi());

    let frames = [frame::Frame::MaxStreamsBidi { max: MAX_STREAM_ID }];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    assert_eq!(MAX_STREAM_ID - 3, pipe.server.peer_streams_left_bidi());
}

#[rstest]
fn stream_left_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(3, pipe.client.peer_streams_left_uni());
    assert_eq!(3, pipe.server.peer_streams_left_uni());

    pipe.server.stream_send(3, b"a", false).ok();
    assert_eq!(2, pipe.server.peer_streams_left_uni());
    pipe.server.stream_send(7, b"a", false).ok();
    assert_eq!(1, pipe.server.peer_streams_left_uni());

    pipe.server.stream_send(11, b"a", false).ok();
    assert_eq!(0, pipe.server.peer_streams_left_uni());

    let frames = [frame::Frame::MaxStreamsUni { max: MAX_STREAM_ID }];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    assert_eq!(MAX_STREAM_ID - 3, pipe.server.peer_streams_left_uni());
}

#[rstest]
fn stream_limit_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 12,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 16,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 20,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 24,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 28,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::StreamLimit),
    );
}

#[rstest]
fn stream_limit_max_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::MaxStreamsBidi { max: MAX_STREAM_ID }];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    let frames = [frame::Frame::MaxStreamsBidi {
        max: MAX_STREAM_ID + 1,
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidFrame),
    );
}

#[rstest]
fn stream_limit_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 2,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 6,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 10,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 14,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 18,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 22,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 26,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::StreamLimit),
    );
}

#[rstest]
fn stream_limit_max_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::MaxStreamsUni { max: MAX_STREAM_ID }];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    let frames = [frame::Frame::MaxStreamsUni {
        max: MAX_STREAM_ID + 1,
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidFrame),
    );
}

#[rstest]
fn stream_left_reset_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(3, pipe.client.peer_streams_left_bidi());
    assert_eq!(3, pipe.server.peer_streams_left_bidi());

    pipe.client.stream_send(0, b"a", false).ok();
    assert_eq!(2, pipe.client.peer_streams_left_bidi());
    pipe.client.stream_send(4, b"a", false).ok();
    assert_eq!(1, pipe.client.peer_streams_left_bidi());
    pipe.client.stream_send(8, b"a", false).ok();
    assert_eq!(0, pipe.client.peer_streams_left_bidi());

    // Client resets the stream.
    pipe.client
        .stream_shutdown(0, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    assert_eq!(0, pipe.client.peer_streams_left_bidi());
    let mut r = pipe.server.readable();
    assert_eq!(Some(0), r.next());
    assert_eq!(Some(4), r.next());
    assert_eq!(Some(8), r.next());
    assert_eq!(None, r.next());

    assert_eq!(
        pipe.server.stream_recv(0, &mut buf),
        Err(Error::StreamReset(1001))
    );

    let mut r = pipe.server.readable();
    assert_eq!(Some(4), r.next());
    assert_eq!(Some(8), r.next());
    assert_eq!(None, r.next());

    // Server resets the stream in reaction.
    pipe.server
        .stream_shutdown(0, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    assert_eq!(1, pipe.client.peer_streams_left_bidi());

    // Repeat for the other 2 streams
    pipe.client
        .stream_shutdown(4, Shutdown::Write, 1001)
        .unwrap();
    pipe.client
        .stream_shutdown(8, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    let mut r = pipe.server.readable();
    assert_eq!(Some(4), r.next());
    assert_eq!(Some(8), r.next());
    assert_eq!(None, r.next());

    assert_eq!(
        pipe.server.stream_recv(4, &mut buf),
        Err(Error::StreamReset(1001))
    );

    assert_eq!(
        pipe.server.stream_recv(8, &mut buf),
        Err(Error::StreamReset(1001))
    );

    let mut r = pipe.server.readable();
    assert_eq!(None, r.next());

    pipe.server
        .stream_shutdown(4, Shutdown::Write, 1001)
        .unwrap();
    pipe.server
        .stream_shutdown(8, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    assert_eq!(3, pipe.client.peer_streams_left_bidi());
}

#[rstest]
fn stream_reset_counts(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    pipe.client.stream_send(0, b"a", false).ok();
    pipe.client.stream_send(2, b"a", false).ok();
    pipe.client.stream_send(4, b"a", false).ok();
    pipe.client.stream_send(8, b"a", false).ok();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 0);

    // Client resets the stream.
    pipe.client
        .stream_shutdown(0, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 0);
    let stats = pipe.server.stats();
    assert_eq!(stats.reset_stream_count_local, 0);
    assert_eq!(stats.reset_stream_count_remote, 1);

    // Server resets the stream in reaction.
    pipe.server
        .stream_shutdown(0, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 1);
    let stats = pipe.server.stats();
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 1);

    // Repeat for the other streams
    pipe.client
        .stream_shutdown(2, Shutdown::Write, 1001)
        .unwrap();
    pipe.client
        .stream_shutdown(4, Shutdown::Write, 1001)
        .unwrap();
    pipe.client
        .stream_shutdown(8, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    pipe.server
        .stream_shutdown(4, Shutdown::Write, 1001)
        .unwrap();
    pipe.server
        .stream_shutdown(8, Shutdown::Write, 1001)
        .unwrap();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 4);
    assert_eq!(stats.reset_stream_count_remote, 3);
    let stats = pipe.server.stats();
    assert_eq!(stats.reset_stream_count_local, 3);
    assert_eq!(stats.reset_stream_count_remote, 4);
}

#[rstest]
fn stream_stop_counts(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    pipe.client.stream_send(0, b"a", false).ok();
    pipe.client.stream_send(2, b"a", false).ok();
    pipe.client.stream_send(4, b"a", false).ok();
    pipe.client.stream_send(8, b"a", false).ok();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 0);

    // Server stops the stream and client automatically resets.
    pipe.server
        .stream_shutdown(0, Shutdown::Read, 1001)
        .unwrap();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.stopped_stream_count_local, 0);
    assert_eq!(stats.stopped_stream_count_remote, 1);
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 0);

    let stats = pipe.server.stats();
    assert_eq!(stats.stopped_stream_count_local, 1);
    assert_eq!(stats.stopped_stream_count_remote, 0);
    assert_eq!(stats.reset_stream_count_local, 0);
    assert_eq!(stats.reset_stream_count_remote, 1);

    // Repeat for the other streams
    pipe.server
        .stream_shutdown(2, Shutdown::Read, 1001)
        .unwrap();
    pipe.server
        .stream_shutdown(4, Shutdown::Read, 1001)
        .unwrap();
    pipe.server
        .stream_shutdown(8, Shutdown::Read, 1001)
        .unwrap();
    pipe.advance().unwrap();

    let stats = pipe.client.stats();
    assert_eq!(stats.stopped_stream_count_local, 0);
    assert_eq!(stats.stopped_stream_count_remote, 4);
    assert_eq!(stats.reset_stream_count_local, 4);
    assert_eq!(stats.reset_stream_count_remote, 0);

    let stats = pipe.server.stats();
    assert_eq!(stats.stopped_stream_count_local, 4);
    assert_eq!(stats.stopped_stream_count_remote, 0);
    assert_eq!(stats.reset_stream_count_local, 0);
    assert_eq!(stats.reset_stream_count_remote, 4);
}

#[rstest]
fn streams_blocked_max_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::StreamsBlockedBidi {
        limit: MAX_STREAM_ID,
    }];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    let frames = [frame::Frame::StreamsBlockedBidi {
        limit: MAX_STREAM_ID + 1,
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidFrame),
    );
}

#[rstest]
fn streams_blocked_max_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::StreamsBlockedUni {
        limit: MAX_STREAM_ID,
    }];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    let frames = [frame::Frame::StreamsBlockedUni {
        limit: MAX_STREAM_ID + 1,
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidFrame),
    );
}

#[rstest]
fn stream_data_overlap(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"bbbbb", 3, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"ccccc", 6, false),
        },
    ];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((11, false)));
    assert_eq!(&b[..11], b"aaaaabbbccc");
    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);
}

#[rstest]
fn stream_data_overlap_with_reordering(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"ccccc", 6, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"bbbbb", 3, false),
        },
    ];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((11, false)));
    assert_eq!(&b[..11], b"aaaaabccccc");
    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);
}

#[rstest]
/// Tests that receiving a valid RESET_STREAM frame when all data has
/// already been read, notifies the application.
fn reset_stream_data_recvd(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(0, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data and sends data back, closing stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, false)));
    assert!(!pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.stream_recv(0, &mut b), Ok((0, true)));
    assert!(pipe.client.stream_finished(0));

    // Client sends RESET_STREAM, closing stream.
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        error_code: 42,
        final_size: 5,
    }];

    let pkt_type = Type::Short;
    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

    // Server is notified of stream readability, due to reset.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_recv(0, &mut b),
        Err(Error::StreamReset(42))
    );

    assert!(pipe.server.stream_finished(0));

    // Sending RESET_STREAM again shouldn't make stream readable again.
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);
    assert_eq!(pipe.server.flow_control.consumed(), 5);
}

#[rstest]
/// Tests that receiving a valid RESET_STREAM frame when all data has _not_
/// been read, discards all buffered data and notifies the application.
fn reset_stream_data_not_recvd(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(0, b"h", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data and sends data back, closing stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((1, false)));
    assert!(!pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.stream_recv(0, &mut b), Ok((0, true)));
    assert!(pipe.client.stream_finished(0));

    // Client sends RESET_STREAM, closing stream.
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        error_code: 42,
        final_size: 5,
    }];

    let pkt_type = Type::Short;
    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

    // Server is notified of stream readability, due to reset.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_recv(0, &mut b),
        Err(Error::StreamReset(42))
    );

    assert!(pipe.server.stream_finished(0));

    // Sending RESET_STREAM again shouldn't make stream readable again.
    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);
    assert_eq!(pipe.server.flow_control.consumed(), 5);
}

#[rstest]
/// Tests that RESET_STREAM frames exceeding the connection-level flow
/// control limit cause an error.
fn reset_stream_flow_control(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(&[1; 15], 0, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 0,
            final_size: 15,
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
}

#[rstest]
/// Tests that RESET_STREAM frames exceeding the stream-level flow control
/// limit cause an error.
fn reset_stream_flow_control_stream(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 0,
            final_size: 16, // Past stream's flow control limit.
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
}

#[rstest]
fn path_challenge(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::PathChallenge { data: [0xba; 8] }];

    let pkt_type = Type::Short;

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    assert!(len > 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
    let mut iter = frames.iter();

    // Ignore ACK.
    iter.next().unwrap();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::PathResponse { data: [0xba; 8] })
    );
}

#[cfg(not(feature = "openssl"))] // 0-RTT not supported when using openssl/quictls
#[rstest]
/// Simulates reception of an early 1-RTT packet on the server, by
/// delaying the client's Handshake packet that completes the handshake.
fn early_1rtt_packet(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends initial flight
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Server sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Client sends Handshake packet.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();

    // Emulate handshake packet delay by not making server process client
    // packet.
    let delayed = flight;

    test_utils::emit_flight(&mut pipe.server).ok();

    assert!(pipe.client.is_established());

    // Send 1-RTT packet #0.
    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"hello, world", 0, true),
    }];

    let pkt_type = Type::Short;
    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // Send 1-RTT packet #1.
    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"hello, world", 0, true),
    }];

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    assert!(!pipe.server.is_established());

    // Client sent 1-RTT packets 0 and 1, but server hasn't received them.
    //
    // Note that `largest_rx_pkt_num` is initialized to 0, so we need to
    // send another 1-RTT packet to make this check meaningful.
    assert_eq!(
        pipe.server.pkt_num_spaces[packet::Epoch::Application].largest_rx_pkt_num,
        0
    );

    // Process delayed packet.
    test_utils::process_flight(&mut pipe.server, delayed).unwrap();

    assert!(pipe.server.is_established());

    assert_eq!(
        pipe.server.pkt_num_spaces[packet::Epoch::Application].largest_rx_pkt_num,
        0
    );
}

#[rstest]
fn stop_sending(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data, and closes stream.
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends data, until blocked.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    while pipe.server.stream_send(0, b"world", false) != Err(Error::Done) {
        assert_eq!(pipe.advance(), Ok(()));
    }

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server sent a RESET_STREAM frame in response.
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 15,
        })
    );

    // Stream is writable, but writing returns an error.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"world", true),
        Err(Error::StreamStopped(42)),
    );

    // Returning `StreamStopped` causes the stream to be collected.
    assert_eq!(pipe.server.streams.len(), 0);

    // Client acks RESET_STREAM frame.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(pipe.server.next_pkt_num - 5..pipe.server.next_pkt_num);

    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));

    // Sending STOP_SENDING again shouldn't trigger RESET_STREAM again.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(frames.len(), 1);

    match frames.first() {
        Some(frame::Frame::ACK { .. }) => (),

        f => panic!("expected ACK frame, got {f:?}"),
    };

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);
}

#[rstest]
fn stop_sending_fin(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data, and closes stream.
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(4));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends data...
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(4, b"world", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // ...and buffers more, and closes stream.
    assert_eq!(pipe.server.stream_send(4, b"world", true), Ok(5));

    // Client sends STOP_SENDING before server flushes stream.
    let frames = [frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server sent a RESET_STREAM frame in response.
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 42,
            final_size: 5,
        })
    );

    // No more frames are sent by the server.
    assert_eq!(iter.next(), None);
}

#[rstest]
/// Tests that resetting a stream restores flow control for unsent data.
fn stop_sending_unsent_tx_cap(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(15);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));

    // Server sends some data.
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server buffers some data, until send capacity limit reached.
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(
        pipe.server.stream_send(4, b"hello", false),
        Err(Error::Done)
    );

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server can now send more data (on a different stream).
    assert_eq!(pipe.client.stream_send(8, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(8, b"hello", false), Ok(5));
    assert_eq!(pipe.server.stream_send(8, b"hello", false), Ok(5));
    assert_eq!(
        pipe.server.stream_send(8, b"hello", false),
        Err(Error::Done)
    );
    assert_eq!(pipe.advance(), Ok(()));
}

#[rstest]
/// Tests that the `StreamStopped` error is propagated even if the RESET_STREAM
/// in response to STOP_SENDING is acked before the application processes
/// writable streams.
fn stop_sending_ack_race(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data, and closes stream.
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends data, until blocked.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    while pipe.server.stream_send(0, b"world", false) != Err(Error::Done) {
        assert_eq!(pipe.advance(), Ok(()));
    }

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server sent a RESET_STREAM frame in response.
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 15,
        })
    );

    // Client acks RESET_STREAM frame *before* server calls `writable()`.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(pipe.server.next_pkt_num - 5..pipe.server.next_pkt_num);

    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));

    assert_eq!(pipe.server.streams.len(), 1);

    // Stream is writable, but writing returns an error.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"world", true),
        Err(Error::StreamStopped(42)),
    );

    // Stream is collected on the server after `StreamStopped` is returned.
    assert_eq!(pipe.server.streams.len(), 0);

    // Sending STOP_SENDING again shouldn't trigger RESET_STREAM again.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(frames.len(), 1);

    match frames.first() {
        Some(frame::Frame::ACK { .. }) => (),

        f => panic!("expected ACK frame, got {f:?}"),
    };

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);
}

#[rstest]
/// Tests that the `StreamStopped` error is propagated even if a STREAM frame
/// is acked before the application processes writable streams.
fn stop_sending_stream_ack_race(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data, and closes stream.
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends data and finishes the stream.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"world", true), Ok(5));

    // Client receives STREAM frame but doesn't ack yet.
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server sent a RESET_STREAM frame in response.
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 5,
        })
    );

    // Client acks RESET_STREAM and STREAM frames *before* server calls
    // `writable()`.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(pipe.server.next_pkt_num - 5..pipe.server.next_pkt_num);

    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));

    assert_eq!(pipe.server.streams.len(), 1);

    // Stream is writable, but writing returns an error.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"world", true),
        Err(Error::StreamStopped(42)),
    );

    // Stream is collected on the server after `StreamStopped` is returned.
    assert_eq!(pipe.server.streams.len(), 0);

    // Sending STOP_SENDING again shouldn't trigger RESET_STREAM again.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(frames.len(), 1);

    match frames.first() {
        Some(frame::Frame::ACK { .. }) => (),

        f => panic!("expected ACK frame, got {f:?}"),
    };

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);
}

#[rstest]
fn stream_shutdown_read(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", false), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let mut dummy = buf[..len].to_vec();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut dummy[..len]).unwrap();
    // make sure the pkt contains the expected StopSending frame
    assert!(frames.iter().any(|f| {
        *f == frame::Frame::StopSending {
            stream_id: 4,
            error_code: 42,
        }
    }));

    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.advance(), Ok(()));

    // Sending more data is forbidden.
    let mut r = pipe.client.writable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.client.stream_send(4, b"bye", false),
        Err(Error::StreamStopped(42))
    );

    // Server sends some data, without reading the incoming data, and closes
    // the stream.
    assert_eq!(pipe.server.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    // Client reads the data.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((12, true)));

    // Stream is collected on both sides.
    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);
    assert_eq!(pipe.client.flow_control.consumed(), pipe.client.rx_data);
    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);

    assert_eq!(
        pipe.server.stream_shutdown(4, Shutdown::Read, 0),
        Err(Error::Done)
    );
}

#[rstest]
fn stream_shutdown_read_after_fin(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data and a FIN.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends a flow control update, but it does NOT send
    // STOP_SENDING frame, since it has already received a FIN from
    // the client.
    let (len, _) = pipe.server.send(&mut buf).unwrap();
    let mut dummy = buf[..len].to_vec();
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut dummy[..len]).unwrap();
    for f in frames {
        assert!(!matches!(f, frame::Frame::StopSending { .. }));
    }
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.advance(), Ok(()));

    // Server sends some data, without reading the incoming data, and closes
    // the stream.
    assert_eq!(pipe.server.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    // Client reads the data.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((12, true)));

    // Stream is collected on both sides.
    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);
    assert_eq!(pipe.client.flow_control.consumed(), pipe.client.rx_data);
    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);

    assert_eq!(
        pipe.server.stream_shutdown(4, Shutdown::Read, 0),
        Err(Error::Done)
    );
}

#[rstest]
fn stream_shutdown_read_update_max_data(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(10000);
    config.set_initial_max_stream_data_bidi_remote(10000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((1, false)));

    // Client sends data that the server does not read before it shuts down
    // the read direction
    assert_eq!(pipe.client.stream_send(0, &buf[0..20], false), Ok(20));
    assert_eq!(pipe.advance(), Ok(()));

    // Server has received 21 bytes, but only 1 have been read/consumed
    assert_eq!(pipe.server.rx_data, 21);
    assert_eq!(pipe.server.flow_control.consumed(), 1);

    assert_eq!(pipe.client.stream_send(0, &buf, false), Ok(9));
    // Connection level flow control limit reached
    assert_eq!(pipe.client.stream_send(0, &[0], false), Err(Error::Done));
    assert_eq!(pipe.client.stream_send(4, &[0], false), Err(Error::Done));

    // Shutting down the read side, returns buffered data to flow control budget
    // (but we are *not advancing* the pipe yet, so client limit is not increased)
    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Read, 123), Ok(()));

    assert!(!pipe.server.stream_readable(0)); // nothing can be consumed

    assert_eq!(pipe.server.rx_data, 21);
    // all bytes in the read buffer have been marked as consumed
    assert_eq!(pipe.server.flow_control.consumed(), 21);
    assert_eq!(pipe.client.tx_data, 30);
    assert_eq!(pipe.client.max_tx_data, 30);

    // Client is still blocked
    assert_eq!(pipe.client.stream_send(0, &[0], false), Err(Error::Done));
    assert_eq!(pipe.client.stream_send(4, &[0], false), Err(Error::Done));

    // Send a flight of packet from server -> client. We only send in this
    // direction so ensure that the server sends a MAX_DATA frame on its own,
    // if we advance the pipe, the client would respond with RESET and that
    // would increase the window
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // The client has dropped the 9 unset bytes in its buffer
    assert_eq!(pipe.client.tx_data, 21);
    assert_eq!(pipe.server.rx_data, 21);
    assert_eq!(pipe.server.flow_control.consumed(), 21);
    // default window is 1.5 * initial_max_data, so 45
    assert_eq!(
        pipe.client.tx_cap,
        pipe.server.flow_control.window() as usize
    );
    assert_eq!(pipe.client.tx_cap, 45);

    assert_eq!(
        pipe.client.stream_send(0, b"hello, world", false),
        Err(Error::StreamStopped(123))
    );

    // fully advance pipe
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.tx_data, 21);
    assert_eq!(pipe.server.rx_data, 21);
    assert!(!pipe.server.stream_readable(0)); // nothing can be consumed

    // Server sends fin to fully close the stream.
    assert_eq!(pipe.server.stream_send(0, &[], true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.stream_recv(0, &mut buf), Ok((0, true)));

    assert!(pipe.server.streams.is_collected(0));
    assert!(pipe.client.streams.is_collected(0));
}

/// Tests that sending a reset should drop the receive buffer on the peer and
/// return flow control credit.
#[rstest]
fn stream_shutdown_write_update_max_data(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(10000);
    config.set_initial_max_stream_data_bidi_remote(10000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((1, false)));

    // Client sends data until blocked that the server does not read
    while pipe.client.stream_send(0, b"world", false) != Err(Error::Done) {
        assert_eq!(pipe.advance(), Ok(()));
    }
    // sending on a different stream is blocked by flow control
    assert_eq!(pipe.client.stream_send(4, b"a", false), Err(Error::Done));
    assert_eq!(pipe.client.max_tx_data, 30);
    assert_eq!(pipe.client.tx_data, 30);

    // Server has received 30 bytes, but only 1 has been read/consumed
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 1);

    // The client shuts down its write and sends a reset
    assert_eq!(pipe.client.stream_shutdown(0, Shutdown::Write, 42), Ok(()));
    pipe.advance().unwrap();

    // Receiving the reset drops the receive buffer and returns flow control
    // credit
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 30);
    assert_eq!(pipe.client.tx_data, 30);
    // default window is 1.5 * initial_max_data, so 45
    assert_eq!(pipe.client.tx_cap, 45);

    // client can send again on a different stream
    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
}

#[rstest]
fn stream_shutdown_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Exchange some data on uni streams.
    assert_eq!(pipe.client.stream_send(2, b"hello, world", false), Ok(10));
    assert_eq!(pipe.server.stream_send(3, b"hello, world", false), Ok(10));
    assert_eq!(pipe.advance(), Ok(()));

    // Test local and remote shutdown.
    assert_eq!(pipe.client.stream_shutdown(2, Shutdown::Write, 42), Ok(()));
    assert_eq!(
        pipe.client.stream_shutdown(2, Shutdown::Read, 42),
        Err(Error::InvalidStreamState(2))
    );

    assert_eq!(
        pipe.client.stream_shutdown(3, Shutdown::Write, 42),
        Err(Error::InvalidStreamState(3))
    );
    assert_eq!(pipe.client.stream_shutdown(3, Shutdown::Read, 42), Ok(()));
}

#[rstest]
fn stream_shutdown_write(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", false), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    // Server sends some data.
    assert_eq!(pipe.server.stream_send(4, b"goodbye, world", false), Ok(14));
    assert_eq!(pipe.advance(), Ok(()));

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 42), Ok(()));

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);

    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let mut dummy = buf[..len].to_vec();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut dummy[..len]).unwrap();
    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 42,
            final_size: 14,
        })
    );

    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.advance(), Ok(()));

    // Sending more data is forbidden.
    assert_eq!(
        pipe.server.stream_send(4, b"bye", false),
        Err(Error::FinalSize)
    );

    // Client sends some data and closes the stream.
    assert_eq!(pipe.client.stream_send(4, b"bye", true), Ok(3));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads the data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((15, true)));

    // Client processes readable streams.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.client.stream_recv(4, &mut buf),
        Err(Error::StreamReset(42))
    );

    // Stream is collected on both sides.
    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);

    assert_eq!(
        pipe.server.stream_shutdown(4, Shutdown::Write, 0),
        Err(Error::Done)
    );
}

#[rstest]
/// Tests that shutting down a stream restores flow control for unsent data.
fn stream_shutdown_write_unsent_tx_cap(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(15);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));

    // Server sends some data.
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server buffers some data, until send capacity limit reached.
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(
        pipe.server.stream_send(4, b"hello", false),
        Err(Error::Done)
    );
    assert_eq!(pipe.server.tx_data, 15);

    // Client shouldn't update flow control.
    assert!(!pipe.client.should_update_max_data());

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 42), Ok(()));
    // Unsend data is dropped and returned to flow control credit
    assert_eq!(pipe.server.tx_data, 5);

    // Server can now send more data (on a different stream).
    assert_eq!(pipe.client.stream_send(8, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(8, b"hello", false), Ok(5));
    assert_eq!(pipe.server.stream_send(8, b"hello", false), Ok(5));
    assert_eq!(
        pipe.server.stream_send(8, b"hello", false),
        Err(Error::Done)
    );
    assert_eq!(pipe.advance(), Ok(()));
}

#[rstest]
/// Tests that the order of flushable streams scheduled on the wire is the
/// same as the order of `stream_send()` calls done by the application.
fn stream_round_robin(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        })
    );

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        })
    );

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        })
    );
}

#[rstest]
/// Tests the readable iterator.
fn stream_readable(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // No readable streams.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    // Server received stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    // Client drains stream.
    let mut b = [0; 15];
    pipe.client.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);

    // Server shuts down stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Read, 0), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Client creates multiple streams.
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.len(), 2);

    assert!(r.next().is_some());
    assert!(r.next().is_some());
    assert!(r.next().is_none());

    assert_eq!(r.len(), 0);
}

#[rstest]
/// Tests the writable iterator.
fn stream_writable(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // No writable streams.
    let mut w = pipe.client.writable();
    assert_eq!(w.next(), None);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));

    // Client created stream.
    let mut w = pipe.client.writable();
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    // Server created stream.
    let mut w = pipe.server.writable();
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );

    // Server stream is full.
    let mut w = pipe.server.writable();
    assert_eq!(w.next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    // Client drains stream.
    let mut b = [0; 15];
    pipe.client.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server stream is writable again.
    let mut w = pipe.server.writable();
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), None);

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Write, 0), Ok(()));

    let mut w = pipe.server.writable();
    assert_eq!(w.next(), None);

    // Client creates multiple streams.
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 2);

    assert!(w.next().is_some());
    assert!(w.next().is_some());
    assert!(w.next().is_none());

    assert_eq!(w.len(), 0);

    // Server finishes stream.
    assert_eq!(pipe.server.stream_send(8, b"aaaaa", true), Ok(5));

    let mut w = pipe.server.writable();
    assert_eq!(w.next(), Some(4));
    assert_eq!(w.next(), None);
}

#[rstest]
fn stream_writable_blocked(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_initial_max_data(70);
    config.set_initial_max_stream_data_bidi_local(150000);
    config.set_initial_max_stream_data_bidi_remote(150000);
    config.set_initial_max_stream_data_uni(150000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client creates stream and sends some data.
    let send_buf = [0; 35];
    assert_eq!(pipe.client.stream_send(0, &send_buf, false), Ok(35));

    // Stream is still writable as it still has capacity.
    assert_eq!(pipe.client.stream_writable_next(), Some(0));
    assert_eq!(pipe.client.stream_writable_next(), None);

    // Client fills stream, which becomes unwritable due to connection
    // capacity.
    let send_buf = [0; 36];
    assert_eq!(pipe.client.stream_send(0, &send_buf, false), Ok(35));

    assert_eq!(pipe.client.stream_writable_next(), None);

    assert_eq!(pipe.client.tx_cap, 0);

    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 70];
    pipe.server.stream_recv(0, &mut b).unwrap();

    assert_eq!(pipe.advance(), Ok(()));

    // The connection capacity has increased and the stream is now writable
    // again.
    assert_ne!(pipe.client.tx_cap, 0);

    assert_eq!(pipe.client.stream_writable_next(), Some(0));
    assert_eq!(pipe.client.stream_writable_next(), None);
}

#[rstest]
/// Tests that we don't exceed the per-connection flow control limit set by
/// the peer.
fn flow_control_limit_send(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.stream_send(4, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.stream_send(8, b"a", false), Err(Error::Done));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert!(r.next().is_some());
    assert!(r.next().is_some());
    assert!(r.next().is_none());

    assert_eq!(pipe.server.data_blocked_sent_count, 0);
    assert_eq!(pipe.server.stream_data_blocked_sent_count, 0);
    assert_eq!(pipe.server.data_blocked_recv_count, 1);
    assert_eq!(pipe.server.stream_data_blocked_recv_count, 0);

    assert_eq!(pipe.client.data_blocked_sent_count, 1);
    assert_eq!(pipe.client.stream_data_blocked_sent_count, 0);
    assert_eq!(pipe.client.data_blocked_recv_count, 0);
    assert_eq!(pipe.client.stream_data_blocked_recv_count, 0);
}

#[rstest]
/// Tests that invalid packets received before any other valid ones cause
/// the server to close the connection immediately.
fn invalid_initial_server(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    let frames = [frame::Frame::Padding { len: 10 }];

    let written = test_utils::encode_pkt(
        &mut pipe.client,
        Type::Initial,
        &frames,
        &mut buf,
    )
    .unwrap();

    // Corrupt the packets's last byte to make decryption fail (the last
    // byte is part of the AEAD tag, so changing it means that the packet
    // cannot be authenticated during decryption).
    buf[written - 1] = !buf[written - 1];

    assert_eq!(pipe.server.timeout(), None);

    assert_eq!(
        pipe.server_recv(&mut buf[..written]),
        Err(Error::CryptoFail)
    );

    assert!(pipe.server.is_closed());
}

#[rstest]
/// Tests that invalid Initial packets received to cause
/// the client to close the connection immediately.
fn invalid_initial_client(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();

    // Server sends initial flight.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(1200));

    let frames = [frame::Frame::Padding { len: 10 }];

    let written = test_utils::encode_pkt(
        &mut pipe.server,
        Type::Initial,
        &frames,
        &mut buf,
    )
    .unwrap();

    // Corrupt the packets's last byte to make decryption fail (the last
    // byte is part of the AEAD tag, so changing it means that the packet
    // cannot be authenticated during decryption).
    buf[written - 1] = !buf[written - 1];

    // Client will ignore invalid packet.
    assert_eq!(pipe.client_recv(&mut buf[..written]), Ok(71));

    // The connection should be alive...
    assert!(!pipe.client.is_closed());

    // ...and the idle timeout should be armed.
    assert!(pipe.client.idle_timer.is_some());
}

#[rstest]
/// Tests that packets with invalid payload length received before any other
/// valid packet cause the server to close the connection immediately.
fn invalid_initial_payload(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    let mut b = octets::OctetsMut::with_slice(&mut buf);

    let epoch = Type::Initial.to_epoch().unwrap();

    let pn = 0;
    let pn_len = packet::pkt_num_len(pn, 0);

    let dcid = pipe.client.destination_id();
    let scid = pipe.client.source_id();

    let hdr = Header {
        ty: Type::Initial,
        version: pipe.client.version,
        dcid: ConnectionId::from_ref(&dcid),
        scid: ConnectionId::from_ref(&scid),
        pkt_num: 0,
        pkt_num_len: pn_len,
        token: pipe.client.token.clone(),
        versions: None,
        key_phase: false,
    };

    hdr.to_bytes(&mut b).unwrap();

    // Payload length is invalid!!!
    let payload_len = 4096;

    let len = pn_len + payload_len;
    b.put_varint(len as u64).unwrap();

    packet::encode_pkt_num(pn, pn_len, &mut b).unwrap();

    let payload_offset = b.off();

    let frames = [frame::Frame::Padding { len: 10 }];

    for frame in &frames {
        frame.to_bytes(&mut b).unwrap();
    }

    let crypto_ctx = &mut pipe.client.crypto_ctx[epoch];

    // Use correct payload length when encrypting the packet.
    let payload_len = frames.iter().fold(0, |acc, x| acc + x.wire_len());

    let aead = crypto_ctx.crypto_seal.as_ref().unwrap();

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )
    .unwrap();

    assert_eq!(pipe.server.timeout(), None);

    assert_eq!(
        pipe.server_recv(&mut buf[..written]),
        Err(Error::InvalidPacket)
    );

    assert!(pipe.server.is_closed());
}

#[rstest]
/// Tests that invalid packets don't cause the connection to be closed.
fn invalid_packet(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Padding { len: 10 }];

    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)
            .unwrap();

    // Corrupt the packets's last byte to make decryption fail (the last
    // byte is part of the AEAD tag, so changing it means that the packet
    // cannot be authenticated during decryption).
    buf[written - 1] = !buf[written - 1];

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // Corrupt the packets's first byte to make the header fail decoding.
    buf[0] = 255;

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
}

#[rstest]
fn recv_empty_buffer(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server_recv(&mut buf[..0]), Err(Error::BufferTooShort));
}

#[rstest]
fn stop_sending_before_flushed_packets(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data, and closes stream.
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends data, until blocked.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    while pipe.server.stream_send(0, b"world", false) != Err(Error::Done) {}

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server sent a RESET_STREAM frame in response.
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 0,
        })
    );

    // Stream is writable, but writing returns an error.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"world", true),
        Err(Error::StreamStopped(42)),
    );

    // Returning `StreamStopped` causes the stream to be collected.
    assert_eq!(pipe.server.streams.len(), 0);

    // Client acks RESET_STREAM frame.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..6);

    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));
}

#[rstest]
fn reset_before_flushed_packets(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(5);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data, and closes stream.
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server sends data and is blocked by small stream flow control.
    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"helloworld", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Client reads to give flow control back.
    assert_eq!(pipe.client.stream_recv(0, &mut b), Ok((5, false)));
    assert_eq!(pipe.advance(), Ok(()));

    // Server writes stream data and resets the stream before sending a
    // packet.
    assert_eq!(pipe.server.stream_send(0, b"world", false), Ok(5));
    pipe.server.stream_shutdown(0, Shutdown::Write, 42).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Client has ACK'd the RESET_STREAM so the stream is collected.
    assert_eq!(pipe.server.streams.len(), 0);

    assert_eq!(pipe.server.data_blocked_sent_count, 0);
    assert_eq!(pipe.server.stream_data_blocked_sent_count, 1);
    assert_eq!(pipe.server.data_blocked_recv_count, 0);
    assert_eq!(pipe.server.stream_data_blocked_recv_count, 0);

    assert_eq!(pipe.client.data_blocked_sent_count, 0);
    assert_eq!(pipe.client.stream_data_blocked_sent_count, 0);
    assert_eq!(pipe.client.data_blocked_recv_count, 0);
    assert_eq!(pipe.client.stream_data_blocked_recv_count, 1);
}

#[rstest]
/// Tests that the MAX_STREAMS frame is sent for bidirectional streams.
fn stream_limit_update_bidi(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    pipe.server.stream_recv(4, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data, with fin.
    assert_eq!(pipe.server.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(4, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(4, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(0, b"b", true), Ok(1));

    // Server sends MAX_STREAMS.
    assert_eq!(pipe.advance(), Ok(()));

    // Client tries to create new streams.
    assert_eq!(pipe.client.stream_send(8, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(12, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(16, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(20, b"a", false),
        Err(Error::StreamLimit)
    );

    assert_eq!(pipe.server.readable().len(), 3);
}

#[rstest]
/// Tests that the MAX_STREAMS frame is sent for unidirectional streams.
fn stream_limit_update_uni(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(0);
    config.set_initial_max_streams_uni(3);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(2, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(6, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(6, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(2, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(2, &mut b).unwrap();
    pipe.server.stream_recv(6, &mut b).unwrap();

    // Server sends MAX_STREAMS.
    assert_eq!(pipe.advance(), Ok(()));

    // Client tries to create new streams.
    assert_eq!(pipe.client.stream_send(10, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(14, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(18, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(22, b"a", false),
        Err(Error::StreamLimit)
    );

    assert_eq!(pipe.server.readable().len(), 3);
}

#[rstest]
/// Tests that the stream's fin flag is properly flushed even if there's no
/// data in the buffer, and that the buffer becomes readable on the other
/// side.
fn stream_zero_length_fin(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame.
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should be readable on the server after receiving empty fin.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame (again).
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should _not_ be readable on the server after receiving empty
    // fin, because it was already finished.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);
}

#[rstest]
/// Tests that the stream's fin flag is properly flushed even if there's no
/// data in the buffer, that the buffer becomes readable on the other
/// side and stays readable even if the stream is fin'd locally.
fn stream_zero_length_fin_deferred_collection(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame.
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends zero-length frame.
    assert_eq!(pipe.server.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should be readable on the server after receiving empty fin.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame (again).
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should _not_ be readable on the server after receiving empty
    // fin, because it was already finished.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Stream _is_readable on the client side.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));

    pipe.client.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Stream is completed and _is not_ readable.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);
}

#[rstest]
/// Tests that the stream gets created with stream_send() even if there's
/// no data in the buffer and the fin flag is not set.
fn stream_zero_length_non_fin(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"", false), Ok(0));

    // The stream now should have been created.
    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.advance(), Ok(()));

    // Sending an empty non-fin should not change any stream state on the
    // other side.
    let mut r = pipe.server.readable();
    assert!(r.next().is_none());
}

#[rstest]
/// Tests that completed streams are garbage collected.
fn collect_streams(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.stream_finished(0));
    assert!(!pipe.server.stream_finished(0));

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    let mut b = [0; 5];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(0, b"aaaaa", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.stream_finished(0));
    assert!(pipe.server.stream_finished(0));

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 0);

    let mut b = [0; 5];
    pipe.client.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);

    assert!(pipe.client.stream_finished(0));
    assert!(pipe.server.stream_finished(0));

    assert_eq!(pipe.client.stream_send(0, b"", true), Err(Error::Done));

    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"aa", 0, false),
    }];

    let pkt_type = Type::Short;
    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));
}

#[test]
fn config_set_cc_algorithm_name() {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();

    assert_eq!(config.set_cc_algorithm_name("reno"), Ok(()));

    // Unknown name.
    assert_eq!(
        config.set_cc_algorithm_name("???"),
        Err(Error::CongestionControl)
    );
}

#[rstest]
fn peer_cert(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    match pipe.client.peer_cert() {
        Some(c) => assert_eq!(c.len(), 753),

        None => panic!("missing server certificate"),
    }
}

#[rstest]
fn peer_cert_chain(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert-big.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    match pipe.client.peer_cert_chain() {
        Some(c) => assert_eq!(c.len(), 5),

        None => panic!("missing server certificate chain"),
    }
}

#[rstest]
fn retry(#[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    // Client sends initial flight.
    let (mut len, _) = pipe.client.send(&mut buf).unwrap();

    // Server sends Retry packet.
    let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();

    let odcid = hdr.dcid.clone();

    let mut scid = [0; MAX_CONN_ID_LEN];
    rand::rand_bytes(&mut scid[..]);
    let scid = ConnectionId::from_ref(&scid);

    let token = b"quiche test retry token";

    len =
        packet::retry(&hdr.scid, &hdr.dcid, &scid, token, hdr.version, &mut buf)
            .unwrap();

    // Client receives Retry and sends new Initial.
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    let (len, send_info) = pipe.client.send(&mut buf).unwrap();

    let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();
    assert_eq!(&hdr.token.unwrap(), token);

    // Server accepts connection.
    pipe.server = accept(
        &scid,
        Some(&odcid),
        test_utils::Pipe::server_addr(),
        send_info.from,
        &mut config,
    )
    .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.advance(), Ok(()));

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());
}

#[rstest]
fn retry_with_pto(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    // Client sends initial flight.
    let (mut len, _) = pipe.client.send(&mut buf).unwrap();

    // Server sends Retry packet.
    let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();

    let odcid = hdr.dcid.clone();

    let mut scid = [0; MAX_CONN_ID_LEN];
    rand::rand_bytes(&mut scid[..]);
    let scid = ConnectionId::from_ref(&scid);

    let token = b"quiche test retry token";

    len =
        packet::retry(&hdr.scid, &hdr.dcid, &scid, token, hdr.version, &mut buf)
            .unwrap();

    // Client receives Retry and sends new Initial.
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    let (len, send_info) = pipe.client.send(&mut buf).unwrap();

    let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();
    assert_eq!(&hdr.token.unwrap(), token);

    // Server accepts connection.
    pipe.server = accept(
        &scid,
        Some(&odcid),
        test_utils::Pipe::server_addr(),
        send_info.from,
        &mut config,
    )
    .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Wait for the client's PTO so it will try to send an Initial again.
    let timer = pipe.client.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));
    pipe.client.on_timeout();

    assert_eq!(pipe.advance(), Ok(()));

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());
}

#[rstest]
fn missing_retry_source_connection_id(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    // Client sends initial flight.
    let (mut len, _) = pipe.client.send(&mut buf).unwrap();

    // Server sends Retry packet.
    let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();

    let mut scid = [0; MAX_CONN_ID_LEN];
    rand::rand_bytes(&mut scid[..]);
    let scid = ConnectionId::from_ref(&scid);

    let token = b"quiche test retry token";

    len =
        packet::retry(&hdr.scid, &hdr.dcid, &scid, token, hdr.version, &mut buf)
            .unwrap();

    // Client receives Retry and sends new Initial.
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    // Server accepts connection and send first flight. But original
    // destination connection ID is ignored.
    let from = "127.0.0.1:1234".parse().unwrap();
    pipe.server = accept(
        &scid,
        None,
        test_utils::Pipe::server_addr(),
        from,
        &mut config,
    )
    .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    assert_eq!(
        test_utils::process_flight(&mut pipe.client, flight),
        Err(Error::InvalidTransportParam)
    );
}

#[rstest]
fn invalid_retry_source_connection_id(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    // Client sends initial flight.
    let (mut len, _) = pipe.client.send(&mut buf).unwrap();

    // Server sends Retry packet.
    let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();

    let mut scid = [0; MAX_CONN_ID_LEN];
    rand::rand_bytes(&mut scid[..]);
    let scid = ConnectionId::from_ref(&scid);

    let token = b"quiche test retry token";

    len =
        packet::retry(&hdr.scid, &hdr.dcid, &scid, token, hdr.version, &mut buf)
            .unwrap();

    // Client receives Retry and sends new Initial.
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    // Server accepts connection and send first flight. But original
    // destination connection ID is invalid.
    let from = "127.0.0.1:1234".parse().unwrap();
    let odcid = ConnectionId::from_ref(b"bogus value");
    pipe.server = accept(
        &scid,
        Some(&odcid),
        test_utils::Pipe::server_addr(),
        from,
        &mut config,
    )
    .unwrap();
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    assert_eq!(
        test_utils::process_flight(&mut pipe.client, flight),
        Err(Error::InvalidTransportParam)
    );
}

#[rstest]
/// Tests that a zero-length NEW_TOKEN frame is detected as an error.
fn zero_length_new_token(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = vec![frame::Frame::NewToken { token: vec![] }];

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.server, pkt_type, &frames, &mut buf)
            .unwrap();

    assert_eq!(
        pipe.client_recv(&mut buf[..written]),
        Err(Error::InvalidFrame)
    );
}

#[rstest]
/// Tests that a NEW_TOKEN frame sent by client is detected as an error.
fn client_sent_new_token(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = vec![frame::Frame::NewToken {
        token: vec![1, 2, 3],
    }];

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    assert_eq!(
        pipe.server_recv(&mut buf[..written]),
        Err(Error::InvalidPacket)
    );
}

fn check_send(_: &mut impl Send) {}

#[rstest]
fn config_must_be_send(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    check_send(&mut config);
}

#[rstest]
fn connection_must_be_send(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    check_send(&mut pipe.client);
}

fn check_sync(_: &mut impl Sync) {}

#[rstest]
fn config_must_be_sync(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    check_sync(&mut config);
}

#[rstest]
fn connection_must_be_sync(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    check_sync(&mut pipe.client);
}

#[rstest]
fn data_blocked(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"aaaaaaaaaa", false), Ok(10));
    assert_eq!(pipe.client.blocked_limit, None);
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"aaaaaaaaaa", false), Ok(10));
    assert_eq!(pipe.client.blocked_limit, None);
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaaaaaaaa", false), Ok(10));
    assert_eq!(pipe.client.blocked_limit, Some(30));

    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(pipe.client.blocked_limit, None);

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    assert_eq!(iter.next(), Some(&frame::Frame::DataBlocked { limit: 30 }));

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"aaaaaaaaaa", 0, false),
        })
    );

    assert_eq!(iter.next(), None);
}

#[rstest]
fn stream_data_blocked(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaaa", false), Ok(5));
    assert_eq!(pipe.client.streams.blocked().len(), 1);

    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::StreamDataBlocked {
            stream_id: 0,
            limit: 15,
        })
    );

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        })
    );

    assert_eq!(iter.next(), None);

    // Send from another stream, make sure we don't send STREAM_DATA_BLOCKED
    // again.
    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));

    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        })
    );

    assert_eq!(iter.next(), None);

    // Send again from blocked stream and make sure it is not marked as
    // blocked again.
    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaa", false),
        Err(Error::Done)
    );
    assert_eq!(pipe.client.streams.blocked().len(), 0);
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));
}

#[rstest]
fn stream_data_blocked_unblocked_flow_control(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaah", false),
        Ok(15)
    );
    assert_eq!(pipe.client.streams.blocked().len(), 1);
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    // Send again on blocked stream. It's blocked at the same offset as
    // previously, so it should not be marked as blocked again.
    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    // No matter how many times we try to write stream data tried, no
    // packets containing STREAM_BLOCKED should be emitted.
    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    // Now read some data at the server to release flow control.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    let mut b = [0; 10];
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((10, false)));
    assert_eq!(&b[..10], b"aaaaaaaaaa");
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"hhhhhhhhhh!", false), Ok(10));
    assert_eq!(pipe.client.streams.blocked().len(), 1);

    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::StreamDataBlocked {
            stream_id: 0,
            limit: 25,
        })
    );

    // don't care about remaining received frames

    assert_eq!(pipe.client.stream_send(0, b"!", false), Err(Error::Done));
    assert_eq!(pipe.client.streams.blocked().len(), 0);
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));
}

#[rstest]
fn app_limited_true(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data smaller than cwnd.
    let send_buf = [0; 10000];
    assert_eq!(pipe.server.stream_send(0, &send_buf, false), Ok(10000));
    assert_eq!(pipe.advance(), Ok(()));

    // app_limited should be true because we send less than cwnd.
    assert!(pipe
        .server
        .paths
        .get_active()
        .expect("no active")
        .recovery
        .app_limited());
}

#[rstest]
fn app_limited_false(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf1 = [0; 20000];
    assert_eq!(pipe.server.stream_send(0, &send_buf1, false), Ok(12000));

    test_utils::emit_flight(&mut pipe.server).ok();

    // We can't create a new packet header because there is no room by cwnd.
    // app_limited should be false because we can't send more by cwnd.
    assert!(!pipe
        .server
        .paths
        .get_active()
        .expect("no active")
        .recovery
        .app_limited());
}

#[test]
fn tx_cap_factor() {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(12000);
    config.set_initial_max_stream_data_bidi_remote(12000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    config.set_send_capacity_factor(2.0);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.client.stream_send(4, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 50000];

    // Server reads stream data.
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf = [0; 50000];
    assert_eq!(pipe.server.stream_send(0, &send_buf, false), Ok(12000));
    assert_eq!(pipe.server.stream_send(4, &send_buf, false), Ok(12000));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(pipe.client.stream_recv(0, &mut b), Ok((12000, false)));

    assert_eq!(r.next(), Some(4));
    assert_eq!(pipe.client.stream_recv(4, &mut b), Ok((12000, false)));

    assert_eq!(r.next(), None);
}

#[rstest]
fn client_rst_stream_while_bytes_in_flight(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] use_stop_sending: bool,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(120000);
    config.set_initial_max_stream_data_bidi_remote(120000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    // Send FIN if we want to exercise the case of the client sending
    // STOP_SENDING instead of RESET_STREAM.
    assert_eq!(pipe.client.stream_send(4, b"a", use_stop_sending), Ok(1));
    assert_eq!(pipe.client.stream_send(8, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 50000];

    // Server reads stream data.
    pipe.server.stream_recv(0, &mut b).unwrap();
    pipe.server.stream_recv(4, &mut b).unwrap();
    pipe.server.stream_recv(8, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf = [0; 50000];
    assert_eq!(
        pipe.server.stream_send(4, &send_buf, false),
        if cc_algorithm_name == "cubic" {
            Ok(12000)
        } else if cfg!(feature = "openssl") {
            Ok(13964)
        } else {
            Ok(13878)
        }
    );
    let server_flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    // And generate a stop sending or reset at the client.
    assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Read, 42), Ok(()));
    if !use_stop_sending {
        // Client did not send a FIN on stream 4, shutdown both sides to send a
        // RESET_STREAM.
        assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Write, 42), Ok(()));
    }
    let client_flight = test_utils::emit_flight(&mut pipe.client).unwrap();

    test_utils::process_flight(&mut pipe.server, client_flight).unwrap();
    test_utils::process_flight(&mut pipe.client, server_flight).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // tx_buffered goes down to 0 after the reset and acks are
    // processed.  A full cwnd's worth of packets can be sent.
    let expected_cwnd = match cc_algorithm_name {
        "bbr2" | "bbr2_gcongestion" =>
            if cfg!(feature = "openssl") {
                27928
            } else {
                27756
            },
        _ => 24000,
    };

    assert_eq!(pipe.server.tx_buffered, 0);
    assert_eq!(
        pipe.server.stream_send(8, &send_buf, false),
        Ok(expected_cwnd)
    );
    assert_eq!(pipe.server.tx_buffered, expected_cwnd);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .cwnd(),
        expected_cwnd
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.tx_buffered_state, TxBufferTrackingState::Ok);
}

#[rstest]
fn client_rst_stream_while_bytes_in_flight_with_packet_loss(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(120000);
    config.set_initial_max_stream_data_bidi_remote(120000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.client.stream_send(4, b"a", true), Ok(1));
    assert_eq!(pipe.client.stream_send(8, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 50000];

    // Server reads stream data.
    pipe.server.stream_recv(0, &mut b).unwrap();
    pipe.server.stream_recv(4, &mut b).unwrap();
    pipe.server.stream_recv(8, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf = [0; 50000];
    assert_eq!(
        pipe.server.stream_send(4, &send_buf, false),
        if cc_algorithm_name == "cubic" {
            Ok(12000)
        } else if cfg!(feature = "openssl") {
            Ok(13964)
        } else {
            Ok(13878)
        }
    );
    let mut server_flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    // And generate a STOP_SENDING at the client.
    assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Read, 42), Ok(()));
    let client_flight = test_utils::emit_flight(&mut pipe.client).unwrap();

    // Lose the first packet of the server flight.
    server_flight.remove(0);

    test_utils::process_flight(&mut pipe.server, client_flight).unwrap();
    test_utils::process_flight(&mut pipe.client, server_flight).unwrap();

    assert_eq!(pipe.advance(), Ok(()));

    // tx_buffered goes down to 0 after the reset and acks are
    // processed.  A full cwnd's worth of packets can be sent.
    let expected_cwnd = match cc_algorithm_name {
        "bbr2" | "bbr2_gcongestion" =>
            if cfg!(feature = "openssl") {
                26728
            } else {
                26556
            },
        _ => 8400,
    };

    assert_eq!(pipe.server.tx_buffered, 0);

    let send_result = pipe.server.stream_send(8, &send_buf, false).unwrap();
    if cc_algorithm_name != "cubic" {
        assert_eq!(send_result, expected_cwnd);
    } else {
        // cubic adjusts the congestion window downwards due to the
        // lost packet.  The exact send size varies.
        assert!((15000..17000).contains(&send_result));
    }
    assert_eq!(pipe.server.tx_buffered, send_result);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .cwnd(),
        expected_cwnd
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.tx_buffered_state, TxBufferTrackingState::Ok);
}

#[rstest]
fn sends_ack_only_pkt_when_full_cwnd_and_ack_elicited(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data bigger than cwnd (it will never arrive to the
    // server).
    let send_buf1 = [0; 20000];
    assert_eq!(
        pipe.client.stream_send(0, &send_buf1, false),
        if cc_algorithm_name == "cubic" {
            Ok(12000)
        } else if cfg!(feature = "openssl") {
            Ok(12345)
        } else {
            Ok(12299)
        }
    );

    test_utils::emit_flight(&mut pipe.client).ok();

    // Server sends some stream data that will need ACKs.
    assert_eq!(
        pipe.server.stream_send(1, &send_buf1[..500], false),
        Ok(500)
    );

    test_utils::process_flight(
        &mut pipe.client,
        test_utils::emit_flight(&mut pipe.server).unwrap(),
    )
    .unwrap();

    let mut buf = [0; 2000];

    let ret = pipe.client.send(&mut buf);

    assert_eq!(pipe.client.tx_cap, 0);

    assert!(matches!(ret, Ok((_, _))), "the client should at least send one packet to acknowledge the newly received data");

    let (sent, _) = ret.unwrap();

    assert_ne!(sent, 0, "the client should at least send a pure ACK packet");

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..sent]).unwrap();
    assert_eq!(1, frames.len());
    assert!(
        matches!(frames[0], frame::Frame::ACK { .. }),
        "the packet sent by the client must be an ACK only packet"
    );
}

/// Like sends_ack_only_pkt_when_full_cwnd_and_ack_elicited, but when
/// ack_eliciting is explicitly requested.
#[rstest]
fn sends_ack_only_pkt_when_full_cwnd_and_ack_elicited_despite_max_unacknowledging(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data bigger than cwnd (it will never arrive to the
    // server). This exhausts the congestion window.
    let send_buf1 = [0; 20000];
    assert_eq!(
        pipe.client.stream_send(0, &send_buf1, false),
        if cc_algorithm_name == "cubic" {
            Ok(12000)
        } else if cfg!(feature = "openssl") {
            Ok(12345)
        } else {
            Ok(12299)
        }
    );

    test_utils::emit_flight(&mut pipe.client).ok();

    // Client gets PING frames from server, which elicit ACK
    let mut buf = [0; 2000];
    for _ in 0..recovery::MAX_OUTSTANDING_NON_ACK_ELICITING {
        let written = test_utils::encode_pkt(
            &mut pipe.server,
            Type::Short,
            &[frame::Frame::Ping { mtu_probe: None }],
            &mut buf,
        )
        .unwrap();

        pipe.client_recv(&mut buf[..written])
            .expect("client recv ping");

        // Client acknowledges despite a full congestion window
        let ret = pipe.client.send(&mut buf);

        assert!(matches!(ret, Ok((_, _))), "the client should at least send one packet to acknowledge the newly received data");

        let (sent, _) = ret.unwrap();

        assert_ne!(sent, 0, "the client should at least send a pure ACK packet");

        let frames =
            test_utils::decode_pkt(&mut pipe.server, &mut buf[..sent]).unwrap();

        assert_eq!(1, frames.len());

        assert!(
            matches!(frames[0], frame::Frame::ACK { .. }),
            "the packet sent by the client must be an ACK only packet"
        );
    }

    // The client shouldn't need to send any more packets after the ACK only
    // packet it just sent.
    assert_eq!(
        pipe.client.send(&mut buf),
        Err(Error::Done),
        "nothing for client to send after ACK-only packet"
    );
}

#[rstest]
fn validate_peer_sent_ack_range(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm_name(cc_algorithm_name).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(10);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    pipe.handshake().unwrap();

    let mut buf = [0; 2000];
    let epoch = packet::Epoch::Application;
    let pkt_type = Type::Short;

    // Elicit client to send an ACK to the server
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let expected_max_active_pkt_sent = 3;
    let recovery = &pipe.server.paths.get_active().unwrap().recovery;
    assert_eq!(
        recovery.largest_sent_pkt_num_on_path(epoch).unwrap(),
        expected_max_active_pkt_sent
    );
    assert_eq!(recovery.get_largest_acked_on_epoch(epoch).unwrap(), 3);
    assert_eq!(recovery.sent_packets_len(epoch), 0);
    // Verify largest sent on the connection
    assert_eq!(
        pipe.server.pkt_num_spaces[epoch]
            .largest_tx_pkt_num
            .unwrap(),
        expected_max_active_pkt_sent
    );

    // Elicit server to send a packet(ACK) by sending it a packet first. This
    // will result in Server sent packets that require an ACK
    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"aa", 0, false),
    }];
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();
    let recovery = &pipe.server.paths.get_active().unwrap().recovery;
    assert_eq!(recovery.largest_sent_pkt_num_on_path(epoch).unwrap(), 4);
    assert_eq!(recovery.get_largest_acked_on_epoch(epoch).unwrap(), 3);
    assert_eq!(recovery.sent_packets_len(epoch), 1);

    // Send an invalid ACK range to the server and expect server error
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..10);
    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap_err(),
        Error::InvalidAckRange
    );

    // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
    // An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION
    assert_eq!(
        pipe.server.local_error.unwrap().error_code,
        WireErrorCode::ProtocolViolation as u64
    );
}

#[rstest]
fn validate_peer_sent_ack_range_for_multi_path(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    let probed_pid =
        pipe.client.probe_path(client_addr_2, server_addr).unwrap() as usize;

    // Exchange path challenge/response and establish the second path
    pipe.advance().unwrap();
    assert_eq!(pipe.server.paths.len(), 2);

    let mut buf = [0; 2000];
    let epoch = packet::Epoch::Application;
    let pkt_type = Type::Short;

    // active path
    let expected_max_active_pkt_sent = 7;
    let active_path = &pipe.server.paths.get_mut(0).unwrap();
    let p1_recovery = &active_path.recovery;
    assert_eq!(
        p1_recovery.largest_sent_pkt_num_on_path(epoch).unwrap(),
        expected_max_active_pkt_sent
    );
    assert_eq!(p1_recovery.get_largest_acked_on_epoch(epoch).unwrap(), 6);
    assert_eq!(p1_recovery.sent_packets_len(epoch), 1);

    // non-active path
    let expected_max_second_pkt_sent = 5;
    let second_path = &pipe.server.paths.get_mut(probed_pid).unwrap();
    let p2_recovery = &second_path.recovery;
    assert_eq!(
        p2_recovery.largest_sent_pkt_num_on_path(epoch).unwrap(),
        expected_max_second_pkt_sent
    );
    assert_eq!(p2_recovery.get_largest_acked_on_epoch(epoch).unwrap(), 5);
    assert_eq!(p2_recovery.sent_packets_len(epoch), 0);

    // Verify largest sent on the connection is the max of the two paths
    let global_max_sent = pipe.server.pkt_num_spaces[epoch]
        .largest_tx_pkt_num
        .unwrap();
    assert_eq!(
        global_max_sent,
        expected_max_active_pkt_sent.max(expected_max_second_pkt_sent)
    );

    // Send a valid ACK range based on the global max.  Range is not inclusive
    // so +1 to include global_max_sent pkt
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..global_max_sent + 1);
    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // active path
    let active_path = &pipe.server.paths.get_mut(0).unwrap();
    assert!(active_path.active());
    let p1_recovery = &active_path.recovery;
    assert_eq!(p1_recovery.largest_sent_pkt_num_on_path(epoch).unwrap(), 7);
    assert_eq!(p1_recovery.get_largest_acked_on_epoch(epoch).unwrap(), 7);
    assert_eq!(p1_recovery.sent_packets_len(epoch), 0);

    // non-active path
    let second_path = &pipe.server.paths.get_mut(probed_pid).unwrap();
    let p2_recovery = &second_path.recovery;
    assert_eq!(p2_recovery.largest_sent_pkt_num_on_path(epoch).unwrap(), 5);
    assert_eq!(p2_recovery.get_largest_acked_on_epoch(epoch).unwrap(), 5);
    assert_eq!(p2_recovery.sent_packets_len(epoch), 0);

    // Send a large invalid ACK range to the server. Range is not inclusive so
    // +2 to include a packet greater than global_max_sent pkt
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..global_max_sent + 2);
    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap_err(),
        Error::InvalidAckRange
    );

    // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
    // An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION
    assert_eq!(
        pipe.server.local_error.unwrap().error_code,
        WireErrorCode::ProtocolViolation as u64
    );
}

// Both Client and Server should skip pn to prevent an optimistic ack attack
#[rstest]
fn optimistic_ack_mitigation_via_skip_pn(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm_name(cc_algorithm_name).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(100_0000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    pipe.handshake().unwrap();

    let mut server_skip_pn = None;
    let mut client_skip_pn = None;
    let buf = [42; 100];
    while server_skip_pn.is_none() || client_skip_pn.is_none() {
        // Server should send some data
        assert_eq!(pipe.server.stream_send(1, &buf, false).unwrap(), 100);

        // Advance server tx and client rx
        let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
        test_utils::process_flight(&mut pipe.client, flight).unwrap();

        // Check if server skipped a pn
        let server_num_manager = &pipe.server.pkt_num_manager;
        if let Some(skip_pn) = server_num_manager.skip_pn() {
            server_skip_pn = Some(skip_pn);
        }

        // Advance client tx and server rx
        let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
        test_utils::process_flight(&mut pipe.server, flight).unwrap();

        // Check if client skipped a pn
        let client_num_manager = &pipe.client.pkt_num_manager;
        if let Some(skip_pn) = client_num_manager.skip_pn() {
            client_skip_pn = Some(skip_pn);
        }
    }

    // Confirm both server and client skip pn
    assert!(server_skip_pn.is_some() && client_skip_pn.is_some());
}

// Connection should validate skip pn to prevent an optimistic ack attack
#[rstest]
fn prevent_optimistic_ack(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm_name(cc_algorithm_name).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(100_0000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    pipe.handshake().unwrap();

    let mut server_skip_pn = None;
    let buf = [42; 100];
    while server_skip_pn.is_none() {
        // Server should send some data
        pipe.server.stream_send(1, &buf, false).unwrap();

        // Advance server tx and client rx
        let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
        test_utils::process_flight(&mut pipe.client, flight).unwrap();

        // Check if server skipped a pn
        if let Some(skip_pn) = pipe.server.pkt_num_manager.skip_pn() {
            server_skip_pn = Some(skip_pn);
        }
    }

    let pkt_type = Type::Short;
    let mut buf = [0; 2000];

    // Construct an ACK with the skip_pn to send to the server
    let skip_pn = server_skip_pn.unwrap();
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(skip_pn..skip_pn + 1);
    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    // Receiving an ACK for the skip_pn results in an error
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
            .err()
            .unwrap(),
        Error::OptimisticAckDetected
    );

    // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
    // An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION
    assert_eq!(
        pipe.server.local_error.unwrap().error_code,
        WireErrorCode::ProtocolViolation as u64
    );
}

#[rstest]
fn app_limited_false_no_frame(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_max_recv_udp_payload_size(1405);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf1 = [0; 20000];
    assert_eq!(pipe.server.stream_send(0, &send_buf1, false), Ok(12000));

    test_utils::emit_flight(&mut pipe.server).ok();

    // We can't create a new packet header because there is no room by cwnd.
    // app_limited should be false because we can't send more by cwnd.
    assert!(!pipe
        .server
        .paths
        .get_active()
        .expect("no active")
        .recovery
        .app_limited());
}

#[rstest]
fn app_limited_false_no_header(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_max_recv_udp_payload_size(1406);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf1 = [0; 20000];
    assert_eq!(pipe.server.stream_send(0, &send_buf1, false), Ok(12000));

    test_utils::emit_flight(&mut pipe.server).ok();

    // We can't create a new frame because there is no room by cwnd.
    // app_limited should be false because we can't send more by cwnd.
    assert!(!pipe
        .server
        .paths
        .get_active()
        .expect("no active")
        .recovery
        .app_limited());
}

#[rstest]
fn app_limited_not_changed_on_no_new_frames(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    // Client's app_limited is true because its bytes-in-flight
    // is much smaller than the current cwnd.
    assert!(pipe
        .client
        .paths
        .get_active()
        .expect("no active")
        .recovery
        .app_limited());

    // Client has no new frames to send - returns Done.
    assert_eq!(test_utils::emit_flight(&mut pipe.client), Err(Error::Done));

    // Client's app_limited should remain the same.
    assert!(pipe
        .client
        .paths
        .get_active()
        .expect("no active")
        .recovery
        .app_limited());
}

#[rstest]
fn limit_ack_ranges(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let epoch = packet::Epoch::Application;

    assert_eq!(pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.len(), 0);

    let frames = [
        frame::Frame::Ping { mtu_probe: None },
        frame::Frame::Padding { len: 3 },
    ];

    let pkt_type = Type::Short;

    let mut last_packet_sent = 0;

    for _ in 0..512 {
        let recv_count = pipe.server.recv_count;

        last_packet_sent = pipe.client.next_pkt_num;

        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap();

        assert_eq!(pipe.server.recv_count, recv_count + 1);

        // Skip packet number.
        pipe.client.next_pkt_num += 1;
    }

    assert_eq!(
        pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.len(),
        MAX_ACK_RANGES
    );

    assert_eq!(
        pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.first(),
        Some(last_packet_sent - ((MAX_ACK_RANGES as u64) - 1) * 2)
    );

    assert_eq!(
        pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.last(),
        Some(last_packet_sent)
    );
}

#[rstest]
/// Tests that streams are correctly scheduled based on their priority.
fn stream_priority(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    // Limit 1-RTT packet size to avoid congestion control interference.
    const MAX_TEST_PACKET_SIZE: usize = 540;

    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(0);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(12, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(16, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(20, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 1];

    let out = [b'b'; 500];

    // Server prioritizes streams as follows:
    //  * Stream 8 and 16 have the same priority but are non-incremental.
    //  * Stream 4, 12 and 20 have the same priority but 20 is non-incremental and
    //    4 and 12 are incremental.
    //  * Stream 0 is on its own.

    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(0, 255, true), Ok(()));
    pipe.server.stream_send(0, &out, false).unwrap();
    pipe.server.stream_send(0, &out, false).unwrap();
    pipe.server.stream_send(0, &out, false).unwrap();

    pipe.server.stream_recv(12, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(12, 42, true), Ok(()));
    pipe.server.stream_send(12, &out, false).unwrap();
    pipe.server.stream_send(12, &out, false).unwrap();
    pipe.server.stream_send(12, &out, false).unwrap();

    pipe.server.stream_recv(16, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(16, 10, false), Ok(()));
    pipe.server.stream_send(16, &out, false).unwrap();
    pipe.server.stream_send(16, &out, false).unwrap();
    pipe.server.stream_send(16, &out, false).unwrap();

    pipe.server.stream_recv(4, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(4, 42, true), Ok(()));
    pipe.server.stream_send(4, &out, false).unwrap();
    pipe.server.stream_send(4, &out, false).unwrap();
    pipe.server.stream_send(4, &out, false).unwrap();

    pipe.server.stream_recv(8, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(8, 10, false), Ok(()));
    pipe.server.stream_send(8, &out, false).unwrap();
    pipe.server.stream_send(8, &out, false).unwrap();
    pipe.server.stream_send(8, &out, false).unwrap();

    pipe.server.stream_recv(20, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(20, 42, false), Ok(()));
    pipe.server.stream_send(20, &out, false).unwrap();
    pipe.server.stream_send(20, &out, false).unwrap();
    pipe.server.stream_send(20, &out, false).unwrap();

    // First is stream 8.
    let mut off = 0;

    for _ in 1..=3 {
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let stream = frames.first().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(&out, off, false),
        });

        off = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
    }

    // Then is stream 16.
    let mut off = 0;

    for _ in 1..=3 {
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let stream = frames.first().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 16,
            data: <RangeBuf>::from(&out, off, false),
        });

        off = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
    }

    // Then is stream 20.
    let mut off = 0;

    for _ in 1..=3 {
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let stream = frames.first().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 20,
            data: <RangeBuf>::from(&out, off, false),
        });

        off = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
    }

    // Then are stream 12 and 4, with the same priority, incrementally.
    let mut off = 0;

    for _ in 1..=3 {
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

        assert_eq!(
            frames.first(),
            Some(&frame::Frame::Stream {
                stream_id: 12,
                data: <RangeBuf>::from(&out, off, false),
            })
        );

        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

        let stream = frames.first().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(&out, off, false),
        });

        off = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
    }

    // Final is stream 0.
    let mut off = 0;

    for _ in 1..=3 {
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let stream = frames.first().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(&out, off, false),
        });

        off = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
    }

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
}

#[rstest]
/// Tests that changing a stream's priority is correctly propagated.
fn stream_reprioritize(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(0);
    config.set_initial_max_streams_bidi(5);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(12, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 1];

    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(0, 255, true), Ok(()));
    pipe.server.stream_send(0, b"b", false).unwrap();

    pipe.server.stream_recv(12, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(12, 42, true), Ok(()));
    pipe.server.stream_send(12, b"b", false).unwrap();

    pipe.server.stream_recv(8, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(8, 10, true), Ok(()));
    pipe.server.stream_send(8, b"b", false).unwrap();

    pipe.server.stream_recv(4, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(4, 42, true), Ok(()));
    pipe.server.stream_send(4, b"b", false).unwrap();

    // Stream 0 is re-prioritized!!!
    assert_eq!(pipe.server.stream_priority(0, 20, true), Ok(()));

    // First is stream 8.
    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"b", 0, false),
        })
    );

    // Then is stream 0.
    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"b", 0, false),
        })
    );

    // Then are stream 12 and 4, with the same priority.
    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::Stream {
            stream_id: 12,
            data: <RangeBuf>::from(b"b", 0, false),
        })
    );

    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"b", 0, false),
        })
    );

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
}

#[rstest]
/// Tests that streams and datagrams are correctly scheduled.
fn stream_datagram_priority(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    // Limit 1-RTT packet size to avoid congestion control interference.
    const MAX_TEST_PACKET_SIZE: usize = 540;

    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(0);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0);
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 1];

    let out = [b'b'; 500];

    // Server prioritizes Stream 0 and 4 with the same urgency with
    // incremental, meaning the frames should be sent in round-robin
    // fashion. It also sends DATAGRAMS which are always interleaved with
    // STREAM frames. So we'll expect a mix of frame types regardless
    // of the order that the application writes things in.

    pipe.server.stream_recv(0, &mut b).unwrap();
    assert_eq!(pipe.server.stream_priority(0, 255, true), Ok(()));
    pipe.server.stream_send(0, &out, false).unwrap();
    pipe.server.stream_send(0, &out, false).unwrap();
    pipe.server.stream_send(0, &out, false).unwrap();

    assert_eq!(pipe.server.stream_priority(4, 255, true), Ok(()));
    pipe.server.stream_send(4, &out, false).unwrap();
    pipe.server.stream_send(4, &out, false).unwrap();
    pipe.server.stream_send(4, &out, false).unwrap();

    for _ in 1..=6 {
        assert_eq!(pipe.server.dgram_send(&out), Ok(()));
    }

    let mut off_0 = 0;
    let mut off_4 = 0;

    for _ in 1..=3 {
        // DATAGRAM
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let mut frame_iter = frames.iter();

        assert_eq!(frame_iter.next().unwrap(), &frame::Frame::Datagram {
            data: out.into()
        });
        assert_eq!(frame_iter.next(), None);

        // STREAM 0
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let mut frame_iter = frames.iter();
        let stream = frame_iter.next().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(&out, off_0, false),
        });

        off_0 = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
        assert_eq!(frame_iter.next(), None);

        // DATAGRAM
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let mut frame_iter = frames.iter();

        assert_eq!(frame_iter.next().unwrap(), &frame::Frame::Datagram {
            data: out.into()
        });
        assert_eq!(frame_iter.next(), None);

        // STREAM 4
        let (len, _) =
            pipe.server.send(&mut buf[..MAX_TEST_PACKET_SIZE]).unwrap();

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        let mut frame_iter = frames.iter();
        let stream = frame_iter.next().unwrap();

        assert_eq!(stream, &frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(&out, off_4, false),
        });

        off_4 = match stream {
            frame::Frame::Stream { data, .. } => data.max_off(),

            _ => unreachable!(),
        };
        assert_eq!(frame_iter.next(), None);
    }
}

#[rstest]
/// Tests that old data is retransmitted on PTO.
fn early_retransmit(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends more stream data, but packet is lost
    assert_eq!(pipe.client.stream_send(4, b"b", false), Ok(1));
    assert!(pipe.client.send(&mut buf).is_ok());

    // Wait until PTO expires. Since the RTT is very low, wait a bit more.
    let timer = pipe.client.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();

    let epoch = packet::Epoch::Application;
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        1,
    );

    // Client retransmits stream data in PTO probe.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        0,
    );

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"b", 0, false),
        })
    );
    assert_eq!(pipe.client.stats().retrans, 1);
}

#[rstest]
/// Tests that PTO probe packets are not coalesced together.
fn dont_coalesce_probes(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends Initial packet.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, 1200);
    assert_eq!(pipe.client.path_stats().next().unwrap().total_pto_count, 0);

    // Wait for PTO to expire.
    let timer = pipe.client.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();
    assert_eq!(pipe.client.path_stats().next().unwrap().total_pto_count, 1);

    let epoch = packet::Epoch::Initial;
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        1,
    );

    // Client sends PTO probe.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        0,
    );

    // Wait for PTO to expire.
    let timer = pipe.client.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();
    assert_eq!(pipe.client.path_stats().next().unwrap().total_pto_count, 2);

    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        2,
    );

    // Client sends first PTO probe.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        1,
    );

    // Client sends second PTO probe.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .loss_probes(epoch),
        0,
    );
}

#[rstest]
fn coalesce_padding_short(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends first flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Server sends first flight.
    let (len, _) = pipe.server.send(&mut buf).unwrap();
    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    let (len, _) = pipe.server.send(&mut buf).unwrap();
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    // Client sends stream data.
    assert!(pipe.client.is_established());
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));

    // Client sends second flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // None of the sent packets should have been dropped.
    assert_eq!(pipe.client.sent_count, pipe.server.recv_count);
    assert_eq!(pipe.server.sent_count, pipe.client.recv_count);
}

#[rstest]
/// Tests that client avoids handshake deadlock by arming PTO.
fn handshake_anti_deadlock(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert-big.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();

    let mut pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();

    assert!(!pipe.client.handshake_status().has_handshake_keys);
    assert!(!pipe.client.handshake_status().peer_verified_address);
    assert!(!pipe.server.handshake_status().has_handshake_keys);
    assert!(pipe.server.handshake_status().peer_verified_address);

    // Client sends padded Initial.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, 1200);

    // Server receives client's Initial and sends own Initial and Handshake
    // until it's blocked by the anti-amplification limit.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    assert!(!pipe.client.handshake_status().has_handshake_keys);
    assert!(!pipe.client.handshake_status().peer_verified_address);
    assert!(pipe.server.handshake_status().has_handshake_keys);
    assert!(pipe.server.handshake_status().peer_verified_address);

    // Client receives the server flight and sends Handshake ACK, but it is
    // lost.
    test_utils::process_flight(&mut pipe.client, flight).unwrap();
    test_utils::emit_flight(&mut pipe.client).unwrap();

    assert!(pipe.client.handshake_status().has_handshake_keys);
    assert!(!pipe.client.handshake_status().peer_verified_address);
    assert!(pipe.server.handshake_status().has_handshake_keys);
    assert!(pipe.server.handshake_status().peer_verified_address);

    // Make sure client's PTO timer is armed.
    assert!(pipe.client.timeout().is_some());
}

#[rstest]
/// Tests that packets with corrupted type (from Handshake to Initial) are
/// properly ignored.
fn handshake_packet_type_corruption(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends padded Initial.
    let (len, _) = pipe.client.send(&mut buf).unwrap();
    assert_eq!(len, 1200);

    // Server receives client's Initial and sends own Initial and Handshake.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Client sends Initial packet with ACK.
    let active_pid = pipe.client.paths.get_active_path_id().expect("no active");
    let (ty, len) = pipe
        .client
        .send_single(&mut buf, active_pid, false, Instant::now())
        .unwrap();
    assert_eq!(ty, Type::Initial);

    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Client sends Handshake packet.
    let (ty, len) = pipe
        .client
        .send_single(&mut buf, active_pid, false, Instant::now())
        .unwrap();
    assert_eq!(ty, Type::Handshake);

    // Packet type is corrupted to Initial.
    buf[0] &= !(0x20);

    let hdr = Header::from_slice(&mut buf[..len], 0).unwrap();
    assert_eq!(hdr.ty, Type::Initial);

    // Server receives corrupted packet without returning an error.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
}

#[rstest]
fn dgram_send_fails_invalidstate(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.dgram_send(b"hello, world"),
        Err(Error::InvalidState)
    );
}

#[rstest]
fn dgram_send_app_limited(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];
    let send_buf = [0xcf; 1000];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 1000, 1000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    for _ in 0..1000 {
        assert_eq!(pipe.client.dgram_send(&send_buf), Ok(()));
    }

    // bbr2_gcongestion uses different logic to set app_limited
    // TODO fix
    let should_be_app_limited =
        cc_algorithm_name == "cubic" || cc_algorithm_name == "reno";
    assert_eq!(
        !pipe
            .client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .app_limited(),
        should_be_app_limited
    );
    assert_eq!(pipe.client.dgram_send_queue.byte_size(), 1_000_000);

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 0);
    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 1_000_000);
    assert_eq!(
        !pipe
            .client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .app_limited(),
        should_be_app_limited
    );

    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 0);
    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 1_000_000);

    assert_eq!(
        !pipe
            .client
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .app_limited(),
        should_be_app_limited
    );
}

#[rstest]
fn dgram_single_datagram(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));

    assert_eq!(pipe.advance(), Ok(()));

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(12));

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Err(Error::Done));
}

#[rstest]
fn dgram_multiple_datagrams(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 2, 3);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.dgram_send_queue_len(), 0);
    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 0);

    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"ciao, mondo"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"hola, mundo"), Ok(()));
    assert!(pipe.client.is_dgram_send_queue_full());

    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 34);

    pipe.client
        .dgram_purge_outgoing(|d: &[u8]| -> bool { d[0] == b'c' });

    assert_eq!(pipe.client.dgram_send_queue_len(), 2);
    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 23);
    assert!(!pipe.client.is_dgram_send_queue_full());

    // Before packets exchanged, no dgrams on server receive side.
    assert_eq!(pipe.server.dgram_recv_queue_len(), 0);

    assert_eq!(pipe.advance(), Ok(()));

    // After packets exchanged, no dgrams on client send side.
    assert_eq!(pipe.client.dgram_send_queue_len(), 0);
    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 0);

    assert_eq!(pipe.server.dgram_recv_queue_len(), 2);
    assert_eq!(pipe.server.dgram_recv_queue_byte_size(), 23);
    assert!(pipe.server.is_dgram_recv_queue_full());

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(12));
    assert_eq!(buf[0], b'h');
    assert_eq!(buf[1], b'e');
    assert!(!pipe.server.is_dgram_recv_queue_full());

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Ok(11));
    assert_eq!(buf[0], b'h');
    assert_eq!(buf[1], b'o');

    let result3 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result3, Err(Error::Done));

    assert_eq!(pipe.server.dgram_recv_queue_len(), 0);
    assert_eq!(pipe.server.dgram_recv_queue_byte_size(), 0);
}

#[rstest]
fn dgram_send_queue_overflow(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 2);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"ciao, mondo"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"hola, mundo"), Err(Error::Done));

    assert_eq!(pipe.advance(), Ok(()));

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(12));
    assert_eq!(buf[0], b'h');
    assert_eq!(buf[1], b'e');

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Ok(11));
    assert_eq!(buf[0], b'c');
    assert_eq!(buf[1], b'i');

    let result3 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result3, Err(Error::Done));
}

#[rstest]
fn dgram_recv_queue_overflow(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 2, 10);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"ciao, mondo"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"hola, mundo"), Ok(()));

    assert_eq!(pipe.advance(), Ok(()));

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(11));
    assert_eq!(buf[0], b'c');
    assert_eq!(buf[1], b'i');

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Ok(11));
    assert_eq!(buf[0], b'h');
    assert_eq!(buf[1], b'o');

    let result3 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result3, Err(Error::Done));
}

#[rstest]
fn dgram_send_max_size(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; MAX_DGRAM_FRAME_SIZE as usize];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 10);
    config.set_max_recv_udp_payload_size(1452);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

    // Before handshake (before peer settings) we don't know max dgram size
    assert_eq!(pipe.client.dgram_max_writable_len(), None);

    assert_eq!(pipe.handshake(), Ok(()));

    let max_dgram_size = pipe.client.dgram_max_writable_len().unwrap();

    // Tests use a 16-byte connection ID, so the max datagram frame payload
    // size is (1200 byte-long packet - 40 bytes overhead)
    assert_eq!(max_dgram_size, 1160);

    let dgram_packet: Vec<u8> = vec![42; max_dgram_size];

    assert_eq!(pipe.client.dgram_send(&dgram_packet), Ok(()));

    assert_eq!(pipe.advance(), Ok(()));

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(max_dgram_size));

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Err(Error::Done));
}

#[rstest]
/// Tests is_readable check.
fn is_readable(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 10);
    config.set_max_recv_udp_payload_size(1452);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // No readable data.
    assert!(!pipe.client.is_readable());
    assert!(!pipe.server.is_readable());

    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server received stream.
    assert!(!pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    assert_eq!(
        pipe.server.stream_send(4, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    // Client received stream.
    assert!(pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Client drains stream.
    let mut b = [0; 15];
    pipe.client.stream_recv(4, &mut b).unwrap();
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 0), Ok(()));
    assert!(!pipe.server.is_readable());

    // Server received dgram.
    assert_eq!(pipe.client.dgram_send(b"dddddddddddddd"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Client received dgram.
    assert_eq!(pipe.server.dgram_send(b"dddddddddddddd"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Drain the dgram queues.
    let r = pipe.server.dgram_recv(&mut buf);
    assert_eq!(r, Ok(14));
    assert!(!pipe.server.is_readable());

    let r = pipe.client.dgram_recv(&mut buf);
    assert_eq!(r, Ok(14));
    assert!(!pipe.client.is_readable());
}

#[rstest]
fn close(#[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.close(false, 0x1234, b"hello?"), Ok(()));

    assert_eq!(
        pipe.client.close(false, 0x4321, b"hello?"),
        Err(Error::Done)
    );

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::ConnectionClose {
            error_code: 0x1234,
            frame_type: 0,
            reason: b"hello?".to_vec(),
        })
    );
}

#[rstest]
fn app_close_by_client(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.close(true, 0x1234, b"hello!"), Ok(()));

    assert_eq!(pipe.client.close(true, 0x4321, b"hello!"), Err(Error::Done));

    let (len, _) = pipe.client.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.server, &mut buf[..len]).unwrap();

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::ApplicationClose {
            error_code: 0x1234,
            reason: b"hello!".to_vec(),
        })
    );
}

// OpenSSL does not provide a straightforward interface to deal with custom
// off-load key signing.
#[cfg(not(feature = "openssl"))]
#[rstest]
fn app_close_by_server_during_handshake_private_key_failure(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    pipe.server.handshake.set_failing_private_key_method();

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, flight),
        Err(Error::TlsFail)
    );

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    // Both connections are not established.
    assert!(!pipe.server.is_established());
    assert!(!pipe.client.is_established());

    // Connection should already be closed due the failure during key signing.
    assert_eq!(
        pipe.server.close(true, 123, b"fail whale"),
        Err(Error::Done)
    );

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Connection should already be closed due the failure during key signing.
    assert_eq!(
        pipe.client.close(true, 123, b"fail whale"),
        Err(Error::Done)
    );

    // Connection is not established on the server / client (and never
    // will be)
    assert!(!pipe.server.is_established());
    assert!(!pipe.client.is_established());

    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x01,
            reason: vec![],
        })
    );
    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x01,
            reason: vec![],
        })
    );
}

#[rstest]
fn app_close_by_server_during_handshake_not_established(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    // Both connections are not established.
    assert!(!pipe.client.is_established() && !pipe.server.is_established());

    // Server closes before connection is established.
    pipe.server.close(true, 123, b"fail whale").unwrap();

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Connection is established on the client.
    assert!(pipe.client.is_established());

    // Client sends after connection is established.
    pipe.client.stream_send(0, b"badauthtoken", true).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Connection is not established on the server (and never will be)
    assert!(!pipe.server.is_established());

    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x0c,
            reason: vec![],
        })
    );
    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x0c,
            reason: vec![],
        })
    );
}

#[rstest]
fn app_close_by_server_during_handshake_established(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    // Both connections are not established.
    assert!(!pipe.client.is_established() && !pipe.server.is_established());

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Connection is established on the client.
    assert!(pipe.client.is_established());

    // Client sends after connection is established.
    pipe.client.stream_send(0, b"badauthtoken", true).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Connection is established on the server but the Handshake ACK has not
    // been sent yet.
    assert!(pipe.server.is_established());

    // Server closes after connection is established.
    pipe.server
        .close(true, 123, b"Invalid authentication")
        .unwrap();

    // Server sends Handshake ACK and then 1RTT CONNECTION_CLOSE.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 123,
            reason: b"Invalid authentication".to_vec()
        })
    );
    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 123,
            reason: b"Invalid authentication".to_vec()
        })
    );
}

#[rstest]
fn transport_close_by_client_during_handshake_established(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    // Both connections are not established.
    assert!(!pipe.client.is_established() && !pipe.server.is_established());

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Connection is established on the client.
    assert!(pipe.client.is_established());

    // Client sends after connection is established.
    pipe.client.close(false, 123, b"connection close").unwrap();

    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert_eq!(
        pipe.server.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 123,
            reason: b"connection close".to_vec()
        })
    );
    assert_eq!(
        pipe.client.local_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 123,
            reason: b"connection close".to_vec()
        })
    );
}

#[rstest]
fn peer_error(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.close(false, 0x1234, b"hello?"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x1234u64,
            reason: b"hello?".to_vec()
        })
    );
}

#[rstest]
fn app_peer_error(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.close(true, 0x1234, b"hello!"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 0x1234u64,
            reason: b"hello!".to_vec()
        })
    );
}

#[rstest]
fn local_error(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.local_error(), None);

    assert_eq!(pipe.server.close(true, 0x1234, b"hello!"), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 0x1234u64,
            reason: b"hello!".to_vec()
        })
    );
}

#[rstest]
fn update_max_datagram_size(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut client_scid = [0; 16];
    rand::rand_bytes(&mut client_scid[..]);
    let client_scid = ConnectionId::from_ref(&client_scid);
    let client_addr = "127.0.0.1:1234".parse().unwrap();

    let mut server_scid = [0; 16];
    rand::rand_bytes(&mut server_scid[..]);
    let server_scid = ConnectionId::from_ref(&server_scid);
    let server_addr = "127.0.0.1:4321".parse().unwrap();

    let mut client_config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(
        client_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );
    client_config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    client_config.set_max_recv_udp_payload_size(1200);

    let mut server_config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );
    server_config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    server_config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    server_config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    server_config.verify_peer(false);
    server_config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    // Larger than the client
    server_config.set_max_send_udp_payload_size(1500);

    let mut pipe = test_utils::Pipe {
        client: connect(
            Some("quic.tech"),
            &client_scid,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .unwrap(),
        server: accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )
        .unwrap(),
    };

    // Before handshake
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .max_datagram_size(),
        1500,
    );

    assert_eq!(pipe.handshake(), Ok(()));

    // After handshake, max_datagram_size should match to client's
    // max_recv_udp_payload_size which is smaller
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .max_datagram_size(),
        1200,
    );
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .recovery
            .cwnd(),
        if cc_algorithm_name == "cubic" {
            12000
        } else if cfg!(feature = "openssl") {
            13437
        } else {
            13421
        },
    );
}

#[rstest]
/// Tests that connection-level send capacity decreases as more stream data
/// is buffered.
fn send_capacity(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(100000);
    config.set_initial_max_stream_data_bidi_local(10000);
    config.set_initial_max_stream_data_bidi_remote(10000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(12, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable().collect::<Vec<u64>>();
    assert_eq!(r.len(), 4);

    r.sort();

    assert_eq!(r, [0, 4, 8, 12]);

    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((6, true)));
    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((6, true)));
    assert_eq!(pipe.server.stream_recv(8, &mut buf), Ok((6, true)));
    assert_eq!(pipe.server.stream_recv(12, &mut buf), Ok((6, true)));

    assert_eq!(
        pipe.server.tx_cap,
        if cc_algorithm_name == "cubic" {
            12000
        } else if cfg!(feature = "openssl") {
            13959
        } else {
            13873
        }
    );

    assert_eq!(pipe.server.stream_send(0, &buf[..5000], false), Ok(5000));
    assert_eq!(pipe.server.stream_send(4, &buf[..5000], false), Ok(5000));
    assert_eq!(
        pipe.server.stream_send(8, &buf[..5000], false),
        if cc_algorithm_name == "cubic" {
            Ok(2000)
        } else if cfg!(feature = "openssl") {
            Ok(3959)
        } else {
            Ok(3873)
        }
    );

    // No more connection send capacity.
    assert_eq!(
        pipe.server.stream_send(12, &buf[..5000], false),
        Err(Error::Done)
    );
    assert_eq!(pipe.server.tx_cap, 0);

    assert_eq!(pipe.advance(), Ok(()));
}

#[cfg(feature = "boringssl-boring-crate")]
#[rstest]
fn user_provided_boring_ctx(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    // Manually construct boring ssl ctx for server
    let mut server_tls_ctx_builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .unwrap();
    server_tls_ctx_builder
        .set_certificate_chain_file("examples/cert.crt")
        .unwrap();
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", boring::ssl::SslFiletype::PEM)
        .unwrap();

    let mut server_config = Config::with_boring_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;
    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(
        client_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    assert_eq!(pipe.handshake(), Ok(()));

    Ok(())
}

#[cfg(feature = "boringssl-boring-crate")]
#[rstest]
fn in_handshake_config(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = [0; 65535];

    const CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 30;
    const CUSTOM_INITIAL_MAX_STREAMS_BIDI: u64 = 30;
    const CUSTOM_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(3);

    // Manually construct `SslContextBuilder` for the server so we can modify
    // CWND during the handshake.
    let mut server_tls_ctx_builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .unwrap();
    server_tls_ctx_builder
        .set_certificate_chain_file("examples/cert.crt")
        .unwrap();
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", boring::ssl::SslFiletype::PEM)
        .unwrap();
    server_tls_ctx_builder.set_select_certificate_callback(|mut hello| {
        <Connection>::set_initial_congestion_window_packets_in_handshake(
            hello.ssl_mut(),
            CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS,
        )
        .unwrap();

        <Connection>::set_max_idle_timeout_in_handshake(
            hello.ssl_mut(),
            CUSTOM_MAX_IDLE_TIMEOUT.as_millis() as u64,
        )
        .unwrap();

        <Connection>::set_initial_max_streams_bidi_in_handshake(
            hello.ssl_mut(),
            CUSTOM_INITIAL_MAX_STREAMS_BIDI,
        )
        .unwrap();

        Ok(())
    });

    let mut server_config = Config::with_boring_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(1000000);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf).unwrap();

    assert_eq!(pipe.server.tx_cap, 0);

    // Server receives client's initial flight and updates its config.
    pipe.server_recv(&mut buf[..len]).unwrap();

    assert_eq!(
        pipe.server.tx_cap,
        CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200
    );

    assert_eq!(pipe.server.idle_timeout(), Some(CUSTOM_MAX_IDLE_TIMEOUT));

    // Server sends initial flight.
    let (len, _) = pipe.server.send(&mut buf).unwrap();
    pipe.client_recv(&mut buf[..len]).unwrap();

    // Ensure the client received the new transport parameters.
    assert_eq!(pipe.client.idle_timeout(), Some(CUSTOM_MAX_IDLE_TIMEOUT));

    assert_eq!(
        pipe.client.peer_streams_left_bidi(),
        CUSTOM_INITIAL_MAX_STREAMS_BIDI
    );

    assert_eq!(pipe.handshake(), Ok(()));

    Ok(())
}

#[rstest]
fn initial_cwnd(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    const CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 30;

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.set_initial_congestion_window_packets(
        CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS,
    );
    // From Pipe::new()
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(1000000);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.set_ack_delay_exponent(8);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    if cc_algorithm_name == "cubic" {
        assert_eq!(
            pipe.server.tx_cap,
            CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200
        );
    } else {
        // TODO understand where these adjustments come from and why they vary
        // by TLS implementation and OS target.
        let expected = CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200 +
            if cfg!(feature = "openssl") {
                1463
            } else {
                1447
            };

        assert!(
            pipe.server.tx_cap >= expected,
            "{} vs {}",
            pipe.server.tx_cap,
            expected
        );
        assert!(
            pipe.server.tx_cap <= expected + 1,
            "{} vs {}",
            pipe.server.tx_cap,
            expected + 1
        );
    }

    Ok(())
}

#[rstest]
/// Tests that resetting a stream restores flow control for unsent data.
fn last_tx_data_larger_than_tx_data(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(12000);
    config.set_initial_max_stream_data_bidi_local(20000);
    config.set_initial_max_stream_data_bidi_remote(20000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens stream 4 and 8.
    assert_eq!(pipe.client.stream_send(4, b"a", true), Ok(1));
    assert_eq!(pipe.client.stream_send(8, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    let mut b = [0; 15];
    pipe.server.stream_recv(4, &mut b).unwrap();

    // Server sends stream data close to cwnd (12000).
    let buf = [0; 10000];
    assert_eq!(pipe.server.stream_send(4, &buf, false), Ok(10000));

    test_utils::emit_flight(&mut pipe.server).unwrap();

    // Server buffers some data, until send capacity limit reached.
    let mut buf = [0; 1200];
    assert_eq!(pipe.server.stream_send(4, &buf, false), Ok(1200));
    assert_eq!(pipe.server.stream_send(8, &buf, false), Ok(800));
    assert_eq!(pipe.server.stream_send(4, &buf, false), Err(Error::Done));

    // Wait for PTO to expire.
    let timer = pipe.server.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.server.on_timeout();

    // Server sends PTO probe (not limited to cwnd),
    // to update last_tx_data.
    let (len, _) = pipe.server.send(&mut buf).unwrap();
    assert_eq!(len, 1200);

    // Client sends STOP_SENDING to decrease tx_data
    // by unsent data. It will make last_tx_data > tx_data
    // and trigger #1232 bug.
    let frames = [frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();
}

/// Tests that when the client provides a new ConnectionId, it eventually
/// reaches the server and notifies the application.
#[rstest]
fn send_connection_ids(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // So far, there should not have any QUIC event.
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 2);

    let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid, reset_token, false), Ok(1));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 1);

    // Now, a second CID can be provided.
    let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid, reset_token, false), Ok(2));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 2);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 0);

    // If now the client tries to send another CID, it reports an error
    // since it exceeds the limit of active CIDs.
    let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(
        pipe.client.new_scid(&scid, reset_token, false),
        Err(Error::IdLimit),
    );
}

#[rstest]
/// Tests that NEW_CONNECTION_ID with zero-length CID are rejected.
fn connection_id_zero(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let mut frames = Vec::new();

    // Client adds a CID that is too short.
    let (scid, reset_token) = test_utils::create_cid_and_reset_token(0);

    frames.push(frame::Frame::NewConnectionId {
        seq_num: 1,
        retire_prior_to: 0,
        conn_id: scid.to_vec(),
        reset_token: reset_token.to_be_bytes(),
    });

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    let active_path = pipe.server.paths.get_active().unwrap();
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };

    assert_eq!(
        pipe.server.recv(&mut buf[..written], info),
        Err(Error::InvalidFrame)
    );

    let written = match pipe.server.send(&mut buf) {
        Ok((write, _)) => write,

        Err(_) => unreachable!(),
    };

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..written]).unwrap();
    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ConnectionClose {
            error_code: 0x7,
            frame_type: 0,
            reason: Vec::new(),
        })
    );
}

#[rstest]
/// Tests that NEW_CONNECTION_ID with too long CID are rejected.
fn connection_id_invalid_max_len(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let mut frames = Vec::new();

    // Client adds a CID that is too long.
    let (scid, reset_token) =
        test_utils::create_cid_and_reset_token(MAX_CONN_ID_LEN + 1);

    frames.push(frame::Frame::NewConnectionId {
        seq_num: 1,
        retire_prior_to: 0,
        conn_id: scid.to_vec(),
        reset_token: reset_token.to_be_bytes(),
    });

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    let active_path = pipe.server.paths.get_active().unwrap();
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };

    assert_eq!(
        pipe.server.recv(&mut buf[..written], info),
        Err(Error::InvalidFrame)
    );

    let written = match pipe.server.send(&mut buf) {
        Ok((write, _)) => write,

        Err(_) => unreachable!(),
    };

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..written]).unwrap();
    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ConnectionClose {
            error_code: 0x7,
            frame_type: 0,
            reason: Vec::new(),
        })
    );
}

#[rstest]
/// Exercises the handling of NEW_CONNECTION_ID and RETIRE_CONNECTION_ID
/// frames.
fn connection_id_handling(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // So far, there should not have any QUIC event.
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 1);

    let scid = pipe.client.source_id().into_owned();

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 0);

    // Now we assume that the client wants to advertise more source
    // Connection IDs than the advertised limit. This is valid if it
    // requests its peer to retire enough Connection IDs to fit within the
    // limits.

    let (scid_2, reset_token_2) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_2, reset_token_2, true), Ok(2));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server still have a spare DCID.
    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);

    // Client should have received a retired notification.
    assert_eq!(pipe.client.retired_scid_next(), Some(scid));
    assert_eq!(pipe.client.retired_scid_next(), None);

    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 0);

    // The active Destination Connection ID of the server should now be the
    // one with sequence number 1.
    assert_eq!(pipe.server.destination_id(), scid_1);

    // Now tries to experience CID retirement. If the server tries to remove
    // non-existing DCIDs, it fails.
    assert_eq!(pipe.server.retire_dcid(0), Err(Error::InvalidState));
    assert_eq!(pipe.server.retire_dcid(3), Err(Error::InvalidState));

    // Now it removes DCID with sequence 1.
    assert_eq!(pipe.server.retire_dcid(1), Ok(()));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.retired_scid_next(), Some(scid_1));
    assert_eq!(pipe.client.retired_scid_next(), None);

    assert_eq!(pipe.server.destination_id(), scid_2);
    assert_eq!(pipe.server.available_dcids(), 0);

    // Trying to remove the last DCID triggers an error.
    assert_eq!(pipe.server.retire_dcid(2), Err(Error::OutOfIdentifiers));
}

#[rstest]
fn lost_connection_id_frames(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let scid = pipe.client.source_id().into_owned();

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));

    // Packets are sent, but never received.
    test_utils::emit_flight(&mut pipe.client).unwrap();

    // Wait until timer expires. Since the RTT is very low, wait a bit more.
    let timer = pipe.client.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 1);

    // Now the server retires the first Destination CID.
    assert_eq!(pipe.server.retire_dcid(0), Ok(()));

    // But the packet never reaches the client.
    test_utils::emit_flight(&mut pipe.server).unwrap();

    // Wait until timer expires. Since the RTT is very low, wait a bit more.
    let timer = pipe.server.timeout().unwrap();
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.server.on_timeout();

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.retired_scid_next(), Some(scid));
    assert_eq!(pipe.client.retired_scid_next(), None);
}

#[rstest]
fn sending_duplicate_scids(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Trying to send the same CID with a different reset token raises an
    // InvalidState error.
    let reset_token_2 = reset_token_1.wrapping_add(1);
    assert_eq!(
        pipe.client.new_scid(&scid_1, reset_token_2, false),
        Err(Error::InvalidState),
    );

    // Retrying to send the exact same CID with the same token returns the
    // previously assigned CID seq, but without sending anything.
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));
    assert!(!pipe.client.ids.has_new_scids());

    // Now retire this new CID.
    assert_eq!(pipe.server.retire_dcid(1), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    // It is up to the application to ensure that a given SCID is not reused
    // later.
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(2));
}

#[rstest]
/// Tests the limit to retired DCID sequence numbers.
fn connection_id_retire_limit(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // So far, there should not have any QUIC event.
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 1);

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 0);

    let mut frames = Vec::new();

    // Client retires more than 3x the number of allowed active CIDs.
    for i in 2..=7 {
        let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);

        frames.push(frame::Frame::NewConnectionId {
            seq_num: i,
            retire_prior_to: i,
            conn_id: scid.to_vec(),
            reset_token: reset_token.to_be_bytes(),
        });
    }

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
            .unwrap();

    let active_path = pipe.server.paths.get_active().unwrap();
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };

    assert_eq!(
        pipe.server.recv(&mut buf[..written], info),
        Err(Error::IdLimit)
    );

    let written = match pipe.server.send(&mut buf) {
        Ok((write, _)) => write,

        Err(_) => unreachable!(),
    };

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..written]).unwrap();
    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ConnectionClose {
            error_code: 0x9,
            frame_type: 0,
            reason: Vec::new(),
        })
    );
}

#[rstest]
fn connection_id_retire_exotic_sequence(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_uni(3);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Inject an exotic sequence of NEW_CONNECTION_ID frames, unbeknowst to
    // quiche client connection object.
    let frames = [
        frame::Frame::NewConnectionId {
            seq_num: 8,
            retire_prior_to: 1,
            conn_id: vec![0],
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        },
        frame::Frame::NewConnectionId {
            seq_num: 1,
            retire_prior_to: 0,
            conn_id: vec![2],
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        },
        frame::Frame::NewConnectionId {
            seq_num: 6,
            retire_prior_to: 6,
            conn_id: vec![0x15],
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
        },
        frame::Frame::NewConnectionId {
            seq_num: 8,
            retire_prior_to: 1,
            conn_id: vec![0],
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
        },
        frame::Frame::NewConnectionId {
            seq_num: 48,
            retire_prior_to: 8,
            conn_id: vec![1],
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
        },
    ];

    let pkt_type = Type::Short;
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Ensure operations continue to be allowed.
    assert_eq!(pipe.client.stream_send(0, b"data", true), Ok(4));
    assert_eq!(pipe.server.stream_send(1, b"data", true), Ok(4));
    assert_eq!(pipe.client.stream_send(2, b"data", true), Ok(4));
    assert_eq!(pipe.server.stream_send(3, b"data", true), Ok(4));

    assert_eq!(pipe.advance(), Ok(()));

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((4, true)));
    assert_eq!(pipe.server.stream_recv(2, &mut b), Ok((4, true)));

    // The exotic sequence insertion messes with the client object's
    // worldview so we can't check its side of things.
}

// Utility function.
fn pipe_with_exchanged_cids(
    config: &mut Config, client_scid_len: usize, server_scid_len: usize,
    additional_cids: usize,
) -> test_utils::Pipe {
    let mut pipe = test_utils::Pipe::with_config_and_scid_lengths(
        config,
        client_scid_len,
        server_scid_len,
    )
    .unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let mut c_cids = Vec::new();
    let mut c_reset_tokens = Vec::new();
    let mut s_cids = Vec::new();
    let mut s_reset_tokens = Vec::new();

    for i in 0..additional_cids {
        if client_scid_len > 0 {
            let (c_cid, c_reset_token) =
                test_utils::create_cid_and_reset_token(client_scid_len);
            c_cids.push(c_cid);
            c_reset_tokens.push(c_reset_token);

            assert_eq!(
                pipe.client.new_scid(&c_cids[i], c_reset_tokens[i], true),
                Ok(i as u64 + 1)
            );
        }

        if server_scid_len > 0 {
            let (s_cid, s_reset_token) =
                test_utils::create_cid_and_reset_token(server_scid_len);
            s_cids.push(s_cid);
            s_reset_tokens.push(s_reset_token);
            assert_eq!(
                pipe.server.new_scid(&s_cids[i], s_reset_tokens[i], true),
                Ok(i as u64 + 1)
            );
        }
    }

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    if client_scid_len > 0 {
        assert_eq!(pipe.server.available_dcids(), additional_cids);
    }

    if server_scid_len > 0 {
        assert_eq!(pipe.client.available_dcids(), additional_cids);
    }

    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);

    pipe
}

#[rstest]
fn path_validation(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

    // We cannot probe a new path if there are not enough identifiers.
    assert_eq!(
        pipe.client.probe_path(client_addr_2, server_addr),
        Err(Error::OutOfIdentifiers)
    );

    let (c_cid, c_reset_token) = test_utils::create_cid_and_reset_token(16);

    assert_eq!(pipe.client.new_scid(&c_cid, c_reset_token, true), Ok(1));

    let (s_cid, s_reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.server.new_scid(&s_cid, s_reset_token, true), Ok(1));

    // We need to exchange the CIDs first.
    assert_eq!(
        pipe.client.probe_path(client_addr_2, server_addr),
        Err(Error::OutOfIdentifiers)
    );

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.available_dcids(), 1);
    assert_eq!(pipe.client.path_event_next(), None);

    // Now the path probing can work.
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    // But the server cannot probe a yet-unseen path.
    assert_eq!(
        pipe.server.probe_path(server_addr, client_addr_2),
        Err(Error::InvalidState),
    );

    assert_eq!(pipe.advance(), Ok(()));

    // The path should be validated at some point.
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr)),
    );
    assert_eq!(pipe.client.path_event_next(), None);

    // The server should be notified of this new path.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2)),
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2)),
    );
    assert_eq!(pipe.server.path_event_next(), None);

    // The server can later probe the path again.
    assert_eq!(pipe.server.probe_path(server_addr, client_addr_2), Ok(1));

    // This should not trigger any event at client side.
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
}

#[rstest]
fn losing_probing_packets(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    // The client creates the PATH CHALLENGE, but it is lost.
    test_utils::emit_flight(&mut pipe.client).unwrap();

    // Wait until probing timer expires. Since the RTT is very low,
    // wait a bit more.
    let probed_pid = pipe
        .client
        .paths
        .path_id_from_addrs(&(client_addr_2, server_addr))
        .unwrap();
    let probe_instant = pipe
        .client
        .paths
        .get(probed_pid)
        .unwrap()
        .recovery
        .loss_detection_timer()
        .unwrap();
    let timer = probe_instant.duration_since(Instant::now());
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();

    assert_eq!(pipe.advance(), Ok(()));

    // The path should be validated at some point.
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    assert_eq!(pipe.client.path_event_next(), None);

    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    // The path should be validated at some point.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);
}

#[rstest]
fn failed_path_validation(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    for _ in 0..MAX_PROBING_TIMEOUTS {
        // The client creates the PATH CHALLENGE, but it is always lost.
        test_utils::emit_flight(&mut pipe.client).unwrap();

        // Wait until probing timer expires. Since the RTT is very low,
        // wait a bit more.
        let probed_pid = pipe
            .client
            .paths
            .path_id_from_addrs(&(client_addr_2, server_addr))
            .unwrap();
        let probe_instant = pipe
            .client
            .paths
            .get(probed_pid)
            .unwrap()
            .recovery
            .loss_detection_timer()
            .unwrap();
        let timer = probe_instant.duration_since(Instant::now());
        std::thread::sleep(timer + Duration::from_millis(1));

        pipe.client.on_timeout();
    }

    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::FailedValidation(client_addr_2, server_addr)),
    );
}

#[rstest]
fn client_discard_unknown_address(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_uni(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Server sends stream data.
    assert_eq!(pipe.server.stream_send(3, b"a", true), Ok(1));

    let mut flight =
        test_utils::emit_flight(&mut pipe.server).expect("no packet");
    // Let's change the address info.
    flight
        .iter_mut()
        .for_each(|(_, si)| si.from = "127.0.0.1:9292".parse().unwrap());
    assert_eq!(test_utils::process_flight(&mut pipe.client, flight), Ok(()));
    assert_eq!(pipe.client.paths.len(), 1);
}

#[rstest]
fn path_validation_limited_mtu(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    // Limited MTU of 1199 bytes for some reason.
    test_utils::process_flight(
        &mut pipe.server,
        test_utils::emit_flight_with_max_buffer(
            &mut pipe.client,
            1199,
            None,
            None,
        )
        .expect("no packet"),
    )
    .expect("error when processing client packets");
    test_utils::process_flight(
        &mut pipe.client,
        test_utils::emit_flight(&mut pipe.server).expect("no packet"),
    )
    .expect("error when processing client packets");
    let probed_pid = pipe
        .client
        .paths
        .path_id_from_addrs(&(client_addr_2, server_addr))
        .unwrap();
    assert!(!pipe.client.paths.get(probed_pid).unwrap().validated(),);
    assert_eq!(pipe.client.path_event_next(), None);
    // Now let the client probe at its MTU.
    assert_eq!(pipe.advance(), Ok(()));
    assert!(pipe.client.paths.get(probed_pid).unwrap().validated());
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
}

#[rstest]
fn path_probing_dos(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    assert_eq!(pipe.advance(), Ok(()));

    // The path should be validated at some point.
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    assert_eq!(pipe.client.path_event_next(), None);

    // The server should be notified of this new path.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);

    assert_eq!(pipe.server.paths.len(), 2);

    // Now forge a packet reusing the unverified path's CID over another
    // 4-tuple.
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    let client_addr_3 = "127.0.0.1:9012".parse().unwrap();
    let mut flight =
        test_utils::emit_flight(&mut pipe.client).expect("no generated packet");
    flight
        .iter_mut()
        .for_each(|(_, si)| si.from = client_addr_3);
    test_utils::process_flight(&mut pipe.server, flight)
        .expect("failed to process");
    assert_eq!(pipe.server.paths.len(), 2);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::ReusedSourceConnectionId(
            1,
            (server_addr, client_addr_2),
            (server_addr, client_addr_3)
        ))
    );
    assert_eq!(pipe.server.path_event_next(), None);
}

#[rstest]
fn retiring_active_path_dcid(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);
    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    assert_eq!(pipe.client.retire_dcid(0), Err(Error::OutOfIdentifiers));
}

#[rstest]
fn send_on_path_test(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_initial_max_data(100000);
    config.set_initial_max_stream_data_bidi_local(100000);
    config.set_initial_max_stream_data_bidi_remote(100000);
    config.set_initial_max_streams_bidi(2);
    config.set_active_connection_id_limit(4);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 3);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr = test_utils::Pipe::client_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    let mut buf = [0; 65535];
    // There is nothing to send on the initial path.
    assert_eq!(
        pipe.client
            .send_on_path(&mut buf, Some(client_addr), Some(server_addr)),
        Err(Error::Done)
    );

    // Client should send padded PATH_CHALLENGE.
    let (sent, si) = pipe
        .client
        .send_on_path(&mut buf, Some(client_addr_2), Some(server_addr))
        .expect("No error");
    assert_eq!(sent, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(si.from, client_addr_2);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 1);

    // A non-existing 4-tuple raises an InvalidState.
    let client_addr_3 = "127.0.0.1:9012".parse().unwrap();
    let server_addr_2 = "127.0.0.1:9876".parse().unwrap();
    assert_eq!(
        pipe.client.send_on_path(
            &mut buf,
            Some(client_addr_3),
            Some(server_addr)
        ),
        Err(Error::InvalidState)
    );
    assert_eq!(
        pipe.client.send_on_path(
            &mut buf,
            Some(client_addr),
            Some(server_addr_2)
        ),
        Err(Error::InvalidState)
    );

    // Let's introduce some additional path challenges and data exchange.
    assert_eq!(pipe.client.probe_path(client_addr, server_addr_2), Ok(2));
    assert_eq!(pipe.client.probe_path(client_addr_3, server_addr), Ok(3));
    // Just to fit in two packets.
    assert_eq!(pipe.client.stream_send(0, &buf[..1201], true), Ok(1201));

    // PATH_CHALLENGE
    let (sent, si) = pipe
        .client
        .send_on_path(&mut buf, Some(client_addr), None)
        .expect("No error");
    assert_eq!(sent, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(si.from, client_addr);
    assert_eq!(si.to, server_addr_2);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 2);

    // STREAM frame on active path.
    let (sent, si) = pipe
        .client
        .send_on_path(&mut buf, Some(client_addr), None)
        .expect("No error");
    assert_eq!(si.from, client_addr);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 2);

    // PATH_CHALLENGE
    let (sent, si) = pipe
        .client
        .send_on_path(&mut buf, None, Some(server_addr))
        .expect("No error");
    assert_eq!(sent, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(si.from, client_addr_3);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 3);

    // STREAM frame on active path.
    let (sent, si) = pipe
        .client
        .send_on_path(&mut buf, None, Some(server_addr))
        .expect("No error");
    assert_eq!(si.from, client_addr);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    // No more data to exchange leads to Error::Done.
    assert_eq!(
        pipe.client.send_on_path(&mut buf, Some(client_addr), None),
        Err(Error::Done)
    );
    assert_eq!(
        pipe.client.send_on_path(&mut buf, None, Some(server_addr)),
        Err(Error::Done)
    );

    assert_eq!(pipe.advance(), Ok(()));

    let mut v1 = pipe.client.paths_iter(client_addr).collect::<Vec<_>>();
    let mut v2 = vec![server_addr, server_addr_2];

    v1.sort();
    v2.sort();

    assert_eq!(v1, v2);

    let mut v1 = pipe.client.paths_iter(client_addr_2).collect::<Vec<_>>();
    let mut v2 = vec![server_addr];

    v1.sort();
    v2.sort();

    assert_eq!(v1, v2);

    let mut v1 = pipe.client.paths_iter(client_addr_3).collect::<Vec<_>>();
    let mut v2 = vec![server_addr];

    v1.sort();
    v2.sort();

    assert_eq!(v1, v2);

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 3);
}

#[rstest]
fn connection_migration(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 2);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
    let client_addr_3 = "127.0.0.1:9012".parse().unwrap();
    let client_addr_4 = "127.0.0.1:8908".parse().unwrap();

    // Case 1: the client first probes the new address, the server too, and
    // then migrates.
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.client.is_path_validated(client_addr_2, server_addr),
        Ok(true)
    );
    assert_eq!(
        pipe.server.is_path_validated(server_addr, client_addr_2),
        Ok(true)
    );
    // The server can never initiates the connection migration.
    assert_eq!(
        pipe.server.migrate(server_addr, client_addr_2),
        Err(Error::InvalidState)
    );
    assert_eq!(pipe.client.migrate(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.client.stream_send(0, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        client_addr_2
    );
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::PeerMigrated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        client_addr_2
    );

    // Case 2: the client migrates on a path that was not previously
    // validated, and has spare SCIDs/DCIDs to do so.
    assert_eq!(pipe.client.migrate(client_addr_3, server_addr), Ok(2));
    assert_eq!(pipe.client.stream_send(4, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        client_addr_3
    );
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_3))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_3))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::PeerMigrated(server_addr, client_addr_3))
    );
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        client_addr_3
    );

    // Case 3: the client tries to migrate on the current active path.
    // This is not an error, but it triggers nothing.
    assert_eq!(pipe.client.migrate(client_addr_3, server_addr), Ok(2));
    assert_eq!(pipe.client.stream_send(8, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        client_addr_3
    );
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        server_addr
    );
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        client_addr_3
    );

    // Case 4: the client tries to migrate on a path that was not previously
    // validated, and has no spare SCIDs/DCIDs. Prevent active migration.
    assert_eq!(
        pipe.client.migrate(client_addr_4, server_addr),
        Err(Error::OutOfIdentifiers)
    );
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        client_addr_3
    );
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        server_addr
    );
}

#[rstest]
fn connection_migration_zero_length_cid(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 0, 16, 1);

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

    // The client migrates on a path that was not previously
    // validated, and has spare SCIDs/DCIDs to do so.
    assert_eq!(pipe.client.migrate(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.client.stream_send(4, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        client_addr_2
    );
    assert_eq!(
        pipe.client
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::PeerMigrated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .local_addr(),
        server_addr
    );
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        client_addr_2
    );
}

#[rstest]
fn connection_migration_reordered_non_probing(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let client_addr = test_utils::Pipe::client_addr();
    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);

    // A first flight sent from secondary address.
    assert_eq!(pipe.client.stream_send(0, b"data", true), Ok(4));
    let mut first = test_utils::emit_flight(&mut pipe.client).unwrap();
    first.iter_mut().for_each(|(_, si)| si.from = client_addr_2);
    // A second one, but sent from the original one.
    assert_eq!(pipe.client.stream_send(4, b"data", true), Ok(4));
    let second = test_utils::emit_flight(&mut pipe.client).unwrap();
    // Second flight is received before first one.
    assert_eq!(test_utils::process_flight(&mut pipe.server, second), Ok(()));
    assert_eq!(test_utils::process_flight(&mut pipe.server, first), Ok(()));

    // Server does not perform connection migration because of packet
    // reordering.
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(
        pipe.server
            .paths
            .get_active()
            .expect("no active")
            .peer_addr(),
        client_addr
    );
}

#[rstest]
fn resilience_against_migration_attack(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);
    config.set_initial_max_data(100000);
    config.set_initial_max_stream_data_bidi_local(100000);
    config.set_initial_max_stream_data_bidi_remote(100000);
    config.set_initial_max_streams_bidi(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1);

    let client_addr = test_utils::Pipe::client_addr();
    let server_addr = test_utils::Pipe::server_addr();
    let spoofed_client_addr = "127.0.0.1:6666".parse().unwrap();

    const DATA_BYTES: usize = 24000;
    let buf = [42; DATA_BYTES];
    let mut recv_buf = [0; DATA_BYTES];
    let send1_bytes = pipe.server.stream_send(1, &buf, true).unwrap();
    assert_eq!(send1_bytes, match cc_algorithm_name {
        #[cfg(feature = "openssl")]
        "bbr2" => 13966,
        #[cfg(not(feature = "openssl"))]
        "bbr2" => 13880,
        #[cfg(feature = "openssl")]
        "bbr2_gcongestion" => 13966,
        #[cfg(not(feature = "openssl"))]
        "bbr2_gcongestion" => 13880,
        _ => 12000,
    });
    assert_eq!(
        test_utils::process_flight(
            &mut pipe.client,
            test_utils::emit_flight(&mut pipe.server).unwrap()
        ),
        Ok(())
    );
    let (rcv_data_1, _) = pipe.client.stream_recv(1, &mut recv_buf).unwrap();

    // Fake the source address of client.
    let mut faked_addr_flight =
        test_utils::emit_flight(&mut pipe.client).unwrap();
    faked_addr_flight
        .iter_mut()
        .for_each(|(_, si)| si.from = spoofed_client_addr);
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, faked_addr_flight),
        Ok(())
    );
    assert_eq!(
        pipe.server.stream_send(1, &buf[send1_bytes..], true),
        Ok(24000 - send1_bytes)
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::ReusedSourceConnectionId(
            0,
            (server_addr, client_addr),
            (server_addr, spoofed_client_addr)
        ))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, spoofed_client_addr))
    );

    assert_eq!(
        pipe.server.is_path_validated(server_addr, client_addr),
        Ok(true)
    );
    assert_eq!(
        pipe.server
            .is_path_validated(server_addr, spoofed_client_addr),
        Ok(false)
    );

    // The client creates the PATH CHALLENGE, but it is always lost.
    test_utils::emit_flight(&mut pipe.server).unwrap();

    // Wait until probing timer expires. Since the RTT is very low,
    // wait a bit more.
    let probed_pid = pipe
        .server
        .paths
        .path_id_from_addrs(&(server_addr, spoofed_client_addr))
        .unwrap();
    let probe_instant = pipe
        .server
        .paths
        .get(probed_pid)
        .unwrap()
        .recovery
        .loss_detection_timer()
        .unwrap();
    let timer = probe_instant.duration_since(Instant::now());
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.server.on_timeout();

    // Because of the small ACK size, the server cannot send more to the
    // client. Fallback on the previous active path.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::FailedValidation(
            server_addr,
            spoofed_client_addr
        ))
    );

    assert_eq!(
        pipe.server.is_path_validated(server_addr, client_addr),
        Ok(true)
    );
    assert_eq!(
        pipe.server
            .is_path_validated(server_addr, spoofed_client_addr),
        Ok(false)
    );

    let server_active_path = pipe.server.paths.get_active().unwrap();
    assert_eq!(server_active_path.local_addr(), server_addr);
    assert_eq!(server_active_path.peer_addr(), client_addr);
    assert_eq!(pipe.advance(), Ok(()));
    let (rcv_data_2, fin) = pipe.client.stream_recv(1, &mut recv_buf).unwrap();
    assert!(fin);
    assert_eq!(rcv_data_1 + rcv_data_2, DATA_BYTES);
}

#[rstest]
fn consecutive_non_ack_eliciting(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut buf = [0; 65535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends a bunch of PING frames, causing server to ACK (ACKs aren't
    // ack-eliciting)
    let frames = [frame::Frame::Ping { mtu_probe: None }];
    let pkt_type = Type::Short;
    for _ in 0..24 {
        let len = pipe
            .send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap();
        assert!(len > 0);

        let frames =
            test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
        assert!(
            frames
                .iter()
                .all(|frame| matches!(frame, frame::Frame::ACK { .. })),
            "ACK only"
        );
    }

    // After 24 non-ack-eliciting, an ACK is explicitly elicited with a PING
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();
    assert!(len > 0);

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, frame::Frame::Ping { mtu_probe: None })),
        "found a PING"
    );
}

#[rstest]
fn send_ack_eliciting_causes_ping(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    // First establish a connection
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Queue a PING frame
    pipe.server.send_ack_eliciting().unwrap();

    // Make sure ping is sent
    let mut buf = [0; 1500];
    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
    let mut iter = frames.iter();

    assert_eq!(iter.next(), Some(&frame::Frame::Ping { mtu_probe: None }));
}

#[rstest]
fn send_ack_eliciting_no_ping(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    // First establish a connection
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Queue a PING frame
    pipe.server.send_ack_eliciting().unwrap();

    // Send a stream frame, which is ACK-eliciting to make sure the ping is
    // not sent
    assert_eq!(pipe.server.stream_send(1, b"a", false), Ok(1));

    // Make sure ping is not sent
    let mut buf = [0; 1500];
    let (len, _) = pipe.server.send(&mut buf).unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();
    let mut iter = frames.iter();

    assert!(matches!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 1,
            data: _
        })
    ));
    assert!(iter.next().is_none());
}

/// Tests that streams do not keep being "writable" after being collected
/// on reset.
#[rstest]
fn stop_sending_stream_send_after_reset_stream_ack(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut b = [0; 15];

    let mut buf = [0; 65535];

    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_initial_max_data(999999999);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(1000);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.streams.len(), 0);
    assert_eq!(pipe.server.readable().len(), 0);
    assert_eq!(pipe.server.writable().len(), 0);

    // Client opens a load of streams
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(8, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(12, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(16, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(20, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(24, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(28, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(32, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(36, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server iterators are populated
    let mut r = pipe.server.readable();
    assert_eq!(r.len(), 10);
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), Some(8));
    assert_eq!(r.next(), Some(12));
    assert_eq!(r.next(), Some(16));
    assert_eq!(r.next(), Some(20));
    assert_eq!(r.next(), Some(24));
    assert_eq!(r.next(), Some(28));
    assert_eq!(r.next(), Some(32));
    assert_eq!(r.next(), Some(36));

    assert_eq!(r.next(), None);

    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 10);
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), Some(4));
    assert_eq!(w.next(), Some(8));
    assert_eq!(w.next(), Some(12));
    assert_eq!(w.next(), Some(16));
    assert_eq!(w.next(), Some(20));
    assert_eq!(w.next(), Some(24));
    assert_eq!(w.next(), Some(28));
    assert_eq!(w.next(), Some(32));
    assert_eq!(w.next(), Some(36));
    assert_eq!(w.next(), None);

    // Read one stream
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((5, true)));
    assert!(pipe.server.stream_finished(0));

    assert_eq!(pipe.server.readable().len(), 9);
    assert_eq!(pipe.server.writable().len(), 10);

    assert_eq!(pipe.server.stream_writable(0, 0), Ok(true));

    // Server sends data on stream 0, until blocked.
    while pipe.server.stream_send(0, b"world", false) != Err(Error::Done) {
        assert_eq!(pipe.advance(), Ok(()));
    }

    assert_eq!(pipe.server.writable().len(), 9);
    assert_eq!(pipe.server.stream_writable(0, 0), Ok(true));

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    // Server sent a RESET_STREAM frame in response.
    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 30,
        })
    );

    // Stream 0 is now writable in order to make apps aware of STOP_SENDING
    // via returning an error.
    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 10);

    assert!(w.any(|s| s == 0));
    assert_eq!(
        pipe.server.stream_writable(0, 1),
        Err(Error::StreamStopped(42))
    );

    // Returning `StreamStopped` causes the stream to be collected.
    assert_eq!(pipe.server.streams.len(), 9);
    assert_eq!(pipe.server.writable().len(), 9);

    // Client acks RESET_STREAM frame.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..12);

    let frames = [frame::Frame::ACK {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));

    // Stream is collected on the server after RESET_STREAM is acked.
    assert_eq!(pipe.server.streams.len(), 9);

    // Sending STOP_SENDING again shouldn't trigger RESET_STREAM again.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let len = pipe
        .send_pkt_to_server(pkt_type, &frames, &mut buf)
        .unwrap();

    let frames =
        test_utils::decode_pkt(&mut pipe.client, &mut buf[..len]).unwrap();

    assert_eq!(frames.len(), 1);

    match frames.first() {
        Some(frame::Frame::ACK { .. }) => (),

        f => panic!("expected ACK frame, got {f:?}"),
    };

    assert_eq!(pipe.server.streams.len(), 9);

    // Stream 0 has been collected and must not be writable anymore.
    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 9);
    assert!(!w.any(|s| s == 0));

    // If we called send before the client ACK of reset stream, it would
    // have failed with StreamStopped.
    assert_eq!(pipe.server.stream_send(0, b"world", true), Err(Error::Done),);

    // Stream 0 is still not writable.
    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 9);
    assert!(!w.any(|s| s == 0));
}

#[rstest]
fn challenge_no_cids(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_active_connection_id_limit(4);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe =
        test_utils::Pipe::with_config_and_scid_lengths(&mut config, 16, 16)
            .unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Server send CIDs to client
    let mut server_cids = Vec::new();
    for _ in 0..2 {
        let (cid, reset_token) = test_utils::create_cid_and_reset_token(16);
        pipe.server
            .new_scid(&cid, reset_token, true)
            .expect("server issue cid");
        server_cids.push(cid);
    }
    assert_eq!(pipe.advance(), Ok(()));

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse().unwrap();

    // Client probes path before sending CIDs (simulating race condition)
    let frames = [frame::Frame::PathChallenge {
        data: [0, 1, 2, 3, 4, 5, 6, 7],
    }];
    let mut pkt_buf = [0u8; 1500];
    let mut b = octets::OctetsMut::with_slice(&mut pkt_buf);
    let epoch = Type::Short.to_epoch().unwrap();
    let crypto_ctx = &mut pipe.client.crypto_ctx[epoch];
    let pn = pipe.client.next_pkt_num;
    let pn_len = 4;

    let hdr = Header {
        ty: Type::Short,
        version: pipe.client.version,
        dcid: server_cids[0].clone(),
        scid: ConnectionId::from_ref(&[5, 4, 3, 2, 1]),
        pkt_num: 0,
        pkt_num_len: pn_len,
        token: pipe.client.token.clone(),
        versions: None,
        key_phase: pipe.client.key_phase,
    };
    hdr.to_bytes(&mut b).expect("encode header");
    let payload_len = frames.iter().fold(0, |acc, x| acc + x.wire_len());
    b.put_u32(pn as u32).expect("put pn");

    let payload_offset = b.off();

    for frame in frames {
        frame.to_bytes(&mut b).expect("encode frames");
    }

    let aead = crypto_ctx.crypto_seal.as_ref().expect("crypto seal");

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )
    .expect("packet encrypt");
    pipe.client.next_pkt_num += 1;

    pipe.server
        .recv(&mut pkt_buf[..written], RecvInfo {
            to: server_addr,
            from: client_addr_2,
        })
        .expect("server receive path challenge");

    // Show that the new path is not considered a destination path by quiche
    assert!(!pipe
        .server
        .paths_iter(server_addr)
        .any(|path| path == client_addr_2));
}

#[rstest]
fn pmtud_probe_success(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm_name(cc_algorithm_name).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_application_protos(&[b"proto1"]).unwrap();
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Send probe and let it be acknowledged
    assert_eq!(pipe.advance(), Ok(()));

    // Verify probing is disabled after successful probe
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap();
    assert!(!pmtud.should_probe());

    // Verify MTU was updated
    let current_mtu = pmtud.get_current_mtu();
    assert_eq!(current_mtu, 1400);

    let path_stats = pipe.client.path_stats().next().unwrap();
    assert_eq!(path_stats.pmtu, current_mtu);
}

#[rstest]
/// This test verifies that multiple send() calls after handshake completion
/// only generate one PMTUD probe packet, not multiple identical probes.
fn pmtud_no_duplicate_probes(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm_name(cc_algorithm_name).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Verify PMTUD is enabled and ready to probe
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap();
    assert!(pmtud.should_probe());
    let initial_probe_size = pmtud.get_probe_size();
    assert_eq!(initial_probe_size, 1400);

    let mut frames: Vec<frame::Frame> = Vec::new();
    for _ in 0..2 {
        let mut buf = [0; 1400];
        let (len, _) = pipe.client.send(&mut buf).unwrap();
        frames.append(
            test_utils::decode_pkt(&mut pipe.server, &mut buf[..len])
                .unwrap()
                .as_mut(),
        );
    }

    assert_eq!(frames.len(), 3);
    assert!(matches!(frames[0], frame::Frame::ACK { .. }));
    assert!(matches!(frames[1], frame::Frame::Padding { .. }));
    assert!(matches!(frames[2], frame::Frame::Ping { .. }));

    let mut buf = [0; 1400];
    assert_eq!(pipe.client.send(&mut buf).unwrap_err(), Error::Done);

    // Verify probe flag was reset after sending
    assert!(!pipe
        .client
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap()
        .should_probe());
}

#[rstest]
/// Test that PMTUD retries with smaller probe size after loss
fn pmtud_probe_retry_after_loss(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm_name(cc_algorithm_name).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_application_protos(&[b"proto1"]).unwrap();
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);

    let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));

    // Get initial probe size
    let active_path = pipe.client.paths.get_active_mut().unwrap();
    let initial_probe_size = active_path.pmtud.as_mut().unwrap().get_probe_size();
    assert_eq!(initial_probe_size, 1400);

    // Send first probe
    let mut out = [0; 4096];
    // ACK frame
    let _ = pipe.client.send(&mut out).unwrap();
    // PING + PADDING frames
    let (len, _) = pipe.client.send(&mut out).unwrap();
    assert_eq!(len, 1400);

    // Verify probe flag was reset after sending
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap();
    assert!(!pmtud.should_probe());

    // Simulate probe loss
    pmtud.failed_probe(initial_probe_size);

    // Verify MTU is not updated
    assert_eq!(pmtud.get_current_mtu(), 1200);

    // Verify probe flag is re-enabled and size is reduced
    assert!(pmtud.should_probe());
    assert_eq!(pmtud.get_probe_size(), 1300);

    // Send second probe
    let mut out = [0; 4096];
    // PING + PADDING frames
    let (len, _) = pipe.client.send(&mut out).unwrap();
    assert_eq!(len, 1300);

    // Verify should_probe flag gets reset
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap();
    assert!(!pmtud.should_probe());

    // Simulate second probe loss
    pmtud.failed_probe(1300);

    // Verify MTU is not updated
    assert_eq!(pmtud.get_current_mtu(), 1200);

    // Verify probe flag is re-enabled and probe size is reduced
    assert!(pmtud.should_probe());
    // Third probe should be 1250 bytes which is halfway between 1200 and the
    // second probe size=1300.
    assert_eq!(pmtud.get_probe_size(), 1250);

    let path_stats = pipe.client.path_stats().next().unwrap();
    assert_eq!(path_stats.pmtu, 1200);

    // Make probes succeed til pmtu is found
    assert_eq!(pipe.advance(), Ok(()));

    let pmtud = pipe
        .client
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap();

    // MTU should finally update
    let current_mtu = pmtud.get_current_mtu();
    assert_eq!(current_mtu, 1299);

    // Verify should_probe gets reset
    assert!(!pmtud.should_probe());

    let path_stats = pipe.client.path_stats().next().unwrap();
    assert_eq!(path_stats.pmtu, current_mtu);
}

#[cfg(feature = "boringssl-boring-crate")]
#[rstest]
fn enable_pmtud_mid_handshake(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    // Manually construct `SslContextBuilder` for the server so we can enable
    // PMTUD during the handshake.
    let mut server_tls_ctx_builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .unwrap();
    server_tls_ctx_builder
        .set_certificate_chain_file("examples/cert.crt")
        .unwrap();
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", boring::ssl::SslFiletype::PEM)
        .unwrap();
    server_tls_ctx_builder.set_select_certificate_callback(|mut hello| {
        <Connection>::set_discover_pmtu_in_handshake(hello.ssl_mut(), true)
            .unwrap();

        Ok(())
    });

    let mut server_config = Config::with_boring_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )
    .unwrap();
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );

    let mut client_config = Config::new(PROTOCOL_VERSION).unwrap();
    client_config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    client_config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();

    for config in [&mut client_config, &mut server_config] {
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_initial_max_data(1000000);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
        config.set_max_send_udp_payload_size(1350);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )
    .unwrap();

    let active_path = pipe.server.paths.get_active_mut().unwrap();
    assert!(active_path.pmtud.is_none());

    assert_eq!(pipe.handshake(), Ok(()));

    let active_path = pipe.server.paths.get_active_mut().unwrap();
    assert!(active_path.pmtud.is_some());
    assert_eq!(active_path.pmtud.as_mut().unwrap().get_current_mtu(), 1200);

    assert_eq!(pipe.advance(), Ok(()));

    let current_mtu = pipe
        .server
        .paths
        .get_active_mut()
        .unwrap()
        .pmtud
        .as_mut()
        .unwrap()
        .get_current_mtu();
    assert_eq!(current_mtu, 1350);

    let path_stats = pipe.server.path_stats().next().unwrap();
    assert_eq!(path_stats.pmtu, current_mtu);
}

#[cfg(feature = "boringssl-boring-crate")]
#[rstest]
fn disable_pmtud_mid_handshake(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) {
    // Manually construct `SslContextBuilder` for the server so we can disable
    // PMTUD during the handshake.
    let mut server_tls_ctx_builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .unwrap();
    server_tls_ctx_builder
        .set_certificate_chain_file("examples/cert.crt")
        .unwrap();
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", boring::ssl::SslFiletype::PEM)
        .unwrap();
    server_tls_ctx_builder.set_select_certificate_callback(|mut hello| {
        <Connection>::set_discover_pmtu_in_handshake(hello.ssl_mut(), false)
            .unwrap();

        Ok(())
    });

    let mut server_config = Config::with_boring_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )
    .unwrap();
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );

    let mut client_config = Config::new(PROTOCOL_VERSION).unwrap();
    client_config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    client_config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();

    for config in [&mut client_config, &mut server_config] {
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_initial_max_data(1000000);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
        config.set_max_send_udp_payload_size(1350);
        config.discover_pmtu(true);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )
    .unwrap();

    let active_path = pipe.server.paths.get_active_mut().unwrap();
    assert!(active_path.pmtud.is_some());

    assert_eq!(pipe.handshake(), Ok(()));

    let active_path = pipe.server.paths.get_active_mut().unwrap();
    assert!(active_path.pmtud.is_none());

    assert_eq!(pipe.advance(), Ok(()));

    let active_path = pipe.server.paths.get_active_mut().unwrap();
    assert!(active_path.pmtud.is_none());
}

#[rstest]
fn configuration_values_are_limited_to_max_varint() {
    let mut config = Config::new(0x1).unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    let v = octets::MAX_VAR_INT + 1;
    let uv = v as usize;
    config.set_max_idle_timeout(v);
    config.set_max_recv_udp_payload_size(uv);
    config.set_initial_max_data(v);
    config.set_initial_max_stream_data_bidi_local(v);
    config.set_initial_max_stream_data_bidi_remote(v);
    config.set_initial_max_stream_data_uni(v);
    config.set_initial_max_streams_bidi(v);
    config.set_initial_max_streams_uni(v);
    config.set_ack_delay_exponent(v);
    config.set_max_ack_delay(v);
    config.set_active_connection_id_limit(v);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();
    assert_eq!(
        pipe.client.local_transport_params.max_idle_timeout,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.max_udp_payload_size,
        cmp::min(octets::MAX_VAR_INT, uv as u64)
    );
    assert_eq!(
        pipe.client.local_transport_params.initial_max_data,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client
            .local_transport_params
            .initial_max_stream_data_bidi_local,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client
            .local_transport_params
            .initial_max_stream_data_bidi_remote,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client
            .local_transport_params
            .initial_max_stream_data_uni,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.initial_max_streams_bidi,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.initial_max_streams_uni,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.ack_delay_exponent,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.active_conn_id_limit,
        octets::MAX_VAR_INT
    );

    // It's fine that this will fail with an error. We just want to ensure we
    // do not panic because of too large values that we try to encode via varint.
    assert_eq!(pipe.handshake(), Err(Error::InvalidTransportParam));
}

#[rstest]
fn send_av_token() {
    let mut pipe = test_utils::Pipe::new("cubic").unwrap();

    let avt_data = Vec::from([0xa; 20]);

    pipe.server.send_new_token(avt_data.clone());

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Server sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // Even though AVT was enqueued, it must not be sent in this flight
    let received_token = pipe.client.take_token_for_path(test_utils::Pipe::client_addr(), test_utils::Pipe::server_addr()).unwrap();

    assert!(received_token.is_none());

    // Client sends Handshake packet and completes handshake.
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();

    test_utils::process_flight(&mut pipe.server, flight).unwrap();

    // Server completes and confirms handshake, and sends HANDSHAKE_DONE & NEW_TOKEN
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    // AVT should now be sent
    let received_token = pipe.client.take_token_for_path(test_utils::Pipe::client_addr(), test_utils::Pipe::server_addr()).unwrap().unwrap();

    assert_eq!(&avt_data[..], &received_token[..]);
}

#[rstest]
fn send_multiple_av_tokens() {
    let mut pipe = test_utils::Pipe::new("cubic").unwrap();

    // Big AVT, where only 1 fits per packet
    let avt_data = Vec::from([0xc; 1100]);

    assert_eq!(pipe.handshake(), Ok(()));

    pipe.server.send_new_token(avt_data.clone());
    pipe.server.send_new_token(avt_data.clone());

    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert!(flight.len() > 1);
    test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let received_token = pipe.client.take_token_for_path(test_utils::Pipe::client_addr(), test_utils::Pipe::server_addr()).unwrap().unwrap();
    assert_eq!(&avt_data[..], &received_token[..]);

    let received_token = pipe.client.take_token_for_path(test_utils::Pipe::client_addr(), test_utils::Pipe::server_addr()).unwrap().unwrap();
    assert_eq!(&avt_data[..], &received_token[..]);

    let received_token = pipe.client.take_token_for_path(test_utils::Pipe::client_addr(), test_utils::Pipe::server_addr()).unwrap();
    assert!(received_token.is_none());
}

#[rstest]
fn prevalidate_address() {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name("cubic"), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert.crt").unwrap();
    config.load_priv_key_from_pem_file("examples/cert.key").unwrap();
    config.set_application_protos(&[b"proto1", b"proto2"]).unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.set_ack_delay_exponent(8);

    config.set_handshake_path_verified();

    let pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();
    assert!(pipe.server.paths.get_active().unwrap().verified_peer_address);

    // On reuse of config object: Reset handshake path verified status
    let pipe = test_utils::Pipe::with_server_config(&mut config).unwrap();
    assert!(!pipe.server.paths.get_active().unwrap().verified_peer_address);
}

#[rstest]
fn client_send_av_token() {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    assert_eq!(config.set_cc_algorithm_name("cubic"), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert.crt").unwrap();
    config.load_priv_key_from_pem_file("examples/cert.key").unwrap();
    config.set_application_protos(&[b"proto1", b"proto2"]).unwrap();
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.set_ack_delay_exponent(8);

    let avt = Vec::from([0xa; 20]);

    config.set_address_verification_token(&avt);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config).unwrap();

    let token = pipe.client.token.clone().unwrap();

    assert_eq!(&token[..], &avt[..]);


    let mut buf = [0; 65535];

    // Client sends Initial.
    let (len, _) = pipe.client.send(&mut buf).unwrap();

    // Server receives client's Initial and sends own Initial and Handshake
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
    let _flight = test_utils::emit_flight(&mut pipe.server).unwrap();

    let mut b = octets::OctetsMut::with_slice(&mut buf);
    let hdr = Header::from_bytes(&mut b, pipe.client.source_id().len()).unwrap();

    assert_eq!(hdr.ty, Type::Initial);
    assert!(hdr.token.is_some());
    assert_eq!(&hdr.token.unwrap()[..], &avt[..]);

    assert!(!pipe.server.paths.get_active().unwrap().verified_peer_address);
}
