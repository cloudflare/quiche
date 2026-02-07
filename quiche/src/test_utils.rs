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

use smallvec::smallvec;

use crate::recovery::Sent;

pub struct Pipe {
    pub client: Connection,
    pub server: Connection,
}

impl Pipe {
    pub fn new(cc_algorithm_name: &str) -> Result<Pipe> {
        let mut config = Config::new(PROTOCOL_VERSION)?;
        assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
        config.load_cert_chain_from_pem_file("examples/cert.crt")?;
        config.load_priv_key_from_pem_file("examples/cert.key")?;
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

        Pipe::with_config(&mut config)
    }

    pub fn client_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    pub fn server_addr() -> SocketAddr {
        "127.0.0.1:4321".parse().unwrap()
    }

    pub fn with_config(config: &mut Config) -> Result<Pipe> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        Ok(Pipe {
            client: connect(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                config,
            )?,
            server: accept(&server_scid, None, server_addr, client_addr, config)?,
        })
    }

    pub fn with_config_and_scid_lengths(
        config: &mut Config, client_scid_len: usize, server_scid_len: usize,
    ) -> Result<Pipe> {
        let mut client_scid = vec![0; client_scid_len];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = vec![0; server_scid_len];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        Ok(Pipe {
            client: connect(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                config,
            )?,
            server: accept(&server_scid, None, server_addr, client_addr, config)?,
        })
    }

    pub fn with_client_config(client_config: &mut Config) -> Result<Pipe> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        let mut config = Config::new(PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file("examples/cert.crt")?;
        config.load_priv_key_from_pem_file("examples/cert.key")?;
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_ack_delay_exponent(8);

        Ok(Pipe {
            client: connect(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                client_config,
            )?,
            server: accept(
                &server_scid,
                None,
                server_addr,
                client_addr,
                &mut config,
            )?,
        })
    }

    pub fn with_server_config(server_config: &mut Config) -> Result<Pipe> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        let mut config = Config::new(PROTOCOL_VERSION)?;
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_ack_delay_exponent(8);

        Ok(Pipe {
            client: connect(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                &mut config,
            )?,
            server: accept(
                &server_scid,
                None,
                server_addr,
                client_addr,
                server_config,
            )?,
        })
    }

    pub fn with_client_and_server_config(
        client_config: &mut Config, server_config: &mut Config,
    ) -> Result<Pipe> {
        let mut client_scid = [0; 16];
        rand::rand_bytes(&mut client_scid[..]);
        let client_scid = ConnectionId::from_ref(&client_scid);
        let client_addr = Pipe::client_addr();

        let mut server_scid = [0; 16];
        rand::rand_bytes(&mut server_scid[..]);
        let server_scid = ConnectionId::from_ref(&server_scid);
        let server_addr = Pipe::server_addr();

        Ok(Pipe {
            client: connect(
                Some("quic.tech"),
                &client_scid,
                client_addr,
                server_addr,
                client_config,
            )?,
            server: accept(
                &server_scid,
                None,
                server_addr,
                client_addr,
                server_config,
            )?,
        })
    }

    pub fn handshake(&mut self) -> Result<()> {
        while !self.client.is_established() || !self.server.is_established() {
            let flight = emit_flight(&mut self.client)?;
            process_flight(&mut self.server, flight)?;

            let flight = emit_flight(&mut self.server)?;
            process_flight(&mut self.client, flight)?;
        }

        Ok(())
    }

    pub fn advance(&mut self) -> Result<()> {
        let mut client_done = false;
        let mut server_done = false;

        while !client_done || !server_done {
            match emit_flight(&mut self.client) {
                Ok(flight) => process_flight(&mut self.server, flight)?,

                Err(Error::Done) => client_done = true,

                Err(e) => return Err(e),
            };

            match emit_flight(&mut self.server) {
                Ok(flight) => process_flight(&mut self.client, flight)?,

                Err(Error::Done) => server_done = true,

                Err(e) => return Err(e),
            };
        }

        Ok(())
    }

    pub fn client_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let server_path = &self.server.paths.get_active().unwrap();
        let info = RecvInfo {
            to: server_path.peer_addr(),
            from: server_path.local_addr(),
        };

        self.client.recv(buf, info)
    }

    pub fn server_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let client_path = &self.client.paths.get_active().unwrap();
        let info = RecvInfo {
            to: client_path.peer_addr(),
            from: client_path.local_addr(),
        };

        self.server.recv(buf, info)
    }

    pub fn send_pkt_to_server(
        &mut self, pkt_type: Type, frames: &[frame::Frame], buf: &mut [u8],
    ) -> Result<usize> {
        let written = encode_pkt(&mut self.client, pkt_type, frames, buf)?;
        recv_send(&mut self.server, buf, written)
    }

    pub fn client_update_key(&mut self) -> Result<()> {
        let crypto_ctx = &mut self.client.crypto_ctx[packet::Epoch::Application];

        let open_next = crypto_ctx
            .crypto_open
            .as_ref()
            .unwrap()
            .derive_next_packet_key()
            .unwrap();

        let seal_next = crypto_ctx
            .crypto_seal
            .as_ref()
            .unwrap()
            .derive_next_packet_key()?;

        let open_prev = crypto_ctx.crypto_open.replace(open_next);
        crypto_ctx.crypto_seal.replace(seal_next);

        crypto_ctx.key_update = Some(packet::KeyUpdate {
            crypto_open: open_prev.unwrap(),
            pn_on_update: self.client.next_pkt_num,
            update_acked: true,
            timer: Instant::now(),
        });

        self.client.key_phase = !self.client.key_phase;

        Ok(())
    }
}

pub fn recv_send<F: BufFactory>(
    conn: &mut Connection<F>, buf: &mut [u8], len: usize,
) -> Result<usize> {
    let active_path = conn.paths.get_active()?;
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };

    conn.recv(&mut buf[..len], info)?;

    let mut off = 0;

    match conn.send(&mut buf[off..]) {
        Ok((write, _)) => off += write,

        Err(Error::Done) => (),

        Err(e) => return Err(e),
    }

    Ok(off)
}

pub fn run_work_loop_round_start_hook(conn: &mut Connection) {
    let has_flushable_data = conn.has_flushable_data();
    conn.work_loop_round_start(has_flushable_data, &Instant::now());
}

pub fn process_flight(
    conn: &mut Connection, flight: Vec<(Vec<u8>, SendInfo)>,
) -> Result<()> {
    run_work_loop_round_start_hook(conn);

    for (mut pkt, si) in flight {
        let info = RecvInfo {
            to: si.to,
            from: si.from,
        };

        conn.recv(&mut pkt, info)?;
    }

    Ok(())
}

pub fn emit_flight_with_max_buffer(
    conn: &mut Connection, out_size: usize, from: Option<SocketAddr>,
    to: Option<SocketAddr>,
) -> Result<Vec<(Vec<u8>, SendInfo)>> {
    let mut flight = Vec::new();

    loop {
        let mut out = vec![0u8; out_size];

        let info = match conn.send_on_path(&mut out, from, to) {
            Ok((written, info)) => {
                out.truncate(written);
                info
            },

            Err(Error::Done) => break,

            Err(e) => return Err(e),
        };

        flight.push((out, info));
    }

    if flight.is_empty() {
        return Err(Error::Done);
    }

    Ok(flight)
}

pub fn emit_flight_on_path(
    conn: &mut Connection, from: Option<SocketAddr>, to: Option<SocketAddr>,
) -> Result<Vec<(Vec<u8>, SendInfo)>> {
    emit_flight_with_max_buffer(conn, 65535, from, to)
}

pub fn emit_flight(conn: &mut Connection) -> Result<Vec<(Vec<u8>, SendInfo)>> {
    emit_flight_on_path(conn, None, None)
}

pub fn encode_pkt(
    conn: &mut Connection, pkt_type: Type, frames: &[frame::Frame],
    buf: &mut [u8],
) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(buf);

    let epoch = pkt_type.to_epoch()?;

    let crypto_ctx = &mut conn.crypto_ctx[epoch];

    let pn = conn.next_pkt_num;
    let pn_len = 4;

    let send_path = conn.paths.get_active()?;
    let active_dcid_seq = send_path
        .active_dcid_seq
        .as_ref()
        .ok_or(Error::InvalidState)?;
    let active_scid_seq = send_path
        .active_scid_seq
        .as_ref()
        .ok_or(Error::InvalidState)?;

    let hdr = Header {
        ty: pkt_type,
        version: conn.version,
        dcid: ConnectionId::from_ref(
            conn.ids.get_dcid(*active_dcid_seq)?.cid.as_ref(),
        ),
        scid: ConnectionId::from_ref(
            conn.ids.get_scid(*active_scid_seq)?.cid.as_ref(),
        ),
        pkt_num: pn,
        pkt_num_len: pn_len,
        token: conn.token.clone(),
        versions: None,
        key_phase: conn.key_phase,
    };

    hdr.to_bytes(&mut b)?;

    let payload_len = frames.iter().fold(0, |acc, x| acc + x.wire_len());

    if pkt_type != Type::Short {
        let len = pn_len + payload_len + crypto_ctx.crypto_overhead().unwrap();
        b.put_varint(len as u64)?;
    }

    // Always encode packet number in 4 bytes, to allow encoding packets
    // with empty payloads.
    b.put_u32(pn as u32)?;

    let payload_offset = b.off();

    for frame in frames {
        frame.to_bytes(&mut b)?;
    }

    let aead = match crypto_ctx.crypto_seal {
        Some(ref v) => v,
        None => return Err(Error::InvalidState),
    };

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )?;

    conn.next_pkt_num += 1;

    Ok(written)
}

pub fn decode_pkt(
    conn: &mut Connection, buf: &mut [u8],
) -> Result<Vec<frame::Frame>> {
    let mut b = octets::OctetsMut::with_slice(buf);

    let mut hdr = Header::from_bytes(&mut b, conn.source_id().len()).unwrap();

    let epoch = hdr.ty.to_epoch()?;

    let aead = conn.crypto_ctx[epoch].crypto_open.as_ref().unwrap();

    let payload_len = b.cap();

    packet::decrypt_hdr(&mut b, &mut hdr, aead).unwrap();

    let pn = packet::decode_pkt_num(
        conn.pkt_num_spaces[epoch].largest_rx_pkt_num,
        hdr.pkt_num,
        hdr.pkt_num_len,
    );

    let mut payload =
        packet::decrypt_pkt(&mut b, pn, hdr.pkt_num_len, payload_len, aead)
            .unwrap();

    let mut frames = Vec::new();

    while payload.cap() > 0 {
        let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;
        frames.push(frame);
    }

    Ok(frames)
}

pub fn create_cid_and_reset_token(
    cid_len: usize,
) -> (ConnectionId<'static>, u128) {
    let mut cid = vec![0; cid_len];
    rand::rand_bytes(&mut cid[..]);
    let cid = ConnectionId::from_ref(&cid).into_owned();

    let mut reset_token = [0; 16];
    rand::rand_bytes(&mut reset_token);
    let reset_token = u128::from_be_bytes(reset_token);

    (cid, reset_token)
}

pub fn helper_packet_sent(pkt_num: u64, now: Instant, size: usize) -> Sent {
    Sent {
        pkt_num,
        frames: smallvec![],
        time_sent: now,
        time_acked: None,
        time_lost: None,
        size,
        ack_eliciting: true,
        in_flight: true,
        delivered: 0,
        delivered_time: now,
        first_sent_time: now,
        is_app_limited: false,
        tx_in_flight: 0,
        lost: 0,
        has_data: true,
        is_pmtud_probe: false,
    }
}

// Helper function for testing either stream receive or discard.
pub fn stream_recv_discard(
    conn: &mut Connection, discard: bool, stream_id: u64,
) -> Result<(usize, bool)> {
    let mut buf = [0; 65535];
    if discard {
        conn.stream_discard(stream_id, 65535)
    } else {
        conn.stream_recv(stream_id, &mut buf)
    }
}
