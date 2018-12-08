// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

use std::cmp;
use std::mem;
use std::time;

use std::collections::hash_map;
use std::collections::HashMap;

pub const VERSION_DRAFT15: u32 = 0xff00_000f;

const CLIENT_INITIAL_MIN_LEN: usize = 1200;

// TODO: calculate draining timer as 3 * RTO
const DRAINING_TIMEOUT: time::Duration = time::Duration::from_millis(200);

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NoError,
    Again,
    Done,
    BufferTooShort,
    UnknownVersion,
    InvalidFrame,
    InvalidPacket,
    InvalidState,
    InvalidStreamState,
    InvalidTransportParam,
    CryptoFail,
    TlsFail,
    FlowControl,
}

impl Error {
    pub fn to_wire(&self) -> u16 {
        match self {
            Error::NoError => 0x0,
            Error::InvalidFrame => 0x7,
            Error::InvalidStreamState => 0x5,
            Error::InvalidTransportParam => 0x8,
            Error::CryptoFail => 0x100,
            Error::TlsFail => 0x100,
            Error::Again => 0x0,
            Error::Done => 0x0,
            Error::FlowControl => 0x3,
            _ => 0xa,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Accept,
    Connect,
}

pub struct Config {
    local_transport_params: TransportParams,

    version: u32,

    tls_ctx: tls::Context,
}

impl Config {
    pub fn new(version: u32, tp: &TransportParams) -> Result<Config> {
        let tls_ctx = tls::Context::new().map_err(|_| Error::TlsFail)?;

        Ok(Config {
            local_transport_params: tp.clone(),
            version,
            tls_ctx,
        })
    }

    pub fn load_cert_chain_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.use_certificate_chain_file(file)
                    .map_err(|_| Error::TlsFail)
    }

    pub fn load_priv_key_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.use_privkey_file(file)
                    .map_err(|_| Error::TlsFail)
    }

    pub fn verify_peer(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify);
    }

    pub fn log_keys(&mut self) {
        self.tls_ctx.enable_keylog();
    }
}

pub struct Connection {
    version: u32,

    dcid: Vec<u8>,
    scid: Vec<u8>,

    initial: packet::PktNumSpace,
    handshake: packet::PktNumSpace,
    application: packet::PktNumSpace,

    peer_transport_params: TransportParams,

    local_transport_params: TransportParams,

    tls_state: tls::Handshake,

    recovery: recovery::Recovery,

    rx_data: usize,
    max_rx_data: usize,
    new_max_rx_data: usize,

    tx_data: usize,
    max_tx_data: usize,

    streams: HashMap<u64, stream::Stream>,

    error: Option<u16>,

    app_error: Option<u16>,
    app_reason: Vec<u8>,

    idle_timer: Option<time::Instant>,

    draining_timer: Option<time::Instant>,

    is_server: bool,

    derived_initial_secrets: bool,

    did_version_negotiation: bool,

    got_peer_conn_id: bool,

    handshake_completed: bool,

    draining: bool,

    closed: bool,
}

impl Connection {
    fn new(scid: &[u8], config: &mut Config, role: Role) -> Result<Box<Connection>> {
        let tls = config.tls_ctx.new_handshake().map_err(|_| Error::TlsFail)?;

        let max_rx_data = config.local_transport_params.initial_max_data;

        let is_server = role == Role::Accept;

        let mut conn = Box::new(Connection {
            version: config.version,

            dcid: Vec::new(),
            scid: scid.to_vec(),

            initial: packet::PktNumSpace::new(packet::Type::Initial,
                                              crypto::Level::Initial),
            handshake: packet::PktNumSpace::new(packet::Type::Handshake,
                                                crypto::Level::Handshake),
            application: packet::PktNumSpace::new(packet::Type::Application,
                                                  crypto::Level::Application),

            peer_transport_params: TransportParams::default(),

            local_transport_params: config.local_transport_params.clone(),

            tls_state: tls,

            recovery: recovery::Recovery::default(),

            rx_data: 0,
            max_rx_data: max_rx_data as usize,
            new_max_rx_data: max_rx_data as usize,

            tx_data: 0,
            max_tx_data: 0,

            streams: HashMap::new(),

            error: None,

            app_error: None,
            app_reason: Vec::new(),

            idle_timer: None,

            draining_timer: None,

            is_server,

            derived_initial_secrets: false,

            did_version_negotiation: false,

            got_peer_conn_id: false,

            handshake_completed: false,

            draining: false,

            closed: false,
        });

        conn.tls_state.init(&conn).map_err(|_| Error::TlsFail)?;

        // Derive initial secrets for the client. We can do this here because
        // we already generated the random destination connection ID.
        if !is_server {
            let mut dcid: [u8; 16] = [0; 16];
            rand::rand_bytes(&mut dcid[..]);

            let (aead_open, aead_seal) =
                crypto::derive_initial_key_material(&dcid, conn.is_server)?;

            conn.dcid.extend_from_slice(&dcid);

            conn.initial.crypto_open = Some(aead_open);
            conn.initial.crypto_seal = Some(aead_seal);

            conn.derived_initial_secrets = true;
        }

        Ok(conn)
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let now = time::Instant::now();

        if buf.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.draining {
            return Err(Error::Done);
        }

        let trace_id = self.trace_id();

        self.do_handshake()?;

        let is_closing = self.error.is_some() || self.app_error.is_some();

        if is_closing {
            return Err(Error::Done);
        }

        let mut b = octets::Bytes::new(buf);

        let hdr = packet::Header::from_bytes(&mut b, self.scid.len())?;

        if hdr.ty == packet::Type::VersionNegotiation {
            // Version negotiation packet can only be sent by the server.
            if self.is_server {
                return Err(Error::InvalidPacket);
            }

            // Forbid duplicate version negotiation.
            if self.did_version_negotiation {
                return Err(Error::InvalidState);
            }

            trace!("{} rx pkt {:?}", trace_id, hdr);

            let versions = match hdr.versions {
                Some(ref v) => v,
                None => return Err(Error::InvalidPacket),
            };

            let mut new_version = 0;
            for v in versions.iter() {
                if *v == VERSION_DRAFT15 {
                    new_version = *v;
                }
            }

            // We don't support any of the versions offfered.
            if new_version == 0 {
                return Err(Error::UnknownVersion);
            }

            self.version = new_version;
            self.did_version_negotiation = true;

            // Reset connection state to force sending another Initial packet.
            self.got_peer_conn_id = false;
            self.initial.clear();
            self.tls_state.clear()
                .map_err(|_| Error::TlsFail)?;

            return Ok(b.off());
        }

        if hdr.ty != packet::Type::Application && hdr.version != self.version {
            return Err(Error::UnknownVersion);
        }

        // Long header packets have an explicit payload length, but short
        // packets don't so just use the remaining capacity in the buffer.
        let payload_len = if hdr.ty == packet::Type::Application {
            b.cap()
        } else  {
            b.get_varint()? as usize
        };

        if b.cap() < payload_len {
            return Err(Error::BufferTooShort);
        }

        if !self.is_server && !self.got_peer_conn_id {
            // Replace the randomly generated destination connection ID with
            // the one supplied by the server.
            self.dcid.resize(hdr.scid.len(), 0);
            self.dcid.copy_from_slice(&hdr.scid);

            self.got_peer_conn_id = true;
        }

        // Derive initial secrets on the server.
        if !self.derived_initial_secrets {
            let (aead_open, aead_seal) =
                crypto::derive_initial_key_material(&hdr.dcid,
                                                    self.is_server)?;

            self.initial.crypto_open = Some(aead_open);
            self.initial.crypto_seal = Some(aead_seal);

            self.derived_initial_secrets = true;

            self.dcid.extend_from_slice(&hdr.scid);
            self.got_peer_conn_id = true;
        }

        // Select packet number space context based on the input packet type.
        let space = match hdr.ty {
            packet::Type::Initial => &mut self.initial,

            packet::Type::Handshake => &mut self.handshake,

            packet::Type::Application => &mut self.application,

            _ => return Err(Error::InvalidPacket),
        };

        let aead = match space.crypto_open {
            Some(ref v) => v,
            None        => return Err(Error::InvalidState),
        };

        let (pn, pn_len) = packet::decrypt_pkt_num(&mut b, &aead)?;
        b.skip(pn_len)?;

        let pn = packet::decode_pkt_num(space.largest_rx_pkt_num, pn, pn_len)?;

        trace!("{} rx pkt {:?} len={} pn={}", trace_id, hdr, payload_len, pn);

        let payload_offset = b.off();

        let (header, mut payload) = b.split_at(payload_offset)?;

        let payload_len = {
            let mut ciphertext = payload.peek_bytes(payload_len - pn_len)?;
            aead.open_with_u64_counter(pn, header.as_ref(), ciphertext.as_mut())?
        };

        let mut payload = payload.get_bytes(payload_len)?;

        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK.
        let mut do_ack = false;

        // Process packet payload.
        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload)?;

            trace!("{} rx frm {:?}", trace_id, frame);

            match frame {
                frame::Frame::Padding { .. } => (),

                frame::Frame::ConnectionClose { .. } => {
                    self.draining = true;
                    self.draining_timer = Some(now + DRAINING_TIMEOUT);
                },

                frame::Frame::ApplicationClose { .. } => {
                    self.draining = true;
                    self.draining_timer = Some(now + DRAINING_TIMEOUT);
                },

                frame::Frame::MaxData { max } => {
                    self.max_tx_data = cmp::max(self.max_tx_data,
                                                max as usize);

                    do_ack = true;
                },

                frame::Frame::MaxStreamData { stream_id, max } => {
                    let max_rx_data = self.local_transport_params
                                          .initial_max_stream_data_bidi_remote as usize;
                    let max_tx_data = self.peer_transport_params
                                          .initial_max_stream_data_bidi_local as usize;

                    // Get existing stream or create a new one.
                    let stream = match self.streams.entry(stream_id) {
                        hash_map::Entry::Vacant(v) => {
                            // Peer is not supposed to create this stream.
                            if stream::is_local(stream_id, self.is_server) {
                                return Err(Error::InvalidStreamState);
                            }

                            // TODO: check max stream ID

                            let s = stream::Stream::new(max_rx_data, max_tx_data);
                            v.insert(s)
                        },

                        hash_map::Entry::Occupied(v) => v.into_mut(),
                    };

                    stream.send_max_data(max as usize);

                    do_ack = true;
                },

                // TODO: implement stream count limits
                frame::Frame::MaxStreamId { .. } => {
                    do_ack = true;
                },

                frame::Frame::Ping => {
                    do_ack = true;
                },

                // TODO: implement connection migration
                frame::Frame::NewConnectionId { .. } => {
                    do_ack = true;
                },

                // TODO: implement connection migration
                frame::Frame::RetireConnectionId { .. } => {
                    do_ack = true;
                },

                frame::Frame::StopSending { stream_id, .. } => {
                    // STOP_SENDING on a receive-only stream is a fatal error.
                    if !stream::is_local(stream_id, self.is_server) &&
                       !stream::is_bidi(stream_id) {
                        return Err(Error::InvalidPacket);
                    }

                    do_ack = true;
                },

                frame::Frame::ACK { ranges, ack_delay } => {
                    let ack_delay =
                        ack_delay << self.peer_transport_params.ack_delay_exponent;

                    self.recovery.on_ack_received(&ranges, ack_delay,
                                                  &mut space.flight,
                                                  now, &trace_id);
                },

                // TODO: implement stateless retry
                frame::Frame::NewToken { .. } => {
                    do_ack = true;
                },

                frame::Frame::Crypto { data } => {
                    // Push the data to the stream so it can be re-ordered.
                    space.crypto_stream.recv_push(data)?;

                    // Feed crypto data to the TLS state, if there's data
                    // available at the expected offset.
                    if space.crypto_stream.readable() {
                        let buf = space.crypto_stream.recv_pop()?;
                        let level = space.crypto_level;

                        self.tls_state.provide_data(level, &buf)
                                      .map_err(|_| Error::TlsFail)?;
                    }

                    do_ack = true;
                },

                frame::Frame::Stream { stream_id, data } => {
                    let max_rx_data = self.local_transport_params
                                          .initial_max_stream_data_bidi_remote as usize;
                    let max_tx_data = self.peer_transport_params
                                          .initial_max_stream_data_bidi_local as usize;

                    // Get existing stream or create a new one.
                    let stream = match self.streams.entry(stream_id) {
                        hash_map::Entry::Vacant(v) => {
                            // Peer is not supposed to create this stream.
                            if stream::is_local(stream_id, self.is_server) {
                                return Err(Error::InvalidStreamState);
                            }

                            // TODO: check max stream ID

                            let s = stream::Stream::new(max_rx_data, max_tx_data);
                            v.insert(s)
                        },

                        hash_map::Entry::Occupied(v) => v.into_mut(),
                    };

                    self.rx_data += data.len();

                    if self.tx_data > self.max_rx_data {
                        return Err(Error::FlowControl);
                    }

                    stream.recv_push(data)?;

                    do_ack = true;
                },
            }
        }

        for acked in space.flight.acked.drain(..) {
            match acked {
                frame::Frame::ACK { ranges, .. } => {
                    let largest_acked = ranges.largest().unwrap();
                    space.recv_pkt_num.remove_until(largest_acked);
                },

                _ => (),
            }
        }

        space.recv_pkt_num.push_item(pn);
        space.do_ack = cmp::max(space.do_ack, do_ack);

        space.largest_rx_pkt_num = cmp::max(space.largest_rx_pkt_num, pn);

        self.idle_timer =
            Some(now + time::Duration::from_secs(self.local_transport_params
                                                     .idle_timeout as u64));

        let read = payload_offset + payload_len + aead.alg().tag_len();
        Ok(read)
    }

    pub fn send(&mut self, out: &mut [u8]) -> Result<usize> {
        let now = time::Instant::now();

        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.draining {
            return Err(Error::Done);
        }

        let is_closing = self.error.is_some() || self.app_error.is_some();

        if !is_closing {
            self.do_handshake()?;
        }

        let max_pkt_len = self.peer_transport_params.max_packet_size as usize;

        // Cap output buffer to respect peer's max_packet_size limit.
        let avail = cmp::min(max_pkt_len, out.len());

        let mut b = octets::Bytes::new(&mut out[..avail]);

        let trace_id = self.trace_id();

        // Select packet number space context depending on whether there is
        // handshake data to send, whether there are packets to ACK, or in
        // the case of the application space, whether there are streams that
        // can be written or that needs to increase flow control credit.
        let space =
            // On error or probe, send packet in the latest space available.
            if self.error.is_some() || self.recovery.probes > 0 {
                match self.tls_state.get_write_level() {
                    crypto::Level::Initial     => &mut self.initial,
                    // TODO: implement 0-RTT
                    crypto::Level::ZeroRTT     => panic!("0-RTT not implemented"),
                    crypto::Level::Handshake   => &mut self.handshake,
                    crypto::Level::Application => &mut self.application,
                }
            } else if self.initial.ready() {
                &mut self.initial
            } else if self.handshake.ready() {
                &mut self.handshake
            } else if self.handshake_completed &&
                      (self.application.ready() ||
                       self.streams.values().any(|s| s.writable()) ||
                       self.streams.values().any(|s| s.more_credit())) {
                &mut self.application
            } else {
                return Err(Error::Done);
            };

        for lost in space.flight.lost.drain(..) {
            match lost {
                frame::Frame::Crypto { data } => {
                    space.crypto_stream.send_push_front(data)?;
                },

                frame::Frame::Stream { stream_id, data } => {
                    let stream = match self.streams.get_mut(&stream_id) {
                        Some(v) => v,
                        None => continue,
                    };

                    self.tx_data -= data.len();

                    stream.send_push_front(data)?;
                },

                frame::Frame::ACK { .. } => {
                    space.do_ack = true;
                },

                _ => (),
            }
        }

        let hdr = packet::Header {
            ty: space.pkt_type,
            version: self.version,
            flags: 0,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            token: None,
            versions: None,
        };

        // Calculate available space in the packet based on congestion window.
        let mut left = cmp::min(self.recovery.cwnd(), b.cap());

        hdr.to_bytes(&mut b)?;

        let pn = space.next_pkt_num;
        let pn_len = packet::pkt_num_len(pn)?;

        // Calculate payload length.
        let mut length = pn_len + space.overhead();

        if left < b.off() + length + 4 {
            return Err(Error::Done);
        }

        left -= b.off() + length + 4;

        let mut frames: Vec<frame::Frame> = Vec::new();

        // Create ACK frame.
        if space.do_ack {
            let frame = frame::Frame::ACK {
                ack_delay: 0,
                ranges: space.recv_pkt_num.clone(),
            };

            if frame.wire_len() <= left {
                space.do_ack = false;

                length += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);
            }
        }

        let mut retransmittable = false;
        let mut is_crypto = false;

        // Create MAX_DATA frame, when the new limit is at least double the
        // amount of data that can be received before blocking.
        if space.pkt_type == packet::Type::Application && !is_closing
            && (self.new_max_rx_data != self.max_rx_data &&
                self.new_max_rx_data / 2 > self.max_rx_data - self.rx_data)
        {
            let frame = frame::Frame::MaxData {
                max: self.new_max_rx_data as u64,
            };

            if frame.wire_len() <= left {
                self.max_rx_data = self.new_max_rx_data;

                length += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);

                retransmittable = true;
            }
        }

        // Create MAX_STREAM_DATA frames as needed.
        if space.pkt_type == packet::Type::Application && !is_closing {
            for (id, stream) in self.streams.iter_mut()
                                            .filter(|(_, s)| s.more_credit()) {
                let frame = frame::Frame::MaxStreamData {
                    stream_id: *id,
                    max: stream.recv_update_max_data() as u64,
                };

                if frame.wire_len() > left {
                    break;
                }

                length += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);

                retransmittable = true;
            }
        }

        // Create PING and PADDING for TLP.
        if self.recovery.probes > 0 && left >= 4 {
            let frame = frame::Frame::Ping;

            length += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            let frame = frame::Frame::Padding {
                len: 3,
            };

            length += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.recovery.probes -= 1;

            retransmittable = true;
        }

        // Create CONNECTION_CLOSE frame.
        if let Some(err) = self.error {
            let frame = frame::Frame::ConnectionClose {
                error_code: err,
                frame_type: 0,
                reason: Vec::new(),
            };

            length += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.draining = true;
            self.draining_timer = Some(now + DRAINING_TIMEOUT);
        }

        // Create APPLICAtiON_CLOSE frame.
        if let Some(err) = self.app_error {
            let frame = frame::Frame::ApplicationClose {
                error_code: err,
                reason: self.app_reason.clone(),
            };

            length += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.draining = true;
            self.draining_timer = Some(now + DRAINING_TIMEOUT);
        }

        // Create CRYPTO frame.
        if space.crypto_stream.writable() && !is_closing {
            let crypto_len = left - frame::MAX_CRYPTO_OVERHEAD;
            let crypto_buf = space.crypto_stream.send_pop(crypto_len)?;

            let frame = frame::Frame::Crypto {
                data: crypto_buf,
            };

            length += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            retransmittable = true;
            is_crypto = true;
        }

        // Pad the client's initial packet.
        if !self.is_server && space.pkt_type == packet::Type::Initial {
            let len: usize = cmp::min(CLIENT_INITIAL_MIN_LEN - length, left);

            let frame = frame::Frame::Padding {
                len,
            };

            length += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);
        }

        // Create a single STREAM frame for the first stream that is writable.
        if space.pkt_type == packet::Type::Application && !is_closing
            && self.max_tx_data > self.tx_data
            && left > frame::MAX_STREAM_OVERHEAD
        {
            for (id, stream) in self.streams.iter_mut()
                                            .filter(|(_, s)| s.writable()) {
                // Make sure we can fit the data in the packet.
                let stream_len = cmp::min(left - frame::MAX_STREAM_OVERHEAD,
                                          self.max_tx_data - self.tx_data);

                let stream_buf = stream.send_pop(stream_len)?;

                if stream_buf.is_empty() {
                    continue;
                }

                self.tx_data += stream_buf.len();

                let frame = frame::Frame::Stream {
                    stream_id: *id,
                    data: stream_buf,
                };

                length += frame.wire_len();

                frames.push(frame);

                retransmittable = true;
                break;
            }
        }

        if frames.is_empty() {
            return Err(Error::Done);
        }

        // Only long header packets have an explicit length field.
        if space.pkt_type != packet::Type::Application {
            b.put_varint(length as u64)?;
        }

        packet::encode_pkt_num(pn, &mut b)?;

        let payload_len = length - pn_len;

        let payload_offset = b.off();

        trace!("{} tx pkt {:?} len={} pn={}", trace_id, hdr, payload_len, pn);

        // Encode frames into the output packet.
        for frame in &frames {
            trace!("{} tx frm {:?}", trace_id, frame);

            frame.to_bytes(&mut b)?;
        }

        let aead = match space.crypto_seal {
            Some(ref v) => v,
            None        => return Err(Error::InvalidState),
        };

        let (mut header, mut payload) = b.split_at(payload_offset)?;

        // Encrypt + authenticate payload.
        let ciphertext = payload.slice(payload_len)?;
        aead.seal_with_u64_counter(pn, header.as_ref(), ciphertext)?;

        // Encrypt packet number.
        let sample = &ciphertext[4 - pn_len..16 + (4 - pn_len)];
        let pn_ciphertext = header.slice_last(pn_len)?;
        aead.xor_keystream(sample, pn_ciphertext)?;

        let written = payload_offset + payload_len;

        let sent = recovery::Sent::new(pn, frames, written, retransmittable,
                                       is_crypto, now);

        self.recovery.on_packet_sent(sent, &mut space.flight, now, &trace_id);

        space.next_pkt_num += 1;

        Ok(written)
    }

    pub fn stream_recv(&mut self, stream_id: u64) -> Result<stream::RangeBuf> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return Err(Error::InvalidStreamState),
        };

        if !stream.readable() {
            return Err(Error::Done);
        }

        let buf = stream.recv_pop()?;

        self.new_max_rx_data = self.max_rx_data + buf.len();

        Ok(buf)
    }

    pub fn stream_send(&mut self, stream_id: u64, buf: &[u8], fin: bool)
                                                            -> Result<usize> {
        // We can't write on the peer's unidirectional streams.
        if !stream::is_bidi(stream_id) &&
           !stream::is_local(stream_id, self.is_server) {
            return Err(Error::InvalidStreamState);
        }

        let max_rx_data = self.local_transport_params
                              .initial_max_stream_data_bidi_local as usize;
        let max_tx_data = self.peer_transport_params
                              .initial_max_stream_data_bidi_remote as usize;

        // Get existing stream or create a new one.
        let stream = match self.streams.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                if !stream::is_local(stream_id, self.is_server) {
                    return Err(Error::InvalidStreamState);
                }

                // TODO: check max stream ID

                let s = stream::Stream::new(max_rx_data, max_tx_data);
                v.insert(s)
            },

            hash_map::Entry::Occupied(v) => v.into_mut(),
        };

        // TODO: implement backpressure based on peer's flow control

        stream.send_push(buf, fin)?;

        Ok(buf.len())
    }

    pub fn stream_iter(&mut self) -> Readable {
        stream::Readable::new(&self.streams)
    }

    pub fn timeout(&self) -> Option<std::time::Instant> {
        if self.closed {
            return None;
        }

        if self.draining {
            return self.draining_timer;
        }

        if self.recovery.loss_detection_timer().is_some() {
            return self.recovery.loss_detection_timer();
        }

        if self.idle_timer.is_some() {
            return self.idle_timer;
        }

        None
    }

    pub fn on_timeout(&mut self) {
        let now = time::Instant::now();

        let trace_id = self.trace_id();

        if self.draining {
            if self.draining_timer.is_some() &&
               self.draining_timer.unwrap() <= now {
                trace!("{} draining timeout expired", trace_id);

                self.closed = true;
            }

            return;
        }

        if self.idle_timer.is_some() && self.idle_timer.unwrap() <= now {
            trace!("{} idle timeout expired", trace_id);

            self.closed = true;
            return;
        }

        if self.recovery.loss_detection_timer().is_some() &&
           self.recovery.loss_detection_timer().unwrap() <= now {
            trace!("{} loss detection timeout expired", trace_id);

            self.recovery.on_loss_detection_timer(&mut self.initial.flight,
                                                  &mut self.handshake.flight,
                                                  &mut self.application.flight,
                                                  now, &trace_id);
            return;
        }
    }

    pub fn close(&mut self, app: bool, err: u16, reason: &[u8]) -> Result<()> {
        if self.draining {
            return Err(Error::Done);
        }

        if self.error.is_some() || self.app_error.is_some() {
            return Err(Error::Done);
        }

        if app {
            self.app_error = Some(err);
            self.app_reason.extend_from_slice(reason);
        } else {
            self.error = Some(err);
        }

        Ok(())
    }

    pub fn trace_id(&self) -> String {
        let vec: Vec<String> = self.scid.as_slice().iter()
                                   .map(|b| format!("{:02x}", b))
                                   .collect();

        vec.join("")
    }

    pub fn is_established(&self) -> bool {
        self.handshake_completed
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn do_handshake(&mut self) -> Result<()> {
        if !self.handshake_completed {
            match self.tls_state.do_handshake() {
                Ok(_) => {
                    // Handshake is complete!
                    self.handshake_completed = true;

                    let mut raw_params =
                        self.tls_state.get_quic_transport_params()
                                      .map_err(|_| Error::TlsFail)?;

                    let peer_params = TransportParams::decode(&mut raw_params,
                                                              self.version,
                                                              self.is_server)?;

                    self.max_tx_data = peer_params.initial_max_data as usize;

                    let max_ack_delay = u64::from(peer_params.max_ack_delay);
                    self.recovery.max_ack_delay =
                        time::Duration::from_millis(max_ack_delay);

                    self.peer_transport_params = peer_params;

                    trace!("{} connection established: cipher={:?} params={:?}",
                           self.trace_id(),
                           self.application.cipher(),
                           self.peer_transport_params);
                },

                Err(tls::Error::TlsFail) => {
                    // If we have an error to send (e.g. a TLS alert), ignore
                    // the error so we send a CONNECTION_CLOSE to the peer.
                    if self.error.is_none() {
                        return Err(Error::TlsFail);
                    }
                },

                Err(tls::Error::WantRead)         => (), // continue
                Err(tls::Error::WantWrite)        => (), // continue
                Err(tls::Error::SyscallFail)      => return Err(Error::TlsFail),
                Err(tls::Error::PendingOperation) => return Err(Error::Again),
            }
        }

        Ok(())
    }
}

pub fn accept(scid: &[u8], config: &mut Config) -> Result<Box<Connection>> {
    let conn = Connection::new(scid, config, Role::Accept)?;

    Ok(conn)
}

pub fn connect(server_name: Option<&str>, scid: &[u8], config: &mut Config)
                                                -> Result<Box<Connection>> {
    let conn = Connection::new(scid, config, Role::Connect)?;

    if server_name.is_some() {
        conn.tls_state.set_host_name(server_name.unwrap())
                      .map_err(|_| Error::TlsFail)?;
    }

    Ok(conn)
}

pub fn negotiate_version(hdr: &packet::Header, out: &mut [u8]) -> Result<usize> {
    packet::negotiate_version(hdr, out)
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransportParams {
    pub idle_timeout: u16,
    pub initial_max_data: u32,
    pub initial_max_bidi_streams: u16,
    pub initial_max_uni_streams: u16,
    pub max_packet_size: u16,
    pub ack_delay_exponent: u8,
    pub disable_migration: bool,
    pub max_ack_delay: u8,
    pub initial_max_stream_data_bidi_local: u32,
    pub initial_max_stream_data_bidi_remote: u32,
    pub initial_max_stream_data_uni: u32,
    pub stateless_reset_token_present: bool,
    pub stateless_reset_token: [u8; 16],
    // pub preferred_address: ...
}

impl TransportParams {
    fn decode(buf: &mut [u8], _version: u32, is_server: bool)
                                                -> Result<TransportParams> {
        let mut b = octets::Bytes::new(buf);

        // TODO: check version
        let _tp_version = b.get_u32()?;

        if !is_server {
            // Ignore supported versions from server.
            b.get_bytes_with_u8_length()?;
        }

        let mut tp = TransportParams::default();

        let mut params = b.get_bytes_with_u16_length()?;

        while params.cap() > 0 {
            let id = params.get_u16()?;

            let mut val = params.get_bytes_with_u16_length()?;

            // TODO: forbid duplicated param

            match id {
                0x0000 => {
                    tp.initial_max_stream_data_bidi_local = val.get_u32()?;
                },

                0x0001 => {
                    tp.initial_max_data = val.get_u32()?;
                },

                0x0002 => {
                    tp.initial_max_bidi_streams = val.get_u16()?;
                },

                0x0003 => {
                    tp.idle_timeout = val.get_u16()?;
                },

                0x0004 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    // TODO: parse preferred_address
                },

                0x0005 => {
                    tp.max_packet_size = val.get_u16()?;
                },

                0x0006 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    let token = val.get_bytes(16)?;
                    tp.stateless_reset_token.copy_from_slice(token.as_ref());
                    tp.stateless_reset_token_present = true;
                },

                0x0007 => {
                    tp.ack_delay_exponent = val.get_u8()?;
                },

                0x0008 => {
                    tp.initial_max_uni_streams = val.get_u16()?;
                },

                0x0009 => {
                    tp.disable_migration = true;
                },

                0x000a => {
                    tp.initial_max_stream_data_bidi_remote = val.get_u32()?;
                },

                0x000b => {
                    tp.initial_max_stream_data_uni = val.get_u32()?;
                },

                0x000c => {
                    tp.max_ack_delay = val.get_u8()?;
                },

                0x000d => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    // TODO: implement address validation
                },

                // Ignore unknown parameters.
                _ => (),
            }
        }

        Ok(tp)
    }

    fn encode<'a>(tp: &TransportParams, version: u32, is_server: bool,
                  out: &'a mut [u8]) -> Result<&'a mut [u8]> {
        // TODO: implement put_with_length API for octets::Bytes to avoid this copy
        let mut params: [u8; 128] = [0; 128];

        let params_len = {
            let mut b = octets::Bytes::new(&mut params);

            if tp.idle_timeout != 0 {
                b.put_u16(0x0003)?;
                b.put_u16(mem::size_of::<u16>() as u16)?;
                b.put_u16(tp.idle_timeout)?;
            }

            if tp.initial_max_data != 0 {
                b.put_u16(0x0001)?;
                b.put_u16(mem::size_of::<u32>() as u16)?;
                b.put_u32(tp.initial_max_data)?;
            }

            if tp.initial_max_bidi_streams != 0 {
                b.put_u16(0x0002)?;
                b.put_u16(mem::size_of::<u16>() as u16)?;
                b.put_u16(tp.initial_max_bidi_streams)?;
            }

            if tp.initial_max_uni_streams != 0 {
                b.put_u16(0x0008)?;
                b.put_u16(mem::size_of::<u16>() as u16)?;
                b.put_u16(tp.initial_max_uni_streams)?;
            }

            if tp.max_packet_size != 0 {
                b.put_u16(0x0005)?;
                b.put_u16(mem::size_of::<u16>() as u16)?;
                b.put_u16(tp.max_packet_size)?;
            }

            if tp.ack_delay_exponent != 0 {
                b.put_u16(0x0007)?;
                b.put_u16(mem::size_of::<u8>() as u16)?;
                b.put_u8(tp.ack_delay_exponent)?;
            }

            if tp.disable_migration {
                b.put_u16(0x0009)?;
                b.put_u16(0)?;
            }

            if tp.initial_max_stream_data_bidi_local != 0 {
                b.put_u16(0x0000)?;
                b.put_u16(mem::size_of::<u32>() as u16)?;
                b.put_u32(tp.initial_max_stream_data_bidi_local)?;
            }

            if tp.initial_max_stream_data_bidi_remote != 0 {
                b.put_u16(0x000a)?;
                b.put_u16(mem::size_of::<u32>() as u16)?;
                b.put_u32(tp.initial_max_stream_data_bidi_remote)?;
            }

            if tp.initial_max_stream_data_uni != 0 {
                b.put_u16(0x000b)?;
                b.put_u16(mem::size_of::<u32>() as u16)?;
                b.put_u32(tp.initial_max_stream_data_uni)?;
            }

            if is_server && tp.stateless_reset_token_present {
                b.put_u16(0x0006)?;
                b.put_u16(tp.stateless_reset_token.len() as u16)?;
                b.put_bytes(&tp.stateless_reset_token)?;
            }

            b.off()
        };

        let out_len = {
            let mut b = octets::Bytes::new(out);

            b.put_u32(version)?;

            if is_server {
                b.put_u8(mem::size_of::<u32>() as u8)?;
                b.put_u32(version)?;
            };

            b.put_u16(params_len as u16)?;
            b.put_bytes(&params[..params_len])?;

            b.off()
        };

        Ok(&mut out[..out_len])
    }
}

impl Default for TransportParams {
    fn default() -> TransportParams {
        TransportParams {
            idle_timeout: 0,
            initial_max_data: 0,
            initial_max_bidi_streams: 0,
            initial_max_uni_streams: 0,
            max_packet_size: 1205,
            ack_delay_exponent: 3,
            disable_migration: false,
            max_ack_delay: 25,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            stateless_reset_token_present: false,
            stateless_reset_token: [0; 16],
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_params() {
        let tp = TransportParams {
            idle_timeout: 30,
            initial_max_data: 424_645_563,
            initial_max_bidi_streams: 12_231,
            initial_max_uni_streams: 18_473,
            max_packet_size: 23_421,
            ack_delay_exponent: 123,
            disable_migration: true,
            max_ack_delay: 25,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            stateless_reset_token_present: true,
            stateless_reset_token: [0xba; 16],
        };

        let mut raw_params: [u8; 256] = [42; 256];
        let mut raw_params = TransportParams::encode(&tp, VERSION_DRAFT15, true,
                                              &mut raw_params).unwrap();
        assert_eq!(raw_params.len(), 96);

        let new_tp = TransportParams::decode(&mut raw_params, VERSION_DRAFT15,
                                             false).unwrap();

        assert_eq!(new_tp, tp);
    }

    fn create_conn(is_server: bool) -> Box<Connection> {
        let tp = TransportParams::default();

        let mut scid: [u8; 16] = [0; 16];
        rand::rand_bytes(&mut scid[..]);

        let role = if is_server {
            Role::Accept
        } else {
            Role::Connect
        };

        let mut config = Config::new(VERSION_DRAFT15, &tp).unwrap();
        config.load_cert_chain_from_pem_file("examples/cert.crt").unwrap();
        config.load_priv_key_from_pem_file("examples/cert.key").unwrap();
        config.verify_peer(false);

        Connection::new(&scid, &mut config, role).unwrap()
    }

    fn recv_send(conn: &mut Connection, buf: &mut [u8], len: usize) -> usize {
        let mut left = len;

        while left > 0 {
            let read = conn.recv(&mut buf[len - left..len]).unwrap();

            left -= read;
        }

        let mut off = 0;

        while off < buf.len() {
            let write = match conn.send(&mut buf[off..]) {
                Ok(v)   => v,

                Err(Error::Done) => { break; },

                Err(e)  => panic!("SEND FAILED: {:?}", e),
            };

            off += write;
        }

        off
    }

    #[test]
    fn self_handshake() {
        let mut buf = [0; 65535];

        let mut cln = create_conn(false);
        let mut srv = create_conn(true);

        let mut len = cln.send(&mut buf).unwrap();

        while !cln.is_established() && !srv.is_established() {
            len = recv_send(&mut srv, &mut buf, len);
            len = recv_send(&mut cln, &mut buf, len);
        }

        assert!(true);
    }
}

pub use crate::stream::RangeBuf;
pub use crate::stream::Readable;
pub use crate::packet::Header;
pub use crate::packet::Type;

mod crypto;
mod frame;
mod octets;
mod packet;
mod rand;
mod ranges;
mod recovery;
mod stream;
mod tls;
