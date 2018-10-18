// Copyright (c) 2018, Alessandro Ghedini
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

extern crate core;
extern crate libc;
extern crate ring;

#[macro_use]
extern crate lazy_static;

use std::cmp;
use std::mem;
use std::collections::HashMap;

pub const VERSION_DRAFT14: u32 = 0xff00000e;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(PartialEq, Clone, Debug)]
pub enum Error {
    WrongForm,
    UnknownVersion,
    UnknownPacket,
    UnknownFrame,
    UnknownStream,
    BufferTooShort,
    InvalidPacket,
    InvalidState,
    CryptoFail,
    TlsFail,
    Again,
    NothingToDo,
}

#[derive(PartialEq, Copy, Clone, Debug)]
enum State {
    Idle,
    Initial,
    Handshake,
    Established,
    // Closing,
    Draining,
}

#[derive(Copy, Clone, Debug)]
pub struct Config<'a> {
    pub version: u32,

    pub local_conn_id: &'a [u8],

    pub local_transport_params: &'a TransportParams,

    pub tls_server_name: &'a str,
    pub tls_certificate: &'a str,
    pub tls_certificate_key: &'a str,
}

pub struct Conn {
    state: State,

    version: u32,

    dcid: Vec<u8>,
    scid: Vec<u8>,

    initial: packet::PktNumSpace,
    handshake: packet::PktNumSpace,
    application: packet::PktNumSpace,

    peer_transport_params: Option<TransportParams>,

    local_transport_params: TransportParams,

    tls_state: tls::State,

    streams: HashMap<u64, stream::Stream>,

    is_server: bool,
}

pub fn accept(config: Config) -> Result<Box<Conn>> {
    Conn::new(config, true)
}

impl Conn {
    fn new_with_tls(config: Config, tls: tls::State, is_server: bool)
                                                    -> Result<Box<Conn>> {
        let conn = Box::new(Conn {
            state: State::Idle,

            version: config.version,

            dcid: Vec::new(),
            scid: config.local_conn_id.to_vec(),

            initial: packet::PktNumSpace::new(packet::Type::Initial,
                                              crypto::Level::Initial),
            handshake: packet::PktNumSpace::new(packet::Type::Handshake,
                                                crypto::Level::Handshake),
            application: packet::PktNumSpace::new(packet::Type::Application,
                                                  crypto::Level::Application),

            peer_transport_params: None,

            local_transport_params: config.local_transport_params.clone(),

            tls_state: tls,

            streams: HashMap::new(),

            is_server,
        });

        conn.tls_state.init_with_conn_extra(&conn, &config)
                      .map_err(|_e| Error::TlsFail)?;

        Ok(conn)
    }

    fn new(config: Config, is_server: bool) -> Result<Box<Conn>> {
        Conn::new_with_tls(config, tls::State::new(), is_server)
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::BufferTooShort);
        }

        let mut b = octets::Bytes::new(buf);

        let hdr = if !packet::has_long_header(b.peek_u8()?) {
            packet::Header::short_from_bytes(&mut b, self.scid.len())?
        } else {
            let hdr = packet::Header::long_from_bytes(&mut b)?;

            if hdr.version != self.version {
                return Err(Error::UnknownVersion);
            }

            hdr
        };

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

        // Select packet number space context.
        let space = match hdr.ty {
            packet::Type::Initial => {
                if self.state == State::Idle {
                    let (aead_open, aead_seal) =
                        crypto::derive_initial_key_material(&hdr.dcid,
                                                            self.is_server)?;

                    self.dcid.extend_from_slice(&hdr.scid);

                    self.initial.crypto_open = Some(aead_open);
                    self.initial.crypto_seal = Some(aead_seal);

                    self.state = State::Initial;
                }

                &mut self.initial
            },

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

        let payload_offset = b.off();

        let (header, mut payload) = b.split_at(payload_offset)?;

        let payload_len = {
            let mut ciphertext = payload.peek_bytes(payload_len - pn_len)?;
            packet::decrypt_pkt(ciphertext.as_mut(), pn, header.as_ref(), &aead)?
        };

        let mut payload = payload.get_bytes(payload_len)?;

        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK.
        let mut ack_only = true;

        // Process packet payload.
        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload)?;

            match frame {
                frame::Frame::Padding => (),

                frame::Frame::ConnectionClose { .. } => {
                    ack_only = false;

                    self.state = State::Draining;
                },

                frame::Frame::ApplicationClose { .. } => {
                    ack_only = false;

                    self.state = State::Draining;
                },

                frame::Frame::Ping => {
                    ack_only = false;
                },

                frame::Frame::NewConnectionId { .. } => {
                    ack_only = false;
                },

                // TODO: implement ack and retransmission.
                frame::Frame::ACK { .. } => (),

                frame::Frame::Crypto { offset: _, data } => {
                    match self.tls_state.provide_data(space.crypto_level,
                                                      data.as_ref()) {
                        Ok(_)  => (),
                        Err(_) => return Err(Error::TlsFail),
                    }

                    ack_only = false;
                },

                frame::Frame::Stream { stream_id, offset, data, fin: _ } => {
                    let stream = self.streams.entry(stream_id).or_insert_with(|| {
                        // TODO: enforce stream limits
                        stream::Stream::new()
                    });

                    // TODO: enforce flow control
                    stream.push_recv(data.as_ref(), offset as usize)?;

                    ack_only = false;
                },
            }
        }

        if !ack_only {
            space.need_ack.push(pn);
        }

        let read = payload_offset + payload_len + aead.tag_len();
        Ok(read)
    }

    pub fn send(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.state == State::Idle {
            return Err(Error::InvalidState);
        }

        self.do_handshake()?;

        let max_pkt_len = match self.peer_transport_params {
            Some(ref v) => v.max_packet_size as usize,
            None        => return Err(Error::InvalidState),
        };

        // Cap output buffer to respect peer's max_packet_size.
        let avail = cmp::min(max_pkt_len, out.len());

        let mut b = octets::Bytes::new(&mut out[..avail]);

        // Select packet number space context depending on whether there is
        // handshake data to send, or whether there are packets to ACK.
        let space =
            if self.initial.pending() > 0 ||
               self.initial.need_ack.len() > 0 {
                &mut self.initial
            } else if self.handshake.pending() > 0 ||
                      self.handshake.need_ack.len() > 0 {
                &mut self.handshake
            } else if (self.application.pending() > 0 ||
                       self.application.need_ack.len() > 0) &&
                      self.state == State::Established {
                &mut self.application
            } else {
                return Err(Error::NothingToDo);
            };

        let hdr = packet::Header {
            ty: space.pkt_type,
            version: self.version,
            flags: 0,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            token: None,
        };

        if space.pkt_type == packet::Type::Application {
            packet::Header::short_to_bytes(&hdr, &mut b)?;
        } else {
            packet::Header::long_to_bytes(&hdr, &mut b)?;
        }

        let pn = space.last_pkt_num;
        let pn_len = packet::pkt_num_len(pn)?;

        space.last_pkt_num += 1;

        // Calculate remaining available space for the payload, excluding
        // payload length, pkt num and AEAD oerhead..
        let left = b.cap() - 4 - pn_len - space.overhead();

        let mut frames: Vec<frame::Frame> = Vec::new();

        // Create ACK frame.
        if space.need_ack.len() > 0 {
            let frame = frame::Frame::ACK {
                largest_ack: space.need_ack.pop().unwrap(),
                ack_delay: 0,
            };

            frames.push(frame);
        }

        let overhead = space.overhead();

        // Create CRYPTO frame.
        if space.pending() > 0 {
            let crypto_len = cmp::min(left, space.pending());
            let crypto_off = space.crypto_offset;

            space.advance(crypto_len)?;

            let crypto_buf = &mut space.crypto_buf[crypto_off..crypto_len];

            let frame = frame::Frame::Crypto {
                offset: crypto_off as u64,
                data: octets::Bytes::new(crypto_buf),
            };

            frames.push(frame);
        }

        // Calculate payload length.
        let mut length = pn_len + overhead;

        for frame in &frames {
            length += frame.wire_len();
        }

        // Only long header packets have an explicit length field.
        if space.pkt_type != packet::Type::Application {
            b.put_varint(length as u64)?;
        }

        packet::encode_pkt_num(pn, &mut b)?;

        let payload_len = length - pn_len;

        let payload_offset = b.off();

        for frame in &frames {
            frame.to_bytes(&mut b)?;
        }

        let aead = match space.crypto_seal {
            Some(ref v) => v,
            None        => return Err(Error::InvalidState),
        };

        let (mut header, mut payload) = b.split_at(payload_offset)?;

        let ciphertext = payload.slice(payload_len)?;
        packet::encrypt_pkt(ciphertext, pn, header.as_ref(), aead)?;

        aead.xor_keystream(&ciphertext[4 - pn_len..16 + (4 - pn_len)],
                           header.slice_last(pn_len)?)?;

        let written = payload_offset + payload_len;
        Ok(written)
    }

    pub fn stream_recv(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<usize> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return Err(Error::UnknownStream),
        };

        if !stream.can_read() {
            return Ok(0);
        }

        stream.pop_recv(buf)
    }

    pub fn stream_send(&mut self, stream_id: u64, buf: &mut [u8], fin: bool,
                       out: &mut [u8]) -> Result<usize> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return Err(Error::UnknownStream),
        };

        // TODO: respect peer's flow control
        let offset = stream.push_send(buf)?;

        // TODO: refactor to avoid duplication with send()
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.state != State::Established {
            return Err(Error::InvalidState);
        }

        let max_pkt_len = match self.peer_transport_params {
            Some(ref v) => v.max_packet_size as usize,
            None        => return Err(Error::InvalidState),
        };

        // Cap output buffer to respect peer's max_packet_size.
        let avail = cmp::min(max_pkt_len, out.len());

        let mut b = octets::Bytes::new(&mut out[..avail]);

        // Select packet number space context depending on whether there is
        // handshake data to send, or whether there are packets to ACK.
        let space = &mut self.application;

        let hdr = packet::Header {
            ty: space.pkt_type,
            version: self.version,
            flags: 0,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            token: None,
        };

        packet::Header::short_to_bytes(&hdr, &mut b)?;

        let pn = space.last_pkt_num;
        let pn_len = packet::pkt_num_len(pn)?;

        space.last_pkt_num += 1;

        // Calculate remaining available space for the payload, excluding
        // payload length, pkt num and AEAD oerhead..
        let left = b.cap() - 4 - pn_len - space.overhead();

        let overhead = space.overhead();

        let stream_len = cmp::min(buf.len(), left);
        let stream_data = octets::Bytes::new(&mut buf[..stream_len]);

        // Create STREAM frame.
        let frame = frame::Frame::Stream {
            stream_id: stream_id,
            offset: offset as u64,
            data: stream_data,
            fin: fin,
        };

        // Calculate payload length.
        let length = pn_len + overhead + frame.wire_len();

        packet::encode_pkt_num(pn, &mut b)?;

        let payload_len = length - pn_len;

        let payload_offset = b.off();

        frame.to_bytes(&mut b)?;

        let aead = match space.crypto_seal {
            Some(ref v) => v,
            None        => return Err(Error::InvalidState),
        };

        let (mut header, mut payload) = b.split_at(payload_offset)?;

        let ciphertext = payload.slice(payload_len)?;
        packet::encrypt_pkt(ciphertext, pn, header.as_ref(), aead)?;

        aead.xor_keystream(&ciphertext[4 - pn_len..16 + (4 - pn_len)],
                           header.slice_last(pn_len)?)?;

        let written = payload_offset + payload_len;
        Ok(written)
    }

    pub fn stream_iter(&mut self) -> stream::StreamIterator {
        stream::StreamIterator::new(self.streams.iter())
    }

    fn do_handshake(&mut self) -> Result<()> {
        if self.state != State::Established {
            match self.tls_state.do_handshake() {
                Ok(_)                             => {
                    self.state = State::Established
                },

                Err(tls::Error::TlsFail)          => return Err(Error::TlsFail),
                Err(tls::Error::WantRead)         => (), // continue
                Err(tls::Error::WantWrite)        => (), // continue
                Err(tls::Error::SyscallFail)      => return Err(Error::TlsFail),
                Err(tls::Error::PendingOperation) => return Err(Error::Again),
            }
        }

        if self.state == State::Initial {
            let mut raw_params = self.tls_state.get_quic_transport_params()
                                               .map_err(|_e| Error::TlsFail)?;

            let peer_params = TransportParams::decode(&mut raw_params,
                                                      self.version,
                                                      self.is_server)?;

            self.peer_transport_params = Some(peer_params);

            self.state = State::Handshake;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TransportParams {
    pub idle_timeout: u16,
    pub initial_max_data: u32,
    pub initial_max_bidi_streams: u16,
    pub initial_max_uni_streams: u16,
    pub max_packet_size: u16,
    pub ack_delay_exponent: u8,
    pub disable_migration: bool,
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

        let mut tp = TransportParams {
            idle_timeout: 0,
            initial_max_data: 0,
            initial_max_bidi_streams: 0,
            initial_max_uni_streams: 0,
            max_packet_size: 65527,
            ack_delay_exponent: 3,
            disable_migration: false,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            stateless_reset_token_present: false,
            stateless_reset_token: [0; 16],
        };

        let mut params = b.get_bytes_with_u16_length()?;

        while params.cap() > 0 {
            let id = params.get_u16()?;

            let mut val = params.get_bytes_with_u16_length()?;

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
                    // TODO: parse preferred_address
                },

                0x0005 => {
                    tp.max_packet_size = val.get_u16()?;
                },

                0x0006 => {
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

            if tp.stateless_reset_token_present {
                b.put_u16(0x0006)?;
                b.put_u16(tp.stateless_reset_token.len() as u16)?;
                b.put_bytes(&tp.stateless_reset_token)?;
            }

            b.off()
        };

        let out_len = {
            let mut b = octets::Bytes::new(out);

            if is_server {
                b.put_u32(version)?;
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_params() {
        let tp = TransportParams {
            idle_timeout: 30,
            initial_max_data: 424645563,
            initial_max_bidi_streams: 12231,
            initial_max_uni_streams: 18473,
            max_packet_size: 23421,
            ack_delay_exponent: 123,
            disable_migration: true,
            initial_max_stream_data_bidi_local: 154323123,
            initial_max_stream_data_bidi_remote: 6587456,
            initial_max_stream_data_uni: 2461234,
            stateless_reset_token_present: true,
            stateless_reset_token: [0xba; 16],
        };

        let mut raw_params: [u8; 256] = [42; 256];
        let mut raw_params = TransportParams::encode(&tp, VERSION_DRAFT14, true,
                                              &mut raw_params).unwrap();
        assert_eq!(raw_params.len(), 96);

        let new_tp = TransportParams::decode(&mut raw_params, VERSION_DRAFT14,
                                             false).unwrap();

        assert_eq!(new_tp.idle_timeout, tp.idle_timeout);
        assert_eq!(new_tp.initial_max_data, tp.initial_max_data);
        assert_eq!(new_tp.initial_max_bidi_streams, tp.initial_max_bidi_streams);
        assert_eq!(new_tp.initial_max_uni_streams, tp.initial_max_uni_streams);
        assert_eq!(new_tp.max_packet_size, tp.max_packet_size);
        assert_eq!(new_tp.ack_delay_exponent, tp.ack_delay_exponent);
        assert_eq!(new_tp.disable_migration, tp.disable_migration);
        assert_eq!(new_tp.initial_max_stream_data_bidi_local,
                   tp.initial_max_stream_data_bidi_local);
        assert_eq!(new_tp.initial_max_stream_data_bidi_remote,
                   tp.initial_max_stream_data_bidi_remote);
        assert_eq!(new_tp.initial_max_stream_data_uni,
                   tp.initial_max_stream_data_uni);
        assert_eq!(new_tp.stateless_reset_token_present,
                   tp.stateless_reset_token_present);
        assert_eq!(new_tp.stateless_reset_token, tp.stateless_reset_token);
    }
}

pub mod packet;
pub mod rand;

mod crypto;
mod frame;
mod stream;
mod tls;
mod octets;
