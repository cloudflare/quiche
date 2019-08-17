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

use std::time;

use crate::Error;
use crate::Result;

use crate::crypto;
use crate::octets;
use crate::rand;
use crate::ranges;
use crate::stream;

const FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const KEY_PHASE_BIT: u8 = 0x04;

const TYPE_MASK: u8 = 0x30;
const PKT_NUM_MASK: u8 = 0x03;

pub const MAX_CID_LEN: u8 = 20;

const MAX_PKT_NUM_LEN: usize = 4;
const SAMPLE_LEN: usize = 16;

pub const EPOCH_INITIAL: usize = 0;
pub const EPOCH_HANDSHAKE: usize = 1;
pub const EPOCH_APPLICATION: usize = 2;
pub const EPOCH_COUNT: usize = 3;

/// Packet number space epoch.
///
/// This should only ever be one of `EPOCH_INITIAL`, `EPOCH_HANDSHAKE` or
/// `EPOCH_APPLICATION`, and can be used to index state specific to a packet
/// number space in `Connection` and `Recovery`.
pub type Epoch = usize;

/// QUIC packet type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type {
    /// Initial packet.
    Initial,

    /// Retry packet.
    Retry,

    /// Handshake packet.
    Handshake,

    /// 0-RTT packet.
    ZeroRTT,

    /// Version negotiation packet.
    VersionNegotiation,

    /// Short header packet.
    Application,
}

impl Type {
    pub(crate) fn from_epoch(e: Epoch) -> Type {
        match e {
            EPOCH_INITIAL => Type::Initial,

            EPOCH_HANDSHAKE => Type::Handshake,

            EPOCH_APPLICATION => Type::Application,

            _ => unreachable!(),
        }
    }

    pub(crate) fn to_epoch(self) -> Result<Epoch> {
        match self {
            Type::Initial => Ok(EPOCH_INITIAL),

            Type::ZeroRTT => Ok(EPOCH_APPLICATION),

            Type::Handshake => Ok(EPOCH_HANDSHAKE),

            Type::Application => Ok(EPOCH_APPLICATION),

            _ => Err(Error::InvalidPacket),
        }
    }
}

/// A QUIC packet's header.
#[derive(Clone, PartialEq)]
pub struct Header {
    /// The type of the packet.
    pub ty: Type,

    /// The version of the packet.
    pub version: u32,

    /// The destination connection ID of the packet.
    pub dcid: Vec<u8>,

    /// The source connection ID of the packet.
    pub scid: Vec<u8>,

    /// The original destination connection ID. Only present in `Retry`
    /// packets.
    pub odcid: Option<Vec<u8>>,

    /// The packet number. It's only meaningful after the header protection is
    /// removed.
    pub(crate) pkt_num: u64,

    /// The length of the packet number. It's only meaningful after the header
    /// protection is removed.
    pub(crate) pkt_num_len: usize,

    /// The address verification token of the packet. Only present in `Initial`
    /// and `Retry` packets.
    pub token: Option<Vec<u8>>,

    /// The list of versions in the packet. Only present in
    /// `VersionNegotiation` packets.
    pub versions: Option<Vec<u32>>,

    /// The key phase bit of the packet. It's only meaningful after the header
    /// protection is removed.
    pub(crate) key_phase: bool,
}

impl Header {
    /// Parses a QUIC packet header from the given buffer.
    ///
    /// The `dcid_len` parameter is the length of the destination connection ID,
    /// required to parse short header packets.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # const LOCAL_CONN_ID_LEN: usize = 16;
    /// # let mut buf = [0; 512];
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// let (len, src) = socket.recv_from(&mut buf).unwrap();
    ///
    /// let hdr = quiche::Header::from_slice(&mut buf[..len], LOCAL_CONN_ID_LEN)?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn from_slice(buf: &mut [u8], dcid_len: usize) -> Result<Header> {
        let mut b = octets::Octets::with_slice(buf);
        Header::from_bytes(&mut b, dcid_len)
    }

    pub(crate) fn from_bytes(
        b: &mut octets::Octets, dcid_len: usize,
    ) -> Result<Header> {
        let first = b.get_u8()?;

        if !Header::is_long(first) {
            // Decode short header.
            let dcid = b.get_bytes(dcid_len)?;

            return Ok(Header {
                ty: Type::Application,
                version: 0,
                dcid: dcid.to_vec(),
                scid: Vec::new(),
                odcid: None,
                pkt_num: 0,
                pkt_num_len: 0,
                token: None,
                versions: None,
                key_phase: false,
            });
        }

        // Decode long header.
        let version = b.get_u32()?;

        let ty = if version == 0 {
            Type::VersionNegotiation
        } else {
            match (first & TYPE_MASK) >> 4 {
                0x00 => Type::Initial,
                0x01 => Type::ZeroRTT,
                0x02 => Type::Handshake,
                0x03 => Type::Retry,
                _ => return Err(Error::InvalidPacket),
            }
        };

        let dcid_len = b.get_u8()?;
        if version == crate::PROTOCOL_VERSION && dcid_len > MAX_CID_LEN {
            return Err(Error::InvalidPacket);
        }
        let dcid = b.get_bytes(dcid_len as usize)?.to_vec();

        let scid_len = b.get_u8()?;
        if version == crate::PROTOCOL_VERSION && scid_len > MAX_CID_LEN {
            return Err(Error::InvalidPacket);
        }
        let scid = b.get_bytes(scid_len as usize)?.to_vec();

        // End of invariants.

        let mut odcid: Option<Vec<u8>> = None;
        let mut token: Option<Vec<u8>> = None;
        let mut versions: Option<Vec<u32>> = None;

        match ty {
            Type::Initial => {
                token = Some(b.get_bytes_with_varint_length()?.to_vec());
            },

            Type::Retry => {
                let odcid_len = b.get_u8()?;

                if odcid_len > MAX_CID_LEN {
                    return Err(Error::InvalidPacket);
                }

                odcid = Some(b.get_bytes(odcid_len as usize)?.to_vec());
                token = Some(b.to_vec());
            },

            Type::VersionNegotiation => {
                let mut list: Vec<u32> = Vec::new();

                while b.cap() > 0 {
                    let version = b.get_u32()?;
                    list.push(version);
                }

                versions = Some(list);
            },

            _ => (),
        };

        Ok(Header {
            ty,
            version,
            dcid,
            scid,
            odcid,
            pkt_num: 0,
            pkt_num_len: 0,
            token,
            versions,
            key_phase: false,
        })
    }

    pub(crate) fn to_bytes(&self, out: &mut octets::Octets) -> Result<()> {
        let mut first = 0;

        // Encode pkt num length.
        first |= self.pkt_num_len.saturating_sub(1) as u8;

        // Encode short header.
        if self.ty == Type::Application {
            // Unset form bit for short header.
            first &= !FORM_BIT;

            // Set fixed bit.
            first |= FIXED_BIT;

            // Set key phase bit.
            if self.key_phase {
                first |= KEY_PHASE_BIT;
            } else {
                first &= !KEY_PHASE_BIT;
            }

            out.put_u8(first)?;
            out.put_bytes(&self.dcid)?;

            return Ok(());
        }

        // Encode long header.
        let ty: u8 = match self.ty {
            Type::Initial => 0x00,
            Type::ZeroRTT => 0x01,
            Type::Handshake => 0x02,
            Type::Retry => 0x03,
            _ => return Err(Error::InvalidPacket),
        };

        first |= FORM_BIT | FIXED_BIT | (ty << 4);

        out.put_u8(first)?;

        out.put_u32(self.version)?;

        out.put_u8(self.dcid.len() as u8)?;
        out.put_bytes(&self.dcid)?;

        out.put_u8(self.scid.len() as u8)?;
        out.put_bytes(&self.scid)?;

        if self.ty == Type::Retry {
            let odcid = self.odcid.as_ref().unwrap();
            out.put_u8(odcid.len() as u8)?;
            out.put_bytes(odcid)?;
        }

        // Only Initial and Retry packets have a token.
        if self.ty == Type::Initial {
            match self.token {
                Some(ref v) => {
                    out.put_varint(v.len() as u64)?;
                    out.put_bytes(v)?;
                },

                // No token, so length = 0.
                None => {
                    out.put_varint(0)?;
                },
            }
        }

        // Retry packets don't have a token length.
        if self.ty == Type::Retry {
            out.put_bytes(self.token.as_ref().unwrap())?;
        }

        Ok(())
    }

    /// Returns true if the packet has a long header.
    ///
    /// The `b` parameter represents the first byte of the QUIC header.
    fn is_long(b: u8) -> bool {
        b & FORM_BIT != 0
    }
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.ty)?;

        if self.ty != Type::Application {
            write!(f, " version={:x}", self.version)?;
        }

        write!(f, " dcid=")?;
        for b in &self.dcid {
            write!(f, "{:02x}", b)?;
        }

        if self.ty != Type::Application {
            write!(f, " scid=")?;
            for b in &self.scid {
                write!(f, "{:02x}", b)?;
            }
        }

        if let Some(ref odcid) = self.odcid {
            write!(f, " odcid=")?;
            for b in odcid {
                write!(f, "{:02x}", b)?;
            }
        }

        if let Some(ref token) = self.token {
            write!(f, " token=")?;
            for b in token {
                write!(f, "{:02x}", b)?;
            }
        }

        if let Some(ref versions) = self.versions {
            write!(f, " versions={:x?}", versions)?;
        }

        if self.ty == Type::Application {
            write!(f, " key_phase={}", self.key_phase)?;
        }

        Ok(())
    }
}

pub fn pkt_num_len(pn: u64) -> Result<usize> {
    let len = if pn < u64::from(std::u8::MAX) {
        1
    } else if pn < u64::from(std::u16::MAX) {
        2
    } else if pn < u64::from(std::u32::MAX) {
        4
    } else {
        return Err(Error::InvalidPacket);
    };

    Ok(len)
}

pub fn decrypt_hdr(
    b: &mut octets::Octets, hdr: &mut Header, aead: &crypto::Open,
) -> Result<()> {
    let mut first = {
        let (first_buf, _) = b.split_at(1)?;
        first_buf.as_ref()[0]
    };

    let mut pn_and_sample = b.peek_bytes(MAX_PKT_NUM_LEN + SAMPLE_LEN)?;

    let (mut ciphertext, sample) =
        pn_and_sample.split_at(MAX_PKT_NUM_LEN).unwrap();

    let ciphertext = ciphertext.as_mut();

    let mask = aead.new_mask(sample.as_ref())?;

    if Header::is_long(first) {
        first ^= mask[0] & 0x0f;
    } else {
        first ^= mask[0] & 0x1f;
    }

    let pn_len = usize::from((first & PKT_NUM_MASK) + 1);

    let ciphertext = &mut ciphertext[..pn_len];

    for i in 0..pn_len {
        ciphertext[i] ^= mask[i + 1];
    }

    // Extract packet number corresponding to the decoded length.
    let pn = match pn_len {
        1 => u64::from(b.get_u8()?),

        2 => u64::from(b.get_u16()?),

        3 => u64::from(b.get_u24()?),

        4 => u64::from(b.get_u32()?),

        _ => return Err(Error::InvalidPacket),
    };

    // Write decrypted first byte back into the input buffer.
    let (mut first_buf, _) = b.split_at(1)?;
    first_buf.as_mut()[0] = first;

    hdr.pkt_num = pn;
    hdr.pkt_num_len = pn_len;

    if hdr.ty == Type::Application {
        hdr.key_phase = (first & KEY_PHASE_BIT) != 0;
    }

    Ok(())
}

pub fn decode_pkt_num(largest_pn: u64, truncated_pn: u64, pn_len: usize) -> u64 {
    let pn_nbits = pn_len * 8;
    let expected_pn = largest_pn + 1;
    let pn_win = 1 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

    if candidate_pn + pn_hwin <= expected_pn {
        return candidate_pn + pn_win;
    }

    if candidate_pn > expected_pn + pn_hwin && candidate_pn > pn_win {
        return candidate_pn - pn_win;
    }

    candidate_pn
}

pub fn decrypt_pkt<'a>(
    b: &'a mut octets::Octets, pn: u64, pn_len: usize, payload_len: usize,
    aead: &crypto::Open,
) -> Result<octets::Octets<'a>> {
    let payload_offset = b.off();

    let (header, mut payload) = b.split_at(payload_offset)?;

    let mut ciphertext = payload.peek_bytes(payload_len - pn_len)?;

    let payload_len =
        aead.open_with_u64_counter(pn, header.as_ref(), ciphertext.as_mut())?;

    Ok(b.get_bytes(payload_len)?)
}

pub fn encrypt_hdr(
    b: &mut octets::Octets, pn_len: usize, payload: &[u8], aead: &crypto::Seal,
) -> Result<()> {
    let sample = &payload[4 - pn_len..16 + (4 - pn_len)];

    let mask = aead.new_mask(sample)?;

    let (mut first, mut rest) = b.split_at(1)?;

    let first = first.as_mut();

    if Header::is_long(first[0]) {
        first[0] ^= mask[0] & 0x0f;
    } else {
        first[0] ^= mask[0] & 0x1f;
    }

    let pn_buf = rest.slice_last(pn_len)?;
    for i in 0..pn_len {
        pn_buf[i] ^= mask[i + 1];
    }

    Ok(())
}

pub fn encrypt_pkt(
    b: &mut octets::Octets, pn: u64, pn_len: usize, payload_len: usize,
    payload_offset: usize, aead: &crypto::Seal,
) -> Result<usize> {
    let (mut header, mut payload) = b.split_at(payload_offset)?;

    // Encrypt + authenticate payload.
    let ciphertext = payload.slice(payload_len)?;
    aead.seal_with_u64_counter(pn, header.as_ref(), ciphertext)?;

    encrypt_hdr(&mut header, pn_len, ciphertext, aead)?;

    Ok(payload_offset + payload_len)
}

pub fn encode_pkt_num(pn: u64, b: &mut octets::Octets) -> Result<()> {
    let len = pkt_num_len(pn)?;

    match len {
        1 => b.put_u8(pn as u8)?,

        2 => b.put_u16(pn as u16)?,

        3 => b.put_u24(pn as u32)?,

        4 => b.put_u32(pn as u32)?,

        _ => return Err(Error::InvalidPacket),
    };

    Ok(())
}

pub fn negotiate_version(
    scid: &[u8], dcid: &[u8], out: &mut [u8],
) -> Result<usize> {
    let mut b = octets::Octets::with_slice(out);

    let first = rand::rand_u8() | FORM_BIT;

    b.put_u8(first)?;
    b.put_u32(0)?;

    b.put_u8(scid.len() as u8)?;
    b.put_bytes(&scid)?;
    b.put_u8(dcid.len() as u8)?;
    b.put_bytes(&dcid)?;
    b.put_u32(crate::PROTOCOL_VERSION)?;

    Ok(b.off())
}

pub fn retry(
    scid: &[u8], dcid: &[u8], new_scid: &[u8], token: &[u8], out: &mut [u8],
) -> Result<usize> {
    let mut b = octets::Octets::with_slice(out);

    let hdr = Header {
        ty: Type::Retry,
        version: crate::PROTOCOL_VERSION,
        dcid: scid.to_vec(),
        scid: new_scid.to_vec(),
        pkt_num: 0,
        pkt_num_len: 0,
        odcid: Some(dcid.to_vec()),
        token: Some(token.to_vec()),
        versions: None,
        key_phase: false,
    };

    hdr.to_bytes(&mut b)?;

    Ok(b.off())
}

pub struct PktNumSpace {
    pub largest_rx_pkt_num: u64,

    pub largest_rx_pkt_time: time::Instant,

    pub next_pkt_num: u64,

    pub recv_pkt_need_ack: ranges::RangeSet,

    pub recv_pkt_num: PktNumWindow,

    pub ack_elicited: bool,

    pub crypto_open: Option<crypto::Open>,
    pub crypto_seal: Option<crypto::Seal>,

    pub crypto_stream: stream::Stream,
}

impl PktNumSpace {
    pub fn new() -> PktNumSpace {
        PktNumSpace {
            largest_rx_pkt_num: 0,

            largest_rx_pkt_time: time::Instant::now(),

            next_pkt_num: 0,

            recv_pkt_need_ack: ranges::RangeSet::default(),

            recv_pkt_num: PktNumWindow::default(),

            ack_elicited: false,

            crypto_open: None,
            crypto_seal: None,

            crypto_stream: stream::Stream::new(std::u64::MAX, std::u64::MAX),
        }
    }

    pub fn clear(&mut self) {
        self.crypto_stream = stream::Stream::new(std::u64::MAX, std::u64::MAX);

        self.ack_elicited = false;
    }

    pub fn overhead(&self) -> usize {
        self.crypto_seal.as_ref().unwrap().alg().tag_len()
    }

    pub fn ready(&self) -> bool {
        self.crypto_stream.flushable() || self.ack_elicited
    }
}

#[derive(Clone, Copy, Default)]
pub struct PktNumWindow {
    lower: u64,
    window: u128,
}

impl PktNumWindow {
    pub fn insert(&mut self, seq: u64) {
        // Packet is on the left end of the window.
        if seq < self.lower {
            return;
        }

        // Packet is on the right end of the window.
        if seq > self.upper() {
            let diff = seq - self.upper();
            self.lower += diff;

            self.window = self.window.checked_shl(diff as u32).unwrap_or(0);
        }

        let mask = 1_u128 << (self.upper() - seq);
        self.window |= mask;
    }

    pub fn contains(&mut self, seq: u64) -> bool {
        // Packet is on the right end of the window.
        if seq > self.upper() {
            return false;
        }

        // Packet is on the left end of the window.
        if seq < self.lower {
            return true;
        }

        let mask = 1_u128 << (self.upper() - seq);
        self.window & mask != 0
    }

    fn upper(&self) -> u64 {
        self.lower
            .saturating_add(std::mem::size_of::<u128>() as u64 * 8) -
            1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto;
    use crate::octets;

    #[test]
    fn retry() {
        let hdr = Header {
            ty: Type::Retry,
            version: 0xafafafaf,
            dcid: vec![0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba],
            scid: vec![0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: Some(vec![0x01, 0x02, 0x03, 0x04]),
            token: Some(vec![0xba; 24]),
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 52];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9).unwrap(), hdr);
    }

    #[test]
    fn initial() {
        let hdr = Header {
            ty: Type::Initial,
            version: 0xafafafaf,
            dcid: vec![0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba],
            scid: vec![0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: None,
            token: Some(vec![0x05, 0x06, 0x07, 0x08]),
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9).unwrap(), hdr);
    }

    #[test]
    fn initial_v1_dcid_too_long() {
        let hdr = Header {
            ty: Type::Initial,
            version: crate::PROTOCOL_VERSION,
            dcid: vec![
                0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,
                0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,
            ],
            scid: vec![0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: None,
            token: Some(vec![0x05, 0x06, 0x07, 0x08]),
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 21), Err(Error::InvalidPacket));
    }

    #[test]
    fn initial_v1_scid_too_long() {
        let hdr = Header {
            ty: Type::Initial,
            version: crate::PROTOCOL_VERSION,
            dcid: vec![0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba],
            scid: vec![
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            ],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: None,
            token: Some(vec![0x05, 0x06, 0x07, 0x08]),
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9), Err(Error::InvalidPacket));
    }

    #[test]
    fn initial_non_v1_scid_long() {
        let hdr = Header {
            ty: Type::Initial,
            version: 0xafafafaf,
            dcid: vec![0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba],
            scid: vec![
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            ],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: None,
            token: Some(vec![0x05, 0x06, 0x07, 0x08]),
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9).unwrap(), hdr);
    }

    #[test]
    fn handshake() {
        let hdr = Header {
            ty: Type::Handshake,
            version: 0xafafafaf,
            dcid: vec![0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba],
            scid: vec![0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: None,
            token: None,
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9).unwrap(), hdr);
    }

    #[test]
    fn application() {
        let hdr = Header {
            ty: Type::Application,
            version: 0,
            dcid: vec![0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba],
            scid: vec![],
            pkt_num: 0,
            pkt_num_len: 0,
            odcid: None,
            token: None,
            versions: None,
            key_phase: false,
        };

        let mut d = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9).unwrap(), hdr);
    }

    #[test]
    fn pkt_num_decode() {
        let pn = decode_pkt_num(0xa82f30ea, 0x9b32, 2);
        assert_eq!(pn, 0xa82f9b32);
    }

    #[test]
    fn pkt_num_window() {
        let mut win = PktNumWindow::default();
        assert_eq!(win.lower, 0);
        assert!(!win.contains(0));
        assert!(!win.contains(1));

        win.insert(0);
        assert_eq!(win.lower, 0);
        assert!(win.contains(0));
        assert!(!win.contains(1));

        win.insert(1);
        assert_eq!(win.lower, 0);
        assert!(win.contains(0));
        assert!(win.contains(1));

        win.insert(3);
        assert_eq!(win.lower, 0);
        assert!(win.contains(0));
        assert!(win.contains(1));
        assert!(!win.contains(2));
        assert!(win.contains(3));

        win.insert(10);
        assert_eq!(win.lower, 0);
        assert!(win.contains(0));
        assert!(win.contains(1));
        assert!(!win.contains(2));
        assert!(win.contains(3));
        assert!(!win.contains(4));
        assert!(!win.contains(5));
        assert!(!win.contains(6));
        assert!(!win.contains(7));
        assert!(!win.contains(8));
        assert!(!win.contains(9));
        assert!(win.contains(10));

        win.insert(132);
        assert_eq!(win.lower, 5);
        assert!(win.contains(0));
        assert!(win.contains(1));
        assert!(win.contains(2));
        assert!(win.contains(3));
        assert!(win.contains(4));
        assert!(!win.contains(5));
        assert!(!win.contains(6));
        assert!(!win.contains(7));
        assert!(!win.contains(8));
        assert!(!win.contains(9));
        assert!(win.contains(10));
        assert!(!win.contains(128));
        assert!(!win.contains(130));
        assert!(!win.contains(131));
        assert!(win.contains(132));

        win.insert(1024);
        assert_eq!(win.lower, 897);
        assert!(win.contains(0));
        assert!(win.contains(1));
        assert!(win.contains(2));
        assert!(win.contains(3));
        assert!(win.contains(4));
        assert!(win.contains(5));
        assert!(win.contains(6));
        assert!(win.contains(7));
        assert!(win.contains(8));
        assert!(win.contains(9));
        assert!(win.contains(10));
        assert!(win.contains(128));
        assert!(win.contains(130));
        assert!(win.contains(132));
        assert!(win.contains(896));
        assert!(!win.contains(897));
        assert!(!win.contains(1022));
        assert!(!win.contains(1023));
        assert!(win.contains(1024));
        assert!(!win.contains(1025));
        assert!(!win.contains(1026));

        win.insert(std::u64::MAX - 1);
        assert!(win.contains(0));
        assert!(win.contains(1));
        assert!(win.contains(2));
        assert!(win.contains(3));
        assert!(win.contains(4));
        assert!(win.contains(5));
        assert!(win.contains(6));
        assert!(win.contains(7));
        assert!(win.contains(8));
        assert!(win.contains(9));
        assert!(win.contains(10));
        assert!(win.contains(128));
        assert!(win.contains(130));
        assert!(win.contains(132));
        assert!(win.contains(896));
        assert!(win.contains(897));
        assert!(win.contains(1022));
        assert!(win.contains(1023));
        assert!(win.contains(1024));
        assert!(win.contains(1025));
        assert!(win.contains(1026));
        assert!(!win.contains(std::u64::MAX - 2));
        assert!(win.contains(std::u64::MAX - 1));
    }

    fn test_decrypt_pkt(
        pkt: &mut [u8], dcid: &[u8], is_server: bool, expected_frames: &[u8],
        expected_pn: u64, expected_pn_len: usize,
    ) {
        let mut b = octets::Octets::with_slice(pkt);

        let mut hdr = Header::from_bytes(&mut b, 0).unwrap();
        assert_eq!(hdr.ty, Type::Initial);

        let payload_len = b.get_varint().unwrap() as usize;

        let (aead, _) =
            crypto::derive_initial_key_material(dcid, is_server).unwrap();

        decrypt_hdr(&mut b, &mut hdr, &aead).unwrap();
        let pn = decode_pkt_num(0, hdr.pkt_num, hdr.pkt_num_len);

        assert_eq!(hdr.pkt_num, expected_pn);
        assert_eq!(hdr.pkt_num_len, expected_pn_len);

        let payload =
            decrypt_pkt(&mut b, pn, hdr.pkt_num_len, payload_len, &aead).unwrap();

        let payload = payload.as_ref();
        assert_eq!(&payload[..expected_frames.len()], expected_frames);
    }

    #[test]
    fn decrypt_client_initial() {
        let mut pkt = [
            0xc2, 0xff, 0x00, 0x00, 0x16, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
            0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x9b, 0xd3, 0x43, 0xfd,
            0x65, 0xf3, 0x54, 0xeb, 0xb4, 0x00, 0x41, 0x8b, 0x61, 0x4f, 0x73,
            0x76, 0x50, 0x09, 0xc0, 0x16, 0x2d, 0x59, 0x47, 0x77, 0xf9, 0xe6,
            0xdd, 0xeb, 0x32, 0xfb, 0xa3, 0x86, 0x5c, 0xff, 0xd7, 0xe2, 0x6e,
            0x37, 0x24, 0xd4, 0x99, 0x7c, 0xdd, 0xe8, 0xdf, 0x34, 0xf8, 0x86,
            0x87, 0x72, 0xfe, 0xd2, 0x41, 0x2d, 0x43, 0x04, 0x6f, 0x44, 0xdc,
            0x7c, 0x6a, 0xdf, 0x5e, 0xe1, 0x0d, 0xa4, 0x56, 0xd5, 0x6c, 0x89,
            0x2c, 0x8f, 0x69, 0x59, 0x45, 0x94, 0xe8, 0xdc, 0xab, 0xed, 0xb1,
            0x0d, 0x59, 0x11, 0x30, 0xca, 0x46, 0x45, 0x88, 0xf2, 0x83, 0x4e,
            0xab, 0x93, 0x1b, 0x10, 0xfe, 0xb9, 0x63, 0xc1, 0x94, 0x7a, 0x05,
            0xf5, 0x70, 0x62, 0x69, 0x2c, 0x24, 0x22, 0x48, 0xad, 0x01, 0x33,
            0xb3, 0x1f, 0x6d, 0xcc, 0x58, 0x5b, 0xa3, 0x44, 0xca, 0x5b, 0xeb,
            0x38, 0x2f, 0xb6, 0x19, 0x27, 0x2e, 0x65, 0xdf, 0xcc, 0xae, 0x59,
            0xc0, 0x8e, 0xb0, 0x0b, 0x7d, 0x2a, 0x5b, 0xbc, 0xcd, 0x88, 0x85,
            0x82, 0xdf, 0x1d, 0x1a, 0xee, 0x04, 0x0a, 0xea, 0x76, 0xab, 0x4d,
            0xfd, 0xca, 0xe1, 0x26, 0x79, 0x1e, 0x71, 0x56, 0x1b, 0x1f, 0x58,
            0x31, 0x2e, 0xdb, 0x31, 0xc1, 0x64, 0xff, 0x13, 0x41, 0xfd, 0x28,
            0x20, 0xe2, 0x39, 0x99, 0x46, 0xba, 0xd9, 0x01, 0xe4, 0x25, 0xda,
            0xe5, 0x8a, 0x98, 0x59, 0xef, 0x18, 0x25, 0xe7, 0xd7, 0x57, 0xa6,
            0x29, 0x1d, 0x9b, 0xa6, 0xee, 0x1a, 0x8c, 0x83, 0x6d, 0xc0, 0x02,
            0x7c, 0xd7, 0x05, 0xbd, 0x2b, 0xc6, 0x7f, 0x56, 0xba, 0xd0, 0x02,
            0x4e, 0xfa, 0xa3, 0x81, 0x9c, 0xbb, 0x5d, 0x46, 0xce, 0xfd, 0xb7,
            0xe0, 0xdf, 0x3a, 0xd9, 0x2b, 0x06, 0x89, 0x65, 0x0e, 0x2b, 0x49,
            0xac, 0x29, 0xe6, 0x39, 0x8b, 0xed, 0xc7, 0x55, 0x54, 0x1a, 0x3f,
            0x38, 0x65, 0xbc, 0x47, 0x59, 0xbe, 0xc7, 0x4d, 0x72, 0x1a, 0x28,
            0xa0, 0x45, 0x2c, 0x12, 0x60, 0x18, 0x9e, 0x8e, 0x92, 0xf8, 0x44,
            0xc9, 0x1b, 0x27, 0xa0, 0x0f, 0xc5, 0xed, 0x6d, 0x14, 0xd8, 0xfc,
            0xeb, 0x5a, 0x84, 0x8b, 0xea, 0x0a, 0x32, 0x08, 0x16, 0x2c, 0x7a,
            0x95, 0x78, 0x2f, 0xcf, 0x9a, 0x04, 0x5b, 0x20, 0xb7, 0x67, 0x10,
            0xa2, 0x56, 0x53, 0x72, 0xf2, 0x54, 0x11, 0x81, 0x03, 0x0e, 0x43,
            0x50, 0xe1, 0x99, 0xe6, 0x2f, 0xa4, 0xe2, 0xe0, 0xbb, 0xa1, 0x9f,
            0xf6, 0x66, 0x62, 0xab, 0x8c, 0xc6, 0x81, 0x5e, 0xea, 0xa2, 0x0b,
            0x80, 0xd5, 0xf3, 0x1c, 0x41, 0xe5, 0x51, 0xf5, 0x58, 0xd2, 0xc8,
            0x36, 0xa2, 0x15, 0xcc, 0xff, 0x4e, 0x8a, 0xfd, 0x2f, 0xec, 0x4b,
            0xfc, 0xb9, 0xea, 0x9d, 0x05, 0x1d, 0x12, 0x16, 0x2f, 0x1b, 0x14,
            0x84, 0x24, 0x89, 0xb6, 0x9d, 0x72, 0xa3, 0x07, 0xd9, 0x14, 0x4f,
            0xce, 0xd6, 0x4f, 0xc4, 0xaa, 0x21, 0xeb, 0xd3, 0x10, 0xf8, 0x97,
            0xcf, 0x00, 0x06, 0x2e, 0x90, 0xda, 0xd5, 0xdb, 0xf0, 0x41, 0x86,
            0x62, 0x2e, 0x6c, 0x12, 0x96, 0xd3, 0x88, 0x17, 0x65, 0x85, 0xfd,
            0xb3, 0x95, 0x35, 0x8e, 0xcf, 0xec, 0x4d, 0x95, 0xdb, 0x44, 0x29,
            0xf4, 0x47, 0x3a, 0x76, 0x21, 0x08, 0x66, 0xfd, 0x18, 0x0e, 0xae,
            0xb6, 0x0d, 0xa4, 0x33, 0x50, 0x0c, 0x74, 0xc0, 0x0a, 0xef, 0x24,
            0xd7, 0x7e, 0xae, 0x81, 0x75, 0x5f, 0xaa, 0x03, 0xe7, 0x1a, 0x88,
            0x79, 0x93, 0x7b, 0x32, 0xd3, 0x1b, 0xe2, 0xba, 0x51, 0xd4, 0x1b,
            0x5d, 0x7a, 0x1f, 0xbb, 0x4d, 0x95, 0x2b, 0x10, 0xdd, 0x2d, 0x6e,
            0xc1, 0x71, 0xa3, 0x18, 0x7c, 0xf3, 0xf6, 0x4d, 0x52, 0x0a, 0xfa,
            0xd7, 0x96, 0xe4, 0x18, 0x8b, 0xc3, 0x2d, 0x15, 0x32, 0x41, 0xc0,
            0x83, 0xf2, 0x25, 0xb6, 0xe6, 0xb8, 0x45, 0xce, 0x99, 0x11, 0xbd,
            0x3f, 0xe1, 0xeb, 0x47, 0x37, 0xb7, 0x1c, 0x8d, 0x55, 0xe3, 0x96,
            0x28, 0x71, 0xb7, 0x36, 0x57, 0xb1, 0xe2, 0xcc, 0xe3, 0x68, 0xc7,
            0x40, 0x06, 0x58, 0xd4, 0x7c, 0xfd, 0x92, 0x90, 0xed, 0x16, 0xcd,
            0xc2, 0xa6, 0xe3, 0xe7, 0xdc, 0xea, 0x77, 0xfb, 0x5c, 0x64, 0x59,
            0x30, 0x3a, 0x32, 0xd5, 0x8f, 0x62, 0x96, 0x9d, 0x8f, 0x46, 0x70,
            0xce, 0x27, 0xf5, 0x91, 0xc7, 0xa5, 0x9c, 0xc3, 0xe7, 0x55, 0x6e,
            0xda, 0x4c, 0x58, 0xa3, 0x2e, 0x9f, 0x53, 0xfd, 0x7f, 0x9d, 0x60,
            0xa9, 0xc0, 0x5c, 0xd6, 0x23, 0x8c, 0x71, 0xe3, 0xc8, 0x2d, 0x2e,
            0xfa, 0xbd, 0x3b, 0x51, 0x77, 0x67, 0x0b, 0x8d, 0x59, 0x51, 0x51,
            0xd7, 0xeb, 0x44, 0xaa, 0x40, 0x1f, 0xe3, 0xb5, 0xb8, 0x7b, 0xdb,
            0x88, 0xdf, 0xfb, 0x2b, 0xfb, 0x6d, 0x1d, 0x0d, 0x88, 0x68, 0xa4,
            0x1b, 0xa9, 0x62, 0x65, 0xca, 0x7a, 0x68, 0xd0, 0x6f, 0xc0, 0xb7,
            0x4b, 0xcc, 0xac, 0x55, 0xb0, 0x38, 0xf8, 0x36, 0x2b, 0x84, 0xd4,
            0x7f, 0x52, 0x74, 0x43, 0x23, 0xd0, 0x8b, 0x46, 0xbf, 0xec, 0x8c,
            0x42, 0x1f, 0x99, 0x1e, 0x13, 0x94, 0x93, 0x8a, 0x54, 0x6a, 0x74,
            0x82, 0xa1, 0x7c, 0x72, 0xbe, 0x10, 0x9e, 0xa4, 0xb0, 0xc7, 0x1a,
            0xbc, 0x7d, 0x9c, 0x0a, 0xc0, 0x96, 0x03, 0x27, 0x75, 0x4e, 0x10,
            0x43, 0xf1, 0x8a, 0x32, 0xb9, 0xfb, 0x40, 0x2f, 0xc3, 0x3f, 0xdc,
            0xb6, 0xa0, 0xb4, 0xfd, 0xbb, 0xdd, 0xbd, 0xf0, 0xd8, 0x57, 0x79,
            0x87, 0x9e, 0x98, 0xef, 0x21, 0x1d, 0x10, 0x4a, 0x52, 0x71, 0xf2,
            0x28, 0x23, 0xf1, 0x69, 0x42, 0xcf, 0xa8, 0xac, 0xe6, 0x8d, 0x0c,
            0x9e, 0x5b, 0x52, 0x29, 0x7d, 0xa9, 0x70, 0x2d, 0x8f, 0x1d, 0xe2,
            0x4b, 0xcd, 0x06, 0x28, 0x4a, 0xc8, 0xaa, 0x10, 0x68, 0xfa, 0x21,
            0xa8, 0x2a, 0xbb, 0xca, 0x7e, 0x74, 0x54, 0xb8, 0x48, 0xd7, 0xde,
            0x8c, 0x3d, 0x43, 0x56, 0x05, 0x41, 0xa3, 0x62, 0xff, 0x4f, 0x6b,
            0xe0, 0x6c, 0x01, 0x15, 0xe3, 0xa7, 0x33, 0xbf, 0xf4, 0x44, 0x17,
            0xda, 0x11, 0xae, 0x66, 0x88, 0x57, 0xbb, 0xa2, 0xc5, 0x3b, 0xa1,
            0x7d, 0xb8, 0xc1, 0x00, 0xf1, 0xb5, 0xc7, 0xc9, 0xea, 0x96, 0x0d,
            0x3f, 0x3d, 0x3b, 0x9e, 0x77, 0xc1, 0x6c, 0x31, 0xa2, 0x22, 0xb4,
            0x98, 0xa7, 0x38, 0x4e, 0x28, 0x6b, 0x9b, 0x7c, 0x45, 0x16, 0x7d,
            0x57, 0x03, 0xde, 0x71, 0x5f, 0x9b, 0x06, 0x70, 0x84, 0x03, 0x56,
            0x2d, 0xcf, 0xf7, 0x7f, 0xdf, 0x27, 0x93, 0xf9, 0x4e, 0x29, 0x48,
            0x88, 0xce, 0xbe, 0x8d, 0xa4, 0xee, 0x88, 0xa5, 0x3e, 0x38, 0xf2,
            0x43, 0x0a, 0xdd, 0xc1, 0x61, 0xe8, 0xb2, 0xe2, 0xf2, 0xd4, 0x05,
            0x41, 0xd1, 0x0c, 0xda, 0x9a, 0x7a, 0xa5, 0x18, 0xac, 0x14, 0xd0,
            0x19, 0x5d, 0x8c, 0x20, 0x12, 0x0b, 0x4f, 0x1d, 0x47, 0xd6, 0xd0,
            0x90, 0x9e, 0x69, 0xc4, 0xa0, 0xe6, 0x41, 0xb8, 0x3c, 0x1a, 0xd4,
            0xff, 0xf8, 0x5a, 0xf4, 0x75, 0x10, 0x35, 0xbc, 0x56, 0x98, 0xb6,
            0x14, 0x1e, 0xcc, 0x3f, 0xbf, 0xfc, 0xf2, 0xf5, 0x50, 0x36, 0x88,
            0x00, 0x71, 0xba, 0x11, 0x89, 0x27, 0x40, 0x07, 0x96, 0x7f, 0x64,
            0x46, 0x81, 0x72, 0x85, 0x4d, 0x14, 0x0d, 0x22, 0x93, 0x20, 0xd6,
            0x89, 0xf5, 0x76, 0x60, 0xf6, 0xc4, 0x45, 0xe6, 0x29, 0xd1, 0x5f,
            0xf2, 0xdc, 0xdf, 0xf4, 0xb7, 0x1a, 0x41, 0xec, 0x0c, 0x24, 0xbd,
            0x2f, 0xd8, 0xf5, 0xad, 0x13, 0xb2, 0xc3, 0x68, 0x8e, 0x0f, 0xdb,
            0x8d, 0xbc, 0xce, 0x42, 0xe6, 0xcf, 0x49, 0xcf, 0x60, 0xd0, 0x22,
            0xcc, 0xd5, 0xb1, 0x9b, 0x4f, 0xd5, 0xd9, 0x8d, 0xc1, 0x0d, 0x9c,
            0xe3, 0xa6, 0x26, 0x85, 0x1b, 0x1f, 0xdd, 0x23, 0xe1, 0xfa, 0x3a,
            0x96, 0x1f, 0x9b, 0x03, 0x33, 0xab, 0x8d, 0x63, 0x2e, 0x48, 0xc9,
            0x44, 0xb8, 0x2b, 0xdd, 0x9e, 0x80, 0x0f, 0xa2, 0xb2, 0xb9, 0xe3,
            0x1e, 0x96, 0xae, 0xe5, 0x4b, 0x40, 0xed, 0xaf, 0x6b, 0x79, 0xec,
            0x21, 0x1f, 0xdc, 0x95, 0xd9, 0x5e, 0xf5, 0x52, 0xaa, 0x53, 0x25,
            0x83, 0xd7, 0x6a, 0x53, 0x9e, 0x98, 0x8e, 0x41, 0x6a, 0x0a, 0x10,
            0xdf, 0x25, 0x50, 0xcd, 0xea, 0xca, 0xfc, 0x3d, 0x61, 0xb0, 0xb0,
            0xa7, 0x93, 0x37, 0x96, 0x0a, 0x0b, 0xe8, 0xcf, 0x61, 0x69, 0xe4,
            0xd5, 0x5f, 0xa6, 0xe7, 0xa9, 0xc2, 0xe8, 0xef, 0xab, 0xab, 0x3d,
            0xa0, 0x08, 0xf5, 0xbc, 0xc3, 0x8c, 0x1b, 0xba, 0xbd, 0xb6, 0xc1,
            0x03, 0x68, 0x72, 0x3d, 0xa0, 0xae, 0x83, 0xc4, 0xb1, 0x81, 0x9f,
            0xf5, 0x49, 0x46, 0xe7, 0x80, 0x64, 0x58, 0xd8, 0x0d, 0x7b, 0xe2,
            0xc8, 0x67, 0xd4, 0x6f, 0xe1, 0xf0, 0x29, 0x0c, 0x22, 0x64, 0x57,
            0x46, 0xb8, 0xbb, 0x00, 0xb6, 0xcb, 0xa4, 0xf5, 0xb8, 0x2f, 0x9b,
            0x24,
        ];

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let frames = [
            0x06, 0x00, 0x40, 0xc4, 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0x66,
            0x60, 0x26, 0x1f, 0xf9, 0x47, 0xce, 0xa4, 0x9c, 0xce, 0x6c, 0xfa,
            0xd6, 0x87, 0xf4, 0x57, 0xcf, 0x1b, 0x14, 0x53, 0x1b, 0xa1, 0x41,
            0x31, 0xa0, 0xe8, 0xf3, 0x09, 0xa1, 0xd0, 0xb9, 0xc4, 0x00, 0x00,
            0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91,
            0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65,
            0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
            0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
            0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04,
            0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00,
            0x1d, 0x00, 0x20, 0x4c, 0xfd, 0xfc, 0xd1, 0x78, 0xb7, 0x84, 0xbf,
            0x32, 0x8c, 0xae, 0x79, 0x3b, 0x13, 0x6f, 0x2a, 0xed, 0xce, 0x00,
            0x5f, 0xf1, 0x83, 0xd7, 0xbb, 0x14, 0x95, 0x20, 0x72, 0x36, 0x64,
            0x70, 0x37, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d,
            0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
            0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
            0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02,
            0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02,
            0x40, 0x01,
        ];

        test_decrypt_pkt(&mut pkt, &dcid, true, &frames, 2, 4);
    }

    #[test]
    fn decrypt_server_initial() {
        let mut pkt = [
            0xca, 0xff, 0x00, 0x00, 0x16, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50,
            0x2a, 0x42, 0x62, 0xb5, 0x00, 0x40, 0x74, 0xd7, 0x4b, 0x7e, 0x48,
            0x61, 0x76, 0xfa, 0x3b, 0x71, 0x3f, 0x27, 0x2a, 0x9b, 0xf0, 0x3e,
            0xe2, 0x8d, 0x3c, 0x8a, 0xdd, 0xb4, 0xe8, 0x05, 0xb3, 0xa1, 0x10,
            0xb6, 0x63, 0x12, 0x2a, 0x75, 0xee, 0xe9, 0x3c, 0x91, 0x77, 0xac,
            0x6b, 0x7a, 0x6b, 0x54, 0x8e, 0x15, 0xa7, 0xb8, 0xf8, 0x84, 0x65,
            0xe9, 0xea, 0xb2, 0x53, 0xa7, 0x60, 0x77, 0x9b, 0x2e, 0x6a, 0x2c,
            0x57, 0x48, 0x82, 0xb4, 0x8d, 0x3a, 0x3e, 0xed, 0x69, 0x6e, 0x50,
            0xd0, 0x4d, 0x5e, 0xc5, 0x9a, 0xf8, 0x52, 0x61, 0xe4, 0xcd, 0xbe,
            0x26, 0x4b, 0xd6, 0x5f, 0x2b, 0x07, 0x67, 0x60, 0xc6, 0x9b, 0xee,
            0xf2, 0x3a, 0xa7, 0x14, 0xc9, 0xa1, 0x74, 0xd6, 0x01, 0x37, 0x3b,
            0xf1, 0x57, 0x5c, 0x93, 0xed, 0xf1, 0xd0, 0x09, 0x06, 0x72, 0x10,
            0x23, 0xeb,
        ];

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let frames = [
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x18, 0x41, 0x0a, 0x02, 0x00, 0x00,
            0x56, 0x03, 0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1,
            0x63, 0x2e, 0x96, 0x67, 0x78, 0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf,
            0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43, 0x0b, 0x9a, 0x04,
            0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69,
            0x0b, 0x84, 0xd0, 0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68,
            0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc, 0xf3,
            0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ];

        test_decrypt_pkt(&mut pkt, &dcid, false, &frames, 1, 2);
    }
}
