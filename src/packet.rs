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
use crate::recovery;
use crate::stream;

const FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const KEY_PHASE_BIT: u8 = 0x04;

const TYPE_MASK: u8 = 0x30;
const PKT_NUM_MASK: u8 = 0x03;

pub const MAX_CID_LEN: u8 = 18;

const MAX_PKT_NUM_LEN: usize = 4;
const SAMPLE_LEN: usize = 16;

/// QUIC packet type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type {
    Initial,
    Retry,
    Handshake,
    ZeroRTT,
    VersionNegotiation,
    Application,
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
    /// The `dcil` parameter is the length of the destionation connection ID,
    /// required to parse short header packets.
    pub fn from_slice(buf: &mut [u8], dcil: usize) -> Result<Header> {
        let mut b = octets::Octets::with_slice(buf);
        Header::from_bytes(&mut b, dcil)
    }

    pub(crate) fn from_bytes(
        b: &mut octets::Octets, dcil: usize,
    ) -> Result<Header> {
        let first = b.get_u8()?;

        if !Header::is_long(first) {
            // Decode short header.
            let dcid = b.get_bytes(dcil)?;

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

        let (dcil, scil) = match b.get_u8() {
            Ok(v) => {
                let mut dcil = v >> 4;
                let mut scil = v & 0xf;

                if dcil > 0 {
                    dcil += 3;
                }

                if scil > 0 {
                    scil += 3;
                }

                if dcil > MAX_CID_LEN || scil > MAX_CID_LEN {
                    return Err(Error::InvalidPacket);
                }

                (dcil, scil)
            },

            Err(_) => return Err(Error::BufferTooShort),
        };

        let dcid = b.get_bytes(dcil as usize)?.to_vec();
        let scid = b.get_bytes(scil as usize)?.to_vec();

        // End of invariants.

        let mut odcid: Option<Vec<u8>> = None;
        let mut token: Option<Vec<u8>> = None;
        let mut versions: Option<Vec<u32>> = None;

        match ty {
            Type::Initial => {
                token = Some(b.get_bytes_with_varint_length()?.to_vec());
            },

            Type::Retry => {
                let mut odcil = first & 0x0f;

                if odcil > 0 {
                    odcil += 3;
                }

                if odcil > MAX_CID_LEN {
                    return Err(Error::InvalidPacket);
                }

                odcid = Some(b.get_bytes(odcil as usize)?.to_vec());
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

        if self.ty == Type::Retry {
            let odcid = self.odcid.as_ref().unwrap();
            first |= (odcid.len() - 3) as u8;
        }

        out.put_u8(first)?;

        out.put_u32(self.version)?;

        let mut cil: u8 = 0;

        if !self.dcid.is_empty() {
            cil |= ((self.dcid.len() - 3) as u8) << 4;
        }

        if !self.scid.is_empty() {
            cil |= ((self.scid.len() - 3) as u8) & 0xf;
        }

        out.put_u8(cil)?;

        out.put_bytes(&self.dcid)?;
        out.put_bytes(&self.scid)?;

        if self.ty == Type::Retry {
            let odcid = self.odcid.as_ref().unwrap();
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
                None => out.put_varint(0)?,
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

    b.get_bytes(payload_len)
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

    // Invert client's scid and dcid.
    let mut cil: u8 = 0;
    if !scid.is_empty() {
        cil |= ((scid.len() - 3) as u8) << 4;
    }

    if !dcid.is_empty() {
        cil |= ((dcid.len() - 3) as u8) & 0xf;
    }

    b.put_u8(cil)?;
    b.put_bytes(&scid)?;
    b.put_bytes(&dcid)?;
    b.put_u32(crate::VERSION_DRAFT18)?;

    Ok(b.off())
}

pub fn retry(
    scid: &[u8], dcid: &[u8], new_scid: &[u8], token: &[u8], out: &mut [u8],
) -> Result<usize> {
    let mut b = octets::Octets::with_slice(out);

    let hdr = Header {
        ty: Type::Retry,
        version: crate::VERSION_DRAFT18,
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

    pub flight: recovery::InFlight,

    pub do_ack: bool,

    pub crypto_level: crypto::Level,

    pub crypto_open: Option<crypto::Open>,
    pub crypto_seal: Option<crypto::Seal>,

    pub crypto_stream: stream::Stream,
}

impl PktNumSpace {
    pub fn new(crypto_level: crypto::Level) -> PktNumSpace {
        PktNumSpace {
            largest_rx_pkt_num: 0,

            largest_rx_pkt_time: time::Instant::now(),

            next_pkt_num: 0,

            recv_pkt_need_ack: ranges::RangeSet::default(),

            recv_pkt_num: PktNumWindow::default(),

            flight: recovery::InFlight::default(),

            do_ack: false,

            crypto_level,

            crypto_open: None,
            crypto_seal: None,

            crypto_stream: stream::Stream::new(std::usize::MAX, std::usize::MAX),
        }
    }

    pub fn clear(&mut self) {
        self.flight = recovery::InFlight::default();
        self.crypto_stream =
            stream::Stream::new(std::usize::MAX, std::usize::MAX);
    }

    pub fn overhead(&self) -> usize {
        self.crypto_seal.as_ref().unwrap().alg().tag_len()
    }

    pub fn ready(&self) -> bool {
        self.crypto_stream.writable() ||
            !self.flight.lost.is_empty() ||
            self.do_ack
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

        let mut d = [0; 50];

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
            0xc1, 0xff, 0x00, 0x00, 0x12, 0x50, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
            0x51, 0x57, 0x08, 0x00, 0x44, 0x9f, 0x0d, 0xbc, 0x19, 0x5a, 0x00,
            0x00, 0xf3, 0xa6, 0x94, 0xc7, 0x57, 0x75, 0xb4, 0xe5, 0x46, 0x17,
            0x2c, 0xe9, 0xe0, 0x47, 0xcd, 0x0b, 0x5b, 0xee, 0x51, 0x81, 0x64,
            0x8c, 0x72, 0x7a, 0xdc, 0x87, 0xf7, 0xea, 0xe5, 0x44, 0x73, 0xec,
            0x6c, 0xba, 0x6b, 0xda, 0xd4, 0xf5, 0x98, 0x23, 0x17, 0x4b, 0x76,
            0x9f, 0x12, 0x35, 0x8a, 0xbd, 0x29, 0x2d, 0x4f, 0x32, 0x86, 0x93,
            0x44, 0x84, 0xfb, 0x8b, 0x23, 0x9c, 0x38, 0x73, 0x2e, 0x1f, 0x3b,
            0xbb, 0xc6, 0xa0, 0x03, 0x05, 0x64, 0x87, 0xeb, 0x8b, 0x5c, 0x88,
            0xb9, 0xfd, 0x92, 0x79, 0xff, 0xff, 0x3b, 0x0f, 0x4e, 0xcf, 0x95,
            0xc4, 0x62, 0x4d, 0xb6, 0xd6, 0x5d, 0x41, 0x13, 0x32, 0x9e, 0xe9,
            0xb0, 0xbf, 0x8c, 0xdd, 0x7c, 0x8a, 0x8d, 0x72, 0x80, 0x6d, 0x55,
            0xdf, 0x25, 0xec, 0xb6, 0x64, 0x88, 0xbc, 0x11, 0x9d, 0x7c, 0x9a,
            0x29, 0xab, 0xaf, 0x99, 0xbb, 0x33, 0xc5, 0x6b, 0x08, 0xad, 0x8c,
            0x26, 0x99, 0x5f, 0x83, 0x8b, 0xb3, 0xb7, 0xa3, 0xd5, 0xc1, 0x85,
            0x8b, 0x8e, 0xc0, 0x6b, 0x83, 0x9d, 0xb2, 0xdc, 0xf9, 0x18, 0xd5,
            0xea, 0x93, 0x17, 0xf1, 0xac, 0xd6, 0xb6, 0x63, 0xcc, 0x89, 0x25,
            0x86, 0x8e, 0x2f, 0x6a, 0x1b, 0xda, 0x54, 0x66, 0x95, 0xf3, 0xc3,
            0xf3, 0x31, 0x75, 0x94, 0x4d, 0xb4, 0xa1, 0x1a, 0x34, 0x6a, 0xfb,
            0x07, 0xe7, 0x84, 0x89, 0xe5, 0x09, 0xb0, 0x2a, 0xdd, 0x51, 0xb7,
            0xb2, 0x03, 0xed, 0xa5, 0xc3, 0x30, 0xb0, 0x36, 0x41, 0x17, 0x9a,
            0x31, 0xfb, 0xba, 0x9b, 0x56, 0xce, 0x00, 0xf3, 0xd5, 0xb5, 0xe3,
            0xd7, 0xd9, 0xc5, 0x42, 0x9a, 0xeb, 0xb9, 0x57, 0x6f, 0x2f, 0x7e,
            0xac, 0xbe, 0x27, 0xbc, 0x1b, 0x80, 0x82, 0xaa, 0xf6, 0x8f, 0xb6,
            0x9c, 0x92, 0x1a, 0xa5, 0xd3, 0x3e, 0xc0, 0xc8, 0x51, 0x04, 0x10,
            0x86, 0x5a, 0x17, 0x8d, 0x86, 0xd7, 0xe5, 0x41, 0x22, 0xd5, 0x5e,
            0xf2, 0xc2, 0xbb, 0xc0, 0x40, 0xbe, 0x46, 0xd7, 0xfe, 0xce, 0x73,
            0xfe, 0x8a, 0x1b, 0x24, 0x49, 0x5e, 0xc1, 0x60, 0xdf, 0x2d, 0xa9,
            0xb2, 0x0a, 0x7b, 0xa2, 0xf2, 0x6d, 0xfa, 0x2a, 0x44, 0x36, 0x6d,
            0xbc, 0x63, 0xde, 0x5c, 0xd7, 0xd7, 0xc9, 0x4c, 0x57, 0x17, 0x2f,
            0xe6, 0xd7, 0x9c, 0x90, 0x1f, 0x02, 0x5c, 0x00, 0x10, 0xb0, 0x2c,
            0x89, 0xb3, 0x95, 0x40, 0x2c, 0x00, 0x9f, 0x62, 0xdc, 0x05, 0x3b,
            0x80, 0x67, 0xa1, 0xe0, 0xed, 0x0a, 0x1e, 0x0c, 0xf5, 0x08, 0x7d,
            0x7f, 0x78, 0xcb, 0xd9, 0x4a, 0xfe, 0x0c, 0x3d, 0xd5, 0x5d, 0x2d,
            0x4b, 0x1a, 0x5c, 0xfe, 0x2b, 0x68, 0xb8, 0x62, 0x64, 0xe3, 0x51,
            0xd1, 0xdc, 0xd8, 0x58, 0x78, 0x3a, 0x24, 0x0f, 0x89, 0x3f, 0x00,
            0x8c, 0xee, 0xd7, 0x43, 0xd9, 0x69, 0xb8, 0xf7, 0x35, 0xa1, 0x67,
            0x7e, 0xad, 0x96, 0x0b, 0x1f, 0xb1, 0xec, 0xc5, 0xac, 0x83, 0xc2,
            0x73, 0xb4, 0x92, 0x88, 0xd0, 0x2d, 0x72, 0x86, 0x20, 0x7e, 0x66,
            0x3c, 0x45, 0xe1, 0xa7, 0xba, 0xf5, 0x06, 0x40, 0xc9, 0x1e, 0x76,
            0x29, 0x41, 0xcf, 0x38, 0x0c, 0xe8, 0xd7, 0x9f, 0x3e, 0x86, 0x76,
            0x7f, 0xbb, 0xcd, 0x25, 0xb4, 0x2e, 0xf7, 0x0e, 0xc3, 0x34, 0x83,
            0x5a, 0x3a, 0x6d, 0x79, 0x2e, 0x17, 0x0a, 0x43, 0x2c, 0xe0, 0xcb,
            0x7b, 0xde, 0x9a, 0xaa, 0x1e, 0x75, 0x63, 0x7c, 0x1c, 0x34, 0xae,
            0x5f, 0xef, 0x43, 0x38, 0xf5, 0x3d, 0xb8, 0xb1, 0x3a, 0x4d, 0x2d,
            0xf5, 0x94, 0xef, 0xbf, 0xa0, 0x87, 0x84, 0x54, 0x38, 0x15, 0xc9,
            0xc0, 0xd4, 0x87, 0xbd, 0xdf, 0xa1, 0x53, 0x9b, 0xc2, 0x52, 0xcf,
            0x43, 0xec, 0x36, 0x86, 0xe9, 0x80, 0x2d, 0x65, 0x1c, 0xfd, 0x2a,
            0x82, 0x9a, 0x06, 0xa9, 0xf3, 0x32, 0xa7, 0x33, 0xa4, 0xa8, 0xae,
            0xd8, 0x0e, 0xfe, 0x34, 0x78, 0x09, 0x3f, 0xbc, 0x69, 0xc8, 0x60,
            0x81, 0x46, 0xb3, 0xf1, 0x6f, 0x1a, 0x5c, 0x4e, 0xac, 0x93, 0x20,
            0xda, 0x49, 0xf1, 0xaf, 0xa5, 0xf5, 0x38, 0xdd, 0xec, 0xbb, 0xe7,
            0x88, 0x8f, 0x43, 0x55, 0x12, 0xd0, 0xdd, 0x74, 0xfd, 0x9b, 0x8c,
            0x99, 0xe3, 0x14, 0x5b, 0xa8, 0x44, 0x10, 0xd8, 0xca, 0x9a, 0x36,
            0xdd, 0x88, 0x41, 0x09, 0xe7, 0x6e, 0x5f, 0xb8, 0x22, 0x2a, 0x52,
            0xe1, 0x47, 0x3d, 0xa1, 0x68, 0x51, 0x9c, 0xe7, 0xa8, 0xa3, 0xc3,
            0x2e, 0x91, 0x49, 0x67, 0x1b, 0x16, 0x72, 0x4c, 0x6c, 0x5c, 0x51,
            0xbb, 0x5c, 0xd6, 0x4f, 0xb5, 0x91, 0xe5, 0x67, 0xfb, 0x78, 0xb1,
            0x0f, 0x9f, 0x6f, 0xee, 0x62, 0xc2, 0x76, 0xf2, 0x82, 0xa7, 0xdf,
            0x6b, 0xcf, 0x7c, 0x17, 0x74, 0x7b, 0xc9, 0xa8, 0x1e, 0x6c, 0x9c,
            0x3b, 0x03, 0x2f, 0xdd, 0x0e, 0x1c, 0x3a, 0xc9, 0xea, 0xa5, 0x07,
            0x7d, 0xe3, 0xde, 0xd1, 0x8b, 0x2e, 0xd4, 0xfa, 0xf3, 0x28, 0xf4,
            0x98, 0x75, 0xaf, 0x2e, 0x36, 0xad, 0x5c, 0xe5, 0xf6, 0xcc, 0x99,
            0xef, 0x4b, 0x60, 0xe5, 0x7b, 0x3b, 0x5b, 0x9c, 0x9f, 0xcb, 0xcd,
            0x4c, 0xfb, 0x39, 0x75, 0xe7, 0x0c, 0xe4, 0xc2, 0x50, 0x6b, 0xcd,
            0x71, 0xfe, 0xf0, 0xe5, 0x35, 0x92, 0x46, 0x15, 0x04, 0xe3, 0xd4,
            0x2c, 0x88, 0x5c, 0xaa, 0xb2, 0x1b, 0x78, 0x2e, 0x26, 0x29, 0x4c,
            0x6a, 0x9d, 0x61, 0x11, 0x8c, 0xc4, 0x0a, 0x26, 0xf3, 0x78, 0x44,
            0x1c, 0xeb, 0x48, 0xf3, 0x1a, 0x36, 0x2b, 0xf8, 0x50, 0x2a, 0x72,
            0x3a, 0x36, 0xc6, 0x35, 0x02, 0x22, 0x9a, 0x46, 0x2c, 0xc2, 0xa3,
            0x79, 0x62, 0x79, 0xa5, 0xe3, 0xa7, 0xf8, 0x1a, 0x68, 0xc7, 0xf8,
            0x13, 0x12, 0xc3, 0x81, 0xcc, 0x16, 0xa4, 0xab, 0x03, 0x51, 0x3a,
            0x51, 0xad, 0x5b, 0x54, 0x30, 0x6e, 0xc1, 0xd7, 0x8a, 0x5e, 0x47,
            0xe2, 0xb1, 0x5e, 0x5b, 0x7a, 0x14, 0x38, 0xe5, 0xb8, 0xb2, 0x88,
            0x2d, 0xbd, 0xad, 0x13, 0xd6, 0xa4, 0xa8, 0xc3, 0x55, 0x8c, 0xae,
            0x04, 0x35, 0x01, 0xb6, 0x8e, 0xb3, 0xb0, 0x40, 0x06, 0x71, 0x52,
            0x33, 0x7c, 0x05, 0x1c, 0x40, 0xb5, 0xaf, 0x80, 0x9a, 0xca, 0x28,
            0x56, 0x98, 0x6f, 0xd1, 0xc8, 0x6a, 0x4a, 0xde, 0x17, 0xd2, 0x54,
            0xb6, 0x26, 0x2a, 0xc1, 0xbc, 0x07, 0x73, 0x43, 0xb5, 0x2b, 0xf8,
            0x9f, 0xa2, 0x7d, 0x73, 0xe3, 0xc6, 0xf3, 0x11, 0x8c, 0x99, 0x61,
            0xf0, 0xbe, 0xbe, 0x68, 0xa5, 0xc3, 0x23, 0xc2, 0xd8, 0x4b, 0x8c,
            0x29, 0xa2, 0x80, 0x7d, 0xf6, 0x63, 0x63, 0x52, 0x23, 0x24, 0x2a,
            0x2c, 0xe9, 0x82, 0x8d, 0x44, 0x29, 0xac, 0x27, 0x0a, 0xab, 0x5f,
            0x18, 0x41, 0xe8, 0xe4, 0x9c, 0xf4, 0x33, 0xb1, 0x54, 0x79, 0x89,
            0xf4, 0x19, 0xca, 0xa3, 0xc7, 0x58, 0xff, 0xf9, 0x6d, 0xed, 0x40,
            0xcf, 0x34, 0x27, 0xf0, 0x76, 0x1b, 0x67, 0x8d, 0xaa, 0x1a, 0x9e,
            0x55, 0x54, 0x46, 0x5d, 0x46, 0xb7, 0xa9, 0x17, 0x49, 0x3f, 0xc7,
            0x0f, 0x9e, 0xc5, 0xe4, 0xe5, 0xd7, 0x86, 0xca, 0x50, 0x17, 0x30,
            0x89, 0x8a, 0xaa, 0x11, 0x51, 0xdc, 0xd3, 0x18, 0x29, 0x64, 0x1e,
            0x29, 0x42, 0x8d, 0x90, 0xe6, 0x06, 0x55, 0x11, 0xc2, 0x4d, 0x31,
            0x09, 0xf7, 0xcb, 0xa3, 0x22, 0x25, 0xd4, 0xac, 0xcf, 0xc5, 0x4f,
            0xec, 0x42, 0xb7, 0x33, 0xf9, 0x58, 0x52, 0x52, 0xee, 0x36, 0xfa,
            0x5e, 0xa0, 0xc6, 0x56, 0x93, 0x43, 0x85, 0xb4, 0x68, 0xee, 0xe2,
            0x45, 0x31, 0x51, 0x46, 0xb8, 0xc0, 0x47, 0xed, 0x27, 0xc5, 0x19,
            0xb2, 0xc0, 0xa5, 0x2d, 0x33, 0xef, 0xe7, 0x2c, 0x18, 0x6f, 0xfe,
            0x0a, 0x23, 0x0f, 0x50, 0x56, 0x76, 0xc5, 0x32, 0x4b, 0xaa, 0x6a,
            0xe0, 0x06, 0xa7, 0x3e, 0x13, 0xaa, 0x8c, 0x39, 0xab, 0x17, 0x3a,
            0xd2, 0xb2, 0x77, 0x8e, 0xea, 0x0b, 0x34, 0xc4, 0x6f, 0x2b, 0x3b,
            0xea, 0xe2, 0xc6, 0x2a, 0x2c, 0x8d, 0xb2, 0x38, 0xbf, 0x58, 0xfc,
            0x7c, 0x27, 0xbd, 0xce, 0xb9, 0x6c, 0x56, 0xd2, 0x9d, 0xee, 0xc8,
            0x7c, 0x12, 0x35, 0x1b, 0xfd, 0x59, 0x62, 0x49, 0x74, 0x18, 0x71,
            0x6a, 0x4b, 0x91, 0x5d, 0x33, 0x4f, 0xfb, 0x5b, 0x92, 0xca, 0x94,
            0xff, 0xe1, 0xe4, 0xf7, 0x89, 0x67, 0x04, 0x26, 0x38, 0x63, 0x9a,
            0x9d, 0xe3, 0x25, 0x35, 0x7f, 0x5f, 0x08, 0xf6, 0x43, 0x50, 0x61,
            0xe5, 0xa2, 0x74, 0x70, 0x39, 0x36, 0xc0, 0x6f, 0xc5, 0x6a, 0xf9,
            0x2c, 0x42, 0x07, 0x97, 0x49, 0x9c, 0xa4, 0x31, 0xa7, 0xab, 0xaa,
            0x46, 0x18, 0x63, 0xbc, 0xa6, 0x56, 0xfa, 0xcf, 0xad, 0x56, 0x4e,
            0x62, 0x74, 0xd4, 0xa7, 0x41, 0x03, 0x3a, 0xca, 0x1e, 0x31, 0xbf,
            0x63, 0x20, 0x0d, 0xf4, 0x1c, 0xdf, 0x41, 0xc1, 0x0b, 0x91, 0x2b,
            0xec,
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
            0xc4, 0xff, 0x00, 0x00, 0x12, 0x05, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
            0x42, 0x62, 0xb5, 0x00, 0x40, 0x74, 0xf7, 0xed, 0x5f, 0x01, 0xc4,
            0xc2, 0xa2, 0x30, 0x3d, 0x29, 0x7e, 0x3c, 0x51, 0x9b, 0xf6, 0xb2,
            0x23, 0x86, 0xe3, 0xd0, 0xbd, 0x6d, 0xfc, 0x66, 0x12, 0x16, 0x77,
            0x29, 0x80, 0x31, 0x04, 0x1b, 0xb9, 0xa7, 0x9c, 0x9f, 0x0f, 0x9d,
            0x4c, 0x58, 0x77, 0x27, 0x0a, 0x66, 0x0f, 0x5d, 0xa3, 0x62, 0x07,
            0xd9, 0x8b, 0x73, 0x83, 0x9b, 0x2f, 0xdf, 0x2e, 0xf8, 0xe7, 0xdf,
            0x5a, 0x51, 0xb1, 0x7b, 0x8c, 0x68, 0xd8, 0x64, 0xfd, 0x3e, 0x70,
            0x8c, 0x6c, 0x1b, 0x71, 0xa9, 0x8a, 0x33, 0x18, 0x15, 0x59, 0x9e,
            0xf5, 0x01, 0x4e, 0xa3, 0x8c, 0x44, 0xbd, 0xfd, 0x38, 0x7c, 0x03,
            0xb5, 0x27, 0x5c, 0x35, 0xe0, 0x09, 0xb6, 0x23, 0x8f, 0x83, 0x14,
            0x20, 0x04, 0x7c, 0x72, 0x71, 0x28, 0x1c, 0xcb, 0x54, 0xdf, 0x78,
            0x84,
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
