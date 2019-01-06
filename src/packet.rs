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

use crate::Result;
use crate::Error;

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

const MAX_CID_LEN: u8 = 18;

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

    /// The length of the packet number.
    pub pkt_num_len: u8,

    /// The address verification token of the packet. Only present in `Initial`
    /// packets.
    pub token: Option<Vec<u8>>,

    /// The list of versions in the packet. Only present in `VersionNegotiation`
    /// packets.
    pub versions: Option<Vec<u32>>,
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

    pub(crate) fn from_bytes(b: &mut octets::Octets, dcil: usize) -> Result<Header> {
        let first = b.get_u8()?;

        if !Header::is_long(first) {
            // Decode short header.
            let dcid = b.get_bytes(dcil)?;

            return Ok(Header {
                ty: Type::Application,
                version: 0,
                dcid: dcid.to_vec(),
                scid: Vec::new(),
                pkt_num_len: 0,
                token: None,
                versions: None,
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
                _    => return Err(Error::InvalidPacket),
            }
        };

        let (dcil, scil) = match b.get_u8() {
            Ok(v) => {
                let mut dcil = v >> 4;
                let mut scil = v & 0xf;

                if dcil > MAX_CID_LEN || scil > MAX_CID_LEN {
                    return Err(Error::InvalidPacket);
                }

                if dcil > 0 {
                    dcil += 3;
                }

                if scil > 0 {
                    scil += 3;
                }

                (dcil, scil)
            },

            Err(_) => return Err(Error::BufferTooShort),
        };

        let dcid = b.get_bytes(dcil as usize)?.to_vec();
        let scid = b.get_bytes(scil as usize)?.to_vec();

        // End of invariants.

        let mut token: Option<Vec<u8>> = None;
        let mut versions: Option<Vec<u32>> = None;

        match ty {
            Type::Initial => {
                // Only Initial packet have a token.
                token = Some(b.get_bytes_with_varint_length()?.to_vec());
            },

            Type::Retry => {
                // TODO: implement stateless retry
                return Err(Error::Done)
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
            pkt_num_len: 0,
            token,
            versions,
        })
    }

    pub(crate) fn to_bytes(&self, out: &mut octets::Octets) -> Result<()> {
        let mut first = 0;

        // Encode pkt num length.
        first |= self.pkt_num_len.checked_sub(1)
                                 .unwrap_or(0);

        // Encode short header.
        if self.ty == Type::Application {
            // Unset form bit for short header.
            first &= !FORM_BIT;

            // Set fixed bit.
            first |= FIXED_BIT;

            // TODO: support key update
            first &= !KEY_PHASE_BIT;

            out.put_u8(first)?;
            out.put_bytes(&self.dcid)?;

            return Ok(());
        }

        // Encode long header.
        let ty: u8 = match self.ty {
                Type::Initial   => 0x00,
                Type::ZeroRTT   => 0x01,
                Type::Handshake => 0x02,
                Type::Retry     => 0x03,
                _               => return Err(Error::InvalidPacket),
        };

        first |= FORM_BIT | FIXED_BIT | (ty << 4);

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

        // Only Initial packet have a token.
        if self.ty == Type::Initial {
            match self.token {
                Some(ref v) => {
                    out.put_bytes(v)?;
                },

                None => {
                    // No token, so lemgth = 0.
                    out.put_varint(0)?;
                }
            }
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

        if self.ty == Type::VersionNegotiation {
            if let Some(ref versions) = self.versions {
                write!(f, " versions={:x?}", versions)?;
            }
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

pub fn decrypt_hdr(b: &mut octets::Octets, aead: &crypto::Open)
                                                    -> Result<(u64, usize)> {
    let mut first = {
        let (first_buf, _) = b.split_at(1)?;
        first_buf.as_ref()[0]
    };

    let mut pn_and_sample = b.peek_bytes(MAX_PKT_NUM_LEN + SAMPLE_LEN)?;

    let (mut ciphertext, sample) = pn_and_sample.split_at(MAX_PKT_NUM_LEN)
                                                .unwrap();

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

    Ok((pn, pn_len))
}

pub fn decode_pkt_num(largest_pn: u64, truncated_pn: u64, pn_len: usize) -> u64 {
    let pn_nbits     = pn_len * 8;
    let expected_pn  = largest_pn + 1;
    let pn_win       = 1 << pn_nbits;
    let pn_hwin      = pn_win / 2;
    let pn_mask      = pn_win - 1;
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

    if candidate_pn + pn_hwin <= expected_pn {
         return candidate_pn + pn_win;
    }

    if candidate_pn > expected_pn + pn_hwin && candidate_pn > pn_win {
        return candidate_pn - pn_win;
    }

    candidate_pn
}

pub fn decrypt_pkt<'a>(b: &'a mut octets::Octets, pn: u64, pn_len: usize,
                       payload_len: usize, aead: &crypto::Open)
                                                -> Result<octets::Octets<'a>> {
    let payload_offset = b.off();

    let (header, mut payload) = b.split_at(payload_offset)?;

    let mut ciphertext = payload.peek_bytes(payload_len - pn_len)?;

    let payload_len = 
        aead.open_with_u64_counter(pn, header.as_ref(), ciphertext.as_mut())?;

    b.get_bytes(payload_len)
}

pub fn encrypt_hdr(b: &mut octets::Octets, pn_len: usize, payload: &[u8],
                   aead: &crypto::Seal) -> Result<()> {
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

pub fn encrypt_pkt(b: &mut octets::Octets, pn: u64, pn_len: usize,
                   payload_len: usize, payload_offset: usize,
                   aead: &crypto::Seal) -> Result<usize> {
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

pub fn negotiate_version(hdr: &Header, out: &mut [u8]) -> Result<usize> {
    let mut b = octets::Octets::with_slice(out);

    let first = rand::rand_u8() | FORM_BIT;

    b.put_u8(first)?;
    b.put_u32(0)?;

    // Invert client's scid and dcid.
    let mut cil: u8 = 0;
    if !hdr.scid.is_empty() {
        cil |= ((hdr.scid.len() - 3) as u8) << 4;
    }

    if !hdr.dcid.is_empty() {
        cil |= ((hdr.dcid.len() - 3) as u8) & 0xf;
    }

    b.put_u8(cil)?;
    b.put_bytes(&hdr.scid)?;
    b.put_bytes(&hdr.dcid)?;
    b.put_u32(crate::VERSION_DRAFT17)?;

    Ok(b.off())
}

pub struct PktNumSpace {
    pub largest_rx_pkt_num: u64,

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
        self.crypto_stream = stream::Stream::new(std::usize::MAX,
                                                 std::usize::MAX);
    }

    pub fn cipher(&self) -> crypto::Algorithm {
        match self.crypto_open {
            Some(ref v) => v.alg(),
            None => crypto::Algorithm::Null,
        }
    }

    pub fn overhead(&self) -> usize {
        self.crypto_seal.as_ref().unwrap().alg().tag_len()
    }

    pub fn ready(&self) -> bool {
        self.crypto_stream.writable() || !self.flight.lost.is_empty() || self.do_ack
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

            self.window = self.window.checked_shl(diff as u32)
                                     .unwrap_or(0);
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
        self.lower.checked_add(std::mem::size_of::<u128>() as u64 * 8)
                  .unwrap_or(std::u64::MAX) - 1
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto;
    use crate::octets;

    #[test]
    fn long_header() {
        let hdr = Header {
            ty: Type::Handshake,
            version: 0xafafafaf,
            dcid: vec![ 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba ],
            scid: vec![ 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb ],
            pkt_num_len: 0,
            token: None,
            versions: None,
        };

        let mut d: [u8; 50] = [0; 50];

        let mut b = octets::Octets::with_slice(&mut d);
        assert!(hdr.to_bytes(&mut b).is_ok());

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Header::from_bytes(&mut b, 9).unwrap(), hdr);
    }

    #[test]
    fn short_header() {
        let hdr = Header {
            ty: Type::Application,
            version: 0,
            dcid: vec![ 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba ],
            scid: vec![ ],
            pkt_num_len: 0,
            token: None,
            versions: None,
        };

        let mut d: [u8; 50] = [0; 50];

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

    fn test_decrypt_pkt(pkt: &mut [u8], dcid: &[u8], is_server: bool,
                         expected_frames: &[u8],
                         expected_pn: u64,
                         expected_pn_len: usize) {
        let mut b = octets::Octets::with_slice(pkt);

        let hdr = Header::from_bytes(&mut b, 0).unwrap();
        assert_eq!(hdr.ty, Type::Initial);

        let payload_len = b.get_varint().unwrap() as usize;

        let (aead, _) = 
            crypto::derive_initial_key_material(dcid, is_server).unwrap();

        let (pn, pn_len) = decrypt_hdr(&mut b, &aead).unwrap();
        let pn = decode_pkt_num(0, pn, pn_len);

        assert_eq!(pn, expected_pn);
        assert_eq!(pn_len, expected_pn_len);

        let payload =
            decrypt_pkt(&mut b, pn, pn_len, payload_len, &aead).unwrap();

        let payload = payload.as_ref();
        assert_eq!(&payload[..expected_frames.len()], expected_frames);
    }

    #[test]
    fn decrypt_client_initial() {
        let mut pkt = [ 
            0xc0, 0xff, 0x00, 0x00, 0x12, 0x50, 0x83, 0x94, 0xc8,
            0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x44, 0x9f, 0xdd,
            0xef, 0x27, 0xaf, 0x81, 0x98, 0x36, 0xc8, 0x04, 0x2d,
            0xac, 0xeb, 0x73, 0x9f, 0x1f, 0xa1, 0xfa, 0x76, 0xc8,
            0x2b, 0x24, 0x19, 0xeb, 0x0f, 0x33, 0xd8, 0x7d, 0xac,
            0xb8, 0x84, 0x37, 0x6e, 0xc1, 0x1e, 0xf5, 0x44, 0x38,
            0x84, 0x72, 0xf4, 0x44, 0x62, 0x62, 0xaf, 0x71, 0xec,
            0x6e, 0xf2, 0xc5, 0x71, 0xf7, 0x97, 0x9d, 0x1c, 0x3d,
            0xeb, 0x06, 0xcc, 0xf8, 0x5a, 0x16, 0x17, 0x8d, 0x17,
            0x12, 0xd1, 0x24, 0xe1, 0x8b, 0xd8, 0x0b, 0x20, 0x38,
            0x73, 0x6f, 0x1c, 0x23, 0x3a, 0x55, 0x77, 0xd7, 0x9d,
            0x9e, 0xee, 0xfd, 0x61, 0x7b, 0xec, 0x8f, 0xe2, 0xb5,
            0x76, 0x55, 0xe4, 0x46, 0x8f, 0xa6, 0x2c, 0x12, 0xc3,
            0x36, 0x23, 0x08, 0xdd, 0x13, 0x6b, 0x49, 0x4b, 0x7c,
            0x25, 0x7d, 0xaf, 0x0a, 0x83, 0x43, 0xfd, 0x8c, 0x22,
            0x8f, 0x06, 0xfd, 0x77, 0xf0, 0x32, 0xd0, 0x38, 0xba,
            0x01, 0x8c, 0xec, 0xfc, 0x0e, 0x8e, 0x22, 0xd1, 0xc0,
            0xfa, 0xbf, 0x45, 0xe1, 0xb4, 0x6e, 0x11, 0x03, 0xcb,
            0xaf, 0x3e, 0xdc, 0x82, 0xe7, 0x6f, 0x22, 0x20, 0x2e,
            0xf8, 0xde, 0x0d, 0x90, 0xaf, 0xd3, 0x75, 0x3e, 0x38,
            0xa1, 0xe8, 0x30, 0xfc, 0x2d, 0x5c, 0xd5, 0xfa, 0xf5,
            0x83, 0xa1, 0xaf, 0x62, 0xb9, 0xd0, 0xdb, 0x00, 0x1b,
            0x7f, 0xe9, 0xc5, 0x90, 0x1a, 0x9e, 0x7b, 0xef, 0xeb,
            0x44, 0xee, 0x27, 0xfb, 0x46, 0xea, 0xab, 0x7c, 0x38,
            0xa9, 0xe4, 0x37, 0x3a, 0x8a, 0x24, 0x91, 0x75, 0x4e,
            0x2a, 0x99, 0xed, 0x6b, 0xf3, 0x38, 0x79, 0xb8, 0xb9,
            0x83, 0xb0, 0xe3, 0xd1, 0xd0, 0x75, 0xb4, 0x2e, 0x68,
            0x69, 0x3a, 0x4a, 0x4f, 0x4a, 0x37, 0xa5, 0x9b, 0x33,
            0x88, 0x1c, 0x77, 0xc4, 0xab, 0x11, 0x02, 0x71, 0x01,
            0xeb, 0x1e, 0xbf, 0x0a, 0x7e, 0x1f, 0xec, 0xc0, 0xd2,
            0x25, 0xa6, 0xb8, 0x08, 0xa7, 0xa7, 0x93, 0x52, 0x9f,
            0x2b, 0x19, 0xbf, 0x82, 0xa5, 0x33, 0x78, 0x44, 0x49,
            0x98, 0x8d, 0xa4, 0xcb, 0x0d, 0x88, 0x4c, 0xa4, 0xa3,
            0x05, 0x46, 0xc5, 0x70, 0x67, 0x98, 0xa8, 0xe4, 0xae,
            0xb5, 0xbd, 0x48, 0x47, 0xf2, 0x90, 0x84, 0x34, 0x7b,
            0x90, 0xb0, 0x85, 0x30, 0x03, 0xc7, 0x53, 0x78, 0x4b,
            0x65, 0x23, 0xab, 0x02, 0x61, 0x16, 0xc3, 0x9f, 0x8e,
            0xc3, 0x36, 0x83, 0x9a, 0x19, 0xeb, 0xcd, 0x9b, 0xab,
            0x1f, 0xb3, 0x84, 0xc0, 0x73, 0xec, 0x9b, 0x92, 0xae,
            0x2a, 0x5b, 0x23, 0xd2, 0x66, 0x02, 0x60, 0x9b, 0x66,
            0x39, 0x69, 0x2b, 0x23, 0xe5, 0x9b, 0x18, 0x47, 0x73,
            0x2d, 0xfb, 0x03, 0xf3, 0x81, 0xfd, 0x81, 0x20, 0x06,
            0x91, 0xc6, 0xd8, 0x24, 0x24, 0xa6, 0xa4, 0xf9, 0xe5,
            0x86, 0xdb, 0xe9, 0xe6, 0xc1, 0x31, 0x09, 0x24, 0xa3,
            0x5e, 0x48, 0x7a, 0xcf, 0xc9, 0x3f, 0xeb, 0x03, 0x2a,
            0x04, 0x62, 0xba, 0xf4, 0x24, 0x8a, 0x02, 0xc2, 0x6a,
            0x18, 0x46, 0x0f, 0x08, 0x2d, 0x46, 0x11, 0x88, 0x99,
            0x05, 0x9a, 0x0f, 0xa1, 0xb2, 0xe4, 0x47, 0x50, 0xe4,
            0x7a, 0xc2, 0xab, 0x80, 0x2f, 0xf6, 0xe5, 0x3a, 0xfb,
            0xfc, 0xd5, 0xb3, 0x8f, 0xb5, 0x43, 0xbb, 0x31, 0x7b,
            0x57, 0xde, 0xf7, 0xb8, 0x1d, 0xc2, 0x30, 0xf7, 0xc3,
            0x7e, 0x28, 0x07, 0x43, 0x3e, 0xdb, 0x7f, 0x18, 0xe2,
            0xeb, 0xc2, 0xda, 0x37, 0x42, 0xfd, 0x2f, 0xd0, 0x61,
            0x10, 0x96, 0x85, 0xfe, 0x09, 0xd2, 0xc4, 0xcf, 0x4d,
            0x5c, 0xfc, 0xdd, 0xf3, 0x07, 0x9b, 0xec, 0x24, 0xa6,
            0x13, 0x1a, 0x31, 0x46, 0xfd, 0xa9, 0x01, 0x0e, 0x8f,
            0x8d, 0xb0, 0x47, 0x8b, 0x26, 0x5e, 0xa8, 0x75, 0xe0,
            0x55, 0xd5, 0x87, 0xda, 0x61, 0xae, 0x8c, 0x88, 0xc8,
            0x54, 0x86, 0x1b, 0x41, 0xe3, 0x8e, 0x4a, 0x72, 0x08,
            0x63, 0xd4, 0xcb, 0xad, 0x1d, 0xe2, 0xa7, 0xa5, 0x71,
            0x95, 0xb9, 0xce, 0xbc, 0xbb, 0x52, 0x73, 0xe9, 0x44,
            0xbe, 0xb1, 0xa1, 0x3d, 0xb9, 0x32, 0x8a, 0x97, 0xb2,
            0x0b, 0x02, 0xab, 0x53, 0x61, 0x3f, 0x1e, 0x12, 0x0a,
            0x42, 0xac, 0x64, 0x74, 0xf5, 0x55, 0x92, 0x34, 0x52,
            0x22, 0x0e, 0x79, 0x1a, 0xb9, 0x9b, 0x25, 0x1b, 0x79,
            0xb7, 0xf0, 0x7e, 0xd1, 0x19, 0x16, 0xe3, 0xf8, 0x30,
            0x99, 0x25, 0xd8, 0x55, 0x58, 0x09, 0x7e, 0x2c, 0x4c,
            0x86, 0xba, 0x44, 0x5f, 0x25, 0x0d, 0xb2, 0xbb, 0x3e,
            0xe7, 0xd5, 0x81, 0x32, 0x56, 0xa8, 0x6a, 0xf9, 0x88,
            0x2a, 0x26, 0xb9, 0x45, 0xd7, 0x55, 0x52, 0x83, 0xde,
            0x6a, 0x9f, 0x88, 0xee, 0x07, 0xe9, 0x3f, 0xa9, 0x93,
            0x78, 0xd2, 0x13, 0xfb, 0xc1, 0x76, 0x70, 0x72, 0x53,
            0x80, 0x99, 0x9d, 0xbc, 0xba, 0x21, 0xa7, 0xf6, 0xd6,
            0x83, 0x59, 0x19, 0x44, 0x91, 0x0e, 0x50, 0x0c, 0x81,
            0xa6, 0x5f, 0x7d, 0xf1, 0x03, 0x20, 0x21, 0x58, 0x88,
            0x03, 0x8f, 0xbf, 0xb1, 0xc7, 0xd6, 0xa0, 0x50, 0x74,
            0x82, 0x71, 0x30, 0x2f, 0xf3, 0xcc, 0xf5, 0xab, 0x7d,
            0xb3, 0xf9, 0xd8, 0xb9, 0x9b, 0x56, 0xaf, 0x48, 0xba,
            0x9d, 0x49, 0xe4, 0x9b, 0xf5, 0x90, 0xb5, 0x7b, 0x23,
            0xf9, 0x81, 0xa2, 0x7a, 0x2b, 0x4a, 0x90, 0x38, 0x3a,
            0xf4, 0x56, 0x14, 0xa7, 0xdc, 0xff, 0x57, 0xcc, 0x8a,
            0xec, 0x88, 0x1e, 0xaf, 0x07, 0x32, 0xf3, 0xc6, 0xdb,
            0x03, 0x26, 0xb0, 0x53, 0x50, 0xbe, 0x8d, 0x47, 0x61,
            0x63, 0x1b, 0xd3, 0xa1, 0xa0, 0xa4, 0x7e, 0x9c, 0xa4,
            0x90, 0x3b, 0x8a, 0xc1, 0xa2, 0xe1, 0x46, 0xdc, 0x50,
            0xca, 0x8c, 0xd1, 0x1a, 0x24, 0x8b, 0x15, 0x9c, 0x8d,
            0x69, 0x4e, 0xc1, 0x5b, 0xa3, 0xe3, 0x63, 0x1b, 0x1a,
            0x03, 0x43, 0x70, 0x40, 0x0c, 0x8e, 0x9d, 0x04, 0x79,
            0x90, 0xa6, 0xc6, 0x30, 0xa6, 0xa7, 0xa8, 0xc2, 0xda,
            0x55, 0xcc, 0x08, 0x78, 0x53, 0x17, 0x62, 0x0b, 0x53,
            0x7c, 0xd0, 0xee, 0xb7, 0x71, 0xeb, 0x05, 0xcd, 0x8d,
            0x92, 0x85, 0xdf, 0x6a, 0x67, 0xf4, 0x22, 0x72, 0x03,
            0x4f, 0x7e, 0x13, 0x0f, 0xc4, 0x35, 0x7a, 0x88, 0x62,
            0x75, 0x19, 0xd1, 0x85, 0x56, 0x13, 0xec, 0xdc, 0xae,
            0xb6, 0xf4, 0xe8, 0x5f, 0x44, 0x2e, 0xa7, 0x8c, 0x72,
            0xff, 0x6b, 0x5e, 0x6d, 0xb9, 0x17, 0xac, 0xe3, 0xfd,
            0xa8, 0xb1, 0x24, 0x59, 0x7d, 0x7b, 0xdc, 0x69, 0xb7,
            0x77, 0x53, 0xb0, 0x3b, 0x1d, 0x47, 0xa7, 0x3f, 0x39,
            0xc2, 0xed, 0x94, 0x77, 0xd5, 0x73, 0xb6, 0xaf, 0x2f,
            0x25, 0xa2, 0xca, 0x26, 0x85, 0x4a, 0x0f, 0xc7, 0x74,
            0x74, 0xb9, 0xd7, 0xb2, 0xcb, 0x02, 0xc0, 0xab, 0x55,
            0x5a, 0x84, 0x46, 0x39, 0x8f, 0x77, 0xf8, 0x29, 0xf8,
            0x50, 0x4f, 0xdc, 0xd7, 0xad, 0x6a, 0x76, 0xe9, 0x78,
            0xaa, 0x87, 0xa7, 0x1d, 0xcd, 0xa2, 0xbc, 0xc1, 0x87,
            0xcc, 0xb3, 0x76, 0x24, 0xe9, 0xab, 0x19, 0xc2, 0x81,
            0x0f, 0x50, 0x36, 0xcd, 0x96, 0x90, 0x4c, 0xfe, 0x74,
            0xca, 0x1a, 0xed, 0x2a, 0x8c, 0x3e, 0xb6, 0x16, 0x42,
            0x47, 0xf5, 0xe7, 0xdc, 0xfb, 0xc5, 0x47, 0x6a, 0x7d,
            0x57, 0xb9, 0xb1, 0x51, 0xad, 0xba, 0xb4, 0x5c, 0x5f,
            0xe0, 0x8a, 0xd4, 0x1b, 0x39, 0xf2, 0x1f, 0xe9, 0x93,
            0x59, 0xde, 0x9f, 0xf0, 0x8f, 0xce, 0x07, 0x5c, 0xb3,
            0x82, 0x1d, 0x1e, 0x83, 0x5a, 0x89, 0x3a, 0x79, 0xbb,
            0x6b, 0x4c, 0x58, 0x67, 0xef, 0x74, 0x73, 0x84, 0x6a,
            0xc1, 0x06, 0x51, 0x0b, 0xa1, 0x1a, 0x85, 0xb9, 0xbd,
            0x55, 0x5c, 0xf3, 0xdd, 0xa2, 0x60, 0x7a, 0xa7, 0x20,
            0xb8, 0x84, 0xbf, 0x16, 0x16, 0x6d, 0xb9, 0x55, 0xf0,
            0xa0, 0xcd, 0x69, 0x04, 0x9e, 0x81, 0xe4, 0xec, 0x51,
            0xc5, 0x56, 0x79, 0x87, 0x6b, 0x34, 0xf6, 0x08, 0x34,
            0x58, 0x45, 0xd9, 0x47, 0x11, 0x4f, 0xcc, 0x70, 0x5d,
            0x3c, 0xac, 0x74, 0x55, 0xcd, 0xb1, 0x87, 0xa0, 0xa4,
            0x78, 0x5c, 0x3f, 0xea, 0x26, 0x9d, 0x6d, 0xef, 0xf5,
            0x7c, 0x0f, 0x9b, 0xb4, 0x7d, 0xd9, 0xda, 0x0a, 0x00,
            0xbd, 0x19, 0xe1, 0xed, 0x17, 0x90, 0xad, 0x49, 0x95,
            0xbb, 0x54, 0x60, 0x7c, 0x68, 0x21, 0xa1, 0x13, 0x92,
            0x5f, 0x72, 0x74, 0x48, 0xc5, 0x8f, 0x3d, 0x59, 0x17,
            0xc1, 0x21, 0x09, 0x2e, 0xe5, 0x93, 0x93, 0xad, 0xbc,
            0xfc, 0x67, 0x90, 0x19, 0xc4, 0xe6, 0x04, 0x8b, 0x39,
            0x91, 0xa6, 0xc5, 0xbf, 0xc4, 0xc3, 0xdb, 0x72, 0x38,
            0x71, 0xe9, 0xee, 0xe7, 0xa0, 0x57, 0x27, 0x41, 0x4c,
            0x98, 0x06, 0x1e, 0xec, 0x59, 0x1d, 0xf6, 0xf9, 0x5d,
            0x20, 0x97, 0xac, 0xe4, 0xcc, 0xbe, 0xf2, 0x36, 0xba,
            0x30, 0x0d, 0x3a, 0xea, 0x2b, 0x06, 0xaa, 0xa7, 0xb4,
            0x86, 0x26, 0x29, 0x19, 0xd0, 0x41, 0xd1, 0x8e, 0x79,
            0xd8, 0xb2, 0x4c, 
        ];

        let dcid = [ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 ];

        let frames = [
            0x06, 0x00, 0x40, 0xc4, 0x01, 0x00, 0x00, 0xc0, 0x03,
            0x03, 0x66, 0x60, 0x26, 0x1f, 0xf9, 0x47, 0xce, 0xa4,
            0x9c, 0xce, 0x6c, 0xfa, 0xd6, 0x87, 0xf4, 0x57, 0xcf,
            0x1b, 0x14, 0x53, 0x1b, 0xa1, 0x41, 0x31, 0xa0, 0xe8,
            0xf3, 0x09, 0xa1, 0xd0, 0xb9, 0xc4, 0x00, 0x00, 0x06,
            0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00,
            0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00,
            0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12,
            0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01,
            0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04,
            0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x4c, 0xfd, 0xfc, 0xd1,
            0x78, 0xb7, 0x84, 0xbf, 0x32, 0x8c, 0xae, 0x79, 0x3b,
            0x13, 0x6f, 0x2a, 0xed, 0xce, 0x00, 0x5f, 0xf1, 0x83,
            0xd7, 0xbb, 0x14, 0x95, 0x20, 0x72, 0x36, 0x64, 0x70,
            0x37, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
            0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03,
            0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08,
            0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
            0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00,
            0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02,
            0x40, 0x01, 
        ];

        test_decrypt_pkt(&mut pkt, &dcid, true, &frames, 0, 4);
    }

    #[test]
    fn decrypt_server_initial() {
        let mut pkt = [ 
            0xc2, 0xff, 0x00, 0x00, 0x12, 0x05, 0xf0, 0x67, 0xa5,
            0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00, 0x40, 0x74, 0x28,
            0xf6, 0x3f, 0x2a, 0xbf, 0x65, 0xa0, 0x3e, 0x3e, 0x7c,
            0xe0, 0x41, 0x08, 0x7c, 0xb1, 0x1f, 0xd7, 0xba, 0x33,
            0x8b, 0x4f, 0xcd, 0x9e, 0x22, 0xbb, 0xdb, 0x5c, 0xff,
            0x66, 0x21, 0x8a, 0x8a, 0xc4, 0x82, 0x69, 0x09, 0x8d,
            0x73, 0x57, 0x72, 0x22, 0xd3, 0xe0, 0x2a, 0xf7, 0xeb,
            0x40, 0x17, 0x96, 0xa2, 0xd6, 0x7c, 0x1c, 0x9e, 0x89,
            0xd0, 0xdc, 0x5a, 0x5d, 0xfc, 0x6c, 0xee, 0xad, 0xf4,
            0xeb, 0xd4, 0xea, 0xe0, 0xe3, 0x18, 0x5d, 0xfe, 0x99,
            0xa7, 0xf5, 0x92, 0x88, 0xaf, 0xaa, 0x75, 0x53, 0x9c,
            0xfa, 0xd2, 0xba, 0xb4, 0x40, 0x12, 0x6a, 0x57, 0x21,
            0x33, 0x25, 0xf8, 0x6d, 0x3b, 0x8a, 0x5c, 0xb1, 0x3b,
            0x33, 0xf7, 0x3a, 0x63, 0x17, 0xe3, 0x4f, 0x73, 0xac,
            0x35, 0xba, 0x3d, 0x7a, 0x1f, 0x0b, 0x5c, 
        ];

        let dcid = [ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 ];

        let frames = [
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x18, 0x41, 0x0a, 0x02,
            0x00, 0x00, 0x56, 0x03, 0x03, 0xee, 0xfc, 0xe7, 0xf7,
            0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25,
            0xdf, 0x56, 0x6d, 0xc5, 0x43, 0x0b, 0x9a, 0x04, 0x5a,
            0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33,
            0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94,
            0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0, 0x8a, 0x60, 0x99,
            0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28,
            0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9,
            0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 
        ];

        test_decrypt_pkt(&mut pkt, &dcid, false, &frames, 0, 2);
    }
}
