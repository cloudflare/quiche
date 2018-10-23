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

use std::cmp;
use std::fmt;
use std::slice;

use ::Result;
use ::Error;

use octets;
use crypto;
use rand;
use stream;

const FORM_BIT: u8 = 0x80;
const KEY_PHASE_BIT: u8 = 0x40;
const DEMUX_BIT: u8 = 0x08;

const TYPE_MASK: u8 = 0x7f;

const MAX_CID_LEN: u8 = 18;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type {
    Initial,
    Retry,
    Handshake,
    ZeroRTT,
    VersionNegotiation,
    Application,
}

pub fn has_long_header(b: u8) -> bool {
    b & FORM_BIT != 0
}

#[derive(Clone)]
pub struct Header {
    pub ty: Type,
    pub version: u32,
    pub flags: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Option<Vec<u8>>,
}

impl Header {
    pub fn decode_long(buf: &mut [u8]) -> Result<Header> {
        let mut b = octets::Bytes::new(buf);
        Header::long_from_bytes(&mut b)
    }

    pub fn decode_short(buf: &mut [u8], dcil: usize) -> Result<Header> {
        let mut b = octets::Bytes::new(buf);
        Header::short_from_bytes(&mut b, dcil)
    }

    pub fn long_from_bytes(b: &mut octets::Bytes) -> Result<Header> {
        let first = b.get_u8()?;

        if !has_long_header(first) {
            return Err(Error::WrongForm);
        }

        let version = b.get_u32()?;

        let ty = if version == 0 {
            Type::VersionNegotiation
        } else {
            match first & TYPE_MASK {
                0x7f => Type::Initial,
                0x7e => Type::Retry,
                0x7d => Type::Handshake,
                0x7c => Type::ZeroRTT,
                _    => return Err(Error::UnknownPacket),
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

        match ty {
            Type::Initial => {
                token = Some(b.get_bytes_with_varint_length()?.to_vec());
            },

            Type::Retry => {
                panic!("Retry not supported");
            },

            Type::VersionNegotiation => {
                panic!("Version negotiation not supported");
            },

            _ => (),
        };

        Ok(Header {
            ty,
            flags: first & FORM_BIT,
            version,
            dcid,
            scid,
            token,
        })
    }

    pub fn long_to_bytes(hdr: &Header, out: &mut octets::Bytes) -> Result<()> {
        let ty: u8 = match hdr.ty {
                Type::Initial   => 0x7f,
                Type::Retry     => 0x7e,
                Type::Handshake => 0x7d,
                Type::ZeroRTT   => 0x7c,
                // TODO: unify handling of version negotiation
                _               => return Err(Error::UnknownPacket),
        };

        let first = FORM_BIT | ty;

        out.put_u8(first)?;

        out.put_u32(hdr.version)?;

        let mut cil: u8 = 0;

        if hdr.dcid.len() > 0 {
            cil |= ((hdr.dcid.len() - 3) as u8) << 4;
        }

        if hdr.scid.len() > 0 {
            cil |= ((hdr.scid.len() - 3) as u8) & 0xf;
        }

        out.put_u8(cil)?;

        out.put_bytes(&hdr.dcid)?;
        out.put_bytes(&hdr.scid)?;

        // Only Initial packet have a token.
        if hdr.ty == Type::Initial {
            match hdr.token {
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

    pub fn short_from_bytes(b: &mut octets::Bytes, dcil: usize) -> Result<Header> {
        let first = b.get_u8()?;

        if has_long_header(first) {
            return Err(Error::WrongForm);
        }

        let dcid = b.get_bytes(dcil)?;

        Ok(Header {
            ty: Type::Application,
            flags: first & FORM_BIT,
            version: 0,
            dcid: dcid.to_vec(),
            scid: Vec::new(),
            token: None,
        })
    }

    pub fn short_to_bytes(hdr: &Header, out: &mut octets::Bytes) -> Result<()> {
        let mut first = rand::rand_u8();

        // Unset form bit for short header.
        first &= !FORM_BIT;

        // TODO: support key update
        first &= !KEY_PHASE_BIT;

        // "The third bit (0x20) of octet 0 is set to 1."
        first |= 0x20;

        // "The fourth bit (0x10) of octet 0 is set to 1."
        first |= 0x10;

        // Clear Google QUIC demultiplexing bit
        first &= !DEMUX_BIT;

        out.put_u8(first)?;
        out.put_bytes(&hdr.dcid)?;

        Ok(())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.ty)?;

        if self.ty != Type::Application {
            write!(f, " vers={:x}", self.version)?;
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

        Ok(())
    }
}

pub fn pkt_num_len(pn: u64) -> Result<usize> {
    let len = if pn < 128 {
        1
    } else if pn < 16384 {
        2
    } else if pn < 1_073_741_824 {
        4
    } else {
        return Err(Error::InvalidPacket);
    };

    Ok(len)
}

pub fn decrypt_pkt_num(b: &mut octets::Bytes, aead: &crypto::Open)
                                                    -> Result<(u64,usize)> {
    let max_pn_len = cmp::min(b.cap() - aead.pn_nonce_len(), 4);

    let mut pn_and_sample = b.peek_bytes(max_pn_len + aead.pn_nonce_len())?;

    let (mut ciphertext, sample) = pn_and_sample.split_at(max_pn_len).unwrap();

    let ciphertext = ciphertext.as_mut();

    // Decrypt first byte of pkt num into separate buffer to get length.
    let mut first: u8 = ciphertext[0];

    aead.xor_keystream(sample.as_ref(), slice::from_mut(&mut first))?;

    let len = if first >> 7 == 0 {
        1
    } else {
        // Map most significant 2 bits to actual pkt num length.
        match first >> 6 {
            2 => 2,
            3 => 4,
            _ => return Err(Error::InvalidPacket),
        }
    };

    // Decrypt full pkt num in-place.
    aead.xor_keystream(sample.as_ref(), &mut ciphertext[..len])?;

    let mut plaintext = Vec::with_capacity(len);
    plaintext.extend_from_slice(&ciphertext[..len]);

    // Mask the 2 most significant bits to remove the encoded length.
    if len > 1 {
        plaintext[0] &= 0x3f;
    }

    let mut b = octets::Bytes::new(&mut plaintext);

    // Extract packet number corresponding to the decoded length.
    let out = match len {
        1 => u64::from(b.get_u8()?),
        2 => u64::from(b.get_u16()?),
        4 => u64::from(b.get_u32()?),
        _ => return Err(Error::InvalidPacket),
    };

    // TODO: implement packet number truncation
    Ok((out as u64, len))
}

pub fn encode_pkt_num(pn: u64, b: &mut octets::Bytes) -> Result<()> {
    let len = pkt_num_len(pn)?;

    match len {
        1 => {
            let mut buf = b.put_u8(pn as u8)?;
            buf[0] &= !0x80;
        },

        2 => {
            let mut buf = b.put_u16(pn as u16)?;
            buf[0] &= !0xc0;
            buf[0] |= 0x80;
        },

        4 => {
            let mut buf = b.put_u32(pn as u32)?;
            buf[0] |= 0xc0;
        },

        _ => return Err(Error::InvalidPacket),
    };

    Ok(())
}

pub fn decrypt_pkt(payload: &mut [u8], pn: u64, ad: &[u8], aead: &crypto::Open)
                                                            -> Result<usize> {
    aead.open_with_u64_counter(pn, ad, payload)
}

pub fn encrypt_pkt(payload: &mut [u8], pn: u64, ad: &[u8], aead: &crypto::Seal)
                                                            -> Result<usize> {
    aead.seal_with_u64_counter(pn, ad, payload)
}

pub fn negotiate_version(hdr: &Header, out: &mut [u8]) -> Result<usize> {
    let mut b = octets::Bytes::new(out);

    let first = rand::rand_u8() | FORM_BIT;

    b.put_u8(first)?;
    b.put_u32(0)?;

    // Invert client's scid and dcid.
    let mut cil: u8 = 0;
    if hdr.scid.len() > 0 {
        cil |= ((hdr.scid.len() - 3) as u8) << 4;
    }

    if hdr.dcid.len() > 0 {
        cil |= ((hdr.dcid.len() - 3) as u8) & 0xf;
    }

    b.put_u8(cil)?;
    b.put_bytes(&hdr.scid)?;
    b.put_bytes(&hdr.dcid)?;
    b.put_u32(::VERSION_DRAFT15)?;

    Ok(b.off())
}

pub struct PktNumSpace {
    pub pkt_type: Type,

    pub expected_pkt_num: u64,

    pub last_pkt_num: u64,

    pub need_ack: Vec<u64>,

    pub crypto_level: crypto::Level,

    pub crypto_open: Option<crypto::Open>,
    pub crypto_seal: Option<crypto::Seal>,

    pub crypto_stream: stream::Stream,
}

impl PktNumSpace {
    pub fn new(ty: Type, crypto_level: crypto::Level) -> PktNumSpace {
        PktNumSpace {
            pkt_type: ty,

            expected_pkt_num: 0,

            last_pkt_num: 0,

            need_ack: Vec::new(),

            crypto_level,

            crypto_open: None,
            crypto_seal: None,

            crypto_stream: stream::Stream::default(),
        }
    }

    pub fn cipher(&self) -> crypto::Algorithm {
        match self.crypto_open {
            Some(ref v) => v.algorithm(),
            None => crypto::Algorithm::Null,
        }
    }

    pub fn overhead(&self) -> usize {
        self.crypto_seal.as_ref().unwrap().tag_len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn decrypt_initial() {
        decrypt_initial_helper("test_data/initial_ngtcp2.txt");
        decrypt_initial_helper("test_data/initial_quicly.txt");
    }

    fn decrypt_initial_helper(file_name: &'static str) {
        let mut file = File::open(file_name).unwrap();

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let mut b = octets::Bytes::new(&mut buf);

        let hdr = Header::long_from_bytes(&mut b).unwrap();

        let payload_len = b.get_varint().unwrap() as usize;

        let (aead_open, _) =
            crypto::derive_initial_key_material(&hdr.dcid, true).unwrap();

        let (pn, pn_len) = decrypt_pkt_num(&mut b, &aead_open).unwrap();
        b.skip(pn_len).unwrap();

        let payload_offset = b.off();

        let (header, mut payload) = b.split_at(payload_offset).unwrap();

        decrypt_pkt(payload.slice(payload_len - pn_len).unwrap(),
                    pn, header.as_ref(), &aead_open).unwrap();
    }
}
