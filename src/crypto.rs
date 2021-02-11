// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use ring::aead;
use ring::hkdf;

use crate::Error;
use crate::Result;

use crate::packet;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Initial   = 0,
    ZeroRTT   = 1,
    Handshake = 2,
    OneRTT    = 3,
}

impl Level {
    pub fn from_epoch(e: packet::Epoch) -> Level {
        match e {
            packet::EPOCH_INITIAL => Level::Initial,

            packet::EPOCH_HANDSHAKE => Level::Handshake,

            packet::EPOCH_APPLICATION => Level::OneRTT,

            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    #[allow(non_camel_case_types)]
    AES128_GCM,

    #[allow(non_camel_case_types)]
    AES256_GCM,

    #[allow(non_camel_case_types)]
    ChaCha20_Poly1305,
}

impl Algorithm {
    fn get_ring_aead(self) -> &'static aead::Algorithm {
        match self {
            Algorithm::AES128_GCM => &aead::AES_128_GCM,
            Algorithm::AES256_GCM => &aead::AES_256_GCM,
            Algorithm::ChaCha20_Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    fn get_ring_hp(self) -> &'static aead::quic::Algorithm {
        match self {
            Algorithm::AES128_GCM => &aead::quic::AES_128,
            Algorithm::AES256_GCM => &aead::quic::AES_256,
            Algorithm::ChaCha20_Poly1305 => &aead::quic::CHACHA20,
        }
    }

    fn get_ring_digest(self) -> hkdf::Algorithm {
        match self {
            Algorithm::AES128_GCM => hkdf::HKDF_SHA256,
            Algorithm::AES256_GCM => hkdf::HKDF_SHA384,
            Algorithm::ChaCha20_Poly1305 => hkdf::HKDF_SHA256,
        }
    }

    pub fn key_len(self) -> usize {
        self.get_ring_aead().key_len()
    }

    pub fn tag_len(self) -> usize {
        if cfg!(feature = "fuzzing") {
            return 0;
        }

        self.get_ring_aead().tag_len()
    }

    pub fn nonce_len(self) -> usize {
        self.get_ring_aead().nonce_len()
    }
}

pub struct Open {
    alg: Algorithm,

    hp_key: aead::quic::HeaderProtectionKey,

    key: aead::LessSafeKey,

    nonce: Vec<u8>,
}

impl Open {
    pub fn new(
        alg: Algorithm, key: &[u8], iv: &[u8], hp_key: &[u8],
    ) -> Result<Open> {
        Ok(Open {
            hp_key: aead::quic::HeaderProtectionKey::new(
                alg.get_ring_hp(),
                hp_key,
            )
            .map_err(|_| Error::CryptoFail)?,

            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(alg.get_ring_aead(), key)
                    .map_err(|_| Error::CryptoFail)?,
            ),

            nonce: Vec::from(iv),

            alg,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8]) -> Result<Open> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];
        let mut pn_key = vec![0; key_len];

        derive_pkt_key(aead, &secret, &mut key)?;
        derive_pkt_iv(aead, &secret, &mut iv)?;
        derive_hdr_key(aead, &secret, &mut pn_key)?;

        Open::new(aead, &key, &iv, &pn_key)
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            return Ok(buf.len());
        }

        let nonce = make_nonce(&self.nonce, counter);

        let ad = aead::Aad::from(ad);

        let plain = self
            .key
            .open_in_place(nonce, ad, buf)
            .map_err(|_| Error::CryptoFail)?;

        Ok(plain.len())
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if cfg!(feature = "fuzzing") {
            return Ok(<[u8; 5]>::default());
        }

        let mask = self
            .hp_key
            .new_mask(sample)
            .map_err(|_| Error::CryptoFail)?;

        Ok(mask)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }
}

pub struct Seal {
    alg: Algorithm,

    hp_key: aead::quic::HeaderProtectionKey,

    key: aead::LessSafeKey,

    nonce: Vec<u8>,
}

impl Seal {
    pub fn new(
        alg: Algorithm, key: &[u8], iv: &[u8], hp_key: &[u8],
    ) -> Result<Seal> {
        Ok(Seal {
            hp_key: aead::quic::HeaderProtectionKey::new(
                alg.get_ring_hp(),
                hp_key,
            )
            .map_err(|_| Error::CryptoFail)?,

            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(alg.get_ring_aead(), key)
                    .map_err(|_| Error::CryptoFail)?,
            ),

            nonce: Vec::from(iv),

            alg,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8]) -> Result<Seal> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];
        let mut pn_key = vec![0; key_len];

        derive_pkt_key(aead, &secret, &mut key)?;
        derive_pkt_iv(aead, &secret, &mut iv)?;
        derive_hdr_key(aead, &secret, &mut pn_key)?;

        Seal::new(aead, &key, &iv, &pn_key)
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<()> {
        if cfg!(feature = "fuzzing") {
            return Ok(());
        }

        let nonce = make_nonce(&self.nonce, counter);

        let ad = aead::Aad::from(ad);

        let tag_len = self.alg().tag_len();

        let in_out_len =
            buf.len().checked_sub(tag_len).ok_or(Error::CryptoFail)?;

        let (in_out, tag_out) = buf.split_at_mut(in_out_len);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, ad, in_out)
            .map_err(|_| Error::CryptoFail)?;

        // Append the AEAD tag to the end of the sealed buffer.
        tag_out.copy_from_slice(tag.as_ref());

        Ok(())
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if cfg!(feature = "fuzzing") {
            return Ok(<[u8; 5]>::default());
        }

        let mask = self
            .hp_key
            .new_mask(sample)
            .map_err(|_| Error::CryptoFail)?;

        Ok(mask)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }
}

pub fn derive_initial_key_material(
    cid: &[u8], version: u32, is_server: bool,
) -> Result<(Open, Seal)> {
    let mut secret = [0; 32];

    let aead = Algorithm::AES128_GCM;

    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();

    let initial_secret = derive_initial_secret(&cid, version);

    // Client.
    let mut client_key = vec![0; key_len];
    let mut client_iv = vec![0; nonce_len];
    let mut client_hp_key = vec![0; key_len];

    derive_client_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut client_key)?;
    derive_pkt_iv(aead, &secret, &mut client_iv)?;
    derive_hdr_key(aead, &secret, &mut client_hp_key)?;

    // Server.
    let mut server_key = vec![0; key_len];
    let mut server_iv = vec![0; nonce_len];
    let mut server_hp_key = vec![0; key_len];

    derive_server_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut server_key)?;
    derive_pkt_iv(aead, &secret, &mut server_iv)?;
    derive_hdr_key(aead, &secret, &mut server_hp_key)?;

    let (open, seal) = if is_server {
        (
            Open::new(aead, &client_key, &client_iv, &client_hp_key)?,
            Seal::new(aead, &server_key, &server_iv, &server_hp_key)?,
        )
    } else {
        (
            Open::new(aead, &server_key, &server_iv, &server_hp_key)?,
            Seal::new(aead, &client_key, &client_iv, &client_hp_key)?,
        )
    };

    Ok((open, seal))
}

fn derive_initial_secret(secret: &[u8], version: u32) -> hkdf::Prk {
    const INITIAL_SALT: [u8; 20] = [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1,
        0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
    ];

    const INITIAL_SALT_OLD: [u8; 20] = [
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43,
        0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
    ];

    let salt = match version {
        crate::PROTOCOL_VERSION_DRAFT27 | crate::PROTOCOL_VERSION_DRAFT28 =>
            &INITIAL_SALT_OLD,

        _ => &INITIAL_SALT,
    };

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    salt.extract(secret)
}

fn derive_client_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"client in";
    hkdf_expand_label(prk, LABEL, out)
}

fn derive_server_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"server in";
    hkdf_expand_label(prk, LABEL, out)
}

pub fn derive_hdr_key(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"quic hp";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_key(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"quic key";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_iv(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"quic iv";

    let nonce_len = aead.nonce_len();

    if nonce_len > out.len() {
        return Err(Error::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..nonce_len])
}

fn hkdf_expand_label(
    prk: &hkdf::Prk, label: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let out_len = (out.len() as u16).to_be_bytes();
    let label_len = (LABEL_PREFIX.len() + label.len()) as u8;

    let info = [&out_len, &[label_len][..], LABEL_PREFIX, label, &[0][..]];

    prk.expand(&info, ArbitraryOutputLen(out.len()))
        .map_err(|_| Error::CryptoFail)?
        .fill(out)
        .map_err(|_| Error::CryptoFail)?;

    Ok(())
}

fn make_nonce(iv: &[u8], counter: u64) -> aead::Nonce {
    let mut nonce = [0; aead::NONCE_LEN];
    nonce.copy_from_slice(&iv);

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    aead::Nonce::assume_unique_for_key(nonce)
}

// The ring HKDF expand() API does not accept an arbitrary output length, so we
// need to hide the `usize` length as part of a type that implements the trait
// `ring::hkdf::KeyType` in order to trick ring into accepting it.
struct ArbitraryOutputLen(usize);

impl hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_initial_secrets() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];

        let aead = Algorithm::AES128_GCM;

        let initial_secret =
            derive_initial_secret(&dcid, crate::PROTOCOL_VERSION);

        // Client.
        assert!(
            derive_client_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_client_initial_secret = [
            0x00, 0x88, 0x11, 0x92, 0x88, 0xf1, 0xd8, 0x66, 0x73, 0x3c, 0xee,
            0xed, 0x15, 0xff, 0x9d, 0x50, 0x90, 0x2c, 0xf8, 0x29, 0x52, 0xee,
            0xe2, 0x7e, 0x9d, 0x4d, 0x49, 0x18, 0xea, 0x37, 0x1d, 0x87,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0x17, 0x52, 0x57, 0xa3, 0x1e, 0xb0, 0x9d, 0xea, 0x93, 0x66, 0xd8,
            0xbb, 0x79, 0xad, 0x80, 0xba,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0x6b, 0x26, 0x11, 0x4b, 0x9c, 0xba, 0x2b, 0x63, 0xa9, 0xe8, 0xdd,
            0x4f,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0x9d, 0xdd, 0x12, 0xc9, 0x94, 0xc0, 0x69, 0x8b, 0x89, 0x37, 0x4a,
            0x9c, 0x07, 0x7a, 0x30, 0x77,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Server.
        assert!(
            derive_server_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_server_initial_secret = [
            0x00, 0x6f, 0x88, 0x13, 0x59, 0x24, 0x4d, 0xd9, 0xad, 0x1a, 0xcf,
            0x85, 0xf5, 0x95, 0xba, 0xd6, 0x7c, 0x13, 0xf9, 0xf5, 0x58, 0x6f,
            0x5e, 0x64, 0xe1, 0xac, 0xae, 0x1d, 0x9e, 0xa8, 0xf6, 0x16,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0x14, 0x9d, 0x0b, 0x16, 0x62, 0xab, 0x87, 0x1f, 0xbe, 0x63, 0xc4,
            0x9b, 0x5e, 0x65, 0x5a, 0x5d,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0xba, 0xb2, 0xb1, 0x2a, 0x4c, 0x76, 0x01, 0x6a, 0xce, 0x47, 0x85,
            0x6d,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xc0, 0xc4, 0x99, 0xa6, 0x5a, 0x60, 0x02, 0x4a, 0x18, 0xa2, 0x50,
            0x97, 0x4e, 0xa0, 0x1d, 0xfa,
        ];
        assert_eq!(&hdr_key, &expected_server_hdr_key);
    }

    #[test]
    fn derive_initial_secrets_old() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];

        let aead = Algorithm::AES128_GCM;

        let initial_secret =
            derive_initial_secret(&dcid, crate::PROTOCOL_VERSION_DRAFT28);

        // Client.
        assert!(
            derive_client_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_client_initial_secret = [
            0xfd, 0xa3, 0x95, 0x3a, 0xec, 0xc0, 0x40, 0xe4, 0x8b, 0x34, 0xe2,
            0x7e, 0xf8, 0x7d, 0xe3, 0xa6, 0x09, 0x8e, 0xcf, 0x0e, 0x38, 0xb7,
            0xe0, 0x32, 0xc5, 0xc5, 0x7b, 0xcb, 0xd5, 0x97, 0x5b, 0x84,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0xaf, 0x7f, 0xd7, 0xef, 0xeb, 0xd2, 0x18, 0x78, 0xff, 0x66, 0x81,
            0x12, 0x48, 0x98, 0x36, 0x94,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0x86, 0x81, 0x35, 0x94, 0x10, 0xa7, 0x0b, 0xb9, 0xc9, 0x2f, 0x04,
            0x20,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0xa9, 0x80, 0xb8, 0xb4, 0xfb, 0x7d, 0x9f, 0xbc, 0x13, 0xe8, 0x14,
            0xc2, 0x31, 0x64, 0x25, 0x3d,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Server.
        assert!(
            derive_server_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_server_initial_secret = [
            0x55, 0x43, 0x66, 0xb8, 0x19, 0x12, 0xff, 0x90, 0xbe, 0x41, 0xf1,
            0x7e, 0x80, 0x22, 0x21, 0x30, 0x90, 0xab, 0x17, 0xd8, 0x14, 0x91,
            0x79, 0xbc, 0xad, 0xf2, 0x22, 0xf2, 0x9f, 0xf2, 0xdd, 0xd5,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0x5d, 0x51, 0xda, 0x9e, 0xe8, 0x97, 0xa2, 0x1b, 0x26, 0x59, 0xcc,
            0xc7, 0xe5, 0xbf, 0xa5, 0x77,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0x5e, 0x5a, 0xe6, 0x51, 0xfd, 0x1e, 0x84, 0x95, 0xaf, 0x13, 0x50,
            0x8b,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xa8, 0xed, 0x82, 0xe6, 0x66, 0x4f, 0x86, 0x5a, 0xed, 0xf6, 0x10,
            0x69, 0x43, 0xf9, 0x5f, 0xb8,
        ];
        assert_eq!(&hdr_key, &expected_server_hdr_key);
    }

    #[test]
    fn derive_chacha20_secrets() {
        let secret = [
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42,
            0x27, 0x48, 0xad, 0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0,
            0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
        ];

        let aead = Algorithm::ChaCha20_Poly1305;

        let mut pkt_key = [0; 32];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 32];

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_pkt_key = [
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20,
            0x94, 0xf6, 0x9c, 0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88,
            0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8,
        ];
        assert_eq!(&pkt_key, &expected_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_pkt_iv = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1,
            0x44,
        ];
        assert_eq!(&pkt_iv, &expected_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_hdr_key = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89,
            0x17, 0xa4, 0xfc, 0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85,
            0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
        ];
        assert_eq!(&hdr_key, &expected_hdr_key);
    }
}
