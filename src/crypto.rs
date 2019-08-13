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

use ring::aead;
use ring::hkdf;

use crate::Error;
use crate::Result;

use crate::packet;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Initial     = 0,
    // Silence "variant is never constructed" warning because the value can
    // be received from BoringSSL as part of the FFI callbacks.
    #[allow(dead_code)]
    ZeroRTT     = 1,
    Handshake   = 2,
    Application = 3,
}

impl Level {
    pub fn from_epoch(e: packet::Epoch) -> Level {
        match e {
            packet::EPOCH_INITIAL => Level::Initial,

            packet::EPOCH_HANDSHAKE => Level::Handshake,

            packet::EPOCH_APPLICATION => Level::Application,

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

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let nonce = make_nonce(&self.nonce, counter);

        let ad = aead::Aad::from(ad);

        let plain = self
            .key
            .open_in_place(nonce, ad, buf)
            .map_err(|_| Error::CryptoFail)?;

        Ok(plain.len())
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
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

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<()> {
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
    cid: &[u8], is_server: bool,
) -> Result<(Open, Seal)> {
    let mut secret = [0; 32];

    let aead = Algorithm::AES128_GCM;

    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();

    let initial_secret = derive_initial_secret(&cid)?;

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

fn derive_initial_secret(secret: &[u8]) -> Result<hkdf::Prk> {
    const INITIAL_SALT: [u8; 20] = [
        0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd,
        0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a,
    ];

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT);
    Ok(salt.extract(secret))
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
    let mut nonce = [0; 12];
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
        let dcid = [0xc6, 0x54, 0xef, 0xd8, 0xa3, 0x1b, 0x47, 0x92];

        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];

        let aead = Algorithm::AES128_GCM;

        let initial_secret = derive_initial_secret(&dcid).unwrap();

        // Client.
        assert!(
            derive_client_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_client_initial_secret = [
            0xf3, 0x30, 0x76, 0x33, 0x57, 0xe7, 0x8b, 0xa3, 0xc9, 0x48, 0xa5,
            0xbb, 0xbe, 0x28, 0xaa, 0x2a, 0x38, 0x6c, 0x10, 0xc7, 0xf4, 0x32,
            0xd8, 0x97, 0xa7, 0x7e, 0x2b, 0x24, 0x4b, 0x03, 0x05, 0x33,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0xd4, 0xe4, 0x3d, 0x22, 0x68, 0xf8, 0xe4, 0x3b, 0xab, 0x1c, 0xa6,
            0x7a, 0x36, 0x80, 0x46, 0x0f,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0x67, 0x1f, 0x1c, 0x3d, 0x21, 0xde, 0x47, 0xff, 0x01, 0x8b, 0x11,
            0x3b,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0xed, 0x6c, 0x63, 0x14, 0xdd, 0xc8, 0x69, 0xa5, 0x94, 0x19, 0x74,
            0x42, 0x87, 0x71, 0x39, 0x83,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Server.
        assert!(
            derive_server_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_server_initial_secret = [
            0x5e, 0x84, 0x2c, 0xcb, 0x6c, 0xac, 0x42, 0xa7, 0x22, 0x48, 0xbd,
            0x57, 0xd3, 0x30, 0x64, 0x65, 0xd3, 0xde, 0x66, 0x50, 0x64, 0x1e,
            0x1f, 0xb1, 0x34, 0xdc, 0x87, 0xf5, 0x4a, 0xc8, 0xad, 0x74,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0x9d, 0xa3, 0x3b, 0xa0, 0x27, 0x46, 0xa3, 0xd3, 0x58, 0x12, 0x89,
            0xc0, 0x19, 0x9c, 0x3a, 0xf2,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0xe6, 0x9c, 0x4e, 0xaf, 0xce, 0x11, 0x3d, 0xb5, 0x70, 0xb9, 0x4c,
            0x0c,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xc5, 0x0f, 0x34, 0x99, 0x5b, 0x8a, 0xa7, 0x16, 0x08, 0x7b, 0x64,
            0x87, 0x6e, 0xdd, 0x68, 0x38,
        ];
        assert_eq!(&hdr_key, &expected_server_hdr_key);
    }

    #[test]
    fn derive_initial_secrets2() {
        let dcid = [0xc6, 0x54, 0xef, 0xd8, 0xa3, 0x1b, 0x47, 0x92];

        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];

        let aead = Algorithm::AES128_GCM;

        let initial_secret = derive_initial_secret(&dcid).unwrap();

        // Client.
        assert!(
            derive_client_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_client_initial_secret = [
            0xf3, 0x30, 0x76, 0x33, 0x57, 0xe7, 0x8b, 0xa3, 0xc9, 0x48, 0xa5,
            0xbb, 0xbe, 0x28, 0xaa, 0x2a, 0x38, 0x6c, 0x10, 0xc7, 0xf4, 0x32,
            0xd8, 0x97, 0xa7, 0x7e, 0x2b, 0x24, 0x4b, 0x03, 0x05, 0x33,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0xd4, 0xe4, 0x3d, 0x22, 0x68, 0xf8, 0xe4, 0x3b, 0xab, 0x1c, 0xa6,
            0x7a, 0x36, 0x80, 0x46, 0x0f,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0x67, 0x1f, 0x1c, 0x3d, 0x21, 0xde, 0x47, 0xff, 0x01, 0x8b, 0x11,
            0x3b,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0xed, 0x6c, 0x63, 0x14, 0xdd, 0xc8, 0x69, 0xa5, 0x94, 0x19, 0x74,
            0x42, 0x87, 0x71, 0x39, 0x83,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Server.
        assert!(
            derive_server_initial_secret(&initial_secret, &mut secret).is_ok()
        );
        let expected_server_initial_secret = [
            0x5e, 0x84, 0x2c, 0xcb, 0x6c, 0xac, 0x42, 0xa7, 0x22, 0x48, 0xbd,
            0x57, 0xd3, 0x30, 0x64, 0x65, 0xd3, 0xde, 0x66, 0x50, 0x64, 0x1e,
            0x1f, 0xb1, 0x34, 0xdc, 0x87, 0xf5, 0x4a, 0xc8, 0xad, 0x74,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0x9d, 0xa3, 0x3b, 0xa0, 0x27, 0x46, 0xa3, 0xd3, 0x58, 0x12, 0x89,
            0xc0, 0x19, 0x9c, 0x3a, 0xf2,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0xe6, 0x9c, 0x4e, 0xaf, 0xce, 0x11, 0x3d, 0xb5, 0x70, 0xb9, 0x4c,
            0x0c,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xc5, 0x0f, 0x34, 0x99, 0x5b, 0x8a, 0xa7, 0x16, 0x08, 0x7b, 0x64,
            0x87, 0x6e, 0xdd, 0x68, 0x38,
        ];
        assert_eq!(&hdr_key, &expected_server_hdr_key);
    }
}
