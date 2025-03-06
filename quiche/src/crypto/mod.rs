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

use libc::c_int;
use libc::c_void;

use crate::Error;
use crate::Result;

use crate::packet;

// All the AEAD algorithms we support use 96-bit nonces.
pub const MAX_NONCE_LEN: usize = 12;

// Length of header protection mask.
pub const HP_MASK_LEN: usize = 5;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Initial   = 0,
    ZeroRTT   = 1,
    Handshake = 2,
    OneRTT    = 3,
}

impl Level {
    pub fn from_epoch(e: packet::Epoch) -> Level {
        match e {
            packet::Epoch::Initial => Level::Initial,

            packet::Epoch::Handshake => Level::Handshake,

            packet::Epoch::Application => Level::OneRTT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    #[allow(non_camel_case_types)]
    AES128_GCM,

    #[allow(non_camel_case_types)]
    AES256_GCM,

    #[allow(non_camel_case_types)]
    ChaCha20_Poly1305,
}

// Note: some vendor-specific methods are implemented by each vendor's submodule
// (openssl-quictls / boringssl).
impl Algorithm {
    fn get_evp_digest(self) -> *const EVP_MD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_sha256() },
            Algorithm::AES256_GCM => unsafe { EVP_sha384() },
            Algorithm::ChaCha20_Poly1305 => unsafe { EVP_sha256() },
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Algorithm::AES128_GCM => 16,
            Algorithm::AES256_GCM => 32,
            Algorithm::ChaCha20_Poly1305 => 32,
        }
    }

    pub const fn tag_len(self) -> usize {
        if cfg!(feature = "fuzzing") {
            return 0;
        }

        match self {
            Algorithm::AES128_GCM => 16,
            Algorithm::AES256_GCM => 16,
            Algorithm::ChaCha20_Poly1305 => 16,
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Algorithm::AES128_GCM => 12,
            Algorithm::AES256_GCM => 12,
            Algorithm::ChaCha20_Poly1305 => 12,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct EVP_AEAD {
    _unused: c_void,
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct EVP_MD {
    _unused: c_void,
}

type HeaderProtectionMask = [u8; HP_MASK_LEN];

pub struct Open {
    alg: Algorithm,

    secret: Vec<u8>,

    header: HeaderProtectionKey,

    packet: PacketKey,
}

impl Open {
    // Note: some vendor-specific methods are implemented by each vendor's
    // submodule (openssl-quictls / boringssl).

    pub const DECRYPT: u32 = 0;

    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, hp_key: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Open> {
        Ok(Open {
            alg,

            secret,

            header: HeaderProtectionKey::new(alg, hp_key)?,

            packet: PacketKey::new(alg, key, iv, Self::DECRYPT)?,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8]) -> Result<Open> {
        Ok(Open {
            alg: aead,

            secret: secret.to_vec(),

            header: HeaderProtectionKey::from_secret(aead, secret)?,

            packet: PacketKey::from_secret(aead, secret, Self::DECRYPT)?,
        })
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if cfg!(feature = "fuzzing") {
            return Ok(<[u8; 5]>::default());
        }

        self.header.new_mask(sample)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    pub fn derive_next_packet_key(&self) -> Result<Open> {
        let next_secret = derive_next_secret(self.alg, &self.secret)?;

        let next_packet_key =
            PacketKey::from_secret(self.alg, &next_secret, Self::DECRYPT)?;

        Ok(Open {
            alg: self.alg,

            secret: next_secret,

            header: self.header.clone(),

            packet: next_packet_key,
        })
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            return Ok(buf.len());
        }

        self.packet.open_with_u64_counter(counter, ad, buf)
    }
}

pub struct Seal {
    alg: Algorithm,

    secret: Vec<u8>,

    header: HeaderProtectionKey,

    packet: PacketKey,
}

impl Seal {
    // Note: some vendor-specific methods are implemented by each vendor's
    // submodule (openssl-quictls / boringssl).

    pub const ENCRYPT: u32 = 1;

    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, hp_key: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Seal> {
        Ok(Seal {
            alg,

            secret,

            header: HeaderProtectionKey::new(alg, hp_key)?,

            packet: PacketKey::new(alg, key, iv, Self::ENCRYPT)?,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8]) -> Result<Seal> {
        Ok(Seal {
            alg: aead,

            secret: secret.to_vec(),

            header: HeaderProtectionKey::from_secret(aead, secret)?,

            packet: PacketKey::from_secret(aead, secret, Self::ENCRYPT)?,
        })
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if cfg!(feature = "fuzzing") {
            return Ok(<[u8; 5]>::default());
        }

        self.header.new_mask(sample)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    pub fn derive_next_packet_key(&self) -> Result<Seal> {
        let next_secret = derive_next_secret(self.alg, &self.secret)?;

        let next_packet_key =
            PacketKey::from_secret(self.alg, &next_secret, Self::ENCRYPT)?;

        Ok(Seal {
            alg: self.alg,

            secret: next_secret,

            header: self.header.clone(),

            packet: next_packet_key,
        })
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            if let Some(extra) = extra_in {
                buf[in_len..in_len + extra.len()].copy_from_slice(extra);
                return Ok(in_len + extra.len());
            }

            return Ok(in_len);
        }

        self.packet
            .seal_with_u64_counter(counter, ad, buf, in_len, extra_in)
    }
}

impl HeaderProtectionKey {
    pub fn from_secret(aead: Algorithm, secret: &[u8]) -> Result<Self> {
        let key_len = aead.key_len();

        let mut hp_key = vec![0; key_len];

        derive_hdr_key(aead, secret, &mut hp_key)?;

        Self::new(aead, hp_key)
    }
}

pub fn derive_initial_key_material(
    cid: &[u8], version: u32, is_server: bool, did_reset: bool,
) -> Result<(Open, Seal)> {
    let mut initial_secret = [0; 32];
    let mut client_secret = vec![0; 32];
    let mut server_secret = vec![0; 32];

    let aead = Algorithm::AES128_GCM;

    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();

    derive_initial_secret(cid, version, &mut initial_secret)?;

    derive_client_initial_secret(aead, &initial_secret, &mut client_secret)?;

    derive_server_initial_secret(aead, &initial_secret, &mut server_secret)?;

    // When the initial key material has been reset (e.g. due to retry or
    // version negotiation), we need to prime the AEAD context as well, as the
    // following packet will not start from 0 again. This is done through the
    // `Open/Seal::from_secret()` path, rather than `Open/Seal::new()`.
    if did_reset {
        let (open, seal) = if is_server {
            (
                Open::from_secret(aead, &client_secret)?,
                Seal::from_secret(aead, &server_secret)?,
            )
        } else {
            (
                Open::from_secret(aead, &server_secret)?,
                Seal::from_secret(aead, &client_secret)?,
            )
        };

        return Ok((open, seal));
    }

    // Client.
    let mut client_key = vec![0; key_len];
    let mut client_iv = vec![0; nonce_len];
    let mut client_hp_key = vec![0; key_len];

    derive_pkt_key(aead, &client_secret, &mut client_key)?;
    derive_pkt_iv(aead, &client_secret, &mut client_iv)?;
    derive_hdr_key(aead, &client_secret, &mut client_hp_key)?;

    // Server.
    let mut server_key = vec![0; key_len];
    let mut server_iv = vec![0; nonce_len];
    let mut server_hp_key = vec![0; key_len];

    derive_pkt_key(aead, &server_secret, &mut server_key)?;
    derive_pkt_iv(aead, &server_secret, &mut server_iv)?;
    derive_hdr_key(aead, &server_secret, &mut server_hp_key)?;

    let (open, seal) = if is_server {
        (
            Open::new(aead, client_key, client_iv, client_hp_key, client_secret)?,
            Seal::new(aead, server_key, server_iv, server_hp_key, server_secret)?,
        )
    } else {
        (
            Open::new(aead, server_key, server_iv, server_hp_key, server_secret)?,
            Seal::new(aead, client_key, client_iv, client_hp_key, client_secret)?,
        )
    };

    Ok((open, seal))
}

fn derive_initial_secret(
    secret: &[u8], version: u32, out_prk: &mut [u8],
) -> Result<()> {
    const INITIAL_SALT_V1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
        0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    let salt = match version {
        crate::PROTOCOL_VERSION_V1 => &INITIAL_SALT_V1,

        _ => &INITIAL_SALT_V1,
    };

    hkdf_extract(Algorithm::AES128_GCM, out_prk, secret, salt)
}

fn derive_client_initial_secret(
    aead: Algorithm, prk: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"client in";
    hkdf_expand_label(aead, prk, LABEL, out)
}

fn derive_server_initial_secret(
    aead: Algorithm, prk: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"server in";
    hkdf_expand_label(aead, prk, LABEL, out)
}

fn derive_next_secret(aead: Algorithm, secret: &[u8]) -> Result<Vec<u8>> {
    const LABEL: &[u8] = b"quic ku";

    let mut next_secret = vec![0u8; 32];

    hkdf_expand_label(aead, secret, LABEL, &mut next_secret)?;

    Ok(next_secret)
}

pub fn derive_hdr_key(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"quic hp";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    hkdf_expand_label(aead, secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_key(aead: Algorithm, prk: &[u8], out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"quic key";

    let key_len: usize = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    hkdf_expand_label(aead, prk, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_iv(aead: Algorithm, prk: &[u8], out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"quic iv";

    let nonce_len = aead.nonce_len();

    if nonce_len > out.len() {
        return Err(Error::CryptoFail);
    }

    hkdf_expand_label(aead, prk, LABEL, &mut out[..nonce_len])
}

fn hkdf_expand_label(
    alg: Algorithm, prk: &[u8], label: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let out_len = (out.len() as u16).to_be_bytes();
    let label_len = (LABEL_PREFIX.len() + label.len()) as u8;

    let info = [&out_len, &[label_len][..], LABEL_PREFIX, label, &[0][..]];
    let info = info.concat();

    hkdf_expand(alg, out, prk, &info)?;

    Ok(())
}

fn make_nonce(iv: &[u8], counter: u64) -> [u8; MAX_NONCE_LEN] {
    let mut nonce = [0; MAX_NONCE_LEN];
    nonce.copy_from_slice(iv);

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}

pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::CryptoFail);
    }

    let rc = unsafe { CRYPTO_memcmp(a.as_ptr(), b.as_ptr(), a.len()) };

    if rc == 0 {
        return Ok(());
    }

    Err(Error::CryptoFail)
}

extern "C" {
    fn EVP_sha256() -> *const EVP_MD;

    fn EVP_sha384() -> *const EVP_MD;

    // CRYPTO
    fn CRYPTO_memcmp(a: *const u8, b: *const u8, len: usize) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_initial_secrets_v1() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let mut initial_secret = [0; 32];

        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];

        let aead = Algorithm::AES128_GCM;

        assert!(derive_initial_secret(
            &dcid,
            crate::PROTOCOL_VERSION_V1,
            &mut initial_secret,
        )
        .is_ok());

        // Client.
        assert!(
            derive_client_initial_secret(aead, &initial_secret, &mut secret)
                .is_ok()
        );
        let expected_client_initial_secret = [
            0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf,
            0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81,
            0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef,
            0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25,
            0x5c,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e,
            0x99, 0x33, 0xad, 0xed, 0xd2,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Server.
        assert!(
            derive_server_initial_secret(aead, &initial_secret, &mut secret)
                .is_ok()
        );

        let expected_server_initial_secret = [
            0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15,
            0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46,
            0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3,
            0x79, 0xb6, 0x06, 0x7e, 0x37,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0,
            0x3e,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b,
            0x49, 0x0e, 0xea, 0xa3, 0x14,
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

#[cfg(not(feature = "openssl"))]
mod boringssl;
#[cfg(not(feature = "openssl"))]
pub(crate) use boringssl::*;

#[cfg(feature = "openssl")]
mod openssl_quictls;
#[cfg(feature = "openssl")]
pub(crate) use openssl_quictls::*;
