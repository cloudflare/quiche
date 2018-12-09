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

use ring::aead;
use ring::digest;
use ring::hkdf;
use ring::hmac;
use ring::unauthenticated_stream;

use crate::Result;
use crate::Error;

use crate::octets;

const INITIAL_SALT: [u8; 20] = [
    0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
    0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38,
];

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Initial = 0,
    ZeroRTT = 1,
    Handshake = 2,
    Application = 3,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    Null,

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
            Algorithm::Null => panic!("Not a valid AEAD"),
        }
    }

    fn get_ring_stream(self) -> &'static unauthenticated_stream::Algorithm {
        match self {
            Algorithm::AES128_GCM => &unauthenticated_stream::AES_128_CTR,
            Algorithm::AES256_GCM => &unauthenticated_stream::AES_256_CTR,
            Algorithm::ChaCha20_Poly1305 => &unauthenticated_stream::CHACHA20,
            Algorithm::Null => panic!("Not a valid AEAD"),
        }
    }

    fn get_ring_digest(self) -> &'static digest::Algorithm {
        match self {
            Algorithm::AES128_GCM => &digest::SHA256,
            Algorithm::AES256_GCM => &digest::SHA384,
            Algorithm::ChaCha20_Poly1305 => &digest::SHA256,
            Algorithm::Null => panic!("Not a valid AEAD"),
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

    pub fn pn_nonce_len(self) -> usize {
        // For pkt num decryption a 4 bytes explicit counter is used along
        // with the normal nonce for both ChaCha20 and AES-CTR.
        self.get_ring_aead().nonce_len() + 4
    }
}

pub struct Open {
    alg: Algorithm,
    pn_key: unauthenticated_stream::DecryptingKey,
    key: aead::OpeningKey,
    nonce: Vec<u8>,
}

impl Open {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(alg: Algorithm, key: &[u8], iv: &[u8], pn_key: &[u8])
                                                            -> Result<Open> {
        Ok(Open {
            pn_key: unauthenticated_stream::DecryptingKey::new(
                            alg.get_ring_stream(), &pn_key).unwrap(),
            key: aead::OpeningKey::new(alg.get_ring_aead(), &key).unwrap(),
            nonce: Vec::from(iv),
            alg,
        })
    }

    pub fn open(&self, nonce: &[u8], ad: &[u8], buf: &mut [u8]) -> Result<usize> {
        let plain = aead::open_in_place(&self.key, nonce, ad, 0, buf)
                         .map_err(|_| Error::CryptoFail)?;

        Ok(plain.len())
    }

    pub fn open_with_u64_counter(&self, counter: u64, ad: &[u8], buf: &mut [u8])
                                                            -> Result<usize> {
        let mut counter_nonce: [u8; 12] = [0xba; 12];

        {
            let mut b = octets::Bytes::new(&mut counter_nonce);

            b.put_u32(0 as u32).unwrap();
            b.put_u64(counter).unwrap();
        }

        let mut nonce = self.nonce.clone();

        for i in 0 .. nonce.len() {
            nonce[i] ^= counter_nonce[i];
        }

        self.open(&nonce, ad, buf)
    }

    pub fn xor_keystream(&self, nonce: &[u8], buf: &mut [u8]) -> Result<usize> {
        let plain = unauthenticated_stream::decrypt_in_place(&self.pn_key,
                        nonce, buf).map_err(|_| Error::CryptoFail)?;

        Ok(plain.len())
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }
}

pub struct Seal {
    alg: Algorithm,
    pn_key: unauthenticated_stream::EncryptingKey,
    key: aead::SealingKey,
    nonce: Vec<u8>,
}

impl Seal {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(alg: Algorithm, key: &[u8], iv: &[u8], pn_key: &[u8])
                                                            -> Result<Seal> {
        Ok(Seal {
            pn_key: unauthenticated_stream::EncryptingKey::new(
                            alg.get_ring_stream(), &pn_key).unwrap(),
            key: aead::SealingKey::new(alg.get_ring_aead(), &key).unwrap(),
            nonce: Vec::from(iv),
            alg,
        })
    }

    pub fn seal(&self, nonce: &[u8], ad: &[u8], buf: &mut [u8]) -> Result<usize> {
        let cipher = aead::seal_in_place(&self.key, nonce, ad, buf, self.alg().tag_len())
                          .map_err(|_| Error::CryptoFail)?;

        Ok(cipher)
    }

    pub fn seal_with_u64_counter(&self, counter: u64, ad: &[u8], buf: &mut [u8])
                                                            -> Result<usize> {
        let mut counter_nonce: [u8; 12] = [0xba; 12];

        {
            let mut b = octets::Bytes::new(&mut counter_nonce);

            b.put_u32(0 as u32).unwrap();
            b.put_u64(counter).unwrap();
        }

        let mut nonce = self.nonce.clone();

        for i in 0 .. nonce.len() {
            nonce[i] ^= counter_nonce[i];
        }

        self.seal(&nonce, ad, buf)
    }

    pub fn xor_keystream(&self, nonce: &[u8], buf: &mut [u8]) -> Result<usize> {
        let plain = unauthenticated_stream::encrypt_in_place(&self.pn_key,
                        nonce, buf).map_err(|_| Error::CryptoFail)?;

        Ok(plain)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }
}

pub fn derive_initial_key_material(cid: &[u8], is_server: bool)
                                                    -> Result<(Open, Seal)> {
    let mut secret: [u8; 32] =  unsafe { std::mem::uninitialized() };

    let aead = Algorithm::AES128_GCM;

    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();

    let initial_secret = derive_initial_secret(&cid)?;

    // Client.
    let mut client_key = vec![0; key_len];
    let mut client_iv = vec![0; nonce_len];
    let mut client_pn_key = vec![0; key_len];

    derive_client_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut client_key)?;
    derive_pkt_iv(aead, &secret, &mut client_iv)?;
    derive_pkt_num_key(aead, &secret, &mut client_pn_key)?;

    // Server.
    let mut server_key = vec![0; key_len];
    let mut server_iv = vec![0; nonce_len];
    let mut server_pn_key = vec![0; key_len];

    derive_server_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut server_key)?;
    derive_pkt_iv(aead, &secret, &mut server_iv)?;
    derive_pkt_num_key(aead, &secret, &mut server_pn_key)?;

    let (open, seal) = if is_server {
        (Open::new(aead, &client_key, &client_iv, &client_pn_key)?,
         Seal::new(aead, &server_key, &server_iv, &server_pn_key)?)
    } else {
        (Open::new(aead, &server_key, &server_iv, &server_pn_key)?,
         Seal::new(aead, &client_key, &client_iv, &client_pn_key)?)
    };

    Ok((open, seal))
}

fn derive_initial_secret(secret: &[u8]) -> Result<hmac::SigningKey> {
    let salt = hmac::SigningKey::new(&digest::SHA256, &INITIAL_SALT);
    Ok(hkdf::extract(&salt, secret))
}

fn derive_client_initial_secret(prk: &hmac::SigningKey, out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"client in";
    hkdf_expand_label(prk, LABEL, out)
}

fn derive_server_initial_secret(prk: &hmac::SigningKey, out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"server in";
    hkdf_expand_label(prk, LABEL, out)
}

pub fn derive_pkt_num_key(aead: Algorithm, secret: &[u8], out: &mut [u8])
                                                                -> Result<()> {
    const LABEL: &[u8] = b"pn";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    let secret = hmac::SigningKey::new(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_key(aead: Algorithm, secret: &[u8], out: &mut [u8])
                                                                -> Result<()> {
    const LABEL: &[u8] = b"key";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    let secret = hmac::SigningKey::new(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_iv(aead: Algorithm, secret: &[u8], out: &mut [u8])
                                                                -> Result<()> {
    const LABEL: &[u8] = b"iv";

    let nonce_len = aead.nonce_len();

    if nonce_len > out.len() {
        return Err(Error::CryptoFail);
    }

    let secret = hmac::SigningKey::new(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..nonce_len])
}

fn hkdf_expand_label(prk: &hmac::SigningKey, label: &[u8],  out: &mut [u8])
                                                            -> Result<()> {
    const LABEL_PREFIX: &[u8] = b"quic ";

    let mut info: [u8; 256] = unsafe { std::mem::uninitialized() };

    let info_len = {
        let mut b = octets::Bytes::new(&mut info);

        if b.put_u16(out.len() as u16).is_err() ||
           b.put_u8((LABEL_PREFIX.len() + label.len()) as u8).is_err() ||
           b.put_bytes(LABEL_PREFIX).is_err() ||
           b.put_bytes(label).is_err() ||
           b.put_u8(0).is_err() {
            return Err(Error::CryptoFail);
        }

        b.off()
    };

    hkdf::expand(prk, &info[..info_len], out);

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_initial_secrets() {
        let dcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let mut secret: [u8; 32] = [0; 32];
        let mut key: [u8; 16] = [0; 16];
        let mut iv: [u8; 12] = [0; 12];
        let mut pn_key: [u8; 16] = [0; 16];

        let aead = Algorithm::AES128_GCM;

        let initial_secret = derive_initial_secret(&dcid).unwrap();

        // Client.
        assert!(derive_client_initial_secret(&initial_secret, &mut secret).is_ok());
        let expected_client_initial_secret: [u8; 32] = [
            0x9f, 0x53, 0x64, 0x57, 0xf3, 0x2a, 0x1e, 0x0a,
            0xe8, 0x64, 0xbc, 0xb3, 0xca, 0xf1, 0x23, 0x51,
            0x10, 0x63, 0x0e, 0x1d, 0x1f, 0xb3, 0x38, 0x35,
            0xbd, 0x05, 0x41, 0x70, 0xf9, 0x9b, 0xf7, 0xdc,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut key).is_ok());
        let expected_client_key: [u8; 16] = [
            0xf2, 0x92, 0x8f, 0x26, 0x14, 0xad, 0x6c, 0x20,
            0xb9, 0xbd, 0x00, 0x8e, 0x9c, 0x89, 0x63, 0x1c,
        ];
        assert_eq!(&key, &expected_client_key);

        assert!(derive_pkt_iv(aead, &secret, &mut iv).is_ok());
        let expected_client_iv: [u8; 12] = [
            0xab, 0x95, 0x0b, 0x01, 0x98, 0x63, 0x79, 0x78,
            0xcf, 0x44, 0xaa, 0xb9,
        ];
        assert_eq!(&iv, &expected_client_iv);

        assert!(derive_pkt_num_key(aead, &secret, &mut pn_key).is_ok());
        let expected_cliet_pn_key: [u8; 16] = [
            0x68, 0xc3, 0xf6, 0x4e, 0x2d, 0x66, 0x34, 0x41,
            0x2b, 0x8e, 0x32, 0x94, 0x62, 0x8d, 0x76, 0xf1,
        ];
        assert_eq!(&pn_key, &expected_cliet_pn_key);

        // Server.
        assert!(derive_server_initial_secret(&initial_secret, &mut secret).is_ok());
        let expected_server_initial_secret: [u8; 32] = [
            0xb0, 0x87, 0xdc, 0xd7, 0x47, 0x8d, 0xda, 0x8a,
            0x85, 0x8f, 0xbf, 0x3d, 0x60, 0x5c, 0x88, 0x85,
            0x86, 0xc0, 0xa3, 0xa9, 0x87, 0x54, 0x23, 0xad,
            0x4f, 0x11, 0x4f, 0x0b, 0xa3, 0x8e, 0x5a, 0x2e,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut key).is_ok());
        let expected_server_key: [u8; 16] = [
            0xf5, 0x68, 0x17, 0xd0, 0xfc, 0x59, 0x5c, 0xfc,
            0x0a, 0x2b, 0x0b, 0xcf, 0xb1, 0x87, 0x35, 0xec,
        ];
        assert_eq!(&key, &expected_server_key);

        assert!(derive_pkt_iv(aead, &secret, &mut iv).is_ok());
        let expected_server_iv: [u8; 12] = [
            0x32, 0x05, 0x03, 0x5a, 0x3c, 0x93, 0x7c, 0x90,
            0x2e, 0xe4, 0xf4, 0xd6,
        ];
        assert_eq!(&iv, &expected_server_iv);

        assert!(derive_pkt_num_key(aead, &secret, &mut pn_key).is_ok());
        let expected_server_pn_key: [u8; 16] = [
            0xa3, 0x13, 0xc8, 0x6d, 0x13, 0x73, 0xec, 0xbc,
            0xcb, 0x32, 0x94, 0xb1, 0x49, 0x74, 0x22, 0x6c,
        ];
        assert_eq!(&pn_key, &expected_server_pn_key);
    }
}
