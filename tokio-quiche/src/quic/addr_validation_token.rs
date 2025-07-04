// Copyright (C) 2025, Cloudflare, Inc.
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

use quiche::ConnectionId;
use std::io::Write;
use std::io::{
    self,
};
use std::net::IpAddr;
use std::net::SocketAddr;

use crate::QuicResultExt;

const HMAC_KEY_LEN: usize = 32;
const HMAC_TAG_LEN: usize = 32;

pub(crate) struct AddrValidationTokenManager {
    sign_key: [u8; HMAC_KEY_LEN],
}

impl Default for AddrValidationTokenManager {
    fn default() -> Self {
        let mut key_bytes = [0; HMAC_KEY_LEN];
        boring::rand::rand_bytes(&mut key_bytes).unwrap();

        AddrValidationTokenManager {
            sign_key: key_bytes,
        }
    }
}

impl AddrValidationTokenManager {
    pub(super) fn gen(
        &self, original_dcid: &[u8], client_addr: SocketAddr,
    ) -> Vec<u8> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        let token_len = HMAC_TAG_LEN + ip_bytes.len() + original_dcid.len();
        let mut token = io::Cursor::new(vec![0u8; token_len]);

        token.set_position(HMAC_TAG_LEN as u64);
        token.write_all(&ip_bytes).unwrap();
        token.write_all(original_dcid).unwrap();

        let tag = boring::hash::hmac_sha256(
            &self.sign_key,
            &token.get_ref()[HMAC_TAG_LEN..],
        )
        .unwrap();

        token.set_position(0);
        token.write_all(tag.as_ref()).unwrap();

        token.into_inner()
    }

    pub(super) fn validate_and_extract_original_dcid<'t>(
        &self, token: &'t [u8], client_addr: SocketAddr,
    ) -> io::Result<ConnectionId<'t>> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        let hmac_and_ip_len = HMAC_TAG_LEN + ip_bytes.len();

        if token.len() < hmac_and_ip_len {
            return Err("token is too short").into_io();
        }

        let (tag, payload) = token.split_at(HMAC_TAG_LEN);

        let expected_tag =
            boring::hash::hmac_sha256(&self.sign_key, payload).unwrap();

        if !boring::memcmp::eq(&expected_tag, tag) {
            return Err("signature verification failed").into_io();
        }

        if payload[..ip_bytes.len()] != *ip_bytes {
            return Err("IPs don't match").into_io();
        }

        Ok(ConnectionId::from_ref(&token[hmac_and_ip_len..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate() {
        let manager = AddrValidationTokenManager::default();

        let assert_tag_generated = |token: &[u8]| {
            let tag = &token[..HMAC_TAG_LEN];
            let all_nulls = tag.iter().all(|b| *b == 0u8);

            assert!(!all_nulls);
        };

        let token = manager.gen(b"foo", "127.0.0.1:1337".parse().unwrap());

        assert_tag_generated(&token);
        assert_eq!(token[HMAC_TAG_LEN..HMAC_TAG_LEN + 4], [127, 0, 0, 1]);
        assert_eq!(&token[HMAC_TAG_LEN + 4..], b"foo");

        let token = manager.gen(b"bar", "[::1]:1338".parse().unwrap());

        assert_tag_generated(&token);

        assert_eq!(token[HMAC_TAG_LEN..HMAC_TAG_LEN + 16], [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]);

        assert_eq!(&token[HMAC_TAG_LEN + 16..], b"bar");
    }

    #[test]
    fn validate() {
        let manager = AddrValidationTokenManager::default();

        let addr = "127.0.0.1:1337".parse().unwrap();
        let token = manager.gen(b"foo", addr);

        assert_eq!(
            manager
                .validate_and_extract_original_dcid(&token, addr)
                .unwrap(),
            ConnectionId::from_ref(b"foo")
        );

        let addr = "[::1]:1338".parse().unwrap();
        let token = manager.gen(b"barbaz", addr);

        assert_eq!(
            manager
                .validate_and_extract_original_dcid(&token, addr)
                .unwrap(),
            ConnectionId::from_ref(b"barbaz")
        );
    }

    #[test]
    fn validate_err_short_token() {
        let manager = AddrValidationTokenManager::default();
        let v4_addr = "127.0.0.1:1337".parse().unwrap();
        let v6_addr = "[::1]:1338".parse().unwrap();

        for addr in &[v4_addr, v6_addr] {
            assert!(manager
                .validate_and_extract_original_dcid(b"", *addr)
                .is_err());

            assert!(manager
                .validate_and_extract_original_dcid(&[1u8; HMAC_TAG_LEN], *addr)
                .is_err());

            assert!(manager
                .validate_and_extract_original_dcid(
                    &[1u8; HMAC_TAG_LEN + 1],
                    *addr
                )
                .is_err());
        }
    }

    #[test]
    fn validate_err_ips_mismatch() {
        let manager = AddrValidationTokenManager::default();

        let token = manager.gen(b"foo", "127.0.0.1:1337".parse().unwrap());

        assert!(manager
            .validate_and_extract_original_dcid(
                &token,
                "127.0.0.2:1337".parse().unwrap()
            )
            .is_err());

        let token = manager.gen(b"barbaz", "[::1]:1338".parse().unwrap());

        assert!(manager
            .validate_and_extract_original_dcid(
                &token,
                "[::2]:1338".parse().unwrap()
            )
            .is_err());
    }

    #[test]
    fn validate_err_invalid_signature() {
        let manager = AddrValidationTokenManager::default();

        let addr = "127.0.0.1:1337".parse().unwrap();
        let mut token = manager.gen(b"foo", addr);

        token[..HMAC_TAG_LEN].copy_from_slice(&[1u8; HMAC_TAG_LEN]);

        assert!(manager
            .validate_and_extract_original_dcid(&token, addr)
            .is_err());
    }
}
