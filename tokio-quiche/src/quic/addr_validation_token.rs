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
use std::io;
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
        &self, original_dcid: &[u8], client_addr: SocketAddr, scid: &[u8],
    ) -> Vec<u8> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => &addr.octets()[..],
            IpAddr::V6(addr) => &addr.octets()[..],
        };

        // The token itself only consists of the client's original DCID and the
        // HMAC tag. However, we calculate the HMAC over the client's IP and our
        // SCID as well to bind the token to a specific connection.
        let hmac_len = std::cmp::max(
            original_dcid.len() + HMAC_TAG_LEN,
            original_dcid.len() + ip_bytes.len() + scid.len(),
        );

        let mut token_buf = Vec::with_capacity(hmac_len);
        token_buf.extend_from_slice(original_dcid);
        token_buf.extend_from_slice(ip_bytes);
        token_buf.extend_from_slice(scid);

        let tag = boring::hash::hmac_sha256(&self.sign_key, &token_buf).unwrap();
        debug_assert_eq!(tag.len(), HMAC_TAG_LEN);

        // Drop the non-payload parts of the HMAC and reuse the storage for the
        // tag.
        token_buf.truncate(original_dcid.len());
        token_buf.extend_from_slice(&tag[..]);
        token_buf
    }

    pub(super) fn validate_and_extract_original_dcid<'t>(
        &self, token: &'t [u8], client_addr: SocketAddr, scid: &[u8],
    ) -> io::Result<ConnectionId<'t>> {
        let Some((payload, _)) = split_last_n(token, HMAC_TAG_LEN) else {
            return Err("token is too short").into_io();
        };
        if payload.is_empty() {
            return Err("token is too short").into_io();
        }

        let original_dcid = payload;
        let expected_token = self.gen(original_dcid, client_addr, scid);

        if token.len() != expected_token.len() ||
            !boring::memcmp::eq(token, &expected_token)
        {
            return Err("signature verification failed").into_io();
        }

        Ok(ConnectionId::from_ref(original_dcid))
    }
}

fn split_last_n(v: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    let mid = v.len().checked_sub(n)?;
    v.split_at_checked(mid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate() {
        let manager = AddrValidationTokenManager::default();
        let v4_addr = "127.0.0.1:1337".parse().unwrap();
        let v6_addr = "[::1]:1338".parse().unwrap();

        let token = manager.gen(b"foo", v4_addr, b"bar");

        let (payload, tag) = split_last_n(&token, HMAC_TAG_LEN).unwrap();
        assert!(!tag.iter().all(|b| *b == 0));
        assert_eq!(payload, b"foo");

        let token = manager.gen(b"bar", v6_addr, b"foo");

        let (payload, tag) = split_last_n(&token, HMAC_TAG_LEN).unwrap();
        assert!(!tag.iter().all(|b| *b == 0));
        assert_eq!(payload, b"bar");
    }

    #[test]
    fn validate() {
        let manager = AddrValidationTokenManager::default();

        let addr = "127.0.0.1:1337".parse().unwrap();
        let token = manager.gen(b"foo", addr, b"bar");

        assert_eq!(
            manager
                .validate_and_extract_original_dcid(&token, addr, b"bar")
                .unwrap(),
            ConnectionId::from_ref(b"foo")
        );

        let addr = "[::1]:1338".parse().unwrap();
        let token = manager.gen(b"barbaz", addr, b"foofuz");

        assert_eq!(
            manager
                .validate_and_extract_original_dcid(&token, addr, b"foofuz")
                .unwrap(),
            ConnectionId::from_ref(b"barbaz")
        );
    }

    #[test]
    fn validate_err_token_wrong_size() {
        let manager = AddrValidationTokenManager::default();
        let v4_addr = "127.0.0.1:1337".parse().unwrap();
        let v6_addr = "[::1]:1338".parse().unwrap();

        for addr in &[v4_addr, v6_addr] {
            assert!(manager
                .validate_and_extract_original_dcid(b"", *addr, b"foo")
                .is_err());

            assert!(manager
                .validate_and_extract_original_dcid(
                    &[1u8; HMAC_TAG_LEN],
                    *addr,
                    b"foo"
                )
                .is_err());

            let mut token = manager.gen(b"foo", *addr, b"bar");
            token.extend_from_slice(&[1; 17]);
            assert!(manager
                .validate_and_extract_original_dcid(&token, *addr, b"bar")
                .is_err());
        }
    }

    #[test]
    fn validate_err_ips_mismatch() {
        let manager = AddrValidationTokenManager::default();

        let token =
            manager.gen(b"foo", "127.0.0.1:1337".parse().unwrap(), b"bar");

        assert!(manager
            .validate_and_extract_original_dcid(
                &token,
                "127.0.0.2:1337".parse().unwrap(),
                b"bar",
            )
            .is_err());

        let token = manager.gen(b"barbaz", "[::1]:1338".parse().unwrap(), b"foo");

        assert!(manager
            .validate_and_extract_original_dcid(
                &token,
                "[::2]:1338".parse().unwrap(),
                b"foo",
            )
            .is_err());
    }

    #[test]
    fn validate_err_scid_mismatch() {
        let manager = AddrValidationTokenManager::default();
        let addr = "127.0.0.1:1337".parse().unwrap();

        let token = manager.gen(b"foo", addr, b"bar");
        assert!(manager
            .validate_and_extract_original_dcid(&token, addr, b"xyzyx")
            .is_err());
    }

    #[test]
    fn validate_err_invalid_signature() {
        let manager = AddrValidationTokenManager::default();

        let addr = "127.0.0.1:1337".parse().unwrap();
        let mut token = manager.gen(b"foo", addr, b"bar");

        token[..HMAC_TAG_LEN].copy_from_slice(&[1u8; HMAC_TAG_LEN]);

        assert!(manager
            .validate_and_extract_original_dcid(&token, addr, b"bar")
            .is_err());
    }
}
