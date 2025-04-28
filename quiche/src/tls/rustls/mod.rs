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

use crate::crypto;
use crate::tls::ExData;
use crate::Result;

pub struct Context {}

impl Context {
    pub fn new() -> Result<Self> {
        todo!()
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        todo!()
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        todo!()
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        todo!()
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        todo!()
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        todo!()
    }

    pub fn set_verify(&mut self, verify: bool) {
        todo!()
    }

    pub fn enable_keylog(&mut self) {
        todo!()
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        todo!()
    }

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        todo!()
    }
}

pub struct Handshake {}

impl Handshake {
    pub fn init(&mut self, is_server: bool) -> Result<()> {
        todo!()
    }

    pub fn use_legacy_codepoint(&mut self, use_legacy: bool) {
        todo!()
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        todo!()
    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        todo!()
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        todo!()
    }

    pub fn server_name(&self) -> Option<&str> {
        todo!()
    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        todo!()
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        todo!()
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        todo!()
    }

    pub fn write_level(&self) -> crypto::Level {
        todo!()
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        todo!()
    }

    pub fn is_completed(&self) -> bool {
        todo!()
    }

    pub fn is_resumed(&self) -> bool {
        todo!()
    }

    pub fn clear(&mut self) -> Result<()> {
        todo!()
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn curve(&self) -> Option<String> {
        todo!()
    }

    pub fn sigalg(&self) -> Option<String> {
        todo!()
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        todo!()
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        todo!()
    }

    pub fn is_in_early_data(&self) -> bool {
        todo!()
    }
}
