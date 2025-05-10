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

use crate::crypto::crypto_provider;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::server::danger::ClientCertVerified;
use rustls::server::danger::ClientCertVerifier;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::Error;
use rustls::InvalidMessage;
use rustls::SignatureScheme;
use std::fmt::Debug;

#[derive(Debug)]
pub(super) struct DisabledServerCertVerifier {
    supported_algorithms: WebPkiSupportedAlgorithms,
}

impl DisabledServerCertVerifier {
    pub(super) fn new() -> crate::Result<Self> {
        let provider = crypto_provider();
        Ok(Self {
            supported_algorithms: provider.signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for DisabledServerCertVerifier {
    fn verify_server_cert(
        &self, _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>], _server_name: &ServerName<'_>,
        _ocsp_response: &[u8], _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        warn!(
            "Server certificate validation is disabled! \
        Use quiche::Config.verify_peer(true) to enable certificate validation."
        );
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        error!("TLS 1.2 is not supported within the Quic protocol.");
        Err(Error::InvalidMessage(
            InvalidMessage::UnknownProtocolVersion,
        ))
    }

    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        warn!(
            "Server certificate validation is disabled! \
        Use quiche::Config.verify_peer(true) to enable certificate validation."
        );
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms
            .mapping
            .iter()
            .map(|item| item.0)
            .collect()
    }
}

#[derive(Debug)]
pub(super) struct RejectedClientCertAllowedAnonymousVerifier {
    supported_algorithms: WebPkiSupportedAlgorithms,
    client_auth_mandatory: bool,
}

impl RejectedClientCertAllowedAnonymousVerifier {
    pub(super) fn new() -> crate::Result<Self> {
        let provider = crypto_provider();
        Ok(Self {
            supported_algorithms: provider.signature_verification_algorithms,
            client_auth_mandatory: false,
        })
    }
}

impl ClientCertVerifier for RejectedClientCertAllowedAnonymousVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.client_auth_mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self, _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>], _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Err(Error::General("no CA certificates configured to verify presented client auth certificate".to_string()))
    }

    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        error!("TLS 1.2 is not supported within the Quic protocol.");
        Err(Error::InvalidMessage(
            InvalidMessage::UnknownProtocolVersion,
        ))
    }

    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("no CA certificates configured to verify presented client auth certificate".to_string()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms
            .mapping
            .iter()
            .map(|item| item.0)
            .collect()
    }
}
