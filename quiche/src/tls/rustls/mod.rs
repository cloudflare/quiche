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

mod verifiers;

use crate::crypto::crypto_provider;
use crate::crypto::key_material_from_keys;
use crate::crypto::Algorithm;
use crate::crypto::Level;
use crate::crypto::Open;
use crate::crypto::Seal;
use crate::packet;
use crate::tls::rustls::verifiers::DisabledServerCertVerifier;
use crate::tls::rustls::verifiers::RejectedClientCertAllowedAnonymousVerifier;
use crate::tls::ExData;
use crate::ConnectionError;
use crate::Error;
use crate::Result;
use rustls::client::ClientSessionMemoryCache;
use rustls::client::Resumption;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::quic::ClientConnection;
use rustls::quic::Connection;
use rustls::quic::KeyChange;
use rustls::quic::Keys;
use rustls::quic::Secrets;
use rustls::quic::ServerConnection;
use rustls::quic::Version;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::CipherSuite;
use rustls::ClientConfig;
use rustls::HandshakeKind;
use rustls::KeyLogFile;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::Side;
use std::fs::DirEntry;
use std::sync::Arc;

const INTERNAL_ERROR: u64 = 0x01;

pub struct Context {
    client_config: Option<Arc<ClientConfig>>,
    server_config: Option<Arc<ServerConfig>>,
    // required to build the above configs
    // are consumed during configs building
    private_key_client: Option<PrivateKeyDer<'static>>,
    private_key_server: Option<PrivateKeyDer<'static>>,
    ca_certificates: Option<Vec<CertificateDer<'static>>>,
    verify_ca_certificates_store: Option<RootCertStore>,
    system_default_cert_store: Option<RootCertStore>,
    alpns: Vec<Vec<u8>>,
    enable_verify_ca_certificates: bool,
    enable_keylog: bool,
    enable_early_data: bool,
    quic_version: Version,
    client_resumption_store: Arc<ClientSessionMemoryCache>,
}

impl Context {
    pub fn new() -> Result<Self> {
        let _ = crypto_provider();

        Ok(Self {
            client_config: None,
            server_config: None,
            private_key_client: None,
            private_key_server: None,
            ca_certificates: None,
            enable_verify_ca_certificates: false,
            verify_ca_certificates_store: None,
            system_default_cert_store: None,
            enable_keylog: false,
            enable_early_data: false,
            quic_version: Default::default(),
            alpns: vec![],
            client_resumption_store: Arc::new(ClientSessionMemoryCache::new(256)),
        })
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        // user supplied verification store when enabled and available
        // used for server mTLS validation on server or
        // used for server certificate validation on client
        let verify_store = if self.enable_verify_ca_certificates {
            self.verify_ca_certificates_store.clone().take()
        } else {
            None
        };

        if self.server_config.is_none() &&
            self.private_key_server.is_some() &&
            self.ca_certificates.is_some()
        {
            let builder =
                ServerConfig::builder_with_provider(crypto_provider().clone())
                    .with_protocol_versions(&[&TLS13])
                    .map_err(|e| {
                        error!("failed to set protocol version for server config builder: {}", e);
                        Error::TlsFail
                    })?;
            // setup user supplied and enabled CA certificates for mTLS auth
            let builder = if let Some(verify_store) = verify_store.clone() {
                let client_verifier =
                    WebPkiClientVerifier::builder(verify_store.into())
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| {
                            error!("client_verifier: failed to build {}", e);
                            Error::TlsFail
                        })?;

                builder.with_client_cert_verifier(client_verifier)
            } else {
                if self.enable_verify_ca_certificates {
                    // in case no store is present fail on mTLS authentication
                    // user warning is issued during Handshake.do_handshake()
                    builder.with_client_cert_verifier(Arc::new(
                        RejectedClientCertAllowedAnonymousVerifier::new()?,
                    ))
                } else {
                    builder.with_no_client_auth()
                }
            };

            let (Some(certs), Some(key)) =
                (self.ca_certificates.clone(), self.private_key_server.take())
            else {
                error!(
                    "server without certificate and key config is not supported"
                );
                return Err(Error::TlsFail);
            };

            let mut config =
                builder.with_single_cert(certs, key).map_err(|e| {
                    error!("loading certificate or key failed: {}", e);
                    Error::TlsFail
                })?;

            if self.enable_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }

            if self.enable_early_data {
                // rustls currently only allows 0 or 2^32-1 for max early data
                // size
                config.max_early_data_size = u32::MAX;
            }

            if self.alpns.len() > 0 {
                config.alpn_protocols = self.alpns.clone();
            }

            self.server_config = Some(Arc::new(config));
        };

        if self.client_config.is_none() {
            let builder =
                ClientConfig::builder_with_provider(crypto_provider().clone())
                    .with_protocol_versions(&[&TLS13])
                    .map_err(|e| {
                        error!("failed to set protocol version for client config builder: {}", e);
                        Error::TlsFail
                    })?;

            // setup user supplied and enabled CA certificates for server
            // certificate validation
            let builder = if let Some(verify_store) = verify_store.clone() {
                let server_verifier =
                    WebPkiServerVerifier::builder(verify_store.into())
                        .build()
                        .map_err(|e| {
                            error!("failed to build server verifier: {}", e);
                            Error::TlsFail
                        })?;

                builder.with_webpki_verifier(server_verifier)
            } else {
                // in case enabled but no CA certificates provided use system
                // default CAs
                if self.enable_verify_ca_certificates {
                    // default to env variables or system store
                    let store = self.load_system_default_certificate_store();
                    builder.with_root_certificates(store)
                } else {
                    // completely deactivate validation
                    let builder = builder.dangerous();
                    let disabled_server_verification =
                        Arc::new(DisabledServerCertVerifier::new()?);
                    builder.with_custom_certificate_verifier(
                        disabled_server_verification,
                    )
                }
            };

            let mut config = if let (Some(certs), Some(key)) =
                (self.ca_certificates.take(), self.private_key_client.take())
            {
                builder.with_client_auth_cert(certs, key).map_err(|e| {
                    error!("failed to set client auth: {}", e);
                    Error::TlsFail
                })?
            } else {
                builder.with_no_client_auth()
            };

            if self.enable_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }

            if self.enable_early_data {
                config.enable_early_data = true;
            }

            if self.alpns.len() > 0 {
                config.alpn_protocols = self.alpns.clone();
            }

            // required for 0-rtt, the resumption store is persisted within the
            // Context and propagated to all connections on the
            // ClientConfig
            config.resumption =
                Resumption::store(self.client_resumption_store.clone());

            self.client_config = Some(Arc::new(config))
        }

        Ok(Handshake {
            client_config: self.client_config.clone().ok_or_else(|| {
                error!("no client config available");
                Error::TlsFail
            })?,
            server_config: self.server_config.clone(),
            quic_version: self.quic_version.clone(),
            connection: None,
            side: Side::Client, // dummy value, correctly set during init()
            enable_verify_ca_certificates: self.enable_verify_ca_certificates,
            quic_transport_params: None,
            provided_data: None,
            highest_level: Level::Initial,
            hostname: None,
            one_rtt_keys_secrets: None,
        })
    }

    fn load_system_default_certificate_store(&mut self) -> RootCertStore {
        // loading the files is an expensive operation, ensure it's only done once
        // system default cert store is used in some areas
        if let Some(store) = &self.system_default_cert_store {
            return store.clone();
        };

        let mut system_default_certificate_store = RootCertStore::empty();
        let certificates_result = rustls_native_certs::load_native_certs();
        system_default_certificate_store
            .add_parsable_certificates(certificates_result.certs);

        self.system_default_cert_store = Some(system_default_certificate_store);
        self.system_default_cert_store.clone().unwrap()
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let verify_certificates = Self::load_ca_certificates_from_file(file)?;
        self.extend_verify_ca_certificates(verify_certificates);
        Ok(())
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        let files: Result<Vec<DirEntry>> = std::fs::read_dir(path)
            .map_err(|e| {
                error!("failed to load verify locations from directory: {:?}", e);
                Error::TlsFail
            })?
            .into_iter()
            .map(|rd| {
                rd.map_err(|e| {
                    error!(
                        "failed to load verify locations from directory: {:?}",
                        e
                    );
                    Error::TlsFail
                })
            })
            .collect();

        let verify_certificates: Vec<CertificateDer> = files?
            .into_iter()
            .flat_map(|f| Self::load_ca_certificates_from_file(f.path()))
            .flatten()
            .collect();

        self.extend_verify_ca_certificates(verify_certificates);
        Ok(())
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        self.ca_certificates = Some(Self::load_ca_certificates_from_file(file)?);
        Ok(())
    }

    fn load_ca_certificates_from_file(
        file: impl AsRef<std::path::Path>,
    ) -> Result<Vec<CertificateDer<'static>>> {
        let certificates: Result<Vec<CertificateDer>> =
            CertificateDer::pem_file_iter(file)
                .map_err(|e| {
                    error!("failed to load ca certificates from pem file: {}", e);
                    Error::TlsFail
                })?
                .map(|r| {
                    r.map_err(|e| {
                        error!("failed to load pem certificate: {}", e);
                        Error::TlsFail
                    })
                })
                .collect();
        Ok(certificates?)
    }

    fn extend_verify_ca_certificates(
        &mut self, verify_certificates: Vec<CertificateDer<'static>>,
    ) {
        if let Some(cert_store) = &mut self.verify_ca_certificates_store {
            cert_store.add_parsable_certificates(verify_certificates);
        } else {
            let mut store = RootCertStore::empty();
            store.add_parsable_certificates(verify_certificates);
            self.verify_ca_certificates_store = Some(store);
        }
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        let private_key_client =
            PrivateKeyDer::from_pem_file(file).map_err(|e| {
                error!("failed to load private key from pem: {}", e);
                Error::TlsFail
            })?;
        let private_key_server =
            PrivateKeyDer::from_pem_file(file).map_err(|e| {
                error!("failed to load private key from pem: {}", e);
                Error::TlsFail
            })?;

        // NOTE: storing it twice as PrivateKeyDer cannot be copied/cloned
        // ClientConfig & ServerConfig are built in new_handshake()
        self.private_key_client = Some(private_key_client);
        self.private_key_server = Some(private_key_server);
        Ok(())
    }

    pub fn set_verify(&mut self, verify: bool) {
        self.enable_verify_ca_certificates = verify;
    }

    /// uses env variable SSLKEYLOGFILE
    pub fn enable_keylog(&mut self) {
        self.enable_keylog = true;
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        let alpns: Vec<Vec<u8>> = v.iter().map(|a| a.to_vec()).collect();
        self.alpns = alpns;
        Ok(())
    }

    // not supported in rustls
    // pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<()> {}

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        self.enable_early_data = enabled;
    }
}

pub struct Handshake {
    client_config: Arc<ClientConfig>,
    server_config: Option<Arc<ServerConfig>>,
    quic_version: Version,

    side: Side,
    enable_verify_ca_certificates: bool,
    quic_transport_params: Option<Vec<u8>>,
    hostname: Option<ServerName<'static>>,
    connection: Option<Connection>,

    highest_level: Level,
    provided_data: Option<Vec<u8>>,
    one_rtt_keys_secrets: Option<(Keys, Secrets)>,
}

impl Handshake {
    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.side = match is_server {
            true => Side::Server,
            false => Side::Client,
        };

        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, _use_legacy: bool) {
        () // noop for rustls
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let hostname = ServerName::try_from(name)
            .map_err(|e| {
                error!("failed to convert hostname: {}", e);
                Error::TlsFail
            })?
            .to_owned();

        self.hostname = Some(hostname);
        Ok(())
    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        self.quic_transport_params = Some(buf.to_vec());
        Ok(())
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        // peer/remote transport parameters
        if let Some(conn) = &self.connection {
            // when resuming a tls session returning the transport parameters
            // leads to errors as during decoding they are checked
            // against the new connection ids which are not yet
            // fully established and the previous connection ids would be present
            if self.is_in_early_data() {
                return &[];
            };

            return if let Some(params) = conn.quic_transport_parameters() {
                params
            } else {
                &[]
            };
        }

        debug_assert!(false, "connection not available {:?}", self.side);
        &[]
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        if let Some(conn) = &self.connection {
            if let Some(alpns) = conn.alpn_protocol() {
                return alpns;
            }
        }

        &[]
    }

    pub fn server_name(&self) -> Option<&str> {
        self.connection.as_ref().and_then(|c| match c {
            Connection::Client(_) => None,
            Connection::Server(sc) => sc.server_name(),
        })
    }

    // peer/receive Crypto frame data
    pub fn provide_data(&mut self, _level: Level, buf: &[u8]) -> Result<()> {
        debug!(
            "provide_data side={:?} level={:?}",
            self.side, self.highest_level
        );

        let Some(conn) = &mut self.connection else {
            trace!("storing data as no connection present side={:?}", self.side);
            self.provided_data = Some(buf.to_vec());
            return Ok(());
        };

        conn.read_hs(&mut buf.to_vec()).map_err(|e| {
            if let Some(alert) = conn.alert() {
                error!("alert description: {:?}", alert)
            }
            error!("failed to read handshake data: {:?} {:?}", self.side, e);
            Error::TlsFail
        })?;

        Ok(())
    }

    // local/send Crypto frame data
    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        if self.connection.is_none() {
            debug!("no connection present side={:?}", self.side);

            let Some(params) = self.quic_transport_params.clone() else {
                error!("missing transport parameters {:?}", self.side);
                return Err(Error::TlsFail);
            };

            match self.side {
                Side::Client => {
                    let Some(hostname) = self.hostname.clone() else {
                        error!("hostname not present");
                        return Err(Error::TlsFail);
                    };

                    // NOTE: generates ClientHello
                    let client_conn = ClientConnection::new(
                        self.client_config.clone(),
                        self.quic_version.clone(),
                        hostname.to_owned(),
                        params,
                    )
                    .map_err(|e| {
                        error!("failed to create client config {}", e);
                        Error::TlsFail
                    })?;

                    self.connection = Some(client_conn.into())
                },
                Side::Server => {
                    let Some(server_config) = self.server_config.clone() else {
                        error!("server config not present for server side");
                        return Err(Error::TlsFail);
                    };

                    if self.enable_verify_ca_certificates {
                        warn!("verify_peer: enabled but no CA store for mTLS verification configured.");
                    }

                    let mut server_conn = ServerConnection::new(
                        server_config,
                        self.quic_version.clone(),
                        params.clone(),
                    )
                    .map_err(|e| {
                        error!("failed to create server connection {}", e);
                        Error::TlsFail
                    })?;

                    if let Some(crypto_data) = self.provided_data.take() {
                        match server_conn.read_hs(&crypto_data) {
                            Ok(()) => { /* continue */ },
                            Err(e) => {
                                if ex_data.local_error.is_none() {
                                    *ex_data.local_error = Some(ConnectionError {
                                        is_app: false,
                                        error_code: INTERNAL_ERROR,
                                        reason: e.to_string().as_bytes().to_vec(),
                                    })
                                };
                                error!("failed to read handshake data: {:?}", e);
                                return Err(Error::TlsFail);
                            },
                        }
                    }

                    self.connection = Some(server_conn.into());
                },
            }
        };

        loop {
            let current_level = self.highest_level.clone();

            let mut buf = Vec::new();
            let mut key_change =
                self.connection.as_mut().unwrap().write_hs(&mut buf);

            let mut level_upgraded = false;
            if let Some(key_change) = key_change.take() {
                level_upgraded = self.process_key_change(ex_data, key_change)?;
            }

            if !level_upgraded && self.one_rtt_keys_secrets.is_some() {
                let keys_secrets = self.one_rtt_keys_secrets.take().unwrap();
                self.handle_application_keys(ex_data, keys_secrets)?;
            }

            if buf.is_empty() {
                break;
            } else {
                self.write_crypto_stream(current_level, ex_data, buf.as_slice())?;
            }
        }

        let Some(conn) = self.connection.as_mut() else {
            return Err(Error::TlsFail);
        };

        if let Some(zero_rtt_keys) = conn.zero_rtt_keys() {
            let space = &mut ex_data.crypto_ctx[packet::Epoch::Application];
            match self.side {
                Side::Client => {
                    if space.crypto_seal.is_some() {
                        error!("client zero_rtt_keys are already present");
                    };

                    space.crypto_seal = Some(Seal::from(zero_rtt_keys));
                },
                Side::Server => {
                    if space.crypto_0rtt_open.is_some() {
                        error!("server zero_rtt_keys are already present");
                    };

                    space.crypto_0rtt_open = Some(Open::from(zero_rtt_keys));
                },
            }
            self.highest_level = Level::ZeroRTT;
        }

        trace!(
            "handshake status side={:?}, kind={:?}, ongoing={:?}, alpn={:?}",
            self.side,
            conn.handshake_kind(),
            conn.is_handshaking(),
            match conn.alpn_protocol() {
                None => "",
                Some(alpn) => {
                    str::from_utf8(alpn).unwrap()
                },
            }
        );

        // setting a session value to allow for tls resumption / zero-rtt
        if matches!(self.side, Side::Client) &&
            !conn.is_handshaking() &&
            ex_data.session.is_none()
        {
            let mut session = Vec::new();

            let local_params =
                self.quic_transport_params.as_ref().unwrap().as_slice();
            let local_params_len: [u8; 8] =
                (local_params.len() as u64).to_be_bytes();
            session.extend_from_slice(&local_params_len);
            session.extend_from_slice(local_params);

            let peer_params = self.quic_transport_params();
            let peer_params_len: [u8; 8] =
                (peer_params.len() as u64).to_be_bytes();
            session.extend_from_slice(&peer_params_len);
            session.extend_from_slice(peer_params);

            *ex_data.session = Some(session);
        }

        Ok(())
    }

    fn process_key_change(
        &mut self, ex_data: &mut ExData, key_change: KeyChange,
    ) -> Result<bool> {
        match key_change {
            KeyChange::Handshake { keys } => match self.highest_level {
                Level::Initial => {
                    let next_space =
                        &mut ex_data.crypto_ctx[packet::Epoch::Handshake];

                    if next_space.crypto_seal.is_some() ||
                        next_space.crypto_open.is_some()
                    {
                        debug_assert!(
                            false,
                            "keys are already present for Handshake"
                        );
                    };

                    self.highest_level = Level::Handshake;
                    let (open, seal) = key_material_from_keys(keys, None)?;
                    next_space.crypto_open = Some(open);
                    next_space.crypto_seal = Some(seal);

                    self.highest_level = Level::Handshake;
                    Ok(true)
                },
                Level::ZeroRTT | Level::Handshake | Level::OneRTT => {
                    debug_assert!(false, "required to handle handshake keys");
                    Ok(false)
                },
            },

            KeyChange::OneRtt { keys, next } =>
                self.handle_application_keys(ex_data, (keys, next)),
        }
    }

    fn handle_application_keys(
        &mut self, ex_data: &mut ExData, keys_secrets: (Keys, Secrets),
    ) -> Result<bool> {
        self.highest_level = Level::OneRTT;

        if !self.is_completed() {
            // avoid accepts of 1 RTT data before handshake is finished
            // temporarily storing keys/secrets in handshake
            // populate in space once handshake is compeleted
            self.one_rtt_keys_secrets = Some((keys_secrets.0, keys_secrets.1));

            Ok(false)
        } else {
            let next_space = &mut ex_data.crypto_ctx[packet::Epoch::Application];

            let (open, seal) =
                key_material_from_keys(keys_secrets.0, Some(keys_secrets.1))?;
            next_space.crypto_open = Some(open);
            next_space.crypto_seal = Some(seal);

            Ok(true)
        }
    }

    fn write_crypto_stream(
        &self, level: Level, ex_data: &mut ExData, data: &[u8],
    ) -> Result<()> {
        let pkt_num_space = match level {
            Level::Initial => &mut ex_data.crypto_ctx[packet::Epoch::Initial],
            Level::ZeroRTT => unreachable!(),
            Level::Handshake => &mut ex_data.crypto_ctx[packet::Epoch::Handshake],
            Level::OneRTT => &mut ex_data.crypto_ctx[packet::Epoch::Application],
        };

        pkt_num_space.crypto_stream.send.write(data, false)?;

        debug!(
            "handshake crypto data written side={:?}, level={:?}, sent={}",
            self.side,
            self.highest_level,
            data.len()
        );
        Ok(())
    }

    pub fn process_post_handshake(
        &mut self, _ex_data: &mut ExData,
    ) -> Result<()> {
        // no-op
        Ok(())
    }

    pub fn write_level(&self) -> Level {
        self.highest_level
    }

    pub fn cipher(&self) -> Option<Algorithm> {
        let suite = self
            .connection
            .as_ref()
            .and_then(|c| c.negotiated_cipher_suite());
        let Some(suite) = suite else { return None };

        match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(Algorithm::AES128_GCM),
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(Algorithm::AES256_GCM),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 =>
                Some(Algorithm::ChaCha20_Poly1305),
            _ => None,
        }
    }

    pub fn is_completed(&self) -> bool {
        if let Some(conn) = &self.connection {
            return !conn.is_handshaking();
        }

        false
    }

    pub fn is_resumed(&self) -> bool {
        if let Some(conn) = &self.connection {
            if let Some(kind) = conn.handshake_kind() {
                return matches!(kind, HandshakeKind::Resumed);
            }
        }

        false
    }

    pub fn clear(&mut self) -> Result<()> {
        self.connection = None;
        Ok(())
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        match self.side {
            // peer transport parameters are part of the resumption_store
            Side::Client => {
                self.set_quic_transport_params(session)?;
                Ok(())
            },
            Side::Server => {
                error!("set session is a client only operation");
                Err(Error::TlsFail)
            },
        }
    }

    pub fn curve(&self) -> Option<String> {
        let Some(conn) = &self.connection else {
            return None;
        };

        let Some(kx_group) = conn.negotiated_key_exchange_group() else {
            return None;
        };

        Some(format!("{:?}", kx_group.name()))
    }

    pub fn sigalg(&self) -> Option<String> {
        // this information is not available through the connection
        // only handled internally within rustls during handshake
        // loggable with level trace
        None
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let Some(conn) = &self.connection else {
            return None;
        };

        if let Some(certs) = conn.peer_certificates() {
            let out: Vec<&[u8]> = certs.iter().map(|c| c.as_ref()).collect();
            if out.len() > 0 {
                Some(out)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        let Some(conn) = &self.connection else {
            return None;
        };

        if let Some(certs) = conn.peer_certificates() {
            certs.first().map(|c| c.as_ref())
        } else {
            None
        }
    }

    pub fn is_in_early_data(&self) -> bool {
        let Some(conn) = &self.connection else {
            return false;
        };
        conn.zero_rtt_keys().is_some()
    }
}
