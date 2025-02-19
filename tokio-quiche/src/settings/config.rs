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

use foundations::telemetry::log;
use std::borrow::Cow;
use std::fs::File;
use std::time::Duration;

use crate::result::QuicResult;
use crate::settings::CertificateKind;
use crate::settings::ConnectionParams;
use crate::settings::TlsCertificatePaths;
use crate::socket::SocketCapabilities;

/// Internal representation of the combined configuration for a QUIC connection.
pub(crate) struct Config {
    pub quiche_config: quiche::Config,
    pub disable_client_ip_validation: bool,
    pub qlog_dir: Option<String>,
    pub has_gso: bool,
    pub pacing_offload: bool,
    pub enable_expensive_packet_count_metrics: bool,
    pub keylog_file: Option<File>,
    pub listen_backlog: usize,
    pub handshake_timeout: Option<Duration>,
    pub has_ippktinfo: bool,
    pub has_ipv6pktinfo: bool,
}

impl AsMut<quiche::Config> for Config {
    fn as_mut(&mut self) -> &mut quiche::Config {
        &mut self.quiche_config
    }
}

impl Config {
    pub(crate) fn new(
        params: &ConnectionParams, socket_capabilities: SocketCapabilities,
    ) -> QuicResult<Self> {
        let quic_settings = &params.settings;
        let keylog_path = match &quic_settings.keylog_file {
            Some(f) => Some(Cow::Borrowed(f.as_ref())),
            None => std::env::var_os("SSLKEYLOGFILE").map(Cow::from),
        };
        let keylog_file = keylog_path.and_then(|path| if cfg!(feature = "capture_keylogs") {
                File::options().create(true).append(true).open(path)
                    .inspect_err(|e| log::warn!("failed to open SSLKEYLOGFILE"; "error" => e))
                    .ok()
            } else {
                log::warn!("SSLKEYLOGFILE is set, but `capture_keylogs` feature is disabled. No keys will be logged.");
                None
            });

        let SocketCapabilities {
            has_gso,
            has_txtime: pacing_offload,
            has_ippktinfo,
            has_ipv6pktinfo,
            ..
        } = socket_capabilities;

        Ok(Config {
            quiche_config: make_quiche_config(params, keylog_file.is_some())?,
            disable_client_ip_validation: quic_settings
                .disable_client_ip_validation,
            qlog_dir: quic_settings.qlog_dir.clone(),
            has_gso,
            // Only enable pacing if it is explicitly enabled in the configuration
            // and offload is supported.
            pacing_offload: quic_settings.enable_pacing && pacing_offload,
            enable_expensive_packet_count_metrics: quic_settings
                .enable_expensive_packet_count_metrics,
            keylog_file,
            listen_backlog: quic_settings.listen_backlog,
            handshake_timeout: quic_settings.handshake_timeout,
            has_ippktinfo,
            has_ipv6pktinfo,
        })
    }
}

fn make_quiche_config(
    params: &ConnectionParams, should_log_keys: bool,
) -> QuicResult<quiche::Config> {
    let ssl_ctx_builder = params
        .hooks
        .connection_hook
        .as_ref()
        .zip(params.tls_cert)
        .and_then(|(hook, tls)| hook.create_custom_ssl_context_builder(tls));

    let mut config = if let Some(builder) = ssl_ctx_builder {
        quiche::Config::with_boring_ssl_ctx_builder(
            quiche::PROTOCOL_VERSION,
            builder,
        )?
    } else {
        quiche_config_with_tls(params.tls_cert)?
    };

    let quic_settings = &params.settings;
    let alpns: Vec<&[u8]> =
        quic_settings.alpn.iter().map(Vec::as_slice).collect();
    config.set_application_protos(&alpns).unwrap();

    if let Some(timeout) = quic_settings.max_idle_timeout {
        let ms = timeout
            .as_millis()
            .try_into()
            .map_err(|_| "QuicSettings::max_idle_timeout exceeds u64")?;
        config.set_max_idle_timeout(ms);
    }

    config.enable_dgram(
        quic_settings.enable_dgram,
        quic_settings.dgram_recv_max_queue_len,
        quic_settings.dgram_send_max_queue_len,
    );

    config.set_max_recv_udp_payload_size(quic_settings.max_recv_udp_payload_size);
    config.set_max_send_udp_payload_size(quic_settings.max_send_udp_payload_size);
    config.set_initial_max_data(quic_settings.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(
        quic_settings.initial_max_stream_data_bidi_local,
    );
    config.set_initial_max_stream_data_bidi_remote(
        quic_settings.initial_max_stream_data_bidi_remote,
    );
    config.set_initial_max_stream_data_uni(
        quic_settings.initial_max_stream_data_uni,
    );
    config.set_initial_max_streams_bidi(quic_settings.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(quic_settings.initial_max_streams_uni);
    config.set_disable_active_migration(quic_settings.disable_active_migration);
    config.set_cc_algorithm_name(quic_settings.cc_algorithm.as_str())?;
    config.enable_hystart(quic_settings.enable_hystart);
    config.enable_pacing(quic_settings.enable_pacing);

    if should_log_keys {
        config.log_keys();
    }

    Ok(config)
}

fn quiche_config_with_tls(
    tls_cert: Option<TlsCertificatePaths>,
) -> QuicResult<quiche::Config> {
    let Some(tls) = tls_cert else {
        return Ok(quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap());
    };

    match tls.kind {
        #[cfg(not(feature = "rpk"))]
        CertificateKind::RawPublicKey => {
            // TODO: don't compile this enum variant unless rpk feature is enabled
            panic!("Can't use RPK when compiled without rpk feature");
        },
        #[cfg(feature = "rpk")]
        CertificateKind::RawPublicKey => {
            let mut ssl_ctx_builder = boring::ssl::SslContextBuilder::new_rpk()?;
            let raw_public_key = std::fs::read(tls.cert)?;
            ssl_ctx_builder.set_rpk_certificate(&raw_public_key)?;

            let raw_private_key = std::fs::read(tls.private_key)?;
            let pkey =
                boring::pkey::PKey::private_key_from_pem(&raw_private_key)?;
            ssl_ctx_builder.set_null_chain_private_key(&pkey)?;

            Ok(quiche::Config::with_boring_ssl_ctx_builder(
                quiche::PROTOCOL_VERSION,
                ssl_ctx_builder,
            )?)
        },
        CertificateKind::X509 => {
            let mut config =
                quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            config.load_cert_chain_from_pem_file(tls.cert)?;
            config.load_priv_key_from_pem_file(tls.private_key)?;
            Ok(config)
        },
    }
}
