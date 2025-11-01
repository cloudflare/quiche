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

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize, Debug, Default)]
pub struct ClientInfo {
    pub cl: Option<String>,
    pub command_line: Option<String>,
    pub name: Option<String>,
    pub official: Option<String>,
    pub os_type: Option<String>,
    pub version: Option<String>,
    pub version_mod: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Constants {
    #[serde(skip)]
    pub active_field_trial_groups_id_keyed: Vec<String>,
    #[serde(skip)]
    pub address_family_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub cert_path_builder_digest_policy_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub cert_status_flag_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub cert_verifier_flags_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub certificate_trust_type_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub dns_query_type_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub load_flag_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub load_state_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub log_event_phase_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub log_event_types_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub log_source_type_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub net_error_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub quic_error_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub quic_rst_stream_error_id_keyed: HashMap<i64, String>,
    #[serde(skip)]
    pub secure_dns_mode_id_keyed: HashMap<i64, String>,

    pub active_field_trial_groups: Vec<String>,
    pub address_family: HashMap<String, i64>,
    pub cert_path_builder_digest_policy: HashMap<String, i64>,
    pub cert_status_flag: HashMap<String, i64>,
    pub cert_verifier_flags: HashMap<String, i64>,
    pub certificate_trust_type: Option<HashMap<String, i64>>,
    pub client_info: ClientInfo,
    pub dns_query_type: HashMap<String, i64>,
    pub load_flag: HashMap<String, i64>,
    pub load_state: HashMap<String, i64>,
    pub log_event_phase: HashMap<String, i64>,
    pub log_event_types: HashMap<String, i64>,
    pub log_format_version: u64,
    pub log_source_type: HashMap<String, i64>,
    pub net_error: HashMap<String, i64>,
    pub quic_error: HashMap<String, i64>,
    pub quic_rst_stream_error: HashMap<String, i64>,
    pub secure_dns_mode: HashMap<String, i64>,

    pub time_tick_offset: u64,
}

#[derive(Deserialize, Debug)]
pub struct ConstantsLine {
    pub constants: Constants,
}

impl Constants {
    pub fn populate_id_keyed(&mut self) {
        self.address_family_id_keyed = self
            .address_family
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.cert_path_builder_digest_policy_id_keyed = self
            .cert_path_builder_digest_policy
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.cert_status_flag_id_keyed = self
            .cert_status_flag
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.cert_verifier_flags_id_keyed = self
            .cert_verifier_flags
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        if let Some(trust_map) = &self.certificate_trust_type {
            self.certificate_trust_type_id_keyed = trust_map
                .iter()
                .map(|(k, v)| (*v, k.clone()))
                .collect::<HashMap<_, _>>();
        }

        self.dns_query_type_id_keyed = self
            .dns_query_type
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.load_flag_id_keyed = self
            .load_flag
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.load_state_id_keyed = self
            .load_state
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.log_event_phase_id_keyed = self
            .log_event_phase
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.log_event_types_id_keyed = self
            .log_event_types
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.log_source_type_id_keyed = self
            .log_source_type
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.net_error_id_keyed = self
            .net_error
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.quic_error_id_keyed = self
            .quic_error
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.quic_rst_stream_error_id_keyed = self
            .quic_rst_stream_error
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();

        self.secure_dns_mode_id_keyed = self
            .secure_dns_mode
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect::<HashMap<_, _>>();
    }
}
