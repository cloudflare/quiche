// Copyright (C) 2021, Cloudflare, Inc.
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

use serde::Deserialize;
use serde::Serialize;

use super::ApplicationErrorCode;
use super::Bytes;
use super::ConnectionErrorCode;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Attempted,
    Reset,
    Handshake,
    Active,
    Keepalive,
    Draining,
    Closed,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityEventType {
    ServerListening,
    ConnectionStarted,
    ConnectionClosed,
    ConnectionIdUpdated,
    SpinBitUpdated,
    ConnectionStateUpdated,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ServerListening {
    ip_v4: Option<String>, // human-readable or bytes
    ip_v6: Option<String>, // human-readable or bytes
    port_v4: u32,
    port_v6: u32,

    retry_required: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConnectionStarted {
    ip_version: String, // "v4" or "v6"
    src_ip: String,     // human-readable or bytes
    dst_ip: String,     // human-readable or bytes

    protocol: Option<String>,
    src_port: u32,
    dst_port: u32,

    src_cid: Option<Bytes>,
    dst_cid: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConnectionClosed {
    owner: Option<TransportOwner>,

    connection_code: Option<ConnectionErrorCode>,
    application_code: Option<ApplicationErrorCode>,
    internal_code: Option<u32>,

    reason: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConnectionIdUpdated {
    owner: Option<TransportOwner>,

    old: Option<Bytes>,
    new: Option<Bytes>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SpinBitUpdated {
    state: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConnectionStateUpdated {
    old: Option<ConnectionState>,
    new: ConnectionState,
}
