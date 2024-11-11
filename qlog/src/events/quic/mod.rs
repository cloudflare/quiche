// Copyright (C) 2024, Cloudflare, Inc.
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

use crate::events::Bytes;
use crate::events::Token;
use crate::HexSlice;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,

    #[serde(rename = "0RTT")]
    ZeroRtt,

    #[serde(rename = "1RTT")]
    OneRtt,

    Retry,
    VersionNegotiation,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub packet_number: Option<u64>,

    pub flags: Option<u8>,
    pub token: Option<Token>,

    pub length: Option<u16>,

    pub version: Option<Bytes>,

    pub scil: Option<u8>,
    pub dcil: Option<u8>,
    pub scid: Option<Bytes>,
    pub dcid: Option<Bytes>,
}

impl PacketHeader {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new PacketHeader.
    pub fn new(
        packet_type: PacketType, packet_number: Option<u64>, flags: Option<u8>,
        token: Option<Token>, length: Option<u16>, version: Option<u32>,
        scid: Option<&[u8]>, dcid: Option<&[u8]>,
    ) -> Self {
        let (scil, scid) = match scid {
            Some(cid) => (
                Some(cid.len() as u8),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let (dcil, dcid) = match dcid {
            Some(cid) => (
                Some(cid.len() as u8),
                Some(format!("{}", HexSlice::new(&cid))),
            ),

            None => (None, None),
        };

        let version = version.map(|v| format!("{v:x?}"));

        PacketHeader {
            packet_type,
            packet_number,
            flags,
            token,
            length,
            version,
            scil,
            dcil,
            scid,
            dcid,
        }
    }

    /// Creates a new PacketHeader.
    ///
    /// Once a QUIC connection has formed, version, dcid and scid are stable, so
    /// there are space benefits to not logging them in every packet, especially
    /// PacketType::OneRtt.
    pub fn with_type(
        ty: PacketType, packet_number: Option<u64>, version: Option<u32>,
        scid: Option<&[u8]>, dcid: Option<&[u8]>,
    ) -> Self {
        match ty {
            PacketType::OneRtt => PacketHeader::new(
                ty,
                packet_number,
                None,
                None,
                None,
                None,
                None,
                None,
            ),

            _ => PacketHeader::new(
                ty,
                packet_number,
                None,
                None,
                None,
                version,
                scid,
                dcid,
            ),
        }
    }
}

pub mod connectivity;
// qlog has the category quic#quic so the inception lies there
#[allow(clippy::module_inception)]
pub mod quic;
pub mod recovery;
pub mod security;
