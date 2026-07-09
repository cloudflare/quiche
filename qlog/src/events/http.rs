// Copyright (C) 2026, Cloudflare, Inc.
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

use crate::events::RawInfo;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HttpEventType {
    CapsuleCreated,
    CapsuleParsed,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "capsule_type")]
#[serde(rename_all = "snake_case")]
pub enum HttpCapsule {
    Datagram {
        raw: Option<RawInfo>,
    },

    Unknown {
        capsule_type_value: Option<u64>,
        raw: Option<RawInfo>,
    },
}

impl Default for HttpCapsule {
    fn default() -> Self {
        Self::Unknown {
            capsule_type_value: None,
            raw: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct CapsuleCreated {
    pub stream_id: u64,
    pub capsule: HttpCapsule,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct CapsuleParsed {
    pub stream_id: u64,
    pub capsule: HttpCapsule,
}
