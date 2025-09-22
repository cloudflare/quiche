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

use crate::events::RawInfo;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Initiator {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Request,
    Control,
    Push,
    Reserved,
    #[default]
    Unknown,
    QpackEncode,
    QpackDecode,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PushDecision {
    Claimed,
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PriorityTargetStreamType {
    Request,
    Push,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3EventType {
    ParametersSet,
    ParametersRestored,
    StreamTypeSet,
    PriorityUpdated,
    FrameCreated,
    FrameParsed,
    DatagramCreated,
    DatagramParsed,
    PushResolved,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Setting {
    pub name: String,
    pub value: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3FrameTypeName {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    DuplicatePush,
    Reserved,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these frame types have a frame_type
// field. But instead of making that a rust object property, just use serde to
// ensure it goes out on the wire. This means that deserialization of frames
// also works automatically.
pub enum Http3Frame {
    Data {
        raw: Option<RawInfo>,
    },

    Headers {
        headers: Vec<HttpHeader>,
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        settings: Vec<Setting>,
    },

    PushPromise {
        push_id: u64,
        headers: Vec<HttpHeader>,
    },

    Goaway {
        id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    PriorityUpdate {
        target_stream_type: PriorityTargetStreamType,
        prioritized_element_id: u64,
        priority_field_value: String,
    },

    Reserved {
        length: Option<u64>,
    },

    Unknown {
        frame_type_value: u64,
        raw: Option<RawInfo>,
    },
}

impl Default for Http3Frame {
    fn default() -> Self {
        Self::Unknown {
            frame_type_value: 0,
            raw: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ParametersSet {
    pub initiator: Option<Initiator>,

    #[serde(alias = "max_header_list_size")]
    pub max_field_section_size: Option<u64>,
    pub max_table_capacity: Option<u64>,
    pub blocked_streams_count: Option<u64>,
    pub extended_connect: Option<u16>,
    pub h3_datagram: Option<u16>,

    // qlog-defined
    pub waits_for_settings: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ParametersRestored {
    #[serde(alias = "max_header_list_size")]
    pub max_field_section_size: Option<u64>,
    pub max_table_capacity: Option<u64>,
    pub blocked_streams_count: Option<u64>,
    pub extended_connect: Option<u16>,
    pub h3_datagram: Option<u16>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct StreamTypeSet {
    pub owner: Option<Initiator>,
    pub stream_id: u64,
    pub stream_type: StreamType,
    pub stream_type_bytes: Option<u64>,
    pub associated_push_id: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PriorityUpdatedTrigger {
    ClientSignalReceived,
    Local,
    Other,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PriorityUpdatedReason {
    ClientSignalOnly,
    ClientServerMerged,
    LocalPolicy,
    Other,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct PriorityUpdated {
    pub stream_id: Option<u64>,
    pub push_id: Option<u64>,
    pub old: Option<String>,
    pub new: String,
    pub trigger: Option<PriorityUpdatedTrigger>,
    pub reason: Option<PriorityUpdatedReason>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct FrameCreated {
    pub stream_id: u64,
    pub length: Option<u64>,
    pub frame: Http3Frame,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct FrameParsed {
    pub stream_id: u64,
    pub length: Option<u64>,
    pub frame: Http3Frame,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct DatagramCreated {
    pub quarter_stream_id: u64,
    pub datagram: Option<Vec<String>>,
    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct DatagramParsed {
    pub quarter_stream_id: u64,
    pub datagram: Option<Vec<String>>,
    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PushResolved {
    push_id: Option<u64>,
    stream_id: Option<u64>,

    decision: Option<PushDecision>,
}
