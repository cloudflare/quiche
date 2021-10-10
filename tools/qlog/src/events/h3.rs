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

use super::RawInfo;
use crate::Bytes;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum H3Owner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum H3StreamType {
    Data,
    Control,
    Push,
    Reserved,
    QpackEncode,
    QpackDecode,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum H3PushDecision {
    Claimed,
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3EventType {
    ParametersSet,
    ParametersRestored,
    StreamTypeSet,
    FrameCreated,
    FrameParsed,
    PushResolved,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationError {
    HttpNoError,
    HttpGeneralProtocolError,
    HttpInternalError,
    HttpRequestCancelled,
    HttpIncompleteRequest,
    HttpConnectError,
    HttpFrameError,
    HttpExcessiveLoad,
    HttpVersionFallback,
    HttpIdError,
    HttpStreamCreationError,
    HttpClosedCriticalStream,
    HttpEarlyResponse,
    HttpMissingSettings,
    HttpUnexpectedFrame,
    HttpRequestRejection,
    HttpSettingsError,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Setting {
    pub name: String,
    pub value: String,
}

// ================================================================== //
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Http3Frame {
    Data {
        frame_type: Http3FrameTypeName,

        raw: Option<Bytes>,
    },

    Headers {
        frame_type: Http3FrameTypeName,
        headers: Vec<HttpHeader>,
    },

    CancelPush {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    Settings {
        frame_type: Http3FrameTypeName,
        settings: Vec<Setting>,
    },

    PushPromise {
        frame_type: Http3FrameTypeName,
        push_id: String,
        headers: Vec<HttpHeader>,
    },

    Goaway {
        frame_type: Http3FrameTypeName,
        stream_id: String,
    },

    MaxPushId {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    DuplicatePush {
        frame_type: Http3FrameTypeName,
        push_id: String,
    },

    Reserved {
        frame_type: Http3FrameTypeName,
    },

    Unknown {
        frame_type: Http3FrameTypeName,
    },
}

impl Http3Frame {
    pub fn data(raw: Option<Bytes>) -> Self {
        Http3Frame::Data {
            frame_type: Http3FrameTypeName::Data,
            raw,
        }
    }

    pub fn headers(headers: Vec<HttpHeader>) -> Self {
        Http3Frame::Headers {
            frame_type: Http3FrameTypeName::Headers,
            headers,
        }
    }

    pub fn cancel_push(push_id: String) -> Self {
        Http3Frame::CancelPush {
            frame_type: Http3FrameTypeName::CancelPush,
            push_id,
        }
    }

    pub fn settings(settings: Vec<Setting>) -> Self {
        Http3Frame::Settings {
            frame_type: Http3FrameTypeName::Settings,
            settings,
        }
    }

    pub fn push_promise(push_id: String, headers: Vec<HttpHeader>) -> Self {
        Http3Frame::PushPromise {
            frame_type: Http3FrameTypeName::PushPromise,
            push_id,
            headers,
        }
    }

    pub fn goaway(stream_id: String) -> Self {
        Http3Frame::Goaway {
            frame_type: Http3FrameTypeName::Goaway,
            stream_id,
        }
    }

    pub fn max_push_id(push_id: String) -> Self {
        Http3Frame::MaxPushId {
            frame_type: Http3FrameTypeName::MaxPushId,
            push_id,
        }
    }

    pub fn duplicate_push(push_id: String) -> Self {
        Http3Frame::DuplicatePush {
            frame_type: Http3FrameTypeName::DuplicatePush,
            push_id,
        }
    }

    pub fn reserved() -> Self {
        Http3Frame::Reserved {
            frame_type: Http3FrameTypeName::Reserved,
        }
    }

    pub fn unknown() -> Self {
        Http3Frame::Unknown {
            frame_type: Http3FrameTypeName::Unknown,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct H3ParametersSet {
    pub owner: Option<H3Owner>,

    pub max_header_list_size: Option<u64>,
    pub max_table_capacity: Option<u64>,
    pub blocked_streams_count: Option<u64>,

    // qlog-defined
    pub waits_for_settings: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct H3ParametersRestored {
    pub max_header_list_size: Option<u64>,
    pub max_table_capacity: Option<u64>,
    pub blocked_streams_count: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct H3StreamTypeSet {
    pub stream_id: u64,
    pub owner: Option<H3Owner>,

    pub old: Option<H3StreamType>,
    pub new: H3StreamType,

    pub associated_push_id: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct H3FrameCreated {
    pub stream_id: u64,
    pub length: Option<u64>,
    pub frame: Http3Frame,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct H3FrameParsed {
    pub stream_id: u64,
    pub length: Option<u64>,
    pub frame: Http3Frame,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct H3PushResolved {
    push_id: Option<u64>,
    stream_id: Option<u64>,

    decision: Option<H3PushDecision>,
}
