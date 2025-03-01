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

use serde::Deserialize;
use serde::Serialize;

use super::RawInfo;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MOQTOwner {
    Local,
    Remote,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MOQTStreamType {
    SubgroupHeader,
    FetchHeader,
    Control,
    SubscribeNamespace,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MOQTEventType {
    StreamTypeSet,
    ControlMessageCreated,
    ControlMessageParsed,
    ObjectDatagramCreated,
    ObjectDatagramParsed,
    SubgroupHeaderCreated,
    SubgroupHeaderParsed,
    SubgroupObjectCreated,
    SubgroupObjectParsed,
    FetchHeaderCreated,
    FetchHeaderParsed,
    FetchObjectCreated,
    FetchObjectParsed,
    #[default]
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "name")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these parameters have a name field. But
// instead of making that a rust object property, just use serde to ensure it
// goes out on the wire. This means that deserialization of frames also works
// automatically.
pub enum MOQTSetupParameter {
    Path {
        value: String,
    },

    MaxRequestId {
        value: u64,
    },

    Authority {
        value: String,
    },

    MaxAuthTokenCacheSize {
        value: u64,
    },

    AuthorizationToken {
        alias_type: MOQTAliasType,
        token_alias: Option<u64>,
        token_type: Option<u64>,
        token_value: Option<RawInfo>,
    },

    Implementation {
        value: String,
    },

    Unknown {
        name_bytes: u64,
        length: Option<u64>,
        value: Option<u64>,
        value_bytes: Option<RawInfo>,
    },
}

impl Default for MOQTSetupParameter {
    fn default() -> Self {
        Self::Unknown {
            name_bytes: 0,
            length: None,
            value: None,
            value_bytes: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "name")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these parameters have a name field. But
// instead of making that a rust object property, just use serde to ensure it
// goes out on the wire. This means that deserialization of frames also works
// automatically.
pub enum MOQTParameter {
    AuthorizationToken {
        alias_type: u64,
        token_alias: Option<u64>,
        token_type: Option<u64>,
        token_value: Option<RawInfo>,
    },

    DeliveryTimeout {
        value: u64,
    },

    MaxCacheDuration {
        value: u64,
    },

    PublisherPriority {
        value: u64,
    },

    SubscriberPriority {
        value: u64,
    },

    GroupOrder {
        value: u64,
    },

    SubscriptionFilter {
        value: MOQTSubscriptionFilter,
    },

    Expires {
        value: u64,
    },

    LargestObject {
        value: MOQTLocation,
    },

    Forward {
        value: u64,
    },

    DynamicGroups {
        value: u64,
    },

    NewGroupRequest {
        value: u64,
    },

    Unknown {
        name_bytes: u64,
        length: Option<u64>,
        value: Option<u64>,
        value_bytes: Option<RawInfo>,
    },
}

impl Default for MOQTParameter {
    fn default() -> Self {
        Self::Unknown {
            name_bytes: 0,
            length: None,
            value: None,
            value_bytes: None,
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTByteString {
    pub value: Option<String>,
    pub value_bytes: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTLocation {
    pub group: u64,
    pub object: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubscriptionFilter {
    pub filter_type: u64,
    pub start_location: Option<MOQTLocation>,
    pub end_group: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MOQTAliasType {
    Delete,
    Register,
    UseAlias,
    UseValue,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MOQTFetchType {
    Standalone,
    Joining,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTExtensionHeader {
    pub header_type: u64,
    pub header_value: Option<u64>,
    pub header_length: Option<u64>,
    pub payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these control messages have a type
// field. But instead of making that a rust object property, just use serde to
// ensure it goes out on the wire. This means that deserialization of control
// messages also works automatically.
pub enum MOQTControlMessage {
    ClientSetup {
        number_of_parameters: u64,
        setup_parameters: Option<Vec<MOQTSetupParameter>>,
    },

    ServerSetup {
        number_of_parameters: u64,
        setup_parameters: Option<Vec<MOQTSetupParameter>>,
    },

    Goaway {
        new_session_uri: RawInfo,
    },

    Subscribe {
        request_id: u64,
        track_alias: u64,
        track_namespace: Vec<MOQTByteString>,
        track_name: MOQTByteString,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    RequestUpdate {
        request_id: u64,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    Unsubscribe {
        request_id: u64,
    },

    Fetch {
        request_id: u64,
        track_namespace: Vec<MOQTByteString>,
        track_name: MOQTByteString,
        fetch_type: Option<MOQTFetchType>,
        start_location: Option<MOQTLocation>,
        end_location: Option<MOQTLocation>,
        joining_request_id: Option<u64>,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    FetchCancel {
        request_id: u64,
    },

    SubscribeNamespace {
        track_namespace_prefix: Vec<MOQTByteString>,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    SubscribeOk {
        request_id: u64,
        track_alias: u64,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    RequestError {
        request_id: u64,
        error_code: u64,
        reason: Option<MOQTByteString>,
    },

    FetchOk {
        request_id: u64,
        end_location: Option<MOQTLocation>,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    PublishDone {
        track_alias: u64,
        status_code: u64,
        reason: Option<MOQTByteString>,
    },

    MaxRequestId {
        request_id: u64,
    },

    RequestsBlocked {
        maximum_request_id: u64,
    },

    Publish {
        track_namespace: Vec<MOQTByteString>,
        track_name: MOQTByteString,
        track_alias: u64,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    PublishOk {
        track_namespace: Vec<MOQTByteString>,
        track_name: MOQTByteString,
        track_alias: u64,
    },

    PublishNamespace {
        track_namespace_prefix: Vec<MOQTByteString>,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    Namespace {
        track_namespace_suffix: Vec<MOQTByteString>,
        track_name: MOQTByteString,
        track_alias: u64,
        number_of_parameters: u64,
        parameters: Option<Vec<MOQTParameter>>,
    },

    PublishNamespaceDone {
        track_namespace_prefix: Vec<MOQTByteString>,
        status_code: u64,
        reason: Option<MOQTByteString>,
    },

    NamespaceDone,

    PublishNamespaceCancel {
        track_namespace_prefix: Vec<MOQTByteString>,
        error_code: u64,
        reason: Option<MOQTByteString>,
    },

    TrackStatus {
        track_namespace: Vec<MOQTByteString>,
        track_name: MOQTByteString,
        status_code: u64,
        last_location: Option<MOQTLocation>,
    },
    #[default]
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTControlMessageCreated {
    pub stream_id: u64,
    pub length: Option<u64>,
    pub message: MOQTControlMessage,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTControlMessageParsed {
    pub stream_id: u64,
    pub length: Option<u64>,
    pub message: MOQTControlMessage,

    pub raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTStreamTypeSet {
    pub owner: Option<MOQTOwner>,
    pub stream_id: u64,
    pub stream_type: MOQTStreamType,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTObjectDatagramCreated {
    pub track_alias: u64,
    pub group_id: u64,
    pub object_id: Option<u64>,
    pub publisher_priority: Option<u8>,
    pub extension_headers_length: Option<u64>,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
    pub end_of_group: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTObjectDatagramParsed {
    pub track_alias: u64,
    pub group_id: u64,
    pub object_id: Option<u64>,
    pub publisher_priority: Option<u8>,
    pub extension_headers_length: Option<u64>,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
    pub end_of_group: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupHeaderCreated {
    pub stream_id: u64,
    pub track_alias: u64,
    pub group_id: u64,
    pub subgroup_id_mode: u8,
    pub subgroup_id: Option<u64>,
    pub publisher_priority: Option<u8>,
    pub contains_end_of_group: bool,
    pub extensions_present: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupHeaderParsed {
    pub stream_id: u64,
    pub track_alias: u64,
    pub group_id: u64,
    pub subgroup_id_mode: u8,
    pub subgroup_id: Option<u64>,
    pub publisher_priority: Option<u8>,
    pub contains_end_of_group: bool,
    pub extensions_present: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupObjectCreated {
    pub stream_id: u64,
    pub object_id_delta: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupObjectParsed {
    pub stream_id: u64,
    pub object_id_delta: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchHeaderCreated {
    pub stream_id: u64,
    pub request_id: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchHeaderParsed {
    pub stream_id: u64,
    pub request_id: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchObjectCreated {
    pub stream_id: u64,
    pub datagram: bool,
    pub end_of_nonexistent_range: bool,
    pub end_of_unknown_range: bool,
    pub subgroup_id_bits: Option<u8>,
    pub group_id: Option<u64>,
    pub subgroup_id: Option<u64>,
    pub object_id: Option<u64>,
    pub publisher_priority: Option<u8>,
    pub extension_headers_length: Option<u64>,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchObjectParsed {
    pub stream_id: u64,
    pub datagram: bool,
    pub end_of_nonexistent_range: bool,
    pub end_of_unknown_range: bool,
    pub subgroup_id_bits: Option<u8>,
    pub group_id: Option<u64>,
    pub subgroup_id: Option<u64>,
    pub object_id: Option<u64>,
    pub publisher_priority: Option<u8>,
    pub extension_headers_length: Option<u64>,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe() {
        let sub = MOQTControlMessage::Subscribe {
            request_id: 123,
            track_alias: 456,
            track_namespace: vec![
                MOQTByteString {
                    value: Some("hello".to_string()),
                    value_bytes: None,
                },
                MOQTByteString {
                    value: None,
                    value_bytes: Some("world".to_string()),
                },
            ],
            track_name: MOQTByteString {
                value: Some("byeeee".to_string()),
                value_bytes: None,
            },
            number_of_parameters: 2,
            parameters: Some(vec![
                MOQTParameter::AuthorizationToken {
                    alias_type: 3,
                    token_alias: None,
                    token_type: Some(1),
                    token_value: None,
                },
                MOQTParameter::DeliveryTimeout { value: 1000 },
            ]),
        };

        let log_string = r#"{
  "type": "subscribe",
  "request_id": 123,
  "track_alias": 456,
  "track_namespace": [
    {
      "value": "hello"
    },
    {
      "value_bytes": "world"
    }
  ],
  "track_name": {
    "value": "byeeee"
  },
  "number_of_parameters": 2,
  "parameters": [
    {
      "name": "authorization_token",
      "alias_type": 3,
      "token_type": 1
    },
    {
      "name": "delivery_timeout",
      "value": 1000
    }
  ]
}"#;

        assert_eq!(serde_json::to_string_pretty(&sub).unwrap(), log_string);
    }
}
