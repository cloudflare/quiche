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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MOQTOwner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MOQTStreamType {
    SubgroupHeader,
    FetchHeader,
    Control,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MOQTEventType {
    StreamTypeSet,
    ControlMessageCreated,
    ControlMessageParsed,
    ObjectDatagramCreated,
    ObjectDatagramParsed,
    ObjectDatagramStatusCreated,
    ObjectDatagramStatusParsed,
    SubgroupHeaderCreated,
    SubgroupHeaderParsed,
    SubgroupObjectCreated,
    SubgroupObjectParsed,
    FetchHeaderCreated,
    FetchHeaderParsed,
    FetchObjectCreated,
    FetchObjectParsed,
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

    MaxSubscribeId {
        value: u64,
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
    AuthorizationInfo {
        value: String,
    },

    DeliveryTimeout {
        value: u64,
    },

    MaxCacheDuration {
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
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MOQTStringOrBytes {
    pub value: Option<String>,
    pub value_bytes: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MOQTExtensionHeader {
    pub header_type: u64,
    pub header_value: Option<u64>,
    pub header_length: Option<u64>,
    pub payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
// Strictly, the qlog spec says that all these control messages have a type
// field. But instead of making that a rust object property, just use serde to
// ensure it goes out on the wire. This means that deserialization of control
// messages also works automatically.
pub enum MOQTControlMessage {
    ClientSetup {
        number_of_supported_versions: u64,
        supported_versions: Vec<u64>,
        number_of_parameters: u64,
        setup_parameters: Vec<MOQTSetupParameter>,
    },

    ServerSetup {
        selected_version: u64,
        number_of_parameters: u64,
        setup_parameters: Vec<MOQTSetupParameter>,
    },

    Goaway {
        new_session_uri: RawInfo,
    },

    Subscribe {
        subscribe_id: u64,
        track_alias: u64,
        track_namespace: Vec<MOQTStringOrBytes>,
        track_name: MOQTStringOrBytes,
        subscriber_priority: u8,
        group_order: u8,
        filter_type: u64,
        start_group: Option<u64>,
        start_object: Option<u64>,
        end_group: Option<u64>,
        number_of_parameters: u64,
        subscribe_parameters: Vec<MOQTParameter>,
    },

    SubscribeUpdate {
        subscribe_id: u64,
        start_group: u64,
        start_object: u64,
        end_group: u64,
        subscriber_priority: u8,
        number_of_parameters: u64,
        subscribe_parameters: Vec<MOQTParameter>,
    },

    Unsubscribe {
        subscribe_id: u64,
    },

    Fetch {
        subscribe_id: u64,
        subscriber_priority: u8,
        group_order: u8,
        fetch_type: u64,
        track_namespace: Vec<MOQTStringOrBytes>,
        track_name: Option<MOQTStringOrBytes>,
        start_group: Option<u64>,
        start_object: Option<u64>,
        end_group: Option<u64>,
        end_object: Option<u64>,
        joining_subscribe_id: Option<u64>,
        preceding_group_offset: Option<u64>,
        number_of_parameters: u64,
        parameters: Vec<MOQTParameter>,
    },

    FetchCancel {
        subscribe_id: u64,
    },

    AnnounceOk {
        track_namespace: Vec<MOQTStringOrBytes>,
    },

    AnnounceError {
        track_namespace: Vec<MOQTStringOrBytes>,
        error_code: u64,
        reason: Option<String>,
        reason_bytes: Option<String>,
    },

    AnnounceCancel {
        track_namespace: Vec<MOQTStringOrBytes>,
        error_code: u64,
        reason: Option<String>,
        reason_bytes: Option<String>,
    },

    TrackStatusRequest {
        track_namespace: Vec<MOQTStringOrBytes>,
        track_name: MOQTStringOrBytes,
    },

    SubscribeAnnounces {
        track_namespace: Vec<MOQTStringOrBytes>,
        number_of_parameters: u64,
        parameters: Vec<MOQTParameter>,
    },

    UnsubscribeAnnounces {
        track_namespace: Vec<MOQTStringOrBytes>,
    },

    SubscribeOk {
        subscribe_id: u64,
        expires: u8,
        group_order: u8,
        content_exists: u8,
        largest_group_id: Option<u64>,
        largest_object_id: Option<u64>,
        number_of_parameters: u64,
        subscribe_parameters: Vec<MOQTParameter>,
    },

    SubscribeError {
        subscribe_id: u64,
        error_code: u64,
        reason: Option<String>,
        reason_bytes: Option<String>,
        track_alias: u64,
    },

    FetchOk {
        subscribe_id: u64,
        group_order: u8,
        end_of_track: u8,
        largest_group_id: Option<u64>,
        largest_object_id: Option<u64>,
        number_of_parameters: u64,
        parameters: Vec<MOQTParameter>,
    },

    FetchError {
        subscribe_id: u64,
        error_code: u64,
        reason: Option<String>,
        reason_bytes: Option<String>,
    },

    SubscribeDone {
        subscribe_id: u64,
        status_code: u64,
        stream_count: u64,
        reason: Option<String>,
        reason_bytes: Option<String>,
    },

    MaxSubscribeId {
        subscribe_id: u64,
    },

    SubscribedBlocked {
        maximum_subscribe_id: u64,
    },

    Announce {
        track_namespace: Vec<MOQTStringOrBytes>,
        number_of_parameters: u64,
        parameters: Vec<MOQTParameter>,
    },

    Unannounce {
        track_namespace: Vec<MOQTStringOrBytes>,
    },

    TrackStatus {
        track_namespace: Vec<MOQTStringOrBytes>,
        track_name: MOQTStringOrBytes,
        status_code: u64,
        last_group_id: Option<u64>,
        last_object_id: Option<u64>,
    },

    SubscribeAnnouncesOk {
        track_namespace: Vec<MOQTStringOrBytes>,
    },

    SubscribeAnnouncesError {
        track_namespace: Vec<MOQTStringOrBytes>,
        error_code: u64,
        reason: Option<String>,
        reason_bytes: Option<String>,
    },

    Unknown,
}

impl Default for MOQTControlMessage {
    fn default() -> Self {
        Self::Unknown
    }
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
    pub object_id: u64,
    pub publisher_priority: u8,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload: RawInfo,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTObjectDatagramParsed {
    pub track_alias: u64,
    pub group_id: u64,
    pub object_id: u64,
    pub publisher_priority: u8,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload: RawInfo,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTObjectDatagramStatusCreated {
    pub track_alias: u64,
    pub group_id: u64,
    pub object_id: u64,
    pub publisher_priority: u8,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_status: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTObjectDatagramStatusParsed {
    pub track_alias: u64,
    pub group_id: u64,
    pub object_id: u64,
    pub publisher_priority: u8,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_status: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupHeaderCreated {
    pub stream_id: u64,
    pub track_alias: u64,
    pub group_id: u64,
    pub subgroup_id: u64,
    pub publisher_priority: u8,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupHeaderParsed {
    pub stream_id: u64,
    pub track_alias: u64,
    pub group_id: u64,
    pub subgroup_id: u64,
    pub publisher_priority: u8,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupObjectCreated {
    pub stream_id: u64,
    pub group_id: Option<u64>,
    pub subgroup_id: Option<u64>,
    pub object_id: u64,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTSubgroupObjectParsed {
    pub stream_id: u64,
    pub group_id: Option<u64>,
    pub subgroup_id: Option<u64>,
    pub object_id: u64,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchHeaderCreated {
    pub stream_id: u64,
    pub subscribe_id: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchHeaderParsed {
    pub stream_id: u64,
    pub subscribe_id: u64,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchObjectCreated {
    pub stream_id: u64,
    pub group_id: u64,
    pub subgroup_id: u64,
    pub object_id: u64,
    pub publisher_priority: u8,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct MOQTFetchObjectParsed {
    pub stream_id: u64,
    pub group_id: u64,
    pub subgroup_id: u64,
    pub object_id: u64,
    pub publisher_priority: u8,
    pub extension_headers_length: u64,
    pub extension_headers: Option<Vec<MOQTExtensionHeader>>,
    pub object_payload_length: u64,
    pub object_status: Option<u64>,
    pub object_payload: Option<RawInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsribe() {
        let sub = MOQTControlMessage::Subscribe {
            subscribe_id: 123,
            track_alias: 456,
            track_namespace: vec![
                MOQTStringOrBytes {
                    value: Some("hello".to_string()),
                    value_bytes: None,
                },
                MOQTStringOrBytes {
                    value: None,
                    value_bytes: Some("world".to_string()),
                },
            ],
            track_name: MOQTStringOrBytes {
                value: Some("byeeee".to_string()),
                value_bytes: None,
            },
            subscriber_priority: 99,
            group_order: 55,
            filter_type: 1,
            start_group: Some(2),
            start_object: Some(0),
            end_group: Some(3),
            number_of_parameters: 2,
            subscribe_parameters: vec![
                MOQTParameter::AuthorizationInfo {
                    value: "letmein".to_string(),
                },
                MOQTParameter::DeliveryTimeout { value: 1000 },
            ],
        };

        let log_string = r#"{
  "type": "subscribe",
  "subscribe_id": 123,
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
  "subscriber_priority": 99,
  "group_order": 55,
  "filter_type": 1,
  "start_group": 2,
  "start_object": 0,
  "end_group": 3,
  "number_of_parameters": 2,
  "subscribe_parameters": [
    {
      "name": "authorization_info",
      "value": "letmein"
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
