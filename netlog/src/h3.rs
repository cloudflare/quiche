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

use super::EventHeader;

#[derive(Debug)]
pub enum Event {
    Http3PriorityUpdateSent(Http3PriorityUpdateSentEvent),
    Http3HeadersSent(Http3HeadersSentEvent),
    Http3DataSent(Http3DataSentEvent),
    Http3HeadersReceived(Http3HeadersReceivedEvent),
    Http3HeadersDecoded(Http3HeadersDecodedEvent),
    Http3DataFrameReceived(Http3DataFrameReceivedEvent),
}
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrioritizedElementType {
    PushStream,
    #[default]
    RequestStream,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3PriorityUpdateSentParams {
    pub prioritized_element_id: u64,
    pub priority_field_value: String,
    #[serde(rename = "type")]
    pub ty: Option<PrioritizedElementType>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3PriorityUpdateSentEvent {
    pub params: Http3PriorityUpdateSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3HeadersSentParams {
    pub stream_id: u64,
    pub headers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3HeadersSentEvent {
    pub params: Http3HeadersSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3DataSentParams {
    pub payload_length: u64,
    pub stream_id: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3DataSentEvent {
    pub params: Http3DataSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3HeadersReceivedParams {
    pub stream_id: u64,
    pub compressed_headers_length: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3HeadersReceivedEvent {
    pub params: Http3HeadersReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3HeadersDecodedParams {
    pub stream_id: u64,
    pub headers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3HeadersDecodedEvent {
    pub params: Http3HeadersDecodedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3DataFrameReceivedParams {
    pub payload_length: u64,
    pub stream_id: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http3DataFrameReceivedEvent {
    pub params: Http3DataFrameReceivedParams,
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
pub fn parse_event(
    event_hdr: &EventHeader, event: &[u8],
) -> Option<super::Event> {
    match event_hdr.ty_string.as_str() {
        "HTTP3_HEADERS_SENT" => {
            let ev: Http3HeadersSentEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H3(Event::Http3HeadersSent(ev)));
        },

        "HTTP3_DATA_SENT" => {
            let ev: Http3DataSentEvent = serde_json::from_slice(event).unwrap();
            return Some(super::Event::H3(Event::Http3DataSent(ev)));
        },

        "HTTP3_HEADERS_RECEIVED" => {
            let ev: Http3HeadersReceivedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H3(Event::Http3HeadersReceived(ev)));
        },

        "HTTP3_HEADERS_DECODED" => {
            let ev: Http3HeadersDecodedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H3(Event::Http3HeadersDecoded(ev)));
        },

        "HTTP3_DATA_FRAME_RECEIVED" => {
            let ev: Http3DataFrameReceivedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H3(Event::Http3DataFrameReceived(ev)));
        },

        "HTTP3_PRIORITY_UPDATE_SENT" => {
            let ev: Http3PriorityUpdateSentEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H3(Event::Http3PriorityUpdateSent(ev)));
        },

        "HTTP3_GOAWAY_SENT" | "HTTP3_GOAWAY_RECEIVED" => {
            // TODO
        },

        // Other events observed in netlogs but not currently supported.
        "HTTP3_LOCAL_CONTROL_STREAM_CREATED" |
        "HTTP3_LOCAL_QPACK_DECODER_STREAM_CREATED" |
        "HTTP3_LOCAL_QPACK_ENCODER_STREAM_CREATED" |
        "HTTP3_PEER_QPACK_DECODER_STREAM_CREATED" |
        "HTTP3_PEER_QPACK_ENCODER_STREAM_CREATED" |
        "HTTP3_SETTINGS_SENT" |
        "HTTP3_SETTINGS_RESUMED" |
        "HTTP3_PEER_CONTROL_STREAM_CREATED" |
        "HTTP3_SETTINGS_RECEIVED" |
        "HTTP3_UNKNOWN_FRAME_RECEIVED" => (),

        // The netlog format is continually evolving, log any unknown types
        // in case they are interesting.
        _ =>
            log::trace!("skipping unknown HTTP/3 type....{}", event_hdr.ty_string),
    }

    None
}
