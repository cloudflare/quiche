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

use super::EventHeader;
use super::SourceDependency;

use regex::Regex;
use std::convert::TryFrom;

#[derive(Debug)]
pub enum Event {
    Http2Session(Http2SessionEvent),
    Http2SessionInitialized(Http2SessionInitializedEvent),
    Http2SessionSendSettings(Http2SessionSendSettingsEvent),
    Http2SessionRecvSetting(Http2SessionRecvSettingEvent),
    Http2SessionSendHeaders(Http2SessionSendHeadersEvent),
    Http2SessionSendData(Http2SessionSendDataEvent),
    Http2SessionRecvHeaders(Http2SessionRecvHeadersEvent),
    Http2SessionRecvData(Http2SessionRecvDataEvent),
    Http2SessionUpdateRecvWindow(Http2SessionUpdateRecvWindowEvent),
    Http2SessionUpdateSendWindow(Http2SessionUpdateSendWindowEvent),
    Http2SessionUpdateStreamsSendWindowSize(
        Http2SessionUpdateStreamsSendWindowSizeEvent,
    ),
    Http2SessionSendWindowUpdate(Http2SessionSendWindowUpdateEvent),
    Http2SessionRecvWindowUpdate(Http2SessionRecvWindowUpdateEvent),
    Http2StreamUpdateSendWindow(Http2StreamUpdateSendWindowEvent),
    Http2StreamUpdateRecvWindow(Http2StreamUpdateRecvWindowEvent),
    Http2StreamStalledByStreamSendWindow(
        Http2StreamStalledByStreamSendWindowEvent,
    ),
    Http2SessionPing(Http2SessionPingEvent),
    Http2SessionSendRstStream(Http2SessionSendRstStreamEvent),
    Http2SessionRecvRstStream(Http2SessionRecvRstStreamEvent),
    Http2SessionRecvGoaway(Http2SessionRecvGoawayEvent),
    Http2SessionClose(Http2SessionCloseEvent),
    Http2SessionStalledMaxStreams(Htt2SessionStalledMaxStreamsEvent),
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionParams {
    pub host: String,
    pub proxy: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionEvent {
    pub params: Http2SessionParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionInitializedParams {
    pub protocol: String,
    pub source_dependency: SourceDependency,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionInitializedEvent {
    pub params: Http2SessionInitializedParams,
}

// Example: "[id:1 (SETTINGS_HEADER_TABLE_SIZE) value:65536]"
pub const H2_SEND_SETTINGS_PATTERN: &str = r"^\[id:(\d+) \(\w+\) value:(\d+)\]";
#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendSettingsParams {
    pub settings: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendSettingsEvent {
    pub params: Http2SessionSendSettingsParams,
}

// Example: "3 (SETTINGS_MAX_CONCURRENT_STREAMS)"
pub const H2_RECV_SETTING_PATTERN: &str = r"^(\d+) \(\w+\)";
#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvSettingParams {
    pub id: String,
    pub value: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvSettingEvent {
    pub params: Http2SessionRecvSettingParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendHeadersParams {
    pub stream_id: u32,
    pub headers: Vec<String>,
    pub fin: bool,

    pub has_priority: bool,
    pub exclusive: bool,
    pub weight: u16, /* TODO: this is really an 8-bit integer but the number
                      * range is 1-256 so u8 fails */
    pub parent_stream_id: u32,

    pub source_dependency: SourceDependency,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendHeadersEvent {
    pub params: Http2SessionSendHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendDataParams {
    pub stream_id: u32,
    pub size: u32,
    pub fin: bool,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendDataEvent {
    pub params: Http2SessionSendDataParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvHeadersParams {
    pub stream_id: u32,
    pub headers: Vec<String>,
    pub fin: bool,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvHeadersEvent {
    pub params: Http2SessionRecvHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvDataParams {
    pub stream_id: u32,
    pub size: u32,
    pub fin: bool,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvDataEvent {
    pub params: Http2SessionSendDataParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionUpdateRecvWindowParams {
    pub delta: i32,
    pub window_size: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionUpdateRecvWindowEvent {
    pub params: Http2SessionUpdateRecvWindowParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionUpdateSendWindowParams {
    pub delta: i32,
    pub window_size: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionUpdateSendWindowEvent {
    pub params: Http2SessionUpdateSendWindowParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionUpdateStreamsSendWindowSizeParams {
    pub delta_window_size: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionUpdateStreamsSendWindowSizeEvent {
    pub params: Http2SessionUpdateStreamsSendWindowSizeParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendWindowUpdateParams {
    pub delta: i32,
    pub stream_id: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendWindowUpdateEvent {
    pub params: Http2SessionSendWindowUpdateParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvWindowUpdateParams {
    pub delta: i32,
    pub stream_id: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvWindowUpdateEvent {
    pub params: Http2SessionRecvWindowUpdateParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2StreamUpdateSendWindowParams {
    pub delta: i32,
    pub stream_id: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2StreamUpdateSendWindowEvent {
    pub params: Http2StreamUpdateSendWindowParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2StreamUpdateRecvWindowParams {
    pub delta: i32,
    pub stream_id: u32,
    pub window_size: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2StreamUpdateRecvWindowEvent {
    pub params: Http2StreamUpdateRecvWindowParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2StreamStalledByStreamSendWindowParams {
    pub stream_id: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2StreamStalledByStreamSendWindowEvent {
    pub params: Http2StreamStalledByStreamSendWindowParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionPingParams {
    pub is_ack: bool,
    #[serde(rename = "type")]
    pub ty: String,
    pub unique_id: u64,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionPingEvent {
    pub params: Http2SessionPingParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendRstStreamParams {
    pub stream_id: u32,
    pub description: String,
    pub error_code: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionSendRstStreamEvent {
    pub params: Http2SessionSendRstStreamParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvRstStreamParams {
    pub stream_id: u32,
    pub error_code: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvRstStreamEvent {
    pub params: Http2SessionRecvRstStreamParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvGoawayParams {
    pub active_streams: u32,
    pub debug_data: String,
    pub error_code: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionRecvGoawayEvent {
    pub params: Http2SessionRecvGoawayParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionCloseParams {
    pub description: String,
    pub net_error: i64,
}

#[derive(Deserialize, Debug, Default)]
pub struct Http2SessionCloseEvent {
    pub params: Http2SessionCloseParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct Htt2SessionStalledMaxStreamsParams {
    pub max_concurrent_streams: u32,
    pub num_active_streams: u32,
    pub num_created_streams: u32,
}

#[derive(Deserialize, Debug, Default)]
pub struct Htt2SessionStalledMaxStreamsEvent {
    pub params: Htt2SessionStalledMaxStreamsParams,
}

const H2_HEADER_TABLE_SIZE: u16 = 0x01;
const H2_ENABLE_PUSH: u16 = 0x02;
const H2_MAX_CONCURRENT_STREAMS: u16 = 0x03;
const H2_INITIAL_WINDOW_SIZE: u16 = 0x04;
const H2_MAX_FRAME_SIZE: u16 = 0x05;
const H2_MAX_HEADER_LIST_SIZE: u16 = 0x06;
const H2_ENABLE_CONNECT_PROTOCOL: u16 = 0x08;
const H2_NO_RFC7540_PRIORITIES: u16 = 0x09;
const H2_TLS_RENEG_PERMITTED: u16 = 0x10;
const H2_ENABLE_METADATA: u16 = 0x4d44;

pub const H2_DEFAULT_WINDOW_SIZE: u32 = 65535;

#[derive(Debug, Default)]
pub struct Http2Settings {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: Option<u32>,
    pub no_rfc7540_priorities: Option<u32>,
    pub tls_reneg_permitted: Option<u32>,
    pub enable_metadata: Option<u32>,
}

impl Http2Settings {
    pub fn set_from_wire(&mut self, id: u16, value: u32) {
        match id {
            H2_HEADER_TABLE_SIZE => self.header_table_size = Some(value),
            H2_ENABLE_PUSH => self.enable_push = Some(value),
            H2_MAX_CONCURRENT_STREAMS =>
                self.max_concurrent_streams = Some(value),
            H2_INITIAL_WINDOW_SIZE => self.initial_window_size = Some(value),
            H2_MAX_FRAME_SIZE => self.max_frame_size = Some(value),
            H2_MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),
            H2_ENABLE_CONNECT_PROTOCOL =>
                self.enable_connect_protocol = Some(value),
            H2_NO_RFC7540_PRIORITIES => self.no_rfc7540_priorities = Some(value),
            H2_TLS_RENEG_PERMITTED => self.tls_reneg_permitted = Some(value),
            H2_ENABLE_METADATA => self.enable_metadata = Some(value),

            // TODO: ignoring unknown settings but could capture them
            _ => (),
        }
    }
}

impl TryFrom<&[String]> for Http2Settings {
    type Error = String;

    fn try_from(settings: &[String]) -> Result<Self, Self::Error> {
        let re = Regex::new(H2_SEND_SETTINGS_PATTERN).unwrap();
        let mut parsed = Self::default();

        for setting in settings {
            match re.captures(setting) {
                Some(caps) => match (caps.get(1), caps.get(2)) {
                    (Some(id), Some(value)) => {
                        match (
                            id.as_str().parse::<u16>(),
                            value.as_str().parse::<u32>(),
                        ) {
                            (Ok(id), Ok(v)) => {
                                parsed.set_from_wire(id, v);
                            },

                            _ =>
                                return Err(format!(
                                    "error: parsing H2 setting {}",
                                    setting
                                )),
                        }
                    },

                    _ =>
                        return Err(format!(
                            "error: parsing H2 setting {}",
                            setting
                        )),
                },

                None =>
                    return Err(format!("error: parsing H2 setting {}", setting)),
            }
        }

        Ok(parsed)
    }
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
pub fn parse_event(
    event_hdr: &EventHeader, event: &[u8],
) -> Option<super::Event> {
    match event_hdr.ty_string.as_str() {
        "HTTP2_SESSION" =>
            if event_hdr.phase_string == "PHASE_BEGIN" {
                let ev: Http2SessionEvent =
                    serde_json::from_slice(event).unwrap();
                return Some(super::Event::H2(Event::Http2Session(ev)));
            },

        "HTTP2_SESSION_INITIALIZED" => {
            let ev: Http2SessionInitializedEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionInitialized(ev)));
        },

        "HTTP2_SESSION_SEND_SETTINGS" => {
            let ev: Http2SessionSendSettingsEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionSendSettings(ev)));
        },

        "HTTP2_SESSION_RECV_SETTING" => {
            let ev: Http2SessionRecvSettingEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionRecvSetting(ev)));
        },

        "HTTP2_SESSION_UPDATE_RECV_WINDOW" => {
            let ev: Http2SessionUpdateRecvWindowEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionUpdateRecvWindow(
                ev,
            )));
        },

        "HTTP2_SESSION_UPDATE_SEND_WINDOW" => {
            let ev: Http2SessionUpdateSendWindowEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionUpdateSendWindow(
                ev,
            )));
        },

        "HTTP2_SESSION_UPDATE_STREAMS_SEND_WINDOW_SIZE" => {
            let ev: Http2SessionUpdateStreamsSendWindowSizeEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(
                Event::Http2SessionUpdateStreamsSendWindowSize(ev),
            ));
        },

        "HTTP2_SESSION_SEND_WINDOW_UPDATE" => {
            let ev: Http2SessionSendWindowUpdateEvent =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::H2(Event::Http2SessionSendWindowUpdate(
                ev,
            )));
        },

        "HTTP2_SESSION_RECV_WINDOW_UPDATE" => {
            let ev: Http2SessionRecvWindowUpdateEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionRecvWindowUpdate(
                ev,
            )));
        },

        "HTTP2_STREAM_UPDATE_SEND_WINDOW" => {
            let ev: Http2StreamUpdateSendWindowEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2StreamUpdateSendWindow(
                ev,
            )));
        },

        "HTTP2_STREAM_UPDATE_RECV_WINDOW" => {
            let ev: Http2StreamUpdateRecvWindowEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2StreamUpdateRecvWindow(
                ev,
            )));
        },

        "HTTP2_SESSION_STREAM_STALLED_BY_STREAM_SEND_WINDOW" => {
            let ev: Http2StreamStalledByStreamSendWindowEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(
                Event::Http2StreamStalledByStreamSendWindow(ev),
            ));
        },

        "HTTP2_SESSION_SEND_HEADERS" => {
            let ev: Http2SessionSendHeadersEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionSendHeaders(ev)));
        },

        "HTTP2_SESSION_SEND_DATA" => {
            let ev: Http2SessionSendDataEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionSendData(ev)));
        },

        "HTTP2_SESSION_RECV_HEADERS" => {
            let ev: Http2SessionRecvHeadersEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionRecvHeaders(ev)));
        },

        "HTTP2_SESSION_RECV_DATA" => {
            let ev: Http2SessionRecvDataEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionRecvData(ev)));
        },

        "HTTP2_SESSION_PING" => {
            let ev: Http2SessionPingEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionPing(ev)));
        },

        "HTTP2_SESSION_SEND_RST_STREAM" => {
            let ev: Http2SessionSendRstStreamEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionSendRstStream(ev)));
        },

        "HTTP2_SESSION_RECV_RST_STREAM" => {
            let ev: Http2SessionRecvRstStreamEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionRecvRstStream(ev)));
        },

        "HTTP2_SESSION_RECV_GOAWAY" => {
            let ev: Http2SessionRecvGoawayEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionRecvGoaway(ev)));
        },

        "HTTP2_SESSION_CLOSE" => {
            let ev: Http2SessionCloseEvent =
                serde_json::from_slice(event).unwrap();

            return Some(super::Event::H2(Event::Http2SessionClose(ev)));
        },

        "HTTP2_SESSION_STALLED_MAX_STREAMS" => {
            let ev: Htt2SessionStalledMaxStreamsEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::H2(Event::Http2SessionStalledMaxStreams(
                ev,
            )));
        },

        // TODO
        "HTTP2_PROXY_CLIENT_SESSION" |
        "HTTP2_SESSION_INITIAL_WINDOW_SIZE_OUT_OF_RANGE" |
        "HTTP2_SESSION_RECV_INVALID_HEADER" |
        "HTTP2_SESSION_RECV_PUSH_PROMISE" |
        "HTTP2_SESSION_SEND_GREASED_FRAME" |
        "HTTP2_SESSION_STREAM_STALLED_BY_SESSION_SEND_WINDOW" |
        "HTTP2_STREAM" |
        "HTTP2_STREAM_ADOPTED_PUSH_STREAM" |
        "HTTP2_STREAM_ERROR" |
        "HTTP2_STREAM_FLOW_CONTROL_UNSTALLED" |
        "HTTP2_STREAM_SEND_PRIORITY" => log::trace!(
            "todo: {} => {}\n",
            event_hdr.ty_string,
            String::from_utf8_lossy(event)
        ),

        // Other events observed in netlogs but not currently supported.
        "HTTP2_SESSION_POOL_CREATED_NEW_SESSION" |
        "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION" |
        "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION_FROM_IP_POOL" |
        "HTTP2_SESSION_POOL_IMPORTED_SESSION_FROM_SOCKET" |
        "HTTP2_SESSION_POOL_REMOVE_SESSION" |
        "HTTP2_SESSION_RECV_ACCEPT_CH" |
        "HTTP2_SESSION_RECV_SETTINGS" |
        "HTTP2_SESSION_SEND_SETTINGS_ACK" |
        "HTTP2_SESSION_RECV_SETTINGS_ACK" => (),

        // The netlog format is continually evolving, log any unknown types in
        // case they are interesting.
        _ =>
            log::trace!("skipping unknown HTTP/2 type....{}", event_hdr.ty_string),
    }

    None
}
