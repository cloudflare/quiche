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

use std::collections::BTreeMap;

use serde::Deserialize;

use super::EventHeader;
use super::SourceDependency;

#[derive(Debug)]
pub enum Event {
    HttpTransactionSendRequestHeaders(HttpTransactionSendRequestHeadersEvent),
    HttpTransactionHttp2SendRequestHeaders(
        HttpTransactionHttp2SendRequestHeadersEvent,
    ),
    HttpTransactionQuicSendRequestHeaders(
        HttpTransactionQuicSendRequestHeadersEvent,
    ),
    HttpTransactionReadResponseHeaders(HttpTransactionReadResponseHeadersEvent),
    HttpStreamJobBoundToRequest(HttpStreamJobBoundToRequestEvent),
    HttpStreamRequestBoundToJob(HttpStreamRequestBoundToJobEvent),
    HttpStreamRequestBoundToQuicSession(HttpStreamRequestBoundToQuicSessionEvent),
}
#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionSendRequestHeadersParams {
    pub headers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionSendRequestHeadersEvent {
    pub params: HttpTransactionSendRequestHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionHttp2SendRequestHeadersParams {
    pub headers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionHttp2SendRequestHeadersEvent {
    pub params: HttpTransactionHttp2SendRequestHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionQuicSendRequestHeadersParams {
    pub headers: Vec<String>,
    pub quic_priority_incremental: bool,
    pub quic_priority_type: String,
    pub quic_priority_urgency: u8,
    pub quic_stream_id: u64,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionQuicSendRequestHeadersEvent {
    pub params: HttpTransactionQuicSendRequestHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionReadResponseHeadersParams {
    pub headers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionReadResponseHeadersEvent {
    pub params: HttpTransactionReadResponseHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamJobBoundToRequestParams {
    pub source_dependency: SourceDependency,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToJobEvent {
    pub params: HttpStreamJobBoundToRequestParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToJobParams {
    pub source_dependency: SourceDependency,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamJobBoundToRequestEvent {
    pub params: HttpStreamJobBoundToRequestParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToQuicSessionEvent {
    pub params: HttpStreamRequestBoundToQuicSessionParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToQuicSessionParams {
    pub source_dependency: SourceDependency,
}

pub fn headers_to_map(hdrs: &[String]) -> BTreeMap<String, String> {
    let mut ret = BTreeMap::new();

    for hdr in hdrs {
        let mut split = hdr.split(": ");
        let name = split.next();
        let val = split.next();

        match (name, val) {
            (Some(k), Some(v)) => {
                ret.insert(k.to_string(), v.to_string());
            },

            (Some(k), None) => {
                ret.insert(k.to_string(), "".to_string());
            },

            _ => (),
        }
    }

    ret
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
pub fn parse_event(
    event_hdr: &EventHeader, event: &[u8],
) -> Option<super::Event> {
    match event_hdr.ty_string.as_str() {
        "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS" => {
            let ev: HttpTransactionHttp2SendRequestHeadersEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(
                Event::HttpTransactionHttp2SendRequestHeaders(ev),
            ));
        },

        "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS" => {
            let ev: HttpTransactionQuicSendRequestHeadersEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(
                Event::HttpTransactionQuicSendRequestHeaders(ev),
            ));
        },

        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS" => {
            let ev: HttpTransactionSendRequestHeadersEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(
                Event::HttpTransactionSendRequestHeaders(ev),
            ));
        },

        "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" => {
            let ev: HttpTransactionReadResponseHeadersEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(
                Event::HttpTransactionReadResponseHeaders(ev),
            ));
        },

        "HTTP_STREAM_REQUEST_BOUND_TO_JOB" => {
            let ev: HttpStreamRequestBoundToJobEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(Event::HttpStreamRequestBoundToJob(
                ev,
            )));
        },

        "HTTP_STREAM_JOB_BOUND_TO_REQUEST" => {
            let ev: HttpStreamJobBoundToRequestEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(Event::HttpStreamJobBoundToRequest(
                ev,
            )));
        },

        "HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION" => {
            let ev: HttpStreamRequestBoundToQuicSessionEvent =
                serde_json::from_slice(event).unwrap();
            return Some(super::Event::Http(
                Event::HttpStreamRequestBoundToQuicSession(ev),
            ));
        },

        // ignore these for now
        "HTTP_TRANSACTION_READ_EARLY_HINTS_RESPONSE_HEADERS" |
        "HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS" |
        "HTTP_TRANSACTION_RESTART_AFTER_ERROR" |
        "HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST" |
        "HTTP_TRANSACTION_SEND_REQUEST_BODY" |
        "HTTP_TRANSACTION_SEND_TUNNEL_HEADERS" |
        "HTTP_TRANSACTION_TUNNEL_READ_HEADERS" |
        "HTTP_TRANSACTION_TUNNEL_SEND_REQUEST" => (),

        // ignore these ones since they contain no extra params
        "HTTP_TRANSACTION_SEND_REQUEST" |
        "HTTP_TRANSACTION_READ_HEADERS" |
        "HTTP_TRANSACTION_READ_BODY" => (),

        _ => log::trace!("skipping unknown type....{}", event_hdr.ty_string),
    }

    None
}
