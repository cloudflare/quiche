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

//! Actions specific to HTTP/3 and QUIC
//!
//! Actions are small operations such as sending HTTP/3 frames or managing QUIC
//! streams. Each independent use case for h3i requires its own collection of
//! Actions, that h3i iterates over in sequence and executes.

use std::collections::HashMap;
use std::time::Duration;

use quiche;
use quiche::h3::frame::Frame;
use quiche::h3::Header;
use quiche::ConnectionError;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;

use crate::encode_header_block;

/// An action which the HTTP/3 client should take.
///
/// The client iterates over a vector of said actions, executing each one
/// sequentially. Note that packets will be flushed when said iteration has
/// completed, regardless of if an [`Action::FlushPackets`] was the terminal
/// action.
#[derive(Clone, Debug)]
pub enum Action {
    /// Send a [quiche::h3::frame::Frame] over a stream.
    SendFrame {
        stream_id: u64,
        fin_stream: bool,
        frame: Frame,
    },

    /// Send a HEADERS frame over a stream.
    SendHeadersFrame {
        stream_id: u64,
        fin_stream: bool,
        headers: Vec<Header>,
        frame: Frame,
    },

    /// Send arbitrary bytes over a stream.
    StreamBytes {
        stream_id: u64,
        fin_stream: bool,
        bytes: Vec<u8>,
    },

    /// Open a new unidirectional stream.
    OpenUniStream {
        stream_id: u64,
        fin_stream: bool,
        stream_type: u64,
    },

    /// Send a RESET_STREAM frame with the given error code.
    ResetStream {
        stream_id: u64,
        error_code: u64,
    },

    /// Send a STOP_SENDING frame with the given error code.
    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    /// Send a CONNECTION_CLOSE frame with the given [`ConnectionError`].
    ConnectionClose {
        error: ConnectionError,
    },

    FlushPackets,

    /// Wait for an event. See [WaitType] for the events.
    Wait {
        wait_type: WaitType,
    },
}

/// Configure the wait behavior for a connection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
#[serde_as]
pub enum WaitType {
    /// Wait for a time before firing the next action
    #[serde_as(as = "DurationMilliSeconds<f64>")]
    WaitDuration(Duration),
    /// Wait for some form of a response before firing the next action. This can
    /// be superseded in several cases:
    /// 1. The peer resets the spcified stream.
    /// 2. The peer sends a `fin` over the specified stream
    StreamEvent(StreamEvent),
}

/// A response event, received over a stream, which will terminate the wait
/// period.
///
/// See [StreamEventType] for the types of events.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename = "snake_case")]
pub struct StreamEvent {
    pub stream_id: u64,
    #[serde(rename = "type")]
    pub event_type: StreamEventType,
}

/// Response that can terminate a wait period.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamEventType {
    /// A HEADERS frame was received.
    Headers,
    /// A DATA frame was received.
    Data,
    /// The stream was somehow finished, either by a RESET_STREAM frame or via
    /// the `fin` bit being set.
    Finished,
}

#[derive(Debug, Default)]
pub(crate) struct WaitingFor(HashMap<u64, Vec<StreamEvent>>);

impl WaitingFor {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.values().all(|v| v.is_empty())
    }

    pub(crate) fn add_wait(&mut self, stream_event: &StreamEvent) {
        self.0
            .entry(stream_event.stream_id)
            .or_default()
            .push(*stream_event);
    }

    pub(crate) fn remove_wait(&mut self, stream_event: StreamEvent) {
        if let Some(waits) = self.0.get_mut(&stream_event.stream_id) {
            let old_len = waits.len();
            waits.retain(|wait| wait != &stream_event);
            let new_len = waits.len();

            if old_len != new_len {
                log::info!("No longer waiting for {:?}", stream_event);
            }
        }
    }

    pub(crate) fn clear_waits_on_stream(&mut self, stream_id: u64) {
        if let Some(waits) = self.0.get_mut(&stream_id) {
            if !waits.is_empty() {
                log::info!("Clearing all waits for stream {}", stream_id);
                waits.clear();
            }
        }
    }
}

/// Convenience to convert between header-related data and a
/// [Action::SendHeadersFrame].
pub fn send_headers_frame(
    stream_id: u64, fin_stream: bool, headers: Vec<Header>,
) -> Action {
    let header_block = encode_header_block(&headers).unwrap();

    Action::SendHeadersFrame {
        stream_id,
        fin_stream,
        headers,
        frame: Frame::Headers { header_block },
    }
}
