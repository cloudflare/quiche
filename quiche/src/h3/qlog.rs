// Copyright (C) 2018-2019, Cloudflare, Inc.
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

//! Qlog logging support for HTTP/3 connections.

use qlog::events::h3::H3FrameCreated;
use qlog::events::h3::H3FrameParsed;
use qlog::events::h3::H3Owner;
use qlog::events::h3::H3PriorityTargetStreamType;
use qlog::events::h3::H3StreamType;
use qlog::events::h3::H3StreamTypeSet;
use qlog::events::h3::Http3EventType;
use qlog::events::h3::Http3Frame;
use qlog::events::h3::HttpHeader;
use qlog::events::EventData;
use qlog::events::EventType;

// Event type constants for filtering.
const FRAME_CREATED: EventType =
    EventType::Http3EventType(Http3EventType::FrameCreated);
const FRAME_PARSED: EventType =
    EventType::Http3EventType(Http3EventType::FrameParsed);
const STREAM_TYPE_SET: EventType =
    EventType::Http3EventType(Http3EventType::StreamTypeSet);

use super::NameValue;

/// Logs a frame created event with a pre-converted frame.
pub(crate) fn log_frame_created(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64, frame: Http3Frame,
) {
    crate::qlog::with_type!(FRAME_CREATED, qlog, q, {
        let ev_data = EventData::H3FrameCreated(H3FrameCreated {
            stream_id,
            length: Some(length),
            frame,
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a frame created event, converting the frame to qlog format.
pub(crate) fn log_frame_created_from(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64,
    frame: &super::frame::Frame,
) {
    log_frame_created(qlog, stream_id, length, frame.to_qlog());
}

/// Logs a headers frame created event with decoded headers.
pub(crate) fn log_frame_created_headers<T: NameValue>(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64, headers: &[T],
) {
    crate::qlog::with_type!(FRAME_CREATED, qlog, q, {
        let qlog_headers = headers
            .iter()
            .map(|h| HttpHeader {
                name: String::from_utf8_lossy(h.name()).into_owned(),
                value: String::from_utf8_lossy(h.value()).into_owned(),
            })
            .collect();

        let frame = Http3Frame::Headers {
            headers: qlog_headers,
        };
        let ev_data = EventData::H3FrameCreated(H3FrameCreated {
            stream_id,
            length: Some(length),
            frame,
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a data frame created event.
pub(crate) fn log_frame_created_data(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64,
) {
    log_frame_created(qlog, stream_id, length, Http3Frame::Data { raw: None });
}

/// Logs a priority update frame created event.
pub(crate) fn log_frame_created_priority_update(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64,
    prioritized_element_id: u64, priority_field_value: String,
) {
    let frame = Http3Frame::PriorityUpdate {
        target_stream_type: H3PriorityTargetStreamType::Request,
        prioritized_element_id,
        priority_field_value,
    };
    log_frame_created(qlog, stream_id, length, frame);
}

/// Logs a reserved (GREASE) frame created event.
pub(crate) fn log_frame_created_reserved(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64,
) {
    let frame = Http3Frame::Reserved {
        length: Some(length),
    };
    log_frame_created(qlog, stream_id, length, frame);
}

/// Logs a frame parsed event with a pre-converted frame.
pub(crate) fn log_frame_parsed(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64, frame: Http3Frame,
) {
    crate::qlog::with_type!(FRAME_PARSED, qlog, q, {
        let ev_data = EventData::H3FrameParsed(H3FrameParsed {
            stream_id,
            length: Some(length),
            frame,
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a frame parsed event, converting the frame to qlog format.
pub(crate) fn log_frame_parsed_from(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64,
    frame: &super::frame::Frame,
) {
    log_frame_parsed(qlog, stream_id, length, frame.to_qlog());
}

/// Logs a headers frame parsed event with decoded headers.
pub(crate) fn log_frame_parsed_headers<T: NameValue>(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64, headers: &[T],
) {
    crate::qlog::with_type!(FRAME_PARSED, qlog, q, {
        let qlog_headers = headers
            .iter()
            .map(|h| HttpHeader {
                name: String::from_utf8_lossy(h.name()).into_owned(),
                value: String::from_utf8_lossy(h.value()).into_owned(),
            })
            .collect();

        let frame = Http3Frame::Headers {
            headers: qlog_headers,
        };
        let ev_data = EventData::H3FrameParsed(H3FrameParsed {
            stream_id,
            length: Some(length),
            frame,
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a data frame parsed event.
pub(crate) fn log_frame_parsed_data(
    qlog: &mut crate::qlog::Info, stream_id: u64, length: u64,
) {
    log_frame_parsed(qlog, stream_id, length, Http3Frame::Data { raw: None });
}

/// Logs a stream type set event for local streams.
pub(crate) fn log_stream_type_set_local(
    qlog: &mut crate::qlog::Info, stream_id: u64, stream_type: H3StreamType,
) {
    crate::qlog::with_type!(STREAM_TYPE_SET, qlog, q, {
        let ev_data = EventData::H3StreamTypeSet(H3StreamTypeSet {
            stream_id,
            owner: Some(H3Owner::Local),
            stream_type,
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a stream type set event for local GREASE/unknown streams.
pub(crate) fn log_stream_type_set_local_unknown(
    qlog: &mut crate::qlog::Info, stream_id: u64, stream_type_value: u64,
) {
    crate::qlog::with_type!(STREAM_TYPE_SET, qlog, q, {
        let ev_data = EventData::H3StreamTypeSet(H3StreamTypeSet {
            stream_id,
            owner: Some(H3Owner::Local),
            stream_type: H3StreamType::Unknown,
            stream_type_value: Some(stream_type_value),
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a stream type set event for remote streams.
pub(crate) fn log_stream_type_set_remote(
    qlog: &mut crate::qlog::Info, stream_id: u64, stream_type: H3StreamType,
    stream_type_value: Option<u64>,
) {
    crate::qlog::with_type!(STREAM_TYPE_SET, qlog, q, {
        let ev_data = EventData::H3StreamTypeSet(H3StreamTypeSet {
            stream_id,
            owner: Some(H3Owner::Remote),
            stream_type,
            stream_type_value,
            ..Default::default()
        });

        q.add_event_data_now(ev_data).ok();
    });
}

/// Logs a stream type set event for remote streams, converting the type.
pub(crate) fn log_stream_type_set_remote_from(
    qlog: &mut crate::qlog::Info, stream_id: u64,
    stream_type: super::stream::Type, stream_type_value: Option<u64>,
) {
    log_stream_type_set_remote(
        qlog,
        stream_id,
        stream_type.to_qlog(),
        stream_type_value,
    );
}
