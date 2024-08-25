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

//! The main h3i client runner.
//!
//! The client is responsible for connecting to an indicated server, executing
//! as series of [Action]s, and capturing the results in a
//! [ConnectionSummary].

pub mod connection_summary;
pub mod sync_client;

use connection_summary::*;
use qlog::events::h3::HttpHeader;
use quiche::ConnectionError;

use std::collections::HashMap;
use std::time::Instant;

use crate::actions::h3::Action;
use crate::actions::h3::StreamEvent;
use crate::actions::h3::StreamEventType;
use crate::frame::H3iFrame;
use crate::frame::ResetStream;
use crate::frame_parser::FrameParseResult;
use crate::frame_parser::FrameParser;
use crate::frame_parser::InterruptCause;
use crate::recordreplay::qlog::QlogEvent;
use crate::recordreplay::qlog::*;
use qlog::events::h3::H3FrameParsed;
use qlog::events::h3::Http3Frame;
use qlog::events::EventData;
use qlog::streamer::QlogStreamer;

use quiche;
use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Error;
use quiche::h3::NameValue;

fn handle_qlog(
    qlog_streamer: Option<&mut QlogStreamer>, qlog_frame: Http3Frame,
    stream_id: u64,
) {
    if let Some(s) = qlog_streamer {
        let ev_data = EventData::H3FrameParsed(H3FrameParsed {
            stream_id,
            length: None,
            frame: qlog_frame,
            raw: None,
        });

        s.add_event_data_now(ev_data).ok();
    }
}

#[derive(Debug)]
/// Represents different errors that can occur when [sync_client] runs.
pub enum ClientError {
    /// An error during the QUIC handshake.
    HandshakeFail,
    /// An error during HTTP/3 exchanges.
    HttpFail,
    /// Some other type of error.
    Other(String),
}

// Placeholder so that we can reuse parse_streams between the sync/async clients
pub(crate) enum ClientVariant {
    Sync {
        stream_map: StreamMap,
        stream_parser_map: StreamParserMap,
    },
    #[allow(dead_code)]
    Async,
}

pub(crate) type StreamParserMap = HashMap<u64, FrameParser>;

pub(crate) fn execute_action(
    action: &Action, conn: &mut quiche::Connection,
    stream_parsers: &mut StreamParserMap,
) {
    match action {
        Action::SendFrame {
            stream_id,
            fin_stream,
            frame,
        } => {
            log::info!("frame tx id={} frame={:?}", stream_id, frame);

            // TODO: make serialization smarter
            let mut d = [42; 9999];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            if let Some(s) = conn.qlog_streamer() {
                let events: QlogEvents = action.into();
                for event in events {
                    match event {
                        QlogEvent::Event { data, ex_data } => {
                            // skip dummy packet
                            if matches!(data.as_ref(), EventData::PacketSent(..))
                            {
                                continue;
                            }

                            s.add_event_data_ex_now(*data, ex_data).ok();
                        },

                        QlogEvent::JsonEvent(mut ev) => {
                            // need to rewrite the event time
                            ev.time = Instant::now()
                                .duration_since(s.start_time())
                                .as_secs_f32() *
                                1000.0;
                            s.add_event(ev).ok();
                        },
                    }
                }
            }
            let len = frame.to_bytes(&mut b).unwrap();

            // TODO - pass errors here to the connectionsummary, which means we
            // can't initialize it when the connection's been shut
            // down
            conn.stream_send(*stream_id, &d[..len], *fin_stream)
                .unwrap();

            stream_parsers
                .entry(*stream_id)
                .or_insert_with(|| FrameParser::new(*stream_id));
        },

        Action::SendHeadersFrame {
            stream_id,
            fin_stream,
            headers,
            frame,
            ..
        } => {
            log::info!(
                "headers frame tx stream={} hdrs={:?}",
                stream_id,
                headers
            );

            // TODO: make serialization smarter
            let mut d = [42; 9999];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            if let Some(s) = conn.qlog_streamer() {
                let events: QlogEvents = action.into();
                for event in events {
                    match event {
                        QlogEvent::Event { data, ex_data } => {
                            // skip dummy packet
                            if matches!(data.as_ref(), EventData::PacketSent(..))
                            {
                                continue;
                            }

                            s.add_event_data_ex_now(*data, ex_data).ok();
                        },

                        QlogEvent::JsonEvent(mut ev) => {
                            // need to rewrite the event time
                            ev.time = Instant::now()
                                .duration_since(s.start_time())
                                .as_secs_f32() *
                                1000.0;
                            s.add_event(ev).ok();
                        },
                    }
                }
            }
            let len = frame.to_bytes(&mut b).unwrap();
            conn.stream_send(*stream_id, &d[..len], *fin_stream)
                .unwrap();

            stream_parsers
                .entry(*stream_id)
                .or_insert_with(|| FrameParser::new(*stream_id));
        },

        Action::OpenUniStream {
            stream_id,
            fin_stream,
            stream_type,
        } => {
            log::info!(
                "open uni stream_id={} ty={} fin={}",
                stream_id,
                stream_type,
                fin_stream
            );

            let mut d = [42; 8];
            let mut b = octets::OctetsMut::with_slice(&mut d);
            b.put_varint(*stream_type).unwrap();
            let off = b.off();

            conn.stream_send(*stream_id, &d[..off], *fin_stream)
                .unwrap();

            stream_parsers
                .entry(*stream_id)
                .or_insert_with(|| FrameParser::new(*stream_id));
        },

        Action::StreamBytes {
            stream_id,
            bytes,
            fin_stream,
        } => {
            log::info!(
                "stream bytes tx id={} len={} fin={}",
                stream_id,
                bytes.len(),
                fin_stream
            );
            conn.stream_send(*stream_id, bytes, *fin_stream).unwrap();

            stream_parsers
                .entry(*stream_id)
                .or_insert_with(|| FrameParser::new(*stream_id));
        },

        Action::ResetStream {
            stream_id,
            error_code,
        } => {
            log::info!(
                "reset_stream stream_id={} error_code={}",
                stream_id,
                error_code
            );
            if let Err(e) = conn.stream_shutdown(
                *stream_id,
                quiche::Shutdown::Write,
                *error_code,
            ) {
                log::error!("can't send reset_stream: {}", e);
                // Clients can't reset streams they don't own. If we attempt to do
                // this, stream_shutdown would fail, and we
                // shouldn't create a parser.
                return;
            }

            stream_parsers
                .entry(*stream_id)
                .or_insert_with(|| FrameParser::new(*stream_id));
        },

        Action::StopSending {
            stream_id,
            error_code,
        } => {
            log::info!(
                "stop_sending stream id={} error_code={}",
                stream_id,
                error_code
            );

            if let Err(e) = conn.stream_shutdown(
                *stream_id,
                quiche::Shutdown::Read,
                *error_code,
            ) {
                log::error!("can't send stop_sending: {}", e);
            }

            // A `STOP_SENDING` should elicit a `RESET_STREAM` in response, which
            // the frame parser can automatically handle.
            stream_parsers
                .entry(*stream_id)
                .or_insert_with(|| FrameParser::new(*stream_id));
        },

        Action::ConnectionClose { error } => {
            let ConnectionError {
                is_app,
                error_code,
                reason,
            } = error;

            log::info!("connection_close={error:?}");
            let _ = conn.close(*is_app, *error_code, reason);
        },

        // Neither of these actions will manipulate the Quiche connection
        Action::FlushPackets | Action::Wait { .. } => unreachable!(),
    }
}

pub(crate) fn parse_streams(
    conn: &mut quiche::Connection, client_variant: &mut ClientVariant,
) -> Vec<StreamEvent> {
    fn handle_fin(
        responded_streams: &mut Vec<StreamEvent>, stream_id: u64,
        stream_parsers: &mut StreamParserMap,
    ) {
        responded_streams.push(StreamEvent {
            stream_id,
            event_type: StreamEventType::Finished,
        });

        stream_parsers.remove(&stream_id);
    }

    let mut responded_streams: Vec<StreamEvent> =
        Vec::with_capacity(conn.readable().len());

    // Ugly, but we have to get the components out of the ClientVariant so that we
    // avoid simultaneous mutable borrows. This will be better when the sync
    // client gets deprecated
    let (stream_parsers, mut stream_map_interaction) = match client_variant {
        ClientVariant::Sync {
            stream_parser_map,
            stream_map,
        } => (stream_parser_map, StreamMapInserter::Native(stream_map)),

        ClientVariant::Async => unimplemented!("async client"),
    };

    for stream in conn.readable() {
        // TODO: ignoring control streams
        if stream % 4 != 0 {
            continue;
        }

        let parser = stream_parsers
            .get_mut(&stream)
            .expect("stream readable with no parser");
        loop {
            match parser.try_parse_frame(conn) {
                Ok(FrameParseResult::FrameParsed { h3i_frame, fin }) => {
                    if let H3iFrame::Headers(ref headers) = h3i_frame {
                        log::info!("hdrs={:?}", headers);
                    }

                    handle_response_frame(
                        &mut stream_map_interaction,
                        conn.qlog_streamer(),
                        &mut responded_streams,
                        stream,
                        h3i_frame,
                    );

                    if fin {
                        handle_fin(
                            &mut responded_streams,
                            stream,
                            stream_parsers,
                        );

                        break;
                    }
                },
                Ok(FrameParseResult::Retry) => {},
                Ok(FrameParseResult::Interrupted(cause)) => {
                    if let InterruptCause::ResetStream(error_code) = cause {
                        let frame = H3iFrame::ResetStream(ResetStream {
                            stream_id: stream,
                            error_code,
                        });

                        log::info!("received reset stream: {:?}", frame);
                        handle_response_frame(
                            &mut stream_map_interaction,
                            None,
                            &mut responded_streams,
                            stream,
                            frame,
                        );
                    }

                    handle_fin(&mut responded_streams, stream, stream_parsers);

                    break;
                },
                Err(e) => {
                    match e {
                        Error::TransportError(quiche::Error::Done) => {
                            log::debug!("stream {stream} exhausted");
                        },
                        Error::TransportError(quiche::Error::StreamReset(
                            error_code,
                        )) => {
                            let frame = H3iFrame::ResetStream(ResetStream {
                                stream_id: stream,
                                error_code,
                            });

                            log::info!("received reset stream: {:?}", frame);

                            handle_response_frame(
                                &mut stream_map_interaction,
                                None,
                                &mut responded_streams,
                                stream,
                                frame,
                            );

                            stream_parsers.remove(&stream);
                        },
                        _ => {
                            log::warn!("stream read error: {e}");
                        },
                    };

                    break;
                },
            }
        }
    }

    responded_streams
}

/// An abstraction over a [`StreamMap`]. This is required because the async
/// client doesn't construct the [`StreamMap`] directly - rather, it's
/// constructed piecemeal as the receiver sees new frames.
enum StreamMapInserter<'a> {
    Native(&'a mut StreamMap),
}

/// Push any responses to the [StreamMap] as well as store them in the
/// `responded` vector
fn handle_response_frame(
    stream_map_inserter: &mut StreamMapInserter,
    qlog_streamer: Option<&mut QlogStreamer>,
    responded_streams: &mut Vec<StreamEvent>, stream_id: u64, frame: H3iFrame,
) {
    let cloned = frame.clone();
    match stream_map_inserter {
        StreamMapInserter::Native(s) => s.insert(stream_id, cloned),
    }

    let mut to_qlog: Option<Http3Frame> = None;
    let mut push_to_responses: Option<StreamEvent> = None;

    match frame {
        H3iFrame::Headers(enriched_headers) => {
            push_to_responses = Some(StreamEvent {
                stream_id,
                event_type: StreamEventType::Headers,
            });

            let qlog_headers: Vec<HttpHeader> = enriched_headers
                .headers()
                .iter()
                .map(|h| qlog::events::h3::HttpHeader {
                    name: String::from_utf8_lossy(h.name()).into_owned(),
                    value: String::from_utf8_lossy(h.value()).into_owned(),
                })
                .collect();

            to_qlog = Some(Http3Frame::Headers {
                headers: qlog_headers,
            });
        },
        H3iFrame::QuicheH3(quiche_frame) => {
            if let QFrame::Data { .. } = quiche_frame {
                push_to_responses = Some(StreamEvent {
                    stream_id,
                    event_type: StreamEventType::Data,
                });
            }

            to_qlog = Some(quiche_frame.to_qlog());
        },
        H3iFrame::ResetStream(_) => {
            push_to_responses = Some(StreamEvent {
                stream_id,
                event_type: StreamEventType::Finished,
            });
        },
    }

    if let Some(to_qlog) = to_qlog {
        handle_qlog(qlog_streamer, to_qlog, stream_id);
    }

    if let Some(to_push) = push_to_responses {
        responded_streams.push(to_push);
    }
}
