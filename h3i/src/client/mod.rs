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
use std::net::SocketAddr;
use std::time::Instant;

use crate::actions::h3::Action;
use crate::actions::h3::StreamEvent;
use crate::actions::h3::StreamEventType;
use crate::config::Config;
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

use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Error;
use quiche::h3::NameValue;
use quiche::Connection;
use quiche::Result;
use quiche::{
    self,
};

const MAX_DATAGRAM_SIZE: usize = 1350;
const QUIC_VERSION: u32 = 1;

pub fn build_quiche_connection(
    args: Config, peer_addr: SocketAddr, local_addr: SocketAddr,
) -> Result<Connection> {
    // We'll only connect to one server.
    let connect_url = if !args.omit_sni {
        args.host_port.split(':').next()
    } else {
        None
    };

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(QUIC_VERSION).unwrap();

    config.verify_peer(args.verify_peer);
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(args.idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config
        .set_initial_max_stream_data_bidi_local(args.max_stream_data_bidi_local);
    config.set_initial_max_stream_data_bidi_remote(
        args.max_stream_data_bidi_remote,
    );
    config.set_initial_max_stream_data_uni(args.max_stream_data_uni);
    config.set_initial_max_streams_bidi(args.max_streams_bidi);
    config.set_initial_max_streams_uni(args.max_streams_uni);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(0);

    config.set_max_connection_window(args.max_window);
    config.set_max_stream_window(args.max_stream_window);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    config.grease(false);

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(connect_url, &scid, local_addr, peer_addr, &mut config)?;

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    log::info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addr,
        local_addr,
        scid,
    );

    Ok(conn)
}

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

pub(crate) trait Client {
    /// Gives mutable access to the stream parsers to update their state.
    fn stream_parsers_mut(&mut self) -> &mut StreamParserMap;

    /// Handles a response frame. This allows [`Client`]s to customize how they
    /// construct a [`StreamMap`] from a list of frames.
    fn handle_response_frame(&mut self, stream_id: u64, frame: H3iFrame);
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

pub(crate) fn parse_streams<C: Client>(
    conn: &mut quiche::Connection, client: &mut C,
) -> Vec<StreamEvent> {
    let mut responded_streams: Vec<StreamEvent> =
        Vec::with_capacity(conn.readable().len());

    for stream in conn.readable() {
        // TODO: ignoring control streams
        if stream % 4 != 0 {
            continue;
        }

        loop {
            let stream_parse_result = client
                .stream_parsers_mut()
                .get_mut(&stream)
                .expect("stream readable with no parser")
                .try_parse_frame(conn);

            match stream_parse_result {
                Ok(FrameParseResult::FrameParsed { h3i_frame, fin }) => {
                    if let H3iFrame::Headers(ref headers) = h3i_frame {
                        log::info!("hdrs={:?}", headers);
                    }

                    handle_response_frame(
                        client,
                        conn.qlog_streamer(),
                        &mut responded_streams,
                        stream,
                        h3i_frame,
                    );

                    if fin {
                        handle_fin(
                            &mut responded_streams,
                            client.stream_parsers_mut(),
                            stream,
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
                            client,
                            None,
                            &mut responded_streams,
                            stream,
                            frame,
                        );
                    }

                    handle_fin(
                        &mut responded_streams,
                        client.stream_parsers_mut(),
                        stream,
                    );
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
                                client,
                                None,
                                &mut responded_streams,
                                stream,
                                frame,
                            );

                            client.stream_parsers_mut().remove(&stream);
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

fn handle_fin(
    responded_streams: &mut Vec<StreamEvent>,
    stream_parsers: &mut StreamParserMap, stream_id: u64,
) {
    responded_streams.push(StreamEvent {
        stream_id,
        event_type: StreamEventType::Finished,
    });

    stream_parsers.remove(&stream_id);
}

/// Push any responses to the [StreamMap] as well as store them in the
/// `responded` vector
fn handle_response_frame<C: Client>(
    client: &mut C, qlog_streamer: Option<&mut QlogStreamer>,
    responded_streams: &mut Vec<StreamEvent>, stream_id: u64, frame: H3iFrame,
) {
    let cloned = frame.clone();
    client.handle_response_frame(stream_id, cloned);

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
