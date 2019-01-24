// Copyright (C) 2019, Cloudflare, Inc.
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

//! HTTP/3 client and server.

use std::collections::BTreeMap;

use crate::octets;

use http::{
    Request,
    Response,
    StatusCode,
    Uri,
};

pub type Result<T> = std::result::Result<T, Error>;

pub enum Event {
    OnReqHeaders {
        stream_id: u64,
        value: http::Request<()>,
    },
    OnRespHeaders {
        stream_id: u64,
        value: http::Response<()>,
    },
    OnPayloadData {
        stream_id: u64,
        value: Vec<u8>,
    },
}

/// An HTTP/3 error.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum Error {
    /// There is no error, just stream or connection close.
    Done                 = -1,

    /// The provided buffer is too short.
    BufferTooShort       = -2,

    /// Setting sent in wrong direction.
    WrongSettingDirection = -3,

    /// The server attempted to push content that the client will not accept.
    PushRefused          = -4,

    /// Internal error in the H3 stack.
    InternalError        = -5,

    /// The server attempted to push something the client already has.
    PushAlreadyInCache   = -6,

    /// The client no longer needs the requested data.
    RequestCancelled     = -7,

    /// The request stream terminated before completing the request.
    IncompleteRequest    = -8,

    /// Forward connection failure for CONNECT target.
    ConnectError         = -9,

    /// Endpoint detected that the peer is exhibiting behaviour that causes.
    /// excessive load
    ExcessiveLoad        = -10,

    /// Operation cannot be served over HTT/3. Retry over HTTP/1.1.
    VersionFallback      = -11,

    /// Frame received on stream where it is not permitted.
    WrongStream          = -12,

    /// Stream ID, Push ID or Placeholder Id greater that current maximum was.
    /// used
    LimitExceeded        = -13,

    /// Push ID used in two different stream headers.
    DuplicatePush        = -14,

    /// Unknown unidirection stream type.
    UnknownStreamType    = -15,

    /// Too many unidirectional streams of a type were created.
    WrongStreamCount     = -16,

    /// A required critical stream was closed.
    ClosedCriticalStream = -17,

    /// Unidirectional stream type opened at peer that is prohibited.
    WrongStreamDirection = -18,

    /// Inform client that remainder of request is not needed. Used in
    /// STOP_SENDING only.
    EarlyResponse        = -19,

    /// No SETTINGS frame at beggining of control stream.
    MissingSettings      = -20,

    /// A frame was received which is not permitted in the current state.
    UnexpectedFrame      = -21,

    /// Server rejected request without performing any application processing.
    RequestRejected      = -22,

    /// Peer violated protocol requirements in a way that doesn't match a more
    /// specific code.
    GeneralProtocolError = -23,

    /// TODO: malformed frame where last on-wire byte is the frame type.
    MalformedFrame       = -24,

    /// QPACK Header block decompression failure.
    QpackDecompressionFailed = -25,

    /// QPACK encoder stream error.
    QpackEncoderStreamError = -26,

    /// QPACK decoder stream error.
    QpackDecoderStreamError = -27,
}

impl Error {
    pub fn to_wire(self) -> u16 {
        match self {
            Error::Done => 0x0,
            Error::WrongSettingDirection => 0x1,
            Error::PushRefused => 0x2,
            Error::InternalError => 0x3,
            Error::PushAlreadyInCache => 0x4,
            Error::RequestCancelled => 0x5,
            Error::IncompleteRequest => 0x6,
            Error::ConnectError => 0x07,
            Error::ExcessiveLoad => 0x08,
            Error::VersionFallback => 0x09,
            Error::WrongStream => 0xA,
            Error::LimitExceeded => 0xB,
            Error::DuplicatePush => 0xC,
            Error::UnknownStreamType => 0xD,
            Error::WrongStreamCount => 0xE,
            Error::ClosedCriticalStream => 0xF,
            Error::WrongStreamDirection => 0x10,
            Error::EarlyResponse => 0x11,
            Error::MissingSettings => 0x12,
            Error::UnexpectedFrame => 0x13,
            Error::RequestRejected => 0x14,
            Error::GeneralProtocolError => 0xFF,
            Error::MalformedFrame => 0x10,

            Error::QpackDecompressionFailed => 0x20, // TODO: value is TBD
            Error::QpackEncoderStreamError => 0x21,  // TODO: value is TBD
            Error::QpackDecoderStreamError => 0x22,  // TODO: value is TBD
            Error::BufferTooShort => 0x999,
        }
    }
}

impl std::convert::From<super::Error> for Error {
    fn from(err: super::Error) -> Self {
        match err {
            super::Error::Done => Error::Done,
            super::Error::BufferTooShort => Error::BufferTooShort,
            _ => Error::GeneralProtocolError,
        }
    }
}

fn req_hdrs_to_qpack(
    encoder: &mut qpack::Encoder, request: &http::Request<()>,
) -> Vec<u8> {
    let mut vec = vec![0u8; 65535];

    let mut headers: Vec<qpack::Header> = Vec::new();

    headers.push(qpack::Header::new(":method", request.method().as_str()));
    headers.push(qpack::Header::new(
        ":scheme",
        request.uri().scheme_str().unwrap(),
    ));
    headers.push(qpack::Header::new(
        ":authority",
        request.uri().host().unwrap(),
    ));
    headers.push(qpack::Header::new(
        ":path",
        request.uri().path_and_query().unwrap().as_str(),
    ));

    for (key, value) in request.headers().iter() {
        headers.push(qpack::Header::new(key.as_str(), value.to_str().unwrap()));
    }

    let len = encoder.encode(&headers, &mut vec);

    vec.truncate(len.unwrap());
    trace!("Encoded header block len={:?}", len);

    vec
}

fn resp_hdrs_to_qpack(
    encoder: &mut qpack::Encoder, response: &http::Response<Vec<u8>>,
) -> Vec<u8> {
    let mut vec = vec![0u8; 65535];

    let mut headers: Vec<qpack::Header> = Vec::new();

    headers.push(qpack::Header::new(":status", response.status().as_str()));

    for (key, value) in response.headers().iter() {
        headers.push(qpack::Header::new(key.as_str(), value.to_str().unwrap()));
    }

    let len = encoder.encode(&headers, &mut vec);

    vec.truncate(len.unwrap());
    trace!("Encoded header block len={:?}", len);

    vec
}

fn req_hdrs_from_qpack(
    decoder: &mut qpack::Decoder, hdr_block: &mut [u8],
) -> http::Request<()> {
    let mut req: Request<()> = Request::default();

    // TODO: make pseudo header parsing more efficient. Right now, we create
    // some variables to hold pseudo headers that may arrive in any order.
    // Some of these are later formatted back into a complete URI
    let mut method = String::new();
    let mut scheme = String::new();
    let mut authority = String::new();
    let mut path = String::new();

    for hdr in decoder.decode(hdr_block).unwrap() {
        match hdr.name() {
            ":method" => {
                method = hdr.value().to_string();
            },
            ":scheme" => {
                scheme = hdr.value().to_string();
            },
            ":authority" => {
                authority = hdr.value().to_string();
            },
            ":path" => {
                path = hdr.value().to_string();
            },
            _ => {
                req.headers_mut().insert(
                    http::header::HeaderName::from_bytes(hdr.name().as_bytes())
                        .unwrap(),
                    http::header::HeaderValue::from_str(hdr.value()).unwrap(),
                );
            },
        }
    }

    let uri = format!("{}://{}{}", scheme, authority, path);

    *req.method_mut() = method.parse().unwrap();
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = uri.parse::<Uri>().unwrap();

    req
}

fn resp_hdrs_from_qpack(
    decoder: &mut qpack::Decoder, hdr_block: &mut [u8],
) -> http::Response<()> {
    let mut resp: Response<()> = Response::default();

    // TODO: make pseudo header parsing more efficient.
    let mut status = String::new();

    for hdr in decoder.decode(hdr_block).unwrap() {
        match hdr.name() {
            ":status" => {
                status = hdr.value().to_string();
            },
            _ => {
                resp.headers_mut().insert(
                    http::header::HeaderName::from_bytes(hdr.name().as_bytes())
                        .unwrap(),
                    http::header::HeaderValue::from_str(hdr.value()).unwrap(),
                );
            },
        }
    }

    *resp.status_mut() = StatusCode::from_bytes(status.as_bytes()).unwrap();
    *resp.version_mut() = http::Version::HTTP_2;

    resp
}

/// An HTTP/3 configuration.
pub struct Config {
    pub num_placeholders: u64,
    pub max_header_list_size: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Config {
    pub fn new(
        num_placeholders: u64, max_header_list_size: u64,
        qpack_max_table_capacity: u64, qpack_blocked_streams: u64,
    ) -> Result<Config> {
        Ok(Config {
            num_placeholders,
            max_header_list_size,
            qpack_max_table_capacity,
            qpack_blocked_streams,
        })
    }

    pub fn set_num_placeholders(&mut self, num_placeholders: u64) {
        self.num_placeholders = num_placeholders;
    }

    pub fn set_max_header_list_size(&mut self, max_header_list_size: u64) {
        self.max_header_list_size = max_header_list_size;
    }

    pub fn set_qpack_max_table_capacity(
        &mut self, qpack_max_table_capacity: u64,
    ) {
        self.qpack_max_table_capacity = qpack_max_table_capacity;
    }

    pub fn set_qpacked_blocked_streams(&mut self, qpack_blocked_streams: u64) {
        self.qpack_blocked_streams = qpack_blocked_streams;
    }
}

type StreamMap = BTreeMap<u64, stream::Stream>;

pub struct ConnectionSettings {
    pub num_placeholders: Option<u64>,
    pub max_header_list_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
}

pub struct QpackStreams {
    pub encoder_stream_id: Option<u64>,
    pub decoder_stream_id: Option<u64>,
}

/// An HTTP/3 connection.
pub struct Connection {
    is_server: bool,

    highest_request_stream_id: u64,
    highest_uni_stream_id: u64,

    streams: StreamMap,

    local_settings: ConnectionSettings,
    peer_settings: ConnectionSettings,

    control_stream_id: Option<u64>,
    peer_control_stream_id: Option<u64>,

    qpack_encoder: qpack::Encoder,
    qpack_decoder: qpack::Decoder,

    local_qpack_streams: QpackStreams,
    peer_qpack_streams: QpackStreams,
}

impl Connection {
    fn new(config: &Config, is_server: bool) -> Result<Connection> {
        let initial_uni_stream_id = if is_server { 0x3 } else { 0x2 };

        Ok(Connection {
            is_server,

            highest_request_stream_id: 0,
            highest_uni_stream_id: initial_uni_stream_id,

            streams: StreamMap::new(),

            local_settings: ConnectionSettings {
                num_placeholders: Some(config.num_placeholders),
                max_header_list_size: Some(config.max_header_list_size),
                qpack_max_table_capacity: Some(config.qpack_max_table_capacity),
                qpack_blocked_streams: Some(config.qpack_blocked_streams),
            },

            peer_settings: ConnectionSettings {
                num_placeholders: None,
                max_header_list_size: None,
                qpack_max_table_capacity: None,
                qpack_blocked_streams: None,
            },

            control_stream_id: None,
            peer_control_stream_id: None,

            qpack_encoder: qpack::Encoder::new(),
            qpack_decoder: qpack::Decoder::new(),

            local_qpack_streams: QpackStreams {
                encoder_stream_id: None,
                decoder_stream_id: None,
            },
            peer_qpack_streams: QpackStreams {
                encoder_stream_id: None,
                decoder_stream_id: None,
            },
        })
    }

    /// Get a request stream ID if there is one available
    fn get_available_request_stream(&mut self) -> Result<u64> {
        if self.highest_request_stream_id < std::u64::MAX {
            let ret = self.highest_request_stream_id;
            self.highest_request_stream_id += 4;
            return Ok(ret);
        }

        Err(Error::LimitExceeded)
    }

    /// Returns an available stream ID for the local endpoint to use
    fn get_available_uni_stream(&mut self) -> Result<u64> {
        if self.highest_uni_stream_id < std::u64::MAX {
            let ret = self.highest_uni_stream_id;
            self.highest_uni_stream_id += 4;
            return Ok(ret);
        }

        Err(Error::LimitExceeded)
    }

    pub fn is_established(&self) -> bool {
        trace!("is established?: control={} decoder={} encoder={} peer_control={} peer_decoder={} peer_encoder={}",
         self.control_stream_id.is_some(),
         self.local_qpack_streams.encoder_stream_id.is_some(),
            self.local_qpack_streams.decoder_stream_id.is_some(),
            self.peer_control_stream_id.is_some(),
            self.peer_qpack_streams.decoder_stream_id.is_some(),
            self.peer_qpack_streams.encoder_stream_id.is_some(),
        );

        self.control_stream_id.is_some() &&
            self.local_qpack_streams.encoder_stream_id.is_some() &&
            self.local_qpack_streams.decoder_stream_id.is_some() &&
            self.peer_control_stream_id.is_some() &&
            self.peer_qpack_streams.decoder_stream_id.is_some() &&
            self.peer_qpack_streams.encoder_stream_id.is_some()
    }

    pub fn open_control_stream(
        &mut self, quic_conn: &mut super::Connection,
    ) -> Result<()> {
        if self.control_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            quic_conn.stream_send(
                stream_id,
                &stream::HTTP3_CONTROL_STREAM_TYPE_ID.to_be_bytes(),
                false,
            )?;

            self.control_stream_id = Some(stream_id);
        }

        Ok(())
    }

    fn open_qpack_streams(
        &mut self, quic_conn: &mut super::Connection,
    ) -> Result<()> {
        if self.local_qpack_streams.encoder_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            info!("Opening QPACK Encoder stream on id {}", stream_id);
            quic_conn.stream_send(
                stream_id,
                &stream::QPACK_ENCODER_STREAM_TYPE_ID.to_be_bytes(),
                false,
            )?;

            // TODO await ACK of stream open?
            self.local_qpack_streams.encoder_stream_id = Some(stream_id);
        }

        if self.local_qpack_streams.decoder_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            info!("Opening QPACK Decoder stream on id {}", stream_id);
            quic_conn.stream_send(
                stream_id,
                &stream::QPACK_DECODER_STREAM_TYPE_ID.to_be_bytes(),
                false,
            )?;

            // TODO await ACK of stream open?
            self.local_qpack_streams.decoder_stream_id = Some(stream_id);
        }

        Ok(())
    }

    /// Send SETTINGS frame based on HTTP/3 config.
    fn send_settings(&mut self, quic_conn: &mut super::Connection) -> Result<()> {
        self.open_control_stream(quic_conn)?;

        let mut d = [42; 128];

        // Client cannot send placeholders, so validate here
        let num_placeholders = if self.is_server {
            self.local_settings.num_placeholders
        } else {
            None
        };

        let frame = frame::Frame::Settings {
            num_placeholders,
            max_header_list_size: self.local_settings.max_header_list_size,
            qpack_max_table_capacity: self
                .local_settings
                .qpack_max_table_capacity,
            qpack_blocked_streams: self.local_settings.qpack_blocked_streams,
        };

        let mut b = octets::Octets::with_slice(&mut d);

        let frame_size = frame.to_bytes(&mut b).unwrap();
        let off = b.off();
        trace!("Frame size is {} and octet offset is {}", frame_size, off);

        match self.control_stream_id {
            Some(id) => {
                info!("Opening Control stream on id {}", id);
                quic_conn.stream_send(id, &d[..off], false)?;
            },
            None => {
                return Err(Error::InternalError);
            },
        }

        Ok(())
    }

    /// Prepare a request in HTTP/3 wire format, allocate a stream ID and send
    /// it. Request body (if any) is ignored.
    pub fn send_request(
        &mut self, quic_conn: &mut super::Connection,
        request: &http::Request<()>, has_body: bool,
    ) -> Result<(u64)> {
        let mut d = [42; 65535];

        let req_frame = frame::Frame::Headers {
            header_block: req_hdrs_to_qpack(&mut self.qpack_encoder, &request),
        };

        let mut b = octets::Octets::with_slice(&mut d);
        req_frame.to_bytes(&mut b).unwrap();

        let stream_id = self.get_available_request_stream()?;
        self.streams
            .insert(stream_id, stream::Stream::new(stream_id, true));

        let off = b.off();

        trace!(
            "{} sending request of size {} on stream {}",
            quic_conn.trace_id(),
            off,
            stream_id
        );

        if let Err(e) = quic_conn.stream_send(stream_id, &d[..off], !has_body) {
            error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
            return Err(Error::from(e));
        }

        Ok(stream_id)
    }

    /// Prepare a response in HTTP/3 wire format, allocate a stream ID and send
    /// it.
    pub fn send_response(
        &mut self, quic_conn: &mut super::Connection, stream_id: u64,
        response: http::Response<Vec<u8>>,
    ) {
        let mut stream_d = [42; 65535];
        let fin_stream = response.body().is_empty();

        let headers = frame::Frame::Headers {
            header_block: resp_hdrs_to_qpack(&mut self.qpack_encoder, &response),
        };

        let mut stream_b = octets::Octets::with_slice(&mut stream_d);
        headers.to_bytes(&mut stream_b).unwrap();

        let off = stream_b.off();

        trace!(
            "{} sending response HEADERS frame of size {} on stream {}",
            quic_conn.trace_id(),
            off,
            stream_id
        );

        if let Err(e) =
            quic_conn.stream_send(stream_id, &stream_d[..off], fin_stream)
        {
            error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
        }

        let data = frame::Frame::Data {
            payload: response.into_body(),
        };

        // reuse the octets object
        let mut stream_b = octets::Octets::with_slice(&mut stream_d);
        data.to_bytes(&mut stream_b).unwrap();

        let off = stream_b.off();

        info!(
            "{} sending response DATA frame of size {} on stream {}",
            quic_conn.trace_id(),
            off,
            stream_id
        );

        if let Err(e) = quic_conn.stream_send(stream_id, &stream_d[..off], true) {
            error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
        }
    }

    pub fn process(
        &mut self, quic_conn: &mut super::Connection,
    ) -> Result<Event> {
        loop {
            match self.process_transport_streams(quic_conn) {
                Ok(()) => {
                    break;
                },
                Err(Error::Done) => {
                    break;
                },
                Err(Error::BufferTooShort) => {
                    // Keep processing transport stream
                    // trace!("{} feed me", quic_conn.trace_id());
                },

                Err(e) => {
                    error!(
                        "{} process_transport_streams: {:?}",
                        quic_conn.trace_id(),
                        e
                    );
                    return Err(e);
                },
            }
        }

        let event = self.process_http3_streams()?;

        Ok(event)
    }

    /// Read from all readable QUIC streams and assign HTTP/3 meaning
    pub fn process_transport_streams(
        &mut self, quic_conn: &mut super::Connection,
    ) -> Result<()> {
        // Read streams and handle the data on them.
        let streams: Vec<u64> = quic_conn.readable().collect();

        for s in streams {
            debug!("{} stream id {} is readable", quic_conn.trace_id(), s);
            loop {
                match self.handle_stream(quic_conn, s) {
                    Ok(_) => {
                        // TODO
                    },

                    Err(Error::Done) => {
                        debug!(
                            "{} done handling stream id {}",
                            quic_conn.trace_id(),
                            s
                        );
                        break;
                    },

                    Err(Error::BufferTooShort) => {
                        debug!(
                            "{}pub stream id needs feeding {}",
                            quic_conn.trace_id(),
                            s
                        );
                        return Err(Error::BufferTooShort);
                    },

                    Err(e) => {
                        error!(
                            "{} handling stream id {} failed: {:?}",
                            quic_conn.trace_id(),
                            s,
                            e
                        );
                        return Err(e);
                    },
                };
            }
        }

        Ok(())
    }

    pub fn process_http3_streams(&mut self) -> Result<Event> {
        for (stream_id, stream) in self.streams.iter_mut() {
            let frame = stream.get_frame();

            if frame.is_some() {
                match frame.unwrap() {
                    frame::Frame::Settings {
                        num_placeholders,
                        max_header_list_size,
                        qpack_max_table_capacity,
                        qpack_blocked_streams,
                    } => {
                        if self.is_server && num_placeholders.is_some() {
                            error!("SETTINGS frame with placeholders received at server");
                            return Err(Error::WrongSettingDirection);
                        }

                        self.peer_settings = ConnectionSettings {
                            num_placeholders,
                            max_header_list_size,
                            qpack_max_table_capacity,
                            qpack_blocked_streams,
                        };
                    },
                    frame::Frame::Priority { .. } => {
                        debug!("PRIORITY frame received but not doing anything.");
                    },
                    frame::Frame::CancelPush { .. } => {
                        debug!(
                            "CANCEL_PUSH frame received but not doing anything."
                        );
                    },
                    frame::Frame::MaxPushId { .. } => {
                        debug!(
                            "MAX_PUSH_ID frame received but not doing anything."
                        );
                    },
                    frame::Frame::GoAway { .. } => {
                        if self.is_server {
                            error!("GOAWAY frame received at server.");
                            return Err(Error::UnexpectedFrame);
                        }

                        debug!("GOAWAY frame received but not doing anything.");
                    },
                    frame::Frame::Headers { mut header_block } => {
                        if self.is_server {
                            let req = req_hdrs_from_qpack(
                                &mut self.qpack_decoder,
                                &mut header_block[..],
                            );

                            return Ok(Event::OnReqHeaders {
                                stream_id: *stream_id,
                                value: req,
                            });
                        } else {
                            let resp = resp_hdrs_from_qpack(
                                &mut self.qpack_decoder,
                                &mut header_block[..],
                            );

                            return Ok(Event::OnRespHeaders {
                                stream_id: *stream_id,
                                value: resp,
                            });
                        }
                    },
                    frame::Frame::Data { payload } => {
                        debug!("DATA frame received on stream id {}", stream_id);
                        return Ok(Event::OnPayloadData {
                            stream_id: *stream_id,
                            value: payload.to_vec(),
                        });
                    },
                    _ => {
                        // TODO: we should ignore unknown frame types but for now
                        // generate an error and let someone else deal with it.
                        debug!("Unknown frame type received.");
                        return Err(Error::UnexpectedFrame);
                    },
                }
            }
        }

        Err(Error::Done)
    }

    fn handle_stream(
        &mut self, quic_conn: &mut super::Connection, stream_id: u64,
    ) -> Result<()> {
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| stream::Stream::new(stream_id, false));

        trace!("Stream id {} is in {:?} state", stream_id, stream.state());
        // TODO: decide how many bytes we want to pull out of the QUIC stream
        let mut d = vec![0; 124];
        let (read, _fin) = quic_conn.stream_recv(stream_id, &mut d)?;
        debug!(
            "{} received {} bytes on stream {}",
            quic_conn.trace_id(),
            read,
            stream_id
        );
        stream.add_data(&mut d.drain(..read).collect())?;

        while stream.more() {
            match stream.state() {
                stream::State::StreamTypeLen => {
                    // stream.add_data(&mut d.drain(..read).collect())?;

                    // TODO: draft 18 uses 1 byte stream type, so we can double
                    // jump through states
                    let varint_len = 1;
                    // draft 18+ let varint_len =
                    // octets::Octets::varint_parse_len(stream.buf[stream.
                    // buf_read_off])?;
                    stream.set_stream_type_len(varint_len)?;

                    // draft 18+ we don't set the type here, all the following
                    // code should be moved to the next state match
                    // `StreamTypeLen` and checked to make sure it is valid for
                    // true varints
                    let varint_bytes = stream.buf_bytes(varint_len as usize)?;
                    let varint = varint_bytes[0];

                    let ty = stream::Type::deserialize(varint);

                    if ty.is_none() {
                        return Err(Error::UnknownStreamType);
                    }

                    // TODO: consider if we want to set type later, after
                    // validation...
                    stream.set_stream_type(ty)?;

                    match &ty {
                        Some(stream::Type::Control) => {
                            // only one control stream allowed.
                            if self.peer_control_stream_id.is_some() {
                                error!("Peer already opened a control stream!");
                                return Err(Error::WrongStreamCount);
                            }

                            info!("Peer opened a Control stream on id {}.", stream_id);
                            self.peer_control_stream_id = Some(stream_id);
                        },
                        Some(stream::Type::Push) => {
                            // only clients can receive push stream.
                            if self.is_server {
                                error!("Client opened a push stream!");
                                return Err(Error::WrongStreamDirection);
                            }
                        },
                        Some(stream::Type::QpackEncoder) => {
                            // only one qpack encoder stream allowed.
                            if self.peer_qpack_streams.encoder_stream_id.is_some() {
                                error!(
                                    "Peer already opened a QPACK encoder stream!"
                                );
                                return Err(Error::WrongStreamCount);
                            }

                            info!("Peer opened a QPACK encoder stream on id {}.", stream_id);
                            self.peer_qpack_streams.encoder_stream_id = Some(stream_id);

                        },
                        Some(stream::Type::QpackDecoder) => {
                            // only one qpack decoder allowed.
                            if self.peer_qpack_streams.decoder_stream_id.is_some() {
                                error!(
                                    "Peer already opened a QPACK decoder stream!"
                                );
                                return Err(Error::WrongStreamCount);
                            }

                            info!("Peer opened a QPACK decoder stream on id {}.", stream_id);
                            self.peer_qpack_streams.decoder_stream_id = Some(stream_id);

                        },
                        // TODO: enable GREASE streamsget_varint
                        /*Some(stream::Type::Grease) => {
                            // TODO: Grease stream types should be ignored (by
                            // default). Until then, return an error and let
                            // someone else deal with it. Endpoint should
                            // probably avoid reading from the stream at all?
                            error!("Peer opened a GREASE stream type!");
                            return Err(Error::UnknownStreamType);
                        },*/
                        Some(stream::Type::Request) => unreachable!(),
                        None => {
                            // We don't know the type, so we should just ignore
                            // things being sent on this stream. But for now,
                            // return an error and let someone else deal with it.
                            error!("Peer opened an unknown stream type!");
                            return Err(Error::UnknownStreamType);
                        },
                    }
                },
                stream::State::StreamType => {
                    // TODO: populate this in draft 18+
                },
                stream::State::FramePayloadLenLen => {
                    let varint_byte = stream.buf_bytes(1)?[0];
                    stream.set_next_varint_len(octets::varint_parse_len(
                        varint_byte,
                    ))?
                },
                stream::State::FramePayloadLen => {
                    let varint = stream.get_varint()?;
                    stream.set_frame_payload_len(varint)?;
                },
                stream::State::FrameTypeLen => {
                    let varint_byte = stream.buf_bytes(1)?[0];
                    stream.set_next_varint_len(octets::varint_parse_len(
                        varint_byte,
                    ))?
                },
                stream::State::FrameType => {
                    // TODO: draft 18+
                    // let varint = stream.get_varint()?;
                    let varint = stream.get_u8()?;
                    stream.set_frame_type(varint)?;
                },
                stream::State::FramePayload => {
                    stream.parse_frame()?;
                },
                stream::State::QpackInstruction => {
                    info!("QPACK dynamic compression not supported yet.");
                    return Err(Error::Done);
                },
                _ => {
                    // TODO
                },
            }
        }

        Err(Error::Done)
    }
}

/// Creates a new client-side connection.
pub fn connect(
    quic_conn: &mut super::Connection, config: &Config,
) -> Result<Connection> {
    let mut http3_conn = Connection::new(config, false)?;

    http3_conn.send_settings(quic_conn)?;
    http3_conn.open_qpack_streams(quic_conn)?;

    Ok(http3_conn)
}

/// Creates a new server-side connection.
pub fn accept(
    quic_conn: &mut super::Connection, config: &Config,
) -> Result<Connection> {
    let mut http3_conn = Connection::new(config, true)?;

    http3_conn.send_settings(quic_conn)?;
    http3_conn.open_qpack_streams(quic_conn)?;

    Ok(http3_conn)
}

mod frame;
pub mod qpack;
mod stream;
