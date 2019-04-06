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

//! HTTP/3 wire protocol and QPACK implementation.
//!
//! This module provides a high level API for sending and receiving HTTP/3
//! requests and responses on top of the QUIC transport protocol.
//!
//! ## Connection setup
//!
//! HTTP/3 connections require a QUIC transport-layer connection, see
//! [Connection setup] for a full description of the setup process.
//!
//! To use HTTP/3, the QUIC connection must be configured with a suitable
//! Application Layer Protocol Negotiation (ALPN) Protocol ID:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::VERSION_DRAFT19).unwrap();
//! config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL);
//! ```
//!
//! The QUIC handshake is driven by [sending] and [receiving] QUIC packets.
//!
//! Once the handshake has completed, the first step in establishing an HTTP/3
//! connection is creating its configuration object:
//!
//! ```
//! let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();
//! ```
//!
//! HTTP/3 client and server connections are both created using the
//! [`with_transport()`] function, the role is inferred from the type of QUIC
//! connection:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT19).unwrap();
//! # config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
//! # let server_name = "quic.tech";
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();
//! let h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();
//! ```
//!
//! ## Sending a request
//!
//! An HTTP/3 client can send a request by using the connection's
//! [`send_request()`] method to queue request headers; [sending] QUIC packets
//! causes the requests to get sent to the peer:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT19).unwrap();
//! # config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
//! # let server_name = "quic.tech";
//! # let scid = [0xba; 16];
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();
//! # let mut conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();
//! let req = vec![
//!     quiche::h3::Header::new(":method", "GET"),
//!     quiche::h3::Header::new(":scheme", "https"),
//!     quiche::h3::Header::new(":authority", "quic.tech"),
//!     quiche::h3::Header::new(":path", "/"),
//!     quiche::h3::Header::new(":user-agent", "quiche"),
//! ];
//!
//! h3_conn.send_request(&mut conn, &req, true).unwrap();
//! ```
//!
//! An HTTP/3 client can send a request with additional body data by using
//! the connection's [`send_body()`] method:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT19).unwrap();
//! # config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
//! # let server_name = "quic.tech";
//! # let scid = [0xba; 16];
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();
//! # let mut conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();
//! let req = vec![
//!     quiche::h3::Header::new(":method", "GET"),
//!     quiche::h3::Header::new(":scheme", "https"),
//!     quiche::h3::Header::new(":authority", "quic.tech"),
//!     quiche::h3::Header::new(":path", "/"),
//!     quiche::h3::Header::new(":user-agent", "quiche"),
//! ];
//!
//! let stream_id = h3_conn.send_request(&mut conn, &req, false).unwrap();
//! h3_conn.send_body(&mut conn, stream_id, b"Hello World!", true).unwrap();
//! ```
//!
//! ## Handling requests and responses
//!
//! After [receiving] QUIC packets, HTTP/3 data is processed using the
//! connection's [`poll()`] method. On success, this returns an [`Event`] object
//! and an ID corresponding to the stream where the `Event` originated.
//!
//! An HTTP/3 server uses [`poll()`] to read requests and responds to them using
//! [`send_response()`] and [`send_body()`]:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT19).unwrap();
//! # config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
//! # let scid = [0xba; 16];
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn,
//! #                                                       &h3_config).unwrap();
//! loop {
//!     match h3_conn.poll(&mut conn) {
//!         Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
//!             let mut headers = headers.into_iter();
//!
//!             // Look for the request's method.
//!             let method = headers.find(|h| h.name() == ":method").unwrap();
//!
//!             // Look for the request's path.
//!             let path = headers.find(|h| h.name() == ":path").unwrap();
//!
//!             if method.value() == "GET" && path.value() == "/" {
//!                 let resp = vec![
//!                     quiche::h3::Header::new(":status", &200.to_string()),
//!                     quiche::h3::Header::new("server", "quiche"),
//!                 ];
//!
//!                 h3_conn.send_response(&mut conn, stream_id, &resp, false).unwrap();
//!                 h3_conn.send_body(&mut conn, stream_id, b"Hello World!", true).unwrap();
//!             }
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Data(data))) => {
//!             // Request body data, handle it.
//!             # return;
//!         },
//!
//!         Err(quiche::h3::Error::Done) => {
//!             // Done reading.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     }
//! }
//! ```
//!
//! An HTTP/3 client uses [`poll()`] to read responses:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT19).unwrap();
//! # config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
//! # let server_name = "quic.tech";
//! # let scid = [0xba; 16];
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0).unwrap();
//! # let mut conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn,
//! #                                                       &h3_config).unwrap();
//! loop {
//!     match h3_conn.poll(&mut conn) {
//!         Ok((stream_id, quiche::h3::Event::Headers(headers))) => {
//!             let status = headers.iter().find(|h| h.name() == ":status").unwrap();
//!             println!("Received {} response on stream {}",
//!                      status.value(), stream_id);
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Data(data))) => {
//!             println!("Received {} bytes of payload on stream {}",
//!                      data.len(), stream_id);
//!         },
//!
//!         Err(quiche::h3::Error::Done) => {
//!             // Done reading.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     }
//! }
//! ```
//!
//! ## Detecting end of stream
//!
//! HTTP/3 request and response exchanges may consist of several HEADERS and
//! DATA frames. Calling [`poll()`] repeatedly will generate an [`Event`] for
//! each. The QUIC connection's [`stream_finished()`] method can be used to
//! detect if the stream was ended by the peer. Additional HTTP/3 validation
//! can be applied by the application to ensure protocol correctness.
//!
//! [`application_proto()`]: ../struct.Connection.html#method.application_proto
//! [`stream_finished()`]: ../struct.Connection.html#method.stream_finished
//! [Connection setup]: ../index.html#connection-setup
//! [sending]: ../index.html#generating-outgoing-packets
//! [receiving]: ../index.html#handling-incoming-packets
//! [`with_transport()`]: struct.Connection.html#method.with_transport
//! [`poll()`]: struct.Connection.html#method.poll
//! [`Event`]: enum.Event.html
//! [`send_request()`]: struct.Connection.html#method.send_response
//! [`send_response()`]: struct.Connection.html#method.send_response
//! [`send_body()`]: struct.Connection.html#method.send_body

use std::collections::BTreeMap;

use crate::octets;

/// The current HTTP/3 ALPN token.
pub const APPLICATION_PROTOCOL: &[u8] = b"\x05h3-18";

/// A specialized [`Result`] type for quiche HTTP/3 operations.
///
/// This type is used throughout quiche's HTTP/3 public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// An HTTP/3 error.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum Error {
    /// There is no error or no work to do
    Done                 = -1,

    /// The provided buffer is too short.
    BufferTooShort       = -2,

    /// Setting sent in wrong direction.
    WrongSettingDirection = -3,

    /// The server attempted to push content that the client will not accept.
    PushRefused          = -4,

    /// Internal error in the HTTP/3 stack.
    InternalError        = -5,

    /// The server attempted to push something the client already has.
    PushAlreadyInCache   = -6,

    /// The client no longer needs the requested data.
    RequestCancelled     = -7,

    /// The request stream terminated before completing the request.
    IncompleteRequest    = -8,

    /// Forward connection failure for CONNECT target.
    ConnectError         = -9,

    /// Endpoint detected that the peer is exhibiting behavior that causes.
    /// excessive load.
    ExcessiveLoad        = -10,

    /// Operation cannot be served over HTTP/3. Retry over HTTP/1.1.
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

    /// No SETTINGS frame at beginning of control stream.
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

    fn to_c(self) -> libc::ssize_t {
        self as _
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        // TODO: fill this
        ""
    }

    fn cause(&self) -> Option<&std::error::Error> {
        None
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

/// An HTTP/3 configuration.
pub struct Config {
    num_placeholders: u64,
    max_header_list_size: u64,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
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
}

/// A name-value pair representing a raw HTTP header.
#[derive(Clone, Debug, PartialEq)]
pub struct Header(String, String);

impl Header {
    /// Creates a new header.
    pub fn new(name: &str, value: &str) -> Header {
        Header(String::from(name), String::from(value))
    }

    /// Returns the header's name.
    pub fn name(&self) -> &str {
        &self.0
    }

    /// Returns the header's value.
    pub fn value(&self) -> &str {
        &self.1
    }
}

/// An HTTP/3 connection event.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Request/response headers were received.
    Headers(Vec<Header>),

    /// Data was received.
    Data(Vec<u8>),
}

struct ConnectionSettings {
    pub num_placeholders: Option<u64>,
    pub max_header_list_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
}

struct QpackStreams {
    pub encoder_stream_id: Option<u64>,
    pub decoder_stream_id: Option<u64>,
}

/// An HTTP/3 connection.
pub struct Connection {
    is_server: bool,

    highest_request_stream_id: u64,
    highest_uni_stream_id: u64,

    streams: BTreeMap<u64, stream::Stream>,

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

            streams: BTreeMap::new(),

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

    /// Creates a new HTTP/3 connection using the provided QUIC connection.
    ///
    /// This will also initiate the HTTP/3 handshake with the peer by opening
    /// all control streams (including QPACK) and sending the local settings.
    pub fn with_transport(
        conn: &mut super::Connection, config: &Config,
    ) -> Result<Connection> {
        let mut http3_conn = Connection::new(config, conn.is_server)?;

        http3_conn.send_settings(conn)?;
        http3_conn.open_qpack_streams(conn)?;

        Ok(http3_conn)
    }

    /// Sends an HTTP/3 request.
    ///
    /// The request is encoded from the provided list of headers, and sent on
    /// a newly allocated stream.
    ///
    /// On success the newly allocated stream ID is returned.
    pub fn send_request(
        &mut self, conn: &mut super::Connection, headers: &[Header], fin: bool,
    ) -> Result<u64> {
        let stream_id = self.get_available_request_stream()?;
        self.streams
            .insert(stream_id, stream::Stream::new(stream_id, true));

        self.send_headers(conn, stream_id, headers, fin)?;

        Ok(stream_id)
    }

    /// Sends an HTTP/3 response on the specified stream.
    pub fn send_response(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        headers: &[Header], fin: bool,
    ) -> Result<()> {
        self.send_headers(conn, stream_id, headers, fin)?;

        Ok(())
    }

    fn send_headers(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        headers: &[Header], fin: bool,
    ) -> Result<()> {
        let mut d = [42; 10];

        let headers_len = headers
            .iter()
            .fold(0, |acc, h| acc + h.value().len() + h.name().len() + 32);
        let mut header_block = vec![0; headers_len];
        let len = self
            .qpack_encoder
            .encode(&headers, &mut header_block)
            .map_err(|_| Error::InternalError)?;
        header_block.truncate(len);

        let mut b = octets::Octets::with_slice(&mut d);
        b.put_varint(len as u64)?;
        b.put_u8(frame::HEADERS_FRAME_TYPE_ID)?;

        let off = b.off();

        if conn.grease {
            self.send_grease_frames(conn, stream_id)?;
        }

        trace!(
            "{} sending HEADERS of size {} on stream {}",
            conn.trace_id(),
            off + len,
            stream_id
        );

        conn.stream_send(stream_id, &d[..off], fin)?;

        conn.stream_send(stream_id, &header_block, fin)?;

        Ok(())
    }

    /// Sends an HTTP/3 body chunk on the given stream.
    ///
    /// On success the number of bytes written is returned.
    pub fn send_body(
        &mut self, conn: &mut super::Connection, stream_id: u64, body: &[u8],
        fin: bool,
    ) -> Result<usize> {
        let mut d = [42; 10];

        let mut b = octets::Octets::with_slice(&mut d);
        b.put_varint(body.len() as u64)?;
        b.put_u8(frame::DATA_FRAME_TYPE_ID)?;

        let off = b.off();

        trace!(
            "{} sending DATA frame of size {} on stream {}",
            conn.trace_id(),
            off + body.len(),
            stream_id
        );

        conn.stream_send(stream_id, &d[..off], false)?;

        // Return how many bytes were written, excluding the frame header.
        let written = conn.stream_send(stream_id, body, fin)?;

        Ok(written)
    }

    /// Processes HTTP/3 data received from the peer.
    ///
    /// On success it returns an [`Event`] as well as the event's source stream
    /// ID. The stream ID can be used when calling [`send_response()`] and
    /// [`send_body()`] when responding to incoming requests.
    ///
    /// [`Event`]: enum.Event.html
    /// [`send_response()`]: struct.Connection.html#method.send_response
    /// [`send_body()`]: struct.Connection.html#method.send_body
    pub fn poll(&mut self, conn: &mut super::Connection) -> Result<(u64, Event)> {
        let streams: Vec<u64> = conn.readable().collect();

        // Process HTTP/3 data from readable streams.
        for s in streams {
            trace!("{} stream id {} is readable", conn.trace_id(), s);

            loop {
                match self.handle_stream(conn, s) {
                    Ok(_) => break,

                    Err(Error::Done) => break,

                    Err(Error::BufferTooShort) => {
                        // Keep processing transport stream.
                    },

                    Err(e) => return Err(e),
                };
            }
        }

        for (stream_id, stream) in self.streams.iter_mut() {
            if let Some(frame) = stream.get_frame() {
                trace!("{} rx frm {:?}", conn.trace_id(), frame);

                match frame {
                    frame::Frame::Settings {
                        num_placeholders,
                        max_header_list_size,
                        qpack_max_table_capacity,
                        qpack_blocked_streams,
                    } => {
                        if self.is_server && num_placeholders.is_some() {
                            return Err(Error::WrongSettingDirection);
                        }

                        self.peer_settings = ConnectionSettings {
                            num_placeholders,
                            max_header_list_size,
                            qpack_max_table_capacity,
                            qpack_blocked_streams,
                        };
                    },

                    frame::Frame::Headers { mut header_block } => {
                        let headers = self
                            .qpack_decoder
                            .decode(&mut header_block[..])
                            .map_err(|_| Error::QpackDecompressionFailed)?;
                        return Ok((*stream_id, Event::Headers(headers)));
                    },

                    frame::Frame::Data { payload } => {
                        return Ok((*stream_id, Event::Data(payload)));
                    },

                    // TODO: implement GOAWAY
                    frame::Frame::GoAway { .. } => {},
                    // TODO: implement MAX_PUSH_ID
                    frame::Frame::MaxPushId { .. } => {},
                    // TODO: implement PUSH_PROMISE
                    frame::Frame::PushPromise { .. } => {},
                    // TODO: implement DUPLICATE_PUSH
                    frame::Frame::DuplicatePush { .. } => {},
                    // TODO: implement CANCEL_PUSH frame
                    frame::Frame::CancelPush { .. } => {},
                }
            }
        }

        Err(Error::Done)
    }

    /// Allocates a new request stream ID for the local endpoint to use.
    fn get_available_request_stream(&mut self) -> Result<u64> {
        if self.highest_request_stream_id < std::u64::MAX {
            let ret = self.highest_request_stream_id;
            self.highest_request_stream_id += 4;
            return Ok(ret);
        }

        Err(Error::LimitExceeded)
    }

    /// Allocates a new unidirectional stream ID for the local endpoint to use.
    fn get_available_uni_stream(&mut self) -> Result<u64> {
        if self.highest_uni_stream_id < std::u64::MAX {
            let ret = self.highest_uni_stream_id;
            self.highest_uni_stream_id += 4;
            return Ok(ret);
        }

        Err(Error::LimitExceeded)
    }

    /// Opens HTTP/3 control stream, if not already opened.
    fn open_control_stream(
        &mut self, conn: &mut super::Connection,
    ) -> Result<()> {
        if self.control_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            conn.stream_send(
                stream_id,
                &stream::HTTP3_CONTROL_STREAM_TYPE_ID.to_be_bytes(),
                false,
            )?;

            self.control_stream_id = Some(stream_id);
        }

        Ok(())
    }

    /// Opens QPACK encoder and decoder streams, if not already opened.
    fn open_qpack_streams(&mut self, conn: &mut super::Connection) -> Result<()> {
        if self.local_qpack_streams.encoder_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            conn.stream_send(
                stream_id,
                &stream::QPACK_ENCODER_STREAM_TYPE_ID.to_be_bytes(),
                false,
            )?;

            self.local_qpack_streams.encoder_stream_id = Some(stream_id);
        }

        if self.local_qpack_streams.decoder_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            conn.stream_send(
                stream_id,
                &stream::QPACK_DECODER_STREAM_TYPE_ID.to_be_bytes(),
                false,
            )?;

            self.local_qpack_streams.decoder_stream_id = Some(stream_id);
        }

        Ok(())
    }

    /// Send GREASE frames on the provided stream ID.
    fn send_grease_frames(
        &mut self, conn: &mut super::Connection, stream_id: u64,
    ) -> Result<()> {
        let mut d = [42; 128];

        let mut b = octets::Octets::with_slice(&mut d);

        // Empty GREASE frame.
        b.put_varint(0)?;
        b.put_u8(0xb)?;

        // GREASE frame with payload.
        b.put_varint(18)?;
        b.put_u8(0x2a)?;

        trace!(
            "{} sending GREASE frames on stream {}",
            conn.trace_id(),
            stream_id
        );

        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;

        conn.stream_send(stream_id, b"GREASE is the word", false)?;

        Ok(())
    }

    /// Sends SETTINGS frame based on HTTP/3 configuration.
    fn send_settings(&mut self, conn: &mut super::Connection) -> Result<()> {
        let mut d = [42; 128];

        self.open_control_stream(conn)?;

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

        frame.to_bytes(&mut b)?;

        let off = b.off();

        if let Some(id) = self.control_stream_id {
            conn.stream_send(id, &d[..off], false)?;
        }

        Ok(())
    }

    fn handle_stream(
        &mut self, conn: &mut super::Connection, stream_id: u64,
    ) -> Result<()> {
        let mut d = [0; 32768];

        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| stream::Stream::new(stream_id, false));

        let (read, _fin) = conn.stream_recv(stream_id, &mut d)?;
        stream.push(&d[..read])?;

        trace!(
            "{} read {} bytes on stream {}",
            conn.trace_id(),
            read,
            stream_id
        );

        while stream.more() {
            match stream.state() {
                stream::State::StreamTypeLen => {
                    let varint_len = 1;

                    stream.set_stream_type_len(varint_len)?;

                    let varint_bytes = stream.buf_bytes(varint_len as usize)?;
                    let varint = varint_bytes[0];

                    let ty = stream::Type::deserialize(varint)?;

                    stream.set_stream_type(ty)?;

                    match &ty {
                        stream::Type::Control => {
                            // Only one control stream allowed.
                            if self.peer_control_stream_id.is_some() {
                                return Err(Error::WrongStreamCount);
                            }

                            trace!(
                                "{} peer's control stream: {}",
                                conn.trace_id(),
                                stream_id
                            );

                            self.peer_control_stream_id = Some(stream_id);
                        },

                        stream::Type::Push => {
                            // Only clients can receive push stream.
                            if self.is_server {
                                return Err(Error::WrongStreamDirection);
                            }
                        },

                        stream::Type::QpackEncoder => {
                            // Only one qpack encoder stream allowed.
                            if self.peer_qpack_streams.encoder_stream_id.is_some()
                            {
                                return Err(Error::WrongStreamCount);
                            }

                            self.peer_qpack_streams.encoder_stream_id =
                                Some(stream_id);
                        },

                        stream::Type::QpackDecoder => {
                            // Only one qpack decoder allowed.
                            if self.peer_qpack_streams.decoder_stream_id.is_some()
                            {
                                return Err(Error::WrongStreamCount);
                            }

                            self.peer_qpack_streams.decoder_stream_id =
                                Some(stream_id);
                        },

                        // TODO: enable GREASE streamsget_varint
                        stream::Type::Request => unreachable!(),
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
                    let varint = stream.get_u8()?;
                    stream.set_frame_type(varint)?;
                },

                stream::State::FramePayload => {
                    stream.parse_frame()?;
                },

                stream::State::QpackInstruction => {
                    return Err(Error::Done);
                },

                _ => (),
            }
        }

        Err(Error::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing;

    #[test]
    fn simple_request() {
        let mut buf = [0; 65535];

        let mut config = crate::Config::new(crate::VERSION_DRAFT19).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(b"\x02h3").unwrap();
        config.set_initial_max_data(150);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let config = Config::new(0, 1024, 0, 0).unwrap();

        let mut h3_cln =
            Connection::with_transport(&mut pipe.client, &config).unwrap();
        let mut h3_srv =
            Connection::with_transport(&mut pipe.server, &config).unwrap();

        pipe.advance(&mut buf).ok();

        let req = [
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
            Header::new("user-agent", "quiche-test"),
        ];

        let stream = h3_cln.send_request(&mut pipe.client, &req, true).unwrap();
        assert_eq!(stream, 0);

        pipe.advance(&mut buf).ok();

        let ev = h3_srv.poll(&mut pipe.server).unwrap();
        assert_eq!(ev, (stream, Event::Headers(req.to_vec())));

        let resp = [
            Header::new(":status", "200"),
            Header::new("server", "quiche-test"),
        ];

        h3_srv
            .send_response(&mut pipe.server, stream, &resp, true)
            .unwrap();

        pipe.advance(&mut buf).ok();

        let ev = h3_cln.poll(&mut pipe.client).unwrap();
        assert_eq!(ev, (stream, Event::Headers(resp.to_vec())));
    }
}

mod ffi;
mod frame;
#[doc(hidden)]
pub mod qpack;
mod stream;
