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
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The QUIC handshake is driven by [sending] and [receiving] QUIC packets.
//!
//! Once the handshake has completed, the first step in establishing an HTTP/3
//! connection is creating its configuration object:
//!
//! ```
//! let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! HTTP/3 client and server connections are both created using the
//! [`with_transport()`] function, the role is inferred from the type of QUIC
//! connection:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! let h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Sending a request
//!
//! An HTTP/3 client can send a request by using the connection's
//! [`send_request()`] method to queue request headers; [sending] QUIC packets
//! causes the requests to get sent to the peer:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let req = vec![
//!     quiche::h3::Header::new(":method", "GET"),
//!     quiche::h3::Header::new(":scheme", "https"),
//!     quiche::h3::Header::new(":authority", "quic.tech"),
//!     quiche::h3::Header::new(":path", "/"),
//!     quiche::h3::Header::new(":user-agent", "quiche"),
//! ];
//!
//! h3_conn.send_request(&mut conn, &req, true)?;
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! An HTTP/3 client can send a request with additional body data by using
//! the connection's [`send_body()`] method:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let req = vec![
//!     quiche::h3::Header::new(":method", "GET"),
//!     quiche::h3::Header::new(":scheme", "https"),
//!     quiche::h3::Header::new(":authority", "quic.tech"),
//!     quiche::h3::Header::new(":path", "/"),
//!     quiche::h3::Header::new(":user-agent", "quiche"),
//! ];
//!
//! let stream_id = h3_conn.send_request(&mut conn, &req, false)?;
//! h3_conn.send_body(&mut conn, stream_id, b"Hello World!", true)?;
//! # Ok::<(), quiche::h3::Error>(())
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
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
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
//!                 h3_conn.send_response(&mut conn, stream_id, &resp, false)?;
//!                 h3_conn.send_body(&mut conn, stream_id, b"Hello World!", true)?;
//!             }
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Data(data))) => {
//!             // Request body data, handle it.
//!             # return Ok(());
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Finished)) => {
//!             // Peer terminated stream, handle it.
//!         }
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
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! An HTTP/3 client uses [`poll()`] to read responses:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::connect(None, &scid, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new(0, 1024, 0, 0)?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
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
//!         Ok((stream_id, quiche::h3::Event::Finished)) => {
//!             // Peer terminated stream, handle it.
//!         }
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
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Detecting end of request or response
//!
//! A single HTTP/3 request or response may consist of several HEADERS and DATA
//! frames; it is finished when the QUIC stream is closed. Calling [`poll()`]
//! repeatedly will generate an [`Event`] for each of these. The application may
//! use these event to do additional HTTP semantic validation.
//!
//! ## HTTP/3 protocol errors
//!
//! Quiche is responsible for managing the HTTP/3 connection, ensuring it is in
//! a correct state and validating all messages received by a peer. This mainly
//! takes place in the [`poll()`] method. If an HTTP/3 error occurs, quiche will
//! close the connection and send an appropriate CONNECTION_CLOSE frame to the
//! peer. An [`Error`] is returned to the application so that it can perform any
//! required tidy up such as closing sockets.
//!
//! [`application_proto()`]: ../struct.Connection.html#method.application_proto
//! [`stream_finished()`]: ../struct.Connection.html#method.stream_finished
//! [Connection setup]: ../index.html#connection-setup
//! [sending]: ../index.html#generating-outgoing-packets
//! [receiving]: ../index.html#handling-incoming-packets
//! [`with_transport()`]: struct.Connection.html#method.with_transport
//! [`poll()`]: struct.Connection.html#method.poll
//! [`Event`]: enum.Event.html
//! [`Error`]: enum.Error.html
//! [`send_request()`]: struct.Connection.html#method.send_response
//! [`send_response()`]: struct.Connection.html#method.send_response
//! [`send_body()`]: struct.Connection.html#method.send_body

use std::collections::BTreeMap;

use crate::octets;

/// The current HTTP/3 ALPN token.
pub const APPLICATION_PROTOCOL: &[u8] = b"\x05h3-20";

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

    /// Error originated from the transport layer.
    TransportError       = -28,
}

impl Error {
    fn to_wire(self) -> u16 {
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

            Error::QpackDecompressionFailed => 0x200,
            Error::QpackEncoderStreamError => 0x201,
            Error::QpackDecoderStreamError => 0x202,
            Error::BufferTooShort => 0x999,

            Error::TransportError => 0xFF,
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

            _ => Error::TransportError,
        }
    }
}

impl std::convert::From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
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
    /// Creates a new configuration object with the specified parameters.
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
    ///
    /// Both `name` and `value` will be cloned, and `name` will also be
    /// converted into lower-case.
    pub fn new(name: &str, value: &str) -> Header {
        Header(name.to_lowercase(), String::from(value))
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

    /// Stream was closed,
    Finished,
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

    max_push_id: u64,
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

            max_push_id: 0,
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

        // Try opening QPACK streams, but ignore errors if it fails since we
        // don't need them right now.
        http3_conn.open_qpack_encoder_stream(conn).ok();
        http3_conn.open_qpack_decoder_stream(conn).ok();

        if conn.grease {
            // Try opening a GREASE stream, but ignore errors since it's not
            // critical.
            http3_conn.open_grease_stream(conn).ok();
        }

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

    fn encode_header_block(&mut self, headers: &[Header]) -> Result<Vec<u8>> {
        let headers_len = headers
            .iter()
            .fold(0, |acc, h| acc + h.value().len() + h.name().len() + 32);

        let mut header_block = vec![0; headers_len];
        let len = self
            .qpack_encoder
            .encode(&headers, &mut header_block)
            .map_err(|_| Error::InternalError)?;

        header_block.truncate(len);

        Ok(header_block)
    }

    fn send_headers(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        headers: &[Header], fin: bool,
    ) -> Result<()> {
        let mut d = [42; 10];
        let mut b = octets::Octets::with_slice(&mut d);

        let header_block = self.encode_header_block(headers)?;

        if conn.grease {
            self.send_grease_frames(conn, stream_id)?;
        }

        trace!(
            "{} sending HEADERS of size {} on stream {}",
            conn.trace_id(),
            header_block.len(),
            stream_id
        );

        conn.stream_send(
            stream_id,
            b.put_varint(frame::HEADERS_FRAME_TYPE_ID)?,
            false,
        )?;

        conn.stream_send(
            stream_id,
            b.put_varint(header_block.len() as u64)?,
            false,
        )?;
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

        // Validate that it is sane to send data on the stream.
        if !self.streams.contains_key(&stream_id) || stream_id % 4 != 0 {
            return Err(Error::WrongStream);
        }

        trace!(
            "{} sending DATA frame of size {} on stream {}",
            conn.trace_id(),
            body.len(),
            stream_id
        );

        conn.stream_send(
            stream_id,
            b.put_varint(frame::DATA_FRAME_TYPE_ID)?,
            false,
        )?;

        conn.stream_send(stream_id, b.put_varint(body.len() as u64)?, false)?;

        // Return how many bytes were written, excluding the frame header.
        let written = conn.stream_send(stream_id, body, fin)?;

        // Tidy up streams.
        if fin &&
            self.streams
                .get(&stream_id)
                .filter(|s| s.peer_fin())
                .is_some()
        {
            self.streams.remove(&stream_id);
        };

        Ok(written)
    }

    /// Processes HTTP/3 data received from the peer.
    ///
    /// On success it returns an [`Event`] as well as the event's source stream
    /// ID. The stream ID can be used when calling [`send_response()`] and
    /// [`send_body()`] when responding to incoming requests. On error the
    /// connection will be closed by calling [`close()`] with the appropriate
    /// error code.
    ///
    /// [`Event`]: enum.Event.html
    /// [`send_response()`]: struct.Connection.html#method.send_response
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`close()`]: ../struct.Connection.html#method.close
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

        for (stream_id, stream) in
            self.streams.iter_mut().filter(|s| !s.1.peer_fin())
        {
            if let Some(frame) = stream.get_frame() {
                trace!(
                    "{} rx frm {:?} on stream {}",
                    conn.trace_id(),
                    frame,
                    stream_id
                );

                match frame {
                    frame::Frame::Settings {
                        num_placeholders,
                        max_header_list_size,
                        qpack_max_table_capacity,
                        qpack_blocked_streams,
                        ..
                    } => {
                        if self.is_server && num_placeholders.is_some() {
                            conn.close(
                                true,
                                Error::WrongSettingDirection.to_wire(),
                                b"Num placeholder setting received by server.",
                            )?;

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
                        if Some(*stream_id) == self.peer_control_stream_id {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"HEADERS received on control stream",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        let headers = self
                            .qpack_decoder
                            .decode(&mut header_block[..])
                            .map_err(|_| Error::QpackDecompressionFailed)?;
                        return Ok((*stream_id, Event::Headers(headers)));
                    },

                    frame::Frame::Data { payload } => {
                        if Some(*stream_id) == self.peer_control_stream_id {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"DATA received on control stream",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        return Ok((*stream_id, Event::Data(payload)));
                    },

                    frame::Frame::GoAway {
                        stream_id: goaway_stream_id,
                    } => {
                        if self.is_server {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"GOWAY received on server",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        if Some(*stream_id) != self.peer_control_stream_id {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"GOAWAY received on non-control stream",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        if goaway_stream_id % 4 != 0 {
                            conn.close(
                                true,
                                Error::WrongStream.to_wire(),
                                b"GOAWAY received with ID of non-request stream",
                            )?;

                            return Err(Error::WrongStream);
                        }

                        // TODO: implement GOAWAY
                    },

                    frame::Frame::MaxPushId { push_id } => {
                        if Some(*stream_id) != self.peer_control_stream_id {
                            conn.close(
                                true,
                                Error::WrongStream.to_wire(),
                                b"MAX_PUSH_ID received on non-control stream",
                            )?;

                            return Err(Error::WrongStream);
                        }

                        if !self.is_server {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"MAX_PUSH_ID received by client",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        // The spec says this lower limit elicits an
                        // HTTP_MALFORMED_FRAME error. It's a non-sensical
                        // error because at this point we already parsed the
                        // frame just fine. Therefore, just send a
                        // HTTP_GENERAL_PROTOCOL_ERROR.
                        if push_id < self.max_push_id {
                            conn.close(
                                true,
                                Error::GeneralProtocolError.to_wire(),
                                b"MAX_PUSH_ID reduced limit",
                            )?;

                            return Err(Error::GeneralProtocolError);
                        }

                        self.max_push_id = push_id;
                    },

                    frame::Frame::PushPromise { .. } => {
                        if self.is_server {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"PUSH_PROMISE received by server",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        if stream_id % 4 != 0 {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"PUSH_PROMISE received on non-request stream",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        // TODO: implement more checks and PUSH_PROMISE event
                    },

                    frame::Frame::DuplicatePush { .. } => {
                        if self.is_server {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"DUPLICATE_PUSH received by server",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        if stream_id % 4 != 0 {
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                b"DUPLICATE_PUSH received on non-request stream",
                            )?;

                            return Err(Error::UnexpectedFrame);
                        }

                        // TODO: implement DUPLICATE_PUSH
                    },

                    frame::Frame::CancelPush { .. } => {
                        if Some(*stream_id) != self.peer_control_stream_id {
                            conn.close(
                                true,
                                Error::WrongStream.to_wire(),
                                b"CANCEL_PUSH received on non-control stream",
                            )?;

                            return Err(Error::WrongStream);
                        }

                        // TODO: implement CANCEL_PUSH frame
                    },
                }
            }

            if conn.stream_finished(*stream_id) {
                // Only fin the stream and generate events once.
                if !stream.peer_fin() {
                    stream.set_peer_fin(true);

                    match stream.ty() {
                        Some(stream::Type::Control) |
                        Some(stream::Type::QpackEncoder) |
                        Some(stream::Type::QpackDecoder) => {
                            conn.close(
                                true,
                                Error::ClosedCriticalStream.to_wire(),
                                b"Critical stream closed.",
                            )?;

                            return Err(Error::ClosedCriticalStream);
                        },

                        _ => (),
                    }

                    return Ok((*stream_id, Event::Finished));
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

    fn open_uni_stream(
        &mut self, conn: &mut super::Connection, ty: u64,
    ) -> Result<u64> {
        let stream_id = self.get_available_uni_stream()?;

        let mut d = [0; 8];
        let mut b = octets::Octets::with_slice(&mut d);

        conn.stream_send(stream_id, b.put_varint(ty)?, false)?;

        Ok(stream_id)
    }

    fn open_qpack_encoder_stream(
        &mut self, conn: &mut super::Connection,
    ) -> Result<()> {
        self.local_qpack_streams.encoder_stream_id = Some(
            self.open_uni_stream(conn, stream::QPACK_ENCODER_STREAM_TYPE_ID)?,
        );

        Ok(())
    }

    fn open_qpack_decoder_stream(
        &mut self, conn: &mut super::Connection,
    ) -> Result<()> {
        self.local_qpack_streams.decoder_stream_id = Some(
            self.open_uni_stream(conn, stream::QPACK_DECODER_STREAM_TYPE_ID)?,
        );

        Ok(())
    }

    /// Send GREASE frames on the provided stream ID.
    fn send_grease_frames(
        &mut self, conn: &mut super::Connection, stream_id: u64,
    ) -> Result<()> {
        let mut d = [42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        trace!(
            "{} sending GREASE frames on stream id {}",
            conn.trace_id(),
            stream_id
        );

        // Empty GREASE frame.
        conn.stream_send(stream_id, b.put_varint(grease_value())?, false)?;
        conn.stream_send(stream_id, b.put_varint(0)?, false)?;

        // GREASE frame with payload.
        conn.stream_send(stream_id, b.put_varint(grease_value())?, false)?;
        conn.stream_send(stream_id, b.put_varint(18)?, false)?;

        conn.stream_send(stream_id, b"GREASE is the word", false)?;

        Ok(())
    }

    /// Opens a new unidirectional stream with a GREASE type and sends some
    /// unframed payload.
    fn open_grease_stream(&mut self, conn: &mut super::Connection) -> Result<()> {
        match self.open_uni_stream(conn, grease_value()) {
            Ok(stream_id) => {
                trace!(
                    "{} sending GREASE stream on stream id {}",
                    conn.trace_id(),
                    stream_id
                );

                conn.stream_send(stream_id, b"GREASE is the word", false)?;
            },

            Err(Error::LimitExceeded) => {
                trace!("{} sending GREASE stream was blocked", conn.trace_id(),);

                return Ok(());
            },

            Err(e) => return Err(e),
        };

        Ok(())
    }

    /// Sends SETTINGS frame based on HTTP/3 configuration.
    fn send_settings(&mut self, conn: &mut super::Connection) -> Result<()> {
        self.control_stream_id = Some(
            self.open_uni_stream(conn, stream::HTTP3_CONTROL_STREAM_TYPE_ID)?,
        );

        // Client cannot send placeholders, so validate here
        let num_placeholders = if self.is_server {
            self.local_settings.num_placeholders
        } else {
            None
        };

        let grease = if conn.grease {
            Some((grease_value(), grease_value()))
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
            grease,
        };

        let mut d = [42; 128];
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
                    let varint_byte = stream.buf_bytes(1)?[0];
                    stream.set_next_varint_len(octets::varint_parse_len(
                        varint_byte,
                    ))?;
                },

                stream::State::StreamType => {
                    let varint = stream.get_varint()?;

                    let ty = stream::Type::deserialize(varint)?;

                    stream.set_ty(ty)?;

                    match &ty {
                        stream::Type::Control => {
                            // Only one control stream allowed.
                            if self.peer_control_stream_id.is_some() {
                                conn.close(
                                    true,
                                    Error::WrongStreamCount.to_wire(),
                                    b"Received multiple control streams",
                                )?;

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
                                conn.close(
                                    true,
                                    Error::WrongStreamDirection.to_wire(),
                                    b"Server received push stream.",
                                )?;

                                return Err(Error::WrongStreamDirection);
                            }
                        },

                        stream::Type::QpackEncoder => {
                            // Only one qpack encoder stream allowed.
                            if self.peer_qpack_streams.encoder_stream_id.is_some()
                            {
                                conn.close(
                                    true,
                                    Error::WrongStreamCount.to_wire(),
                                    b"Received multiple QPACK encoder streams",
                                )?;

                                return Err(Error::WrongStreamCount);
                            }

                            self.peer_qpack_streams.encoder_stream_id =
                                Some(stream_id);
                        },

                        stream::Type::QpackDecoder => {
                            // Only one qpack decoder allowed.
                            if self.peer_qpack_streams.decoder_stream_id.is_some()
                            {
                                conn.close(
                                    true,
                                    Error::WrongStreamCount.to_wire(),
                                    b"Received multiple QPACK decoder streams",
                                )?;

                                return Err(Error::WrongStreamCount);
                            }

                            self.peer_qpack_streams.decoder_stream_id =
                                Some(stream_id);
                        },

                        stream::Type::Unknown => {
                            // Unknown stream types are ignored.
                            // TODO: we MAY send STOP_SENDING
                        },

                        stream::Type::Request => unreachable!(),
                    }
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
                    let varint = stream.get_varint()?;
                    match stream.set_frame_type(varint) {
                        Err(Error::UnexpectedFrame) => {
                            let msg = format!("Unexpected frame type {}", varint);
                            conn.close(
                                true,
                                Error::UnexpectedFrame.to_wire(),
                                msg.as_bytes(),
                            )?;
                            return Err(Error::UnexpectedFrame);
                        },

                        Err(e) => {
                            conn.close(
                                true,
                                e.to_wire(),
                                b"Error handling frame.",
                            )?;
                            return Err(e);
                        },

                        _ => (),
                    }
                },

                stream::State::FramePayload => {
                    if let Err(e) = stream.parse_frame() {
                        match e {
                            Error::BufferTooShort => (),

                            _ => conn.close(
                                true,
                                e.to_wire(),
                                b"Error handling frame.",
                            )?,
                        };

                        return Err(e);
                    }
                },

                stream::State::QpackInstruction => return Err(Error::Done),

                stream::State::Done => return Err(Error::Done),

                _ => (),
            }
        }

        Err(Error::Done)
    }
}

/// Generates an HTTP/3 GREASE variable length integer.
fn grease_value() -> u64 {
    let n = std::cmp::min(super::rand::rand_u64(), 148_764_065_110_560_899);
    31 * n + 33
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing;

    /// Session is an HTTP/3 test helper structure. It holds a client, server
    /// and pipe that allows them to communicate.
    ///
    /// `default()` creates a session with some sensible default
    /// configuration. `with_configs()` allows for providing a specific
    /// configuration.
    ///
    /// `handshake()` performs all the steps needed to establish an HTTP/3
    /// connection.
    ///
    /// Some utility functions are provided that make it less verbose to send
    /// request, responses and individual headers. The full quiche API remains
    /// avaialable for any test that need to do unconventional things (such as
    /// bad behaviour that triggers errors).
    struct Session {
        pipe: testing::Pipe,
        client: Connection,
        server: Connection,

        buf: [u8; 65535],
    }

    impl Session {
        fn default() -> Result<Session> {
            let mut config = crate::Config::new(crate::PROTOCOL_VERSION)?;
            config.load_cert_chain_from_pem_file("examples/cert.crt")?;
            config.load_priv_key_from_pem_file("examples/cert.key")?;
            config.set_application_protos(b"\x02h3")?;
            config.set_initial_max_data(1500);
            config.set_initial_max_stream_data_bidi_local(150);
            config.set_initial_max_stream_data_bidi_remote(150);
            config.set_initial_max_stream_data_uni(150);
            config.set_initial_max_streams_bidi(5);
            config.set_initial_max_streams_uni(5);
            config.verify_peer(false);

            let mut h3_config = Config::new(0, 1024, 0, 0)?;
            Session::with_configs(&mut config, &mut h3_config)
        }

        fn with_configs(
            config: &mut crate::Config, h3_config: &mut Config,
        ) -> Result<Session> {
            Ok(Session {
                pipe: testing::Pipe::with_config(config)?,
                client: Connection::new(&h3_config, false)?,
                server: Connection::new(&h3_config, true)?,
                buf: [0; 65535],
            })
        }

        /// Do the HTTP/3 handshake so both ends are in sane initial state.
        fn handshake(&mut self) -> Result<()> {
            self.pipe.handshake(&mut self.buf)?;

            // Client streams.
            self.client.send_settings(&mut self.pipe.client)?;
            self.pipe.advance(&mut self.buf).ok();

            self.client
                .open_qpack_encoder_stream(&mut self.pipe.client)?;
            self.pipe.advance(&mut self.buf).ok();

            self.client
                .open_qpack_decoder_stream(&mut self.pipe.client)?;
            self.pipe.advance(&mut self.buf).ok();

            if self.pipe.client.grease {
                self.client.open_grease_stream(&mut self.pipe.client)?;
            }

            self.pipe.advance(&mut self.buf).ok();

            // Server streams.
            self.server.send_settings(&mut self.pipe.server)?;
            self.pipe.advance(&mut self.buf).ok();

            self.server
                .open_qpack_encoder_stream(&mut self.pipe.server)?;
            self.pipe.advance(&mut self.buf).ok();

            self.server
                .open_qpack_decoder_stream(&mut self.pipe.server)?;
            self.pipe.advance(&mut self.buf).ok();

            if self.pipe.server.grease {
                self.server.open_grease_stream(&mut self.pipe.server)?;
            }

            self.advance().ok();

            while self.client.poll(&mut self.pipe.client).is_ok() {
                // Do nothing.
            }

            while self.server.poll(&mut self.pipe.server).is_ok() {
                // Do nothing.
            }

            Ok(())
        }

        /// Advances the session pipe over the buffer.
        fn advance(&mut self) -> crate::Result<()> {
            self.pipe.advance(&mut self.buf)
        }

        /// Polls the client for events.
        fn poll_client(&mut self) -> Result<(u64, Event)> {
            self.client.poll(&mut self.pipe.client)
        }

        /// Polls the server for events.
        fn poll_server(&mut self) -> Result<(u64, Event)> {
            self.server.poll(&mut self.pipe.server)
        }

        /// Sends a request from client with default headers.
        ///
        /// On success it returns the newly allocated stream and the headers.
        fn send_request(&mut self, fin: bool) -> Result<(u64, Vec<Header>)> {
            let req = vec![
                Header::new(":method", "GET"),
                Header::new(":scheme", "https"),
                Header::new(":authority", "quic.tech"),
                Header::new(":path", "/test"),
                Header::new("user-agent", "quiche-test"),
            ];

            let stream = self
                .client
                .send_request(&mut self.pipe.client, &req, fin)
                .unwrap();

            self.advance().ok();

            Ok((stream, req))
        }

        /// Sends a response from server with default headers.
        ///
        /// On success it returns the headers.
        fn send_response(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<Header>> {
            let resp = vec![
                Header::new(":status", "200"),
                Header::new("server", "quiche-test"),
            ];
            self.server.send_response(
                &mut self.pipe.server,
                stream,
                &resp,
                fin,
            )?;

            self.advance().ok();

            Ok(resp)
        }

        /// Sends some default payload from client.
        ///
        /// On success it returns the payload.
        fn send_body_client(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.client
                .send_body(&mut self.pipe.client, stream, &bytes, fin)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Sends some default payload from server.
        ///
        /// On success it returns the payload.
        fn send_body_server(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.server
                .send_body(&mut self.pipe.server, stream, &bytes, fin)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Sends a single HTTP/3 frame from the client.
        fn send_frame_client(
            &mut self, frame: frame::Frame, stream_id: u64, fin: bool,
        ) -> Result<()> {
            let mut d = [42; 65535];

            let mut b = octets::Octets::with_slice(&mut d);

            frame.to_bytes(&mut b)?;

            let off = b.off();
            self.pipe.client.stream_send(stream_id, &d[..off], fin)?;

            self.advance().ok();

            Ok(())
        }

        /// Sends a single HTTP/3 frame from the server.
        fn send_frame_server(
            &mut self, frame: frame::Frame, stream_id: u64, fin: bool,
        ) -> Result<()> {
            let mut d = [42; 65535];

            let mut b = octets::Octets::with_slice(&mut d);

            frame.to_bytes(&mut b)?;

            let off = b.off();
            self.pipe.server.stream_send(stream_id, &d[..off], fin)?;

            self.advance().ok();

            Ok(())
        }
    }

    #[test]
    /// Make sure that random GREASE values is within the specified limit.
    fn grease_value_in_varint_limit() {
        assert!(grease_value() < 2u64.pow(62) - 1);
    }

    #[test]
    /// Send a request with no body, get a response with no body.
    fn request_no_body_response_no_body() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(stream, 0);

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, Event::Headers(resp))));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with one DATA frame.
    fn request_no_body_response_one_chunk() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();
        assert_eq!(stream, 0);

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, false).unwrap();

        let body = s.send_body_server(stream, true).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, Event::Headers(resp))));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data(body))));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with multiple DATA frames.
    fn request_no_body_response_many_chunks() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let total_data_frames = 4;
        let mut sent_frames = 0;
        let mut received_frames = 0;

        let resp = s.send_response(stream, false).unwrap();

        while sent_frames < total_data_frames - 1 {
            s.send_body_server(stream, false).unwrap();;

            sent_frames += 1;
        }

        let body = s.send_body_server(stream, true).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, Event::Headers(resp))));
        while received_frames < total_data_frames {
            assert_eq!(s.poll_client(), Ok((stream, Event::Data(body.clone()))));
            received_frames += 1;
        }
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with one DATA frame, get a response with no body.
    fn request_one_chunk_response_no_body() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let body = s.send_body_client(stream, true).unwrap();;

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data(body))));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, Event::Headers(resp))));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a request with multiple DATA frames, get a response with no body.
    fn request_many_chunks_response_no_body() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let total_data_frames = 4;
        let mut sent_frames = 0;
        let mut received_frames = 0;

        while sent_frames < total_data_frames - 1 {
            s.send_body_client(stream, false).unwrap();;

            sent_frames += 1;
        }

        let body = s.send_body_client(stream, true).unwrap();

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        while received_frames < total_data_frames {
            assert_eq!(s.poll_server(), Ok((stream, Event::Data(body.clone()))));
            received_frames += 1;
        }
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, Event::Headers(resp))));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a request with multiple DATA frames, get a response with one DATA
    /// frame.
    fn many_requests_many_chunks_response_one_chunk() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream1, req1) = s.send_request(false).unwrap();
        assert_eq!(stream1, 0);

        let (stream2, req2) = s.send_request(false).unwrap();
        assert_eq!(stream2, 4);

        let (stream3, req3) = s.send_request(false).unwrap();
        assert_eq!(stream3, 8);

        let body = s.send_body_client(stream1, false).unwrap();
        s.send_body_client(stream2, false).unwrap();
        s.send_body_client(stream3, false).unwrap();

        // Reverse order of writes.

        s.send_body_client(stream3, true).unwrap();
        s.send_body_client(stream2, true).unwrap();
        s.send_body_client(stream1, true).unwrap();

        assert_eq!(s.poll_server(), Ok((stream1, Event::Headers(req1))));
        assert_eq!(s.poll_server(), Ok((stream1, Event::Data(body.clone()))));
        assert_eq!(s.poll_server(), Ok((stream1, Event::Data(body.clone()))));
        assert_eq!(s.poll_server(), Ok((stream1, Event::Finished)));

        assert_eq!(s.poll_server(), Ok((stream2, Event::Headers(req2))));
        assert_eq!(s.poll_server(), Ok((stream2, Event::Data(body.clone()))));
        assert_eq!(s.poll_server(), Ok((stream2, Event::Data(body.clone()))));
        assert_eq!(s.poll_server(), Ok((stream2, Event::Finished)));

        assert_eq!(s.poll_server(), Ok((stream3, Event::Headers(req3))));
        assert_eq!(s.poll_server(), Ok((stream3, Event::Data(body.clone()))));
        assert_eq!(s.poll_server(), Ok((stream3, Event::Data(body.clone()))));
        assert_eq!(s.poll_server(), Ok((stream3, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let resp1 = s.send_response(stream1, true).unwrap();
        let resp2 = s.send_response(stream2, true).unwrap();
        let resp3 = s.send_response(stream3, true).unwrap();

        assert_eq!(s.poll_client(), Ok((stream1, Event::Headers(resp1))),);
        assert_eq!(s.poll_client(), Ok((stream1, Event::Finished)));

        assert_eq!(s.poll_client(), Ok((stream2, Event::Headers(resp2))),);
        assert_eq!(s.poll_client(), Ok((stream2, Event::Finished)));

        assert_eq!(s.poll_client(), Ok((stream3, Event::Headers(resp3))),);
        assert_eq!(s.poll_client(), Ok((stream3, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Try to send DATA frames on wrong streams, ensure the API returns an
    /// error before anything hits the transport layer.
    fn send_body_invalid_server_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        assert_eq!(s.send_body_server(0, true), Err(Error::WrongStream));

        assert_eq!(
            s.send_body_server(s.server.control_stream_id.unwrap(), true),
            Err(Error::WrongStream)
        );

        assert_eq!(
            s.send_body_server(
                s.server.local_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::WrongStream)
        );

        assert_eq!(
            s.send_body_server(
                s.server.local_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::WrongStream)
        );

        assert_eq!(
            s.send_body_server(s.server.peer_control_stream_id.unwrap(), true),
            Err(Error::WrongStream)
        );

        assert_eq!(
            s.send_body_server(
                s.server.peer_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::WrongStream)
        );

        assert_eq!(
            s.send_body_server(
                s.server.peer_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::WrongStream)
        );
    }

    #[test]
    /// Send a MAX_PUSH_ID frame from the client on a valid stream.
    fn max_push_id_from_client_good() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Send a MAX_PUSH_ID frame from the client on an invalid stream.
    fn max_push_id_from_client_bad_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, _req) = s.send_request(false).unwrap();

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 2 },
            stream,
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Err(Error::WrongStream));
    }

    #[test]
    /// Send a sequence of MAX_PUSH_ID frames from the client that attempt to
    /// reduce the limit.
    fn max_push_id_from_client_limit_reduction() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 2 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.poll_server(), Err(Error::GeneralProtocolError));
    }

    #[test]
    /// Send a MAX_PUSH_ID frame from the server, which is forbidden.
    fn max_push_id_from_server() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            frame::Frame::MaxPushId { push_id: 1 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::UnexpectedFrame));
    }

    #[test]
    /// Send a PUSH_PROMISE frame from the client, which is forbidden.
    fn push_promise_from_client() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let header_block = s.client.encode_header_block(&req).unwrap();

        s.send_frame_client(
            frame::Frame::PushPromise {
                push_id: 1,
                header_block,
            },
            stream,
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Err(Error::UnexpectedFrame));
    }

    #[test]
    /// Send a CANCEL_PUSH frame from the client.
    fn cancel_push_from_client() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            frame::Frame::CancelPush { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Send a CANCEL_PUSH frame from the client on an invalid stream.
    fn cancel_push_from_client_bad_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, _req) = s.send_request(false).unwrap();

        s.send_frame_client(
            frame::Frame::CancelPush { push_id: 2 },
            stream,
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Err(Error::WrongStream));
    }

    #[test]
    /// Send a CANCEL_PUSH frame from the client.
    fn cancel_push_from_server() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            frame::Frame::CancelPush { push_id: 1 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a DUPLICATE_PUSH frame from the client, which is forbidden.
    fn duplicate_push_from_client() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        s.send_frame_client(
            frame::Frame::DuplicatePush { push_id: 1 },
            stream,
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Err(Error::UnexpectedFrame));
    }

    #[test]
    /// Send a GOAWAY frame from the client, which is forbidden.
    fn goaway_from_client() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            frame::Frame::GoAway { stream_id: 100 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::UnexpectedFrame));
    }

    #[test]
    /// Send a GOAWAY frame from the server.
    fn goaway_from_server_good() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            frame::Frame::GoAway { stream_id: 100 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a GOAWAY frame from the server, that references a request that does
    /// not exist.
    fn goaway_from_server_bad_id() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            frame::Frame::GoAway { stream_id: 1 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::WrongStream));
    }

    #[test]
    /// Send a prioritized request from the client, ensure server accepts it
    fn priority_request() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        // Create an approximate PRIORITY frame in the buffer
        b.put_varint(frame::PRIORITY_FRAME_TYPE_ID).unwrap();
        b.put_varint(2).unwrap(); // 2 u8s = Bitfield + Weight
        b.put_u8(0).unwrap(); // bitfield
        b.put_u8(16).unwrap(); // weight
        let off = b.off();

        let stream = 0;
        s.pipe.client.stream_send(stream, &d[..off], false).unwrap();
        s.advance().ok();

        let req = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
            Header::new("user-agent", "quiche-test"),
        ];

        s.client
            .send_headers(&mut s.pipe.client, stream, &req, true)
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((stream, Event::Headers(req))));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a PRIORITY frame from the client, ensure server accepts it
    fn priority_control_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::Octets::with_slice(&mut d);

        // Create an approximate PRIORITY frame in the buffer
        b.put_varint(frame::PRIORITY_FRAME_TYPE_ID).unwrap();
        b.put_varint(1 + octets::varint_parse_len(1) as u64 + 1)
            .unwrap(); // 2 u8s = Bitfield + varint + Weight
        b.put_u8(128).unwrap(); // bitfield
        b.put_varint(1).unwrap();
        b.put_u8(16).unwrap(); // weight
        let off = b.off();

        s.pipe
            .client
            .stream_send(s.client.control_stream_id.unwrap(), &d[..off], false)
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Ensure quiche allocates streams for client and server roles as expected.
    fn uni_stream_local_counting() {
        let config = Config::new(0, 1024, 0, 0).unwrap();

        let mut h3_cln = Connection::new(&config, false).unwrap();

        assert_eq!(h3_cln.get_available_uni_stream().unwrap(), 2);
        assert_eq!(h3_cln.get_available_uni_stream().unwrap(), 6);
        assert_eq!(h3_cln.get_available_uni_stream().unwrap(), 10);
        assert_eq!(h3_cln.get_available_uni_stream().unwrap(), 14);
        assert_eq!(h3_cln.get_available_uni_stream().unwrap(), 18);

        let mut h3_srv = Connection::new(&config, true).unwrap();

        assert_eq!(h3_srv.get_available_uni_stream().unwrap(), 3);
        assert_eq!(h3_srv.get_available_uni_stream().unwrap(), 7);
        assert_eq!(h3_srv.get_available_uni_stream().unwrap(), 11);
        assert_eq!(h3_srv.get_available_uni_stream().unwrap(), 15);
        assert_eq!(h3_srv.get_available_uni_stream().unwrap(), 19);
    }

    #[test]
    /// Client opens multiple control streams, which is forbidden.
    fn open_multiple_control_streams() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let stream_id = s.client.get_available_uni_stream().unwrap();

        let mut d = [42; 8];
        let mut b = octets::Octets::with_slice(&mut d);

        s.pipe
            .client
            .stream_send(
                stream_id,
                b.put_varint(stream::HTTP3_CONTROL_STREAM_TYPE_ID).unwrap(),
                false,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::WrongStreamCount));
    }

    #[test]
    /// Client closes the control stream, which is forbidden.
    fn close_control_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut control_stream_closed = false;

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            true,
        )
        .unwrap();

        loop {
            match s.server.poll(&mut s.pipe.server) {
                Ok(_) => (),

                Err(Error::Done) => {
                    break;
                },

                Err(Error::ClosedCriticalStream) => {
                    control_stream_closed = true;
                    break;
                },

                Err(_) => (),
            }
        }

        assert!(control_stream_closed);
    }

    #[test]
    /// Client closes a qpack stream, which is forbidden.
    fn close_qpack_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut qpack_stream_closed = false;

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 1 },
            s.client.local_qpack_streams.encoder_stream_id.unwrap(),
            true,
        )
        .unwrap();

        loop {
            match s.server.poll(&mut s.pipe.server) {
                Ok(_) => (),

                Err(Error::Done) => {
                    break;
                },

                Err(Error::ClosedCriticalStream) => {
                    qpack_stream_closed = true;
                    break;
                },

                Err(_) => (),
            }
        }

        assert!(qpack_stream_closed);
    }
}

mod ffi;
mod frame;
#[doc(hidden)]
pub mod qpack;
mod stream;
