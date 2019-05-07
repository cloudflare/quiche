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
        http3_conn.open_qpack_streams(conn)?;

        if conn.grease {
            http3_conn.open_grease_stream(conn)?;
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

    fn send_headers(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        headers: &[Header], fin: bool,
    ) -> Result<()> {
        let mut d = [42; 10];
        let mut b = octets::Octets::with_slice(&mut d);

        let headers_len = headers
            .iter()
            .fold(0, |acc, h| acc + h.value().len() + h.name().len() + 32);

        let mut header_block = vec![0; headers_len];
        let len = self
            .qpack_encoder
            .encode(&headers, &mut header_block)
            .map_err(|_| Error::InternalError)?;

        header_block.truncate(len);

        if conn.grease {
            self.send_grease_frames(conn, stream_id)?;
        }

        trace!(
            "{} sending HEADERS of size {} on stream {}",
            conn.trace_id(),
            len,
            stream_id
        );

        conn.stream_send(
            stream_id,
            b.put_varint(frame::HEADERS_FRAME_TYPE_ID)?,
            false,
        )?;

        conn.stream_send(stream_id, b.put_varint(len as u64)?, false)?;
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

        Ok(written)
    }

    /// Checks whether an open critical stream has been closed.
    fn critical_stream_closed(
        &mut self, conn: &mut super::Connection,
    ) -> Result<()> {
        let mut crit_closed = false;

        if let Some(s) = self.control_stream_id {
            crit_closed |= conn.stream_finished(s);
        }

        if let Some(s) = self.local_qpack_streams.encoder_stream_id {
            crit_closed |= conn.stream_finished(s);
        }

        if let Some(s) = self.local_qpack_streams.decoder_stream_id {
            crit_closed |= conn.stream_finished(s);
        }

        if let Some(s) = self.peer_control_stream_id {
            crit_closed |= conn.stream_finished(s);
        }

        if let Some(s) = self.peer_qpack_streams.encoder_stream_id {
            crit_closed |= conn.stream_finished(s);
        }

        if let Some(s) = self.peer_qpack_streams.decoder_stream_id {
            crit_closed |= conn.stream_finished(s);
        }

        if crit_closed {
            conn.close(
                true,
                Error::ClosedCriticalStream.to_wire(),
                b"Critical stream closed.",
            )?;

            return Err(Error::ClosedCriticalStream);
        }

        Ok(())
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
        self.critical_stream_closed(conn)?;

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
                            Connection::close_unexpected_frame(
                                conn,
                                b"HEADERS received on control stream",
                            )?;
                        }

                        let headers = self
                            .qpack_decoder
                            .decode(&mut header_block[..])
                            .map_err(|_| Error::QpackDecompressionFailed)?;
                        return Ok((*stream_id, Event::Headers(headers)));
                    },

                    frame::Frame::Data { payload } => {
                        if Some(*stream_id) == self.peer_control_stream_id {
                            Connection::close_unexpected_frame(
                                conn,
                                b"DATA received on control stream",
                            )?;
                        }

                        return Ok((*stream_id, Event::Data(payload)));
                    },

                    frame::Frame::GoAway { .. } => {
                        if Some(*stream_id) != self.peer_control_stream_id {
                            Connection::close_unexpected_frame(
                                conn,
                                b"GOAWAY received on non-control stream",
                            )?;
                        }

                        if self.is_server {
                            Connection::close_unexpected_frame(
                                conn,
                                b"GOWAY received on server",
                            )?;
                        }

                        // TODO: implement GOAWAY
                    },

                    frame::Frame::MaxPushId { push_id } => {
                        if Some(*stream_id) != self.peer_control_stream_id {
                            Connection::close_unexpected_frame(
                                conn,
                                b"MAX_PUSH_ID received on non-control stream",
                            )?;
                        }

                        if !self.is_server {
                            Connection::close_unexpected_frame(
                                conn,
                                b"MAX_PUSH_ID received by client",
                            )?;
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
                        if stream_id % 4 != 0 {
                            Connection::close_unexpected_frame(
                                conn,
                                b"PUSH_PROMISE received on non-request stream",
                            )?;
                        }

                        // TODO: implement PUSH_PROMISE
                    },

                    frame::Frame::DuplicatePush { .. } => {
                        if stream_id % 4 != 0 {
                            Connection::close_unexpected_frame(
                                conn,
                                b"DUPLICATE_PUSH received on non-request stream",
                            )?;
                        }

                        // TODO: implement DUPLICATE_PUSH
                    },

                    frame::Frame::CancelPush { .. } => {
                        if Some(*stream_id) != self.peer_control_stream_id {
                            Connection::close_unexpected_frame(
                                conn,
                                b"CANCEL_PUSH received on non-control stream",
                            )?;
                        }

                        // TODO: implement CANCEL_PUSH frame
                    },
                }
            }
        }

        Err(Error::Done)
    }

    fn close_unexpected_frame(
        conn: &mut super::Connection, reason: &[u8],
    ) -> Result<()> {
        conn.close(true, Error::UnexpectedFrame.to_wire(), reason)?;

        Err(Error::UnexpectedFrame)
    }

    fn close_wrong_stream_count(
        conn: &mut super::Connection, reason: &[u8],
    ) -> Result<()> {
        conn.close(true, Error::WrongStreamCount.to_wire(), reason)?;

        Err(Error::WrongStreamCount)
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

            let mut d = [42; 8];
            let mut b = octets::Octets::with_slice(&mut d);

            conn.stream_send(
                stream_id,
                b.put_varint(stream::HTTP3_CONTROL_STREAM_TYPE_ID)?,
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

            let mut d = [0; 8];
            let mut b = octets::Octets::with_slice(&mut d);

            conn.stream_send(
                stream_id,
                b.put_varint(stream::QPACK_ENCODER_STREAM_TYPE_ID)?,
                false,
            )?;

            self.local_qpack_streams.encoder_stream_id = Some(stream_id);
        }

        if self.local_qpack_streams.decoder_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;

            let mut d = [0; 8];
            let mut b = octets::Octets::with_slice(&mut d);

            conn.stream_send(
                stream_id,
                b.put_varint(stream::QPACK_DECODER_STREAM_TYPE_ID)?,
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
        let stream_id = self.get_available_uni_stream()?;

        let mut d = [0; 8];
        let mut b = octets::Octets::with_slice(&mut d);

        match conn.stream_send(stream_id, b.put_varint(grease_value())?, false) {
            Ok(_) => {
                trace!(
                    "{} sending GREASE stream on stream id {}",
                    conn.trace_id(),
                    stream_id
                );

                conn.stream_send(stream_id, b"GREASE is the word", false)?;
            },

            Err(super::Error::StreamLimit) => {
                trace!(
                    "{} sending GREASE stream was blocked on stream id {}",
                    conn.trace_id(),
                    stream_id
                );

                return Ok(());
            },

            Err(e) => return Err(Error::from(e)),
        };

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

                    stream.set_stream_type(ty)?;

                    match &ty {
                        stream::Type::Control => {
                            // Only one control stream allowed.
                            if self.peer_control_stream_id.is_some() {
                                Connection::close_wrong_stream_count(
                                    conn,
                                    b"Received multiple control streams",
                                )?;
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
                                Connection::close_wrong_stream_count(
                                    conn,
                                    b"Received multiple QPACK encoder streams",
                                )?;
                            }

                            self.peer_qpack_streams.encoder_stream_id =
                                Some(stream_id);
                        },

                        stream::Type::QpackDecoder => {
                            // Only one qpack decoder allowed.
                            if self.peer_qpack_streams.decoder_stream_id.is_some()
                            {
                                Connection::close_wrong_stream_count(
                                    conn,
                                    b"Received multiple QPACK decoder streams",
                                )?;
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
                    if let Err(e) = stream.set_frame_type(varint) {
                        conn.close(true, e.to_wire(), b"Error handling frame.")?;
                        return Err(e);
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

    struct Session {
        pub pipe: testing::Pipe,
        pub client: Connection,
        pub server: Connection,
    }

    impl Session {
        pub fn default() -> Result<Session> {
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

        pub fn with_configs(
            config: &mut crate::Config, h3_config: &mut Config,
        ) -> Result<Session> {
            Ok(Session {
                pipe: testing::Pipe::with_config(config)?,
                client: Connection::new(&h3_config, false)?,
                server: Connection::new(&h3_config, true)?,
            })
        }

        pub fn handshake(&mut self, buf: &mut [u8]) -> Result<()> {
            self.pipe.handshake(buf)?;

            self.client.send_settings(&mut self.pipe.client)?;
            self.pipe.advance(buf).ok();

            self.client.open_qpack_streams(&mut self.pipe.client)?;
            self.pipe.advance(buf).ok();

            if self.pipe.client.grease {
                self.client.open_grease_stream(&mut self.pipe.client)?;
            }

            self.pipe.advance(buf).ok();

            Ok(())
        }
    }

    fn send_frame(
        conn: &mut crate::Connection, frame: frame::Frame, stream_id: u64,
        fin: bool,
    ) -> Result<()> {
        let mut d = [42; 65535];

        let mut b = octets::Octets::with_slice(&mut d);

        frame.to_bytes(&mut b)?;

        let off = b.off();
        conn.stream_send(stream_id, &d[..off], fin)?;

        Ok(())
    }

    #[test]
    fn grease_value_in_varint_limit() {
        assert!(grease_value() < 2u64.pow(62) - 1);
    }

    #[test]
    fn simple_request() {
        let mut buf = [0; 65535];

        let mut s = Session::default().unwrap();
        s.handshake(&mut buf).unwrap();

        let req = [
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
            Header::new("user-agent", "quiche-test"),
        ];

        let stream = s
            .client
            .send_request(&mut s.pipe.client, &req, true)
            .unwrap();
        assert_eq!(stream, 0);

        s.pipe.advance(&mut buf).ok();

        let ev = s.server.poll(&mut s.pipe.server).unwrap();
        assert_eq!(ev, (stream, Event::Headers(req.to_vec())));

        let resp = [
            Header::new(":status", "200"),
            Header::new("server", "quiche-test"),
        ];

        s.server
            .send_response(&mut s.pipe.server, stream, &resp, true)
            .unwrap();

        s.pipe.advance(&mut buf).ok();

        let ev = s.client.poll(&mut s.pipe.client).unwrap();
        assert_eq!(ev, (stream, Event::Headers(resp.to_vec())));
    }

    #[test]
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
    fn open_multiple_control_streams() {
        let mut buf = [0; 65535];

        let mut s = Session::default().unwrap();
        s.handshake(&mut buf).unwrap();

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

        s.pipe.advance(&mut buf).ok();

        assert_eq!(
            s.server.poll(&mut s.pipe.server),
            Err(Error::WrongStreamCount)
        );
    }

    #[test]
    fn close_control_stream() {
        let mut buf = [0; 65535];

        let mut s = Session::default().unwrap();
        s.handshake(&mut buf).unwrap();

        send_frame(
            &mut s.pipe.client,
            frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            true,
        )
        .unwrap();

        s.pipe.advance(&mut buf).ok();

        loop {
            match s.server.poll(&mut s.pipe.server) {
                Ok(_) => (),

                Err(Error::Done) => {
                    break;
                },

                Err(_) => (),
            }
        }

        assert_eq!(
            s.server.poll(&mut s.pipe.server),
            Err(Error::ClosedCriticalStream)
        );
    }

    #[test]
    fn close_qpack_stream() {
        let mut buf = [0; 65535];

        let mut s = Session::default().unwrap();
        s.handshake(&mut buf).unwrap();

        send_frame(
            &mut s.pipe.client,
            frame::Frame::MaxPushId { push_id: 1 },
            s.client.local_qpack_streams.encoder_stream_id.unwrap(),
            true,
        )
        .unwrap();

        s.pipe.advance(&mut buf).ok();

        loop {
            match s.server.poll(&mut s.pipe.server) {
                Ok(_) => (),

                Err(Error::Done) => {
                    break;
                },

                Err(_) => (),
            }
        }

        assert_eq!(
            s.server.poll(&mut s.pipe.server),
            Err(Error::ClosedCriticalStream)
        );
    }

}

mod ffi;
mod frame;
#[doc(hidden)]
pub mod qpack;
mod stream;
