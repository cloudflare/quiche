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
//! let h3_config = quiche::h3::Config::new()?;
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
//! # let h3_config = quiche::h3::Config::new()?;
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
//! # let h3_config = quiche::h3::Config::new()?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let req = vec![
//!     quiche::h3::Header::new(":method", "GET"),
//!     quiche::h3::Header::new(":scheme", "https"),
//!     quiche::h3::Header::new(":authority", "quic.tech"),
//!     quiche::h3::Header::new(":path", "/"),
//!     quiche::h3::Header::new("user-agent", "quiche"),
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
//! # let h3_config = quiche::h3::Config::new()?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let req = vec![
//!     quiche::h3::Header::new(":method", "GET"),
//!     quiche::h3::Header::new(":scheme", "https"),
//!     quiche::h3::Header::new(":authority", "quic.tech"),
//!     quiche::h3::Header::new(":path", "/"),
//!     quiche::h3::Header::new("user-agent", "quiche"),
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
//! # let h3_config = quiche::h3::Config::new()?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! loop {
//!     match h3_conn.poll(&mut conn) {
//!         Ok((stream_id, quiche::h3::Event::Headers{list, has_body})) => {
//!             let mut headers = list.into_iter();
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
//!         Ok((stream_id, quiche::h3::Event::Data)) => {
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
//! # let h3_config = quiche::h3::Config::new()?;
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! loop {
//!     match h3_conn.poll(&mut conn) {
//!         Ok((stream_id, quiche::h3::Event::Headers{list, has_body})) => {
//!             let status = list.iter().find(|h| h.name() == ":status").unwrap();
//!             println!("Received {} response on stream {}",
//!                      status.value(), stream_id);
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Data)) => {
//!             let mut body = vec![0; 4096];
//!
//!             if let Ok(read) =
//!                 h3_conn.recv_body(&mut conn, stream_id, &mut body)
//!             {
//!                 println!("Received {} bytes of payload on stream {}",
//!                          read, stream_id);
//!             }
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

use std::collections::HashMap;
use std::collections::VecDeque;

use crate::octets;

/// List of ALPN tokens of supported HTTP/3 versions.
///
/// This can be passed directly to the [`Config::set_application_protos()`]
/// method when implementing HTTP/3 applications.
///
/// [`Config::set_application_protos()`]:
/// ../struct.Config.html#method.set_application_protos
pub const APPLICATION_PROTOCOL: &[u8] = b"\x05h3-29\x05h3-28\x05h3-27";

// The offset used when converting HTTP/3 urgency to quiche urgency.
const PRIORITY_URGENCY_OFFSET: u8 = 124;

/// A specialized [`Result`] type for quiche HTTP/3 operations.
///
/// This type is used throughout quiche's HTTP/3 public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// An HTTP/3 error.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// There is no error or no work to do
    Done,

    /// The provided buffer is too short.
    BufferTooShort,

    /// Internal error in the HTTP/3 stack.
    InternalError,

    /// Endpoint detected that the peer is exhibiting behavior that causes.
    /// excessive load.
    ExcessiveLoad,

    /// Stream ID or Push ID greater that current maximum was
    /// used incorrectly, such as exceeding a limit, reducing a limit,
    /// or being reused.
    IdError,

    /// The endpoint detected that its peer created a stream that it will not
    /// accept.
    StreamCreationError,

    /// A required critical stream was closed.
    ClosedCriticalStream,

    /// No SETTINGS frame at beginning of control stream.
    MissingSettings,

    /// A frame was received which is not permitted in the current state.
    FrameUnexpected,

    /// Frame violated layout or size rules.
    FrameError,

    /// QPACK Header block decompression failure.
    QpackDecompressionFailed,

    /// Error originated from the transport layer.
    TransportError(crate::Error),

    /// The underlying QUIC stream (or connection) doesn't have enough capacity
    /// for the operation to complete. The application should retry later on.
    StreamBlocked,
}

impl Error {
    fn to_wire(self) -> u64 {
        match self {
            Error::Done => 0x100,
            Error::InternalError => 0x102,
            Error::StreamCreationError => 0x103,
            Error::ClosedCriticalStream => 0x104,
            Error::FrameUnexpected => 0x105,
            Error::FrameError => 0x106,
            Error::ExcessiveLoad => 0x107,
            Error::IdError => 0x108,
            Error::MissingSettings => 0x10A,
            Error::QpackDecompressionFailed => 0x200,
            Error::BufferTooShort => 0x999,
            Error::TransportError { .. } => 0xFF,
            Error::StreamBlocked => 0xFF,
        }
    }

    fn to_c(self) -> libc::ssize_t {
        match self {
            Error::Done => -1,
            Error::BufferTooShort => -2,
            Error::InternalError => -3,
            Error::ExcessiveLoad => -4,
            Error::IdError => -5,
            Error::StreamCreationError => -6,
            Error::ClosedCriticalStream => -7,
            Error::MissingSettings => -8,
            Error::FrameUnexpected => -9,
            Error::FrameError => -10,
            Error::QpackDecompressionFailed => -11,
            Error::TransportError { .. } => -12,
            Error::StreamBlocked => -13,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<super::Error> for Error {
    fn from(err: super::Error) -> Self {
        match err {
            super::Error::Done => Error::Done,

            _ => Error::TransportError(err),
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
    max_header_list_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
}

impl Config {
    /// Creates a new configuration object with default settings.
    pub fn new() -> Result<Config> {
        Ok(Config {
            max_header_list_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        })
    }

    /// Sets the `SETTINGS_MAX_HEADER_LIST_SIZE` setting.
    ///
    /// By default no limit is enforced.
    pub fn set_max_header_list_size(&mut self, v: u64) {
        self.max_header_list_size = Some(v);
    }

    /// Sets the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
    ///
    /// The default value is `0`.
    pub fn set_qpack_max_table_capacity(&mut self, v: u64) {
        self.qpack_max_table_capacity = Some(v);
    }

    /// Sets the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
    ///
    /// The default value is `0`.
    pub fn set_qpack_blocked_streams(&mut self, v: u64) {
        self.qpack_blocked_streams = Some(v);
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
    Headers {
        /// The list of received header fields. The application should validate
        /// pseudo-headers and headers.
        list: Vec<Header>,

        /// Whether data will follow the headers on the stream.
        has_body: bool,
    },

    /// Data was received.
    ///
    /// This indicates that the application can use the [`recv_body()`] method
    /// to retrieve the data from the stream.
    ///
    /// This event will keep being reported until all the available data is
    /// retrieved by the application.
    ///
    /// [`recv_body()`]: struct.Connection.html#method.recv_body
    Data,

    /// Stream was closed,
    Finished,
}

struct ConnectionSettings {
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

    next_request_stream_id: u64,
    next_uni_stream_id: u64,

    streams: HashMap<u64, stream::Stream>,

    local_settings: ConnectionSettings,
    peer_settings: ConnectionSettings,

    control_stream_id: Option<u64>,
    peer_control_stream_id: Option<u64>,

    qpack_encoder: qpack::Encoder,
    qpack_decoder: qpack::Decoder,

    local_qpack_streams: QpackStreams,
    peer_qpack_streams: QpackStreams,

    max_push_id: u64,

    finished_streams: VecDeque<u64>,

    frames_greased: bool,
}

impl Connection {
    fn new(config: &Config, is_server: bool) -> Result<Connection> {
        let initial_uni_stream_id = if is_server { 0x3 } else { 0x2 };

        Ok(Connection {
            is_server,

            next_request_stream_id: 0,

            next_uni_stream_id: initial_uni_stream_id,

            streams: HashMap::new(),

            local_settings: ConnectionSettings {
                max_header_list_size: config.max_header_list_size,
                qpack_max_table_capacity: config.qpack_max_table_capacity,
                qpack_blocked_streams: config.qpack_blocked_streams,
            },

            peer_settings: ConnectionSettings {
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

            finished_streams: VecDeque::new(),

            frames_greased: false,
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
    /// The request is encoded from the provided list of headers without a
    /// body, and sent on a newly allocated stream. To include a body,
    /// set `fin` as `false` and subsequently call [`send_body()`] with the
    /// same `conn` and the `stream_id` returned from this method.
    ///
    /// On success the newly allocated stream ID is returned.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    pub fn send_request(
        &mut self, conn: &mut super::Connection, headers: &[Header], fin: bool,
    ) -> Result<u64> {
        let stream_id = self.next_request_stream_id;

        self.streams
            .insert(stream_id, stream::Stream::new(stream_id, true));

        // The underlying QUIC stream does not exist yet, so calls to e.g.
        // stream_capacity() will fail. By writing a 0-length buffer, we force
        // the creation of the QUIC stream state, without actually writing
        // anything.
        conn.stream_send(stream_id, b"", false)?;

        self.send_headers(conn, stream_id, headers, fin)?;

        // To avoid skipping stream IDs, we only calculate the next available
        // stream ID when a request has been successfully buffered.
        self.next_request_stream_id = self
            .next_request_stream_id
            .checked_add(4)
            .ok_or(Error::IdError)?;

        Ok(stream_id)
    }

    /// Sends an HTTP/3 response on the specified stream with default priority.
    ///
    /// This method sends the provided `headers` without a body. To include a
    /// body, set `fin` as `false` and subsequently call [`send_body()`] with
    /// the same `conn` and `stream_id`.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    pub fn send_response(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        headers: &[Header], fin: bool,
    ) -> Result<()> {
        let priority = "u=3";

        self.send_response_with_priority(
            conn, stream_id, headers, priority, fin,
        )?;

        Ok(())
    }

    /// Sends an HTTP/3 response on the specified stream with specified
    /// priority.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    pub fn send_response_with_priority(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        headers: &[Header], priority: &str, fin: bool,
    ) -> Result<()> {
        if !self.streams.contains_key(&stream_id) {
            return Err(Error::FrameUnexpected);
        }

        let mut urgency = 3;
        let mut incremental = false;

        for param in priority.split(',') {
            if param.trim() == "i" {
                incremental = true;
                continue;
            }

            if param.trim().starts_with("u=") {
                // u is an sh-integer (an i64) but it has a constrained range of
                // 0-7. So detect anything outside that range and clamp it to
                // the lowest urgency in order to avoid it interfering with
                // valid items.
                //
                // TODO: this also detects when u is not an sh-integer and
                // clamps it in the same way. A real structured header parser
                // would actually fail to parse.
                let mut u =
                    i64::from_str_radix(param.rsplit('=').next().unwrap(), 10)
                        .unwrap_or(7);

                if u < 0 || u > 7 {
                    u = 7;
                }

                // The HTTP/3 urgency needs to be shifted into the quiche
                // urgency range.
                urgency = (u as u8).saturating_add(PRIORITY_URGENCY_OFFSET);
            }
        }

        conn.stream_priority(stream_id, urgency, incremental)?;

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
        let mut b = octets::OctetsMut::with_slice(&mut d);

        if !self.frames_greased && conn.grease {
            self.send_grease_frames(conn, stream_id)?;
            self.frames_greased = true;
        }

        let stream_cap = conn.stream_capacity(stream_id)?;

        let header_block = self.encode_header_block(headers)?;

        let overhead = octets::varint_len(frame::HEADERS_FRAME_TYPE_ID) +
            octets::varint_len(header_block.len() as u64);

        if stream_cap < overhead + header_block.len() {
            return Err(Error::StreamBlocked);
        }

        trace!(
            "{} tx frm HEADERS stream={} len={} fin={}",
            conn.trace_id(),
            stream_id,
            header_block.len(),
            fin
        );

        b.put_varint(frame::HEADERS_FRAME_TYPE_ID)?;
        b.put_varint(header_block.len() as u64)?;
        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;

        // Sending header block separately avoids unnecessary copy.
        conn.stream_send(stream_id, &header_block, fin)?;

        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.initialize_local();
        }

        if fin && conn.stream_finished(stream_id) {
            self.streams.remove(&stream_id);
        }

        Ok(())
    }

    /// Sends an HTTP/3 body chunk on the given stream.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// bytes could be written (e.g. because the stream is blocked).
    ///
    /// Note that the number of written bytes returned can be lower than the
    /// length of the input buffer when the underlying QUIC stream doesn't have
    /// enough capacity for the operation to complete.
    ///
    /// When a partial write happens (including when [`Done`] is returned) the
    /// application should retry the operation once the stream is reported as
    /// writable again.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn send_body(
        &mut self, conn: &mut super::Connection, stream_id: u64, body: &[u8],
        fin: bool,
    ) -> Result<usize> {
        let mut d = [42; 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Validate that it is sane to send data on the stream.
        if stream_id % 4 != 0 {
            return Err(Error::FrameUnexpected);
        }

        match self.streams.get(&stream_id) {
            Some(s) =>
                if !s.local_initialized() {
                    return Err(Error::FrameUnexpected);
                },

            None => {
                return Err(Error::FrameUnexpected);
            },
        };

        let overhead = octets::varint_len(frame::DATA_FRAME_TYPE_ID) +
            octets::varint_len(body.len() as u64);

        let stream_cap = conn.stream_capacity(stream_id)?;

        // Make sure there is enough capacity to send the frame header and at
        // least one byte of frame payload (this to avoid sending 0-length DATA
        // frames).
        if stream_cap <= overhead {
            return Err(Error::Done);
        }

        // Cap the frame payload length to the stream's capacity.
        let body_len = std::cmp::min(body.len(), stream_cap - overhead);

        // If we can't send the entire body, set the fin flag to false so the
        // application can try again later.
        let fin = if body_len != body.len() { false } else { fin };

        trace!(
            "{} tx frm DATA stream={} len={} fin={}",
            conn.trace_id(),
            stream_id,
            body_len,
            fin
        );

        b.put_varint(frame::DATA_FRAME_TYPE_ID)?;
        b.put_varint(body_len as u64)?;
        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;

        // Return how many bytes were written, excluding the frame header.
        // Sending body separately avoids unnecessary copy.
        let written = conn.stream_send(stream_id, &body[..body_len], fin)?;

        if fin && written == body.len() && conn.stream_finished(stream_id) {
            self.streams.remove(&stream_id);
        }

        Ok(written)
    }

    /// Reads request or response body data into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`Data`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there
    /// is no data to read.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Data`]: enum.Event.html#variant.Data
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv_body(
        &mut self, conn: &mut super::Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::Done)?;

        if stream.state() != stream::State::Data {
            return Err(Error::Done);
        }

        let read = stream.try_consume_data(conn, out)?;

        // While body is being received, the stream is marked as finished only
        // when all data is read by the application.
        if conn.stream_finished(stream_id) {
            self.finished_streams.push_back(stream_id);
        }

        Ok(read)
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
        // When connection close is initiated by the local application (e.g. due
        // to a protocol error), the connection itself might be in a broken
        // state, so return early.
        if conn.error.is_some() || conn.app_error.is_some() {
            return Err(Error::Done);
        }

        // Process control streams first.
        if let Some(stream_id) = self.peer_control_stream_id {
            self.process_control_stream(conn, stream_id)?;
        }

        if let Some(stream_id) = self.peer_qpack_streams.encoder_stream_id {
            self.process_control_stream(conn, stream_id)?;
        }

        if let Some(stream_id) = self.peer_qpack_streams.decoder_stream_id {
            self.process_control_stream(conn, stream_id)?;
        }

        // Process finished streams list.
        if let Some(finished) = self.finished_streams.pop_front() {
            return Ok((finished, Event::Finished));
        }

        // Process HTTP/3 data from readable streams.
        for s in conn.readable() {
            trace!("{} stream id {} is readable", conn.trace_id(), s);

            let ev = match self.process_readable_stream(conn, s) {
                Ok(v) => Some(v),

                Err(Error::Done) => None,

                Err(e) => return Err(e),
            };

            if conn.stream_finished(s) {
                self.finished_streams.push_back(s);
            }

            // TODO: check if stream is completed so it can be freed

            if let Some(ev) = ev {
                return Ok(ev);
            }
        }

        Err(Error::Done)
    }

    fn open_uni_stream(
        &mut self, conn: &mut super::Connection, ty: u64,
    ) -> Result<u64> {
        let stream_id = self.next_uni_stream_id;

        let mut d = [0; 8];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        match ty {
            // Control and QPACK streams are the most important to schedule.
            stream::HTTP3_CONTROL_STREAM_TYPE_ID |
            stream::QPACK_ENCODER_STREAM_TYPE_ID |
            stream::QPACK_DECODER_STREAM_TYPE_ID => {
                conn.stream_priority(stream_id, 0, true)?;
            },

            // TODO: Server push
            stream::HTTP3_PUSH_STREAM_TYPE_ID => (),

            // Anything else is a GREASE stream, so make it the least important.
            _ => {
                conn.stream_priority(stream_id, 255, true)?;
            },
        }

        conn.stream_send(stream_id, b.put_varint(ty)?, false)?;

        // To avoid skipping stream IDs, we only calculate the next available
        // stream ID when data has been successfully buffered.
        self.next_uni_stream_id = self
            .next_uni_stream_id
            .checked_add(4)
            .ok_or(Error::IdError)?;

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
        let mut d = [0; 8];

        let stream_cap = conn.stream_capacity(stream_id)?;

        let grease_frame1 = grease_value();
        let grease_frame2 = grease_value();
        let grease_payload = b"GREASE is the word";

        let overhead = octets::varint_len(grease_frame1) + // frame type
            1 + // payload len
            octets::varint_len(grease_frame2) + // frame type
            1 + // payload len
            grease_payload.len(); // payload

        // Don't send GREASE if there is not enough capacity for it. Greasing
        // will _not_ be attempted again later on.
        if stream_cap < overhead {
            return Ok(());
        }

        trace!("{} tx frm GREASE stream={}", conn.trace_id(), stream_id);

        // Empty GREASE frame.
        let mut b = octets::OctetsMut::with_slice(&mut d);
        conn.stream_send(stream_id, b.put_varint(grease_frame1)?, false)?;

        let mut b = octets::OctetsMut::with_slice(&mut d);
        conn.stream_send(stream_id, b.put_varint(0)?, false)?;

        // GREASE frame with payload.
        let mut b = octets::OctetsMut::with_slice(&mut d);
        conn.stream_send(stream_id, b.put_varint(grease_frame2)?, false)?;

        let mut b = octets::OctetsMut::with_slice(&mut d);
        conn.stream_send(stream_id, b.put_varint(18)?, false)?;

        conn.stream_send(stream_id, grease_payload, false)?;

        Ok(())
    }

    /// Opens a new unidirectional stream with a GREASE type and sends some
    /// unframed payload.
    fn open_grease_stream(&mut self, conn: &mut super::Connection) -> Result<()> {
        match self.open_uni_stream(conn, grease_value()) {
            Ok(stream_id) => {
                trace!("{} open GREASE stream {}", conn.trace_id(), stream_id);

                conn.stream_send(stream_id, b"GREASE is the word", false)?;
            },

            Err(Error::IdError) => {
                trace!("{} GREASE stream blocked", conn.trace_id(),);

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

        let grease = if conn.grease {
            Some((grease_value(), grease_value()))
        } else {
            None
        };

        let frame = frame::Frame::Settings {
            max_header_list_size: self.local_settings.max_header_list_size,
            qpack_max_table_capacity: self
                .local_settings
                .qpack_max_table_capacity,
            qpack_blocked_streams: self.local_settings.qpack_blocked_streams,
            grease,
        };

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        frame.to_bytes(&mut b)?;

        let off = b.off();

        if let Some(id) = self.control_stream_id {
            conn.stream_send(id, &d[..off], false)?;
        }

        Ok(())
    }

    fn process_control_stream(
        &mut self, conn: &mut super::Connection, stream_id: u64,
    ) -> Result<()> {
        if conn.stream_finished(stream_id) {
            conn.close(
                true,
                Error::ClosedCriticalStream.to_wire(),
                b"Critical stream closed.",
            )?;

            return Err(Error::ClosedCriticalStream);
        }

        match self.process_readable_stream(conn, stream_id) {
            Ok(_) => (),

            Err(Error::Done) => (),

            Err(e) => return Err(e),
        };

        if conn.stream_finished(stream_id) {
            conn.close(
                true,
                Error::ClosedCriticalStream.to_wire(),
                b"Critical stream closed.",
            )?;

            return Err(Error::ClosedCriticalStream);
        }

        Ok(())
    }

    fn process_readable_stream(
        &mut self, conn: &mut super::Connection, stream_id: u64,
    ) -> Result<(u64, Event)> {
        self.streams
            .entry(stream_id)
            .or_insert_with(|| stream::Stream::new(stream_id, false));

        // We need to get a fresh reference to the stream for each
        // iteration, to avoid borrowing `self` for the entire duration
        // of the loop, because we'll need to borrow it again in the
        // `State::FramePayload` case below.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                stream::State::StreamType => {
                    stream.try_fill_buffer(conn)?;

                    let varint = match stream.try_consume_varint() {
                        Ok(v) => v,

                        Err(_) => continue,
                    };

                    let ty = stream::Type::deserialize(varint)?;

                    if let Err(e) = stream.set_ty(ty) {
                        conn.close(true, e.to_wire(), b"")?;
                        return Err(e);
                    }

                    match &ty {
                        stream::Type::Control => {
                            // Only one control stream allowed.
                            if self.peer_control_stream_id.is_some() {
                                conn.close(
                                    true,
                                    Error::StreamCreationError.to_wire(),
                                    b"Received multiple control streams",
                                )?;

                                return Err(Error::StreamCreationError);
                            }

                            trace!(
                                "{} open peer's control stream {}",
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
                                    Error::StreamCreationError.to_wire(),
                                    b"Server received push stream.",
                                )?;

                                return Err(Error::StreamCreationError);
                            }
                        },

                        stream::Type::QpackEncoder => {
                            // Only one qpack encoder stream allowed.
                            if self.peer_qpack_streams.encoder_stream_id.is_some()
                            {
                                conn.close(
                                    true,
                                    Error::StreamCreationError.to_wire(),
                                    b"Received multiple QPACK encoder streams",
                                )?;

                                return Err(Error::StreamCreationError);
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
                                    Error::StreamCreationError.to_wire(),
                                    b"Received multiple QPACK decoder streams",
                                )?;

                                return Err(Error::StreamCreationError);
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

                stream::State::PushId => {
                    stream.try_fill_buffer(conn)?;

                    let varint = match stream.try_consume_varint() {
                        Ok(v) => v,

                        Err(_) => continue,
                    };

                    if let Err(e) = stream.set_push_id(varint) {
                        conn.close(true, e.to_wire(), b"")?;
                        return Err(e);
                    }
                },

                stream::State::FrameType => {
                    stream.try_fill_buffer(conn)?;

                    let varint = match stream.try_consume_varint() {
                        Ok(v) => v,

                        Err(_) => continue,
                    };

                    match stream.set_frame_type(varint) {
                        Err(Error::FrameUnexpected) => {
                            let msg = format!("Unexpected frame type {}", varint);

                            conn.close(
                                true,
                                Error::FrameUnexpected.to_wire(),
                                msg.as_bytes(),
                            )?;

                            return Err(Error::FrameUnexpected);
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

                stream::State::FramePayloadLen => {
                    stream.try_fill_buffer(conn)?;

                    let varint = match stream.try_consume_varint() {
                        Ok(v) => v,

                        Err(_) => continue,
                    };

                    if let Err(e) = stream.set_frame_payload_len(varint) {
                        conn.close(true, e.to_wire(), b"")?;
                        return Err(e);
                    }
                },

                stream::State::FramePayload => {
                    stream.try_fill_buffer(conn)?;

                    let frame = match stream.try_consume_frame() {
                        Ok(frame) => frame,

                        Err(Error::Done) => return Err(Error::Done),

                        Err(e) => {
                            conn.close(
                                true,
                                e.to_wire(),
                                b"Error handling frame.",
                            )?;

                            return Err(e);
                        },
                    };

                    match self.process_frame(conn, stream_id, frame) {
                        Ok(ev) => return Ok(ev),

                        Err(Error::Done) => (),

                        Err(e) => return Err(e),
                    };
                },

                stream::State::Data => {
                    return Ok((stream_id, Event::Data));
                },

                stream::State::QpackInstruction => {
                    let mut d = [0; 4096];

                    // Read data from the stream and discard immediately.
                    loop {
                        conn.stream_recv(stream_id, &mut d)?;
                    }
                },

                stream::State::Drain => {
                    // Discard incoming data on the stream.
                    conn.stream_shutdown(stream_id, crate::Shutdown::Read, 0)?;

                    break;
                },
            }
        }

        Err(Error::Done)
    }

    fn process_frame(
        &mut self, conn: &mut super::Connection, stream_id: u64,
        frame: frame::Frame,
    ) -> Result<(u64, Event)> {
        trace!(
            "{} rx frm {:?} stream={}",
            conn.trace_id(),
            frame,
            stream_id
        );

        match frame {
            frame::Frame::Settings {
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                ..
            } => {
                self.peer_settings = ConnectionSettings {
                    max_header_list_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                };
            },

            frame::Frame::Headers { header_block } => {
                if Some(stream_id) == self.peer_control_stream_id {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"HEADERS received on control stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // Use "infinite" as default value for max_header_list_size if
                // it is not configured by the application.
                let max_size = self
                    .local_settings
                    .max_header_list_size
                    .unwrap_or(std::u64::MAX);

                let headers = self
                    .qpack_decoder
                    .decode(&header_block[..], max_size)
                    .map_err(|e| match e {
                        qpack::Error::HeaderListTooLarge => Error::ExcessiveLoad,

                        _ => Error::QpackDecompressionFailed,
                    })?;

                let has_body = !conn.stream_finished(stream_id);

                return Ok((stream_id, Event::Headers {
                    list: headers,
                    has_body,
                }));
            },

            frame::Frame::Data { .. } => {
                if Some(stream_id) == self.peer_control_stream_id {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"DATA received on control stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // Do nothing. The Data event is returned separately.
            },

            frame::Frame::GoAway {
                stream_id: goaway_stream_id,
            } => {
                if self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"GOWAY received on server",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if Some(stream_id) != self.peer_control_stream_id {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"GOAWAY received on non-control stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if goaway_stream_id % 4 != 0 {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"GOAWAY received with ID of non-request stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // TODO: implement GOAWAY
            },

            frame::Frame::MaxPushId { push_id } => {
                if Some(stream_id) != self.peer_control_stream_id {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"MAX_PUSH_ID received on non-control stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if !self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"MAX_PUSH_ID received by client",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if push_id < self.max_push_id {
                    conn.close(
                        true,
                        Error::IdError.to_wire(),
                        b"MAX_PUSH_ID reduced limit",
                    )?;

                    return Err(Error::IdError);
                }

                self.max_push_id = push_id;
            },

            frame::Frame::PushPromise { .. } => {
                if self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"PUSH_PROMISE received by server",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if stream_id % 4 != 0 {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"PUSH_PROMISE received on non-request stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // TODO: implement more checks and PUSH_PROMISE event
            },

            frame::Frame::CancelPush { .. } => {
                if Some(stream_id) != self.peer_control_stream_id {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"CANCEL_PUSH received on non-control stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // TODO: implement CANCEL_PUSH frame
            },

            frame::Frame::Unknown => (),
        }

        Err(Error::Done)
    }
}

/// Generates an HTTP/3 GREASE variable length integer.
fn grease_value() -> u64 {
    let n = super::rand::rand_u64_uniform(148_764_065_110_560_899);
    31 * n + 33
}

#[doc(hidden)]
pub mod testing {
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
    /// available for any test that need to do unconventional things (such as
    /// bad behaviour that triggers errors).
    pub struct Session {
        pub pipe: testing::Pipe,
        pub client: Connection,
        pub server: Connection,

        buf: [u8; 65535],
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

            let h3_config = Config::new()?;
            Session::with_configs(&mut config, &h3_config)
        }

        pub fn with_configs(
            config: &mut crate::Config, h3_config: &Config,
        ) -> Result<Session> {
            Ok(Session {
                pipe: testing::Pipe::with_config(config)?,
                client: Connection::new(&h3_config, false)?,
                server: Connection::new(&h3_config, true)?,
                buf: [0; 65535],
            })
        }

        /// Do the HTTP/3 handshake so both ends are in sane initial state.
        pub fn handshake(&mut self) -> Result<()> {
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
        pub fn advance(&mut self) -> crate::Result<()> {
            self.pipe.advance(&mut self.buf)
        }

        /// Polls the client for events.
        pub fn poll_client(&mut self) -> Result<(u64, Event)> {
            self.client.poll(&mut self.pipe.client)
        }

        /// Polls the server for events.
        pub fn poll_server(&mut self) -> Result<(u64, Event)> {
            self.server.poll(&mut self.pipe.server)
        }

        /// Sends a request from client with default headers.
        ///
        /// On success it returns the newly allocated stream and the headers.
        pub fn send_request(&mut self, fin: bool) -> Result<(u64, Vec<Header>)> {
            let req = vec![
                Header::new(":method", "GET"),
                Header::new(":scheme", "https"),
                Header::new(":authority", "quic.tech"),
                Header::new(":path", "/test"),
                Header::new("user-agent", "quiche-test"),
            ];

            let stream =
                self.client.send_request(&mut self.pipe.client, &req, fin)?;

            self.advance().ok();

            Ok((stream, req))
        }

        /// Sends a response from server with default headers.
        ///
        /// On success it returns the headers.
        pub fn send_response(
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
        pub fn send_body_client(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.client
                .send_body(&mut self.pipe.client, stream, &bytes, fin)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Fetches DATA payload from the server.
        ///
        /// On success it returns the number of bytes received.
        pub fn recv_body_client(
            &mut self, stream: u64, buf: &mut [u8],
        ) -> Result<usize> {
            self.client.recv_body(&mut self.pipe.client, stream, buf)
        }

        /// Sends some default payload from server.
        ///
        /// On success it returns the payload.
        pub fn send_body_server(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.server
                .send_body(&mut self.pipe.server, stream, &bytes, fin)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Fetches DATA payload from the client.
        ///
        /// On success it returns the number of bytes received.
        pub fn recv_body_server(
            &mut self, stream: u64, buf: &mut [u8],
        ) -> Result<usize> {
            self.server.recv_body(&mut self.pipe.server, stream, buf)
        }

        /// Sends a single HTTP/3 frame from the client.
        pub fn send_frame_client(
            &mut self, frame: frame::Frame, stream_id: u64, fin: bool,
        ) -> Result<()> {
            let mut d = [42; 65535];

            let mut b = octets::OctetsMut::with_slice(&mut d);

            frame.to_bytes(&mut b)?;

            let off = b.off();
            self.pipe.client.stream_send(stream_id, &d[..off], fin)?;

            self.advance().ok();

            Ok(())
        }

        /// Sends a single HTTP/3 frame from the server.
        pub fn send_frame_server(
            &mut self, frame: frame::Frame, stream_id: u64, fin: bool,
        ) -> Result<()> {
            let mut d = [42; 65535];

            let mut b = octets::OctetsMut::with_slice(&mut d);

            frame.to_bytes(&mut b)?;

            let off = b.off();
            self.pipe.server.stream_send(stream_id, &d[..off], fin)?;

            self.advance().ok();

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::testing::*;

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

        let ev_headers = Event::Headers {
            list: req,
            has_body: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            has_body: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
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

        let ev_headers = Event::Headers {
            list: req,
            has_body: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, false).unwrap();

        let body = s.send_body_server(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            has_body: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with multiple DATA frames.
    fn request_no_body_response_many_chunks() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            has_body: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let total_data_frames = 4;

        let resp = s.send_response(stream, false).unwrap();

        for _ in 0..total_data_frames - 1 {
            s.send_body_server(stream, false).unwrap();
        }

        let body = s.send_body_server(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            has_body: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));

        for _ in 0..total_data_frames {
            assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
            assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));
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

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            has_body: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            has_body: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a request with multiple DATA frames, get a response with no body.
    fn request_many_chunks_response_no_body() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let total_data_frames = 4;

        for _ in 0..total_data_frames - 1 {
            s.send_body_client(stream, false).unwrap();
        }

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            has_body: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        for _ in 0..total_data_frames {
            assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
            assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        }

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            has_body: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a request with multiple DATA frames, get a response with one DATA
    /// frame.
    fn many_requests_many_chunks_response_one_chunk() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut reqs = Vec::new();

        let (stream1, req1) = s.send_request(false).unwrap();
        assert_eq!(stream1, 0);
        reqs.push(req1);

        let (stream2, req2) = s.send_request(false).unwrap();
        assert_eq!(stream2, 4);
        reqs.push(req2);

        let (stream3, req3) = s.send_request(false).unwrap();
        assert_eq!(stream3, 8);
        reqs.push(req3);

        let body = s.send_body_client(stream1, false).unwrap();
        s.send_body_client(stream2, false).unwrap();
        s.send_body_client(stream3, false).unwrap();

        let mut recv_buf = vec![0; body.len()];

        // Reverse order of writes.

        s.send_body_client(stream3, true).unwrap();
        s.send_body_client(stream2, true).unwrap();
        s.send_body_client(stream1, true).unwrap();

        for _ in 0..reqs.len() {
            let (stream, ev) = s.poll_server().unwrap();
            let ev_headers = Event::Headers {
                list: reqs[(stream / 4) as usize].clone(),
                has_body: true,
            };
            assert_eq!(ev, ev_headers);
            assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
            assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
            assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
            assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
            assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        }

        assert_eq!(s.poll_server(), Err(Error::Done));

        let mut resps = Vec::new();

        let resp1 = s.send_response(stream1, true).unwrap();
        resps.push(resp1);

        let resp2 = s.send_response(stream2, true).unwrap();
        resps.push(resp2);

        let resp3 = s.send_response(stream3, true).unwrap();
        resps.push(resp3);

        for _ in 0..resps.len() {
            let (stream, ev) = s.poll_client().unwrap();
            let ev_headers = Event::Headers {
                list: resps[(stream / 4) as usize].clone(),
                has_body: false,
            };
            assert_eq!(ev, ev_headers);
            assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        }

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Try to send DATA frames before HEADERS.
    fn body_response_before_headers() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();
        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            has_body: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        assert_eq!(
            s.send_body_server(stream, true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Try to send DATA frames on wrong streams, ensure the API returns an
    /// error before anything hits the transport layer.
    fn send_body_invalid_client_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        assert_eq!(s.send_body_client(0, true), Err(Error::FrameUnexpected));

        assert_eq!(
            s.send_body_client(s.client.control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.local_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.local_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(s.client.peer_control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.peer_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.peer_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );
    }

    #[test]
    /// Try to send DATA frames on wrong streams, ensure the API returns an
    /// error before anything hits the transport layer.
    fn send_body_invalid_server_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        assert_eq!(s.send_body_server(0, true), Err(Error::FrameUnexpected));

        assert_eq!(
            s.send_body_server(s.server.control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.local_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.local_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(s.server.peer_control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.peer_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.peer_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
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

        let (stream, req) = s.send_request(false).unwrap();

        s.send_frame_client(
            frame::Frame::MaxPushId { push_id: 2 },
            stream,
            false,
        )
        .unwrap();

        let ev_headers = Event::Headers {
            list: req,
            has_body: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::FrameUnexpected));
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

        assert_eq!(s.poll_server(), Err(Error::IdError));
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

        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
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

        let ev_headers = Event::Headers {
            list: req,
            has_body: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::FrameUnexpected));
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

        let (stream, req) = s.send_request(false).unwrap();

        s.send_frame_client(
            frame::Frame::CancelPush { push_id: 2 },
            stream,
            false,
        )
        .unwrap();

        let ev_headers = Event::Headers {
            list: req,
            has_body: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::FrameUnexpected));
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

        assert_eq!(s.poll_server(), Err(Error::FrameUnexpected));
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

        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Ensure quiche allocates streams for client and server roles as expected.
    fn uni_stream_local_counting() {
        let config = Config::new().unwrap();

        let h3_cln = Connection::new(&config, false).unwrap();
        assert_eq!(h3_cln.next_uni_stream_id, 2);

        let h3_srv = Connection::new(&config, true).unwrap();
        assert_eq!(h3_srv.next_uni_stream_id, 3);
    }

    #[test]
    /// Client opens multiple control streams, which is forbidden.
    fn open_multiple_control_streams() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let stream_id = s.client.next_uni_stream_id;

        let mut d = [42; 8];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        s.pipe
            .client
            .stream_send(
                stream_id,
                b.put_varint(stream::HTTP3_CONTROL_STREAM_TYPE_ID).unwrap(),
                false,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::StreamCreationError));
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
    /// Client closes QPACK stream, which is forbidden.
    fn close_qpack_stream() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut qpack_stream_closed = false;

        let stream_id = s.client.local_qpack_streams.encoder_stream_id.unwrap();
        let d = [0; 1];

        s.pipe.client.stream_send(stream_id, &d, false).unwrap();
        s.pipe.client.stream_send(stream_id, &d, true).unwrap();

        s.advance().ok();

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

    #[test]
    /// Client sends QPACK data.
    fn qpack_data() {
        // TODO: QPACK instructions are ignored until dynamic table support is
        // added so we just test that the data is safely ignored.
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let e_stream_id = s.client.local_qpack_streams.encoder_stream_id.unwrap();
        let d_stream_id = s.client.local_qpack_streams.decoder_stream_id.unwrap();
        let d = [0; 20];

        s.pipe.client.stream_send(e_stream_id, &d, false).unwrap();
        s.advance().ok();

        s.pipe.client.stream_send(d_stream_id, &d, false).unwrap();
        s.advance().ok();

        loop {
            match s.server.poll(&mut s.pipe.server) {
                Ok(_) => (),

                Err(Error::Done) => {
                    break;
                },

                Err(_) => {
                    panic!();
                },
            }
        }
    }

    #[test]
    /// Tests limits for the stream state buffer maximum size.
    fn max_state_buf_size() {
        // DATA frames don't consume the state buffer, so can be of any size.
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Ok((0, Event::Data)));

        // GREASE frames consume the state buffer, so need to be limited.
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(148_764_065_110_560_899).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::InternalError));
    }

    #[test]
    /// Tests that DATA frames are properly truncated depending on the request
    /// stream's outgoing flow control capacity.
    fn stream_backpressure() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let total_data_frames = 6;

        for _ in 0..total_data_frames {
            assert_eq!(
                s.client
                    .send_body(&mut s.pipe.client, stream, &bytes, false),
                Ok(bytes.len())
            );

            s.advance().ok();
        }

        assert_eq!(
            s.client.send_body(&mut s.pipe.client, stream, &bytes, true),
            Ok(bytes.len() - 2)
        );

        s.advance().ok();

        let mut recv_buf = vec![0; bytes.len()];

        let ev_headers = Event::Headers {
            list: req,
            has_body: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        for _ in 0..total_data_frames {
            assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
            assert_eq!(
                s.recv_body_server(stream, &mut recv_buf),
                Ok(bytes.len())
            );
        }

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(
            s.recv_body_server(stream, &mut recv_buf),
            Ok(bytes.len() - 2)
        );

        // Fin flag from last send_body() call was not sent as the buffer was
        // only partially written.
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Tests that the max header list size setting is enforced.
    fn request_max_header_size_limit() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(b"\x02h3").unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let mut h3_config = Config::new().unwrap();
        h3_config.set_max_header_list_size(65);

        let mut s = Session::with_configs(&mut config, &mut h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
            Header::new("aaaaaaa", "aaaaaaaa"),
        ];

        let stream = s
            .client
            .send_request(&mut s.pipe.client, &req, true)
            .unwrap();

        s.advance().ok();

        assert_eq!(stream, 0);

        assert_eq!(s.poll_server(), Err(Error::ExcessiveLoad));
    }

    #[test]
    /// Tests that Error::TransportError contains a transport error.
    fn transport_error() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let req = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
            Header::new("user-agent", "quiche-test"),
        ];

        // We need to open all streams in the same flight, so we can't use the
        // Session::send_request() method because it also calls advance(),
        // otherwise the server would send a MAX_STREAMS frame and the client
        // wouldn't hit the streams limit.
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(0));
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(4));
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(8));
        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Ok(12)
        );
        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Ok(16)
        );

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Err(Error::TransportError(crate::Error::StreamLimit))
        );
    }

    #[test]
    /// Tests that calling poll() after an error occured does nothing.
    fn poll_after_error() {
        // DATA frames don't consume the state buffer, so can be of any size.
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Ok((0, Event::Data)));

        // GREASE frames consume the state buffer, so need to be limited.
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(148_764_065_110_560_899).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::InternalError));

        // Try to call poll() again after an error occurred.
        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::Done));
    }

    #[test]
    /// Tests that we limit sending HEADERS based on the stream capacity.
    fn headers_blocked() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(b"\x02h3").unwrap();
        config.set_initial_max_data(70);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let mut h3_config = Config::new().unwrap();

        let mut s = Session::with_configs(&mut config, &mut h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
        ];

        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(0));

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Err(Error::StreamBlocked)
        );

        s.advance().ok();

        // Once the server gives flow control credits back, we can send the
        // request.
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(4));
    }

    #[test]
    /// Tests that blocked 0-length DATA writes are reported correctly.
    fn zero_length_data_blocked() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(b"\x02h3").unwrap();
        config.set_initial_max_data(70);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let mut h3_config = Config::new().unwrap();

        let mut s = Session::with_configs(&mut config, &mut h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "quic.tech"),
            Header::new(":path", "/test"),
        ];

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, false),
            Ok(0)
        );

        assert_eq!(
            s.client.send_body(&mut s.pipe.client, 0, b"", true),
            Err(Error::Done)
        );

        s.advance().ok();

        // Once the server gives flow control credits back, we can send the body.
        assert_eq!(s.client.send_body(&mut s.pipe.client, 0, b"", true), Ok(0));
    }
}

mod ffi;
mod frame;
#[doc(hidden)]
pub mod qpack;
mod stream;
