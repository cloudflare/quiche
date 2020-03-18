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

//! 🥧 Savoury implementation of the QUIC transport protocol and HTTP/3.
//!
//! [quiche] is an implementation of the QUIC transport protocol and HTTP/3 as
//! specified by the [IETF]. It provides a low level API for processing QUIC
//! packets and handling connection state. The application is responsible for
//! providing I/O (e.g. sockets handling) as well as an event loop with support
//! for timers.
//!
//! [quiche]: https://github.com/cloudflare/quiche/
//! [ietf]: https://quicwg.org/
//!
//! ## Connection setup
//!
//! The first step in establishing a QUIC connection using quiche is creating a
//! configuration object:
//!
//! ```
//! let config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! This is shared among multiple connections and can be used to configure a
//! QUIC endpoint.
//!
//! On the client-side the [`connect()`] utility function can be used to create
//! a new connection, while [`accept()`] is for servers:
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let server_name = "quic.tech";
//! # let scid = [0xba; 16];
//! // Client connection.
//! let conn = quiche::connect(Some(&server_name), &scid, &mut config)?;
//!
//! // Server connection.
//! let conn = quiche::accept(&scid, None, &mut config)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ## Handling incoming packets
//!
//! Using the connection's [`recv()`] method the application can process
//! incoming packets that belong to that connection from the network:
//!
//! ```no_run
//! # let mut buf = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config)?;
//! loop {
//!     let read = socket.recv(&mut buf).unwrap();
//!
//!     let read = match conn.recv(&mut buf[..read]) {
//!         Ok(v) => v,
//!
//!         Err(quiche::Error::Done) => {
//!             // Done reading.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     };
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ## Generating outgoing packets
//!
//! Outgoing packet are generated using the connection's [`send()`] method
//! instead:
//!
//! ```no_run
//! # let mut out = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config)?;
//! loop {
//!     let write = match conn.send(&mut out) {
//!         Ok(v) => v,
//!
//!         Err(quiche::Error::Done) => {
//!             // Done writing.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     };
//!
//!     socket.send(&out[..write]).unwrap();
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! When packets are sent, the application is responsible for maintaining a
//! timer to react to time-based connection events. The timer expiration can be
//! obtained using the connection's [`timeout()`] method.
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config)?;
//! let timeout = conn.timeout();
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application is responsible for providing a timer implementation, which
//! can be specific to the operating system or networking framework used. When
//! a timer expires, the connection's [`on_timeout()`] method should be called,
//! after which additional packets might need to be sent on the network:
//!
//! ```no_run
//! # let mut out = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config)?;
//! // Timeout expired, handle it.
//! conn.on_timeout();
//!
//! // Send more packets as needed after timeout.
//! loop {
//!     let write = match conn.send(&mut out) {
//!         Ok(v) => v,
//!
//!         Err(quiche::Error::Done) => {
//!             // Done writing.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     };
//!
//!     socket.send(&out[..write]).unwrap();
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ## Sending and receiving stream data
//!
//! After some back and forth, the connection will complete its handshake and
//! will be ready for sending or receiving application data.
//!
//! Data can be sent on a stream by using the [`stream_send()`] method:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config)?;
//! if conn.is_established() {
//!     // Handshake completed, send some data on stream 0.
//!     conn.stream_send(0, b"hello", true)?;
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application can check whether there are any readable streams by using
//! the connection's [`readable()`] method, which returns an iterator over all
//! the streams that have outstanding data to read.
//!
//! The [`stream_recv()`] method can then be used to retrieve the application
//! data from the readable stream:
//!
//! ```no_run
//! # let mut buf = [0; 512];
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config)?;
//! if conn.is_established() {
//!     // Iterate over readable streams.
//!     for stream_id in conn.readable() {
//!         // Stream is readable, read until there's no more data.
//!         while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
//!             println!("Got {} bytes on stream {}", read, stream_id);
//!         }
//!     }
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ## HTTP/3
//!
//! The quiche [HTTP/3 module] provides a high level API for sending and
//! receiving HTTP requests and responses on top of the QUIC transport protocol.
//!
//! [`connect()`]: fn.connect.html
//! [`accept()`]: fn.accept.html
//! [`recv()`]: struct.Connection.html#method.recv
//! [`send()`]: struct.Connection.html#method.send
//! [`timeout()`]: struct.Connection.html#method.timeout
//! [`on_timeout()`]: struct.Connection.html#method.on_timeout
//! [`stream_send()`]: struct.Connection.html#method.stream_send
//! [`readable()`]: struct.Connection.html#method.readable
//! [`stream_recv()`]: struct.Connection.html#method.stream_recv
//! [HTTP/3 module]: h3/index.html
//!
//! ## Congestion Control
//!
//! The quiche library provides a high-level API for configuring which
//! congestion control algorithm to use throughout the QUIC connection.
//!
//! When a QUIC connection is created, the application can optionally choose
//! which CC algorithm to use. See [`CongestionControlAlgorithm`] for currently
//! available congestion control algorithms.
//!
//! For example:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Reno);
//! ```
//!
//! Alternatively, you can configure the congestion control algorithm to use
//! by its name.
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! config.set_cc_algorithm_name("reno").unwrap();
//! ```
//!
//! Note that the CC algorithm should be configured before calling [`connect()`]
//! or [`accept()`]. Otherwise the connection will use a default CC algorithm.
//!
//! [`CongestionControlAlgorithm`]: cc/enum.Algorithm.html

#![allow(improper_ctypes)]
#![warn(missing_docs)]

#[macro_use]
extern crate log;

use std::cmp;
use std::time;

use std::pin::Pin;
use std::str::FromStr;

/// The current QUIC wire version.
pub const PROTOCOL_VERSION: u32 = PROTOCOL_VERSION_DRAFT27;

/// Supported QUIC versions.
///
/// Note that the older ones might not be fully supported.
const PROTOCOL_VERSION_DRAFT27: u32 = 0xff00_001b;
const PROTOCOL_VERSION_DRAFT25: u32 = 0xff00_0019;
const PROTOCOL_VERSION_DRAFT24: u32 = 0xff00_0018;
const PROTOCOL_VERSION_DRAFT23: u32 = 0xff00_0017;

/// The maximum length of a connection ID.
pub const MAX_CONN_ID_LEN: usize = crate::packet::MAX_CID_LEN as usize;

/// The minimum length of Initial packets sent by a client.
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

#[cfg(not(feature = "fuzzing"))]
const PAYLOAD_MIN_LEN: usize = 4;

#[cfg(feature = "fuzzing")]
// Due to the fact that in fuzzing mode we use a zero-length AEAD tag (which
// would normally be 16 bytes), we need to adjust the minimum payload size to
// account for that.
const PAYLOAD_MIN_LEN: usize = 20;

const MAX_AMPLIFICATION_FACTOR: usize = 3;

/// A specialized [`Result`] type for quiche operations.
///
/// This type is used throughout quiche's public API for any operation that
/// can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A QUIC error.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum Error {
    /// There is no more work to do.
    Done               = -1,

    /// The provided buffer is too short.
    BufferTooShort     = -2,

    /// The provided packet cannot be parsed because its version is unknown.
    UnknownVersion     = -3,

    /// The provided packet cannot be parsed because it contains an invalid
    /// frame.
    InvalidFrame       = -4,

    /// The provided packet cannot be parsed.
    InvalidPacket      = -5,

    /// The operation cannot be completed because the connection is in an
    /// invalid state.
    InvalidState       = -6,

    /// The operation cannot be completed because the stream is in an
    /// invalid state.
    InvalidStreamState = -7,

    /// The peer's transport params cannot be parsed.
    InvalidTransportParam = -8,

    /// A cryptographic operation failed.
    CryptoFail         = -9,

    /// The TLS handshake failed.
    TlsFail            = -10,

    /// The peer violated the local flow control limits.
    FlowControl        = -11,

    /// The peer violated the local stream limits.
    StreamLimit        = -12,

    /// The received data exceeds the stream's final size.
    FinalSize          = -13,

    /// Error in congestion control.
    CongestionControl  = -14,
}

impl Error {
    fn to_wire(self) -> u64 {
        match self {
            Error::Done => 0x0,
            Error::InvalidFrame => 0x7,
            Error::InvalidStreamState => 0x5,
            Error::InvalidTransportParam => 0x8,
            Error::CryptoFail => 0x100,
            Error::TlsFail => 0x100,
            Error::FlowControl => 0x3,
            Error::StreamLimit => 0x4,
            Error::FinalSize => 0x6,
            _ => 0xa,
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
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

/// The stream's side to shutdown.
///
/// This should be used when calling [`stream_shutdown()`].
///
/// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
#[repr(C)]
pub enum Shutdown {
    /// Stop receiving stream data.
    Read  = 0,

    /// Stop sending stream data.
    Write = 1,
}

/// Stores configuration shared between multiple connections.
pub struct Config {
    local_transport_params: TransportParams,

    version: u32,

    tls_ctx: tls::Context,

    application_protos: Vec<Vec<u8>>,

    grease: bool,

    cc_algorithm: CongestionControlAlgorithm,
}

impl Config {
    /// Creates a config object with the given version.
    ///
    /// ## Examples:
    ///
    /// ```
    /// let config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn new(version: u32) -> Result<Config> {
        let tls_ctx = tls::Context::new()?;

        Ok(Config {
            local_transport_params: TransportParams::default(),
            version,
            tls_ctx,
            application_protos: Vec::new(),
            grease: true,
            cc_algorithm: recovery::CongestionControlAlgorithm::Reno,
        })
    }

    /// Configures the given certificate chain.
    ///
    /// The content of `file` is parsed as a PEM-encoded leaf certificate,
    /// followed by optional intermediate certificates.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_cert_chain_from_pem_file("/path/to/cert.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_cert_chain_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.use_certificate_chain_file(file)
    }

    /// Configures the given private key.
    ///
    /// The content of `file` is parsed as a PEM-encoded private key.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_priv_key_from_pem_file("/path/to/key.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_priv_key_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.use_privkey_file(file)
    }

    /// Configures whether to verify the peer's certificate.
    ///
    /// The default value is `true` for client connections, and `false` for
    /// server ones.
    pub fn verify_peer(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify);
    }

    /// Configures whether to send GREASE values.
    ///
    /// The default value is `true`.
    pub fn grease(&mut self, grease: bool) {
        self.grease = grease;
    }

    /// Enables logging of secrets.
    ///
    /// A connection's cryptographic secrets will be logged in the [keylog]
    /// format in the file pointed to by the `SSLKEYLOGFILE` environment
    /// variable.
    ///
    /// [keylog]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    pub fn log_keys(&mut self) {
        self.tls_ctx.enable_keylog();
    }

    /// Enables sending or receiving early data.
    pub fn enable_early_data(&mut self) {
        self.tls_ctx.set_early_data_enabled(true);
    }

    /// Configures the list of supported application protocols.
    ///
    /// The list of protocols `protos` must be in wire-format (i.e. a series
    /// of non-empty, 8-bit length-prefixed strings).
    ///
    /// On the client this configures the list of protocols to send to the
    /// server as part of the ALPN extension.
    ///
    /// On the server this configures the list of supported protocols to match
    /// against the client-supplied list.
    ///
    /// Applications must set a value, but no default is provided.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_application_protos(b"\x08http/1.1\x08http/0.9")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_application_protos(&mut self, protos: &[u8]) -> Result<()> {
        let mut protos = protos.to_vec();

        let mut b = octets::Octets::with_slice(&mut protos);

        let mut protos_list = Vec::new();

        while let Ok(proto) = b.get_bytes_with_u8_length() {
            protos_list.push(proto.to_vec());
        }

        self.application_protos = protos_list;

        self.tls_ctx.set_alpn(&self.application_protos)
    }

    /// Sets the `max_idle_timeout` transport parameter.
    ///
    /// The default value is infinite, that is, no timeout is used.
    pub fn set_max_idle_timeout(&mut self, v: u64) {
        self.local_transport_params.max_idle_timeout = v;
    }

    /// Sets the `max_packet_size transport` parameter.
    ///
    /// The default value is `65527`.
    pub fn set_max_packet_size(&mut self, v: u64) {
        self.local_transport_params.max_packet_size = v;
    }

    /// Sets the `initial_max_data` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for the whole connection (that
    /// is, data that is not yet read by the application) and will allow more
    /// data to be received as the buffer is consumed by the application.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.local_transport_params.initial_max_data = v;
    }

    /// Sets the `initial_max_stream_data_bidi_local` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each locally-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_local = v;
    }

    /// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each remotely-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_remote = v;
    }

    /// Sets the `initial_max_stream_data_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each unidirectional stream
    /// (that is, data that is not yet read by the application) and will allow
    /// more data to be received as the buffer is consumed by the application.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_stream_data_uni = v;
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated bidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// A bidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown, and all outgoing data has
    /// been acked by the peer (up to the `fin` offset) or the stream's write
    /// direction has been shutdown.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_bidi = v;
    }

    /// Sets the `initial_max_streams_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated unidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// A unidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_uni = v;
    }

    /// Sets the `ack_delay_exponent` transport parameter.
    ///
    /// The default value is `3`.
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.local_transport_params.ack_delay_exponent = v;
    }

    /// Sets the `max_ack_delay` transport parameter.
    ///
    /// The default value is `25`.
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.local_transport_params.max_ack_delay = v;
    }

    /// Sets the `disable_active_migration` transport parameter.
    ///
    /// The default value is `false`.
    pub fn set_disable_active_migration(&mut self, v: bool) {
        self.local_transport_params.disable_active_migration = v;
    }

    /// Sets the congestion control algorithm used by string.
    ///
    /// The default value is `reno`. On error `Error::CongestionControl`
    /// will be returned.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_cc_algorithm_name("reno");
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_cc_algorithm_name(&mut self, name: &str) -> Result<()> {
        self.cc_algorithm = CongestionControlAlgorithm::from_str(name)?;

        Ok(())
    }

    /// Sets the congestion control algorithm used.
    ///
    /// The default value is `quiche::CongestionControlAlgorithm::Reno`.
    pub fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }
}

/// A QUIC connection.
pub struct Connection {
    /// QUIC wire version used for the connection.
    version: u32,

    /// Peer's connection ID.
    dcid: Vec<u8>,

    /// Local connection ID.
    scid: Vec<u8>,

    /// Unique opaque ID for the connection that can be used for logging.
    trace_id: String,

    /// Packet number spaces.
    pkt_num_spaces: [packet::PktNumSpace; packet::EPOCH_COUNT],

    /// Peer's transport parameters.
    peer_transport_params: TransportParams,

    /// Local transport parameters.
    local_transport_params: TransportParams,

    /// TLS handshake state.
    handshake: tls::Handshake,

    /// Loss recovery and congestion control state.
    recovery: recovery::Recovery,

    /// List of supported application protocols.
    application_protos: Vec<Vec<u8>>,

    /// Total number of received packets.
    recv_count: usize,

    /// Total number of sent packets.
    sent_count: usize,

    /// Total number of bytes received from the peer.
    rx_data: u64,

    /// Local flow control limit for the connection.
    max_rx_data: u64,

    /// Updated local flow control limit for the connection. This is used to
    /// trigger sending MAX_DATA frames after a certain threshold.
    max_rx_data_next: u64,

    /// Total number of bytes sent to the peer.
    tx_data: u64,

    /// Peer's flow control limit for the connection.
    max_tx_data: u64,

    /// Total number of bytes the server can send before the peer's address
    /// is verified.
    max_send_bytes: usize,

    /// Streams map, indexed by stream ID.
    streams: stream::StreamMap,

    /// Peer's original connection ID. Used by the client during stateless
    /// retry to validate the server's transport parameter.
    odcid: Option<Vec<u8>>,

    /// Received address verification token.
    token: Option<Vec<u8>>,

    /// Error code to be sent to the peer in CONNECTION_CLOSE.
    error: Option<u64>,

    /// Error code to be sent to the peer in APPLICATION_CLOSE.
    app_error: Option<u64>,

    /// Error reason to be sent to the peer in APPLICATION_CLOSE.
    app_reason: Vec<u8>,

    /// Received path challenge.
    challenge: Option<Vec<u8>>,

    /// Idle timeout expiration time.
    idle_timer: Option<time::Instant>,

    /// Draining timeout expiration time.
    draining_timer: Option<time::Instant>,

    /// Whether this is a server-side connection.
    is_server: bool,

    /// Whether the initial secrets have been derived.
    derived_initial_secrets: bool,

    /// Whether a version negotiation packet has already been received. Only
    /// relevant for client connections.
    did_version_negotiation: bool,

    /// Whether a retry packet has already been received. Only relevant for
    /// client connections.
    did_retry: bool,

    /// Whether the peer already updated its connection ID.
    got_peer_conn_id: bool,

    /// Whether the peer's address has been verified.
    verified_peer_address: bool,

    /// Whether the peer's transport parameters were parsed.
    parsed_peer_transport_params: bool,

    /// Whether the HANDSHAKE_DONE has been sent.
    handshake_done_sent: bool,

    /// Whether the connection handshake has been confirmed.
    handshake_confirmed: bool,

    /// Whether an ack-eliciting packet has been sent since last receiving a
    /// packet.
    ack_eliciting_sent: bool,

    /// Whether the connection is closed.
    closed: bool,

    /// Whether to send GREASE.
    grease: bool,
}

/// Creates a new server-side connection.
///
/// The `scid` parameter represents the server's source connection ID, while
/// the optional `odcid` parameter represents the original destination ID the
/// client sent before a stateless retry (this is only required when using
/// the [`retry()`] function).
///
/// [`retry()`]: fn.retry.html
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let scid = [0xba; 16];
/// let conn = quiche::accept(&scid, None, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
pub fn accept(
    scid: &[u8], odcid: Option<&[u8]>, config: &mut Config,
) -> Result<Pin<Box<Connection>>> {
    let conn = Connection::new(scid, odcid, config, true)?;

    Ok(conn)
}

/// Creates a new client-side connection.
///
/// The `scid` parameter is used as the connection's source connection ID,
/// while the optional `server_name` parameter is used to verify the peer's
/// certificate.
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let server_name = "quic.tech";
/// # let scid = [0xba; 16];
/// let conn = quiche::connect(Some(&server_name), &scid, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
pub fn connect(
    server_name: Option<&str>, scid: &[u8], config: &mut Config,
) -> Result<Pin<Box<Connection>>> {
    let conn = Connection::new(scid, None, config, false)?;

    if let Some(server_name) = server_name {
        conn.handshake.set_host_name(server_name)?;
    }

    Ok(conn)
}

/// Writes a version negotiation packet.
///
/// The `scid` and `dcid` parameters are the source connection ID and the
/// destination connection ID extracted from the received client's Initial
/// packet that advertises an unsupported version.
///
/// ## Examples:
///
/// ```no_run
/// # let mut buf = [0; 512];
/// # let mut out = [0; 512];
/// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
/// let (len, src) = socket.recv_from(&mut buf).unwrap();
///
/// let hdr =
///     quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)?;
///
/// if hdr.version != quiche::PROTOCOL_VERSION {
///     let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
///     socket.send_to(&out[..len], &src).unwrap();
/// }
/// # Ok::<(), quiche::Error>(())
/// ```
pub fn negotiate_version(
    scid: &[u8], dcid: &[u8], out: &mut [u8],
) -> Result<usize> {
    packet::negotiate_version(scid, dcid, out)
}

/// Writes a stateless retry packet.
///
/// The `scid` and `dcid` parameters are the source connection ID and the
/// destination connection ID extracted from the received client's Initial
/// packet, while `new_scid` is the server's new source connection ID and
/// `token` is the address validation token the client needs to echo back.
///
/// The application is responsible for generating the address validation
/// token to be sent to the client, and verifying tokens sent back by the
/// client. The generated token should include the `dcid` parameter, such
/// that it can be later extracted from the token and passed to the
/// [`accept()`] function as its `odcid` parameter.
///
/// [`accept()`]: fn.accept.html
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let mut buf = [0; 512];
/// # let mut out = [0; 512];
/// # let scid = [0xba; 16];
/// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
/// # fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
/// #     vec![]
/// # }
/// # fn validate_token<'a>(src: &std::net::SocketAddr, token: &'a [u8]) -> Option<&'a [u8]> {
/// #     None
/// # }
/// let (len, src) = socket.recv_from(&mut buf).unwrap();
///
/// let hdr = quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)?;
///
/// let token = hdr.token.as_ref().unwrap();
///
/// // No token sent by client, create a new one.
/// if token.is_empty() {
///     let new_token = mint_token(&hdr, &src);
///
///     let len = quiche::retry(
///         &hdr.scid, &hdr.dcid, &scid, &new_token, &mut out,
///     )?;
///
///     socket.send_to(&out[..len], &src).unwrap();
///     return Ok(());
/// }
///
/// // Client sent token, validate it.
/// let odcid = validate_token(&src, token);
///
/// if odcid == None {
///     // Invalid address validation token.
///     return Ok(());
/// }
///
/// let conn = quiche::accept(&scid, odcid, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
pub fn retry(
    scid: &[u8], dcid: &[u8], new_scid: &[u8], token: &[u8], out: &mut [u8],
) -> Result<usize> {
    packet::retry(scid, dcid, new_scid, token, out)
}

/// Returns true if the given protocol version is supported.
pub fn version_is_supported(version: u32) -> bool {
    match version {
        PROTOCOL_VERSION_DRAFT27 |
        PROTOCOL_VERSION_DRAFT25 |
        PROTOCOL_VERSION_DRAFT24 |
        PROTOCOL_VERSION_DRAFT23 => true,

        _ => false,
    }
}

/// Pushes a frame to the output packet if there is enough space.
///
/// Returns `true` on success, `false` otherwise. In case of failure it means
/// there is no room to add the frame in the packet. You may retry to add the
/// frame later.
macro_rules! push_frame_to_pkt {
    ($frames:expr, $frame:expr, $payload_len: expr, $left:expr) => {{
        if $frame.wire_len() <= $left {
            $payload_len += $frame.wire_len();
            $left -= $frame.wire_len();

            $frames.push($frame);

            true
        } else {
            false
        }
    }};
}

impl Connection {
    fn new(
        scid: &[u8], odcid: Option<&[u8]>, config: &mut Config, is_server: bool,
    ) -> Result<Pin<Box<Connection>>> {
        let tls = config.tls_ctx.new_handshake()?;
        Connection::with_tls(scid, odcid, config, tls, is_server)
    }

    fn with_tls(
        scid: &[u8], odcid: Option<&[u8]>, config: &mut Config,
        tls: tls::Handshake, is_server: bool,
    ) -> Result<Pin<Box<Connection>>> {
        let max_rx_data = config.local_transport_params.initial_max_data;

        let scid_as_hex: Vec<String> =
            scid.iter().map(|b| format!("{:02x}", b)).collect();

        let mut conn = Box::pin(Connection {
            version: config.version,

            dcid: Vec::new(),
            scid: scid.to_vec(),

            trace_id: scid_as_hex.join(""),

            pkt_num_spaces: [
                packet::PktNumSpace::new(),
                packet::PktNumSpace::new(),
                packet::PktNumSpace::new(),
            ],

            peer_transport_params: TransportParams::default(),

            local_transport_params: config.local_transport_params.clone(),

            handshake: tls,

            recovery: recovery::Recovery::new(&config),

            application_protos: config.application_protos.clone(),

            recv_count: 0,
            sent_count: 0,

            rx_data: 0,
            max_rx_data,
            max_rx_data_next: max_rx_data,

            tx_data: 0,
            max_tx_data: 0,

            max_send_bytes: 0,

            streams: stream::StreamMap::new(
                config.local_transport_params.initial_max_streams_bidi,
                config.local_transport_params.initial_max_streams_uni,
            ),

            odcid: None,

            token: None,

            error: None,

            app_error: None,
            app_reason: Vec::new(),

            challenge: None,

            idle_timer: None,

            draining_timer: None,

            is_server,

            derived_initial_secrets: false,

            did_version_negotiation: false,

            did_retry: false,

            got_peer_conn_id: false,

            // If we did stateless retry assume the peer's address is verified.
            verified_peer_address: odcid.is_some(),

            parsed_peer_transport_params: false,

            handshake_done_sent: false,

            handshake_confirmed: false,

            ack_eliciting_sent: false,

            closed: false,

            grease: config.grease,
        });

        if let Some(odcid) = odcid {
            conn.local_transport_params.original_connection_id =
                Some(odcid.to_vec());
        }

        conn.handshake.init(&conn)?;

        // Derive initial secrets for the client. We can do this here because
        // we already generated the random destination connection ID.
        if !is_server {
            let mut dcid = [0; 16];
            rand::rand_bytes(&mut dcid[..]);

            let (aead_open, aead_seal) =
                crypto::derive_initial_key_material(&dcid, conn.is_server)?;

            conn.dcid.extend_from_slice(&dcid);

            conn.pkt_num_spaces[packet::EPOCH_INITIAL].crypto_open =
                Some(aead_open);
            conn.pkt_num_spaces[packet::EPOCH_INITIAL].crypto_seal =
                Some(aead_seal);

            conn.derived_initial_secrets = true;
        }

        Ok(conn)
    }

    /// Processes QUIC packets received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned, or [`Done`]. On error the connection will be closed by
    /// calling [`close()`] with the appropriate error code.
    ///
    /// Coalesced packets will be processed as necessary.
    ///
    /// Note that the contents of the input buffer `buf` might be modified by
    /// this function due to, for example, in-place decryption.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`close()`]: struct.Connection.html#method.close
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = [0xba; 16];
    /// # let mut conn = quiche::accept(&scid, None, &mut config)?;
    /// loop {
    ///     let read = socket.recv(&mut buf).unwrap();
    ///
    ///     let read = match conn.recv(&mut buf[..read]) {
    ///         Ok(v) => v,
    ///
    ///         Err(quiche::Error::Done) => {
    ///             // Done reading.
    ///             break;
    ///         },
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();

        let mut done = 0;
        let mut left = len;

        // Process coalesced packets.
        while left > 0 {
            let read = match self.recv_single(&mut buf[len - left..len]) {
                Ok(v) => v,

                Err(Error::Done) => return Err(Error::Done),

                Err(e) => {
                    // In case of error processing the incoming packet, close
                    // the connection.
                    self.close(false, e.to_wire(), b"").ok();
                    return Err(e);
                },
            };

            done += read;
            left -= read;
        }

        // Keep track of how many bytes we received from the client, so we
        // can limit bytes sent back before address validation, to a multiple
        // of this. The limit needs to be increased early on, so that if there
        // is an error there is enough credit to send a CONNECTION_CLOSE.
        //
        // It doesn't matter if the packets received were valid or not, we only
        // need to track the total amount of bytes received.
        if !self.verified_peer_address {
            self.max_send_bytes += buf.len() * MAX_AMPLIFICATION_FACTOR;
        }

        Ok(done)
    }

    /// Processes a single QUIC packet received from the peer.
    fn recv_single(&mut self, buf: &mut [u8]) -> Result<usize> {
        let now = time::Instant::now();

        if buf.is_empty() {
            return Err(Error::Done);
        }

        if self.draining_timer.is_some() {
            return Err(Error::Done);
        }

        let is_closing = self.error.is_some() || self.app_error.is_some();

        if is_closing {
            return Err(Error::Done);
        }

        let mut b = octets::Octets::with_slice(buf);

        let mut hdr = Header::from_bytes(&mut b, self.scid.len())
            .map_err(|e| drop_pkt_on_err(e, self.recv_count, &self.trace_id))?;

        if hdr.ty == packet::Type::VersionNegotiation {
            // Version negotiation packets can only be sent by the server.
            if self.is_server {
                return Err(Error::Done);
            }

            // Ignore duplicate version negotiation.
            if self.did_version_negotiation {
                return Err(Error::Done);
            }

            if hdr.dcid != self.scid {
                return Err(Error::Done);
            }

            if hdr.scid != self.dcid {
                return Err(Error::Done);
            }

            trace!("{} rx pkt {:?}", self.trace_id, hdr);

            let versions = hdr.versions.ok_or(Error::Done)?;

            match versions.iter().filter(|v| version_is_supported(**v)).max() {
                Some(v) => self.version = *v,

                None => {
                    // We don't support any of the versions offered.
                    //
                    // While a man-in-the-middle attacker might be able to
                    // inject a version negotiation packet that triggers this
                    // failure, the window of opportunity is very small and
                    // this error is quite useful for debugging, so don't just
                    // ignore the packet.
                    return Err(Error::UnknownVersion);
                },
            };

            self.did_version_negotiation = true;

            // Reset connection state to force sending another Initial packet.
            self.got_peer_conn_id = false;
            self.recovery.drop_unacked_data(packet::EPOCH_INITIAL);
            self.pkt_num_spaces[packet::EPOCH_INITIAL].clear();
            self.handshake.clear()?;

            // Encode transport parameters again, as the new version might be
            // using a different format.
            let mut raw_params = [0; 128];

            let raw_params = TransportParams::encode(
                &self.local_transport_params,
                self.version,
                self.is_server,
                &mut raw_params,
            )?;

            self.handshake.set_quic_transport_params(raw_params)?;

            return Err(Error::Done);
        }

        if hdr.ty == packet::Type::Retry {
            // Retry packets can only be sent by the server.
            if self.is_server {
                return Err(Error::Done);
            }

            // Ignore duplicate retry.
            if self.did_retry {
                return Err(Error::Done);
            }

            // Check if Retry packet is valid.
            if packet::verify_retry_integrity(&b, &self.dcid).is_err() {
                return Err(Error::Done);
            }

            trace!("{} rx pkt {:?}", self.trace_id, hdr);

            self.token = hdr.token;
            self.did_retry = true;

            // Remember peer's new connection ID.
            self.odcid = Some(self.dcid.clone());

            self.dcid.resize(hdr.scid.len(), 0);
            self.dcid.copy_from_slice(&hdr.scid);

            // Derive Initial secrets using the new connection ID.
            let (aead_open, aead_seal) =
                crypto::derive_initial_key_material(&hdr.scid, self.is_server)?;

            self.pkt_num_spaces[packet::EPOCH_INITIAL].crypto_open =
                Some(aead_open);
            self.pkt_num_spaces[packet::EPOCH_INITIAL].crypto_seal =
                Some(aead_seal);

            // Reset connection state to force sending another Initial packet.
            self.got_peer_conn_id = false;
            self.recovery.drop_unacked_data(packet::EPOCH_INITIAL);
            self.pkt_num_spaces[packet::EPOCH_INITIAL].clear();
            self.handshake.clear()?;

            return Err(Error::Done);
        }

        // Discard 1-RTT packets received before handshake is completed (even
        // if the frames are not immediately processed) to avoid potential side
        // effects.
        //
        // TODO: buffer packets instead of discarding as an optimization.
        if hdr.ty == packet::Type::Short && !self.is_established() {
            return Ok(b.len());
        }

        if self.is_server && !self.did_version_negotiation {
            if !version_is_supported(hdr.version) {
                return Err(Error::UnknownVersion);
            }

            self.version = hdr.version;
            self.did_version_negotiation = true;

            // Encode transport parameters again, as the new version might be
            // using a different format.
            let mut raw_params = [0; 128];

            let raw_params = TransportParams::encode(
                &self.local_transport_params,
                self.version,
                self.is_server,
                &mut raw_params,
            )?;

            self.handshake.set_quic_transport_params(raw_params)?;
        }

        if hdr.ty != packet::Type::Short && hdr.version != self.version {
            // At this point version negotiation was already performed, so
            // ignore packets that don't match the connection's version.
            return Err(Error::Done);
        }

        // Long header packets have an explicit payload length, but short
        // packets don't so just use the remaining capacity in the buffer.
        let payload_len = if hdr.ty == packet::Type::Short {
            b.cap()
        } else {
            b.get_varint()? as usize
        };

        if b.cap() < payload_len {
            trace!("{} payload length mismatch", self.trace_id);
            return Err(Error::Done);
        }

        let header_len = b.off();

        if !self.is_server && !self.got_peer_conn_id {
            // Replace the randomly generated destination connection ID with
            // the one supplied by the server.
            self.dcid.resize(hdr.scid.len(), 0);
            self.dcid.copy_from_slice(&hdr.scid);

            self.got_peer_conn_id = true;
        }

        // Derive initial secrets on the server.
        if !self.derived_initial_secrets {
            let (aead_open, aead_seal) =
                crypto::derive_initial_key_material(&hdr.dcid, self.is_server)?;

            self.pkt_num_spaces[packet::EPOCH_INITIAL].crypto_open =
                Some(aead_open);
            self.pkt_num_spaces[packet::EPOCH_INITIAL].crypto_seal =
                Some(aead_seal);

            self.derived_initial_secrets = true;

            self.dcid.extend_from_slice(&hdr.scid);
            self.got_peer_conn_id = true;
        }

        // Select packet number space epoch based on the received packet's type.
        let epoch = hdr.ty.to_epoch()?;

        // TODO: somehow deal with re-ordered 0-RTT data.
        let aead = if hdr.ty == packet::Type::ZeroRTT &&
            self.pkt_num_spaces[epoch].crypto_0rtt_open.is_some()
        {
            self.pkt_num_spaces[epoch]
                .crypto_0rtt_open
                .as_ref()
                .unwrap()
        } else {
            match self.pkt_num_spaces[epoch].crypto_open {
                Some(ref v) => v,

                // Ignore packets that can't be decrypted because we don't have
                // the necessary decryption key (either because we
                // don't yet have it or because we already dropped
                // it).
                //
                // For example, this is necessary to prevent packet reordering
                // (e.g. between Initial and Handshake) from
                // causing the connection to be closed.
                None => {
                    trace!(
                        "{} dropped undecryptable packet type={:?} len={}",
                        self.trace_id,
                        hdr.ty,
                        payload_len
                    );

                    return Ok(header_len + payload_len);
                },
            }
        };

        let aead_tag_len = aead.alg().tag_len();

        packet::decrypt_hdr(&mut b, &mut hdr, &aead)
            .map_err(|e| drop_pkt_on_err(e, self.recv_count, &self.trace_id))?;

        let pn = packet::decode_pkt_num(
            self.pkt_num_spaces[epoch].largest_rx_pkt_num,
            hdr.pkt_num,
            hdr.pkt_num_len,
        );

        let pn_len = hdr.pkt_num_len;

        trace!(
            "{} rx pkt {:?} len={} pn={}",
            self.trace_id,
            hdr,
            payload_len,
            pn
        );

        let mut payload =
            packet::decrypt_pkt(&mut b, pn, pn_len, payload_len, &aead).map_err(
                |e| drop_pkt_on_err(e, self.recv_count, &self.trace_id),
            )?;

        if self.pkt_num_spaces[epoch].recv_pkt_num.contains(pn) {
            trace!("{} ignored duplicate packet {}", self.trace_id, pn);
            return Err(Error::Done);
        }

        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK and PADDING.
        let mut ack_elicited = false;

        // Process packet payload.
        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;

            if frame.ack_eliciting() {
                ack_elicited = true;
            }

            self.process_frame(frame, epoch, now)?;
        }

        // Process acked frames.
        for acked in self.recovery.acked[epoch].drain(..) {
            match acked {
                frame::Frame::ACK { ranges, .. } => {
                    // Stop acknowledging packets less than or equal to the
                    // largest acknowledged in the sent ACK frame that, in
                    // turn, got acked.
                    if let Some(largest_acked) = ranges.largest() {
                        self.pkt_num_spaces[epoch]
                            .recv_pkt_need_ack
                            .remove_until(largest_acked);
                    }
                },

                frame::Frame::Crypto { data } => {
                    self.pkt_num_spaces[epoch]
                        .crypto_stream
                        .send
                        .ack(data.off(), data.len());
                },

                frame::Frame::Stream { stream_id, data } => {
                    let stream = match self.streams.get_mut(stream_id) {
                        Some(v) => v,

                        None => continue,
                    };

                    stream.send.ack(data.off(), data.len());

                    if stream.is_complete() {
                        let local = stream.local;
                        self.streams.collect(stream_id, local);
                    }
                },

                _ => (),
            }
        }

        // We only record the time of arrival of the largest packet number
        // that still needs to be acked, to be used for ACK delay calculation.
        if self.pkt_num_spaces[epoch].recv_pkt_need_ack.largest() < Some(pn) {
            self.pkt_num_spaces[epoch].largest_rx_pkt_time = now;
        }

        self.pkt_num_spaces[epoch].recv_pkt_num.insert(pn);

        self.pkt_num_spaces[epoch].recv_pkt_need_ack.push_item(pn);
        self.pkt_num_spaces[epoch].ack_elicited =
            cmp::max(self.pkt_num_spaces[epoch].ack_elicited, ack_elicited);

        self.pkt_num_spaces[epoch].largest_rx_pkt_num =
            cmp::max(self.pkt_num_spaces[epoch].largest_rx_pkt_num, pn);

        if let Some(idle_timeout) = self.idle_timeout() {
            self.idle_timer = Some(now + idle_timeout);
        }

        self.recv_count += 1;

        let read = b.off() + aead_tag_len;

        // An Handshake packet has been received from the client and has been
        // successfully processed, so we can drop the initial state and consider
        // the client's address to be verified.
        if self.is_server && hdr.ty == packet::Type::Handshake {
            self.drop_epoch_state(packet::EPOCH_INITIAL);

            self.verified_peer_address = true;
        }

        self.ack_eliciting_sent = false;

        Ok(read)
    }

    /// Writes a single QUIC packet to be sent to the peer.
    ///
    /// On success the number of bytes written to the output buffer is
    /// returned, or [`Done`] if there was nothing to write.
    ///
    /// The application should call `send()` multiple times until [`Done`] is
    /// returned, indicating that there are no more packets to send. It is
    /// recommended that `send()` be called in the following cases:
    ///
    ///  * When the application receives QUIC packets from the peer (that is,
    ///    any time [`recv()`] is also called).
    ///
    ///  * When the connection timer expires (that is, any time [`on_timeout()`]
    ///    is also called).
    ///
    ///  * When the application sends data to the peer (for examples, any time
    ///    [`stream_send()`] or [`stream_shutdown()`] are called).
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = [0xba; 16];
    /// # let mut conn = quiche::accept(&scid, None, &mut config)?;
    /// loop {
    ///     let write = match conn.send(&mut out) {
    ///         Ok(v) => v,
    ///
    ///         Err(quiche::Error::Done) => {
    ///             // Done writing.
    ///             break;
    ///         },
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    ///
    ///     socket.send(&out[..write]).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send(&mut self, out: &mut [u8]) -> Result<usize> {
        let now = time::Instant::now();

        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.draining_timer.is_some() {
            return Err(Error::Done);
        }

        // If the Initial secrets have not been derived yet, there's no point
        // in trying to send a packet, so return early.
        if !self.derived_initial_secrets {
            return Err(Error::Done);
        }

        let is_closing = self.error.is_some() || self.app_error.is_some();

        if !is_closing {
            self.do_handshake()?;
        }

        let mut b = octets::Octets::with_slice(out);

        let epoch = self.write_epoch()?;

        let pkt_type = packet::Type::from_epoch(epoch);

        // Process lost frames.
        for lost in self.recovery.lost[epoch].drain(..) {
            match lost {
                frame::Frame::Crypto { data } => {
                    self.pkt_num_spaces[epoch].crypto_stream.send.push(data)?;
                },

                frame::Frame::Stream { stream_id, data } => {
                    let stream = match self.streams.get_mut(stream_id) {
                        Some(v) => v,

                        None => continue,
                    };

                    let was_flushable = stream.is_flushable();

                    let empty_fin = data.is_empty() && data.fin();

                    stream.send.push(data)?;

                    // If the stream is now flushable push it to the flushable
                    // queue, but only if it wasn't already queued.
                    //
                    // Consider the stream flushable also when we are sending a
                    // zero-length frame that has the fin flag set.
                    if (stream.is_flushable() || empty_fin) && !was_flushable {
                        self.streams.push_flushable(stream_id);
                    }
                },

                frame::Frame::ACK { .. } => {
                    self.pkt_num_spaces[epoch].ack_elicited = true;
                },

                frame::Frame::HandshakeDone => {
                    self.handshake_done_sent = false;
                },

                _ => (),
            }
        }

        let mut left = b.cap();

        // Use max_packet_size as sent by the peer, except during the handshake
        // when we haven't parsed transport parameters yet, so use a default
        // value then.
        let max_pkt_len = if self.is_established() {
            // We cap the maximum packet size to 16KB or so, so that it can be
            // always encoded with a 2-byte varint.
            cmp::min(16383, self.peer_transport_params.max_packet_size) as usize
        } else {
            // Allow for 1200 bytes (minimum QUIC packet size) during the
            // handshake.
            1200
        };

        // Limit output packet size to respect peer's max_packet_size limit.
        left = cmp::min(left, max_pkt_len);

        // Limit output packet size by congestion window size.
        left = cmp::min(left, self.recovery.cwnd_available());

        // Limit data sent by the server based on the amount of data received
        // from the client before its address is validated.
        if !self.verified_peer_address && self.is_server {
            left = cmp::min(left, self.max_send_bytes);
        }

        let pn = self.pkt_num_spaces[epoch].next_pkt_num;
        let pn_len = packet::pkt_num_len(pn)?;

        // The AEAD overhead at the current encryption level.
        let overhead =
            self.pkt_num_spaces[epoch].overhead().ok_or(Error::Done)?;

        let hdr = Header {
            ty: pkt_type,
            version: self.version,
            dcid: self.dcid.clone(),

            // Don't needlessly clone the source connection ID for 1-RTT packets
            // as it is not used.
            scid: if pkt_type != packet::Type::Short {
                self.scid.clone()
            } else {
                Vec::new()
            },

            pkt_num: 0,
            pkt_num_len: pn_len,

            // Only clone token for Initial packets, as other packets don't have
            // this field (Retry doesn't count, as it's not encoded as part of
            // this code path).
            token: if pkt_type == packet::Type::Initial {
                self.token.clone()
            } else {
                None
            },

            versions: None,
            key_phase: false,
        };

        hdr.to_bytes(&mut b)?;

        // Make sure we have enough space left for the header, the payload
        // length, the packet number and the AEAD overhead.
        left = left
            .checked_sub(b.off() + pn_len + overhead)
            .ok_or(Error::Done)?;

        // We assume that the payload length, which is only present in long
        // header packets, can always be encoded with a 2-byte varint.
        if pkt_type != packet::Type::Short {
            left = left.checked_sub(2).ok_or(Error::Done)?;
        }

        let mut frames: Vec<frame::Frame> = Vec::new();

        let mut ack_eliciting = false;
        let mut in_flight = false;

        let mut payload_len = 0;

        // Create ACK frame.
        if self.pkt_num_spaces[epoch].ack_elicited && !is_closing {
            let ack_delay =
                self.pkt_num_spaces[epoch].largest_rx_pkt_time.elapsed();

            let ack_delay = ack_delay.as_micros() as u64 /
                2_u64
                    .pow(self.local_transport_params.ack_delay_exponent as u32);

            let frame = frame::Frame::ACK {
                ack_delay,
                ranges: self.pkt_num_spaces[epoch].recv_pkt_need_ack.clone(),
            };

            if push_frame_to_pkt!(frames, frame, payload_len, left) {
                self.pkt_num_spaces[epoch].ack_elicited = false;
            }
        }

        if pkt_type == packet::Type::Short && !is_closing {
            // Create HANDSHAKE_DONE frame.
            if self.is_established() &&
                !self.handshake_done_sent &&
                self.is_server &&
                self.version >= PROTOCOL_VERSION_DRAFT25
            {
                let frame = frame::Frame::HandshakeDone;

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    self.handshake_done_sent = true;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAMS_BIDI frame.
            if self.streams.should_update_max_streams_bidi() {
                let frame = frame::Frame::MaxStreamsBidi {
                    max: self.streams.max_streams_bidi_next(),
                };

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    self.streams.update_max_streams_bidi();

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAMS_UNI frame.
            if self.streams.should_update_max_streams_uni() {
                let frame = frame::Frame::MaxStreamsUni {
                    max: self.streams.max_streams_uni_next(),
                };

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    self.streams.update_max_streams_uni();

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_DATA frame as needed.
            if self.should_update_max_data() {
                let frame = frame::Frame::MaxData {
                    max: self.max_rx_data_next,
                };

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    self.max_rx_data = self.max_rx_data_next;

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create MAX_STREAM_DATA frames as needed.
            for stream_id in self.streams.almost_full() {
                let stream = match self.streams.get_mut(stream_id) {
                    Some(v) => v,

                    None => {
                        // The stream doesn't exist anymore, so remove it from
                        // the almost full set.
                        self.streams.mark_almost_full(stream_id, false);
                        continue;
                    },
                };

                let frame = frame::Frame::MaxStreamData {
                    stream_id,
                    max: stream.recv.max_data_next(),
                };

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    stream.recv.update_max_data();

                    self.streams.mark_almost_full(stream_id, false);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }
        }

        // Create CONNECTION_CLOSE frame.
        if let Some(err) = self.error {
            let frame = frame::Frame::ConnectionClose {
                error_code: err,
                frame_type: 0,
                reason: Vec::new(),
            };

            if push_frame_to_pkt!(frames, frame, payload_len, left) {
                self.draining_timer = Some(now + (self.recovery.pto() * 3));

                ack_eliciting = true;
                in_flight = true;
            }
        }

        // Create APPLICATION_CLOSE frame.
        if let Some(err) = self.app_error {
            if pkt_type == packet::Type::Short {
                let frame = frame::Frame::ApplicationClose {
                    error_code: err,
                    reason: self.app_reason.clone(),
                };

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    self.draining_timer = Some(now + (self.recovery.pto() * 3));

                    ack_eliciting = true;
                    in_flight = true;
                }
            }
        }

        // Create PATH_RESPONSE frame.
        if let Some(ref challenge) = self.challenge {
            let frame = frame::Frame::PathResponse {
                data: challenge.clone(),
            };

            if push_frame_to_pkt!(frames, frame, payload_len, left) {
                self.challenge = None;

                ack_eliciting = true;
                in_flight = true;
            }
        }

        // Create CRYPTO frame.
        if self.pkt_num_spaces[epoch].crypto_stream.is_flushable() &&
            left > frame::MAX_CRYPTO_OVERHEAD &&
            !is_closing
        {
            let crypto_len = left - frame::MAX_CRYPTO_OVERHEAD;
            let crypto_buf = self.pkt_num_spaces[epoch]
                .crypto_stream
                .send
                .pop(crypto_len)?;

            let frame = frame::Frame::Crypto { data: crypto_buf };

            if push_frame_to_pkt!(frames, frame, payload_len, left) {
                ack_eliciting = true;
                in_flight = true;
            }
        }

        // Create a single STREAM frame for the first stream that is flushable.
        if pkt_type == packet::Type::Short &&
            left > frame::MAX_STREAM_OVERHEAD &&
            !is_closing
        {
            while let Some(stream_id) = self.streams.pop_flushable() {
                let stream = match self.streams.get_mut(stream_id) {
                    Some(v) => v,

                    None => continue,
                };

                let off = stream.send.off();

                // Try to accurately account for the STREAM frame's overhead,
                // such that we can fill as much of the packet buffer as
                // possible.
                let overhead = 1 +
                    octets::varint_len(stream_id) +
                    octets::varint_len(off) +
                    octets::varint_len(left as u64);

                let max_len = match left.checked_sub(overhead) {
                    Some(v) => v,

                    None => continue,
                };

                let stream_buf = stream.send.pop(max_len)?;

                if stream_buf.is_empty() && !stream_buf.fin() {
                    continue;
                }

                let frame = frame::Frame::Stream {
                    stream_id,
                    data: stream_buf,
                };

                if push_frame_to_pkt!(frames, frame, payload_len, left) {
                    ack_eliciting = true;
                    in_flight = true;
                }

                // If the stream is still flushable, push it to the back of the
                // queue again.
                if stream.is_flushable() {
                    self.streams.push_flushable(stream_id);
                }

                // When fuzzing, try to coalesce multiple STREAM frames in the
                // same packet, so it's easier to generate fuzz corpora.
                if cfg!(feature = "fuzzing") && left > frame::MAX_STREAM_OVERHEAD
                {
                    continue;
                }

                break;
            }
        }

        // Create PING for PTO probe.
        if self.recovery.loss_probes[epoch] > 0 &&
            !ack_eliciting &&
            left >= 1 &&
            !is_closing
        {
            let frame = frame::Frame::Ping;

            if push_frame_to_pkt!(frames, frame, payload_len, left) {
                ack_eliciting = true;
                in_flight = true;
            }
        }

        if ack_eliciting {
            self.recovery.loss_probes[epoch] =
                self.recovery.loss_probes[epoch].saturating_sub(1);
        }

        if frames.is_empty() {
            return Err(Error::Done);
        }

        // Pad the client's initial packet.
        if !self.is_server && pkt_type == packet::Type::Initial {
            let pkt_len = pn_len + payload_len + overhead;

            let frame = frame::Frame::Padding {
                len: cmp::min(MIN_CLIENT_INITIAL_LEN - pkt_len, left),
            };

            payload_len += frame.wire_len();

            frames.push(frame);

            in_flight = true;
        }

        // Pad payload so that it's always at least 4 bytes.
        if payload_len < PAYLOAD_MIN_LEN {
            let frame = frame::Frame::Padding {
                len: PAYLOAD_MIN_LEN - payload_len,
            };

            payload_len += frame.wire_len();

            frames.push(frame);

            in_flight = true;
        }

        payload_len += overhead;

        // Only long header packets have an explicit length field.
        if pkt_type != packet::Type::Short {
            let len = pn_len + payload_len;
            b.put_varint(len as u64)?;
        }

        packet::encode_pkt_num(pn, &mut b)?;

        let payload_offset = b.off();

        trace!(
            "{} tx pkt {:?} len={} pn={}",
            self.trace_id,
            hdr,
            payload_len,
            pn
        );

        // Encode frames into the output packet.
        for frame in &frames {
            trace!("{} tx frm {:?}", self.trace_id, frame);

            frame.to_bytes(&mut b)?;
        }

        let aead = match self.pkt_num_spaces[epoch].crypto_seal {
            Some(ref v) => v,
            None => return Err(Error::InvalidState),
        };

        let written = packet::encrypt_pkt(
            &mut b,
            pn,
            pn_len,
            payload_len,
            payload_offset,
            aead,
        )?;

        let sent_pkt = recovery::Sent {
            pkt_num: pn,
            frames,
            time: now,
            size: if ack_eliciting { written } else { 0 },
            ack_eliciting,
            in_flight,
            delivered: 0,
            delivered_time: now,
            recent_delivered_packet_sent_time: now,
            is_app_limited: false,
        };

        self.recovery.on_packet_sent(
            sent_pkt,
            epoch,
            self.is_established(),
            now,
            &self.trace_id,
        );

        self.pkt_num_spaces[epoch].next_pkt_num += 1;

        self.sent_count += 1;

        // On the client, drop initial state after sending an Handshake packet.
        if !self.is_server && hdr.ty == packet::Type::Handshake {
            self.drop_epoch_state(packet::EPOCH_INITIAL);
        }

        self.max_send_bytes = self.max_send_bytes.saturating_sub(written);

        // (Re)start the idle timer if we are sending the first ack-eliciting
        // packet since last receiving a packet.
        if ack_eliciting && !self.ack_eliciting_sent {
            if let Some(idle_timeout) = self.idle_timeout() {
                self.idle_timer = Some(now + idle_timeout);
            }
        }

        if ack_eliciting {
            self.ack_eliciting_sent = true;
        }

        Ok(written)
    }

    /// Reads contiguous data from a stream into the provided slice.
    ///
    /// The slice must be sized by the caller and will be populated up to its
    /// capacity.
    ///
    /// On success the amount of bytes read and a flag indicating the fin state
    /// is returned as a tuple, or [`Done`] if there is no data to read.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = [0xba; 16];
    /// # let mut conn = quiche::accept(&scid, None, &mut config)?;
    /// # let stream_id = 0;
    /// while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
    ///     println!("Got {} bytes on stream {}", read, stream_id);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_recv(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool)> {
        // We can't read on our own unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState);
        }

        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or(Error::InvalidStreamState)?;

        if !stream.is_readable() {
            return Err(Error::Done);
        }

        let (read, fin) = stream.recv.pop(out)?;

        self.max_rx_data_next = self.max_rx_data_next.saturating_add(read as u64);

        let readable = stream.is_readable();

        let complete = stream.is_complete();

        let local = stream.local;

        if stream.recv.almost_full() {
            self.streams.mark_almost_full(stream_id, true);
        }

        if !readable {
            self.streams.mark_readable(stream_id, false);
        }

        if complete {
            self.streams.collect(stream_id, local);
        }

        Ok((read, fin))
    }

    /// Writes data to a stream.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// data was written (e.g. because the stream has no capacity).
    ///
    /// Note that in order to avoid buffering an infinite amount of data in the
    /// stream's send buffer, streams are only allowed to buffer outgoing data
    /// up to the amount that the peer allows it to send (that is, up to the
    /// stream's outgoing flow control capacity).
    ///
    /// This means that the number of written bytes returned can be lower than
    /// the length of the input buffer when the stream doesn't have enough
    /// capacity for the operation to complete. The application should retry the
    /// operation once the stream is reported as writable again.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = [0xba; 16];
    /// # let mut conn = quiche::accept(&scid, None, &mut config)?;
    /// # let stream_id = 0;
    /// conn.stream_send(stream_id, b"hello", true)?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_send(
        &mut self, stream_id: u64, buf: &[u8], fin: bool,
    ) -> Result<usize> {
        // We can't write on the peer's unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            !stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState);
        }

        // Truncate the input buffer based on the connection's send capacity if
        // necessary.
        let cap = self.send_capacity();

        let (buf, fin) = if cap < buf.len() {
            (&buf[..cap], false)
        } else {
            (buf, fin)
        };

        // Get existing stream or create a new one.
        let stream = self.get_or_create_stream(stream_id, true)?;

        let was_flushable = stream.is_flushable();

        let sent = stream.send.push_slice(buf, fin)?;

        let flushable = stream.is_flushable();

        let writable = stream.is_writable();

        let empty_fin = buf.is_empty() && fin;

        // If the stream is now flushable push it to the flushable queue, but
        // only if it wasn't already queued.
        //
        // Consider the stream flushable also when we are sending a zero-length
        // frame that has the fin flag set.
        if (flushable || empty_fin) && !was_flushable {
            self.streams.push_flushable(stream_id);
        }

        if !writable {
            self.streams.mark_writable(stream_id, false);
        }

        self.tx_data += sent as u64;

        self.recovery.rate_check_app_limited();

        Ok(sent)
    }

    /// Shuts down reading or writing from/to the specified stream.
    ///
    /// When the `direction` argument is set to [`Shutdown::Read`], outstanding
    /// data in the stream's receive buffer is dropped, and no additional data
    /// is added to it. Data received after calling this method is still
    /// validated and acked but not stored, and [`stream_recv()`] will not
    /// return it to the application.
    ///
    /// When the `direction` argument is set to [`Shutdown::Write`], outstanding
    /// data in the stream's send buffer is dropped, and no additional data
    /// is added to it. Data passed to [`stream_send()`] after calling this
    /// method will be ignored.
    ///
    /// [`Shutdown::Read`]: enum.Shutdown.html#variant.Read
    /// [`Shutdown::Write`]: enum.Shutdown.html#variant.Write
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    pub fn stream_shutdown(
        &mut self, stream_id: u64, direction: Shutdown, _err: u64,
    ) -> Result<()> {
        // Get existing stream.
        let stream = self.streams.get_mut(stream_id).ok_or(Error::Done)?;

        match direction {
            // TODO: send STOP_SENDING
            Shutdown::Read => {
                stream.recv.shutdown()?;

                // Once shutdown, the stream is guaranteed to be non-readable.
                self.streams.mark_readable(stream_id, false);
            },

            // TODO: send RESET_STREAM
            Shutdown::Write => {
                stream.send.shutdown()?;

                // Once shutdown, the stream is guaranteed to be non-writable.
                self.streams.mark_writable(stream_id, false);
            },
        }

        Ok(())
    }

    /// Returns the stream's send capacity in bytes.
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        if let Some(stream) = self.streams.get(stream_id) {
            let cap = cmp::min(self.send_capacity(), stream.send.cap());
            return Ok(cap);
        };

        Err(Error::InvalidStreamState)
    }

    /// Returns true if all the data has been read from the specified stream.
    ///
    /// This instructs the application that all the data received from the
    /// peer on the stream has been read, and there won't be anymore in the
    /// future.
    ///
    /// Basically this returns true when the peer either set the `fin` flag
    /// for the stream, or sent `RESET_STREAM`.
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        let stream = match self.streams.get(stream_id) {
            Some(v) => v,

            None => return true,
        };

        stream.recv.is_fin()
    }

    /// Initializes the stream's application data.
    ///
    /// This can be used by applications to store per-stream information without
    /// having to maintain their own stream map.
    ///
    /// Stream data can only be initialized once. Additional calls to this
    /// method will return [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn stream_init_application_data<T>(
        &mut self, stream_id: u64, data: T,
    ) -> Result<()>
    where
        T: std::any::Any,
    {
        // Get existing stream.
        let stream = self.streams.get_mut(stream_id).ok_or(Error::Done)?;

        if stream.data.is_some() {
            return Err(Error::Done);
        }

        stream.data = Some(Box::new(data));

        Ok(())
    }

    /// Returns the stream's application data, if any was initialized.
    ///
    /// This returns a reference to the application data that was initialized
    /// by calling [`stream_init_application_data()`].
    ///
    /// [`stream_init_application_data()`]:
    /// struct.Connection.html#method.stream_init_application_data
    pub fn stream_application_data(
        &mut self, stream_id: u64,
    ) -> Option<&mut dyn std::any::Any> {
        // Get existing stream.
        let stream = self.streams.get_mut(stream_id)?;

        if let Some(ref mut stream_data) = stream.data {
            return Some(stream_data.as_mut());
        }

        None
    }

    /// Returns an iterator over streams that have outstanding data to read.
    ///
    /// Note that the iterator will only include streams that were readable at
    /// the time the iterator itself was created (i.e. when `readable()` was
    /// called). To account for newly readable streams, the iterator needs to
    /// be created again.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = [0xba; 16];
    /// # let mut conn = quiche::accept(&scid, None, &mut config)?;
    /// // Iterate over readable streams.
    /// for stream_id in conn.readable() {
    ///     // Stream is readable, read until there's no more data.
    ///     while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
    ///         println!("Got {} bytes on stream {}", read, stream_id);
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn readable(&self) -> StreamIter {
        self.streams.readable()
    }

    /// Returns an iterator over streams that can be written to.
    ///
    /// A "writable" stream is a stream that has enough flow control capacity to
    /// send data to the peer. To avoid buffering an infinite amount of data,
    /// streams are only allowed to buffer outgoing data up to the amount that
    /// the peer allows to send.
    ///
    /// Note that the iterator will only include streams that were writable at
    /// the time the iterator itself was created (i.e. when `writable()` was
    /// called). To account for newly writable streams, the iterator needs to
    /// be created again.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = [0xba; 16];
    /// # let mut conn = quiche::accept(&scid, None, &mut config)?;
    /// // Iterate over writable streams.
    /// for stream_id in conn.writable() {
    ///     // Stream is writable, write some data.
    ///     if let Ok(written) = conn.stream_send(stream_id, &buf, false) {
    ///         println!("Written {} bytes on stream {}", written, stream_id);
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn writable(&self) -> StreamIter {
        // If there is not enough connection-level flow control capacity, none
        // of the streams are writable, so return an empty iterator.
        if self.max_tx_data <= self.tx_data {
            return StreamIter::default();
        }

        self.streams.writable()
    }

    /// Returns the amount of time until the next timeout event.
    ///
    /// Once the given duration has elapsed, the [`on_timeout()`] method should
    /// be called. A timeout of `None` means that the timer should be disarmed.
    ///
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    pub fn timeout(&self) -> Option<time::Duration> {
        if self.closed {
            return None;
        }

        let timeout = if self.draining_timer.is_some() {
            // Draining timer takes precedence over all other timers. If it is
            // set it means the connection is closing so there's no point in
            // processing the other timers.
            self.draining_timer
        } else {
            // Use the lowest timer value (i.e. "sooner") among idle and loss
            // detection timers. If they are both unset (i.e. `None`) then the
            // result is `None`, but if at least one of them is set then a
            // `Some(...)` value is returned.
            let timers = [self.idle_timer, self.recovery.loss_detection_timer()];

            timers.iter().filter_map(|&x| x).min()
        };

        if let Some(timeout) = timeout {
            let now = time::Instant::now();

            if timeout <= now {
                return Some(time::Duration::new(0, 0));
            }

            return Some(timeout.duration_since(now));
        }

        None
    }

    /// Processes a timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    pub fn on_timeout(&mut self) {
        let now = time::Instant::now();

        if let Some(draining_timer) = self.draining_timer {
            if draining_timer <= now {
                trace!("{} draining timeout expired", self.trace_id);

                self.closed = true;
            }

            // Draining timer takes precedence over all other timers. If it is
            // set it means the connection is closing so there's no point in
            // processing the other timers.
            return;
        }

        if let Some(timer) = self.idle_timer {
            if timer <= now {
                trace!("{} idle timeout expired", self.trace_id);

                self.closed = true;
                return;
            }
        }

        if let Some(timer) = self.recovery.loss_detection_timer() {
            if timer <= now {
                trace!("{} loss detection timeout expired", self.trace_id);

                self.recovery.on_loss_detection_timeout(
                    self.is_established(),
                    now,
                    &self.trace_id,
                );

                return;
            }
        }
    }

    /// Closes the connection with the given error and reason.
    ///
    /// The `app` parameter specifies whether an application close should be
    /// sent to the peer. Otherwise a normal connection close is sent.
    ///
    /// Returns [`Done`] if the connection had already been closed.
    ///
    /// Note that the connection will not be closed immediately. An application
    /// should continue calling [`recv()`], [`send()`] and [`timeout()`] as
    /// normal, until the [`is_closed()`] method returns `true`.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`send()`]: struct.Connection.html#method.send
    /// [`timeout()`]: struct.Connection.html#method.timeout
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        if self.draining_timer.is_some() {
            return Err(Error::Done);
        }

        if self.error.is_some() || self.app_error.is_some() {
            return Err(Error::Done);
        }

        if app {
            self.app_error = Some(err);
            self.app_reason.extend_from_slice(reason);
        } else {
            self.error = Some(err);
        }

        Ok(())
    }

    /// Returns a string uniquely representing the connection.
    ///
    /// This can be used for logging purposes to differentiate between multiple
    /// connections.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Returns the negotiated ALPN protocol.
    ///
    /// If no protocol has been negotiated, the returned value is empty.
    pub fn application_proto(&self) -> &[u8] {
        self.handshake.alpn_protocol()
    }

    /// Returns the peer's leaf certificate (if any) as a DER-encoded buffer.
    pub fn peer_cert(&self) -> Option<Vec<u8>> {
        self.handshake.peer_cert()
    }

    /// Returns true if the connection handshake is complete.
    pub fn is_established(&self) -> bool {
        self.handshake.is_completed()
    }

    /// Returns true if the connection is resumed.
    pub fn is_resumed(&self) -> bool {
        self.handshake.is_resumed()
    }

    /// Returns true if the connection has a pending handshake that has
    /// progressed enough to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        self.handshake.is_in_early_data()
    }

    /// Returns true if the connection is closed.
    ///
    /// If this returns true, the connection object can be dropped.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Collects and returns statistics about the connection.
    pub fn stats(&self) -> Stats {
        Stats {
            recv: self.recv_count,
            sent: self.sent_count,
            lost: self.recovery.lost_count,
            cwnd: self.recovery.cwnd(),
            rtt: self.recovery.rtt(),
            delivery_rate: self.recovery.delivery_rate(),
        }
    }

    /// Continues the handshake.
    ///
    /// If the connection is already established, it does nothing.
    fn do_handshake(&mut self) -> Result<()> {
        // Handshake is already complete, there's nothing to do.
        if self.is_established() {
            return Ok(());
        }

        match self.handshake.do_handshake() {
            Ok(_) => (),

            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        if self.application_proto().is_empty() {
            // Send no_application_proto TLS alert when no protocol
            // can be negotiated.
            self.error = Some(0x178);
            return Err(Error::TlsFail);
        }

        if !self.parsed_peer_transport_params {
            let mut raw_params = self.handshake.quic_transport_params().to_vec();

            let peer_params = TransportParams::decode(
                &mut raw_params,
                self.version,
                self.is_server,
            )?;

            if peer_params.original_connection_id != self.odcid {
                return Err(Error::InvalidTransportParam);
            }

            self.max_tx_data = peer_params.initial_max_data;

            self.streams.update_peer_max_streams_bidi(
                peer_params.initial_max_streams_bidi,
            );
            self.streams
                .update_peer_max_streams_uni(peer_params.initial_max_streams_uni);

            self.recovery.max_ack_delay =
                time::Duration::from_millis(peer_params.max_ack_delay);

            self.peer_transport_params = peer_params;

            self.parsed_peer_transport_params = true;

            trace!("{} connection established: proto={:?} cipher={:?} curve={:?} sigalg={:?} resumed={} {:?}",
                   &self.trace_id,
                   std::str::from_utf8(self.application_proto()),
                   self.handshake.cipher(),
                   self.handshake.curve(),
                   self.handshake.sigalg(),
                   self.is_resumed(),
                   self.peer_transport_params);
        }

        Ok(())
    }

    /// Selects the packet number space for outgoing packets.
    fn write_epoch(&self) -> Result<packet::Epoch> {
        // On error send packet in the latest epoch available, but only send
        // 1-RTT ones when the handshake is completed.
        if self.error.is_some() {
            let epoch = match self.handshake.write_level() {
                crypto::Level::Initial => packet::EPOCH_INITIAL,
                crypto::Level::ZeroRTT => unreachable!(),
                crypto::Level::Handshake => packet::EPOCH_HANDSHAKE,
                crypto::Level::OneRTT => packet::EPOCH_APPLICATION,
            };

            if epoch == packet::EPOCH_APPLICATION && !self.is_established() {
                // Downgrade the epoch to handshake as the handshake is not
                // completed yet.
                return Ok(packet::EPOCH_HANDSHAKE);
            }

            return Ok(epoch);
        }

        for epoch in packet::EPOCH_INITIAL..packet::EPOCH_COUNT {
            // Only send 1-RTT packets when handshake is complete.
            if epoch == packet::EPOCH_APPLICATION && !self.is_established() {
                continue;
            }

            // We are ready to send data for this packet number space.
            if self.pkt_num_spaces[epoch].ready() {
                return Ok(epoch);
            }

            // There are lost frames in this packet number space.
            if !self.recovery.lost[epoch].is_empty() {
                return Ok(epoch);
            }

            // We need to send PTO probe packets.
            if self.recovery.loss_probes[epoch] > 0 {
                return Ok(epoch);
            }
        }

        // If there are flushable streams, use Application.
        if self.is_established() &&
            (self.should_update_max_data() ||
                self.streams.should_update_max_streams_bidi() ||
                self.streams.should_update_max_streams_uni() ||
                self.streams.has_flushable() ||
                self.streams.has_almost_full())
        {
            return Ok(packet::EPOCH_APPLICATION);
        }

        Err(Error::Done)
    }

    /// Returns the mutable stream with the given ID if it exists, or creates
    /// a new one otherwise.
    fn get_or_create_stream(
        &mut self, id: u64, local: bool,
    ) -> Result<&mut stream::Stream> {
        self.streams.get_or_create(
            id,
            &self.local_transport_params,
            &self.peer_transport_params,
            local,
            self.is_server,
        )
    }

    /// Processes an incoming frame.
    fn process_frame(
        &mut self, frame: frame::Frame, epoch: packet::Epoch, now: time::Instant,
    ) -> Result<()> {
        trace!("{} rx frm {:?}", self.trace_id, frame);

        match frame {
            frame::Frame::Padding { .. } => (),

            frame::Frame::Ping => (),

            frame::Frame::ACK { ranges, ack_delay } => {
                let ack_delay = ack_delay
                    .checked_mul(2_u64.pow(
                        self.peer_transport_params.ack_delay_exponent as u32,
                    ))
                    .ok_or(Error::InvalidFrame)?;

                self.recovery.on_ack_received(
                    &ranges,
                    ack_delay,
                    epoch,
                    self.is_established(),
                    now,
                    &self.trace_id,
                )?;

                // When we receive an ACK for a 1-RTT packet after handshake
                // completion, it means the handshake has been confirmed.
                if epoch == packet::EPOCH_APPLICATION && self.is_established() {
                    self.handshake_confirmed = true;

                    // Once the handshake is confirmed, we can drop Handshake
                    // keys.
                    self.drop_epoch_state(packet::EPOCH_HANDSHAKE);
                }
            },

            frame::Frame::ResetStream {
                stream_id,
                final_size,
                ..
            } => {
                // Peer can't send on our unidirectional streams.
                if !stream::is_bidi(stream_id) &&
                    stream::is_local(stream_id, self.is_server)
                {
                    return Err(Error::InvalidStreamState);
                }

                // Get existing stream or create a new one, but if the stream
                // has already been closed and collected, ignore the frame.
                //
                // This can happen if e.g. an ACK frame is lost, and the peer
                // retransmits another frame before it realizes that the stream
                // is gone.
                //
                // Note that it makes it impossible to check if the frame is
                // illegal, since we have no state, but since we ignore the
                // frame, it should be fine.
                let stream = match self.get_or_create_stream(stream_id, false) {
                    Ok(v) => v,

                    Err(Error::Done) => return Ok(()),

                    Err(e) => return Err(e),
                };

                self.rx_data += stream.recv.reset(final_size)? as u64;

                if self.rx_data > self.max_rx_data {
                    return Err(Error::FlowControl);
                }
            },

            frame::Frame::StopSending { stream_id, .. } => {
                // STOP_SENDING on a receive-only stream is a fatal error.
                if !stream::is_local(stream_id, self.is_server) &&
                    !stream::is_bidi(stream_id)
                {
                    return Err(Error::InvalidStreamState);
                }
            },

            frame::Frame::Crypto { data } => {
                // Push the data to the stream so it can be re-ordered.
                self.pkt_num_spaces[epoch].crypto_stream.recv.push(data)?;

                // Feed crypto data to the TLS state, if there's data
                // available at the expected offset.
                let mut crypto_buf = [0; 512];

                let level = crypto::Level::from_epoch(epoch);

                let stream = &mut self.pkt_num_spaces[epoch].crypto_stream;

                while let Ok((read, _)) = stream.recv.pop(&mut crypto_buf) {
                    let recv_buf = &crypto_buf[..read];
                    self.handshake.provide_data(level, &recv_buf)?;
                }

                self.do_handshake()?;
            },

            // TODO: implement stateless retry
            frame::Frame::NewToken { .. } => (),

            frame::Frame::Stream { stream_id, data } => {
                // Peer can't send on our unidirectional streams.
                if !stream::is_bidi(stream_id) &&
                    stream::is_local(stream_id, self.is_server)
                {
                    return Err(Error::InvalidStreamState);
                }

                // Check for flow control limits.
                let data_len = data.len() as u64;

                if self.rx_data + data_len > self.max_rx_data {
                    return Err(Error::FlowControl);
                }

                // Get existing stream or create a new one, but if the stream
                // has already been closed and collected, ignore the frame.
                //
                // This can happen if e.g. an ACK frame is lost, and the peer
                // retransmits another frame before it realizes that the stream
                // is gone.
                //
                // Note that it makes it impossible to check if the frame is
                // illegal, since we have no state, but since we ignore the
                // frame, it should be fine.
                let stream = match self.get_or_create_stream(stream_id, false) {
                    Ok(v) => v,

                    Err(Error::Done) => return Ok(()),

                    Err(e) => return Err(e),
                };

                stream.recv.push(data)?;

                if stream.is_readable() {
                    self.streams.mark_readable(stream_id, true);
                }

                self.rx_data += data_len;
            },

            frame::Frame::MaxData { max } => {
                self.max_tx_data = cmp::max(self.max_tx_data, max);
            },

            frame::Frame::MaxStreamData { stream_id, max } => {
                // Get existing stream or create a new one, but if the stream
                // has already been closed and collected, ignore the frame.
                //
                // This can happen if e.g. an ACK frame is lost, and the peer
                // retransmits another frame before it realizes that the stream
                // is gone.
                //
                // Note that it makes it impossible to check if the frame is
                // illegal, since we have no state, but since we ignore the
                // frame, it should be fine.
                let stream = match self.get_or_create_stream(stream_id, false) {
                    Ok(v) => v,

                    Err(Error::Done) => return Ok(()),

                    Err(e) => return Err(e),
                };

                let was_flushable = stream.is_flushable();

                stream.send.update_max_data(max);

                let writable = stream.is_writable();

                // If the stream is now flushable push it to the flushable queue,
                // but only if it wasn't already queued.
                if stream.is_flushable() && !was_flushable {
                    self.streams.push_flushable(stream_id);
                }

                if writable {
                    self.streams.mark_writable(stream_id, true);
                }
            },

            frame::Frame::MaxStreamsBidi { max } => {
                if max > 2u64.pow(60) {
                    return Err(Error::StreamLimit);
                }

                self.streams.update_peer_max_streams_bidi(max);
            },

            frame::Frame::MaxStreamsUni { max } => {
                if max > 2u64.pow(60) {
                    return Err(Error::StreamLimit);
                }

                self.streams.update_peer_max_streams_uni(max);
            },

            frame::Frame::DataBlocked { .. } => (),

            frame::Frame::StreamDataBlocked { .. } => (),

            frame::Frame::StreamsBlockedBidi { .. } => (),

            frame::Frame::StreamsBlockedUni { .. } => (),

            // TODO: implement connection migration
            frame::Frame::NewConnectionId { .. } => (),

            // TODO: implement connection migration
            frame::Frame::RetireConnectionId { .. } => (),

            frame::Frame::PathChallenge { data } => {
                self.challenge = Some(data);
            },

            frame::Frame::PathResponse { .. } => (),

            frame::Frame::ConnectionClose { .. } => {
                self.draining_timer = Some(now + (self.recovery.pto() * 3));
            },

            frame::Frame::ApplicationClose { .. } => {
                self.draining_timer = Some(now + (self.recovery.pto() * 3));
            },

            frame::Frame::HandshakeDone => {
                if self.version < PROTOCOL_VERSION_DRAFT25 {
                    return Err(Error::InvalidFrame);
                }

                if self.is_server {
                    return Err(Error::InvalidPacket);
                }

                self.handshake_confirmed = true;

                // Once the handshake is confirmed, we can drop Handshake keys.
                self.drop_epoch_state(packet::EPOCH_HANDSHAKE);
            },
        }

        Ok(())
    }

    /// Drops the keys and recovery state for the given epoch.
    fn drop_epoch_state(&mut self, epoch: packet::Epoch) {
        if self.pkt_num_spaces[epoch].crypto_open.is_none() {
            return;
        }

        self.pkt_num_spaces[epoch].crypto_open = None;
        self.pkt_num_spaces[epoch].crypto_seal = None;
        self.pkt_num_spaces[epoch].clear();
        self.recovery.drop_unacked_data(epoch);

        trace!("{} dropped epoch {} state", self.trace_id, epoch);
    }

    /// Returns true if the connection-level flow control needs to be updated.
    ///
    /// This happens when the new max data limit is at least double the amount
    /// of data that can be received before blocking.
    fn should_update_max_data(&self) -> bool {
        self.max_rx_data_next != self.max_rx_data &&
            self.max_rx_data_next / 2 > self.max_rx_data - self.rx_data
    }

    /// Returns the idle timeout value.
    ///
    /// `None` is returned if both end-points disabled the idle timeout.
    fn idle_timeout(&mut self) -> Option<time::Duration> {
        // If the transport parameter is set to 0, then the respective endpoint
        // decided to disable the idle timeout. If both are disabled we should
        // not set any timeout.
        if self.local_transport_params.max_idle_timeout == 0 &&
            self.peer_transport_params.max_idle_timeout == 0
        {
            return None;
        }

        // If the local endpoint or the peer disabled the idle timeout, use the
        // other peer's value, otherwise use the minimum of the two values.
        let idle_timeout = if self.local_transport_params.max_idle_timeout == 0 {
            self.peer_transport_params.max_idle_timeout
        } else if self.peer_transport_params.max_idle_timeout == 0 {
            self.local_transport_params.max_idle_timeout
        } else {
            cmp::min(
                self.local_transport_params.max_idle_timeout,
                self.peer_transport_params.max_idle_timeout,
            )
        };

        let idle_timeout = time::Duration::from_millis(idle_timeout);
        let idle_timeout = cmp::max(idle_timeout, 3 * self.recovery.pto());

        Some(idle_timeout)
    }

    /// Returns the connection's overall send capacity.
    fn send_capacity(&self) -> usize {
        let cap = self.max_tx_data - self.tx_data;
        cmp::min(cap, self.recovery.cwnd_available() as u64) as usize
    }
}

/// Maps an `Error` to `Error::Done`, or itself.
///
/// When a received packet that hasn't yet been authenticated triggers a failure
/// it should, in most cases, be ignored, instead of raising a connection error,
/// to avoid potential man-in-the-middle and man-on-the-side attacks.
///
/// However, if no other packet was previously received, the connection should
/// indeed be closed as the received packet might just be network background
/// noise, and it shouldn't keep resources occupied indefinitely.
///
/// This function maps an error to `Error::Done` to ignore a packet failure
/// without aborting the connection, except when no other packet was previously
/// received, in which case the error itself is returned.
///
/// This must only be used for errors preceding packet authentication. Failures
/// happening after a packet has been authenticated should still cause the
/// connection to be aborted.
fn drop_pkt_on_err(e: Error, recv_count: usize, trace_id: &str) -> Error {
    // If no other packet has been successflully processed, abort the connection
    // to avoid keeping the connection open when only junk is received.
    if recv_count == 0 {
        return e;
    }

    trace!("{} dropped invalid packet", trace_id);

    // Ignore other invalid packets that haven't been authenticated to prevent
    // man-in-the-middle and man-on-the-side attacks.
    Error::Done
}

/// Statistics about the connection.
///
/// A connections's statistics can be collected using the [`stats()`] method.
///
/// [`stats()`]: struct.Connection.html#method.stats
#[derive(Clone)]
pub struct Stats {
    /// The number of QUIC packets received on this connection.
    pub recv: usize,

    /// The number of QUIC packets sent on this connection.
    pub sent: usize,

    /// The number of QUIC packets that were lost.
    pub lost: usize,

    /// The estimated round-trip time of the connection.
    pub rtt: time::Duration,

    /// The size of the connection's congestion window in bytes.
    pub cwnd: usize,

    /// The estimated data delivery rate in bytes/s.
    pub delivery_rate: u64,
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "recv={} sent={} lost={} rtt={:?} cwnd={} delivery_rate={}",
            self.recv,
            self.sent,
            self.lost,
            self.rtt,
            self.cwnd,
            self.delivery_rate
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
struct TransportParams {
    pub original_connection_id: Option<Vec<u8>>,
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<Vec<u8>>,
    pub max_packet_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    // pub preferred_address: ...,
    pub active_conn_id_limit: u64,
}

impl Default for TransportParams {
    fn default() -> TransportParams {
        TransportParams {
            original_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_packet_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_conn_id_limit: 0,
        }
    }
}

impl TransportParams {
    fn decode(
        buf: &mut [u8], version: u32, is_server: bool,
    ) -> Result<TransportParams> {
        let mut b = octets::Octets::with_slice(buf);

        let mut tp = TransportParams::default();

        let mut params = if version < PROTOCOL_VERSION_DRAFT27 {
            b.get_bytes_with_u16_length()?
        } else {
            b
        };

        while params.cap() > 0 {
            let id = if version < PROTOCOL_VERSION_DRAFT27 {
                params.get_u16()? as u64
            } else {
                params.get_varint()?
            };

            let mut val = if version < PROTOCOL_VERSION_DRAFT27 {
                params.get_bytes_with_u16_length()?
            } else {
                params.get_bytes_with_varint_length()?
            };

            // TODO: forbid duplicated param

            match id {
                0x0000 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.original_connection_id = Some(val.to_vec());
                },

                0x0001 => {
                    tp.max_idle_timeout = val.get_varint()?;
                },

                0x0002 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.stateless_reset_token = Some(val.get_bytes(16)?.to_vec());
                },

                0x0003 => {
                    tp.max_packet_size = val.get_varint()?;

                    if tp.max_packet_size < 1200 {
                        return Err(Error::InvalidTransportParam);
                    }
                },

                0x0004 => {
                    tp.initial_max_data = val.get_varint()?;
                },

                0x0005 => {
                    tp.initial_max_stream_data_bidi_local = val.get_varint()?;
                },

                0x0006 => {
                    tp.initial_max_stream_data_bidi_remote = val.get_varint()?;
                },

                0x0007 => {
                    tp.initial_max_stream_data_uni = val.get_varint()?;
                },

                0x0008 => {
                    let max = val.get_varint()?;

                    if max > 2u64.pow(60) {
                        return Err(Error::StreamLimit);
                    }

                    tp.initial_max_streams_bidi = max;
                },

                0x0009 => {
                    let max = val.get_varint()?;

                    if max > 2u64.pow(60) {
                        return Err(Error::StreamLimit);
                    }

                    tp.initial_max_streams_uni = max;
                },

                0x000a => {
                    let ack_delay_exponent = val.get_varint()?;

                    if ack_delay_exponent > 20 {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.ack_delay_exponent = ack_delay_exponent;
                },

                0x000b => {
                    let max_ack_delay = val.get_varint()?;

                    if max_ack_delay >= 2_u64.pow(14) {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.max_ack_delay = max_ack_delay;
                },

                0x000c => {
                    tp.disable_active_migration = true;
                },

                0x000d => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    // TODO: decode preferred_address
                },

                0x000e => {
                    tp.active_conn_id_limit = val.get_varint()?;
                },

                // Ignore unknown parameters.
                _ => (),
            }
        }

        Ok(tp)
    }

    fn encode_param(
        b: &mut octets::Octets, ty: u64, len: usize, version: u32,
    ) -> Result<()> {
        if version < PROTOCOL_VERSION_DRAFT27 {
            b.put_u16(ty as u16)?;
            b.put_u16(len as u16)?;
        } else {
            b.put_varint(ty)?;
            b.put_varint(len as u64)?;
        }

        Ok(())
    }

    fn encode<'a>(
        tp: &TransportParams, version: u32, is_server: bool, out: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let mut params = [0; 128];

        let params_len = {
            let mut b = octets::Octets::with_slice(&mut params);

            if is_server {
                if let Some(ref odcid) = tp.original_connection_id {
                    TransportParams::encode_param(
                        &mut b,
                        0x0000,
                        odcid.len(),
                        version,
                    )?;
                    b.put_bytes(&odcid)?;
                }
            };

            if tp.max_idle_timeout != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0001,
                    octets::varint_len(tp.max_idle_timeout),
                    version,
                )?;
                b.put_varint(tp.max_idle_timeout)?;
            }

            if let Some(ref token) = tp.stateless_reset_token {
                if is_server {
                    TransportParams::encode_param(
                        &mut b,
                        0x0002,
                        token.len(),
                        version,
                    )?;
                    b.put_bytes(&token)?;
                }
            }

            if tp.max_packet_size != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0003,
                    octets::varint_len(tp.max_packet_size),
                    version,
                )?;
                b.put_varint(tp.max_packet_size)?;
            }

            if tp.initial_max_data != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0004,
                    octets::varint_len(tp.initial_max_data),
                    version,
                )?;
                b.put_varint(tp.initial_max_data)?;
            }

            if tp.initial_max_stream_data_bidi_local != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0005,
                    octets::varint_len(tp.initial_max_stream_data_bidi_local),
                    version,
                )?;
                b.put_varint(tp.initial_max_stream_data_bidi_local)?;
            }

            if tp.initial_max_stream_data_bidi_remote != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0006,
                    octets::varint_len(tp.initial_max_stream_data_bidi_remote),
                    version,
                )?;
                b.put_varint(tp.initial_max_stream_data_bidi_remote)?;
            }

            if tp.initial_max_stream_data_uni != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0007,
                    octets::varint_len(tp.initial_max_stream_data_uni),
                    version,
                )?;
                b.put_varint(tp.initial_max_stream_data_uni)?;
            }

            if tp.initial_max_streams_bidi != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0008,
                    octets::varint_len(tp.initial_max_streams_bidi),
                    version,
                )?;
                b.put_varint(tp.initial_max_streams_bidi)?;
            }

            if tp.initial_max_streams_uni != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x0009,
                    octets::varint_len(tp.initial_max_streams_uni),
                    version,
                )?;
                b.put_varint(tp.initial_max_streams_uni)?;
            }

            if tp.ack_delay_exponent != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x000a,
                    octets::varint_len(tp.ack_delay_exponent),
                    version,
                )?;
                b.put_varint(tp.ack_delay_exponent)?;
            }

            if tp.max_ack_delay != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x000b,
                    octets::varint_len(tp.max_ack_delay),
                    version,
                )?;
                b.put_varint(tp.max_ack_delay)?;
            }

            if tp.disable_active_migration {
                TransportParams::encode_param(&mut b, 0x000c, 0, version)?;
            }

            // TODO: encode preferred_address

            if tp.active_conn_id_limit != 0 {
                TransportParams::encode_param(
                    &mut b,
                    0x000e,
                    octets::varint_len(tp.active_conn_id_limit),
                    version,
                )?;
                b.put_varint(tp.active_conn_id_limit)?;
            }

            b.off()
        };

        let out_len = {
            let mut b = octets::Octets::with_slice(out);

            // TODO: once we drop support for drafts < 27, we should simplify
            // the encoding to serialize the parameters into the output buffer
            // directly.
            if version < PROTOCOL_VERSION_DRAFT27 {
                b.put_u16(params_len as u16)?;
            }

            b.put_bytes(&params[..params_len])?;

            b.off()
        };

        Ok(&mut out[..out_len])
    }
}

#[doc(hidden)]
pub mod testing {
    use super::*;

    pub struct Pipe {
        pub client: Pin<Box<Connection>>,
        pub server: Pin<Box<Connection>>,
    }

    impl Pipe {
        pub fn default() -> Result<Pipe> {
            let mut config = Config::new(crate::PROTOCOL_VERSION)?;
            config.load_cert_chain_from_pem_file("examples/cert.crt")?;
            config.load_priv_key_from_pem_file("examples/cert.key")?;
            config.set_application_protos(b"\x06proto1\x06proto2")?;
            config.set_initial_max_data(30);
            config.set_initial_max_stream_data_bidi_local(15);
            config.set_initial_max_stream_data_bidi_remote(15);
            config.set_initial_max_stream_data_uni(10);
            config.set_initial_max_streams_bidi(3);
            config.set_initial_max_streams_uni(3);
            config.verify_peer(false);

            Pipe::with_config(&mut config)
        }

        pub fn with_config(config: &mut Config) -> Result<Pipe> {
            let mut client_scid = [0; 16];
            rand::rand_bytes(&mut client_scid[..]);

            let mut server_scid = [0; 16];
            rand::rand_bytes(&mut server_scid[..]);

            Ok(Pipe {
                client: connect(Some("quic.tech"), &client_scid, config)?,
                server: accept(&server_scid, None, config)?,
            })
        }

        pub fn with_client_config(client_config: &mut Config) -> Result<Pipe> {
            let mut client_scid = [0; 16];
            rand::rand_bytes(&mut client_scid[..]);

            let mut server_scid = [0; 16];
            rand::rand_bytes(&mut server_scid[..]);

            let mut config = Config::new(crate::PROTOCOL_VERSION)?;
            config.load_cert_chain_from_pem_file("examples/cert.crt")?;
            config.load_priv_key_from_pem_file("examples/cert.key")?;
            config.set_application_protos(b"\x06proto1\x06proto2")?;
            config.set_initial_max_data(30);
            config.set_initial_max_stream_data_bidi_local(15);
            config.set_initial_max_stream_data_bidi_remote(15);
            config.set_initial_max_streams_bidi(3);
            config.set_initial_max_streams_uni(3);

            Ok(Pipe {
                client: connect(Some("quic.tech"), &client_scid, client_config)?,
                server: accept(&server_scid, None, &mut config)?,
            })
        }

        pub fn with_server_config(server_config: &mut Config) -> Result<Pipe> {
            let mut client_scid = [0; 16];
            rand::rand_bytes(&mut client_scid[..]);

            let mut server_scid = [0; 16];
            rand::rand_bytes(&mut server_scid[..]);

            let mut config = Config::new(crate::PROTOCOL_VERSION)?;
            config.set_application_protos(b"\x06proto1\x06proto2")?;
            config.set_initial_max_data(30);
            config.set_initial_max_stream_data_bidi_local(15);
            config.set_initial_max_stream_data_bidi_remote(15);
            config.set_initial_max_streams_bidi(3);
            config.set_initial_max_streams_uni(3);

            Ok(Pipe {
                client: connect(Some("quic.tech"), &client_scid, &mut config)?,
                server: accept(&server_scid, None, server_config)?,
            })
        }

        pub fn handshake(&mut self, buf: &mut [u8]) -> Result<()> {
            let mut len = self.client.send(buf)?;

            while !self.client.is_established() && !self.server.is_established() {
                len = recv_send(&mut self.server, buf, len)?;
                len = recv_send(&mut self.client, buf, len)?;
            }

            recv_send(&mut self.server, buf, len)?;

            Ok(())
        }

        pub fn flush_client(&mut self, buf: &mut [u8]) -> Result<()> {
            loop {
                let len = match self.client.send(buf) {
                    Ok(v) => v,

                    Err(Error::Done) => break,

                    Err(e) => return Err(e),
                };

                match self.server.recv(&mut buf[..len]) {
                    Ok(_) => (),

                    Err(Error::Done) => (),

                    Err(e) => return Err(e),
                }
            }

            Ok(())
        }

        pub fn flush_server(&mut self, buf: &mut [u8]) -> Result<()> {
            loop {
                let len = match self.server.send(buf) {
                    Ok(v) => v,

                    Err(Error::Done) => break,

                    Err(e) => return Err(e),
                };

                match self.client.recv(&mut buf[..len]) {
                    Ok(_) => (),

                    Err(Error::Done) => (),

                    Err(e) => return Err(e),
                }
            }

            Ok(())
        }

        pub fn advance(&mut self, buf: &mut [u8]) -> Result<()> {
            let mut client_done = false;
            let mut server_done = false;

            let mut len = 0;

            while !client_done || !server_done {
                len = recv_send(&mut self.client, buf, len)?;
                client_done = len == 0;

                len = recv_send(&mut self.server, buf, len)?;
                server_done = len == 0;
            }

            Ok(())
        }

        pub fn send_pkt_to_server(
            &mut self, pkt_type: packet::Type, frames: &[frame::Frame],
            buf: &mut [u8],
        ) -> Result<usize> {
            let written = encode_pkt(&mut self.client, pkt_type, frames, buf)?;
            recv_send(&mut self.server, buf, written)
        }
    }

    pub fn recv_send(
        conn: &mut Connection, buf: &mut [u8], len: usize,
    ) -> Result<usize> {
        let mut left = len;

        while left > 0 {
            match conn.recv(&mut buf[len - left..len]) {
                Ok(read) => left -= read,

                Err(Error::Done) => break,

                Err(e) => return Err(e),
            }
        }

        assert_eq!(left, 0);

        let mut off = 0;

        while off < buf.len() {
            match conn.send(&mut buf[off..]) {
                Ok(write) => off += write,

                Err(Error::Done) => break,

                Err(e) => return Err(e),
            }
        }

        Ok(off)
    }

    pub fn encode_pkt(
        conn: &mut Connection, pkt_type: packet::Type, frames: &[frame::Frame],
        buf: &mut [u8],
    ) -> Result<usize> {
        let mut b = octets::Octets::with_slice(buf);

        let epoch = pkt_type.to_epoch()?;

        let space = &mut conn.pkt_num_spaces[epoch];

        let pn = space.next_pkt_num;
        let pn_len = packet::pkt_num_len(pn)?;

        let hdr = Header {
            ty: pkt_type,
            version: conn.version,
            dcid: conn.dcid.clone(),
            scid: conn.scid.clone(),
            pkt_num: 0,
            pkt_num_len: pn_len,
            token: conn.token.clone(),
            versions: None,
            key_phase: false,
        };

        hdr.to_bytes(&mut b)?;

        let payload_len = frames.iter().fold(0, |acc, x| acc + x.wire_len()) +
            space.overhead().unwrap();

        if pkt_type != packet::Type::Short {
            let len = pn_len + payload_len;
            b.put_varint(len as u64)?;
        }

        packet::encode_pkt_num(pn, &mut b)?;

        let payload_offset = b.off();

        for frame in frames {
            frame.to_bytes(&mut b)?;
        }

        let aead = match space.crypto_seal {
            Some(ref v) => v,
            None => return Err(Error::InvalidState),
        };

        let written = packet::encrypt_pkt(
            &mut b,
            pn,
            pn_len,
            payload_len,
            payload_offset,
            aead,
        )?;

        space.next_pkt_num += 1;

        Ok(written)
    }

    pub fn decode_pkt(
        conn: &mut Connection, buf: &mut [u8], len: usize,
    ) -> Result<Vec<frame::Frame>> {
        let mut b = octets::Octets::with_slice(&mut buf[..len]);

        let mut hdr = Header::from_bytes(&mut b, conn.scid.len()).unwrap();

        let epoch = hdr.ty.to_epoch()?;

        let aead = conn.pkt_num_spaces[epoch].crypto_open.as_ref().unwrap();

        let payload_len = b.cap();

        packet::decrypt_hdr(&mut b, &mut hdr, &aead).unwrap();

        let pn = packet::decode_pkt_num(
            conn.pkt_num_spaces[epoch].largest_rx_pkt_num,
            hdr.pkt_num,
            hdr.pkt_num_len,
        );

        let mut payload =
            packet::decrypt_pkt(&mut b, pn, hdr.pkt_num_len, payload_len, aead)
                .unwrap();

        let mut frames = Vec::new();

        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;
            frames.push(frame);
        }

        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_params() {
        // Server encodes, client decodes.
        let tp = TransportParams {
            original_connection_id: None,
            max_idle_timeout: 30,
            stateless_reset_token: Some(vec![0xba; 16]),
            max_packet_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 20,
            max_ack_delay: 2_u64.pow(14) - 1,
            disable_active_migration: true,
            active_conn_id_limit: 8,
        };

        let mut raw_params = [42; 256];
        let mut raw_params =
            TransportParams::encode(&tp, PROTOCOL_VERSION, true, &mut raw_params)
                .unwrap();
        assert_eq!(raw_params.len(), 73);

        let new_tp =
            TransportParams::decode(&mut raw_params, PROTOCOL_VERSION, false)
                .unwrap();

        assert_eq!(new_tp, tp);

        // Client encodes, server decodes.
        let tp = TransportParams {
            original_connection_id: None,
            max_idle_timeout: 30,
            stateless_reset_token: None,
            max_packet_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 20,
            max_ack_delay: 2_u64.pow(14) - 1,
            disable_active_migration: true,
            active_conn_id_limit: 8,
        };

        let mut raw_params = [42; 256];
        let mut raw_params = TransportParams::encode(
            &tp,
            PROTOCOL_VERSION,
            false,
            &mut raw_params,
        )
        .unwrap();
        assert_eq!(raw_params.len(), 55);

        let new_tp =
            TransportParams::decode(&mut raw_params, PROTOCOL_VERSION, true)
                .unwrap();

        assert_eq!(new_tp, tp);
    }

    #[test]
    fn transport_params_old() {
        // Server encodes, client decodes.
        let tp = TransportParams {
            original_connection_id: None,
            max_idle_timeout: 30,
            stateless_reset_token: Some(vec![0xba; 16]),
            max_packet_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 20,
            max_ack_delay: 2_u64.pow(14) - 1,
            disable_active_migration: true,
            active_conn_id_limit: 8,
        };

        let mut raw_params = [42; 256];
        let mut raw_params = TransportParams::encode(
            &tp,
            PROTOCOL_VERSION_DRAFT25,
            true,
            &mut raw_params,
        )
        .unwrap();
        assert_eq!(raw_params.len(), 101);

        let new_tp = TransportParams::decode(
            &mut raw_params,
            PROTOCOL_VERSION_DRAFT25,
            false,
        )
        .unwrap();

        assert_eq!(new_tp, tp);

        // Client encodes, server decodes.
        let tp = TransportParams {
            original_connection_id: None,
            max_idle_timeout: 30,
            stateless_reset_token: None,
            max_packet_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 20,
            max_ack_delay: 2_u64.pow(14) - 1,
            disable_active_migration: true,
            active_conn_id_limit: 8,
        };

        let mut raw_params = [42; 256];
        let mut raw_params = TransportParams::encode(
            &tp,
            PROTOCOL_VERSION_DRAFT25,
            false,
            &mut raw_params,
        )
        .unwrap();
        assert_eq!(raw_params.len(), 81);

        let new_tp = TransportParams::decode(
            &mut raw_params,
            PROTOCOL_VERSION_DRAFT25,
            true,
        )
        .unwrap();

        assert_eq!(new_tp, tp);
    }

    #[test]
    fn unknown_version() {
        let mut buf = [0; 65535];

        let mut config = Config::new(0xbabababa).unwrap();
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();

        assert_eq!(pipe.handshake(&mut buf), Err(Error::UnknownVersion));
    }

    #[test]
    fn version_negotiation() {
        let mut buf = [0; 65535];

        let mut config = Config::new(0xbabababa).unwrap();
        config
            .set_application_protos(b"\x06proto1\x06proto2")
            .unwrap();
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();

        let mut len = pipe.client.send(&mut buf).unwrap();

        let hdr = packet::Header::from_slice(&mut buf[..len], 0).unwrap();
        len = crate::negotiate_version(&hdr.scid, &hdr.dcid, &mut buf).unwrap();

        assert_eq!(pipe.client.recv(&mut buf[..len]), Err(Error::Done));

        assert_eq!(pipe.handshake(&mut buf), Ok(()));
    }

    #[test]
    fn different_client_versions() {
        let mut buf = [0; 65535];
        let protos = b"\x06proto1\x06proto2";

        let mut config = Config::new(crate::PROTOCOL_VERSION_DRAFT23).unwrap();
        config.verify_peer(false);
        config.set_application_protos(protos).unwrap();

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let mut config = Config::new(crate::PROTOCOL_VERSION_DRAFT24).unwrap();
        config.verify_peer(false);
        config.set_application_protos(protos).unwrap();

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let mut config = Config::new(crate::PROTOCOL_VERSION_DRAFT25).unwrap();
        config.verify_peer(false);
        config.set_application_protos(protos).unwrap();

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let mut config = Config::new(crate::PROTOCOL_VERSION_DRAFT27).unwrap();
        config.verify_peer(false);
        config.set_application_protos(protos).unwrap();

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(&mut buf), Ok(()));
    }

    #[test]
    fn handshake() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(
            pipe.client.application_proto(),
            pipe.server.application_proto()
        );
    }

    #[test]
    fn handshake_confirmation() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        // Client sends initial flight.
        let mut len = pipe.client.send(&mut buf).unwrap();

        // Server sends initial flight.
        len = testing::recv_send(&mut pipe.server, &mut buf, len).unwrap();

        assert!(!pipe.client.is_established());
        assert!(!pipe.client.handshake_confirmed);

        assert!(!pipe.server.is_established());
        assert!(!pipe.server.handshake_confirmed);

        // Client sends Handshake packet and completes handshake.
        len = testing::recv_send(&mut pipe.client, &mut buf, len).unwrap();

        assert!(pipe.client.is_established());
        assert!(!pipe.client.handshake_confirmed);

        assert!(!pipe.server.is_established());
        assert!(!pipe.server.handshake_confirmed);

        // Server completes handshake and sends HANDSHAKE_DONE.
        len = testing::recv_send(&mut pipe.server, &mut buf, len).unwrap();

        assert!(pipe.client.is_established());
        assert!(!pipe.client.handshake_confirmed);

        assert!(pipe.server.is_established());
        assert!(!pipe.server.handshake_confirmed);

        // Client acks 1-RTT packet, and confirms handshake.
        len = testing::recv_send(&mut pipe.client, &mut buf, len).unwrap();

        assert!(pipe.client.is_established());
        assert!(pipe.client.handshake_confirmed);

        assert!(pipe.server.is_established());
        assert!(!pipe.server.handshake_confirmed);

        // Server handshake is confirmed.
        testing::recv_send(&mut pipe.server, &mut buf, len).unwrap();

        assert!(pipe.client.is_established());
        assert!(pipe.client.handshake_confirmed);

        assert!(pipe.server.is_established());
        assert!(pipe.server.handshake_confirmed);
    }

    #[test]
    fn handshake_alpn_mismatch() {
        let mut buf = [0; 65535];

        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config
            .set_application_protos(b"\x06proto3\x06proto4")
            .unwrap();
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_client_config(&mut config).unwrap();

        assert_eq!(pipe.handshake(&mut buf), Err(Error::TlsFail));

        assert_eq!(pipe.client.application_proto(), b"");
        assert_eq!(pipe.server.application_proto(), b"");
    }

    #[test]
    fn limit_handshake_data() {
        let mut buf = [0; 65535];

        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert-big.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(b"\x06proto1\06proto2")
            .unwrap();

        let mut pipe = testing::Pipe::with_server_config(&mut config).unwrap();

        let client_sent = pipe.client.send(&mut buf).unwrap();
        let server_sent =
            testing::recv_send(&mut pipe.server, &mut buf, client_sent).unwrap();

        assert_eq!(server_sent, (client_sent - 1) * MAX_AMPLIFICATION_FACTOR);
    }

    #[test]
    fn stream() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));

        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert!(!pipe.server.stream_finished(4));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);

        let mut b = [0; 15];
        assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((12, true)));
        assert_eq!(&b[..12], b"hello, world");

        assert!(pipe.server.stream_finished(4));
    }

    #[test]
    fn stream_send_on_32bit_arch() {
        let mut buf = [0; 65535];

        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(b"\x06proto1\x06proto2")
            .unwrap();
        config.set_initial_max_data(2_u64.pow(32) + 5);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(0);
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        // In 32bit arch, send_capacity() should be min(2^32+5, cwnd),
        // not min(5, cwnd)
        assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));

        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert!(!pipe.server.stream_finished(4));
    }

    #[test]
    fn empty_stream_frame() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"aaaaa", 0, false),
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

        let mut readable = pipe.server.readable();
        assert_eq!(readable.next(), Some(4));

        assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((5, false)));

        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"", 5, true),
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));

        let mut readable = pipe.server.readable();
        assert_eq!(readable.next(), Some(4));

        assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((0, true)));

        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"", 15, true),
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::FinalSize)
        );
    }

    #[test]
    fn flow_control_limit() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 4,
                data: stream::RangeBuf::from(b"aaaaaaaaaaaaaaa", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 8,
                data: stream::RangeBuf::from(b"aaaaaaaaaaaaaaa", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 12,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
        ];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::FlowControl),
        );
    }

    #[test]
    fn flow_control_update() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 4,
                data: stream::RangeBuf::from(b"aaaaaaaaaaaaaaa", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 8,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
        ];

        let pkt_type = packet::Type::Short;

        assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

        pipe.server.stream_recv(4, &mut buf).unwrap();
        pipe.server.stream_recv(8, &mut buf).unwrap();

        let frames = [frame::Frame::Stream {
            stream_id: 8,
            data: stream::RangeBuf::from(b"a", 1, false),
        }];

        let len = pipe
            .send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap();

        assert!(len > 0);

        let frames =
            testing::decode_pkt(&mut pipe.client, &mut buf, len).unwrap();
        let mut iter = frames.iter();

        // Ignore ACK.
        iter.next().unwrap();

        assert_eq!(iter.next(), Some(&frame::Frame::MaxData { max: 46 }));
    }

    #[test]
    fn stream_flow_control_limit_bidi() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"aaaaaaaaaaaaaaaa", 0, true),
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::FlowControl),
        );
    }

    #[test]
    fn stream_flow_control_limit_uni() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::Stream {
            stream_id: 2,
            data: stream::RangeBuf::from(b"aaaaaaaaaaa", 0, true),
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::FlowControl),
        );
    }

    #[test]
    fn stream_flow_control_update() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"aaaaaaa", 0, false),
        }];

        let pkt_type = packet::Type::Short;

        assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

        pipe.server.stream_recv(4, &mut buf).unwrap();

        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"a", 7, false),
        }];

        let len = pipe
            .send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap();

        assert!(len > 0);

        let frames =
            testing::decode_pkt(&mut pipe.client, &mut buf, len).unwrap();
        let mut iter = frames.iter();

        // Ignore ACK.
        iter.next().unwrap();

        assert_eq!(
            iter.next(),
            Some(&frame::Frame::MaxStreamData {
                stream_id: 4,
                max: 22,
            })
        );
    }

    #[test]
    fn stream_limit_bidi() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 4,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 8,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 12,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 16,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 20,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 24,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 28,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
        ];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::StreamLimit),
        );
    }

    #[test]
    fn stream_limit_max_bidi() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::MaxStreamsBidi { max: 2u64.pow(60) }];

        let pkt_type = packet::Type::Short;
        assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

        let frames = [frame::Frame::MaxStreamsBidi {
            max: 2u64.pow(60) + 1,
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::StreamLimit),
        );
    }

    #[test]
    fn stream_limit_uni() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 2,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 6,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 10,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 14,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 18,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 22,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 26,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
        ];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::StreamLimit),
        );
    }

    #[test]
    fn stream_limit_max_uni() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::MaxStreamsUni { max: 2u64.pow(60) }];

        let pkt_type = packet::Type::Short;
        assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

        let frames = [frame::Frame::MaxStreamsUni {
            max: 2u64.pow(60) + 1,
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::StreamLimit),
        );
    }

    #[test]
    fn stream_data_overlap() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"aaaaa", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"bbbbb", 3, false),
            },
            frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"ccccc", 6, false),
            },
        ];

        let pkt_type = packet::Type::Short;
        assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

        let mut b = [0; 15];
        assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((11, false)));
        assert_eq!(&b[..11], b"aaaaabbbccc");
    }

    #[test]
    fn stream_data_overlap_with_reordering() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"aaaaa", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"ccccc", 6, false),
            },
            frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"bbbbb", 3, false),
            },
        ];

        let pkt_type = packet::Type::Short;
        assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

        let mut b = [0; 15];
        assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((11, false)));
        assert_eq!(&b[..11], b"aaaaabccccc");
    }

    #[test]
    fn reset_stream_flow_control() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [
            frame::Frame::Stream {
                stream_id: 4,
                data: stream::RangeBuf::from(b"aaaaaaaaaaaaaaa", 0, false),
            },
            frame::Frame::Stream {
                stream_id: 8,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
            frame::Frame::ResetStream {
                stream_id: 8,
                error_code: 0,
                final_size: 15,
            },
            frame::Frame::Stream {
                stream_id: 12,
                data: stream::RangeBuf::from(b"a", 0, false),
            },
        ];

        let pkt_type = packet::Type::Short;
        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Err(Error::FlowControl),
        );
    }

    #[test]
    fn path_challenge() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::PathChallenge {
            data: vec![0xba; 8],
        }];

        let pkt_type = packet::Type::Short;

        let len = pipe
            .send_pkt_to_server(pkt_type, &frames, &mut buf)
            .unwrap();

        assert!(len > 0);

        let frames =
            testing::decode_pkt(&mut pipe.client, &mut buf, len).unwrap();
        let mut iter = frames.iter();

        // Ignore ACK.
        iter.next().unwrap();

        assert_eq!(
            iter.next(),
            Some(&frame::Frame::PathResponse {
                data: vec![0xba; 8],
            })
        );
    }

    #[test]
    /// Simulates reception of an early 1-RTT packet on the server, by
    /// delaying the client's Handshake packet that completes the handshake.
    fn early_1rtt_packet() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        // Client sends initial flight
        let mut len = pipe.client.send(&mut buf).unwrap();

        // Server sends initial flight..
        len = testing::recv_send(&mut pipe.server, &mut buf, len).unwrap();

        // Client sends Handshake packet.
        len = testing::recv_send(&mut pipe.client, &mut buf, len).unwrap();

        // Emulate handshake packet delay by not making server process client
        // packet.
        let mut delayed = (&buf[..len]).to_vec();
        testing::recv_send(&mut pipe.server, &mut buf, 0).unwrap();

        assert!(pipe.client.is_established());

        // Send 1-RTT packet #0.
        let frames = [frame::Frame::Stream {
            stream_id: 0,
            data: stream::RangeBuf::from(b"hello, world", 0, true),
        }];

        let pkt_type = packet::Type::Short;
        let written =
            testing::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
                .unwrap();
        assert_eq!(pipe.server.recv(&mut buf[..written]), Ok(written));

        // Send 1-RTT packet #1.
        let frames = [frame::Frame::Stream {
            stream_id: 4,
            data: stream::RangeBuf::from(b"hello, world", 0, true),
        }];

        let written =
            testing::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)
                .unwrap();
        assert_eq!(pipe.server.recv(&mut buf[..written]), Ok(written));

        assert!(!pipe.server.is_established());

        // Client sent 1-RTT packets 0 and 1, but server hasn't received them.
        //
        // Note that `largest_rx_pkt_num` is initialized to 0, so we need to
        // send another 1-RTT packet to make this check meaningful.
        assert_eq!(
            pipe.server.pkt_num_spaces[packet::EPOCH_APPLICATION]
                .largest_rx_pkt_num,
            0
        );

        // Process delayed packet.
        pipe.server.recv(&mut delayed).unwrap();

        assert!(pipe.server.is_established());

        assert_eq!(
            pipe.server.pkt_num_spaces[packet::EPOCH_APPLICATION]
                .largest_rx_pkt_num,
            0
        );
    }

    #[test]
    fn stream_shutdown_read() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(4, b"hello, world", false), Ok(12));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);

        assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 0), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);

        assert_eq!(pipe.client.stream_send(4, b"bye", false), Ok(3));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);

        assert_eq!(
            pipe.server.stream_shutdown(4, Shutdown::Read, 0),
            Err(Error::Done)
        );
    }

    #[test]
    fn stream_shutdown_write() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(4, b"hello, world", false), Ok(12));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);

        let mut b = [0; 15];
        pipe.server.stream_recv(4, &mut b).unwrap();

        assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
        assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Write, 0), Ok(()));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);

        assert_eq!(pipe.client.stream_send(4, b"bye", false), Ok(3));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);

        assert_eq!(
            pipe.client.stream_shutdown(4, Shutdown::Write, 0),
            Err(Error::Done)
        );
    }

    #[test]
    /// Tests that the order of flushable streams scheduled on the wire is the
    /// same as the order of `stream_send()` calls done by the application.
    fn stream_round_robin() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
        assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
        assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));

        let len = pipe.client.send(&mut buf).unwrap();

        let frames =
            testing::decode_pkt(&mut pipe.server, &mut buf, len).unwrap();

        assert_eq!(
            frames.iter().next(),
            Some(&frame::Frame::Stream {
                stream_id: 8,
                data: stream::RangeBuf::from(b"aaaaa", 0, false),
            })
        );

        let len = pipe.client.send(&mut buf).unwrap();

        let frames =
            testing::decode_pkt(&mut pipe.server, &mut buf, len).unwrap();

        assert_eq!(
            frames.iter().next(),
            Some(&frame::Frame::Stream {
                stream_id: 0,
                data: stream::RangeBuf::from(b"aaaaa", 0, false),
            })
        );

        let len = pipe.client.send(&mut buf).unwrap();

        let frames =
            testing::decode_pkt(&mut pipe.server, &mut buf, len).unwrap();

        assert_eq!(
            frames.iter().next(),
            Some(&frame::Frame::Stream {
                stream_id: 4,
                data: stream::RangeBuf::from(b"aaaaa", 0, false),
            })
        );
    }

    #[test]
    /// Tests the readable iterator.
    fn stream_readable() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        // No readable streams.
        let mut r = pipe.client.readable();
        assert_eq!(r.next(), None);

        assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));

        let mut r = pipe.client.readable();
        assert_eq!(r.next(), None);

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);

        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Server received stream.
        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);

        assert_eq!(
            pipe.server.stream_send(4, b"aaaaaaaaaaaaaaa", false),
            Ok(15)
        );
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.client.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);

        // Client drains stream.
        let mut b = [0; 15];
        pipe.client.stream_recv(4, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.client.readable();
        assert_eq!(r.next(), None);

        // Server shuts down stream.
        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);

        assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 0), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);

        // Client creates multiple streams.
        assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(12, b"aaaaa", false), Ok(5));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.len(), 2);

        assert!(r.next().is_some());
        assert!(r.next().is_some());
        assert!(r.next().is_none());

        assert_eq!(r.len(), 0);
    }

    #[test]
    /// Tests the writable iterator.
    fn stream_writable() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        // No writable streams.
        let mut w = pipe.client.writable();
        assert_eq!(w.next(), None);

        assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));

        // Client created stream.
        let mut w = pipe.client.writable();
        assert_eq!(w.next(), Some(4));
        assert_eq!(w.next(), None);

        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Server created stream.
        let mut w = pipe.server.writable();
        assert_eq!(w.next(), Some(4));
        assert_eq!(w.next(), None);

        assert_eq!(
            pipe.server.stream_send(4, b"aaaaaaaaaaaaaaa", false),
            Ok(15)
        );

        // Server stream is full.
        let mut w = pipe.server.writable();
        assert_eq!(w.next(), None);

        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Client drains stream.
        let mut b = [0; 15];
        pipe.client.stream_recv(4, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Server stream is writable again.
        let mut w = pipe.server.writable();
        assert_eq!(w.next(), Some(4));
        assert_eq!(w.next(), None);

        // Server suts down stream.
        assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 0), Ok(()));

        let mut w = pipe.server.writable();
        assert_eq!(w.next(), None);

        // Client creates multiple streams.
        assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(12, b"aaaaa", false), Ok(5));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut w = pipe.server.writable();
        assert_eq!(w.len(), 2);

        assert!(w.next().is_some());
        assert!(w.next().is_some());
        assert!(w.next().is_none());

        assert_eq!(w.len(), 0);

        // Server finishes stream.
        assert_eq!(pipe.server.stream_send(12, b"aaaaa", true), Ok(5));

        let mut w = pipe.server.writable();
        assert_eq!(w.next(), Some(8));
        assert_eq!(w.next(), None);
    }

    #[test]
    /// Tests that we don't exceed the per-connection flow control limit set by
    /// the peer.
    fn flow_control_limit_send() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(
            pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
            Ok(15)
        );
        assert_eq!(pipe.advance(&mut buf), Ok(()));
        assert_eq!(
            pipe.client.stream_send(4, b"aaaaaaaaaaaaaaa", false),
            Ok(15)
        );
        assert_eq!(pipe.advance(&mut buf), Ok(()));
        assert_eq!(pipe.client.stream_send(8, b"a", false), Ok(0));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert!(r.next().is_some());
        assert!(r.next().is_some());
        assert!(r.next().is_none());
    }

    #[test]
    /// Tests that invalid packets received before any other valid ones cause
    /// the server to close the connection immediately.
    fn invalid_initial() {
        let mut buf = [0; 65535];
        let mut pipe = testing::Pipe::default().unwrap();

        let frames = [frame::Frame::Padding { len: 10 }];

        let written = testing::encode_pkt(
            &mut pipe.client,
            packet::Type::Initial,
            &frames,
            &mut buf,
        )
        .unwrap();

        // Corrupt the packets's last byte to make decryption fail (the last
        // byte is part of the AEAD tag, so changing it means that the packet
        // cannot be authenticated during decryption).
        buf[written - 1] = !buf[written - 1];

        assert_eq!(pipe.server.timeout(), None);

        assert_eq!(
            pipe.server.recv(&mut buf[..written]),
            Err(Error::CryptoFail)
        );
    }

    #[test]
    /// Tests that invalid packets don't cause the connection to be closed.
    fn invalid_packet() {
        let mut buf = [0; 65535];
        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        let frames = [frame::Frame::Padding { len: 10 }];

        let written = testing::encode_pkt(
            &mut pipe.client,
            packet::Type::Short,
            &frames,
            &mut buf,
        )
        .unwrap();

        // Corrupt the packets's last byte to make decryption fail (the last
        // byte is part of the AEAD tag, so changing it means that the packet
        // cannot be authenticated during decryption).
        buf[written - 1] = !buf[written - 1];

        assert_eq!(pipe.server.recv(&mut buf[..written]), Err(Error::Done));

        // Corrupt the packets's first byte to make the header fail decoding.
        buf[0] = 255;

        assert_eq!(pipe.server.recv(&mut buf[..written]), Err(Error::Done));
    }

    #[test]
    /// Tests that the MAX_STREAMS frame is sent for bidirectional streams.
    fn stream_limit_update_bidi() {
        let mut buf = [0; 65535];

        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(b"\x06proto1\x06proto2")
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(0);
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        // Client sends stream data.
        assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(4, b"b", true), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(0, b"b", true), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Server reads stream data.
        let mut b = [0; 15];
        pipe.server.stream_recv(0, &mut b).unwrap();
        pipe.server.stream_recv(4, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Server sends stream data, with fin.
        assert_eq!(pipe.server.stream_send(0, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.server.stream_send(4, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.server.stream_send(4, b"b", true), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.server.stream_send(0, b"b", true), Ok(1));

        // Server sends MAX_STREAMS.
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Client tries to create new streams.
        assert_eq!(pipe.client.stream_send(8, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(12, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(16, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(
            pipe.client.stream_send(20, b"a", false),
            Err(Error::StreamLimit)
        );

        assert_eq!(pipe.server.readable().len(), 3);
    }

    #[test]
    /// Tests that the MAX_STREAMS frame is sent for unirectional streams.
    fn stream_limit_update_uni() {
        let mut buf = [0; 65535];

        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(b"\x06proto1\x06proto2")
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(0);
        config.set_initial_max_streams_uni(3);
        config.verify_peer(false);

        let mut pipe = testing::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        // Client sends stream data.
        assert_eq!(pipe.client.stream_send(2, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(6, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(6, b"b", true), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(2, b"b", true), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Server reads stream data.
        let mut b = [0; 15];
        pipe.server.stream_recv(2, &mut b).unwrap();
        pipe.server.stream_recv(6, &mut b).unwrap();

        // Server sends MAX_STREAMS.
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Client tries to create new streams.
        assert_eq!(pipe.client.stream_send(10, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(14, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.stream_send(18, b"a", false), Ok(1));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(
            pipe.client.stream_send(22, b"a", false),
            Err(Error::StreamLimit)
        );

        assert_eq!(pipe.server.readable().len(), 3);
    }

    #[test]
    /// Tests that the stream's fin flag is properly flushed even if there's no
    /// data in the buffer, and that the buffer becomes readable on the other
    /// side.
    fn stream_zero_length_fin() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(
            pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
            Ok(15)
        );
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(0));
        assert!(r.next().is_none());

        let mut b = [0; 15];
        pipe.server.stream_recv(0, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Client sends zero-length frame.
        assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Stream should be readable on the server after receiving empty fin.
        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(0));
        assert!(r.next().is_none());

        let mut b = [0; 15];
        pipe.server.stream_recv(0, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Client sends zero-length frame (again).
        assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        // Stream should _not_ be readable on the server after receiving empty
        // fin, because it was already finished.
        let mut r = pipe.server.readable();
        assert_eq!(r.next(), None);
    }

    #[test]
    /// Tests that completed streams are garbage collected.
    fn collect_streams() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        assert_eq!(pipe.client.streams.len(), 0);
        assert_eq!(pipe.server.streams.len(), 0);

        assert_eq!(pipe.client.stream_send(0, b"aaaaa", true), Ok(5));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert!(!pipe.client.stream_finished(0));
        assert!(!pipe.server.stream_finished(0));

        assert_eq!(pipe.client.streams.len(), 1);
        assert_eq!(pipe.server.streams.len(), 1);

        let mut b = [0; 5];
        pipe.server.stream_recv(0, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.server.stream_send(0, b"aaaaa", true), Ok(5));
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert!(!pipe.client.stream_finished(0));
        assert!(pipe.server.stream_finished(0));

        assert_eq!(pipe.client.streams.len(), 1);
        assert_eq!(pipe.server.streams.len(), 0);

        let mut b = [0; 5];
        pipe.client.stream_recv(0, &mut b).unwrap();
        assert_eq!(pipe.advance(&mut buf), Ok(()));

        assert_eq!(pipe.client.streams.len(), 0);
        assert_eq!(pipe.server.streams.len(), 0);

        assert!(pipe.client.stream_finished(0));
        assert!(pipe.server.stream_finished(0));

        assert_eq!(pipe.client.stream_send(0, b"", true), Err(Error::Done));

        let frames = [frame::Frame::Stream {
            stream_id: 0,
            data: stream::RangeBuf::from(b"aa", 0, false),
        }];

        let pkt_type = packet::Type::Short;
        assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(39));
    }

    #[test]
    fn config_set_cc_algorithm_name() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();

        assert_eq!(config.set_cc_algorithm_name("reno"), Ok(()));

        // Unknown name.
        assert_eq!(
            config.set_cc_algorithm_name("???"),
            Err(Error::CongestionControl)
        );
    }

    #[test]
    fn peer_cert() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        assert_eq!(pipe.handshake(&mut buf), Ok(()));

        match pipe.client.peer_cert() {
            Some(c) => assert_eq!(c.len(), 919),

            None => panic!("missing server certificate"),
        }
    }

    #[test]
    fn retry() {
        let mut buf = [0; 65535];

        let mut pipe = testing::Pipe::default().unwrap();

        // Client sends initial flight.
        let mut len = pipe.client.send(&mut buf).unwrap();

        // Server sends Retry packet.
        let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();

        let mut scid = [0; MAX_CONN_ID_LEN];
        rand::rand_bytes(&mut scid[..]);

        let token = b"quiche test retry token";

        len =
            packet::retry(&hdr.scid, &hdr.dcid, &scid, token, &mut buf).unwrap();

        // Client receives Retry and sends new Initial.
        assert_eq!(pipe.client.recv(&mut buf[..len]), Err(Error::Done));

        len = pipe.client.send(&mut buf).unwrap();

        let hdr = Header::from_slice(&mut buf[..len], MAX_CONN_ID_LEN).unwrap();
        assert_eq!(&hdr.token.unwrap(), token);
    }
}

pub use crate::packet::Header;
pub use crate::packet::Type;
pub use crate::recovery::CongestionControlAlgorithm;
pub use crate::stream::StreamIter;

mod crypto;
mod ffi;
mod frame;
pub mod h3;
mod minmax;
mod octets;
mod packet;
mod rand;
mod ranges;
mod recovery;
mod stream;
mod tls;
