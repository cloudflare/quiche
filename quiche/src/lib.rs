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
//! ## Configuring connections
//!
//! The first step in establishing a QUIC connection using quiche is creating a
//! [`Config`] object:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(&[b"example-proto"]);
//!
//! // Additional configuration specific to application and use case...
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The [`Config`] object controls important aspects of the QUIC connection such
//! as QUIC version, ALPN IDs, flow control, congestion control, idle timeout
//! and other properties or features.
//!
//! QUIC is a general-purpose transport protocol and there are several
//! configuration properties where there is no reasonable default value. For
//! example, the permitted number of concurrent streams of any particular type
//! is dependent on the application running over QUIC, and other use-case
//! specific concerns.
//!
//! quiche defaults several properties to zero, applications most likely need
//! to set these to something else to satisfy their needs using the following:
//!
//! - [`set_initial_max_streams_bidi()`]
//! - [`set_initial_max_streams_uni()`]
//! - [`set_initial_max_data()`]
//! - [`set_initial_max_stream_data_bidi_local()`]
//! - [`set_initial_max_stream_data_bidi_remote()`]
//! - [`set_initial_max_stream_data_uni()`]
//!
//! [`Config`] also holds TLS configuration. This can be changed by mutators on
//! the an existing object, or by constructing a TLS context manually and
//! creating a configuration using [`with_boring_ssl_ctx_builder()`].
//!
//! A configuration object can be shared among multiple connections.
//!
//! ### Connection setup
//!
//! On the client-side the [`connect()`] utility function can be used to create
//! a new connection, while [`accept()`] is for servers:
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let server_name = "quic.tech";
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! // Client connection.
//! let conn =
//!     quiche::connect(Some(&server_name), &scid, local, peer, &mut config)?;
//!
//! // Server connection.
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! let conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! In both cases, the application is responsible for generating a new source
//! connection ID that will be used to identify the new connection.
//!
//! The application also need to pass the address of the remote peer of the
//! connection: in the case of a client that would be the address of the server
//! it is trying to connect to, and for a server that is the address of the
//! client that initiated the connection.
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
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! let to = socket.local_addr().unwrap();
//!
//! loop {
//!     let (read, from) = socket.recv_from(&mut buf).unwrap();
//!
//!     let recv_info = quiche::RecvInfo { from, to };
//!
//!     let read = match conn.recv(&mut buf[..read], recv_info) {
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
//! The application has to pass a [`RecvInfo`] structure in order to provide
//! additional information about the received packet (such as the address it
//! was received from).
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
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! loop {
//!     let (write, send_info) = match conn.send(&mut out) {
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
//!     socket.send_to(&out[..write], &send_info.to).unwrap();
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application will be provided with a [`SendInfo`] structure providing
//! additional information about the newly created packet (such as the address
//! the packet should be sent to).
//!
//! When packets are sent, the application is responsible for maintaining a
//! timer to react to time-based connection events. The timer expiration can be
//! obtained using the connection's [`timeout()`] method.
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
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
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! // Timeout expired, handle it.
//! conn.on_timeout();
//!
//! // Send more packets as needed after timeout.
//! loop {
//!     let (write, send_info) = match conn.send(&mut out) {
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
//!     socket.send_to(&out[..write], &send_info.to).unwrap();
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ### Pacing
//!
//! It is recommended that applications [pace] sending of outgoing packets to
//! avoid creating packet bursts that could cause short-term congestion and
//! losses in the network.
//!
//! quiche exposes pacing hints for outgoing packets through the [`at`] field
//! of the [`SendInfo`] structure that is returned by the [`send()`] method.
//! This field represents the time when a specific packet should be sent into
//! the network.
//!
//! Applications can use these hints by artificially delaying the sending of
//! packets through platform-specific mechanisms (such as the [`SO_TXTIME`]
//! socket option on Linux), or custom methods (for example by using user-space
//! timers).
//!
//! [pace]: https://datatracker.ietf.org/doc/html/rfc9002#section-7.7
//! [`SO_TXTIME`]: https://man7.org/linux/man-pages/man8/tc-etf.8.html
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
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
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
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
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
//! [`Config`]: https://docs.quic.tech/quiche/struct.Config.html
//! [`set_initial_max_streams_bidi()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_bidi
//! [`set_initial_max_streams_uni()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_uni
//! [`set_initial_max_data()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_data
//! [`set_initial_max_stream_data_bidi_local()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_bidi_local
//! [`set_initial_max_stream_data_bidi_remote()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_bidi_remote
//! [`set_initial_max_stream_data_uni()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_uni
//! [`with_boring_ssl_ctx_builder()`]: https://docs.quic.tech/quiche/struct.Config.html#method.with_boring_ssl_ctx_builder
//! [`connect()`]: fn.connect.html
//! [`accept()`]: fn.accept.html
//! [`recv()`]: struct.Connection.html#method.recv
//! [`RecvInfo`]: struct.RecvInfo.html
//! [`send()`]: struct.Connection.html#method.send
//! [`SendInfo`]: struct.SendInfo.html
//! [`at`]: struct.SendInfo.html#structfield.at
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
//! [`CongestionControlAlgorithm`]: enum.CongestionControlAlgorithm.html
//!
//! ## Feature flags
//!
//! quiche defines a number of [feature flags] to reduce the amount of compiled
//! code and dependencies:
//!
//! * `boringssl-vendored` (default): Build the vendored BoringSSL library.
//!
//! * `boringssl-boring-crate`: Use the BoringSSL library provided by the
//!   [boring] crate. It takes precedence over `boringssl-vendored` if both
//!   features are enabled.
//!
//! * `pkg-config-meta`: Generate pkg-config metadata file for libquiche.
//!
//! * `ffi`: Build and expose the FFI API.
//!
//! * `qlog`: Enable support for the [qlog] logging format.
//!
//! [feature flags]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
//! [boring]: https://crates.io/crates/boring
//! [qlog]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema

#![allow(clippy::upper_case_acronyms)]
#![warn(missing_docs)]
#![warn(unused_qualifications)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
extern crate log;

use std::cmp;

use std::collections::VecDeque;

use std::net::SocketAddr;

use std::str::FromStr;

use std::sync::Arc;

use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "qlog")]
use qlog::events::connectivity::ConnectivityEventType;
#[cfg(feature = "qlog")]
use qlog::events::connectivity::TransportOwner;
#[cfg(feature = "qlog")]
use qlog::events::quic::RecoveryEventType;
#[cfg(feature = "qlog")]
use qlog::events::quic::TransportEventType;
#[cfg(feature = "qlog")]
use qlog::events::DataRecipient;
#[cfg(feature = "qlog")]
use qlog::events::Event;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::EventType;
#[cfg(feature = "qlog")]
use qlog::events::RawInfo;

use smallvec::SmallVec;

use crate::range_buf::DefaultBufFactory;

use crate::recovery::OnAckReceivedOutcome;
use crate::recovery::OnLossDetectionTimeoutOutcome;
use crate::recovery::RecoveryOps;
use crate::recovery::ReleaseDecision;

use crate::stream::RecvAction;
use crate::stream::StreamPriorityKey;

/// The current QUIC wire version.
pub const PROTOCOL_VERSION: u32 = PROTOCOL_VERSION_V1;

/// Supported QUIC versions.
const PROTOCOL_VERSION_V1: u32 = 0x0000_0001;

/// The maximum length of a connection ID.
pub const MAX_CONN_ID_LEN: usize = packet::MAX_CID_LEN as usize;

/// The minimum length of Initial packets sent by a client.
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

/// The default initial RTT.
const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(333);

const PAYLOAD_MIN_LEN: usize = 4;

// PATH_CHALLENGE (9 bytes) + AEAD tag (16 bytes).
const MIN_PROBING_SIZE: usize = 25;

const MAX_AMPLIFICATION_FACTOR: usize = 3;

// The maximum number of tracked packet number ranges that need to be acked.
//
// This represents more or less how many ack blocks can fit in a typical packet.
const MAX_ACK_RANGES: usize = 68;

// The highest possible stream ID allowed.
const MAX_STREAM_ID: u64 = 1 << 60;

// The default max_datagram_size used in congestion control.
const MAX_SEND_UDP_PAYLOAD_SIZE: usize = 1200;

// The default length of DATAGRAM queues.
const DEFAULT_MAX_DGRAM_QUEUE_LEN: usize = 0;

// The default length of PATH_CHALLENGE receive queue.
const DEFAULT_MAX_PATH_CHALLENGE_RX_QUEUE_LEN: usize = 3;

// The DATAGRAM standard recommends either none or 65536 as maximum DATAGRAM
// frames size. We enforce the recommendation for forward compatibility.
const MAX_DGRAM_FRAME_SIZE: u64 = 65536;

// The length of the payload length field.
const PAYLOAD_LENGTH_LEN: usize = 2;

// The number of undecryptable that can be buffered.
const MAX_UNDECRYPTABLE_PACKETS: usize = 10;

const RESERVED_VERSION_MASK: u32 = 0xfafafafa;

// The default size of the receiver connection flow control window.
const DEFAULT_CONNECTION_WINDOW: u64 = 48 * 1024;

// The maximum size of the receiver connection flow control window.
const MAX_CONNECTION_WINDOW: u64 = 24 * 1024 * 1024;

// How much larger the connection flow control window need to be larger than
// the stream flow control window.
const CONNECTION_WINDOW_FACTOR: f64 = 1.5;

// How many probing packet timeouts do we tolerate before considering the path
// validation as failed.
const MAX_PROBING_TIMEOUTS: usize = 3;

// The default initial congestion window size in terms of packet count.
const DEFAULT_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 10;

// The maximum data offset that can be stored in a crypto stream.
const MAX_CRYPTO_STREAM_OFFSET: u64 = 1 << 16;

// The send capacity factor.
const TX_CAP_FACTOR: f64 = 1.0;

/// Ancillary information about incoming packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvInfo {
    /// The remote address the packet was received from.
    pub from: SocketAddr,

    /// The local address the packet was received on.
    pub to: SocketAddr,
}

/// Ancillary information about outgoing packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendInfo {
    /// The local address the packet should be sent from.
    pub from: SocketAddr,

    /// The remote address the packet should be sent to.
    pub to: SocketAddr,

    /// The time to send the packet out.
    ///
    /// See [Pacing] for more details.
    ///
    /// [Pacing]: index.html#pacing
    pub at: Instant,
}

/// The side of the stream to be shut down.
///
/// This should be used when calling [`stream_shutdown()`].
///
/// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum Shutdown {
    /// Stop receiving stream data.
    Read  = 0,

    /// Stop sending stream data.
    Write = 1,
}

/// Qlog logging level.
#[repr(C)]
#[cfg(feature = "qlog")]
#[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
pub enum QlogLevel {
    /// Logs any events of Core importance.
    Core  = 0,

    /// Logs any events of Core and Base importance.
    Base  = 1,

    /// Logs any events of Core, Base and Extra importance
    Extra = 2,
}

/// Stores configuration shared between multiple connections.
pub struct Config {
    local_transport_params: TransportParams,

    version: u32,

    tls_ctx: tls::Context,

    application_protos: Vec<Vec<u8>>,

    grease: bool,

    cc_algorithm: CongestionControlAlgorithm,
    custom_bbr_params: Option<BbrParams>,
    initial_congestion_window_packets: usize,
    enable_relaxed_loss_threshold: bool,

    pmtud: bool,
    pmtud_max_probes: u8,

    hystart: bool,

    pacing: bool,
    /// Send rate limit in Mbps
    max_pacing_rate: Option<u64>,

    tx_cap_factor: f64,

    dgram_recv_max_queue_len: usize,
    dgram_send_max_queue_len: usize,

    path_challenge_recv_max_queue_len: usize,

    max_send_udp_payload_size: usize,

    max_connection_window: u64,
    max_stream_window: u64,

    max_amplification_factor: usize,

    disable_dcid_reuse: bool,

    track_unknown_transport_params: Option<usize>,

    initial_rtt: Duration,
}

// See https://quicwg.org/base-drafts/rfc9000.html#section-15
fn is_reserved_version(version: u32) -> bool {
    version & RESERVED_VERSION_MASK == version
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
        Self::with_tls_ctx(version, tls::Context::new()?)
    }

    /// Creates a config object with the given version and
    /// [`SslContextBuilder`].
    ///
    /// This is useful for applications that wish to manually configure
    /// [`SslContextBuilder`].
    ///
    /// [`SslContextBuilder`]: https://docs.rs/boring/latest/boring/ssl/struct.SslContextBuilder.html
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn with_boring_ssl_ctx_builder(
        version: u32, tls_ctx_builder: boring::ssl::SslContextBuilder,
    ) -> Result<Config> {
        Self::with_tls_ctx(version, tls::Context::from_boring(tls_ctx_builder))
    }

    fn with_tls_ctx(version: u32, tls_ctx: tls::Context) -> Result<Config> {
        if !is_reserved_version(version) && !version_is_supported(version) {
            return Err(Error::UnknownVersion);
        }

        Ok(Config {
            local_transport_params: TransportParams::default(),
            version,
            tls_ctx,
            application_protos: Vec::new(),
            grease: true,
            cc_algorithm: CongestionControlAlgorithm::CUBIC,
            custom_bbr_params: None,
            initial_congestion_window_packets:
                DEFAULT_INITIAL_CONGESTION_WINDOW_PACKETS,
            enable_relaxed_loss_threshold: false,
            pmtud: false,
            pmtud_max_probes: pmtud::MAX_PROBES_DEFAULT,
            hystart: true,
            pacing: true,
            max_pacing_rate: None,

            tx_cap_factor: TX_CAP_FACTOR,

            dgram_recv_max_queue_len: DEFAULT_MAX_DGRAM_QUEUE_LEN,
            dgram_send_max_queue_len: DEFAULT_MAX_DGRAM_QUEUE_LEN,

            path_challenge_recv_max_queue_len:
                DEFAULT_MAX_PATH_CHALLENGE_RX_QUEUE_LEN,

            max_send_udp_payload_size: MAX_SEND_UDP_PAYLOAD_SIZE,

            max_connection_window: MAX_CONNECTION_WINDOW,
            max_stream_window: stream::MAX_STREAM_WINDOW,

            max_amplification_factor: MAX_AMPLIFICATION_FACTOR,

            disable_dcid_reuse: false,

            track_unknown_transport_params: None,
            initial_rtt: DEFAULT_INITIAL_RTT,
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

    /// Specifies a file where trusted CA certificates are stored for the
    /// purposes of certificate verification.
    ///
    /// The content of `file` is parsed as a PEM-encoded certificate chain.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_verify_locations_from_file("/path/to/cert.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.load_verify_locations_from_file(file)
    }

    /// Specifies a directory where trusted CA certificates are stored for the
    /// purposes of certificate verification.
    ///
    /// The content of `dir` a set of PEM-encoded certificate chains.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_verify_locations_from_directory("/path/to/certs")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_verify_locations_from_directory(
        &mut self, dir: &str,
    ) -> Result<()> {
        self.tls_ctx.load_verify_locations_from_directory(dir)
    }

    /// Configures whether to verify the peer's certificate.
    ///
    /// This should usually be `true` for client-side connections and `false`
    /// for server-side ones.
    ///
    /// Note that by default, no verification is performed.
    ///
    /// Also note that on the server-side, enabling verification of the peer
    /// will trigger a certificate request and make authentication errors
    /// fatal, but will still allow anonymous clients (i.e. clients that
    /// don't present a certificate at all). Servers can check whether a
    /// client presented a certificate by calling [`peer_cert()`] if they
    /// need to.
    ///
    /// [`peer_cert()`]: struct.Connection.html#method.peer_cert
    pub fn verify_peer(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify);
    }

    /// Configures whether to do path MTU discovery.
    ///
    /// The default value is `false`.
    pub fn discover_pmtu(&mut self, discover: bool) {
        self.pmtud = discover;
    }

    /// Configures the maximum number of PMTUD probe attempts before treating
    /// a probe size as failed.
    ///
    /// Defaults to 3 per [RFC 8899 Section 5.1.2](https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2).
    /// If 0 is passed, the default value is used.
    pub fn set_pmtud_max_probes(&mut self, max_probes: u8) {
        self.pmtud_max_probes = max_probes;
    }

    /// Configures whether to send GREASE values.
    ///
    /// The default value is `true`.
    pub fn grease(&mut self, grease: bool) {
        self.grease = grease;
    }

    /// Enables logging of secrets.
    ///
    /// When logging is enabled, the [`set_keylog()`] method must be called on
    /// the connection for its cryptographic secrets to be logged in the
    /// [keylog] format to the specified writer.
    ///
    /// [`set_keylog()`]: struct.Connection.html#method.set_keylog
    /// [keylog]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    pub fn log_keys(&mut self) {
        self.tls_ctx.enable_keylog();
    }

    /// Configures the session ticket key material.
    ///
    /// On the server this key will be used to encrypt and decrypt session
    /// tickets, used to perform session resumption without server-side state.
    ///
    /// By default a key is generated internally, and rotated regularly, so
    /// applications don't need to call this unless they need to use a
    /// specific key (e.g. in order to support resumption across multiple
    /// servers), in which case the application is also responsible for
    /// rotating the key to provide forward secrecy.
    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        self.tls_ctx.set_ticket_key(key)
    }

    /// Enables sending or receiving early data.
    pub fn enable_early_data(&mut self) {
        self.tls_ctx.set_early_data_enabled(true);
    }

    /// Configures the list of supported application protocols.
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
    /// config.set_application_protos(&[b"http/1.1", b"http/0.9"]);
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_application_protos(
        &mut self, protos_list: &[&[u8]],
    ) -> Result<()> {
        self.application_protos =
            protos_list.iter().map(|s| s.to_vec()).collect();

        self.tls_ctx.set_alpn(protos_list)
    }

    /// Configures the list of supported application protocols using wire
    /// format.
    ///
    /// The list of protocols `protos` must be a series of non-empty, 8-bit
    /// length-prefixed strings.
    ///
    /// See [`set_application_protos`](Self::set_application_protos) for more
    /// background about application protocols.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_application_protos_wire_format(b"\x08http/1.1\x08http/0.9")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_application_protos_wire_format(
        &mut self, protos: &[u8],
    ) -> Result<()> {
        let mut b = octets::Octets::with_slice(protos);

        let mut protos_list = Vec::new();

        while let Ok(proto) = b.get_bytes_with_u8_length() {
            protos_list.push(proto.buf());
        }

        self.set_application_protos(&protos_list)
    }

    /// Sets the anti-amplification limit factor.
    ///
    /// The default value is `3`.
    pub fn set_max_amplification_factor(&mut self, v: usize) {
        self.max_amplification_factor = v;
    }

    /// Sets the send capacity factor.
    ///
    /// The default value is `1`.
    pub fn set_send_capacity_factor(&mut self, v: f64) {
        self.tx_cap_factor = v;
    }

    /// Sets the connection's initial RTT.
    ///
    /// The default value is `333`.
    pub fn set_initial_rtt(&mut self, v: Duration) {
        self.initial_rtt = v;
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// The default value is infinite, that is, no timeout is used.
    pub fn set_max_idle_timeout(&mut self, v: u64) {
        self.local_transport_params.max_idle_timeout =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `max_udp_payload_size transport` parameter.
    ///
    /// The default value is `65527`.
    pub fn set_max_recv_udp_payload_size(&mut self, v: usize) {
        self.local_transport_params.max_udp_payload_size =
            cmp::min(v as u64, octets::MAX_VAR_INT);
    }

    /// Sets the maximum outgoing UDP payload size.
    ///
    /// The default and minimum value is `1200`.
    pub fn set_max_send_udp_payload_size(&mut self, v: usize) {
        self.max_send_udp_payload_size = cmp::max(v, MAX_SEND_UDP_PAYLOAD_SIZE);
    }

    /// Sets the `initial_max_data` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes of
    /// incoming stream data to be buffered for the whole connection (that is,
    /// data that is not yet read by the application) and will allow more data
    /// to be received as the buffer is consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.local_transport_params.initial_max_data =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_stream_data_bidi_local` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each locally-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_local =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each remotely-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_remote =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_stream_data_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each unidirectional stream
    /// (that is, data that is not yet read by the application) and will allow
    /// more data to be received as the buffer is consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_stream_data_uni =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated bidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// not allow the peer to open any bidirectional streams.
    ///
    /// A bidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown, and all outgoing data has
    /// been acked by the peer (up to the `fin` offset) or the stream's write
    /// direction has been shutdown.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_bidi =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_streams_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated unidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// not allow the peer to open any unidirectional streams.
    ///
    /// A unidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_uni =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `ack_delay_exponent` transport parameter.
    ///
    /// The default value is `3`.
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.local_transport_params.ack_delay_exponent =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `max_ack_delay` transport parameter.
    ///
    /// The default value is `25`.
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.local_transport_params.max_ack_delay =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `active_connection_id_limit` transport parameter.
    ///
    /// The default value is `2`. Lower values will be ignored.
    pub fn set_active_connection_id_limit(&mut self, v: u64) {
        if v >= 2 {
            self.local_transport_params.active_conn_id_limit =
                cmp::min(v, octets::MAX_VAR_INT);
        }
    }

    /// Sets the `disable_active_migration` transport parameter.
    ///
    /// The default value is `false`.
    pub fn set_disable_active_migration(&mut self, v: bool) {
        self.local_transport_params.disable_active_migration = v;
    }

    /// Sets the congestion control algorithm used.
    ///
    /// The default value is `CongestionControlAlgorithm::CUBIC`.
    pub fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }

    /// Sets custom BBR settings.
    ///
    /// This API is experimental and will be removed in the future.
    ///
    /// Currently this only applies if cc_algorithm is
    /// `CongestionControlAlgorithm::Bbr2Gcongestion` is set.
    ///
    /// The default value is `None`.
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub fn set_custom_bbr_params(&mut self, custom_bbr_settings: BbrParams) {
        self.custom_bbr_params = Some(custom_bbr_settings);
    }

    /// Sets the congestion control algorithm used by string.
    ///
    /// The default value is `cubic`. On error `Error::CongestionControl`
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

    /// Sets initial congestion window size in terms of packet count.
    ///
    /// The default value is 10.
    pub fn set_initial_congestion_window_packets(&mut self, packets: usize) {
        self.initial_congestion_window_packets = packets;
    }

    /// Configure whether to enable relaxed loss detection on spurious loss.
    ///
    /// The default value is false.
    pub fn set_enable_relaxed_loss_threshold(&mut self, enable: bool) {
        self.enable_relaxed_loss_threshold = enable;
    }

    /// Configures whether to enable HyStart++.
    ///
    /// The default value is `true`.
    pub fn enable_hystart(&mut self, v: bool) {
        self.hystart = v;
    }

    /// Configures whether to enable pacing.
    ///
    /// The default value is `true`.
    pub fn enable_pacing(&mut self, v: bool) {
        self.pacing = v;
    }

    /// Sets the max value for pacing rate.
    ///
    /// By default pacing rate is not limited.
    pub fn set_max_pacing_rate(&mut self, v: u64) {
        self.max_pacing_rate = Some(v);
    }

    /// Configures whether to enable receiving DATAGRAM frames.
    ///
    /// When enabled, the `max_datagram_frame_size` transport parameter is set
    /// to 65536 as recommended by draft-ietf-quic-datagram-01.
    ///
    /// The default is `false`.
    pub fn enable_dgram(
        &mut self, enabled: bool, recv_queue_len: usize, send_queue_len: usize,
    ) {
        self.local_transport_params.max_datagram_frame_size = if enabled {
            Some(MAX_DGRAM_FRAME_SIZE)
        } else {
            None
        };
        self.dgram_recv_max_queue_len = recv_queue_len;
        self.dgram_send_max_queue_len = send_queue_len;
    }

    /// Configures the max number of queued received PATH_CHALLENGE frames.
    ///
    /// When an endpoint receives a PATH_CHALLENGE frame and the queue is full,
    /// the frame is discarded.
    ///
    /// The default is 3.
    pub fn set_path_challenge_recv_max_queue_len(&mut self, queue_len: usize) {
        self.path_challenge_recv_max_queue_len = queue_len;
    }

    /// Sets the maximum size of the connection window.
    ///
    /// The default value is MAX_CONNECTION_WINDOW (24MBytes).
    pub fn set_max_connection_window(&mut self, v: u64) {
        self.max_connection_window = v;
    }

    /// Sets the maximum size of the stream window.
    ///
    /// The default value is MAX_STREAM_WINDOW (16MBytes).
    pub fn set_max_stream_window(&mut self, v: u64) {
        self.max_stream_window = v;
    }

    /// Sets the initial stateless reset token.
    ///
    /// This value is only advertised by servers. Setting a stateless retry
    /// token as a client has no effect on the connection.
    ///
    /// The default value is `None`.
    pub fn set_stateless_reset_token(&mut self, v: Option<u128>) {
        self.local_transport_params.stateless_reset_token = v;
    }

    /// Sets whether the QUIC connection should avoid reusing DCIDs over
    /// different paths.
    ///
    /// When set to `true`, it ensures that a destination Connection ID is never
    /// reused on different paths. Such behaviour may lead to connection stall
    /// if the peer performs a non-voluntary migration (e.g., NAT rebinding) and
    /// does not provide additional destination Connection IDs to handle such
    /// event.
    ///
    /// The default value is `false`.
    pub fn set_disable_dcid_reuse(&mut self, v: bool) {
        self.disable_dcid_reuse = v;
    }

    /// Enables tracking unknown transport parameters.
    ///
    /// Specify the maximum number of bytes used to track unknown transport
    /// parameters. The size includes the identifier and its value. If storing a
    /// transport parameter would cause the limit to be exceeded, it is quietly
    /// dropped.
    ///
    /// The default is that the feature is disabled.
    pub fn enable_track_unknown_transport_parameters(&mut self, size: usize) {
        self.track_unknown_transport_params = Some(size);
    }
}

/// Tracks the health of the tx_buffered value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum TxBufferTrackingState {
    /// The send buffer is in a good state
    #[default]
    Ok,
    /// The send buffer is in an inconsistent state, which could lead to
    /// connection stalls or excess buffering due to bugs we haven't
    /// tracked down yet.
    Inconsistent,
}

/// A QUIC connection.
pub struct Connection<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// QUIC wire version used for the connection.
    version: u32,

    /// Connection Identifiers.
    ids: cid::ConnectionIdentifiers,

    /// Unique opaque ID for the connection that can be used for logging.
    trace_id: String,

    /// Packet number spaces.
    pkt_num_spaces: [packet::PktNumSpace; packet::Epoch::count()],

    /// The crypto context.
    crypto_ctx: [packet::CryptoContext; packet::Epoch::count()],

    /// Next packet number.
    next_pkt_num: u64,

    // TODO
    // combine with `next_pkt_num`
    /// Track the packet skip context
    pkt_num_manager: packet::PktNumManager,

    /// Peer's transport parameters.
    peer_transport_params: TransportParams,

    /// If tracking unknown transport parameters from a peer, how much space to
    /// use in bytes.
    peer_transport_params_track_unknown: Option<usize>,

    /// Local transport parameters.
    local_transport_params: TransportParams,

    /// TLS handshake state.
    handshake: tls::Handshake,

    /// Serialized TLS session buffer.
    ///
    /// This field is populated when a new session ticket is processed on the
    /// client. On the server this is empty.
    session: Option<Vec<u8>>,

    /// The configuration for recovery.
    recovery_config: recovery::RecoveryConfig,

    /// The path manager.
    paths: path::PathMap,

    /// PATH_CHALLENGE receive queue max length.
    path_challenge_recv_max_queue_len: usize,

    /// Total number of received PATH_CHALLENGE frames.
    path_challenge_rx_count: u64,

    /// List of supported application protocols.
    application_protos: Vec<Vec<u8>>,

    /// Total number of received packets.
    recv_count: usize,

    /// Total number of sent packets.
    sent_count: usize,

    /// Total number of lost packets.
    lost_count: usize,

    /// Total number of lost packets that were later acked.
    spurious_lost_count: usize,

    /// Total number of packets sent with data retransmitted.
    retrans_count: usize,

    /// Total number of sent DATAGRAM frames.
    dgram_sent_count: usize,

    /// Total number of received DATAGRAM frames.
    dgram_recv_count: usize,

    /// Total number of bytes received from the peer.
    rx_data: u64,

    /// Receiver flow controller.
    flow_control: flowcontrol::FlowControl,

    /// Whether we send MAX_DATA frame.
    almost_full: bool,

    /// Number of stream data bytes that can be buffered.
    tx_cap: usize,

    /// The send capacity factor.
    tx_cap_factor: f64,

    /// Number of bytes buffered in the send buffer.
    tx_buffered: usize,

    /// Tracks the health of tx_buffered.
    tx_buffered_state: TxBufferTrackingState,

    /// Total number of bytes sent to the peer.
    tx_data: u64,

    /// Peer's flow control limit for the connection.
    max_tx_data: u64,

    /// Last tx_data before running a full send() loop.
    last_tx_data: u64,

    /// Total number of bytes retransmitted over the connection.
    /// This counts only STREAM and CRYPTO data.
    stream_retrans_bytes: u64,

    /// Total number of bytes sent over the connection.
    sent_bytes: u64,

    /// Total number of bytes received over the connection.
    recv_bytes: u64,

    /// Total number of bytes sent acked over the connection.
    acked_bytes: u64,

    /// Total number of bytes sent lost over the connection.
    lost_bytes: u64,

    /// Streams map, indexed by stream ID.
    streams: stream::StreamMap<F>,

    /// Peer's original destination connection ID. Used by the client to
    /// validate the server's transport parameter.
    odcid: Option<ConnectionId<'static>>,

    /// Peer's retry source connection ID. Used by the client during stateless
    /// retry to validate the server's transport parameter.
    rscid: Option<ConnectionId<'static>>,

    /// Received address verification token.
    token: Option<Vec<u8>>,

    /// Error code and reason to be sent to the peer in a CONNECTION_CLOSE
    /// frame.
    local_error: Option<ConnectionError>,

    /// Error code and reason received from the peer in a CONNECTION_CLOSE
    /// frame.
    peer_error: Option<ConnectionError>,

    /// The connection-level limit at which send blocking occurred.
    blocked_limit: Option<u64>,

    /// Idle timeout expiration time.
    idle_timer: Option<Instant>,

    /// Draining timeout expiration time.
    draining_timer: Option<Instant>,

    /// List of raw packets that were received before they could be decrypted.
    undecryptable_pkts: VecDeque<(Vec<u8>, RecvInfo)>,

    /// The negotiated ALPN protocol.
    alpn: Vec<u8>,

    /// Whether this is a server-side connection.
    is_server: bool,

    /// Whether the initial secrets have been derived.
    derived_initial_secrets: bool,

    /// Whether a version negotiation packet has already been received. Only
    /// relevant for client connections.
    did_version_negotiation: bool,

    /// Whether stateless retry has been performed.
    did_retry: bool,

    /// Whether the peer already updated its connection ID.
    got_peer_conn_id: bool,

    /// Whether the peer verified our initial address.
    peer_verified_initial_address: bool,

    /// Whether the peer's transport parameters were parsed.
    parsed_peer_transport_params: bool,

    /// Whether the connection handshake has been completed.
    handshake_completed: bool,

    /// Whether the HANDSHAKE_DONE frame has been sent.
    handshake_done_sent: bool,

    /// Whether the HANDSHAKE_DONE frame has been acked.
    handshake_done_acked: bool,

    /// Whether the connection handshake has been confirmed.
    handshake_confirmed: bool,

    /// Key phase bit used for outgoing protected packets.
    key_phase: bool,

    /// Whether an ack-eliciting packet has been sent since last receiving a
    /// packet.
    ack_eliciting_sent: bool,

    /// Whether the connection is closed.
    closed: bool,

    /// Whether the connection was timed out.
    timed_out: bool,

    /// Whether to send GREASE.
    grease: bool,

    /// TLS keylog writer.
    keylog: Option<Box<dyn std::io::Write + Send + Sync>>,

    #[cfg(feature = "qlog")]
    qlog: QlogInfo,

    /// DATAGRAM queues.
    dgram_recv_queue: dgram::DatagramQueue,
    dgram_send_queue: dgram::DatagramQueue,

    /// Whether to emit DATAGRAM frames in the next packet.
    emit_dgram: bool,

    /// Whether the connection should prevent from reusing destination
    /// Connection IDs when the peer migrates.
    disable_dcid_reuse: bool,

    /// The number of streams reset by local.
    reset_stream_local_count: u64,

    /// The number of streams stopped by local.
    stopped_stream_local_count: u64,

    /// The number of streams reset by remote.
    reset_stream_remote_count: u64,

    /// The number of streams stopped by remote.
    stopped_stream_remote_count: u64,

    /// The number of DATA_BLOCKED frames sent due to hitting the connection
    /// flow control limit.
    data_blocked_sent_count: u64,

    /// The number of STREAM_DATA_BLOCKED frames sent due to a stream hitting
    /// the stream flow control limit.
    stream_data_blocked_sent_count: u64,

    /// The number of DATA_BLOCKED frames received from the remote endpoint.
    data_blocked_recv_count: u64,

    /// The number of STREAM_DATA_BLOCKED frames received from the remote
    /// endpoint.
    stream_data_blocked_recv_count: u64,

    /// The anti-amplification limit factor.
    max_amplification_factor: usize,
}

/// Creates a new server-side connection.
///
/// The `scid` parameter represents the server's source connection ID, while
/// the optional `odcid` parameter represents the original destination ID the
/// client sent before a Retry packet (this is only required when using the
/// [`retry()`] function). See also the [`accept_with_retry()`] function for
/// more advanced retry cases.
///
/// [`retry()`]: fn.retry.html
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
/// # let local = "127.0.0.1:0".parse().unwrap();
/// # let peer = "127.0.0.1:1234".parse().unwrap();
/// let conn = quiche::accept(&scid, None, local, peer, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline(always)]
pub fn accept(
    scid: &ConnectionId, odcid: Option<&ConnectionId>, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection> {
    accept_with_buf_factory(scid, odcid, local, peer, config)
}

/// Creates a new server-side connection, with a custom buffer generation
/// method.
///
/// The buffers generated can be anything that can be drereferenced as a byte
/// slice. See [`accept`] and [`BufFactory`] for more info.
#[inline]
pub fn accept_with_buf_factory<F: BufFactory>(
    scid: &ConnectionId, odcid: Option<&ConnectionId>, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    // For connections with `odcid` set, we historically used `retry_source_cid =
    // scid`. Keep this behavior to preserve backwards compatibility.
    // `accept_with_retry` allows the SCIDs to be specified separately.
    let retry_cids = odcid.map(|odcid| RetryConnectionIds {
        original_destination_cid: odcid,
        retry_source_cid: scid,
    });

    Connection::new(scid, retry_cids, local, peer, config, true)
}

/// A wrapper for connection IDs used in [`accept_with_retry`].
pub struct RetryConnectionIds<'a> {
    /// The DCID of the first Initial packet received by the server, which
    /// triggered the Retry packet.
    pub original_destination_cid: &'a ConnectionId<'a>,
    /// The SCID of the Retry packet sent by the server. This can be different
    /// from the new connection's SCID.
    pub retry_source_cid: &'a ConnectionId<'a>,
}

/// Creates a new server-side connection after the client responded to a Retry
/// packet.
///
/// To generate a Retry packet in the first place, use the [`retry()`] function.
///
/// The `scid` parameter represents the server's source connection ID, which can
/// be freshly generated after the application has successfully verified the
/// Retry. `retry_cids` is used to tie the new connection to the Initial + Retry
/// exchange that preceded the connection's creation.
///
/// The DCID of the client's Initial packet is inherently untrusted data. It is
/// safe to use the DCID in the `retry_source_cid` field of the
/// `RetryConnectionIds` provided to this function. However, using the Initial's
/// DCID for the `scid` parameter carries risks. Applications are advised to
/// implement their own DCID validation steps before using the DCID in that
/// manner.
#[inline]
pub fn accept_with_retry<F: BufFactory>(
    scid: &ConnectionId, retry_cids: RetryConnectionIds, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    Connection::new(scid, Some(retry_cids), local, peer, config, true)
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
/// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
/// # let local = "127.0.0.1:4321".parse().unwrap();
/// # let peer = "127.0.0.1:1234".parse().unwrap();
/// let conn =
///     quiche::connect(Some(&server_name), &scid, local, peer, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline]
pub fn connect(
    server_name: Option<&str>, scid: &ConnectionId, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection> {
    let mut conn = Connection::new(scid, None, local, peer, config, false)?;

    if let Some(server_name) = server_name {
        conn.handshake.set_host_name(server_name)?;
    }

    Ok(conn)
}

/// Creates a new client-side connection, with a custom buffer generation
/// method.
///
/// The buffers generated can be anything that can be drereferenced as a byte
/// slice. See [`connect`] and [`BufFactory`] for more info.
#[inline]
pub fn connect_with_buffer_factory<F: BufFactory>(
    server_name: Option<&str>, scid: &ConnectionId, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    let mut conn = Connection::new(scid, None, local, peer, config, false)?;

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
#[inline]
pub fn negotiate_version(
    scid: &ConnectionId, dcid: &ConnectionId, out: &mut [u8],
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
/// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
/// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
/// # let local = socket.local_addr().unwrap();
/// # fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
/// #     vec![]
/// # }
/// # fn validate_token<'a>(src: &std::net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
/// #     None
/// # }
/// let (len, peer) = socket.recv_from(&mut buf).unwrap();
///
/// let hdr = quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)?;
///
/// let token = hdr.token.as_ref().unwrap();
///
/// // No token sent by client, create a new one.
/// if token.is_empty() {
///     let new_token = mint_token(&hdr, &peer);
///
///     let len = quiche::retry(
///         &hdr.scid, &hdr.dcid, &scid, &new_token, hdr.version, &mut out,
///     )?;
///
///     socket.send_to(&out[..len], &peer).unwrap();
///     return Ok(());
/// }
///
/// // Client sent token, validate it.
/// let odcid = validate_token(&peer, token);
///
/// if odcid.is_none() {
///     // Invalid address validation token.
///     return Ok(());
/// }
///
/// let conn = quiche::accept(&scid, odcid.as_ref(), local, peer, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline]
pub fn retry(
    scid: &ConnectionId, dcid: &ConnectionId, new_scid: &ConnectionId,
    token: &[u8], version: u32, out: &mut [u8],
) -> Result<usize> {
    packet::retry(scid, dcid, new_scid, token, version, out)
}

/// Returns true if the given protocol version is supported.
#[inline]
pub fn version_is_supported(version: u32) -> bool {
    matches!(version, PROTOCOL_VERSION_V1)
}

/// Pushes a frame to the output packet if there is enough space.
///
/// Returns `true` on success, `false` otherwise. In case of failure it means
/// there is no room to add the frame in the packet. You may retry to add the
/// frame later.
macro_rules! push_frame_to_pkt {
    ($out:expr, $frames:expr, $frame:expr, $left:expr) => {{
        if $frame.wire_len() <= $left {
            $left -= $frame.wire_len();

            $frame.to_bytes(&mut $out)?;

            $frames.push($frame);

            true
        } else {
            false
        }
    }};
}

/// Executes the provided body if the qlog feature is enabled, quiche has been
/// configured with a log writer, the event's importance is within the
/// configured level.
macro_rules! qlog_with_type {
    ($ty:expr, $qlog:expr, $qlog_streamer_ref:ident, $body:block) => {{
        #[cfg(feature = "qlog")]
        {
            if EventImportance::from($ty).is_contained_in(&$qlog.level) {
                if let Some($qlog_streamer_ref) = &mut $qlog.streamer {
                    $body
                }
            }
        }
    }};
}

#[cfg(feature = "qlog")]
const QLOG_PARAMS_SET: EventType =
    EventType::TransportEventType(TransportEventType::ParametersSet);

#[cfg(feature = "qlog")]
const QLOG_PACKET_RX: EventType =
    EventType::TransportEventType(TransportEventType::PacketReceived);

#[cfg(feature = "qlog")]
const QLOG_PACKET_TX: EventType =
    EventType::TransportEventType(TransportEventType::PacketSent);

#[cfg(feature = "qlog")]
const QLOG_DATA_MV: EventType =
    EventType::TransportEventType(TransportEventType::DataMoved);

#[cfg(feature = "qlog")]
const QLOG_METRICS: EventType =
    EventType::RecoveryEventType(RecoveryEventType::MetricsUpdated);

#[cfg(feature = "qlog")]
const QLOG_CONNECTION_CLOSED: EventType =
    EventType::ConnectivityEventType(ConnectivityEventType::ConnectionClosed);

#[cfg(feature = "qlog")]
struct QlogInfo {
    streamer: Option<qlog::streamer::QlogStreamer>,
    logged_peer_params: bool,
    level: EventImportance,
}

#[cfg(feature = "qlog")]
impl Default for QlogInfo {
    fn default() -> Self {
        QlogInfo {
            streamer: None,
            logged_peer_params: false,
            level: EventImportance::Base,
        }
    }
}

impl<F: BufFactory> Connection<F> {
    fn new(
        scid: &ConnectionId, retry_cids: Option<RetryConnectionIds>,
        local: SocketAddr, peer: SocketAddr, config: &mut Config,
        is_server: bool,
    ) -> Result<Connection<F>> {
        let tls = config.tls_ctx.new_handshake()?;
        Connection::with_tls(
            scid, retry_cids, local, peer, config, tls, is_server,
        )
    }

    fn with_tls(
        scid: &ConnectionId, retry_cids: Option<RetryConnectionIds>,
        local: SocketAddr, peer: SocketAddr, config: &Config,
        tls: tls::Handshake, is_server: bool,
    ) -> Result<Connection<F>> {
        let max_rx_data = config.local_transport_params.initial_max_data;

        let scid_as_hex: Vec<String> =
            scid.iter().map(|b| format!("{b:02x}")).collect();

        let reset_token = if is_server {
            config.local_transport_params.stateless_reset_token
        } else {
            None
        };

        let recovery_config = recovery::RecoveryConfig::from_config(config);

        let mut path = path::Path::new(
            local,
            peer,
            &recovery_config,
            config.path_challenge_recv_max_queue_len,
            true,
            Some(config),
        );

        // If we sent a Retry assume the peer's address is verified.
        path.verified_peer_address = retry_cids.is_some();
        // Assume clients validate the server's address implicitly.
        path.peer_verified_local_address = is_server;

        // Do not allocate more than the number of active CIDs.
        let paths = path::PathMap::new(
            path,
            config.local_transport_params.active_conn_id_limit as usize,
            is_server,
        );

        let active_path_id = paths.get_active_path_id()?;

        let ids = cid::ConnectionIdentifiers::new(
            config.local_transport_params.active_conn_id_limit as usize,
            scid,
            active_path_id,
            reset_token,
        );

        let mut conn = Connection {
            version: config.version,

            ids,

            trace_id: scid_as_hex.join(""),

            pkt_num_spaces: [
                packet::PktNumSpace::new(),
                packet::PktNumSpace::new(),
                packet::PktNumSpace::new(),
            ],

            crypto_ctx: [
                packet::CryptoContext::new(),
                packet::CryptoContext::new(),
                packet::CryptoContext::new(),
            ],

            next_pkt_num: 0,

            pkt_num_manager: packet::PktNumManager::new(),

            peer_transport_params: TransportParams::default(),

            peer_transport_params_track_unknown: config
                .track_unknown_transport_params,

            local_transport_params: config.local_transport_params.clone(),

            handshake: tls,

            session: None,

            recovery_config,

            paths,
            path_challenge_recv_max_queue_len: config
                .path_challenge_recv_max_queue_len,
            path_challenge_rx_count: 0,

            application_protos: config.application_protos.clone(),

            recv_count: 0,
            sent_count: 0,
            lost_count: 0,
            spurious_lost_count: 0,
            retrans_count: 0,
            dgram_sent_count: 0,
            dgram_recv_count: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            acked_bytes: 0,
            lost_bytes: 0,

            rx_data: 0,
            flow_control: flowcontrol::FlowControl::new(
                max_rx_data,
                cmp::min(max_rx_data / 2 * 3, DEFAULT_CONNECTION_WINDOW),
                config.max_connection_window,
            ),
            almost_full: false,

            tx_cap: 0,
            tx_cap_factor: config.tx_cap_factor,

            tx_buffered: 0,
            tx_buffered_state: TxBufferTrackingState::Ok,

            tx_data: 0,
            max_tx_data: 0,
            last_tx_data: 0,

            stream_retrans_bytes: 0,

            streams: stream::StreamMap::new(
                config.local_transport_params.initial_max_streams_bidi,
                config.local_transport_params.initial_max_streams_uni,
                config.max_stream_window,
            ),

            odcid: None,

            rscid: None,

            token: None,

            local_error: None,

            peer_error: None,

            blocked_limit: None,

            idle_timer: None,

            draining_timer: None,

            undecryptable_pkts: VecDeque::new(),

            alpn: Vec::new(),

            is_server,

            derived_initial_secrets: false,

            did_version_negotiation: false,

            did_retry: false,

            got_peer_conn_id: false,

            // Assume clients validate the server's address implicitly.
            peer_verified_initial_address: is_server,

            parsed_peer_transport_params: false,

            handshake_completed: false,

            handshake_done_sent: false,
            handshake_done_acked: false,

            handshake_confirmed: false,

            key_phase: false,

            ack_eliciting_sent: false,

            closed: false,

            timed_out: false,

            grease: config.grease,

            keylog: None,

            #[cfg(feature = "qlog")]
            qlog: Default::default(),

            dgram_recv_queue: dgram::DatagramQueue::new(
                config.dgram_recv_max_queue_len,
            ),

            dgram_send_queue: dgram::DatagramQueue::new(
                config.dgram_send_max_queue_len,
            ),

            emit_dgram: true,

            disable_dcid_reuse: config.disable_dcid_reuse,

            reset_stream_local_count: 0,
            stopped_stream_local_count: 0,
            reset_stream_remote_count: 0,
            stopped_stream_remote_count: 0,

            data_blocked_sent_count: 0,
            stream_data_blocked_sent_count: 0,
            data_blocked_recv_count: 0,
            stream_data_blocked_recv_count: 0,

            max_amplification_factor: config.max_amplification_factor,
        };

        if let Some(retry_cids) = retry_cids {
            conn.local_transport_params
                .original_destination_connection_id =
                Some(retry_cids.original_destination_cid.to_vec().into());

            conn.local_transport_params.retry_source_connection_id =
                Some(retry_cids.retry_source_cid.to_vec().into());

            conn.did_retry = true;
        }

        conn.local_transport_params.initial_source_connection_id =
            Some(conn.ids.get_scid(0)?.cid.to_vec().into());

        conn.handshake.init(is_server)?;

        conn.handshake
            .use_legacy_codepoint(config.version != PROTOCOL_VERSION_V1);

        conn.encode_transport_params()?;

        // Derive initial secrets for the client. We can do this here because
        // we already generated the random destination connection ID.
        if !is_server {
            let mut dcid = [0; 16];
            rand::rand_bytes(&mut dcid[..]);

            let (aead_open, aead_seal) = crypto::derive_initial_key_material(
                &dcid,
                conn.version,
                conn.is_server,
                false,
            )?;

            let reset_token = conn.peer_transport_params.stateless_reset_token;
            conn.set_initial_dcid(
                dcid.to_vec().into(),
                reset_token,
                active_path_id,
            )?;

            conn.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
            conn.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);

            conn.derived_initial_secrets = true;
        }

        Ok(conn)
    }

    /// Sets keylog output to the designated [`Writer`].
    ///
    /// This needs to be called as soon as the connection is created, to avoid
    /// missing some early logs.
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[inline]
    pub fn set_keylog(&mut self, writer: Box<dyn std::io::Write + Send + Sync>) {
        self.keylog = Some(writer);
    }

    /// Sets qlog output to the designated [`Writer`].
    ///
    /// Only events included in `QlogLevel::Base` are written. The serialization
    /// format is JSON-SEQ.
    ///
    /// This needs to be called as soon as the connection is created, to avoid
    /// missing some early logs.
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
    pub fn set_qlog(
        &mut self, writer: Box<dyn std::io::Write + Send + Sync>, title: String,
        description: String,
    ) {
        self.set_qlog_with_level(writer, title, description, QlogLevel::Base)
    }

    /// Sets qlog output to the designated [`Writer`].
    ///
    /// Only qlog events included in the specified `QlogLevel` are written. The
    /// serialization format is JSON-SEQ.
    ///
    /// This needs to be called as soon as the connection is created, to avoid
    /// missing some early logs.
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
    pub fn set_qlog_with_level(
        &mut self, writer: Box<dyn std::io::Write + Send + Sync>, title: String,
        description: String, qlog_level: QlogLevel,
    ) {
        let vp = if self.is_server {
            qlog::VantagePointType::Server
        } else {
            qlog::VantagePointType::Client
        };

        let level = match qlog_level {
            QlogLevel::Core => EventImportance::Core,

            QlogLevel::Base => EventImportance::Base,

            QlogLevel::Extra => EventImportance::Extra,
        };

        self.qlog.level = level;

        let trace = qlog::TraceSeq::new(
            qlog::VantagePoint {
                name: None,
                ty: vp,
                flow: None,
            },
            Some(title.to_string()),
            Some(description.to_string()),
            Some(qlog::Configuration {
                time_offset: Some(0.0),
                original_uris: None,
            }),
            None,
        );

        let mut streamer = qlog::streamer::QlogStreamer::new(
            qlog::QLOG_VERSION.to_string(),
            Some(title),
            Some(description),
            None,
            Instant::now(),
            trace,
            self.qlog.level,
            writer,
        );

        streamer.start_log().ok();

        let ev_data = self
            .local_transport_params
            .to_qlog(TransportOwner::Local, self.handshake.cipher());

        // This event occurs very early, so just mark the relative time as 0.0.
        streamer.add_event(Event::with_time(0.0, ev_data)).ok();

        self.qlog.streamer = Some(streamer);
    }

    /// Returns a mutable reference to the QlogStreamer, if it exists.
    #[cfg(feature = "qlog")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
    pub fn qlog_streamer(&mut self) -> Option<&mut qlog::streamer::QlogStreamer> {
        self.qlog.streamer.as_mut()
    }

    /// Configures the given session for resumption.
    ///
    /// On the client, this can be used to offer the given serialized session,
    /// as returned by [`session()`], for resumption.
    ///
    /// This must only be called immediately after creating a connection, that
    /// is, before any packet is sent or received.
    ///
    /// [`session()`]: struct.Connection.html#method.session
    #[inline]
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        let mut b = octets::Octets::with_slice(session);

        let session_len = b.get_u64()? as usize;
        let session_bytes = b.get_bytes(session_len)?;

        self.handshake.set_session(session_bytes.as_ref())?;

        let raw_params_len = b.get_u64()? as usize;
        let raw_params_bytes = b.get_bytes(raw_params_len)?;

        let peer_params = TransportParams::decode(
            raw_params_bytes.as_ref(),
            self.is_server,
            self.peer_transport_params_track_unknown,
        )?;

        self.process_peer_transport_params(peer_params)?;

        Ok(())
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// This must only be called immediately after creating a connection, that
    /// is, before any packet is sent or received.
    ///
    /// The default value is infinite, that is, no timeout is used unless
    /// already configured when creating the connection.
    pub fn set_max_idle_timeout(&mut self, v: u64) -> Result<()> {
        self.local_transport_params.max_idle_timeout =
            cmp::min(v, octets::MAX_VAR_INT);

        self.encode_transport_params()
    }

    /// Sets the congestion control algorithm used.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_cc_algorithm()`].
    ///
    /// [`Config::set_cc_algorithm()`]: struct.Config.html#method.set_cc_algorithm
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_cc_algorithm_in_handshake(
        ssl: &mut boring::ssl::SslRef, algo: CongestionControlAlgorithm,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.cc_algorithm = algo;

        Ok(())
    }

    /// Sets custom BBR settings.
    ///
    /// This API is experimental and will be removed in the future.
    ///
    /// Currently this only applies if cc_algorithm is
    /// `CongestionControlAlgorithm::Bbr2Gcongestion` is set.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_custom_bbr_settings()`].
    ///
    /// [`Config::set_custom_bbr_settings()`]: struct.Config.html#method.set_custom_bbr_settings
    #[cfg(all(feature = "boringssl-boring-crate", feature = "internal"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    #[doc(hidden)]
    pub fn set_custom_bbr_settings_in_handshake(
        ssl: &mut boring::ssl::SslRef, custom_bbr_params: BbrParams,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.custom_bbr_params = Some(custom_bbr_params);

        Ok(())
    }

    /// Sets the congestion control algorithm used by string.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_cc_algorithm_name()`].
    ///
    /// [`Config::set_cc_algorithm_name()`]: struct.Config.html#method.set_cc_algorithm_name
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_cc_algorithm_name_in_handshake(
        ssl: &mut boring::ssl::SslRef, name: &str,
    ) -> Result<()> {
        let cc_algo = CongestionControlAlgorithm::from_str(name)?;
        Self::set_cc_algorithm_in_handshake(ssl, cc_algo)
    }

    /// Sets initial congestion window size in terms of packet count.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_initial_congestion_window_packets()`].
    ///
    /// [`Config::set_initial_congestion_window_packets()`]: struct.Config.html#method.set_initial_congestion_window_packets
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_initial_congestion_window_packets_in_handshake(
        ssl: &mut boring::ssl::SslRef, packets: usize,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.initial_congestion_window_packets = packets;

        Ok(())
    }

    /// Configure whether to enable relaxed loss detection on spurious loss.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_enable_relaxed_loss_threshold()`].
    ///
    /// [`Config::set_enable_relaxed_loss_threshold()`]: struct.Config.html#method.set_enable_relaxed_loss_threshold
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_enable_relaxed_loss_threshold_in_handshake(
        ssl: &mut boring::ssl::SslRef, enable: bool,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.enable_relaxed_loss_threshold = enable;

        Ok(())
    }

    /// Configures whether to enable HyStart++.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::enable_hystart()`].
    ///
    /// [`Config::enable_hystart()`]: struct.Config.html#method.enable_hystart
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_hystart_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: bool,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.hystart = v;

        Ok(())
    }

    /// Configures whether to enable pacing.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::enable_pacing()`].
    ///
    /// [`Config::enable_pacing()`]: struct.Config.html#method.enable_pacing
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_pacing_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: bool,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.pacing = v;

        Ok(())
    }

    /// Sets the max value for pacing rate.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_max_pacing_rate()`].
    ///
    /// [`Config::set_max_pacing_rate()`]: struct.Config.html#method.set_max_pacing_rate
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_max_pacing_rate_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: Option<u64>,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.max_pacing_rate = v;

        Ok(())
    }

    /// Sets the maximum outgoing UDP payload size.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_max_send_udp_payload_size()`].
    ///
    /// [`Config::set_max_send_udp_payload_size()`]: struct.Config.html#method.set_max_send_udp_payload_size
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_max_send_udp_payload_size_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: usize,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.max_send_udp_payload_size = v;

        Ok(())
    }

    /// Sets the send capacity factor.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_send_capacity_factor()`].
    ///
    /// [`Config::set_max_send_udp_payload_size()`]: struct.Config.html#method.set_send_capacity_factor
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_send_capacity_factor_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: f64,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.tx_cap_factor = v;

        Ok(())
    }

    /// Configures whether to do path MTU discovery.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::discover_pmtu()`].
    ///
    /// [`Config::discover_pmtu()`]: struct.Config.html#method.discover_pmtu
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_discover_pmtu_in_handshake(
        ssl: &mut boring::ssl::SslRef, discover: bool, max_probes: u8,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.pmtud = Some((discover, max_probes));

        Ok(())
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_max_idle_timeout()`].
    ///
    /// [`Config::set_max_idle_timeout()`]: struct.Config.html#method.set_max_idle_timeout
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_max_idle_timeout_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: u64,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.local_transport_params.max_idle_timeout = v;

        Self::set_transport_parameters_in_hanshake(
            ex_data.local_transport_params.clone(),
            ex_data.is_server,
            ssl,
        )
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_initial_max_streams_bidi()`].
    ///
    /// [`Config::set_initial_max_streams_bidi()`]: struct.Config.html#method.set_initial_max_streams_bidi
    #[cfg(feature = "boringssl-boring-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-boring-crate")))]
    pub fn set_initial_max_streams_bidi_in_handshake(
        ssl: &mut boring::ssl::SslRef, v: u64,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.local_transport_params.initial_max_streams_bidi = v;

        Self::set_transport_parameters_in_hanshake(
            ex_data.local_transport_params.clone(),
            ex_data.is_server,
            ssl,
        )
    }

    #[cfg(feature = "boringssl-boring-crate")]
    fn set_transport_parameters_in_hanshake(
        params: TransportParams, is_server: bool, ssl: &mut boring::ssl::SslRef,
    ) -> Result<()> {
        use foreign_types_shared::ForeignTypeRef;

        // In order to apply the new parameter to the TLS state before TPs are
        // written into a TLS message, we need to re-encode all TPs immediately.
        //
        // Since we don't have direct access to the main `Connection` object, we
        // need to re-create the `Handshake` state from the `SslRef`.
        //
        // SAFETY: the `Handshake` object must not be drop()ed, otherwise it
        // would free the underlying BoringSSL structure.
        let mut handshake =
            unsafe { tls::Handshake::from_ptr(ssl.as_ptr() as _) };
        handshake.set_quic_transport_params(&params, is_server)?;

        // Avoid running `drop(handshake)` as that would free the underlying
        // handshake state.
        std::mem::forget(handshake);

        Ok(())
    }

    /// Processes QUIC packets received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned. On error the connection will be closed by calling [`close()`]
    /// with the appropriate error code.
    ///
    /// Coalesced packets will be processed as necessary.
    ///
    /// Note that the contents of the input buffer `buf` might be modified by
    /// this function due to, for example, in-place decryption.
    ///
    /// [`close()`]: struct.Connection.html#method.close
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (read, from) = socket.recv_from(&mut buf).unwrap();
    ///
    ///     let recv_info = quiche::RecvInfo {
    ///         from,
    ///         to: local,
    ///     };
    ///
    ///     let read = match conn.recv(&mut buf[..read], recv_info) {
    ///         Ok(v) => v,
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize> {
        let len = buf.len();

        if len == 0 {
            return Err(Error::BufferTooShort);
        }

        let recv_pid = self.paths.path_id_from_addrs(&(info.to, info.from));

        if let Some(recv_pid) = recv_pid {
            let recv_path = self.paths.get_mut(recv_pid)?;

            // Keep track of how many bytes we received from the client, so we
            // can limit bytes sent back before address validation, to a
            // multiple of this. The limit needs to be increased early on, so
            // that if there is an error there is enough credit to send a
            // CONNECTION_CLOSE.
            //
            // It doesn't matter if the packets received were valid or not, we
            // only need to track the total amount of bytes received.
            //
            // Note that we also need to limit the number of bytes we sent on a
            // path if we are not the host that initiated its usage.
            if self.is_server && !recv_path.verified_peer_address {
                recv_path.max_send_bytes += len * self.max_amplification_factor;
            }
        } else if !self.is_server {
            // If a client receives packets from an unknown server address,
            // the client MUST discard these packets.
            trace!(
                "{} client received packet from unknown address {:?}, dropping",
                self.trace_id,
                info,
            );

            return Ok(len);
        }

        let mut done = 0;
        let mut left = len;

        // Process coalesced packets.
        while left > 0 {
            let read = match self.recv_single(
                &mut buf[len - left..len],
                &info,
                recv_pid,
            ) {
                Ok(v) => v,

                Err(Error::Done) => {
                    // If the packet can't be processed or decrypted, check if
                    // it's a stateless reset.
                    if self.is_stateless_reset(&buf[len - left..len]) {
                        trace!("{} packet is a stateless reset", self.trace_id);

                        self.mark_closed();
                    }

                    left
                },

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

        // Even though the packet was previously "accepted", it
        // should be safe to forward the error, as it also comes
        // from the `recv()` method.
        self.process_undecrypted_0rtt_packets()?;

        Ok(done)
    }

    fn process_undecrypted_0rtt_packets(&mut self) -> Result<()> {
        // Process previously undecryptable 0-RTT packets if the decryption key
        // is now available.
        if self.crypto_ctx[packet::Epoch::Application]
            .crypto_0rtt_open
            .is_some()
        {
            while let Some((mut pkt, info)) = self.undecryptable_pkts.pop_front()
            {
                if let Err(e) = self.recv(&mut pkt, info) {
                    self.undecryptable_pkts.clear();

                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Returns true if a QUIC packet is a stateless reset.
    fn is_stateless_reset(&self, buf: &[u8]) -> bool {
        // If the packet is too small, then we just throw it away.
        let buf_len = buf.len();
        if buf_len < 21 {
            return false;
        }

        // TODO: we should iterate over all active destination connection IDs
        // and check against their reset token.
        match self.peer_transport_params.stateless_reset_token {
            Some(token) => {
                let token_len = 16;

                crypto::verify_slices_are_equal(
                    &token.to_be_bytes(),
                    &buf[buf_len - token_len..buf_len],
                )
                .is_ok()
            },

            None => false,
        }
    }

    /// Processes a single QUIC packet received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned. When the [`Done`] error is returned, processing of the
    /// remainder of the incoming UDP datagram should be interrupted.
    ///
    /// Note that a server might observe a new 4-tuple, preventing to
    /// know in advance to which path the incoming packet belongs to (`recv_pid`
    /// is `None`). As a client, packets from unknown 4-tuple are dropped
    /// beforehand (see `recv()`).
    ///
    /// On error, an error other than [`Done`] is returned.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    fn recv_single(
        &mut self, buf: &mut [u8], info: &RecvInfo, recv_pid: Option<usize>,
    ) -> Result<usize> {
        let now = Instant::now();

        if buf.is_empty() {
            return Err(Error::Done);
        }

        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        let is_closing = self.local_error.is_some();

        if is_closing {
            return Err(Error::Done);
        }

        let buf_len = buf.len();

        let mut b = octets::OctetsMut::with_slice(buf);

        let mut hdr = Header::from_bytes(&mut b, self.source_id().len())
            .map_err(|e| {
                drop_pkt_on_err(
                    e,
                    self.recv_count,
                    self.is_server,
                    &self.trace_id,
                )
            })?;

        if hdr.ty == Type::VersionNegotiation {
            // Version negotiation packets can only be sent by the server.
            if self.is_server {
                return Err(Error::Done);
            }

            // Ignore duplicate version negotiation.
            if self.did_version_negotiation {
                return Err(Error::Done);
            }

            // Ignore version negotiation if any other packet has already been
            // successfully processed.
            if self.recv_count > 0 {
                return Err(Error::Done);
            }

            if hdr.dcid != self.source_id() {
                return Err(Error::Done);
            }

            if hdr.scid != self.destination_id() {
                return Err(Error::Done);
            }

            trace!("{} rx pkt {:?}", self.trace_id, hdr);

            let versions = hdr.versions.ok_or(Error::Done)?;

            // Ignore version negotiation if the version already selected is
            // listed.
            if versions.contains(&self.version) {
                return Err(Error::Done);
            }

            let supported_versions =
                versions.iter().filter(|&&v| version_is_supported(v));

            let mut found_version = false;

            for &v in supported_versions {
                found_version = true;

                // The final version takes precedence over draft ones.
                if v == PROTOCOL_VERSION_V1 {
                    self.version = v;
                    break;
                }

                self.version = cmp::max(self.version, v);
            }

            if !found_version {
                // We don't support any of the versions offered.
                //
                // While a man-in-the-middle attacker might be able to
                // inject a version negotiation packet that triggers this
                // failure, the window of opportunity is very small and
                // this error is quite useful for debugging, so don't just
                // ignore the packet.
                return Err(Error::UnknownVersion);
            }

            self.did_version_negotiation = true;

            // Derive Initial secrets based on the new version.
            let (aead_open, aead_seal) = crypto::derive_initial_key_material(
                &self.destination_id(),
                self.version,
                self.is_server,
                true,
            )?;

            // Reset connection state to force sending another Initial packet.
            self.drop_epoch_state(packet::Epoch::Initial, now);
            self.got_peer_conn_id = false;
            self.handshake.clear()?;

            self.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
            self.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);

            self.handshake
                .use_legacy_codepoint(self.version != PROTOCOL_VERSION_V1);

            // Encode transport parameters again, as the new version might be
            // using a different format.
            self.encode_transport_params()?;

            return Err(Error::Done);
        }

        if hdr.ty == Type::Retry {
            // Retry packets can only be sent by the server.
            if self.is_server {
                return Err(Error::Done);
            }

            // Ignore duplicate retry.
            if self.did_retry {
                return Err(Error::Done);
            }

            // Check if Retry packet is valid.
            if packet::verify_retry_integrity(
                &b,
                &self.destination_id(),
                self.version,
            )
            .is_err()
            {
                return Err(Error::Done);
            }

            trace!("{} rx pkt {:?}", self.trace_id, hdr);

            self.token = hdr.token;
            self.did_retry = true;

            // Remember peer's new connection ID.
            self.odcid = Some(self.destination_id().into_owned());

            self.set_initial_dcid(
                hdr.scid.clone(),
                None,
                self.paths.get_active_path_id()?,
            )?;

            self.rscid = Some(self.destination_id().into_owned());

            // Derive Initial secrets using the new connection ID.
            let (aead_open, aead_seal) = crypto::derive_initial_key_material(
                &hdr.scid,
                self.version,
                self.is_server,
                true,
            )?;

            // Reset connection state to force sending another Initial packet.
            self.drop_epoch_state(packet::Epoch::Initial, now);
            self.got_peer_conn_id = false;
            self.handshake.clear()?;

            self.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
            self.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);

            return Err(Error::Done);
        }

        if self.is_server && !self.did_version_negotiation {
            if !version_is_supported(hdr.version) {
                return Err(Error::UnknownVersion);
            }

            self.version = hdr.version;
            self.did_version_negotiation = true;

            self.handshake
                .use_legacy_codepoint(self.version != PROTOCOL_VERSION_V1);

            // Encode transport parameters again, as the new version might be
            // using a different format.
            self.encode_transport_params()?;
        }

        if hdr.ty != Type::Short && hdr.version != self.version {
            // At this point version negotiation was already performed, so
            // ignore packets that don't match the connection's version.
            return Err(Error::Done);
        }

        // Long header packets have an explicit payload length, but short
        // packets don't so just use the remaining capacity in the buffer.
        let payload_len = if hdr.ty == Type::Short {
            b.cap()
        } else {
            b.get_varint().map_err(|e| {
                drop_pkt_on_err(
                    e.into(),
                    self.recv_count,
                    self.is_server,
                    &self.trace_id,
                )
            })? as usize
        };

        // Make sure the buffer is same or larger than an explicit
        // payload length.
        if payload_len > b.cap() {
            return Err(drop_pkt_on_err(
                Error::InvalidPacket,
                self.recv_count,
                self.is_server,
                &self.trace_id,
            ));
        }

        // Derive initial secrets on the server.
        if !self.derived_initial_secrets {
            let (aead_open, aead_seal) = crypto::derive_initial_key_material(
                &hdr.dcid,
                self.version,
                self.is_server,
                false,
            )?;

            self.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
            self.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);

            self.derived_initial_secrets = true;
        }

        // Select packet number space epoch based on the received packet's type.
        let epoch = hdr.ty.to_epoch()?;

        // Select AEAD context used to open incoming packet.
        let aead = if hdr.ty == Type::ZeroRTT {
            // Only use 0-RTT key if incoming packet is 0-RTT.
            self.crypto_ctx[epoch].crypto_0rtt_open.as_ref()
        } else {
            // Otherwise use the packet number space's main key.
            self.crypto_ctx[epoch].crypto_open.as_ref()
        };

        // Finally, discard packet if no usable key is available.
        let mut aead = match aead {
            Some(v) => v,

            None => {
                if hdr.ty == Type::ZeroRTT &&
                    self.undecryptable_pkts.len() < MAX_UNDECRYPTABLE_PACKETS &&
                    !self.is_established()
                {
                    // Buffer 0-RTT packets when the required read key is not
                    // available yet, and process them later.
                    //
                    // TODO: in the future we might want to buffer other types
                    // of undecryptable packets as well.
                    let pkt_len = b.off() + payload_len;
                    let pkt = (b.buf()[..pkt_len]).to_vec();

                    self.undecryptable_pkts.push_back((pkt, *info));
                    return Ok(pkt_len);
                }

                let e = drop_pkt_on_err(
                    Error::CryptoFail,
                    self.recv_count,
                    self.is_server,
                    &self.trace_id,
                );

                return Err(e);
            },
        };

        let aead_tag_len = aead.alg().tag_len();

        packet::decrypt_hdr(&mut b, &mut hdr, aead).map_err(|e| {
            drop_pkt_on_err(e, self.recv_count, self.is_server, &self.trace_id)
        })?;

        let pn = packet::decode_pkt_num(
            self.pkt_num_spaces[epoch].largest_rx_pkt_num,
            hdr.pkt_num,
            hdr.pkt_num_len,
        );

        let pn_len = hdr.pkt_num_len;

        trace!(
            "{} rx pkt {:?} len={} pn={} {}",
            self.trace_id,
            hdr,
            payload_len,
            pn,
            AddrTupleFmt(info.from, info.to)
        );

        #[cfg(feature = "qlog")]
        let mut qlog_frames = vec![];

        // Check for key update.
        let mut aead_next = None;

        if self.handshake_confirmed &&
            hdr.ty != Type::ZeroRTT &&
            hdr.key_phase != self.key_phase
        {
            // Check if this packet arrived before key update.
            if let Some(key_update) = self.crypto_ctx[epoch]
                .key_update
                .as_ref()
                .and_then(|key_update| {
                    (pn < key_update.pn_on_update).then_some(key_update)
                })
            {
                aead = &key_update.crypto_open;
            } else {
                trace!("{} peer-initiated key update", self.trace_id);

                aead_next = Some((
                    self.crypto_ctx[epoch]
                        .crypto_open
                        .as_ref()
                        .unwrap()
                        .derive_next_packet_key()?,
                    self.crypto_ctx[epoch]
                        .crypto_seal
                        .as_ref()
                        .unwrap()
                        .derive_next_packet_key()?,
                ));

                // `aead_next` is always `Some()` at this point, so the `unwrap()`
                // will never fail.
                aead = &aead_next.as_ref().unwrap().0;
            }
        }

        let mut payload = packet::decrypt_pkt(
            &mut b,
            pn,
            pn_len,
            payload_len,
            aead,
        )
        .map_err(|e| {
            drop_pkt_on_err(e, self.recv_count, self.is_server, &self.trace_id)
        })?;

        if self.pkt_num_spaces[epoch].recv_pkt_num.contains(pn) {
            trace!("{} ignored duplicate packet {}", self.trace_id, pn);
            return Err(Error::Done);
        }

        // Packets with no frames are invalid.
        if payload.cap() == 0 {
            return Err(Error::InvalidPacket);
        }

        // Now that we decrypted the packet, let's see if we can map it to an
        // existing path.
        let recv_pid = if hdr.ty == Type::Short && self.got_peer_conn_id {
            let pkt_dcid = ConnectionId::from_ref(&hdr.dcid);
            self.get_or_create_recv_path_id(recv_pid, &pkt_dcid, buf_len, info)?
        } else {
            // During handshake, we are on the initial path.
            self.paths.get_active_path_id()?
        };

        // The key update is verified once a packet is successfully decrypted
        // using the new keys.
        if let Some((open_next, seal_next)) = aead_next {
            if !self.crypto_ctx[epoch]
                .key_update
                .as_ref()
                .is_none_or(|prev| prev.update_acked)
            {
                // Peer has updated keys twice without awaiting confirmation.
                return Err(Error::KeyUpdate);
            }

            trace!("{} key update verified", self.trace_id);

            let _ = self.crypto_ctx[epoch].crypto_seal.replace(seal_next);

            let open_prev = self.crypto_ctx[epoch]
                .crypto_open
                .replace(open_next)
                .unwrap();

            let recv_path = self.paths.get_mut(recv_pid)?;

            self.crypto_ctx[epoch].key_update = Some(packet::KeyUpdate {
                crypto_open: open_prev,
                pn_on_update: pn,
                update_acked: false,
                timer: now + (recv_path.recovery.pto() * 3),
            });

            self.key_phase = !self.key_phase;

            qlog_with_type!(QLOG_PACKET_RX, self.qlog, q, {
                let trigger = Some(
                    qlog::events::security::KeyUpdateOrRetiredTrigger::RemoteUpdate,
                );

                let ev_data_client =
                    EventData::KeyUpdated(qlog::events::security::KeyUpdated {
                        key_type:
                            qlog::events::security::KeyType::Client1RttSecret,
                        trigger: trigger.clone(),
                        ..Default::default()
                    });

                q.add_event_data_with_instant(ev_data_client, now).ok();

                let ev_data_server =
                    EventData::KeyUpdated(qlog::events::security::KeyUpdated {
                        key_type:
                            qlog::events::security::KeyType::Server1RttSecret,
                        trigger,
                        ..Default::default()
                    });

                q.add_event_data_with_instant(ev_data_server, now).ok();
            });
        }

        if !self.is_server && !self.got_peer_conn_id {
            if self.odcid.is_none() {
                self.odcid = Some(self.destination_id().into_owned());
            }

            // Replace the randomly generated destination connection ID with
            // the one supplied by the server.
            self.set_initial_dcid(
                hdr.scid.clone(),
                self.peer_transport_params.stateless_reset_token,
                recv_pid,
            )?;

            self.got_peer_conn_id = true;
        }

        if self.is_server && !self.got_peer_conn_id {
            self.set_initial_dcid(hdr.scid.clone(), None, recv_pid)?;

            if !self.did_retry {
                self.local_transport_params
                    .original_destination_connection_id =
                    Some(hdr.dcid.to_vec().into());

                self.encode_transport_params()?;
            }

            self.got_peer_conn_id = true;
        }

        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK and PADDING.
        let mut ack_elicited = false;

        // Process packet payload. If a frame cannot be processed, store the
        // error and stop further packet processing.
        let mut frame_processing_err = None;

        // To know if the peer migrated the connection, we need to keep track
        // whether this is a non-probing packet.
        let mut probing = true;

        // Process packet payload.
        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;

            qlog_with_type!(QLOG_PACKET_RX, self.qlog, _q, {
                qlog_frames.push(frame.to_qlog());
            });

            if frame.ack_eliciting() {
                ack_elicited = true;
            }

            if !frame.probing() {
                probing = false;
            }

            if let Err(e) = self.process_frame(frame, &hdr, recv_pid, epoch, now)
            {
                frame_processing_err = Some(e);
                break;
            }
        }

        qlog_with_type!(QLOG_PACKET_RX, self.qlog, q, {
            let packet_size = b.len();

            let qlog_pkt_hdr = qlog::events::quic::PacketHeader::with_type(
                hdr.ty.to_qlog(),
                Some(pn),
                Some(hdr.version),
                Some(&hdr.scid),
                Some(&hdr.dcid),
            );

            let qlog_raw_info = RawInfo {
                length: Some(packet_size as u64),
                payload_length: Some(payload_len as u64),
                data: None,
            };

            let ev_data =
                EventData::PacketReceived(qlog::events::quic::PacketReceived {
                    header: qlog_pkt_hdr,
                    frames: Some(qlog_frames),
                    raw: Some(qlog_raw_info),
                    ..Default::default()
                });

            q.add_event_data_with_instant(ev_data, now).ok();
        });

        qlog_with_type!(QLOG_PACKET_RX, self.qlog, q, {
            let recv_path = self.paths.get_mut(recv_pid)?;
            recv_path.recovery.maybe_qlog(q, now);
        });

        if let Some(e) = frame_processing_err {
            // Any frame error is terminal, so now just return.
            return Err(e);
        }

        // Only log the remote transport parameters once the connection is
        // established (i.e. after frames have been fully parsed) and only
        // once per connection.
        if self.is_established() {
            qlog_with_type!(QLOG_PARAMS_SET, self.qlog, q, {
                if !self.qlog.logged_peer_params {
                    let ev_data = self
                        .peer_transport_params
                        .to_qlog(TransportOwner::Remote, self.handshake.cipher());

                    q.add_event_data_with_instant(ev_data, now).ok();

                    self.qlog.logged_peer_params = true;
                }
            });
        }

        // Process acked frames. Note that several packets from several paths
        // might have been acked by the received packet.
        for (_, p) in self.paths.iter_mut() {
            while let Some(acked) = p.recovery.next_acked_frame(epoch) {
                match acked {
                    frame::Frame::Ping {
                        mtu_probe: Some(mtu_probe),
                    } =>
                        if let Some(pmtud) = p.pmtud.as_mut() {
                            trace!(
                                "{} pmtud probe acked; probe size {:?}",
                                self.trace_id,
                                mtu_probe
                            );

                            // Ensure the probe is within the supported MTU range
                            // before updating the max datagram size
                            if let Some(current_mtu) =
                                pmtud.successful_probe(mtu_probe)
                            {
                                qlog_with_type!(
                                    EventType::ConnectivityEventType(
                                        ConnectivityEventType::MtuUpdated
                                    ),
                                    self.qlog,
                                    q,
                                    {
                                        let pmtu_data = EventData::MtuUpdated(
                                            qlog::events::connectivity::MtuUpdated {
                                                old: Some(
                                                    p.recovery.max_datagram_size()
                                                        as u16,
                                                ),
                                                new: current_mtu as u16,
                                                done: Some(true),
                                            },
                                        );

                                        q.add_event_data_with_instant(
                                            pmtu_data, now,
                                        )
                                        .ok();
                                    }
                                );

                                p.recovery
                                    .pmtud_update_max_datagram_size(current_mtu);
                            }
                        },

                    frame::Frame::ACK { ranges, .. } => {
                        // Stop acknowledging packets less than or equal to the
                        // largest acknowledged in the sent ACK frame that, in
                        // turn, got acked.
                        if let Some(largest_acked) = ranges.last() {
                            self.pkt_num_spaces[epoch]
                                .recv_pkt_need_ack
                                .remove_until(largest_acked);
                        }
                    },

                    frame::Frame::CryptoHeader { offset, length } => {
                        self.crypto_ctx[epoch]
                            .crypto_stream
                            .send
                            .ack_and_drop(offset, length);
                    },

                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        ..
                    } => {
                        // Update tx_buffered and emit qlog before checking if the
                        // stream still exists.  The client does need to ACK
                        // frames that were received after the client sends a
                        // ResetStream.
                        self.tx_buffered =
                            self.tx_buffered.saturating_sub(length);

                        qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                            let ev_data = EventData::DataMoved(
                                qlog::events::quic::DataMoved {
                                    stream_id: Some(stream_id),
                                    offset: Some(offset),
                                    length: Some(length as u64),
                                    from: Some(DataRecipient::Transport),
                                    to: Some(DataRecipient::Dropped),
                                    ..Default::default()
                                },
                            );

                            q.add_event_data_with_instant(ev_data, now).ok();
                        });

                        let stream = match self.streams.get_mut(stream_id) {
                            Some(v) => v,

                            None => continue,
                        };

                        stream.send.ack_and_drop(offset, length);

                        let priority_key = Arc::clone(&stream.priority_key);

                        // Only collect the stream if it is complete and not
                        // readable or writable.
                        //
                        // If it is readable, it will get collected when
                        // stream_recv() is next used.
                        //
                        // If it is writable, it might mean that the stream
                        // has been stopped by the peer (i.e. a STOP_SENDING
                        // frame is received), in which case before collecting
                        // the stream we will need to propagate the
                        // `StreamStopped` error to the application. It will
                        // instead get collected when one of stream_capacity(),
                        // stream_writable(), stream_send(), ... is next called.
                        //
                        // Note that we can't use `is_writable()` here because
                        // it returns false if the stream is stopped. Instead,
                        // since the stream is marked as writable when a
                        // STOP_SENDING frame is received, we check the writable
                        // queue directly instead.
                        let is_writable = priority_key.writable.is_linked() &&
                            // Ensure that the stream is actually stopped.
                            stream.send.is_stopped();

                        let is_complete = stream.is_complete();
                        let is_readable = stream.is_readable();

                        if is_complete && !is_readable && !is_writable {
                            let local = stream.local;
                            self.streams.collect(stream_id, local);
                        }
                    },

                    frame::Frame::HandshakeDone => {
                        // Explicitly set this to true, so that if the frame was
                        // already scheduled for retransmission, it is aborted.
                        self.handshake_done_sent = true;

                        self.handshake_done_acked = true;
                    },

                    frame::Frame::ResetStream { stream_id, .. } => {
                        let stream = match self.streams.get_mut(stream_id) {
                            Some(v) => v,

                            None => continue,
                        };

                        let priority_key = Arc::clone(&stream.priority_key);

                        // Only collect the stream if it is complete and not
                        // readable or writable.
                        //
                        // If it is readable, it will get collected when
                        // stream_recv() is next used.
                        //
                        // If it is writable, it might mean that the stream
                        // has been stopped by the peer (i.e. a STOP_SENDING
                        // frame is received), in which case before collecting
                        // the stream we will need to propagate the
                        // `StreamStopped` error to the application. It will
                        // instead get collected when one of stream_capacity(),
                        // stream_writable(), stream_send(), ... is next called.
                        //
                        // Note that we can't use `is_writable()` here because
                        // it returns false if the stream is stopped. Instead,
                        // since the stream is marked as writable when a
                        // STOP_SENDING frame is received, we check the writable
                        // queue directly instead.
                        let is_writable = priority_key.writable.is_linked() &&
                            // Ensure that the stream is actually stopped.
                            stream.send.is_stopped();

                        let is_complete = stream.is_complete();
                        let is_readable = stream.is_readable();

                        if is_complete && !is_readable && !is_writable {
                            let local = stream.local;
                            self.streams.collect(stream_id, local);
                        }
                    },

                    _ => (),
                }
            }
        }

        // Now that we processed all the frames, if there is a path that has no
        // Destination CID, try to allocate one.
        let no_dcid = self
            .paths
            .iter_mut()
            .filter(|(_, p)| p.active_dcid_seq.is_none());

        for (pid, p) in no_dcid {
            if self.ids.zero_length_dcid() {
                p.active_dcid_seq = Some(0);
                continue;
            }

            let dcid_seq = match self.ids.lowest_available_dcid_seq() {
                Some(seq) => seq,
                None => break,
            };

            self.ids.link_dcid_to_path_id(dcid_seq, pid)?;

            p.active_dcid_seq = Some(dcid_seq);
        }

        // We only record the time of arrival of the largest packet number
        // that still needs to be acked, to be used for ACK delay calculation.
        if self.pkt_num_spaces[epoch].recv_pkt_need_ack.last() < Some(pn) {
            self.pkt_num_spaces[epoch].largest_rx_pkt_time = now;
        }

        self.pkt_num_spaces[epoch].recv_pkt_num.insert(pn);

        self.pkt_num_spaces[epoch].recv_pkt_need_ack.push_item(pn);

        self.pkt_num_spaces[epoch].ack_elicited =
            cmp::max(self.pkt_num_spaces[epoch].ack_elicited, ack_elicited);

        self.pkt_num_spaces[epoch].largest_rx_pkt_num =
            cmp::max(self.pkt_num_spaces[epoch].largest_rx_pkt_num, pn);

        if !probing {
            self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num = cmp::max(
                self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num,
                pn,
            );

            // Did the peer migrated to another path?
            let active_path_id = self.paths.get_active_path_id()?;

            if self.is_server &&
                recv_pid != active_path_id &&
                self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num == pn
            {
                self.on_peer_migrated(recv_pid, self.disable_dcid_reuse, now)?;
            }
        }

        if let Some(idle_timeout) = self.idle_timeout() {
            self.idle_timer = Some(now + idle_timeout);
        }

        // Update send capacity.
        self.update_tx_cap();

        self.recv_count += 1;
        self.paths.get_mut(recv_pid)?.recv_count += 1;

        let read = b.off() + aead_tag_len;

        self.recv_bytes += read as u64;
        self.paths.get_mut(recv_pid)?.recv_bytes += read as u64;

        // An Handshake packet has been received from the client and has been
        // successfully processed, so we can drop the initial state and consider
        // the client's address to be verified.
        if self.is_server && hdr.ty == Type::Handshake {
            self.drop_epoch_state(packet::Epoch::Initial, now);

            self.paths.get_mut(recv_pid)?.verified_peer_address = true;
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
    ///  * When the application sends data to the peer (for example, any time
    ///    [`stream_send()`] or [`stream_shutdown()`] are called).
    ///
    ///  * When the application receives data from the peer (for example any
    ///    time [`stream_recv()`] is called).
    ///
    /// Once [`is_draining()`] returns `true`, it is no longer necessary to call
    /// `send()` and all calls will return [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`is_draining()`]: struct.Connection.html#method.is_draining
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (write, send_info) = match conn.send(&mut out) {
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
    ///     socket.send_to(&out[..write], &send_info.to).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send(&mut self, out: &mut [u8]) -> Result<(usize, SendInfo)> {
        self.send_on_path(out, None, None)
    }

    /// Writes a single QUIC packet to be sent to the peer from the specified
    /// local address `from` to the destination address `to`.
    ///
    /// The behavior of this method differs depending on the value of the `from`
    /// and `to` parameters:
    ///
    ///  * If both are `Some`, then the method only consider the 4-tuple
    ///    (`from`, `to`). Application can monitor the 4-tuple availability,
    ///    either by monitoring [`path_event_next()`] events or by relying on
    ///    the [`paths_iter()`] method. If the provided 4-tuple does not exist
    ///    on the connection (anymore), it returns an [`InvalidState`].
    ///
    ///  * If `from` is `Some` and `to` is `None`, then the method only
    ///    considers sending packets on paths having `from` as local address.
    ///
    ///  * If `to` is `Some` and `from` is `None`, then the method only
    ///    considers sending packets on paths having `to` as peer address.
    ///
    ///  * If both are `None`, all available paths are considered.
    ///
    /// On success the number of bytes written to the output buffer is
    /// returned, or [`Done`] if there was nothing to write.
    ///
    /// The application should call `send_on_path()` multiple times until
    /// [`Done`] is returned, indicating that there are no more packets to
    /// send. It is recommended that `send_on_path()` be called in the
    /// following cases:
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
    ///  * When the application receives data from the peer (for example any
    ///    time [`stream_recv()`] is called).
    ///
    /// Once [`is_draining()`] returns `true`, it is no longer necessary to call
    /// `send_on_path()` and all calls will return [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`path_event_next()`]: struct.Connection.html#method.path_event_next
    /// [`paths_iter()`]: struct.Connection.html#method.paths_iter
    /// [`is_draining()`]: struct.Connection.html#method.is_draining
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (write, send_info) = match conn.send_on_path(&mut out, Some(local), Some(peer)) {
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
    ///     socket.send_to(&out[..write], &send_info.to).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send_on_path(
        &mut self, out: &mut [u8], from: Option<SocketAddr>,
        to: Option<SocketAddr>,
    ) -> Result<(usize, SendInfo)> {
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        let now = Instant::now();

        if self.local_error.is_none() {
            self.do_handshake(now)?;
        }

        // Forwarding the error value here could confuse
        // applications, as they may not expect getting a `recv()`
        // error when calling `send()`.
        //
        // We simply fall-through to sending packets, which should
        // take care of terminating the connection as needed.
        let _ = self.process_undecrypted_0rtt_packets();

        // There's no point in trying to send a packet if the Initial secrets
        // have not been derived yet, so return early.
        if !self.derived_initial_secrets {
            return Err(Error::Done);
        }

        let mut has_initial = false;

        let mut done = 0;

        // Limit output packet size to respect the sender and receiver's
        // maximum UDP payload size limit.
        let mut left = cmp::min(out.len(), self.max_send_udp_payload_size());

        let send_pid = match (from, to) {
            (Some(f), Some(t)) => self
                .paths
                .path_id_from_addrs(&(f, t))
                .ok_or(Error::InvalidState)?,

            _ => self.get_send_path_id(from, to)?,
        };

        let send_path = self.paths.get_mut(send_pid)?;

        // Update max datagram size to allow path MTU discovery probe to be sent.
        if let Some(pmtud) = send_path.pmtud.as_mut() {
            if pmtud.should_probe() {
                let size = if self.handshake_confirmed || self.handshake_completed
                {
                    pmtud.get_probe_size()
                } else {
                    pmtud.get_current_mtu()
                };

                send_path.recovery.pmtud_update_max_datagram_size(size);

                left =
                    cmp::min(out.len(), send_path.recovery.max_datagram_size());
            }
        }

        // Limit data sent by the server based on the amount of data received
        // from the client before its address is validated.
        if !send_path.verified_peer_address && self.is_server {
            left = cmp::min(left, send_path.max_send_bytes);
        }

        // Generate coalesced packets.
        while left > 0 {
            let (ty, written) = match self.send_single(
                &mut out[done..done + left],
                send_pid,
                has_initial,
                now,
            ) {
                Ok(v) => v,

                Err(Error::BufferTooShort) | Err(Error::Done) => break,

                Err(e) => return Err(e),
            };

            done += written;
            left -= written;

            match ty {
                Type::Initial => has_initial = true,

                // No more packets can be coalesced after a 1-RTT.
                Type::Short => break,

                _ => (),
            };

            // When sending multiple PTO probes, don't coalesce them together,
            // so they are sent on separate UDP datagrams.
            if let Ok(epoch) = ty.to_epoch() {
                if self.paths.get_mut(send_pid)?.recovery.loss_probes(epoch) > 0 {
                    break;
                }
            }

            // Don't coalesce packets that must go on different paths.
            if !(from.is_some() && to.is_some()) &&
                self.get_send_path_id(from, to)? != send_pid
            {
                break;
            }
        }

        if done == 0 {
            self.last_tx_data = self.tx_data;

            return Err(Error::Done);
        }

        if has_initial && left > 0 && done < MIN_CLIENT_INITIAL_LEN {
            let pad_len = cmp::min(left, MIN_CLIENT_INITIAL_LEN - done);

            // Fill padding area with null bytes, to avoid leaking information
            // in case the application reuses the packet buffer.
            out[done..done + pad_len].fill(0);

            done += pad_len;
        }

        let send_path = self.paths.get(send_pid)?;

        let info = SendInfo {
            from: send_path.local_addr(),
            to: send_path.peer_addr(),

            at: send_path.recovery.get_packet_send_time(now),
        };

        Ok((done, info))
    }

    fn send_single(
        &mut self, out: &mut [u8], send_pid: usize, has_initial: bool,
        now: Instant,
    ) -> Result<(Type, usize)> {
        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.is_draining() {
            return Err(Error::Done);
        }

        let is_closing = self.local_error.is_some();

        let out_len = out.len();

        let mut b = octets::OctetsMut::with_slice(out);

        let pkt_type = self.write_pkt_type(send_pid)?;

        let max_dgram_len = if !self.dgram_send_queue.is_empty() {
            self.dgram_max_writable_len()
        } else {
            None
        };

        let epoch = pkt_type.to_epoch()?;
        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];

        // Process lost frames. There might be several paths having lost frames.
        for (_, p) in self.paths.iter_mut() {
            while let Some(lost) = p.recovery.next_lost_frame(epoch) {
                match lost {
                    frame::Frame::CryptoHeader { offset, length } => {
                        crypto_ctx.crypto_stream.send.retransmit(offset, length);

                        self.stream_retrans_bytes += length as u64;
                        p.stream_retrans_bytes += length as u64;

                        self.retrans_count += 1;
                        p.retrans_count += 1;
                    },

                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        let stream = match self.streams.get_mut(stream_id) {
                            // Only retransmit data if the stream is not closed
                            // or stopped.
                            Some(v) if !v.send.is_stopped() => v,

                            // Data on a closed stream will not be retransmitted
                            // or acked after it is declared lost, so update
                            // tx_buffered and qlog.
                            _ => {
                                self.tx_buffered =
                                    self.tx_buffered.saturating_sub(length);

                                qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                                    let ev_data = EventData::DataMoved(
                                        qlog::events::quic::DataMoved {
                                            stream_id: Some(stream_id),
                                            offset: Some(offset),
                                            length: Some(length as u64),
                                            from: Some(DataRecipient::Transport),
                                            to: Some(DataRecipient::Dropped),
                                            ..Default::default()
                                        },
                                    );

                                    q.add_event_data_with_instant(ev_data, now)
                                        .ok();
                                });

                                continue;
                            },
                        };

                        let was_flushable = stream.is_flushable();

                        let empty_fin = length == 0 && fin;

                        stream.send.retransmit(offset, length);

                        // If the stream is now flushable push it to the
                        // flushable queue, but only if it wasn't already
                        // queued.
                        //
                        // Consider the stream flushable also when we are
                        // sending a zero-length frame that has the fin flag
                        // set.
                        if (stream.is_flushable() || empty_fin) && !was_flushable
                        {
                            let priority_key = Arc::clone(&stream.priority_key);
                            self.streams.insert_flushable(&priority_key);
                        }

                        self.stream_retrans_bytes += length as u64;
                        p.stream_retrans_bytes += length as u64;

                        self.retrans_count += 1;
                        p.retrans_count += 1;
                    },

                    frame::Frame::ACK { .. } => {
                        pkt_space.ack_elicited = true;
                    },

                    frame::Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } =>
                        if self.streams.get(stream_id).is_some() {
                            self.streams
                                .insert_reset(stream_id, error_code, final_size);
                        },

                    // Retransmit HANDSHAKE_DONE only if it hasn't been acked at
                    // least once already.
                    frame::Frame::HandshakeDone if !self.handshake_done_acked => {
                        self.handshake_done_sent = false;
                    },

                    frame::Frame::MaxStreamData { stream_id, .. } => {
                        if self.streams.get(stream_id).is_some() {
                            self.streams.insert_almost_full(stream_id);
                        }
                    },

                    frame::Frame::MaxData { .. } => {
                        self.almost_full = true;
                    },

                    frame::Frame::NewConnectionId { seq_num, .. } => {
                        self.ids.mark_advertise_new_scid_seq(seq_num, true);
                    },

                    frame::Frame::RetireConnectionId { seq_num } => {
                        self.ids.mark_retire_dcid_seq(seq_num, true)?;
                    },

                    frame::Frame::Ping {
                        mtu_probe: Some(failed_probe),
                    } =>
                        if let Some(pmtud) = p.pmtud.as_mut() {
                            trace!("pmtud probe dropped: {failed_probe}");
                            pmtud.failed_probe(failed_probe);
                        },

                    _ => (),
                }
            }
        }
        self.check_tx_buffered_invariant();

        let is_app_limited = self.delivery_rate_check_if_app_limited();
        let n_paths = self.paths.len();
        let path = self.paths.get_mut(send_pid)?;
        let flow_control = &mut self.flow_control;
        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];
        let pkt_num_manager = &mut self.pkt_num_manager;

        let mut left = if let Some(pmtud) = path.pmtud.as_mut() {
            // Limit output buffer size by estimated path MTU.
            cmp::min(pmtud.get_current_mtu(), b.cap())
        } else {
            b.cap()
        };

        if pkt_num_manager.should_skip_pn(self.handshake_completed) {
            pkt_num_manager.set_skip_pn(Some(self.next_pkt_num));
            self.next_pkt_num += 1;
        };
        let pn = self.next_pkt_num;

        let largest_acked_pkt =
            path.recovery.get_largest_acked_on_epoch(epoch).unwrap_or(0);
        let pn_len = packet::pkt_num_len(pn, largest_acked_pkt);

        // The AEAD overhead at the current encryption level.
        let crypto_overhead = crypto_ctx.crypto_overhead().ok_or(Error::Done)?;

        let dcid_seq = path.active_dcid_seq.ok_or(Error::OutOfIdentifiers)?;

        let dcid =
            ConnectionId::from_ref(self.ids.get_dcid(dcid_seq)?.cid.as_ref());

        let scid = if let Some(scid_seq) = path.active_scid_seq {
            ConnectionId::from_ref(self.ids.get_scid(scid_seq)?.cid.as_ref())
        } else if pkt_type == Type::Short {
            ConnectionId::default()
        } else {
            return Err(Error::InvalidState);
        };

        let hdr = Header {
            ty: pkt_type,

            version: self.version,

            dcid,
            scid,

            pkt_num: 0,
            pkt_num_len: pn_len,

            // Only clone token for Initial packets, as other packets don't have
            // this field (Retry doesn't count, as it's not encoded as part of
            // this code path).
            token: if pkt_type == Type::Initial {
                self.token.clone()
            } else {
                None
            },

            versions: None,
            key_phase: self.key_phase,
        };

        hdr.to_bytes(&mut b)?;

        let hdr_trace = if log::max_level() == log::LevelFilter::Trace {
            Some(format!("{hdr:?}"))
        } else {
            None
        };

        let hdr_ty = hdr.ty;

        #[cfg(feature = "qlog")]
        let qlog_pkt_hdr = self.qlog.streamer.as_ref().map(|_q| {
            qlog::events::quic::PacketHeader::with_type(
                hdr.ty.to_qlog(),
                Some(pn),
                Some(hdr.version),
                Some(&hdr.scid),
                Some(&hdr.dcid),
            )
        });

        // Calculate the space required for the packet, including the header
        // the payload length, the packet number and the AEAD overhead.
        let mut overhead = b.off() + pn_len + crypto_overhead;

        // We assume that the payload length, which is only present in long
        // header packets, can always be encoded with a 2-byte varint.
        if pkt_type != Type::Short {
            overhead += PAYLOAD_LENGTH_LEN;
        }

        // Make sure we have enough space left for the packet overhead.
        match left.checked_sub(overhead) {
            Some(v) => left = v,

            None => {
                // We can't send more because there isn't enough space available
                // in the output buffer.
                //
                // This usually happens when we try to send a new packet but
                // failed because cwnd is almost full. In such case app_limited
                // is set to false here to make cwnd grow when ACK is received.
                path.recovery.update_app_limited(false);
                return Err(Error::Done);
            },
        }

        // Make sure there is enough space for the minimum payload length.
        if left < PAYLOAD_MIN_LEN {
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        let mut frames: SmallVec<[frame::Frame; 1]> = SmallVec::new();

        let mut ack_eliciting = false;
        let mut in_flight = false;
        let mut is_pmtud_probe = false;
        let mut has_data = false;

        // Whether or not we should explicitly elicit an ACK via PING frame if we
        // implicitly elicit one otherwise.
        let ack_elicit_required = path.recovery.should_elicit_ack(epoch);

        let header_offset = b.off();

        // Reserve space for payload length in advance. Since we don't yet know
        // what the final length will be, we reserve 2 bytes in all cases.
        //
        // Only long header packets have an explicit length field.
        if pkt_type != Type::Short {
            b.skip(PAYLOAD_LENGTH_LEN)?;
        }

        packet::encode_pkt_num(pn, pn_len, &mut b)?;

        let payload_offset = b.off();

        let cwnd_available =
            path.recovery.cwnd_available().saturating_sub(overhead);

        let left_before_packing_ack_frame = left;

        // Create ACK frame.
        //
        // When we need to explicitly elicit an ACK via PING later, go ahead and
        // generate an ACK (if there's anything to ACK) since we're going to
        // send a packet with PING anyways, even if we haven't received anything
        // ACK eliciting.
        if pkt_space.recv_pkt_need_ack.len() > 0 &&
            (pkt_space.ack_elicited || ack_elicit_required) &&
            (!is_closing ||
                (pkt_type == Type::Handshake &&
                    self.local_error
                        .as_ref()
                        .is_some_and(|le| le.is_app))) &&
            path.active()
        {
            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = pkt_space.largest_rx_pkt_time.elapsed();

            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = ack_delay.as_micros() as u64 /
                2_u64
                    .pow(self.local_transport_params.ack_delay_exponent as u32);

            // pseudo-random reproducible ack delays when fuzzing
            #[cfg(feature = "fuzzing")]
            let ack_delay = rand::rand_u8() as u64 + 1;

            let frame = frame::Frame::ACK {
                ack_delay,
                ranges: pkt_space.recv_pkt_need_ack.clone(),
                ecn_counts: None, // sending ECN is not supported at this time
            };

            // When a PING frame needs to be sent, avoid sending the ACK if
            // there is not enough cwnd available for both (note that PING
            // frames are always 1 byte, so we just need to check that the
            // ACK's length is lower than cwnd).
            if pkt_space.ack_elicited || frame.wire_len() < cwnd_available {
                // ACK-only packets are not congestion controlled so ACKs must
                // be bundled considering the buffer capacity only, and not the
                // available cwnd.
                if push_frame_to_pkt!(b, frames, frame, left) {
                    pkt_space.ack_elicited = false;
                }
            }
        }

        // Limit output packet size by congestion window size.
        left = cmp::min(
            left,
            // Bytes consumed by ACK frames.
            cwnd_available.saturating_sub(left_before_packing_ack_frame - left),
        );

        let mut challenge_data = None;

        let active_path = self.paths.get_active_mut()?;

        if pkt_type == Type::Short {
            // Create PMTUD probe.
            //
            // In order to send a PMTUD probe the current `left` value, which was
            // already limited by the current PMTU measure, needs to be ignored,
            // but the outgoing packet still needs to be limited by
            // the output buffer size, as well as the congestion
            // window.
            //
            // In addition, the PMTUD probe is only generated when the handshake
            // is confirmed, to avoid interfering with the handshake
            // (e.g. due to the anti-amplification limits).
            let should_probe_pmtu = active_path.should_send_pmtu_probe(
                self.handshake_confirmed,
                self.handshake_completed,
                out_len,
                is_closing,
                frames.is_empty(),
            );

            if should_probe_pmtu {
                if let Some(pmtud) = active_path.pmtud.as_mut() {
                    let probe_size = pmtud.get_probe_size();
                    trace!(
                        "{} sending pmtud probe pmtu_probe={} estimated_pmtu={}",
                        self.trace_id,
                        probe_size,
                        pmtud.get_current_mtu(),
                    );

                    left = probe_size;

                    match left.checked_sub(overhead) {
                        Some(v) => left = v,

                        None => {
                            // We can't send more because there isn't enough space
                            // available in the output buffer.
                            //
                            // This usually happens when we try to send a new
                            // packet but failed
                            // because cwnd is almost full.
                            //
                            // In such case app_limited is set to false here to
                            // make cwnd grow when ACK
                            // is received.
                            active_path.recovery.update_app_limited(false);
                            return Err(Error::Done);
                        },
                    }

                    let frame = frame::Frame::Padding {
                        len: probe_size - overhead - 1,
                    };

                    if push_frame_to_pkt!(b, frames, frame, left) {
                        let frame = frame::Frame::Ping {
                            mtu_probe: Some(probe_size),
                        };

                        if push_frame_to_pkt!(b, frames, frame, left) {
                            ack_eliciting = true;
                            in_flight = true;
                        }
                    }

                    // Reset probe flag after sending to prevent duplicate probes
                    // in a single flight.
                    pmtud.set_in_flight(true);
                    is_pmtud_probe = true;
                }
            }

            let path = self.paths.get_mut(send_pid)?;
            // Create PATH_RESPONSE frame if needed.
            // We do not try to ensure that these are really sent.
            while let Some(challenge) = path.pop_received_challenge() {
                let frame = frame::Frame::PathResponse { data: challenge };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    // If there are other pending PATH_RESPONSE, don't lose them
                    // now.
                    break;
                }
            }

            // Create PATH_CHALLENGE frame if needed.
            if path.validation_requested() {
                // TODO: ensure that data is unique over paths.
                let data = rand::rand_u64().to_be_bytes();

                let frame = frame::Frame::PathChallenge { data };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    // Let's notify the path once we know the packet size.
                    challenge_data = Some(data);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            if let Some(key_update) = crypto_ctx.key_update.as_mut() {
                key_update.update_acked = true;
            }
        }

        let path = self.paths.get_mut(send_pid)?;

        if pkt_type == Type::Short && !is_closing {
            // Create NEW_CONNECTION_ID frames as needed.
            while let Some(seq_num) = self.ids.next_advertise_new_scid_seq() {
                let frame = self.ids.get_new_connection_id_frame_for(seq_num)?;

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.ids.mark_advertise_new_scid_seq(seq_num, false);

                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    break;
                }
            }
        }

        if pkt_type == Type::Short && !is_closing && path.active() {
            // Create HANDSHAKE_DONE frame.
            // self.should_send_handshake_done() but without the need to borrow
            if self.handshake_completed &&
                !self.handshake_done_sent &&
                self.is_server
            {
                let frame = frame::Frame::HandshakeDone;

                if push_frame_to_pkt!(b, frames, frame, left) {
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

                if push_frame_to_pkt!(b, frames, frame, left) {
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

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.update_max_streams_uni();

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create DATA_BLOCKED frame.
            if let Some(limit) = self.blocked_limit {
                let frame = frame::Frame::DataBlocked { limit };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.blocked_limit = None;
                    self.data_blocked_sent_count =
                        self.data_blocked_sent_count.saturating_add(1);

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
                        self.streams.remove_almost_full(stream_id);
                        continue;
                    },
                };

                // Autotune the stream window size.
                stream.recv.autotune_window(now, path.recovery.rtt());

                let frame = frame::Frame::MaxStreamData {
                    stream_id,
                    max: stream.recv.max_data_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    let recv_win = stream.recv.window();

                    stream.recv.update_max_data(now);

                    self.streams.remove_almost_full(stream_id);

                    ack_eliciting = true;
                    in_flight = true;

                    // Make sure the connection window always has some
                    // room compared to the stream window.
                    flow_control.ensure_window_lower_bound(
                        (recv_win as f64 * CONNECTION_WINDOW_FACTOR) as u64,
                    );

                    // Also send MAX_DATA when MAX_STREAM_DATA is sent, to avoid a
                    // potential race condition.
                    self.almost_full = true;
                }
            }

            // Create MAX_DATA frame as needed.
            if self.almost_full &&
                flow_control.max_data() < flow_control.max_data_next()
            {
                // Autotune the connection window size.
                flow_control.autotune_window(now, path.recovery.rtt());

                let frame = frame::Frame::MaxData {
                    max: flow_control.max_data_next(),
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.almost_full = false;

                    // Commits the new max_rx_data limit.
                    flow_control.update_max_data(now);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create STOP_SENDING frames as needed.
            for (stream_id, error_code) in self
                .streams
                .stopped()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, u64)>>()
            {
                let frame = frame::Frame::StopSending {
                    stream_id,
                    error_code,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_stopped(stream_id);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create RESET_STREAM frames as needed.
            for (stream_id, (error_code, final_size)) in self
                .streams
                .reset()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, (u64, u64))>>()
            {
                let frame = frame::Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_reset(stream_id);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create STREAM_DATA_BLOCKED frames as needed.
            for (stream_id, limit) in self
                .streams
                .blocked()
                .map(|(&k, &v)| (k, v))
                .collect::<Vec<(u64, u64)>>()
            {
                let frame = frame::Frame::StreamDataBlocked { stream_id, limit };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.streams.remove_blocked(stream_id);
                    self.stream_data_blocked_sent_count =
                        self.stream_data_blocked_sent_count.saturating_add(1);

                    ack_eliciting = true;
                    in_flight = true;
                }
            }

            // Create RETIRE_CONNECTION_ID frames as needed.
            let retire_dcid_seqs = self.ids.retire_dcid_seqs();

            for seq_num in retire_dcid_seqs {
                // The sequence number specified in a RETIRE_CONNECTION_ID frame
                // MUST NOT refer to the Destination Connection ID field of the
                // packet in which the frame is contained.
                let dcid_seq = path.active_dcid_seq.ok_or(Error::InvalidState)?;

                if seq_num == dcid_seq {
                    continue;
                }

                let frame = frame::Frame::RetireConnectionId { seq_num };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    self.ids.mark_retire_dcid_seq(seq_num, false)?;

                    ack_eliciting = true;
                    in_flight = true;
                } else {
                    break;
                }
            }
        }

        // Create CONNECTION_CLOSE frame. Try to send this only on the active
        // path, unless it is the last one available.
        if path.active() || n_paths == 1 {
            if let Some(conn_err) = self.local_error.as_ref() {
                if conn_err.is_app {
                    // Create ApplicationClose frame.
                    if pkt_type == Type::Short {
                        let frame = frame::Frame::ApplicationClose {
                            error_code: conn_err.error_code,
                            reason: conn_err.reason.clone(),
                        };

                        if push_frame_to_pkt!(b, frames, frame, left) {
                            let pto = path.recovery.pto();
                            self.draining_timer = Some(now + (pto * 3));

                            ack_eliciting = true;
                            in_flight = true;
                        }
                    }
                } else {
                    // Create ConnectionClose frame.
                    let frame = frame::Frame::ConnectionClose {
                        error_code: conn_err.error_code,
                        frame_type: 0,
                        reason: conn_err.reason.clone(),
                    };

                    if push_frame_to_pkt!(b, frames, frame, left) {
                        let pto = path.recovery.pto();
                        self.draining_timer = Some(now + (pto * 3));

                        ack_eliciting = true;
                        in_flight = true;
                    }
                }
            }
        }

        // Create CRYPTO frame.
        if crypto_ctx.crypto_stream.is_flushable() &&
            left > frame::MAX_CRYPTO_OVERHEAD &&
            !is_closing &&
            path.active()
        {
            let crypto_off = crypto_ctx.crypto_stream.send.off_front();

            // Encode the frame.
            //
            // Instead of creating a `frame::Frame` object, encode the frame
            // directly into the packet buffer.
            //
            // First we reserve some space in the output buffer for writing the
            // frame header (we assume the length field is always a 2-byte
            // varint as we don't know the value yet).
            //
            // Then we emit the data from the crypto stream's send buffer.
            //
            // Finally we go back and encode the frame header with the now
            // available information.
            let hdr_off = b.off();
            let hdr_len = 1 + // frame type
                octets::varint_len(crypto_off) + // offset
                2; // length, always encode as 2-byte varint

            if let Some(max_len) = left.checked_sub(hdr_len) {
                let (mut crypto_hdr, mut crypto_payload) =
                    b.split_at(hdr_off + hdr_len)?;

                // Write stream data into the packet buffer.
                let (len, _) = crypto_ctx
                    .crypto_stream
                    .send
                    .emit(&mut crypto_payload.as_mut()[..max_len])?;

                // Encode the frame's header.
                //
                // Due to how `OctetsMut::split_at()` works, `crypto_hdr` starts
                // from the initial offset of `b` (rather than the current
                // offset), so it needs to be advanced to the
                // initial frame offset.
                crypto_hdr.skip(hdr_off)?;

                frame::encode_crypto_header(
                    crypto_off,
                    len as u64,
                    &mut crypto_hdr,
                )?;

                // Advance the packet buffer's offset.
                b.skip(hdr_len + len)?;

                let frame = frame::Frame::CryptoHeader {
                    offset: crypto_off,
                    length: len,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                    has_data = true;
                }
            }
        }

        // The preference of data-bearing frame to include in a packet
        // is managed by `self.emit_dgram`. However, whether any frames
        // can be sent depends on the state of their buffers. In the case
        // where one type is preferred but its buffer is empty, fall back
        // to the other type in order not to waste this function call.
        let mut dgram_emitted = false;
        let dgrams_to_emit = max_dgram_len.is_some();
        let stream_to_emit = self.streams.has_flushable();

        let mut do_dgram = self.emit_dgram && dgrams_to_emit;
        let do_stream = !self.emit_dgram && stream_to_emit;

        if !do_stream && dgrams_to_emit {
            do_dgram = true;
        }

        // Create DATAGRAM frame.
        if (pkt_type == Type::Short || pkt_type == Type::ZeroRTT) &&
            left > frame::MAX_DGRAM_OVERHEAD &&
            !is_closing &&
            path.active() &&
            do_dgram
        {
            if let Some(max_dgram_payload) = max_dgram_len {
                while let Some(len) = self.dgram_send_queue.peek_front_len() {
                    let hdr_off = b.off();
                    let hdr_len = 1 + // frame type
                        2; // length, always encode as 2-byte varint

                    if (hdr_len + len) <= left {
                        // Front of the queue fits this packet, send it.
                        match self.dgram_send_queue.pop() {
                            Some(data) => {
                                // Encode the frame.
                                //
                                // Instead of creating a `frame::Frame` object,
                                // encode the frame directly into the packet
                                // buffer.
                                //
                                // First we reserve some space in the output
                                // buffer for writing the frame header (we
                                // assume the length field is always a 2-byte
                                // varint as we don't know the value yet).
                                //
                                // Then we emit the data from the DATAGRAM's
                                // buffer.
                                //
                                // Finally we go back and encode the frame
                                // header with the now available information.
                                let (mut dgram_hdr, mut dgram_payload) =
                                    b.split_at(hdr_off + hdr_len)?;

                                dgram_payload.as_mut()[..len]
                                    .copy_from_slice(&data);

                                // Encode the frame's header.
                                //
                                // Due to how `OctetsMut::split_at()` works,
                                // `dgram_hdr` starts from the initial offset
                                // of `b` (rather than the current offset), so
                                // it needs to be advanced to the initial frame
                                // offset.
                                dgram_hdr.skip(hdr_off)?;

                                frame::encode_dgram_header(
                                    len as u64,
                                    &mut dgram_hdr,
                                )?;

                                // Advance the packet buffer's offset.
                                b.skip(hdr_len + len)?;

                                let frame =
                                    frame::Frame::DatagramHeader { length: len };

                                if push_frame_to_pkt!(b, frames, frame, left) {
                                    ack_eliciting = true;
                                    in_flight = true;
                                    dgram_emitted = true;
                                    self.dgram_sent_count =
                                        self.dgram_sent_count.saturating_add(1);
                                    path.dgram_sent_count =
                                        path.dgram_sent_count.saturating_add(1);
                                }
                            },

                            None => continue,
                        };
                    } else if len > max_dgram_payload {
                        // This dgram frame will never fit. Let's purge it.
                        self.dgram_send_queue.pop();
                    } else {
                        break;
                    }
                }
            }
        }

        // Create a single STREAM frame for the first stream that is flushable.
        if (pkt_type == Type::Short || pkt_type == Type::ZeroRTT) &&
            left > frame::MAX_STREAM_OVERHEAD &&
            !is_closing &&
            path.active() &&
            !dgram_emitted
        {
            while let Some(priority_key) = self.streams.peek_flushable() {
                let stream_id = priority_key.id;
                let stream = match self.streams.get_mut(stream_id) {
                    // Avoid sending frames for streams that were already stopped.
                    //
                    // This might happen if stream data was buffered but not yet
                    // flushed on the wire when a STOP_SENDING frame is received.
                    Some(v) if !v.send.is_stopped() => v,
                    _ => {
                        self.streams.remove_flushable(&priority_key);
                        continue;
                    },
                };

                let stream_off = stream.send.off_front();

                // Encode the frame.
                //
                // Instead of creating a `frame::Frame` object, encode the frame
                // directly into the packet buffer.
                //
                // First we reserve some space in the output buffer for writing
                // the frame header (we assume the length field is always a
                // 2-byte varint as we don't know the value yet).
                //
                // Then we emit the data from the stream's send buffer.
                //
                // Finally we go back and encode the frame header with the now
                // available information.
                let hdr_off = b.off();
                let hdr_len = 1 + // frame type
                    octets::varint_len(stream_id) + // stream_id
                    octets::varint_len(stream_off) + // offset
                    2; // length, always encode as 2-byte varint

                let max_len = match left.checked_sub(hdr_len) {
                    Some(v) => v,
                    None => {
                        let priority_key = Arc::clone(&stream.priority_key);
                        self.streams.remove_flushable(&priority_key);

                        continue;
                    },
                };

                let (mut stream_hdr, mut stream_payload) =
                    b.split_at(hdr_off + hdr_len)?;

                // Write stream data into the packet buffer.
                let (len, fin) =
                    stream.send.emit(&mut stream_payload.as_mut()[..max_len])?;

                // Encode the frame's header.
                //
                // Due to how `OctetsMut::split_at()` works, `stream_hdr` starts
                // from the initial offset of `b` (rather than the current
                // offset), so it needs to be advanced to the initial frame
                // offset.
                stream_hdr.skip(hdr_off)?;

                frame::encode_stream_header(
                    stream_id,
                    stream_off,
                    len as u64,
                    fin,
                    &mut stream_hdr,
                )?;

                // Advance the packet buffer's offset.
                b.skip(hdr_len + len)?;

                let frame = frame::Frame::StreamHeader {
                    stream_id,
                    offset: stream_off,
                    length: len,
                    fin,
                };

                if push_frame_to_pkt!(b, frames, frame, left) {
                    ack_eliciting = true;
                    in_flight = true;
                    has_data = true;
                }

                let priority_key = Arc::clone(&stream.priority_key);

                // If the stream is no longer flushable, remove it from the queue
                if !stream.is_flushable() {
                    self.streams.remove_flushable(&priority_key);
                } else if stream.incremental {
                    // Cycle the incremental stream to the back of the queue
                    // for round-robin scheduling.
                    self.streams.cycle_flushable(stream_id);
                }

                #[cfg(feature = "fuzzing")]
                // Coalesce STREAM frames when fuzzing.
                if left > frame::MAX_STREAM_OVERHEAD {
                    continue;
                }

                break;
            }
        }

        // Alternate trying to send DATAGRAMs next time.
        self.emit_dgram = !dgram_emitted;

        // If no other ack-eliciting frame is sent, include a PING frame
        // - if PTO probe needed; OR
        // - if we've sent too many non ack-eliciting packets without having
        // sent an ACK eliciting one; OR
        // - the application requested an ack-eliciting frame be sent.
        if (ack_elicit_required || path.needs_ack_eliciting) &&
            !ack_eliciting &&
            left >= 1 &&
            !is_closing
        {
            let frame = frame::Frame::Ping { mtu_probe: None };

            if push_frame_to_pkt!(b, frames, frame, left) {
                ack_eliciting = true;
                in_flight = true;
            }
        }

        if ack_eliciting && !is_pmtud_probe {
            path.needs_ack_eliciting = false;
            path.recovery.ping_sent(epoch);
        }

        if !has_data &&
            !dgram_emitted &&
            cwnd_available > frame::MAX_STREAM_OVERHEAD
        {
            path.recovery.on_app_limited();
        }

        if frames.is_empty() {
            // When we reach this point we are not able to write more, so set
            // app_limited to false.
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        // When coalescing a 1-RTT packet, we can't add padding in the UDP
        // datagram, so use PADDING frames instead.
        //
        // This is only needed if
        // 1) an Initial packet has already been written to the UDP datagram,
        // as Initial always requires padding.
        //
        // 2) this is a probing packet towards an unvalidated peer address.
        if (has_initial || !path.validated()) &&
            pkt_type == Type::Short &&
            left >= 1
        {
            let frame = frame::Frame::Padding { len: left };

            if push_frame_to_pkt!(b, frames, frame, left) {
                in_flight = true;
            }
        }

        // Pad payload so that it's always at least 4 bytes.
        if b.off() - payload_offset < PAYLOAD_MIN_LEN {
            let payload_len = b.off() - payload_offset;

            let frame = frame::Frame::Padding {
                len: PAYLOAD_MIN_LEN - payload_len,
            };

            #[allow(unused_assignments)]
            if push_frame_to_pkt!(b, frames, frame, left) {
                in_flight = true;
            }
        }

        let payload_len = b.off() - payload_offset;

        // Fill in payload length.
        if pkt_type != Type::Short {
            let len = pn_len + payload_len + crypto_overhead;

            let (_, mut payload_with_len) = b.split_at(header_offset)?;
            payload_with_len
                .put_varint_with_len(len as u64, PAYLOAD_LENGTH_LEN)?;
        }

        trace!(
            "{} tx pkt {} len={} pn={} {}",
            self.trace_id,
            hdr_trace.unwrap_or_default(),
            payload_len,
            pn,
            AddrTupleFmt(path.local_addr(), path.peer_addr())
        );

        #[cfg(feature = "qlog")]
        let mut qlog_frames: SmallVec<
            [qlog::events::quic::QuicFrame; 1],
        > = SmallVec::with_capacity(frames.len());

        for frame in &mut frames {
            trace!("{} tx frm {:?}", self.trace_id, frame);

            qlog_with_type!(QLOG_PACKET_TX, self.qlog, _q, {
                qlog_frames.push(frame.to_qlog());
            });
        }

        qlog_with_type!(QLOG_PACKET_TX, self.qlog, q, {
            if let Some(header) = qlog_pkt_hdr {
                // Qlog packet raw info described at
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-00#section-5.1
                //
                // `length` includes packet headers and trailers (AEAD tag).
                let length = payload_len + payload_offset + crypto_overhead;
                let qlog_raw_info = RawInfo {
                    length: Some(length as u64),
                    payload_length: Some(payload_len as u64),
                    data: None,
                };

                let send_at_time =
                    now.duration_since(q.start_time()).as_secs_f32() * 1000.0;

                let ev_data =
                    EventData::PacketSent(qlog::events::quic::PacketSent {
                        header,
                        frames: Some(qlog_frames),
                        raw: Some(qlog_raw_info),
                        send_at_time: Some(send_at_time),
                        ..Default::default()
                    });

                q.add_event_data_with_instant(ev_data, now).ok();
            }
        });

        let aead = match crypto_ctx.crypto_seal {
            Some(ref v) => v,
            None => return Err(Error::InvalidState),
        };

        let written = packet::encrypt_pkt(
            &mut b,
            pn,
            pn_len,
            payload_len,
            payload_offset,
            None,
            aead,
        )?;

        let sent_pkt_has_data = if path.recovery.gcongestion_enabled() {
            has_data || dgram_emitted
        } else {
            has_data
        };

        let sent_pkt = recovery::Sent {
            pkt_num: pn,
            frames,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: if ack_eliciting { written } else { 0 },
            ack_eliciting,
            in_flight,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: sent_pkt_has_data,
            is_pmtud_probe,
        };

        if in_flight && is_app_limited {
            path.recovery.delivery_rate_update_app_limited(true);
        }

        self.next_pkt_num += 1;

        let handshake_status = recovery::HandshakeStatus {
            has_handshake_keys: self.crypto_ctx[packet::Epoch::Handshake]
                .has_keys(),
            peer_verified_address: self.peer_verified_initial_address,
            completed: self.handshake_completed,
        };

        self.on_packet_sent(send_pid, sent_pkt, epoch, handshake_status, now)?;

        let path = self.paths.get_mut(send_pid)?;
        qlog_with_type!(QLOG_METRICS, self.qlog, q, {
            path.recovery.maybe_qlog(q, now);
        });

        // Record sent packet size if we probe the path.
        if let Some(data) = challenge_data {
            path.add_challenge_sent(data, written, now);
        }

        self.sent_count += 1;
        self.sent_bytes += written as u64;
        path.sent_count += 1;
        path.sent_bytes += written as u64;

        if self.dgram_send_queue.byte_size() > path.recovery.cwnd_available() {
            path.recovery.update_app_limited(false);
        }

        path.max_send_bytes = path.max_send_bytes.saturating_sub(written);

        // On the client, drop initial state after sending an Handshake packet.
        if !self.is_server && hdr_ty == Type::Handshake {
            self.drop_epoch_state(packet::Epoch::Initial, now);
        }

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

        Ok((pkt_type, written))
    }

    fn on_packet_sent(
        &mut self, send_pid: usize, sent_pkt: recovery::Sent,
        epoch: packet::Epoch, handshake_status: recovery::HandshakeStatus,
        now: Instant,
    ) -> Result<()> {
        let path = self.paths.get_mut(send_pid)?;

        // It's fine to set the skip counter based on a non-active path's values.
        let cwnd = path.recovery.cwnd();
        let max_datagram_size = path.recovery.max_datagram_size();
        self.pkt_num_spaces[epoch].on_packet_sent(&sent_pkt);
        self.pkt_num_manager.on_packet_sent(
            cwnd,
            max_datagram_size,
            self.handshake_completed,
        );

        path.recovery.on_packet_sent(
            sent_pkt,
            epoch,
            handshake_status,
            now,
            &self.trace_id,
        );

        Ok(())
    }

    /// Returns the desired send time for the next packet.
    #[inline]
    pub fn get_next_release_time(&self) -> Option<ReleaseDecision> {
        Some(
            self.paths
                .get_active()
                .ok()?
                .recovery
                .get_next_release_time(),
        )
    }

    /// Returns whether gcongestion is enabled.
    #[inline]
    pub fn gcongestion_enabled(&self) -> Option<bool> {
        Some(self.paths.get_active().ok()?.recovery.gcongestion_enabled())
    }

    /// Returns the maximum pacing into the future.
    ///
    /// Equals 1/8 of the smoothed RTT, but at least 1ms and not greater than
    /// 5ms.
    pub fn max_release_into_future(&self) -> Duration {
        self.paths
            .get_active()
            .map(|p| p.recovery.rtt().mul_f64(0.125))
            .unwrap_or(Duration::from_millis(1))
            .max(Duration::from_millis(1))
            .min(Duration::from_millis(5))
    }

    /// Returns whether pacing is enabled.
    #[inline]
    pub fn pacing_enabled(&self) -> bool {
        self.recovery_config.pacing
    }

    /// Returns the size of the send quantum, in bytes.
    ///
    /// This represents the maximum size of a packet burst as determined by the
    /// congestion control algorithm in use.
    ///
    /// Applications can, for example, use it in conjunction with segmentation
    /// offloading mechanisms as the maximum limit for outgoing aggregates of
    /// multiple packets.
    #[inline]
    pub fn send_quantum(&self) -> usize {
        match self.paths.get_active() {
            Ok(p) => p.recovery.send_quantum(),
            _ => 0,
        }
    }

    /// Returns the size of the send quantum over the given 4-tuple, in bytes.
    ///
    /// This represents the maximum size of a packet burst as determined by the
    /// congestion control algorithm in use.
    ///
    /// Applications can, for example, use it in conjunction with segmentation
    /// offloading mechanisms as the maximum limit for outgoing aggregates of
    /// multiple packets.
    ///
    /// If the (`local_addr`, peer_addr`) 4-tuple relates to a non-existing
    /// path, this method returns 0.
    pub fn send_quantum_on_path(
        &self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> usize {
        self.paths
            .path_id_from_addrs(&(local_addr, peer_addr))
            .and_then(|pid| self.paths.get(pid).ok())
            .map(|path| path.recovery.send_quantum())
            .unwrap_or(0)
    }

    /// Reads contiguous data from a stream into the provided slice.
    ///
    /// The slice must be sized by the caller and will be populated up to its
    /// capacity.
    ///
    /// On success the amount of bytes read and a flag indicating the fin state
    /// is returned as a tuple, or [`Done`] if there is no data to read.
    ///
    /// Reading data from a stream may trigger queueing of control messages
    /// (e.g. MAX_STREAM_DATA). [`send()`] should be called afterwards.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`send()`]: struct.Connection.html#method.send
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
    ///     println!("Got {} bytes on stream {}", read, stream_id);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_recv(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool)> {
        self.do_stream_recv(stream_id, RecvAction::Emit { out })
    }

    /// Discard contiguous data from a stream without copying.
    ///
    /// On success the amount of bytes discarded and a flag indicating the fin
    /// state is returned as a tuple, or [`Done`] if there is no data to
    /// discard.
    ///
    /// Discarding data from a stream may trigger queueing of control messages
    /// (e.g. MAX_STREAM_DATA). [`send()`] should be called afterwards.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`send()`]: struct.Connection.html#method.send
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// while let Ok((read, fin)) = conn.stream_discard(stream_id, 1) {
    ///     println!("Discarded {} byte(s) on stream {}", read, stream_id);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_discard(
        &mut self, stream_id: u64, len: usize,
    ) -> Result<(usize, bool)> {
        self.do_stream_recv(stream_id, RecvAction::Discard { len })
    }

    // Reads or discards contiguous data from a stream.
    //
    // Passing an `action` of `StreamRecvAction::Emit` results in a read into
    // the provided slice. It must be sized by the caller and will be populated
    // up to its capacity.
    //
    // Passing an `action` of `StreamRecvAction::Discard` results in discard up
    // to the indicated length.
    //
    // On success the amount of bytes read or discarded, and a flag indicating
    // the fin state, is returned as a tuple, or [`Done`] if there is no data to
    // read or discard.
    //
    // Reading or discarding data from a stream may trigger queueing of control
    // messages (e.g. MAX_STREAM_DATA). [`send()`] should be called afterwards.
    //
    // [`Done`]: enum.Error.html#variant.Done
    // [`send()`]: struct.Connection.html#method.send
    fn do_stream_recv(
        &mut self, stream_id: u64, action: RecvAction,
    ) -> Result<(usize, bool)> {
        // We can't read on our own unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))?;

        if !stream.is_readable() {
            return Err(Error::Done);
        }

        let local = stream.local;
        let priority_key = Arc::clone(&stream.priority_key);

        #[cfg(feature = "qlog")]
        let offset = stream.recv.off_front();

        #[cfg(feature = "qlog")]
        let to = match action {
            RecvAction::Emit { .. } => Some(DataRecipient::Application),

            RecvAction::Discard { .. } => Some(DataRecipient::Dropped),
        };

        let (read, fin) = match stream.recv.emit_or_discard(action) {
            Ok(v) => v,

            Err(e) => {
                // Collect the stream if it is now complete. This can happen if
                // we got a `StreamReset` error which will now be propagated to
                // the application, so we don't need to keep the stream's state
                // anymore.
                if stream.is_complete() {
                    self.streams.collect(stream_id, local);
                }

                self.streams.remove_readable(&priority_key);
                return Err(e);
            },
        };

        self.flow_control.add_consumed(read as u64);

        let readable = stream.is_readable();

        let complete = stream.is_complete();

        if stream.recv.almost_full() {
            self.streams.insert_almost_full(stream_id);
        }

        if !readable {
            self.streams.remove_readable(&priority_key);
        }

        if complete {
            self.streams.collect(stream_id, local);
        }

        qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
            let ev_data = EventData::DataMoved(qlog::events::quic::DataMoved {
                stream_id: Some(stream_id),
                offset: Some(offset),
                length: Some(read as u64),
                from: Some(DataRecipient::Transport),
                to,
                ..Default::default()
            });

            let now = Instant::now();
            q.add_event_data_with_instant(ev_data, now).ok();
        });

        if self.should_update_max_data() {
            self.almost_full = true;
        }

        if priority_key.incremental && readable {
            // Shuffle the incremental stream to the back of the queue.
            self.streams.remove_readable(&priority_key);
            self.streams.insert_readable(&priority_key);
        }

        Ok((read, fin))
    }

    /// Writes data to a stream.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// data was written (e.g. because the stream has no capacity).
    ///
    /// Applications can provide a 0-length buffer with the fin flag set to
    /// true. This will lead to a 0-length FIN STREAM frame being sent at the
    /// latest offset. The `Ok(0)` value is only returned when the application
    /// provided a 0-length buffer.
    ///
    /// In addition, if the peer has signalled that it doesn't want to receive
    /// any more data from this stream by sending the `STOP_SENDING` frame, the
    /// [`StreamStopped`] error will be returned instead of any data.
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
    /// Applications should call this method only after the handshake is
    /// completed (whenever [`is_established()`] returns `true`) or during
    /// early data if enabled (whenever [`is_in_early_data()`] returns `true`).
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    /// [`is_established()`]: struct.Connection.html#method.is_established
    /// [`is_in_early_data()`]: struct.Connection.html#method.is_in_early_data
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = "127.0.0.1:4321".parse().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// conn.stream_send(stream_id, b"hello", true)?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_send(
        &mut self, stream_id: u64, buf: &[u8], fin: bool,
    ) -> Result<usize> {
        self.stream_do_send(
            stream_id,
            buf,
            fin,
            |stream: &mut stream::Stream<F>,
             buf: &[u8],
             cap: usize,
             fin: bool| {
                stream.send.write(&buf[..cap], fin).map(|v| (v, v))
            },
        )
    }

    /// Writes data to a stream with zero copying, instead, it appends the
    /// provided buffer directly to the send queue if the capacity allows
    /// it.
    ///
    /// When a partial write happens (including when [`Error::Done`] is
    /// returned) the remaining (unwritten) buffer will also be returned.
    /// The application should retry the operation once the stream is
    /// reported as writable again.
    pub fn stream_send_zc(
        &mut self, stream_id: u64, buf: F::Buf, len: Option<usize>, fin: bool,
    ) -> Result<(usize, Option<F::Buf>)>
    where
        F::Buf: BufSplit,
    {
        self.stream_do_send(
            stream_id,
            buf,
            fin,
            |stream: &mut stream::Stream<F>,
             buf: F::Buf,
             cap: usize,
             fin: bool| {
                let len = len.unwrap_or(usize::MAX).min(cap);
                let (sent, remaining) = stream.send.append_buf(buf, len, fin)?;
                Ok((sent, (sent, remaining)))
            },
        )
    }

    fn stream_do_send<B, R, SND>(
        &mut self, stream_id: u64, buf: B, fin: bool, write_fn: SND,
    ) -> Result<R>
    where
        B: AsRef<[u8]>,
        SND: FnOnce(&mut stream::Stream<F>, B, usize, bool) -> Result<(usize, R)>,
    {
        // We can't write on the peer's unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            !stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        let len = buf.as_ref().len();

        // Mark the connection as blocked if the connection-level flow control
        // limit doesn't let us buffer all the data.
        //
        // Note that this is separate from "send capacity" as that also takes
        // congestion control into consideration.
        if self.max_tx_data - self.tx_data < len as u64 {
            self.blocked_limit = Some(self.max_tx_data);
        }

        let cap = self.tx_cap;

        // Get existing stream or create a new one.
        let stream = self.get_or_create_stream(stream_id, true)?;

        #[cfg(feature = "qlog")]
        let offset = stream.send.off_back();

        let was_writable = stream.is_writable();

        let was_flushable = stream.is_flushable();

        let is_complete = stream.is_complete();
        let is_readable = stream.is_readable();

        let priority_key = Arc::clone(&stream.priority_key);

        // Return early if the stream has been stopped, and collect its state
        // if complete.
        if let Err(Error::StreamStopped(e)) = stream.send.cap() {
            // Only collect the stream if it is complete and not readable.
            // If it is readable, it will get collected when stream_recv()
            // is used.
            //
            // The stream can't be writable if it has been stopped.
            if is_complete && !is_readable {
                let local = stream.local;
                self.streams.collect(stream_id, local);
            }

            return Err(Error::StreamStopped(e));
        };

        // Truncate the input buffer based on the connection's send capacity if
        // necessary.
        //
        // When the cap is zero, the method returns Ok(0) *only* when the passed
        // buffer is empty. We return Error::Done otherwise.
        if cap == 0 && len > 0 {
            if was_writable {
                // When `stream_writable_next()` returns a stream, the writable
                // mark is removed, but because the stream is blocked by the
                // connection-level send capacity it won't be marked as writable
                // again once the capacity increases.
                //
                // Since the stream is writable already, mark it here instead.
                self.streams.insert_writable(&priority_key);
            }

            return Err(Error::Done);
        }

        let (cap, fin, blocked_by_cap) = if cap < len {
            (cap, false, true)
        } else {
            (len, fin, false)
        };

        let (sent, ret) = match write_fn(stream, buf, cap, fin) {
            Ok(v) => v,

            Err(e) => {
                self.streams.remove_writable(&priority_key);
                return Err(e);
            },
        };

        let incremental = stream.incremental;
        let priority_key = Arc::clone(&stream.priority_key);

        let flushable = stream.is_flushable();

        let writable = stream.is_writable();

        let empty_fin = len == 0 && fin;

        if sent < cap {
            let max_off = stream.send.max_off();

            if stream.send.blocked_at() != Some(max_off) {
                stream.send.update_blocked_at(Some(max_off));
                self.streams.insert_blocked(stream_id, max_off);
            }
        } else {
            stream.send.update_blocked_at(None);
            self.streams.remove_blocked(stream_id);
        }

        // If the stream is now flushable push it to the flushable queue, but
        // only if it wasn't already queued.
        //
        // Consider the stream flushable also when we are sending a zero-length
        // frame that has the fin flag set.
        if (flushable || empty_fin) && !was_flushable {
            self.streams.insert_flushable(&priority_key);
        }

        if !writable {
            self.streams.remove_writable(&priority_key);
        } else if was_writable && blocked_by_cap {
            // When `stream_writable_next()` returns a stream, the writable
            // mark is removed, but because the stream is blocked by the
            // connection-level send capacity it won't be marked as writable
            // again once the capacity increases.
            //
            // Since the stream is writable already, mark it here instead.
            self.streams.insert_writable(&priority_key);
        }

        self.tx_cap -= sent;

        self.tx_data += sent as u64;

        self.tx_buffered += sent;
        self.check_tx_buffered_invariant();

        qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
            let ev_data = EventData::DataMoved(qlog::events::quic::DataMoved {
                stream_id: Some(stream_id),
                offset: Some(offset),
                length: Some(sent as u64),
                from: Some(DataRecipient::Application),
                to: Some(DataRecipient::Transport),
                ..Default::default()
            });

            let now = Instant::now();
            q.add_event_data_with_instant(ev_data, now).ok();
        });

        if sent == 0 && cap > 0 {
            return Err(Error::Done);
        }

        if incremental && writable {
            // Shuffle the incremental stream to the back of the queue.
            self.streams.remove_writable(&priority_key);
            self.streams.insert_writable(&priority_key);
        }

        Ok(ret)
    }

    /// Sets the priority for a stream.
    ///
    /// A stream's priority determines the order in which stream data is sent
    /// on the wire (streams with lower priority are sent first). Streams are
    /// created with a default priority of `127`.
    ///
    /// The target stream is created if it did not exist before calling this
    /// method.
    pub fn stream_priority(
        &mut self, stream_id: u64, urgency: u8, incremental: bool,
    ) -> Result<()> {
        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the prioritization.
        let stream = match self.get_or_create_stream(stream_id, true) {
            Ok(v) => v,

            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        if stream.urgency == urgency && stream.incremental == incremental {
            return Ok(());
        }

        stream.urgency = urgency;
        stream.incremental = incremental;

        let old_priority_key = Arc::clone(&stream.priority_key);

        let sequence = self.streams.next_sequence();

        let stream = self.streams.get_mut(stream_id).unwrap();

        let new_priority_key = Arc::new(StreamPriorityKey {
            urgency,
            incremental,
            id: stream_id,
            sequence,
            ..Default::default()
        });

        stream.priority_key = Arc::clone(&new_priority_key);

        self.streams
            .update_priority(&old_priority_key, &new_priority_key);

        Ok(())
    }

    /// Shuts down reading or writing from/to the specified stream.
    ///
    /// When the `direction` argument is set to [`Shutdown::Read`], outstanding
    /// data in the stream's receive buffer is dropped, and no additional data
    /// is added to it. Data received after calling this method is still
    /// validated and acked but not stored, and [`stream_recv()`] will not
    /// return it to the application. In addition, a `STOP_SENDING` frame will
    /// be sent to the peer to signal it to stop sending data.
    ///
    /// When the `direction` argument is set to [`Shutdown::Write`], outstanding
    /// data in the stream's send buffer is dropped, and no additional data is
    /// added to it. Data passed to [`stream_send()`] after calling this method
    /// will be ignored. In addition, a `RESET_STREAM` frame will be sent to the
    /// peer to signal the reset.
    ///
    /// Locally-initiated unidirectional streams can only be closed in the
    /// [`Shutdown::Write`] direction. Remotely-initiated unidirectional streams
    /// can only be closed in the [`Shutdown::Read`] direction. Using an
    /// incorrect direction will return [`InvalidStreamState`].
    ///
    /// [`Shutdown::Read`]: enum.Shutdown.html#variant.Read
    /// [`Shutdown::Write`]: enum.Shutdown.html#variant.Write
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`InvalidStreamState`]: enum.Error.html#variant.InvalidStreamState
    pub fn stream_shutdown(
        &mut self, stream_id: u64, direction: Shutdown, err: u64,
    ) -> Result<()> {
        // Don't try to stop a local unidirectional stream.
        if direction == Shutdown::Read &&
            stream::is_local(stream_id, self.is_server) &&
            !stream::is_bidi(stream_id)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        // Don't try to reset a remote unidirectional stream.
        if direction == Shutdown::Write &&
            !stream::is_local(stream_id, self.is_server) &&
            !stream::is_bidi(stream_id)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        // Get existing stream.
        let stream = self.streams.get_mut(stream_id).ok_or(Error::Done)?;

        let priority_key = Arc::clone(&stream.priority_key);

        match direction {
            Shutdown::Read => {
                let consumed = stream.recv.shutdown()?;
                self.flow_control.add_consumed(consumed);
                if self.flow_control.should_update_max_data() {
                    self.almost_full = true;
                }

                if !stream.recv.is_fin() {
                    self.streams.insert_stopped(stream_id, err);
                }

                // Once shutdown, the stream is guaranteed to be non-readable.
                self.streams.remove_readable(&priority_key);

                self.stopped_stream_local_count =
                    self.stopped_stream_local_count.saturating_add(1);
            },

            Shutdown::Write => {
                let (final_size, unsent) = stream.send.shutdown()?;

                // Claw back some flow control allowance from data that was
                // buffered but not actually sent before the stream was reset.
                self.tx_data = self.tx_data.saturating_sub(unsent);

                self.tx_buffered =
                    self.tx_buffered.saturating_sub(unsent as usize);

                // These drops in qlog are a bit weird, but the only way to ensure
                // that all bytes that are moved from App to Transport in
                // stream_do_send are eventually moved from Transport to Dropped.
                // Ideally we would add a Transport to Network transition also as
                // a way to indicate when bytes were transmitted vs dropped
                // without ever being sent.
                qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                    let ev_data =
                        EventData::DataMoved(qlog::events::quic::DataMoved {
                            stream_id: Some(stream_id),
                            offset: Some(final_size),
                            length: Some(unsent),
                            from: Some(DataRecipient::Transport),
                            to: Some(DataRecipient::Dropped),
                            ..Default::default()
                        });

                    q.add_event_data_with_instant(ev_data, Instant::now()).ok();
                });

                // Update send capacity.
                self.update_tx_cap();

                self.streams.insert_reset(stream_id, err, final_size);

                // Once shutdown, the stream is guaranteed to be non-writable.
                self.streams.remove_writable(&priority_key);

                self.reset_stream_local_count =
                    self.reset_stream_local_count.saturating_add(1);
            },
        }

        Ok(())
    }

    /// Returns the stream's send capacity in bytes.
    ///
    /// If the specified stream doesn't exist (including when it has already
    /// been completed and closed), the [`InvalidStreamState`] error will be
    /// returned.
    ///
    /// In addition, if the peer has signalled that it doesn't want to receive
    /// any more data from this stream by sending the `STOP_SENDING` frame, the
    /// [`StreamStopped`] error will be returned.
    ///
    /// [`InvalidStreamState`]: enum.Error.html#variant.InvalidStreamState
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    #[inline]
    pub fn stream_capacity(&mut self, stream_id: u64) -> Result<usize> {
        if let Some(stream) = self.streams.get(stream_id) {
            let stream_cap = match stream.send.cap() {
                Ok(v) => v,

                Err(Error::StreamStopped(e)) => {
                    // Only collect the stream if it is complete and not
                    // readable. If it is readable, it will get collected when
                    // stream_recv() is used.
                    if stream.is_complete() && !stream.is_readable() {
                        let local = stream.local;
                        self.streams.collect(stream_id, local);
                    }

                    return Err(Error::StreamStopped(e));
                },

                Err(e) => return Err(e),
            };

            let cap = cmp::min(self.tx_cap, stream_cap);
            return Ok(cap);
        };

        Err(Error::InvalidStreamState(stream_id))
    }

    /// Returns the next stream that has data to read.
    ///
    /// Note that once returned by this method, a stream ID will not be returned
    /// again until it is "re-armed".
    ///
    /// The application will need to read all of the pending data on the stream,
    /// and new data has to be received before the stream is reported again.
    ///
    /// This is unlike the [`readable()`] method, that returns the same list of
    /// readable streams when called multiple times in succession.
    ///
    /// [`readable()`]: struct.Connection.html#method.readable
    pub fn stream_readable_next(&mut self) -> Option<u64> {
        let priority_key = self.streams.readable.front().clone_pointer()?;

        self.streams.remove_readable(&priority_key);

        Some(priority_key.id)
    }

    /// Returns true if the stream has data that can be read.
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        let stream = match self.streams.get(stream_id) {
            Some(v) => v,

            None => return false,
        };

        stream.is_readable()
    }

    /// Cycles a readable stream to the back of the priority queue.
    ///
    /// This is used for round-robin scheduling of readable streams. After
    /// processing data from a stream, calling this method moves it to the
    /// back of its priority group, giving other streams a chance to be
    /// processed.
    ///
    /// Returns `true` if the stream was successfully cycled, `false` if the
    /// stream doesn't exist or isn't in the readable set.
    pub(crate) fn cycle_readable(&mut self, stream_id: u64) -> bool {
        self.streams.cycle_readable(stream_id)
    }

    /// Returns the next stream that can be written to.
    ///
    /// Note that once returned by this method, a stream ID will not be returned
    /// again until it is "re-armed".
    ///
    /// This is unlike the [`writable()`] method, that returns the same list of
    /// writable streams when called multiple times in succession. It is not
    /// advised to use both `stream_writable_next()` and [`writable()`] on the
    /// same connection, as it may lead to unexpected results.
    ///
    /// The [`stream_writable()`] method can also be used to fine-tune when a
    /// stream is reported as writable again.
    ///
    /// [`stream_writable()`]: struct.Connection.html#method.stream_writable
    /// [`writable()`]: struct.Connection.html#method.writable
    pub fn stream_writable_next(&mut self) -> Option<u64> {
        // If there is not enough connection-level send capacity, none of the
        // streams are writable.
        if self.tx_cap == 0 {
            return None;
        }

        let mut cursor = self.streams.writable.front();

        while let Some(priority_key) = cursor.clone_pointer() {
            if let Some(stream) = self.streams.get(priority_key.id) {
                let cap = match stream.send.cap() {
                    Ok(v) => v,

                    // Return the stream to the application immediately if it's
                    // stopped.
                    Err(_) =>
                        return {
                            self.streams.remove_writable(&priority_key);

                            Some(priority_key.id)
                        },
                };

                if cmp::min(self.tx_cap, cap) >= stream.send_lowat {
                    self.streams.remove_writable(&priority_key);
                    return Some(priority_key.id);
                }
            }

            cursor.move_next();
        }

        None
    }

    /// Returns true if the stream has enough send capacity.
    ///
    /// When `len` more bytes can be buffered into the given stream's send
    /// buffer, `true` will be returned, `false` otherwise.
    ///
    /// In the latter case, if the additional data can't be buffered due to
    /// flow control limits, the peer will also be notified, and a "low send
    /// watermark" will be set for the stream, such that it is not going to be
    /// reported as writable again by [`stream_writable_next()`] until its send
    /// capacity reaches `len`.
    ///
    /// If the specified stream doesn't exist (including when it has already
    /// been completed and closed), the [`InvalidStreamState`] error will be
    /// returned.
    ///
    /// In addition, if the peer has signalled that it doesn't want to receive
    /// any more data from this stream by sending the `STOP_SENDING` frame, the
    /// [`StreamStopped`] error will be returned.
    ///
    /// [`stream_writable_next()`]: struct.Connection.html#method.stream_writable_next
    /// [`InvalidStreamState`]: enum.Error.html#variant.InvalidStreamState
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    #[inline]
    pub fn stream_writable(
        &mut self, stream_id: u64, len: usize,
    ) -> Result<bool> {
        if self.stream_capacity(stream_id)? >= len {
            return Ok(true);
        }

        let stream = match self.streams.get_mut(stream_id) {
            Some(v) => v,

            None => return Err(Error::InvalidStreamState(stream_id)),
        };

        stream.send_lowat = cmp::max(1, len);

        let is_writable = stream.is_writable();

        let priority_key = Arc::clone(&stream.priority_key);

        if self.max_tx_data - self.tx_data < len as u64 {
            self.blocked_limit = Some(self.max_tx_data);
        }

        if stream.send.cap()? < len {
            let max_off = stream.send.max_off();
            if stream.send.blocked_at() != Some(max_off) {
                stream.send.update_blocked_at(Some(max_off));
                self.streams.insert_blocked(stream_id, max_off);
            }
        } else if is_writable {
            // When `stream_writable_next()` returns a stream, the writable
            // mark is removed, but because the stream is blocked by the
            // connection-level send capacity it won't be marked as writable
            // again once the capacity increases.
            //
            // Since the stream is writable already, mark it here instead.
            self.streams.insert_writable(&priority_key);
        }

        Ok(false)
    }

    /// Returns true if all the data has been read from the specified stream.
    ///
    /// This instructs the application that all the data received from the
    /// peer on the stream has been read, and there won't be anymore in the
    /// future.
    ///
    /// Basically this returns true when the peer either set the `fin` flag
    /// for the stream, or sent `RESET_STREAM`.
    #[inline]
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        let stream = match self.streams.get(stream_id) {
            Some(v) => v,

            None => return true,
        };

        stream.recv.is_fin()
    }

    /// Returns the number of bidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    ///
    /// This can be useful to know if it's possible to create a bidirectional
    /// stream without trying it first.
    #[inline]
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.streams.peer_streams_left_bidi()
    }

    /// Returns the number of unidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    ///
    /// This can be useful to know if it's possible to create a unidirectional
    /// stream without trying it first.
    #[inline]
    pub fn peer_streams_left_uni(&self) -> u64 {
        self.streams.peer_streams_left_uni()
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
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// // Iterate over readable streams.
    /// for stream_id in conn.readable() {
    ///     // Stream is readable, read until there's no more data.
    ///     while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
    ///         println!("Got {} bytes on stream {}", read, stream_id);
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn readable(&self) -> StreamIter {
        self.streams.readable()
    }

    /// Returns an iterator over streams that can be written in priority order.
    ///
    /// The priority order is based on RFC 9218 scheduling recommendations.
    /// Stream priority can be controlled using [`stream_priority()`]. In order
    /// to support fairness requirements, each time this method is called,
    /// internal state is updated. Therefore the iterator ordering can change
    /// between calls, even if no streams were added or removed.
    ///
    /// A "writable" stream is a stream that has enough flow control capacity to
    /// send data to the peer. To avoid buffering an infinite amount of data,
    /// streams are only allowed to buffer outgoing data up to the amount that
    /// the peer allows to send.
    ///
    /// Note that the iterator will only include streams that were writable at
    /// the time the iterator itself was created (i.e. when `writable()` was
    /// called). To account for newly writable streams, the iterator needs to be
    /// created again.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let local = socket.local_addr().unwrap();
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// // Iterate over writable streams.
    /// for stream_id in conn.writable() {
    ///     // Stream is writable, write some data.
    ///     if let Ok(written) = conn.stream_send(stream_id, &buf, false) {
    ///         println!("Written {} bytes on stream {}", written, stream_id);
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    /// [`stream_priority()`]: struct.Connection.html#method.stream_priority
    #[inline]
    pub fn writable(&self) -> StreamIter {
        // If there is not enough connection-level send capacity, none of the
        // streams are writable, so return an empty iterator.
        if self.tx_cap == 0 {
            return StreamIter::default();
        }

        self.streams.writable()
    }

    /// Returns the maximum possible size of egress UDP payloads.
    ///
    /// This is the maximum size of UDP payloads that can be sent, and depends
    /// on both the configured maximum send payload size of the local endpoint
    /// (as configured with [`set_max_send_udp_payload_size()`]), as well as
    /// the transport parameter advertised by the remote peer.
    ///
    /// Note that this value can change during the lifetime of the connection,
    /// but should remain stable across consecutive calls to [`send()`].
    ///
    /// [`set_max_send_udp_payload_size()`]:
    ///     struct.Config.html#method.set_max_send_udp_payload_size
    /// [`send()`]: struct.Connection.html#method.send
    pub fn max_send_udp_payload_size(&self) -> usize {
        let max_datagram_size = self
            .paths
            .get_active()
            .ok()
            .map(|p| p.recovery.max_datagram_size());

        if let Some(max_datagram_size) = max_datagram_size {
            if self.is_established() {
                // We cap the maximum packet size to 16KB or so, so that it can be
                // always encoded with a 2-byte varint.
                return cmp::min(16383, max_datagram_size);
            }
        }

        // Allow for 1200 bytes (minimum QUIC packet size) during the
        // handshake.
        MIN_CLIENT_INITIAL_LEN
    }

    /// Schedule an ack-eliciting packet on the active path.
    ///
    /// QUIC packets might not contain ack-eliciting frames during normal
    /// operating conditions. If the packet would already contain
    /// ack-eliciting frames, this method does not change any behavior.
    /// However, if the packet would not ordinarily contain ack-eliciting
    /// frames, this method ensures that a PING frame sent.
    ///
    /// Calling this method multiple times before [`send()`] has no effect.
    ///
    /// [`send()`]: struct.Connection.html#method.send
    pub fn send_ack_eliciting(&mut self) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Ok(());
        }
        self.paths.get_active_mut()?.needs_ack_eliciting = true;
        Ok(())
    }

    /// Schedule an ack-eliciting packet on the specified path.
    ///
    /// See [`send_ack_eliciting()`] for more detail. [`InvalidState`] is
    /// returned if there is no record of the path.
    ///
    /// [`send_ack_eliciting()`]: struct.Connection.html#method.send_ack_eliciting
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    pub fn send_ack_eliciting_on_path(
        &mut self, local: SocketAddr, peer: SocketAddr,
    ) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Ok(());
        }
        let path_id = self
            .paths
            .path_id_from_addrs(&(local, peer))
            .ok_or(Error::InvalidState)?;
        self.paths.get_mut(path_id)?.needs_ack_eliciting = true;
        Ok(())
    }

    /// Reads the first received DATAGRAM.
    ///
    /// On success the DATAGRAM's data is returned along with its size.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is too small for
    /// the DATAGRAM.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: enum.Error.html#variant.BufferTooShort
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// let mut dgram_buf = [0; 512];
    /// while let Ok((len)) = conn.dgram_recv(&mut dgram_buf) {
    ///     println!("Got {} bytes of DATAGRAM", len);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn dgram_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.dgram_recv_queue.pop() {
            Some(d) => {
                if d.len() > buf.len() {
                    return Err(Error::BufferTooShort);
                }

                buf[..d.len()].copy_from_slice(&d);
                Ok(d.len())
            },

            None => Err(Error::Done),
        }
    }

    /// Reads the first received DATAGRAM.
    ///
    /// This is the same as [`dgram_recv()`] but returns the DATAGRAM as a
    /// `Vec<u8>` instead of copying into the provided buffer.
    ///
    /// [`dgram_recv()`]: struct.Connection.html#method.dgram_recv
    #[inline]
    pub fn dgram_recv_vec(&mut self) -> Result<Vec<u8>> {
        match self.dgram_recv_queue.pop() {
            Some(d) => Ok(d),

            None => Err(Error::Done),
        }
    }

    /// Reads the first received DATAGRAM without removing it from the queue.
    ///
    /// On success the DATAGRAM's data is returned along with the actual number
    /// of bytes peeked. The requested length cannot exceed the DATAGRAM's
    /// actual length.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is smaller the
    /// number of bytes to peek.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: enum.Error.html#variant.BufferTooShort
    #[inline]
    pub fn dgram_recv_peek(&self, buf: &mut [u8], len: usize) -> Result<usize> {
        self.dgram_recv_queue.peek_front_bytes(buf, len)
    }

    /// Returns the length of the first stored DATAGRAM.
    #[inline]
    pub fn dgram_recv_front_len(&self) -> Option<usize> {
        self.dgram_recv_queue.peek_front_len()
    }

    /// Returns the number of items in the DATAGRAM receive queue.
    #[inline]
    pub fn dgram_recv_queue_len(&self) -> usize {
        self.dgram_recv_queue.len()
    }

    /// Returns the total size of all items in the DATAGRAM receive queue.
    #[inline]
    pub fn dgram_recv_queue_byte_size(&self) -> usize {
        self.dgram_recv_queue.byte_size()
    }

    /// Returns the number of items in the DATAGRAM send queue.
    #[inline]
    pub fn dgram_send_queue_len(&self) -> usize {
        self.dgram_send_queue.len()
    }

    /// Returns the total size of all items in the DATAGRAM send queue.
    #[inline]
    pub fn dgram_send_queue_byte_size(&self) -> usize {
        self.dgram_send_queue.byte_size()
    }

    /// Returns whether or not the DATAGRAM send queue is full.
    #[inline]
    pub fn is_dgram_send_queue_full(&self) -> bool {
        self.dgram_send_queue.is_full()
    }

    /// Returns whether or not the DATAGRAM recv queue is full.
    #[inline]
    pub fn is_dgram_recv_queue_full(&self) -> bool {
        self.dgram_recv_queue.is_full()
    }

    /// Sends data in a DATAGRAM frame.
    ///
    /// [`Done`] is returned if no data was written.
    /// [`InvalidState`] is returned if the peer does not support DATAGRAM.
    /// [`BufferTooShort`] is returned if the DATAGRAM frame length is larger
    /// than peer's supported DATAGRAM frame length. Use
    /// [`dgram_max_writable_len()`] to get the largest supported DATAGRAM
    /// frame length.
    ///
    /// Note that there is no flow control of DATAGRAM frames, so in order to
    /// avoid buffering an infinite amount of frames we apply an internal
    /// limit.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    /// [`BufferTooShort`]: enum.Error.html#variant.BufferTooShort
    /// [`dgram_max_writable_len()`]:
    /// struct.Connection.html#method.dgram_max_writable_len
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// conn.dgram_send(b"hello")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<()> {
        let max_payload_len = match self.dgram_max_writable_len() {
            Some(v) => v,

            None => return Err(Error::InvalidState),
        };

        if buf.len() > max_payload_len {
            return Err(Error::BufferTooShort);
        }

        self.dgram_send_queue.push(buf.to_vec())?;

        let active_path = self.paths.get_active_mut()?;

        if self.dgram_send_queue.byte_size() >
            active_path.recovery.cwnd_available()
        {
            active_path.recovery.update_app_limited(false);
        }

        Ok(())
    }

    /// Sends data in a DATAGRAM frame.
    ///
    /// This is the same as [`dgram_send()`] but takes a `Vec<u8>` instead of
    /// a slice.
    ///
    /// [`dgram_send()`]: struct.Connection.html#method.dgram_send
    pub fn dgram_send_vec(&mut self, buf: Vec<u8>) -> Result<()> {
        let max_payload_len = match self.dgram_max_writable_len() {
            Some(v) => v,

            None => return Err(Error::InvalidState),
        };

        if buf.len() > max_payload_len {
            return Err(Error::BufferTooShort);
        }

        self.dgram_send_queue.push(buf)?;

        let active_path = self.paths.get_active_mut()?;

        if self.dgram_send_queue.byte_size() >
            active_path.recovery.cwnd_available()
        {
            active_path.recovery.update_app_limited(false);
        }

        Ok(())
    }

    /// Purges queued outgoing DATAGRAMs matching the predicate.
    ///
    /// In other words, remove all elements `e` such that `f(&e)` returns true.
    ///
    /// ## Examples:
    /// ```no_run
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// conn.dgram_send(b"hello")?;
    /// conn.dgram_purge_outgoing(&|d: &[u8]| -> bool { d[0] == 0 });
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn dgram_purge_outgoing<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        self.dgram_send_queue.purge(f);
    }

    /// Returns the maximum DATAGRAM payload that can be sent.
    ///
    /// [`None`] is returned if the peer hasn't advertised a maximum DATAGRAM
    /// frame size.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// if let Some(payload_size) = conn.dgram_max_writable_len() {
    ///     if payload_size > 5 {
    ///         conn.dgram_send(b"hello")?;
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        match self.peer_transport_params.max_datagram_frame_size {
            None => None,
            Some(peer_frame_len) => {
                let dcid = self.destination_id();
                // Start from the maximum packet size...
                let mut max_len = self.max_send_udp_payload_size();
                // ...subtract the Short packet header overhead...
                // (1 byte of pkt_len + len of dcid)
                max_len = max_len.saturating_sub(1 + dcid.len());
                // ...subtract the packet number (max len)...
                max_len = max_len.saturating_sub(packet::MAX_PKT_NUM_LEN);
                // ...subtract the crypto overhead...
                max_len = max_len.saturating_sub(
                    self.crypto_ctx[packet::Epoch::Application]
                        .crypto_overhead()?,
                );
                // ...clamp to what peer can support...
                max_len = cmp::min(peer_frame_len as usize, max_len);
                // ...subtract frame overhead, checked for underflow.
                // (1 byte of frame type + len of length )
                max_len.checked_sub(1 + frame::MAX_DGRAM_OVERHEAD)
            },
        }
    }

    fn dgram_enabled(&self) -> bool {
        self.local_transport_params
            .max_datagram_frame_size
            .is_some()
    }

    /// Returns when the next timeout event will occur.
    ///
    /// Once the timeout Instant has been reached, the [`on_timeout()`] method
    /// should be called. A timeout of `None` means that the timer should be
    /// disarmed.
    ///
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    pub fn timeout_instant(&self) -> Option<Instant> {
        if self.is_closed() {
            return None;
        }

        if self.is_draining() {
            // Draining timer takes precedence over all other timers. If it is
            // set it means the connection is closing so there's no point in
            // processing the other timers.
            self.draining_timer
        } else {
            // Use the lowest timer value (i.e. "sooner") among idle and loss
            // detection timers. If they are both unset (i.e. `None`) then the
            // result is `None`, but if at least one of them is set then a
            // `Some(...)` value is returned.
            let path_timer = self
                .paths
                .iter()
                .filter_map(|(_, p)| p.recovery.loss_detection_timer())
                .min();

            let key_update_timer = self.crypto_ctx[packet::Epoch::Application]
                .key_update
                .as_ref()
                .map(|key_update| key_update.timer);

            let timers = [self.idle_timer, path_timer, key_update_timer];

            timers.iter().filter_map(|&x| x).min()
        }
    }

    /// Returns the amount of time until the next timeout event.
    ///
    /// Once the given duration has elapsed, the [`on_timeout()`] method should
    /// be called. A timeout of `None` means that the timer should be disarmed.
    ///
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout_instant().map(|timeout| {
            let now = Instant::now();

            if timeout <= now {
                Duration::ZERO
            } else {
                timeout.duration_since(now)
            }
        })
    }

    /// Processes a timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    pub fn on_timeout(&mut self) {
        let now = Instant::now();

        if let Some(draining_timer) = self.draining_timer {
            if draining_timer <= now {
                trace!("{} draining timeout expired", self.trace_id);

                self.mark_closed();
            }

            // Draining timer takes precedence over all other timers. If it is
            // set it means the connection is closing so there's no point in
            // processing the other timers.
            return;
        }

        if let Some(timer) = self.idle_timer {
            if timer <= now {
                trace!("{} idle timeout expired", self.trace_id);

                self.mark_closed();
                self.timed_out = true;
                return;
            }
        }

        if let Some(timer) = self.crypto_ctx[packet::Epoch::Application]
            .key_update
            .as_ref()
            .map(|key_update| key_update.timer)
        {
            if timer <= now {
                // Discard previous key once key update timer expired.
                let _ = self.crypto_ctx[packet::Epoch::Application]
                    .key_update
                    .take();
            }
        }

        let handshake_status = self.handshake_status();

        for (_, p) in self.paths.iter_mut() {
            if let Some(timer) = p.recovery.loss_detection_timer() {
                if timer <= now {
                    trace!("{} loss detection timeout expired", self.trace_id);

                    let OnLossDetectionTimeoutOutcome {
                        lost_packets,
                        lost_bytes,
                    } = p.on_loss_detection_timeout(
                        handshake_status,
                        now,
                        self.is_server,
                        &self.trace_id,
                    );

                    self.lost_count += lost_packets;
                    self.lost_bytes += lost_bytes as u64;

                    qlog_with_type!(QLOG_METRICS, self.qlog, q, {
                        p.recovery.maybe_qlog(q, now);
                    });
                }
            }
        }

        // Notify timeout events to the application.
        self.paths.notify_failed_validations();

        // If the active path failed, try to find a new candidate.
        if self.paths.get_active_path_id().is_err() {
            match self.paths.find_candidate_path() {
                Some(pid) => {
                    if self.set_active_path(pid, now).is_err() {
                        // The connection cannot continue.
                        self.mark_closed();
                    }
                },

                // The connection cannot continue.
                None => {
                    self.mark_closed();
                },
            }
        }
    }

    /// Requests the stack to perform path validation of the proposed 4-tuple.
    ///
    /// Probing new paths requires spare Connection IDs at both the host and the
    /// peer sides. If it is not the case, it raises an [`OutOfIdentifiers`].
    ///
    /// The probing of new addresses can only be done by the client. The server
    /// can only probe network paths that were previously advertised by
    /// [`PathEvent::New`]. If the server tries to probe such an unseen network
    /// path, this call raises an [`InvalidState`].
    ///
    /// The caller might also want to probe an existing path. In such case, it
    /// triggers a PATH_CHALLENGE frame, but it does not require spare CIDs.
    ///
    /// A server always probes a new path it observes. Calling this method is
    /// hence not required to validate a new path. However, a server can still
    /// request an additional path validation of the proposed 4-tuple.
    ///
    /// Calling this method several times before calling [`send()`] or
    /// [`send_on_path()`] results in a single probe being generated. An
    /// application wanting to send multiple in-flight probes must call this
    /// method again after having sent packets.
    ///
    /// Returns the Destination Connection ID sequence number associated to that
    /// path.
    ///
    /// [`PathEvent::New`]: enum.PathEvent.html#variant.New
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`send()`]: struct.Connection.html#method.send
    /// [`send_on_path()`]: struct.Connection.html#method.send_on_path
    pub fn probe_path(
        &mut self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Result<u64> {
        // We may want to probe an existing path.
        let pid = match self.paths.path_id_from_addrs(&(local_addr, peer_addr)) {
            Some(pid) => pid,
            None => self.create_path_on_client(local_addr, peer_addr)?,
        };

        let path = self.paths.get_mut(pid)?;
        path.request_validation();

        path.active_dcid_seq.ok_or(Error::InvalidState)
    }

    /// Migrates the connection to a new local address `local_addr`.
    ///
    /// The behavior is similar to [`migrate()`], with the nuance that the
    /// connection only changes the local address, but not the peer one.
    ///
    /// See [`migrate()`] for the full specification of this method.
    ///
    /// [`migrate()`]: struct.Connection.html#method.migrate
    pub fn migrate_source(&mut self, local_addr: SocketAddr) -> Result<u64> {
        let peer_addr = self.paths.get_active()?.peer_addr();
        self.migrate(local_addr, peer_addr)
    }

    /// Migrates the connection over the given network path between `local_addr`
    /// and `peer_addr`.
    ///
    /// Connection migration can only be initiated by the client. Calling this
    /// method as a server returns [`InvalidState`].
    ///
    /// To initiate voluntary migration, there should be enough Connection IDs
    /// at both sides. If this requirement is not satisfied, this call returns
    /// [`OutOfIdentifiers`].
    ///
    /// Returns the Destination Connection ID associated to that migrated path.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn migrate(
        &mut self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Result<u64> {
        if self.is_server {
            return Err(Error::InvalidState);
        }

        // If the path already exists, mark it as the active one.
        let (pid, dcid_seq) = if let Some(pid) =
            self.paths.path_id_from_addrs(&(local_addr, peer_addr))
        {
            let path = self.paths.get_mut(pid)?;

            // If it is already active, do nothing.
            if path.active() {
                return path.active_dcid_seq.ok_or(Error::OutOfIdentifiers);
            }

            // Ensures that a Source Connection ID has been dedicated to this
            // path, or a free one is available. This is only required if the
            // host uses non-zero length Source Connection IDs.
            if !self.ids.zero_length_scid() &&
                path.active_scid_seq.is_none() &&
                self.ids.available_scids() == 0
            {
                return Err(Error::OutOfIdentifiers);
            }

            // Ensures that the migrated path has a Destination Connection ID.
            let dcid_seq = if let Some(dcid_seq) = path.active_dcid_seq {
                dcid_seq
            } else {
                let dcid_seq = self
                    .ids
                    .lowest_available_dcid_seq()
                    .ok_or(Error::OutOfIdentifiers)?;

                self.ids.link_dcid_to_path_id(dcid_seq, pid)?;
                path.active_dcid_seq = Some(dcid_seq);

                dcid_seq
            };

            (pid, dcid_seq)
        } else {
            let pid = self.create_path_on_client(local_addr, peer_addr)?;

            let dcid_seq = self
                .paths
                .get(pid)?
                .active_dcid_seq
                .ok_or(Error::InvalidState)?;

            (pid, dcid_seq)
        };

        // Change the active path.
        self.set_active_path(pid, Instant::now())?;

        Ok(dcid_seq)
    }

    /// Provides additional source Connection IDs that the peer can use to reach
    /// this host.
    ///
    /// This triggers sending NEW_CONNECTION_ID frames if the provided Source
    /// Connection ID is not already present. In the case the caller tries to
    /// reuse a Connection ID with a different reset token, this raises an
    /// `InvalidState`.
    ///
    /// At any time, the peer cannot have more Destination Connection IDs than
    /// the maximum number of active Connection IDs it negotiated. In such case
    /// (i.e., when [`scids_left()`] returns 0), if the host agrees to
    /// request the removal of previous connection IDs, it sets the
    /// `retire_if_needed` parameter. Otherwise, an [`IdLimit`] is returned.
    ///
    /// Note that setting `retire_if_needed` does not prevent this function from
    /// returning an [`IdLimit`] in the case the caller wants to retire still
    /// unannounced Connection IDs.
    ///
    /// The caller is responsible for ensuring that the provided `scid` is not
    /// repeated several times over the connection. quiche ensures that as long
    /// as the provided Connection ID is still in use (i.e., not retired), it
    /// does not assign a different sequence number.
    ///
    /// Note that if the host uses zero-length Source Connection IDs, it cannot
    /// advertise Source Connection IDs and calling this method returns an
    /// [`InvalidState`].
    ///
    /// Returns the sequence number associated to the provided Connection ID.
    ///
    /// [`scids_left()`]: struct.Connection.html#method.scids_left
    /// [`IdLimit`]: enum.Error.html#IdLimit
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn new_scid(
        &mut self, scid: &ConnectionId, reset_token: u128, retire_if_needed: bool,
    ) -> Result<u64> {
        self.ids.new_scid(
            scid.to_vec().into(),
            Some(reset_token),
            true,
            None,
            retire_if_needed,
        )
    }

    /// Returns the number of source Connection IDs that are active. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    pub fn active_scids(&self) -> usize {
        self.ids.active_source_cids()
    }

    /// Returns the number of source Connection IDs that should be provided
    /// to the peer without exceeding the limit it advertised.
    ///
    /// This will automatically limit the number of Connection IDs to the
    /// minimum between the locally configured active connection ID limit,
    /// and the one sent by the peer.
    ///
    /// To obtain the maximum possible value allowed by the peer an application
    /// can instead inspect the [`peer_active_conn_id_limit`] value.
    ///
    /// [`peer_active_conn_id_limit`]: struct.Stats.html#structfield.peer_active_conn_id_limit
    #[inline]
    pub fn scids_left(&self) -> usize {
        let max_active_source_cids = cmp::min(
            self.peer_transport_params.active_conn_id_limit,
            self.local_transport_params.active_conn_id_limit,
        ) as usize;

        max_active_source_cids - self.active_scids()
    }

    /// Requests the retirement of the destination Connection ID used by the
    /// host to reach its peer.
    ///
    /// This triggers sending RETIRE_CONNECTION_ID frames.
    ///
    /// If the application tries to retire a non-existing Destination Connection
    /// ID sequence number, or if it uses zero-length Destination Connection ID,
    /// this method returns an [`InvalidState`].
    ///
    /// At any time, the host must have at least one Destination ID. If the
    /// application tries to retire the last one, or if the caller tries to
    /// retire the destination Connection ID used by the current active path
    /// while having neither spare Destination Connection IDs nor validated
    /// network paths, this method returns an [`OutOfIdentifiers`]. This
    /// behavior prevents the caller from stalling the connection due to the
    /// lack of validated path to send non-probing packets.
    ///
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    pub fn retire_dcid(&mut self, dcid_seq: u64) -> Result<()> {
        if self.ids.zero_length_dcid() {
            return Err(Error::InvalidState);
        }

        let active_path_dcid_seq = self
            .paths
            .get_active()?
            .active_dcid_seq
            .ok_or(Error::InvalidState)?;

        let active_path_id = self.paths.get_active_path_id()?;

        if active_path_dcid_seq == dcid_seq &&
            self.ids.lowest_available_dcid_seq().is_none() &&
            !self
                .paths
                .iter()
                .any(|(pid, p)| pid != active_path_id && p.usable())
        {
            return Err(Error::OutOfIdentifiers);
        }

        if let Some(pid) = self.ids.retire_dcid(dcid_seq)? {
            // The retired Destination CID was associated to a given path. Let's
            // find an available DCID to associate to that path.
            let path = self.paths.get_mut(pid)?;
            let dcid_seq = self.ids.lowest_available_dcid_seq();

            if let Some(dcid_seq) = dcid_seq {
                self.ids.link_dcid_to_path_id(dcid_seq, pid)?;
            }

            path.active_dcid_seq = dcid_seq;
        }

        Ok(())
    }

    /// Processes path-specific events.
    ///
    /// On success it returns a [`PathEvent`], or `None` when there are no
    /// events to report. Please refer to [`PathEvent`] for the exhaustive event
    /// list.
    ///
    /// Note that all events are edge-triggered, meaning that once reported they
    /// will not be reported again by calling this method again, until the event
    /// is re-armed.
    ///
    /// [`PathEvent`]: enum.PathEvent.html
    pub fn path_event_next(&mut self) -> Option<PathEvent> {
        self.paths.pop_event()
    }

    /// Returns the number of source Connection IDs that are retired.
    pub fn retired_scids(&self) -> usize {
        self.ids.retired_source_cids()
    }

    /// Returns a source `ConnectionId` that has been retired.
    ///
    /// On success it returns a [`ConnectionId`], or `None` when there are no
    /// more retired connection IDs.
    ///
    /// [`ConnectionId`]: struct.ConnectionId.html
    pub fn retired_scid_next(&mut self) -> Option<ConnectionId<'static>> {
        self.ids.pop_retired_scid()
    }

    /// Returns the number of spare Destination Connection IDs, i.e.,
    /// Destination Connection IDs that are still unused.
    ///
    /// Note that this function returns 0 if the host uses zero length
    /// Destination Connection IDs.
    pub fn available_dcids(&self) -> usize {
        self.ids.available_dcids()
    }

    /// Returns an iterator over destination `SockAddr`s whose association
    /// with `from` forms a known QUIC path on which packets can be sent to.
    ///
    /// This function is typically used in combination with [`send_on_path()`].
    ///
    /// Note that the iterator includes all the possible combination of
    /// destination `SockAddr`s, even those whose sending is not required now.
    /// In other words, this is another way for the application to recall from
    /// past [`PathEvent::New`] events.
    ///
    /// [`PathEvent::New`]: enum.PathEvent.html#variant.New
    /// [`send_on_path()`]: struct.Connection.html#method.send_on_path
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let local = socket.local_addr().unwrap();
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// // Iterate over possible destinations for the given local `SockAddr`.
    /// for dest in conn.paths_iter(local) {
    ///     loop {
    ///         let (write, send_info) =
    ///             match conn.send_on_path(&mut out, Some(local), Some(dest)) {
    ///                 Ok(v) => v,
    ///
    ///                 Err(quiche::Error::Done) => {
    ///                     // Done writing for this destination.
    ///                     break;
    ///                 },
    ///
    ///                 Err(e) => {
    ///                     // An error occurred, handle it.
    ///                     break;
    ///                 },
    ///             };
    ///
    ///         socket.send_to(&out[..write], &send_info.to).unwrap();
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn paths_iter(&self, from: SocketAddr) -> SocketAddrIter {
        // Instead of trying to identify whether packets will be sent on the
        // given 4-tuple, simply filter paths that cannot be used.
        SocketAddrIter {
            sockaddrs: self
                .paths
                .iter()
                .filter(|(_, p)| p.active_dcid_seq.is_some())
                .filter(|(_, p)| p.usable() || p.probing_required())
                .filter(|(_, p)| p.local_addr() == from)
                .map(|(_, p)| p.peer_addr())
                .collect(),

            index: 0,
        }
    }

    /// Closes the connection with the given error and reason.
    ///
    /// The `app` parameter specifies whether an application close should be
    /// sent to the peer. Otherwise a normal connection close is sent.
    ///
    /// If `app` is true but the connection is not in a state that is safe to
    /// send an application error (not established nor in early data), in
    /// accordance with [RFC
    /// 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3-3), the
    /// error code is changed to APPLICATION_ERROR and the reason phrase is
    /// cleared.
    ///
    /// Returns [`Done`] if the connection had already been closed.
    ///
    /// Note that the connection will not be closed immediately. An application
    /// should continue calling the [`recv()`], [`send()`], [`timeout()`] and
    /// [`on_timeout()`] methods as normal, until the [`is_closed()`] method
    /// returns `true`.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`send()`]: struct.Connection.html#method.send
    /// [`timeout()`]: struct.Connection.html#method.timeout
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        if self.local_error.is_some() {
            return Err(Error::Done);
        }

        let is_safe_to_send_app_data =
            self.is_established() || self.is_in_early_data();

        if app && !is_safe_to_send_app_data {
            // Clear error information.
            self.local_error = Some(ConnectionError {
                is_app: false,
                error_code: 0x0c,
                reason: vec![],
            });
        } else {
            self.local_error = Some(ConnectionError {
                is_app: app,
                error_code: err,
                reason: reason.to_vec(),
            });
        }

        // When no packet was successfully processed close connection immediately.
        if self.recv_count == 0 {
            self.mark_closed();
        }

        Ok(())
    }

    /// Returns a string uniquely representing the connection.
    ///
    /// This can be used for logging purposes to differentiate between multiple
    /// connections.
    #[inline]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Returns the negotiated ALPN protocol.
    ///
    /// If no protocol has been negotiated, the returned value is empty.
    #[inline]
    pub fn application_proto(&self) -> &[u8] {
        self.alpn.as_ref()
    }

    /// Returns the server name requested by the client.
    #[inline]
    pub fn server_name(&self) -> Option<&str> {
        self.handshake.server_name()
    }

    /// Returns the peer's leaf certificate (if any) as a DER-encoded buffer.
    #[inline]
    pub fn peer_cert(&self) -> Option<&[u8]> {
        self.handshake.peer_cert()
    }

    /// Returns the peer's certificate chain (if any) as a vector of DER-encoded
    /// buffers.
    ///
    /// The certificate at index 0 is the peer's leaf certificate, the other
    /// certificates (if any) are the chain certificate authorities used to
    /// sign the leaf certificate.
    #[inline]
    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        self.handshake.peer_cert_chain()
    }

    /// Returns the serialized cryptographic session for the connection.
    ///
    /// This can be used by a client to cache a connection's session, and resume
    /// it later using the [`set_session()`] method.
    ///
    /// [`set_session()`]: struct.Connection.html#method.set_session
    #[inline]
    pub fn session(&self) -> Option<&[u8]> {
        self.session.as_deref()
    }

    /// Returns the source connection ID.
    ///
    /// When there are multiple IDs, and if there is an active path, the ID used
    /// on that path is returned. Otherwise the oldest ID is returned.
    ///
    /// Note that the value returned can change throughout the connection's
    /// lifetime.
    #[inline]
    pub fn source_id(&self) -> ConnectionId<'_> {
        if let Ok(path) = self.paths.get_active() {
            if let Some(active_scid_seq) = path.active_scid_seq {
                if let Ok(e) = self.ids.get_scid(active_scid_seq) {
                    return ConnectionId::from_ref(e.cid.as_ref());
                }
            }
        }

        let e = self.ids.oldest_scid();
        ConnectionId::from_ref(e.cid.as_ref())
    }

    /// Returns all active source connection IDs.
    ///
    /// An iterator is returned for all active IDs (i.e. ones that have not
    /// been explicitly retired yet).
    #[inline]
    pub fn source_ids(&self) -> impl Iterator<Item = &ConnectionId<'_>> {
        self.ids.scids_iter()
    }

    /// Returns the destination connection ID.
    ///
    /// Note that the value returned can change throughout the connection's
    /// lifetime.
    #[inline]
    pub fn destination_id(&self) -> ConnectionId<'_> {
        if let Ok(path) = self.paths.get_active() {
            if let Some(active_dcid_seq) = path.active_dcid_seq {
                if let Ok(e) = self.ids.get_dcid(active_dcid_seq) {
                    return ConnectionId::from_ref(e.cid.as_ref());
                }
            }
        }

        let e = self.ids.oldest_dcid();
        ConnectionId::from_ref(e.cid.as_ref())
    }

    /// Returns the PMTU for the active path if it exists.
    ///
    /// This requires no additonal packets to be sent but simply checks if PMTUD
    /// has completed and has found a valid PMTU.
    #[inline]
    pub fn pmtu(&self) -> Option<usize> {
        if let Ok(path) = self.paths.get_active() {
            path.pmtud.as_ref().and_then(|pmtud| pmtud.get_pmtu())
        } else {
            None
        }
    }

    /// Revalidates the PMTU for the active path by sending a new probe packet
    /// of PMTU size. If the probe is dropped PMTUD will restart and find a new
    /// valid PMTU.
    #[inline]
    pub fn revalidate_pmtu(&mut self) {
        if let Ok(active_path) = self.paths.get_active_mut() {
            if let Some(pmtud) = active_path.pmtud.as_mut() {
                pmtud.revalidate_pmtu();
            }
        }
    }

    /// Returns true if the connection handshake is complete.
    #[inline]
    pub fn is_established(&self) -> bool {
        self.handshake_completed
    }

    /// Returns true if the connection is resumed.
    #[inline]
    pub fn is_resumed(&self) -> bool {
        self.handshake.is_resumed()
    }

    /// Returns true if the connection has a pending handshake that has
    /// progressed enough to send or receive early data.
    #[inline]
    pub fn is_in_early_data(&self) -> bool {
        self.handshake.is_in_early_data()
    }

    /// Returns the early data reason for the connection.
    ///
    /// This status can be useful for logging and debugging. See [BoringSSL]
    /// documentation for a definition of the reasons.
    ///
    /// [BoringSSL]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#ssl_early_data_reason_t
    #[inline]
    pub fn early_data_reason(&self) -> u32 {
        self.handshake.early_data_reason()
    }

    /// Returns whether there is stream or DATAGRAM data available to read.
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.streams.has_readable() || self.dgram_recv_front_len().is_some()
    }

    /// Returns whether the network path with local address `from` and remote
    /// address `peer` has been validated.
    ///
    /// If the 4-tuple does not exist over the connection, returns an
    /// [`InvalidState`].
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    pub fn is_path_validated(
        &self, from: SocketAddr, to: SocketAddr,
    ) -> Result<bool> {
        let pid = self
            .paths
            .path_id_from_addrs(&(from, to))
            .ok_or(Error::InvalidState)?;

        Ok(self.paths.get(pid)?.validated())
    }

    /// Returns true if the connection is draining.
    ///
    /// If this returns `true`, the connection object cannot yet be dropped, but
    /// no new application data can be sent or received. An application should
    /// continue calling the [`recv()`], [`timeout()`], and [`on_timeout()`]
    /// methods as normal, until the [`is_closed()`] method returns `true`.
    ///
    /// In contrast, once `is_draining()` returns `true`, calling [`send()`]
    /// is not required because no new outgoing packets will be generated.
    ///
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`send()`]: struct.Connection.html#method.send
    /// [`timeout()`]: struct.Connection.html#method.timeout
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    #[inline]
    pub fn is_draining(&self) -> bool {
        self.draining_timer.is_some()
    }

    /// Returns true if the connection is closed.
    ///
    /// If this returns true, the connection object can be dropped.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns true if the connection was closed due to the idle timeout.
    #[inline]
    pub fn is_timed_out(&self) -> bool {
        self.timed_out
    }

    /// Returns the error received from the peer, if any.
    ///
    /// Note that a `Some` return value does not necessarily imply
    /// [`is_closed()`] or any other connection state.
    ///
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    #[inline]
    pub fn peer_error(&self) -> Option<&ConnectionError> {
        self.peer_error.as_ref()
    }

    /// Returns the error [`close()`] was called with, or internally
    /// created quiche errors, if any.
    ///
    /// Note that a `Some` return value does not necessarily imply
    /// [`is_closed()`] or any other connection state.
    /// `Some` also does not guarantee that the error has been sent to
    /// or received by the peer.
    ///
    /// [`close()`]: struct.Connection.html#method.close
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    #[inline]
    pub fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    /// Collects and returns statistics about the connection.
    #[inline]
    pub fn stats(&self) -> Stats {
        Stats {
            recv: self.recv_count,
            sent: self.sent_count,
            lost: self.lost_count,
            spurious_lost: self.spurious_lost_count,
            retrans: self.retrans_count,
            sent_bytes: self.sent_bytes,
            recv_bytes: self.recv_bytes,
            acked_bytes: self.acked_bytes,
            lost_bytes: self.lost_bytes,
            stream_retrans_bytes: self.stream_retrans_bytes,
            dgram_recv: self.dgram_recv_count,
            dgram_sent: self.dgram_sent_count,
            paths_count: self.paths.len(),
            reset_stream_count_local: self.reset_stream_local_count,
            stopped_stream_count_local: self.stopped_stream_local_count,
            reset_stream_count_remote: self.reset_stream_remote_count,
            stopped_stream_count_remote: self.stopped_stream_remote_count,
            data_blocked_sent_count: self.data_blocked_sent_count,
            stream_data_blocked_sent_count: self.stream_data_blocked_sent_count,
            data_blocked_recv_count: self.data_blocked_recv_count,
            stream_data_blocked_recv_count: self.stream_data_blocked_recv_count,
            path_challenge_rx_count: self.path_challenge_rx_count,
            bytes_in_flight_duration: self.bytes_in_flight_duration(),
            tx_buffered_state: self.tx_buffered_state,
        }
    }

    /// Returns the sum of the durations when each path in the
    /// connection was actively sending bytes or waiting for acks.
    /// Note that this could result in a duration that is longer than
    /// the actual connection duration in cases where multiple paths
    /// are active for extended periods of time.  In practice only 1
    /// path is typically active at a time.
    /// TODO revisit computation if in the future multiple paths are
    /// often active at the same time.
    fn bytes_in_flight_duration(&self) -> Duration {
        self.paths.iter().fold(Duration::ZERO, |acc, (_, path)| {
            acc + path.bytes_in_flight_duration()
        })
    }

    /// Returns reference to peer's transport parameters. Returns `None` if we
    /// have not yet processed the peer's transport parameters.
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        if !self.parsed_peer_transport_params {
            return None;
        }

        Some(&self.peer_transport_params)
    }

    /// Collects and returns statistics about each known path for the
    /// connection.
    pub fn path_stats(&self) -> impl Iterator<Item = PathStats> + '_ {
        self.paths.iter().map(|(_, p)| p.stats())
    }

    /// Returns whether or not this is a server-side connection.
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    fn encode_transport_params(&mut self) -> Result<()> {
        self.handshake.set_quic_transport_params(
            &self.local_transport_params,
            self.is_server,
        )
    }

    fn parse_peer_transport_params(
        &mut self, peer_params: TransportParams,
    ) -> Result<()> {
        // Validate initial_source_connection_id.
        match &peer_params.initial_source_connection_id {
            Some(v) if v != &self.destination_id() =>
                return Err(Error::InvalidTransportParam),

            Some(_) => (),

            // initial_source_connection_id must be sent by
            // both endpoints.
            None => return Err(Error::InvalidTransportParam),
        }

        // Validate original_destination_connection_id.
        if let Some(odcid) = &self.odcid {
            match &peer_params.original_destination_connection_id {
                Some(v) if v != odcid =>
                    return Err(Error::InvalidTransportParam),

                Some(_) => (),

                // original_destination_connection_id must be
                // sent by the server.
                None if !self.is_server =>
                    return Err(Error::InvalidTransportParam),

                None => (),
            }
        }

        // Validate retry_source_connection_id.
        if let Some(rscid) = &self.rscid {
            match &peer_params.retry_source_connection_id {
                Some(v) if v != rscid =>
                    return Err(Error::InvalidTransportParam),

                Some(_) => (),

                // retry_source_connection_id must be sent by
                // the server.
                None => return Err(Error::InvalidTransportParam),
            }
        }

        self.process_peer_transport_params(peer_params)?;

        self.parsed_peer_transport_params = true;

        Ok(())
    }

    fn process_peer_transport_params(
        &mut self, peer_params: TransportParams,
    ) -> Result<()> {
        self.max_tx_data = peer_params.initial_max_data;

        // Update send capacity.
        self.update_tx_cap();

        self.streams
            .update_peer_max_streams_bidi(peer_params.initial_max_streams_bidi);
        self.streams
            .update_peer_max_streams_uni(peer_params.initial_max_streams_uni);

        let max_ack_delay = Duration::from_millis(peer_params.max_ack_delay);

        self.recovery_config.max_ack_delay = max_ack_delay;

        let active_path = self.paths.get_active_mut()?;

        active_path.recovery.update_max_ack_delay(max_ack_delay);

        if active_path
            .pmtud
            .as_ref()
            .map(|pmtud| pmtud.should_probe())
            .unwrap_or(false)
        {
            active_path.recovery.pmtud_update_max_datagram_size(
                active_path
                    .pmtud
                    .as_mut()
                    .expect("PMTUD existence verified above")
                    .get_probe_size()
                    .min(peer_params.max_udp_payload_size as usize),
            );
        } else {
            active_path.recovery.update_max_datagram_size(
                peer_params.max_udp_payload_size as usize,
            );
        }

        // Record the max_active_conn_id parameter advertised by the peer.
        self.ids
            .set_source_conn_id_limit(peer_params.active_conn_id_limit);

        self.peer_transport_params = peer_params;

        Ok(())
    }

    /// Continues the handshake.
    ///
    /// If the connection is already established, it does nothing.
    fn do_handshake(&mut self, now: Instant) -> Result<()> {
        let mut ex_data = tls::ExData {
            application_protos: &self.application_protos,

            crypto_ctx: &mut self.crypto_ctx,

            session: &mut self.session,

            local_error: &mut self.local_error,

            keylog: self.keylog.as_mut(),

            trace_id: &self.trace_id,

            local_transport_params: self.local_transport_params.clone(),

            recovery_config: self.recovery_config,

            tx_cap_factor: self.tx_cap_factor,

            pmtud: None,

            is_server: self.is_server,
        };

        if self.handshake_completed {
            return self.handshake.process_post_handshake(&mut ex_data);
        }

        match self.handshake.do_handshake(&mut ex_data) {
            Ok(_) => (),

            Err(Error::Done) => {
                // Apply in-handshake configuration from callbacks if the path's
                // Recovery module can still be reinitilized.
                if self
                    .paths
                    .get_active()
                    .map(|p| p.can_reinit_recovery())
                    .unwrap_or(false)
                {
                    if ex_data.recovery_config != self.recovery_config {
                        if let Ok(path) = self.paths.get_active_mut() {
                            self.recovery_config = ex_data.recovery_config;
                            path.reinit_recovery(&self.recovery_config);
                        }
                    }

                    if ex_data.tx_cap_factor != self.tx_cap_factor {
                        self.tx_cap_factor = ex_data.tx_cap_factor;
                    }

                    if let Some((discover, max_probes)) = ex_data.pmtud {
                        self.paths.set_discover_pmtu_on_existing_paths(
                            discover,
                            self.recovery_config.max_send_udp_payload_size,
                            max_probes,
                        );
                    }

                    if ex_data.local_transport_params !=
                        self.local_transport_params
                    {
                        self.streams.set_max_streams_bidi(
                            ex_data
                                .local_transport_params
                                .initial_max_streams_bidi,
                        );

                        self.local_transport_params =
                            ex_data.local_transport_params;
                    }
                }

                // Try to parse transport parameters as soon as the first flight
                // of handshake data is processed.
                //
                // This is potentially dangerous as the handshake hasn't been
                // completed yet, though it's required to be able to send data
                // in 0.5 RTT.
                let raw_params = self.handshake.quic_transport_params();

                if !self.parsed_peer_transport_params && !raw_params.is_empty() {
                    let peer_params = TransportParams::decode(
                        raw_params,
                        self.is_server,
                        self.peer_transport_params_track_unknown,
                    )?;

                    self.parse_peer_transport_params(peer_params)?;
                }

                return Ok(());
            },

            Err(e) => return Err(e),
        };

        self.handshake_completed = self.handshake.is_completed();

        self.alpn = self.handshake.alpn_protocol().to_vec();

        let raw_params = self.handshake.quic_transport_params();

        if !self.parsed_peer_transport_params && !raw_params.is_empty() {
            let peer_params = TransportParams::decode(
                raw_params,
                self.is_server,
                self.peer_transport_params_track_unknown,
            )?;

            self.parse_peer_transport_params(peer_params)?;
        }

        if self.handshake_completed {
            // The handshake is considered confirmed at the server when the
            // handshake completes, at which point we can also drop the
            // handshake epoch.
            if self.is_server {
                self.handshake_confirmed = true;

                self.drop_epoch_state(packet::Epoch::Handshake, now);
            }

            // Once the handshake is completed there's no point in processing
            // 0-RTT packets anymore, so clear the buffer now.
            self.undecryptable_pkts.clear();

            trace!("{} connection established: proto={:?} cipher={:?} curve={:?} sigalg={:?} resumed={} {:?}",
                   &self.trace_id,
                   std::str::from_utf8(self.application_proto()),
                   self.handshake.cipher(),
                   self.handshake.curve(),
                   self.handshake.sigalg(),
                   self.handshake.is_resumed(),
                   self.peer_transport_params);
        }

        Ok(())
    }

    /// Selects the packet type for the next outgoing packet.
    fn write_pkt_type(&self, send_pid: usize) -> Result<Type> {
        // On error send packet in the latest epoch available, but only send
        // 1-RTT ones when the handshake is completed.
        if self
            .local_error
            .as_ref()
            .is_some_and(|conn_err| !conn_err.is_app)
        {
            let epoch = match self.handshake.write_level() {
                crypto::Level::Initial => packet::Epoch::Initial,
                crypto::Level::ZeroRTT => unreachable!(),
                crypto::Level::Handshake => packet::Epoch::Handshake,
                crypto::Level::OneRTT => packet::Epoch::Application,
            };

            if !self.handshake_confirmed {
                match epoch {
                    // Downgrade the epoch to Handshake as the handshake is not
                    // completed yet.
                    packet::Epoch::Application => return Ok(Type::Handshake),

                    // Downgrade the epoch to Initial as the remote peer might
                    // not be able to decrypt handshake packets yet.
                    packet::Epoch::Handshake
                        if self.crypto_ctx[packet::Epoch::Initial].has_keys() =>
                        return Ok(Type::Initial),

                    _ => (),
                };
            }

            return Ok(Type::from_epoch(epoch));
        }

        for &epoch in packet::Epoch::epochs(
            packet::Epoch::Initial..=packet::Epoch::Application,
        ) {
            let crypto_ctx = &self.crypto_ctx[epoch];
            let pkt_space = &self.pkt_num_spaces[epoch];

            // Only send packets in a space when we have the send keys for it.
            if crypto_ctx.crypto_seal.is_none() {
                continue;
            }

            // We are ready to send data for this packet number space.
            if crypto_ctx.data_available() || pkt_space.ready() {
                return Ok(Type::from_epoch(epoch));
            }

            // There are lost frames in this packet number space.
            for (_, p) in self.paths.iter() {
                if p.recovery.has_lost_frames(epoch) {
                    return Ok(Type::from_epoch(epoch));
                }

                // We need to send PTO probe packets.
                if p.recovery.loss_probes(epoch) > 0 {
                    return Ok(Type::from_epoch(epoch));
                }
            }
        }

        // If there are flushable, almost full or blocked streams, use the
        // Application epoch.
        let send_path = self.paths.get(send_pid)?;
        if (self.is_established() || self.is_in_early_data()) &&
            (self.should_send_handshake_done() ||
                self.almost_full ||
                self.blocked_limit.is_some() ||
                self.dgram_send_queue.has_pending() ||
                self.local_error
                    .as_ref()
                    .is_some_and(|conn_err| conn_err.is_app) ||
                self.streams.should_update_max_streams_bidi() ||
                self.streams.should_update_max_streams_uni() ||
                self.streams.has_flushable() ||
                self.streams.has_almost_full() ||
                self.streams.has_blocked() ||
                self.streams.has_reset() ||
                self.streams.has_stopped() ||
                self.ids.has_new_scids() ||
                self.ids.has_retire_dcids() ||
                send_path
                    .pmtud
                    .as_ref()
                    .is_some_and(|pmtud| pmtud.should_probe()) ||
                send_path.needs_ack_eliciting ||
                send_path.probing_required())
        {
            // Only clients can send 0-RTT packets.
            if !self.is_server && self.is_in_early_data() {
                return Ok(Type::ZeroRTT);
            }

            return Ok(Type::Short);
        }

        Err(Error::Done)
    }

    /// Returns the mutable stream with the given ID if it exists, or creates
    /// a new one otherwise.
    fn get_or_create_stream(
        &mut self, id: u64, local: bool,
    ) -> Result<&mut stream::Stream<F>> {
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
        &mut self, frame: frame::Frame, hdr: &Header, recv_path_id: usize,
        epoch: packet::Epoch, now: Instant,
    ) -> Result<()> {
        trace!("{} rx frm {:?}", self.trace_id, frame);

        match frame {
            frame::Frame::Padding { .. } => (),

            frame::Frame::Ping { .. } => (),

            frame::Frame::ACK {
                ranges, ack_delay, ..
            } => {
                let ack_delay = ack_delay
                    .checked_mul(2_u64.pow(
                        self.peer_transport_params.ack_delay_exponent as u32,
                    ))
                    .ok_or(Error::InvalidFrame)?;

                if epoch == packet::Epoch::Handshake ||
                    (epoch == packet::Epoch::Application &&
                        self.is_established())
                {
                    self.peer_verified_initial_address = true;
                }

                let handshake_status = self.handshake_status();

                let is_app_limited = self.delivery_rate_check_if_app_limited();

                let largest_acked = ranges.last().expect(
                    "ACK frames should always have at least one ack range",
                );

                for (_, p) in self.paths.iter_mut() {
                    if self.pkt_num_spaces[epoch]
                        .largest_tx_pkt_num
                        .is_some_and(|largest_sent| largest_sent < largest_acked)
                    {
                        // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
                        // An endpoint SHOULD treat receipt of an acknowledgment
                        // for a packet it did not send as
                        // a connection error of type PROTOCOL_VIOLATION
                        return Err(Error::InvalidAckRange);
                    }

                    if is_app_limited {
                        p.recovery.delivery_rate_update_app_limited(true);
                    }

                    let OnAckReceivedOutcome {
                        lost_packets,
                        lost_bytes,
                        acked_bytes,
                        spurious_losses,
                    } = p.recovery.on_ack_received(
                        &ranges,
                        ack_delay,
                        epoch,
                        handshake_status,
                        now,
                        self.pkt_num_manager.skip_pn(),
                        &self.trace_id,
                    )?;

                    let skip_pn = self.pkt_num_manager.skip_pn();
                    let largest_acked =
                        p.recovery.get_largest_acked_on_epoch(epoch);

                    // Consider the skip_pn validated if the peer has sent an ack
                    // for a larger pkt number.
                    if let Some((largest_acked, skip_pn)) =
                        largest_acked.zip(skip_pn)
                    {
                        if largest_acked > skip_pn {
                            self.pkt_num_manager.set_skip_pn(None);
                        }
                    }

                    self.lost_count += lost_packets;
                    self.lost_bytes += lost_bytes as u64;
                    self.acked_bytes += acked_bytes as u64;
                    self.spurious_lost_count += spurious_losses;
                }
            },

            frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                // Peer can't send on our unidirectional streams.
                if !stream::is_bidi(stream_id) &&
                    stream::is_local(stream_id, self.is_server)
                {
                    return Err(Error::InvalidStreamState(stream_id));
                }

                let max_rx_data_left = self.max_rx_data() - self.rx_data;

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

                let was_readable = stream.is_readable();
                let priority_key = Arc::clone(&stream.priority_key);

                let stream::RecvBufResetReturn {
                    max_data_delta,
                    consumed_flowcontrol,
                } = stream.recv.reset(error_code, final_size)?;

                if max_data_delta > max_rx_data_left {
                    return Err(Error::FlowControl);
                }

                if !was_readable && stream.is_readable() {
                    self.streams.insert_readable(&priority_key);
                }

                self.rx_data += max_data_delta;
                // We dropped the receive buffer, return connection level
                // flow-control
                self.flow_control.add_consumed(consumed_flowcontrol);

                // ... and check if need to send an updated MAX_DATA frame
                if self.should_update_max_data() {
                    self.almost_full = true;
                }

                self.reset_stream_remote_count =
                    self.reset_stream_remote_count.saturating_add(1);
            },

            frame::Frame::StopSending {
                stream_id,
                error_code,
            } => {
                // STOP_SENDING on a receive-only stream is a fatal error.
                if !stream::is_local(stream_id, self.is_server) &&
                    !stream::is_bidi(stream_id)
                {
                    return Err(Error::InvalidStreamState(stream_id));
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

                let was_writable = stream.is_writable();

                let priority_key = Arc::clone(&stream.priority_key);

                // Try stopping the stream.
                if let Ok((final_size, unsent)) = stream.send.stop(error_code) {
                    // Claw back some flow control allowance from data that was
                    // buffered but not actually sent before the stream was
                    // reset.
                    //
                    // Note that `tx_cap` will be updated later on, so no need
                    // to touch it here.
                    self.tx_data = self.tx_data.saturating_sub(unsent);

                    self.tx_buffered =
                        self.tx_buffered.saturating_sub(unsent as usize);

                    // These drops in qlog are a bit weird, but the only way to
                    // ensure that all bytes that are moved from App to Transport
                    // in stream_do_send are eventually moved from Transport to
                    // Dropped.  Ideally we would add a Transport to Network
                    // transition also as a way to indicate when bytes were
                    // transmitted vs dropped without ever being sent.
                    qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                        let ev_data =
                            EventData::DataMoved(qlog::events::quic::DataMoved {
                                stream_id: Some(stream_id),
                                offset: Some(final_size),
                                length: Some(unsent),
                                from: Some(DataRecipient::Transport),
                                to: Some(DataRecipient::Dropped),
                                ..Default::default()
                            });

                        q.add_event_data_with_instant(ev_data, now).ok();
                    });

                    self.streams.insert_reset(stream_id, error_code, final_size);

                    if !was_writable {
                        self.streams.insert_writable(&priority_key);
                    }

                    self.stopped_stream_remote_count =
                        self.stopped_stream_remote_count.saturating_add(1);
                    self.reset_stream_local_count =
                        self.reset_stream_local_count.saturating_add(1);
                }
            },

            frame::Frame::Crypto { data } => {
                if data.max_off() >= MAX_CRYPTO_STREAM_OFFSET {
                    return Err(Error::CryptoBufferExceeded);
                }

                // Push the data to the stream so it can be re-ordered.
                self.crypto_ctx[epoch].crypto_stream.recv.write(data)?;

                // Feed crypto data to the TLS state, if there's data
                // available at the expected offset.
                let mut crypto_buf = [0; 512];

                let level = crypto::Level::from_epoch(epoch);

                let stream = &mut self.crypto_ctx[epoch].crypto_stream;

                while let Ok((read, _)) = stream.recv.emit(&mut crypto_buf) {
                    let recv_buf = &crypto_buf[..read];
                    self.handshake.provide_data(level, recv_buf)?;
                }

                self.do_handshake(now)?;
            },

            frame::Frame::CryptoHeader { .. } => unreachable!(),

            // TODO: implement stateless retry
            frame::Frame::NewToken { .. } =>
                if self.is_server {
                    return Err(Error::InvalidPacket);
                },

            frame::Frame::Stream { stream_id, data } => {
                // Peer can't send on our unidirectional streams.
                if !stream::is_bidi(stream_id) &&
                    stream::is_local(stream_id, self.is_server)
                {
                    return Err(Error::InvalidStreamState(stream_id));
                }

                let max_rx_data_left = self.max_rx_data() - self.rx_data;

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

                // Check for the connection-level flow control limit.
                let max_off_delta =
                    data.max_off().saturating_sub(stream.recv.max_off());

                if max_off_delta > max_rx_data_left {
                    return Err(Error::FlowControl);
                }

                let was_readable = stream.is_readable();
                let priority_key = Arc::clone(&stream.priority_key);

                let was_draining = stream.recv.is_draining();

                stream.recv.write(data)?;

                if !was_readable && stream.is_readable() {
                    self.streams.insert_readable(&priority_key);
                }

                self.rx_data += max_off_delta;

                if was_draining {
                    // When a stream is in draining state it will not queue
                    // incoming data for the application to read, so consider
                    // the received data as consumed, which might trigger a flow
                    // control update.
                    self.flow_control.add_consumed(max_off_delta);

                    if self.should_update_max_data() {
                        self.almost_full = true;
                    }
                }
            },

            frame::Frame::StreamHeader { .. } => unreachable!(),

            frame::Frame::MaxData { max } => {
                self.max_tx_data = cmp::max(self.max_tx_data, max);
            },

            frame::Frame::MaxStreamData { stream_id, max } => {
                // Peer can't receive on its own unidirectional streams.
                if !stream::is_bidi(stream_id) &&
                    !stream::is_local(stream_id, self.is_server)
                {
                    return Err(Error::InvalidStreamState(stream_id));
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

                let was_flushable = stream.is_flushable();

                stream.send.update_max_data(max);

                let writable = stream.is_writable();

                let priority_key = Arc::clone(&stream.priority_key);

                // If the stream is now flushable push it to the flushable queue,
                // but only if it wasn't already queued.
                if stream.is_flushable() && !was_flushable {
                    let priority_key = Arc::clone(&stream.priority_key);
                    self.streams.insert_flushable(&priority_key);
                }

                if writable {
                    self.streams.insert_writable(&priority_key);
                }
            },

            frame::Frame::MaxStreamsBidi { max } => {
                if max > MAX_STREAM_ID {
                    return Err(Error::InvalidFrame);
                }

                self.streams.update_peer_max_streams_bidi(max);
            },

            frame::Frame::MaxStreamsUni { max } => {
                if max > MAX_STREAM_ID {
                    return Err(Error::InvalidFrame);
                }

                self.streams.update_peer_max_streams_uni(max);
            },

            frame::Frame::DataBlocked { .. } => {
                self.data_blocked_recv_count =
                    self.data_blocked_recv_count.saturating_add(1);
            },

            frame::Frame::StreamDataBlocked { .. } => {
                self.stream_data_blocked_recv_count =
                    self.stream_data_blocked_recv_count.saturating_add(1);
            },

            frame::Frame::StreamsBlockedBidi { limit } => {
                if limit > MAX_STREAM_ID {
                    return Err(Error::InvalidFrame);
                }
            },

            frame::Frame::StreamsBlockedUni { limit } => {
                if limit > MAX_STREAM_ID {
                    return Err(Error::InvalidFrame);
                }
            },

            frame::Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                if self.ids.zero_length_dcid() {
                    return Err(Error::InvalidState);
                }

                let mut retired_path_ids = SmallVec::new();

                // Retire pending path IDs before propagating the error code to
                // make sure retired connection IDs are not in use anymore.
                let new_dcid_res = self.ids.new_dcid(
                    conn_id.into(),
                    seq_num,
                    u128::from_be_bytes(reset_token),
                    retire_prior_to,
                    &mut retired_path_ids,
                );

                for (dcid_seq, pid) in retired_path_ids {
                    let path = self.paths.get_mut(pid)?;

                    // Maybe the path already switched to another DCID.
                    if path.active_dcid_seq != Some(dcid_seq) {
                        continue;
                    }

                    if let Some(new_dcid_seq) =
                        self.ids.lowest_available_dcid_seq()
                    {
                        path.active_dcid_seq = Some(new_dcid_seq);

                        self.ids.link_dcid_to_path_id(new_dcid_seq, pid)?;

                        trace!(
                            "{} path ID {} changed DCID: old seq num {} new seq num {}",
                            self.trace_id, pid, dcid_seq, new_dcid_seq,
                        );
                    } else {
                        // We cannot use this path anymore for now.
                        path.active_dcid_seq = None;

                        trace!(
                            "{} path ID {} cannot be used; DCID seq num {} has been retired",
                            self.trace_id, pid, dcid_seq,
                        );
                    }
                }

                // Propagate error (if any) now...
                new_dcid_res?;
            },

            frame::Frame::RetireConnectionId { seq_num } => {
                if self.ids.zero_length_scid() {
                    return Err(Error::InvalidState);
                }

                if let Some(pid) = self.ids.retire_scid(seq_num, &hdr.dcid)? {
                    let path = self.paths.get_mut(pid)?;

                    // Maybe we already linked a new SCID to that path.
                    if path.active_scid_seq == Some(seq_num) {
                        // XXX: We do not remove unused paths now, we instead
                        // wait until we need to maintain more paths than the
                        // host is willing to.
                        path.active_scid_seq = None;
                    }
                }
            },

            frame::Frame::PathChallenge { data } => {
                self.path_challenge_rx_count += 1;

                self.paths
                    .get_mut(recv_path_id)?
                    .on_challenge_received(data);
            },

            frame::Frame::PathResponse { data } => {
                self.paths.on_response_received(data)?;
            },

            frame::Frame::ConnectionClose {
                error_code, reason, ..
            } => {
                self.peer_error = Some(ConnectionError {
                    is_app: false,
                    error_code,
                    reason,
                });

                let path = self.paths.get_active()?;
                self.draining_timer = Some(now + (path.recovery.pto() * 3));
            },

            frame::Frame::ApplicationClose { error_code, reason } => {
                self.peer_error = Some(ConnectionError {
                    is_app: true,
                    error_code,
                    reason,
                });

                let path = self.paths.get_active()?;
                self.draining_timer = Some(now + (path.recovery.pto() * 3));
            },

            frame::Frame::HandshakeDone => {
                if self.is_server {
                    return Err(Error::InvalidPacket);
                }

                self.peer_verified_initial_address = true;

                self.handshake_confirmed = true;

                // Once the handshake is confirmed, we can drop Handshake keys.
                self.drop_epoch_state(packet::Epoch::Handshake, now);
            },

            frame::Frame::Datagram { data } => {
                // Close the connection if DATAGRAMs are not enabled.
                // quiche always advertises support for 64K sized DATAGRAM
                // frames, as recommended by the standard, so we don't need a
                // size check.
                if !self.dgram_enabled() {
                    return Err(Error::InvalidState);
                }

                // If recv queue is full, discard oldest
                if self.dgram_recv_queue.is_full() {
                    self.dgram_recv_queue.pop();
                }

                self.dgram_recv_queue.push(data)?;

                self.dgram_recv_count = self.dgram_recv_count.saturating_add(1);

                let path = self.paths.get_mut(recv_path_id)?;
                path.dgram_recv_count = path.dgram_recv_count.saturating_add(1);
            },

            frame::Frame::DatagramHeader { .. } => unreachable!(),
        }

        Ok(())
    }

    /// Drops the keys and recovery state for the given epoch.
    fn drop_epoch_state(&mut self, epoch: packet::Epoch, now: Instant) {
        let crypto_ctx = &mut self.crypto_ctx[epoch];
        if crypto_ctx.crypto_open.is_none() {
            return;
        }
        crypto_ctx.clear();
        self.pkt_num_spaces[epoch].clear();

        let handshake_status = self.handshake_status();
        for (_, p) in self.paths.iter_mut() {
            p.recovery
                .on_pkt_num_space_discarded(epoch, handshake_status, now);
        }

        trace!("{} dropped epoch {} state", self.trace_id, epoch);
    }

    /// Returns true if the connection-level flow control needs to be updated.
    ///
    /// This happens when the new max data limit is at least double the amount
    /// of data that can be received before blocking.
    fn should_update_max_data(&self) -> bool {
        self.flow_control.should_update_max_data()
    }

    /// Returns the connection level flow control limit.
    fn max_rx_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Returns true if the HANDSHAKE_DONE frame needs to be sent.
    fn should_send_handshake_done(&self) -> bool {
        self.is_established() && !self.handshake_done_sent && self.is_server
    }

    /// Returns the idle timeout value.
    ///
    /// `None` is returned if both end-points disabled the idle timeout.
    fn idle_timeout(&self) -> Option<Duration> {
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

        let path_pto = match self.paths.get_active() {
            Ok(p) => p.recovery.pto(),
            Err(_) => Duration::ZERO,
        };

        let idle_timeout = Duration::from_millis(idle_timeout);
        let idle_timeout = cmp::max(idle_timeout, 3 * path_pto);

        Some(idle_timeout)
    }

    /// Returns the connection's handshake status for use in loss recovery.
    fn handshake_status(&self) -> recovery::HandshakeStatus {
        recovery::HandshakeStatus {
            has_handshake_keys: self.crypto_ctx[packet::Epoch::Handshake]
                .has_keys(),

            peer_verified_address: self.peer_verified_initial_address,

            completed: self.is_established(),
        }
    }

    /// Updates send capacity.
    fn update_tx_cap(&mut self) {
        let cwin_available = match self.paths.get_active() {
            Ok(p) => p.recovery.cwnd_available() as u64,
            Err(_) => 0,
        };

        let cap =
            cmp::min(cwin_available, self.max_tx_data - self.tx_data) as usize;
        self.tx_cap = (cap as f64 * self.tx_cap_factor).ceil() as usize;
    }

    fn delivery_rate_check_if_app_limited(&self) -> bool {
        // Enter the app-limited phase of delivery rate when these conditions
        // are met:
        //
        // - The remaining capacity is higher than available bytes in cwnd (there
        //   is more room to send).
        // - New data since the last send() is smaller than available bytes in
        //   cwnd (we queued less than what we can send).
        // - There is room to send more data in cwnd.
        //
        // In application-limited phases the transmission rate is limited by the
        // application rather than the congestion control algorithm.
        //
        // Note that this is equivalent to CheckIfApplicationLimited() from the
        // delivery rate draft. This is also separate from `recovery.app_limited`
        // and only applies to delivery rate calculation.
        let cwin_available = self
            .paths
            .iter()
            .filter(|&(_, p)| p.active())
            .map(|(_, p)| p.recovery.cwnd_available())
            .sum();

        ((self.tx_buffered + self.dgram_send_queue_byte_size()) < cwin_available) &&
            (self.tx_data.saturating_sub(self.last_tx_data)) <
                cwin_available as u64 &&
            cwin_available > 0
    }

    fn check_tx_buffered_invariant(&mut self) {
        // tx_buffered should track bytes queued in the stream buffers
        // and unacked retransmitable bytes in the network.
        // If tx_buffered > 0 mark the tx_buffered_state if there are no
        // flushable streams and there no inflight bytes.
        //
        // It is normal to have tx_buffered == 0 while there are inflight bytes
        // since not QUIC frames are retransmittable; inflight tracks all bytes
        // on the network which are subject to congestion control.
        if self.tx_buffered > 0 &&
            !self.streams.has_flushable() &&
            !self
                .paths
                .iter()
                .any(|(_, p)| p.recovery.bytes_in_flight() > 0)
        {
            self.tx_buffered_state = TxBufferTrackingState::Inconsistent;
        }
    }

    fn set_initial_dcid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        path_id: usize,
    ) -> Result<()> {
        self.ids.set_initial_dcid(cid, reset_token, Some(path_id));
        self.paths.get_mut(path_id)?.active_dcid_seq = Some(0);

        Ok(())
    }

    /// Selects the path that the incoming packet belongs to, or creates a new
    /// one if no existing path matches.
    fn get_or_create_recv_path_id(
        &mut self, recv_pid: Option<usize>, dcid: &ConnectionId, buf_len: usize,
        info: &RecvInfo,
    ) -> Result<usize> {
        let ids = &mut self.ids;

        let (in_scid_seq, mut in_scid_pid) =
            ids.find_scid_seq(dcid).ok_or(Error::InvalidState)?;

        if let Some(recv_pid) = recv_pid {
            // If the path observes a change of SCID used, note it.
            let recv_path = self.paths.get_mut(recv_pid)?;

            let cid_entry =
                recv_path.active_scid_seq.and_then(|v| ids.get_scid(v).ok());

            if cid_entry.map(|e| &e.cid) != Some(dcid) {
                let incoming_cid_entry = ids.get_scid(in_scid_seq)?;

                let prev_recv_pid =
                    incoming_cid_entry.path_id.unwrap_or(recv_pid);

                if prev_recv_pid != recv_pid {
                    trace!(
                        "{} peer reused CID {:?} from path {} on path {}",
                        self.trace_id,
                        dcid,
                        prev_recv_pid,
                        recv_pid
                    );

                    // TODO: reset congestion control.
                }

                trace!(
                    "{} path ID {} now see SCID with seq num {}",
                    self.trace_id,
                    recv_pid,
                    in_scid_seq
                );

                recv_path.active_scid_seq = Some(in_scid_seq);
                ids.link_scid_to_path_id(in_scid_seq, recv_pid)?;
            }

            return Ok(recv_pid);
        }

        // This is a new 4-tuple. See if the CID has not been assigned on
        // another path.

        // Ignore this step if are using zero-length SCID.
        if ids.zero_length_scid() {
            in_scid_pid = None;
        }

        if let Some(in_scid_pid) = in_scid_pid {
            // This CID has been used by another path. If we have the
            // room to do so, create a new `Path` structure holding this
            // new 4-tuple. Otherwise, drop the packet.
            let old_path = self.paths.get_mut(in_scid_pid)?;
            let old_local_addr = old_path.local_addr();
            let old_peer_addr = old_path.peer_addr();

            trace!(
                "{} reused CID seq {} of ({},{}) (path {}) on ({},{})",
                self.trace_id,
                in_scid_seq,
                old_local_addr,
                old_peer_addr,
                in_scid_pid,
                info.to,
                info.from
            );

            // Notify the application.
            self.paths.notify_event(PathEvent::ReusedSourceConnectionId(
                in_scid_seq,
                (old_local_addr, old_peer_addr),
                (info.to, info.from),
            ));
        }

        // This is a new path using an unassigned CID; create it!
        let mut path = path::Path::new(
            info.to,
            info.from,
            &self.recovery_config,
            self.path_challenge_recv_max_queue_len,
            false,
            None,
        );

        path.max_send_bytes = buf_len * self.max_amplification_factor;
        path.active_scid_seq = Some(in_scid_seq);

        // Automatically probes the new path.
        path.request_validation();

        let pid = self.paths.insert_path(path, self.is_server)?;

        // Do not record path reuse.
        if in_scid_pid.is_none() {
            ids.link_scid_to_path_id(in_scid_seq, pid)?;
        }

        Ok(pid)
    }

    /// Selects the path on which the next packet must be sent.
    fn get_send_path_id(
        &self, from: Option<SocketAddr>, to: Option<SocketAddr>,
    ) -> Result<usize> {
        // A probing packet must be sent, but only if the connection is fully
        // established.
        if self.is_established() {
            let mut probing = self
                .paths
                .iter()
                .filter(|(_, p)| from.is_none() || Some(p.local_addr()) == from)
                .filter(|(_, p)| to.is_none() || Some(p.peer_addr()) == to)
                .filter(|(_, p)| p.active_dcid_seq.is_some())
                .filter(|(_, p)| p.probing_required())
                .map(|(pid, _)| pid);

            if let Some(pid) = probing.next() {
                return Ok(pid);
            }
        }

        if let Some((pid, p)) = self.paths.get_active_with_pid() {
            if from.is_some() && Some(p.local_addr()) != from {
                return Err(Error::Done);
            }

            if to.is_some() && Some(p.peer_addr()) != to {
                return Err(Error::Done);
            }

            return Ok(pid);
        };

        Err(Error::InvalidState)
    }

    /// Sets the path with identifier 'path_id' to be active.
    fn set_active_path(&mut self, path_id: usize, now: Instant) -> Result<()> {
        if let Ok(old_active_path) = self.paths.get_active_mut() {
            for &e in packet::Epoch::epochs(
                packet::Epoch::Initial..=packet::Epoch::Application,
            ) {
                let (lost_packets, lost_bytes) = old_active_path
                    .recovery
                    .on_path_change(e, now, &self.trace_id);

                self.lost_count += lost_packets;
                self.lost_bytes += lost_bytes as u64;
            }
        }

        self.paths.set_active_path(path_id)
    }

    /// Handles potential connection migration.
    fn on_peer_migrated(
        &mut self, new_pid: usize, disable_dcid_reuse: bool, now: Instant,
    ) -> Result<()> {
        let active_path_id = self.paths.get_active_path_id()?;

        if active_path_id == new_pid {
            return Ok(());
        }

        self.set_active_path(new_pid, now)?;

        let no_spare_dcid =
            self.paths.get_mut(new_pid)?.active_dcid_seq.is_none();

        if no_spare_dcid && !disable_dcid_reuse {
            self.paths.get_mut(new_pid)?.active_dcid_seq =
                self.paths.get_mut(active_path_id)?.active_dcid_seq;
        }

        Ok(())
    }

    /// Creates a new client-side path.
    fn create_path_on_client(
        &mut self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Result<usize> {
        if self.is_server {
            return Err(Error::InvalidState);
        }

        // If we use zero-length SCID and go over our local active CID limit,
        // the `insert_path()` call will raise an error.
        if !self.ids.zero_length_scid() && self.ids.available_scids() == 0 {
            return Err(Error::OutOfIdentifiers);
        }

        // Do we have a spare DCID? If we are using zero-length DCID, just use
        // the default having sequence 0 (note that if we exceed our local CID
        // limit, the `insert_path()` call will raise an error.
        let dcid_seq = if self.ids.zero_length_dcid() {
            0
        } else {
            self.ids
                .lowest_available_dcid_seq()
                .ok_or(Error::OutOfIdentifiers)?
        };

        let mut path = path::Path::new(
            local_addr,
            peer_addr,
            &self.recovery_config,
            self.path_challenge_recv_max_queue_len,
            false,
            None,
        );
        path.active_dcid_seq = Some(dcid_seq);

        let pid = self
            .paths
            .insert_path(path, false)
            .map_err(|_| Error::OutOfIdentifiers)?;
        self.ids.link_dcid_to_path_id(dcid_seq, pid)?;

        Ok(pid)
    }

    // Marks the connection as closed and does any related tidyup.
    fn mark_closed(&mut self) {
        #[cfg(feature = "qlog")]
        {
            let cc = match (self.is_established(), self.timed_out, &self.peer_error, &self.local_error) {
                (false, _, _, _) => qlog::events::connectivity::ConnectionClosed {
                    owner: Some(TransportOwner::Local),
                    connection_code: None,
                    application_code: None,
                    internal_code: None,
                    reason: Some("Failed to establish connection".to_string()),
                    trigger: Some(qlog::events::connectivity::ConnectionClosedTrigger::HandshakeTimeout)
                },

                (true, true, _, _) => qlog::events::connectivity::ConnectionClosed {
                    owner: Some(TransportOwner::Local),
                    connection_code: None,
                    application_code: None,
                    internal_code: None,
                    reason: Some("Idle timeout".to_string()),
                    trigger: Some(qlog::events::connectivity::ConnectionClosedTrigger::IdleTimeout)
                },

                (true, false, Some(peer_error), None) => {
                    let (connection_code, application_code, trigger) = if peer_error.is_app {
                        (None, Some(qlog::events::ApplicationErrorCode::Value(peer_error.error_code)), None)
                    } else {
                        let trigger = if peer_error.error_code == WireErrorCode::NoError as u64 {
                            Some(qlog::events::connectivity::ConnectionClosedTrigger::Clean)
                        } else {
                            Some(qlog::events::connectivity::ConnectionClosedTrigger::Error)
                        };

                        (Some(qlog::events::ConnectionErrorCode::Value(peer_error.error_code)), None, trigger)
                    };

                    qlog::events::connectivity::ConnectionClosed {
                        owner: Some(TransportOwner::Remote),
                        connection_code,
                        application_code,
                        internal_code: None,
                        reason: Some(String::from_utf8_lossy(&peer_error.reason).to_string()),
                        trigger,
                    }
                },

                (true, false, None, Some(local_error)) => {
                    let (connection_code, application_code, trigger) = if local_error.is_app {
                        (None, Some(qlog::events::ApplicationErrorCode::Value(local_error.error_code)), None)
                    } else {
                        let trigger = if local_error.error_code == WireErrorCode::NoError as u64 {
                            Some(qlog::events::connectivity::ConnectionClosedTrigger::Clean)
                        } else {
                            Some(qlog::events::connectivity::ConnectionClosedTrigger::Error)
                        };

                        (Some(qlog::events::ConnectionErrorCode::Value(local_error.error_code)), None, trigger)
                    };

                    qlog::events::connectivity::ConnectionClosed {
                        owner: Some(TransportOwner::Local),
                        connection_code,
                        application_code,
                        internal_code: None,
                        reason: Some(String::from_utf8_lossy(&local_error.reason).to_string()),
                        trigger,
                    }
                },

                _ => qlog::events::connectivity::ConnectionClosed {
                    owner: None,
                    connection_code: None,
                    application_code: None,
                    internal_code: None,
                    reason: None,
                    trigger: None,
                },
            };

            qlog_with_type!(QLOG_CONNECTION_CLOSED, self.qlog, q, {
                let ev_data = EventData::ConnectionClosed(cc);

                q.add_event_data_now(ev_data).ok();
            });
            self.qlog.streamer = None;
        }
        self.closed = true;
    }
}

#[cfg(feature = "boringssl-boring-crate")]
impl<F: BufFactory> AsMut<boring::ssl::SslRef> for Connection<F> {
    fn as_mut(&mut self) -> &mut boring::ssl::SslRef {
        self.handshake.ssl_mut()
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
/// received, in which case the error itself is returned, but only on the
/// server-side as the client will already have armed the idle timer.
///
/// This must only be used for errors preceding packet authentication. Failures
/// happening after a packet has been authenticated should still cause the
/// connection to be aborted.
fn drop_pkt_on_err(
    e: Error, recv_count: usize, is_server: bool, trace_id: &str,
) -> Error {
    // On the server, if no other packet has been successfully processed, abort
    // the connection to avoid keeping the connection open when only junk is
    // received.
    if is_server && recv_count == 0 {
        return e;
    }

    trace!("{trace_id} dropped invalid packet");

    // Ignore other invalid packets that haven't been authenticated to prevent
    // man-in-the-middle and man-on-the-side attacks.
    Error::Done
}

struct AddrTupleFmt(SocketAddr, SocketAddr);

impl std::fmt::Display for AddrTupleFmt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let AddrTupleFmt(src, dst) = &self;

        if src.ip().is_unspecified() || dst.ip().is_unspecified() {
            return Ok(());
        }

        f.write_fmt(format_args!("src:{src} dst:{dst}"))
    }
}

/// Statistics about the connection.
///
/// A connection's statistics can be collected using the [`stats()`] method.
///
/// [`stats()`]: struct.Connection.html#method.stats
#[derive(Clone, Default)]
pub struct Stats {
    /// The number of QUIC packets received.
    pub recv: usize,

    /// The number of QUIC packets sent.
    pub sent: usize,

    /// The number of QUIC packets that were lost.
    pub lost: usize,

    /// The number of QUIC packets that were marked as lost but later acked.
    pub spurious_lost: usize,

    /// The number of sent QUIC packets with retransmitted data.
    pub retrans: usize,

    /// The number of sent bytes.
    pub sent_bytes: u64,

    /// The number of received bytes.
    pub recv_bytes: u64,

    /// The number of bytes sent acked.
    pub acked_bytes: u64,

    /// The number of bytes sent lost.
    pub lost_bytes: u64,

    /// The number of stream bytes retransmitted.
    pub stream_retrans_bytes: u64,

    /// The number of DATAGRAM frames received.
    pub dgram_recv: usize,

    /// The number of DATAGRAM frames sent.
    pub dgram_sent: usize,

    /// The number of known paths for the connection.
    pub paths_count: usize,

    /// The number of streams reset by local.
    pub reset_stream_count_local: u64,

    /// The number of streams stopped by local.
    pub stopped_stream_count_local: u64,

    /// The number of streams reset by remote.
    pub reset_stream_count_remote: u64,

    /// The number of streams stopped by remote.
    pub stopped_stream_count_remote: u64,

    /// The number of DATA_BLOCKED frames sent due to hitting the connection
    /// flow control limit.
    pub data_blocked_sent_count: u64,

    /// The number of STREAM_DATA_BLOCKED frames sent due to a stream hitting
    /// the stream flow control limit.
    pub stream_data_blocked_sent_count: u64,

    /// The number of DATA_BLOCKED frames received from the remote.
    pub data_blocked_recv_count: u64,

    /// The number of STREAM_DATA_BLOCKED frames received from the remote.
    pub stream_data_blocked_recv_count: u64,

    /// The total number of PATH_CHALLENGE frames that were received.
    pub path_challenge_rx_count: u64,

    /// Total duration during which this side of the connection was
    /// actively sending bytes or waiting for those bytes to be acked.
    pub bytes_in_flight_duration: Duration,

    /// Health state of the connection's tx_buffered.
    pub tx_buffered_state: TxBufferTrackingState,
}

impl std::fmt::Debug for Stats {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "recv={} sent={} lost={} retrans={}",
            self.recv, self.sent, self.lost, self.retrans,
        )?;

        write!(
            f,
            " sent_bytes={} recv_bytes={} lost_bytes={}",
            self.sent_bytes, self.recv_bytes, self.lost_bytes,
        )?;

        Ok(())
    }
}

#[doc(hidden)]
pub mod test_utils;

#[cfg(test)]
mod tests;

pub use crate::packet::ConnectionId;
pub use crate::packet::Header;
pub use crate::packet::Type;

pub use crate::path::PathEvent;
pub use crate::path::PathStats;
pub use crate::path::SocketAddrIter;

pub use crate::recovery::BbrBwLoReductionStrategy;
pub use crate::recovery::BbrParams;
pub use crate::recovery::CongestionControlAlgorithm;
pub use crate::recovery::StartupExit;
pub use crate::recovery::StartupExitReason;

pub use crate::stream::StreamIter;

pub use crate::transport_params::TransportParams;
pub use crate::transport_params::UnknownTransportParameter;
pub use crate::transport_params::UnknownTransportParameterIterator;
pub use crate::transport_params::UnknownTransportParameters;

pub use crate::range_buf::BufFactory;
pub use crate::range_buf::BufSplit;

pub use crate::error::ConnectionError;
pub use crate::error::Error;
pub use crate::error::Result;
pub use crate::error::WireErrorCode;

mod cid;
mod crypto;
mod dgram;
mod error;
#[cfg(feature = "ffi")]
mod ffi;
mod flowcontrol;
mod frame;
pub mod h3;
mod minmax;
mod packet;
mod path;
mod pmtud;
mod rand;
mod range_buf;
mod ranges;
mod recovery;
mod stream;
mod tls;
mod transport_params;
