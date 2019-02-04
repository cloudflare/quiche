// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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

//! Savoury implementation of the QUIC transport protocol.
//!
//! quiche is an implementation of the QUIC transport protocol as specified
//! by the IETF. It provides a low level API for processing QUIC packets and
//! handling connection state, while leaving I/O (including dealing with
//! sockets) to the application.
//!
//! The first step in establishing a QUIC connection using quiche is creating a
//! configuration object:
//!
//! ```
//! let config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! ```
//!
//! This is shared among multiple connections and can be used to configure a
//! QUIC endpoint.
//!
//! Now a connection can be created, for clients the [`connect()`] utility
//! function can be used, while [`accept()`] is for servers:
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! # let server_name = "quic.tech";
//! # let scid = [0xba; 16];
//! // Client connection.
//! let conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();
//!
//! // Server connection.
//! let conn = quiche::accept(&scid, None, &mut config).unwrap();
//! ```
//!
//! Using the connection's [`recv()`] method the application can process
//! incoming packets from the network that belong to that connection:
//!
//! ```no_run
//! # let mut buf = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! let read = socket.recv(&mut buf).unwrap();
//!
//! let read = match conn.recv(&mut buf[..read]) {
//!     Ok(v) => v,
//!
//!     Err(quiche::Error::Done) => {
//!         // Done reading.
//!         # return;
//!     },
//!
//!     Err(e) => {
//!         // An error occurred, handle it.
//!         # return;
//!     },
//! };
//! ```
//!
//! Outgoing packet are generated using the connection's [`send()`] method
//! instead:
//!
//! ```no_run
//! # let mut out = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! let write = match conn.send(&mut out) {
//!     Ok(v) => v,
//!
//!     Err(quiche::Error::Done) => {
//!         // Done writing.
//!         # return;
//!     },
//!
//!     Err(e) => {
//!         // An error occurred, handle it.
//!         # return;
//!     },
//! };
//!
//! socket.send(&out[..write]).unwrap();
//! ```
//!
//! When packets are sent, the application is responsible for maintainig a timer
//! to react to time-based connection events. The timer expiration can be
//! obtained using the connection's [`timeout()`] method.
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! let timeout = conn.timeout();
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
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! // Timeout expired, do something.
//! conn.on_timeout();
//!
//! let write = match conn.send(&mut out) {
//!     Ok(v) => v,
//!
//!     Err(quiche::Error::Done) => {
//!         // Done writing.
//!         # return;
//!     },
//!
//!     Err(e) => {
//!         // An error occurred, handle it.
//!         # return;
//!     },
//! };
//!
//! socket.send(&out[..write]).unwrap();
//! ```
//!
//! After some back and forth, the connection will complete its handshake and
//! will be ready for sending or receiving application data:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();
//! # let scid = [0xba; 16];
//! # let mut conn = quiche::accept(&scid, None, &mut config).unwrap();
//! if conn.is_established() {
//!     // Handshake completed, send some data on stream 0.
//!     conn.stream_send(0, b"hello", true);
//! }
//! ```
//!
//! [`connect()`]: fn.connect.html
//! [`accept()`]: fn.accept.html
//! [`recv()`]: struct.Connection.html#method.recv
//! [`send()`]: struct.Connection.html#method.send
//! [`timeout()`]: struct.Connection.html#method.timeout
//! [`on_timeout()`]: struct.Connection.html#method.on_timeout

#[macro_use]
extern crate log;

use std::cmp;
use std::mem;
use std::time;

use std::collections::hash_map;
use std::collections::HashMap;

/// The current QUIC wire version.
pub const VERSION_DRAFT17: u32 = 0xff00_0011;

/// The maximum length of a connection ID.
pub const MAX_CONN_ID_LEN: usize = crate::packet::MAX_CID_LEN as usize;

const CLIENT_INITIAL_MIN_LEN: usize = 1200;

const PAYLOAD_MIN_LEN: usize = 4;

// TODO: calculate draining timer as 3 * RTO
const DRAINING_TIMEOUT: time::Duration = time::Duration::from_millis(200);

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
}

impl Error {
    pub fn to_wire(self) -> u16 {
        match self {
            Error::Done => 0x0,
            Error::InvalidFrame => 0x7,
            Error::InvalidStreamState => 0x5,
            Error::InvalidTransportParam => 0x8,
            Error::CryptoFail => 0x100,
            Error::TlsFail => 0x100,
            Error::FlowControl => 0x3,
            Error::StreamLimit => 0x4,
            _ => 0xa,
        }
    }

    fn to_c(self) -> libc::ssize_t {
        self as _
    }

    fn to_str(self) -> &'static str {
        match self {
            Error::Done => "nothing else to do",
            Error::BufferTooShort => "buffer is too short",
            Error::UnknownVersion => "version is unknown",
            Error::InvalidFrame => "frame is invalid",
            Error::InvalidPacket => "packet is invalid",
            Error::InvalidState => "connection state is invalid",
            Error::InvalidStreamState => "stream state is invalid",
            Error::InvalidTransportParam => "transport parameter is invalid",
            Error::CryptoFail => "crypto operation failed",
            Error::TlsFail => "TLS failed",
            Error::FlowControl => "flow control limit was violated",
            Error::StreamLimit => "stream limit was violated",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.to_str()
    }

    fn cause(&self) -> Option<&std::error::Error> {
        None
    }
}

/// Stores configuration shared between multiple connections.
pub struct Config {
    local_transport_params: TransportParams,

    version: u32,

    tls_ctx: tls::Context,

    application_protos: Vec<Vec<u8>>,
}

impl Config {
    /// Creates a config object with the given version.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(version: u32) -> Result<Config> {
        let tls_ctx = tls::Context::new().map_err(|_| Error::TlsFail)?;

        Ok(Config {
            local_transport_params: TransportParams::default(),
            version,
            tls_ctx,
            application_protos: Vec::new(),
        })
    }

    /// Configures the given certificate chain.
    ///
    /// The content of `file` is parsed as a PEM-encoded leaf certificate,
    /// followed by optional intermediate certificates.
    pub fn load_cert_chain_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx
            .use_certificate_chain_file(file)
            .map_err(|_| Error::TlsFail)
    }

    /// Configures the given private key.
    ///
    /// The content of `file` is parsed as a PEM-encoded private key.
    pub fn load_priv_key_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx
            .use_privkey_file(file)
            .map_err(|_| Error::TlsFail)
    }

    /// Configures whether to verify the peer's certificate.
    pub fn verify_peer(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify);
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

    /// Configures the list of support application protocolos.
    ///
    /// On the client this configures the list of protocols to send to the
    /// server as part of the ALPN extension.
    ///
    /// On the server this configures the list of supported protocols to match
    /// against the client-supplied list.
    pub fn set_application_protos(&mut self, protos: &[&[u8]]) -> Result<()> {
        self.application_protos = protos.iter().map(|p| p.to_vec()).collect();

        self.tls_ctx
            .set_alpn(&self.application_protos)
            .map_err(|_| Error::TlsFail)
    }

    /// Sets the `idle_timeout` transport parameter.
    pub fn set_idle_timeout(&mut self, v: u64) {
        self.local_transport_params.idle_timeout = v;
    }

    /// Sets the `stateless_reset_token` transport parameter.
    pub fn set_stateless_reset_token(&mut self, v: &[u8; 16]) {
        self.local_transport_params.stateless_reset_token = Some(v.to_vec());
    }

    /// Sets the `max_packet_size transport` parameter.
    pub fn set_max_packet_size(&mut self, v: u64) {
        self.local_transport_params.max_packet_size = v;
    }

    /// Sets the `initial_max_data` transport parameter.
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.local_transport_params.initial_max_data = v;
    }

    /// Sets the `initial_max_stream_data_bidi_local` transport parameter.
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_local = v;
    }

    /// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_remote = v;
    }

    /// Sets the `initial_max_stream_data_uni` transport parameter.
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_stream_data_uni = v;
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_bidi = v;
    }

    /// Sets the `initial_max_streams_uni` transport parameter.
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_uni = v;
    }

    /// Sets the `ack_delay_exponent` transport parameter.
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.local_transport_params.ack_delay_exponent = v;
    }

    /// Sets the `max_ack_delay` transport parameter.
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.local_transport_params.max_ack_delay = v;
    }

    /// Sets the `disable_migration` transport parameter.
    pub fn set_disable_migration(&mut self, v: bool) {
        self.local_transport_params.disable_migration = v;
    }
}

/// A QUIC connection.
pub struct Connection {
    version: u32,

    dcid: Vec<u8>,
    scid: Vec<u8>,

    trace_id: String,

    initial: packet::PktNumSpace,
    handshake: packet::PktNumSpace,
    application: packet::PktNumSpace,

    peer_transport_params: TransportParams,

    local_transport_params: TransportParams,

    tls_state: tls::Handshake,

    recovery: recovery::Recovery,

    application_protos: Vec<Vec<u8>>,

    sent_count: usize,
    lost_count: usize,

    rx_data: usize,
    max_rx_data: usize,
    new_max_rx_data: usize,

    tx_data: usize,
    max_tx_data: usize,

    streams: HashMap<u64, stream::Stream>,

    local_max_streams_bidi: usize,
    local_max_streams_uni: usize,

    peer_max_streams_bidi: usize,
    peer_max_streams_uni: usize,

    odcid: Option<Vec<u8>>,

    token: Option<Vec<u8>>,

    error: Option<u16>,

    app_error: Option<u16>,
    app_reason: Vec<u8>,

    challenge: Option<Vec<u8>>,

    idle_timer: Option<time::Instant>,

    draining_timer: Option<time::Instant>,

    is_server: bool,

    derived_initial_secrets: bool,

    did_version_negotiation: bool,

    did_retry: bool,

    got_peer_conn_id: bool,

    handshake_completed: bool,

    draining: bool,

    closed: bool,
}

/// Creates a new server-side connection.
///
/// The `scid` parameter represents the server's source connection ID, while
/// the optional `odcid` parameter represents the original destination ID the
/// client sent before a stateless retry (this is only required when using
/// the [`retry()`] function).
///
/// [`retry()`]: fn.retry.html
pub fn accept(
    scid: &[u8], odcid: Option<&[u8]>, config: &mut Config,
) -> Result<Box<Connection>> {
    let conn = Connection::new(scid, odcid, config, true)?;

    Ok(conn)
}

/// Creates a new client-side connection.
///
/// The `scid` parameter is used as the connection's source connection ID,
/// while the optional `server_name` parameter is used to verify the peer's
/// certificate.
pub fn connect(
    server_name: Option<&str>, scid: &[u8], config: &mut Config,
) -> Result<Box<Connection>> {
    let conn = Connection::new(scid, None, config, false)?;

    if server_name.is_some() {
        conn.tls_state
            .set_host_name(server_name.unwrap())
            .map_err(|_| Error::TlsFail)?;
    }

    Ok(conn)
}

/// Writes a version negotiation packet.
///
/// The `scid` and `dcid` parameters are the source connection ID and the
/// destination connection ID extracted from the received client's Initial
/// packet that advertises an unsupported version.
pub fn negotiate_version(scid: &[u8], dcid: &[u8], out: &mut [u8]) -> Result<usize> {
    packet::negotiate_version(scid, dcid, out)
}

/// Writes a retry packet.
///
/// The `scid` and `dcid` parameters are the source connection ID and the
/// destination connection ID extracted from the received client's Initial
/// packet, while `new_scid` is the server's new source connection ID and
/// `token` is the address verification token the client needs to echo back.
pub fn retry(
    scid: &[u8], dcid: &[u8], new_scid: &[u8], token: &[u8], out: &mut [u8],
) -> Result<usize> {
    packet::retry(scid, dcid, new_scid, token, out)
}

impl Connection {
    #[allow(clippy::new_ret_no_self)]
    fn new(
        scid: &[u8], odcid: Option<&[u8]>, config: &mut Config, is_server: bool,
    ) -> Result<Box<Connection>> {
        let tls = config.tls_ctx.new_handshake().map_err(|_| Error::TlsFail)?;
        Connection::with_tls(scid, odcid, config, tls, is_server)
    }

    #[doc(hidden)]
    pub fn with_tls(
        scid: &[u8], odcid: Option<&[u8]>, config: &mut Config, tls: tls::Handshake,
        is_server: bool,
    ) -> Result<Box<Connection>> {
        let max_rx_data = config.local_transport_params.initial_max_data;

        let scid_as_hex: Vec<String> =
            scid.iter().map(|b| format!("{:02x}", b)).collect();

        let mut conn = Box::new(Connection {
            version: config.version,

            dcid: Vec::new(),
            scid: scid.to_vec(),

            trace_id: scid_as_hex.join(""),

            initial: packet::PktNumSpace::new(crypto::Level::Initial),
            handshake: packet::PktNumSpace::new(crypto::Level::Handshake),
            application: packet::PktNumSpace::new(crypto::Level::Application),

            peer_transport_params: TransportParams::default(),

            local_transport_params: config.local_transport_params.clone(),

            tls_state: tls,

            recovery: recovery::Recovery::default(),

            application_protos: config.application_protos.clone(),

            sent_count: 0,
            lost_count: 0,

            rx_data: 0,
            max_rx_data: max_rx_data as usize,
            new_max_rx_data: max_rx_data as usize,

            tx_data: 0,
            max_tx_data: 0,

            streams: HashMap::new(),

            local_max_streams_bidi: config
                .local_transport_params
                .initial_max_streams_bidi
                as usize,
            local_max_streams_uni: config
                .local_transport_params
                .initial_max_streams_uni as usize,

            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,

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

            handshake_completed: false,

            draining: false,

            closed: false,
        });

        if let Some(odcid) = odcid {
            conn.local_transport_params.original_connection_id =
                Some(odcid.to_vec());
        }

        conn.tls_state.init(&conn).map_err(|_| Error::TlsFail)?;

        // Derive initial secrets for the client. We can do this here because
        // we already generated the random destination connection ID.
        if !is_server {
            let mut dcid = [0; 16];
            rand::rand_bytes(&mut dcid[..]);

            let (aead_open, aead_seal) =
                crypto::derive_initial_key_material(&dcid, conn.is_server)?;

            conn.dcid.extend_from_slice(&dcid);

            conn.initial.crypto_open = Some(aead_open);
            conn.initial.crypto_seal = Some(aead_seal);

            conn.derived_initial_secrets = true;
        }

        Ok(conn)
    }

    /// Processes QUIC packets received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned, or [`Done`].
    ///
    /// Coalesced packets will be processed as necessary.
    ///
    /// Note that the contents of the input buffer `buf` might be modified by
    /// this function due to, for example, in-place decryption.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();

        let mut done = 0;
        let mut left = len;

        // Process coalesced packets.
        while left > 0 {
            let read = self.recv_single(&mut buf[len - left..len])?;

            done += read;
            left -= read;
        }

        Ok(done)
    }

    /// Processes a single QUIC packet received from the peer.
    fn recv_single(&mut self, buf: &mut [u8]) -> Result<usize> {
        let now = time::Instant::now();

        if buf.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.draining {
            return Err(Error::Done);
        }

        self.do_handshake()?;

        let is_closing = self.error.is_some() || self.app_error.is_some();

        if is_closing {
            return Err(Error::Done);
        }

        let mut b = octets::Octets::with_slice(buf);

        let mut hdr = Header::from_bytes(&mut b, self.scid.len())?;

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

            let versions = match hdr.versions {
                Some(ref v) => v,
                None => return Err(Error::InvalidPacket),
            };

            let mut new_version = 0;
            for v in versions.iter() {
                if *v == VERSION_DRAFT17 {
                    new_version = *v;
                }
            }

            // We don't support any of the versions offfered.
            if new_version == 0 {
                return Err(Error::UnknownVersion);
            }

            self.version = new_version;
            self.did_version_negotiation = true;

            // Reset connection state to force sending another Initial packet.
            self.got_peer_conn_id = false;
            self.recovery.drop_unacked_data(&mut self.initial.flight);
            self.initial.clear();
            self.tls_state.clear().map_err(|_| Error::TlsFail)?;

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

            if hdr.odcid.as_ref() != Some(&self.dcid) {
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

            self.initial.crypto_open = Some(aead_open);
            self.initial.crypto_seal = Some(aead_seal);

            // Reset connection state to force sending another Initial packet.
            self.got_peer_conn_id = false;
            self.recovery.drop_unacked_data(&mut self.initial.flight);
            self.initial.clear();
            self.tls_state.clear().map_err(|_| Error::TlsFail)?;

            return Err(Error::Done);
        }

        if hdr.ty != packet::Type::Application && hdr.version != self.version {
            return Err(Error::UnknownVersion);
        }

        // Long header packets have an explicit payload length, but short
        // packets don't so just use the remaining capacity in the buffer.
        let payload_len = if hdr.ty == packet::Type::Application {
            b.cap()
        } else {
            b.get_varint()? as usize
        };

        if b.cap() < payload_len {
            return Err(Error::BufferTooShort);
        }

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

            self.initial.crypto_open = Some(aead_open);
            self.initial.crypto_seal = Some(aead_seal);

            self.derived_initial_secrets = true;

            self.dcid.extend_from_slice(&hdr.scid);
            self.got_peer_conn_id = true;
        }

        // Select packet number space context based on the input packet type.
        let space = match hdr.ty {
            packet::Type::Initial => &mut self.initial,

            packet::Type::Handshake => &mut self.handshake,

            packet::Type::Application => &mut self.application,

            _ => return Err(Error::InvalidPacket),
        };

        let aead = match space.crypto_open {
            Some(ref v) => v,

            None => {
                trace!(
                    "{} dropped undecryptable packet type={:?} len={}",
                    self.trace_id,
                    hdr.ty,
                    payload_len
                );

                return Ok(b.off() + payload_len);
            },
        };

        packet::decrypt_hdr(&mut b, &mut hdr, &aead)?;

        let pn = packet::decode_pkt_num(
            space.largest_rx_pkt_num,
            hdr.pkt_num,
            hdr.pkt_num_len,
        );

        trace!(
            "{} rx pkt {:?} len={} pn={}",
            self.trace_id,
            hdr,
            payload_len,
            pn
        );

        let mut payload = match packet::decrypt_pkt(
            &mut b,
            pn,
            hdr.pkt_num_len,
            payload_len,
            &aead,
        ) {
            Ok(v) => v,

            Err(Error::CryptoFail) => {
                // The packet number has already been parsed, so its length
                // needs to be removed from the payload length.
                let payload_len = payload_len - hdr.pkt_num_len;

                trace!(
                    "{} dropped undecryptable packet type={:?} len={}",
                    self.trace_id,
                    hdr.ty,
                    payload_len,
                );

                return Ok(b.off() + payload_len);
            },

            Err(e) => return Err(e),
        };

        if space.recv_pkt_num.contains(pn) {
            trace!("{} ignored duplicate packet {}", self.trace_id, pn);
            return Err(Error::Done);
        }

        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK.
        let mut do_ack = false;

        // Process packet payload.
        while payload.cap() > 0 {
            let frame = frame::Frame::from_bytes(&mut payload, hdr.ty)?;

            trace!("{} rx frm {:?}", self.trace_id, frame);

            match frame {
                frame::Frame::Padding { .. } => (),

                frame::Frame::Ping => {
                    do_ack = true;
                },

                frame::Frame::ACK { ranges, ack_delay } => {
                    let ack_delay = ack_delay *
                        2_u64.pow(
                            self.peer_transport_params.ack_delay_exponent as u32,
                        );

                    self.recovery.on_ack_received(
                        &ranges,
                        ack_delay,
                        &mut space.flight,
                        now,
                        &self.trace_id,
                    );
                },

                frame::Frame::StopSending { stream_id, .. } => {
                    // STOP_SENDING on a receive-only stream is a fatal error.
                    if !stream::is_local(stream_id, self.is_server) &&
                        !stream::is_bidi(stream_id)
                    {
                        return Err(Error::InvalidPacket);
                    }

                    do_ack = true;
                },

                frame::Frame::Crypto { data } => {
                    // Push the data to the stream so it can be re-ordered.
                    space.crypto_stream.recv_push(data)?;

                    // Feed crypto data to the TLS state, if there's data
                    // available at the expected offset.
                    let mut crypto_buf = [0; 512];

                    let level = space.crypto_level;

                    while let Ok((read, _)) =
                        space.crypto_stream.recv_pop(&mut crypto_buf)
                    {
                        let recv_buf = &crypto_buf[..read];
                        self.tls_state
                            .provide_data(level, &recv_buf)
                            .map_err(|_| Error::TlsFail)?;
                    }

                    do_ack = true;
                },

                // TODO: implement stateless retry
                frame::Frame::NewToken { .. } => {
                    do_ack = true;
                },

                frame::Frame::Stream { stream_id, data } => {
                    // Peer can't send on our unidirectional streams.
                    if !stream::is_bidi(stream_id) &&
                        stream::is_local(stream_id, self.is_server)
                    {
                        return Err(Error::InvalidStreamState);
                    }

                    let max_rx_data = self
                        .local_transport_params
                        .initial_max_stream_data_bidi_remote
                        as usize;
                    let max_tx_data = self
                        .peer_transport_params
                        .initial_max_stream_data_bidi_local
                        as usize;

                    // Get existing stream or create a new one.
                    let stream = match self.streams.entry(stream_id) {
                        hash_map::Entry::Vacant(v) => {
                            // Peer is not supposed to create this stream.
                            if stream::is_local(stream_id, self.is_server) {
                                return Err(Error::InvalidStreamState);
                            }

                            // Enforce stream count limits.
                            if stream::is_bidi(stream_id) {
                                self.local_max_streams_bidi
                                    .checked_sub(1)
                                    .ok_or(Error::StreamLimit)?;
                            } else {
                                self.local_max_streams_uni
                                    .checked_sub(1)
                                    .ok_or(Error::StreamLimit)?;
                            }

                            let s = stream::Stream::new(max_rx_data, max_tx_data);
                            v.insert(s)
                        },

                        hash_map::Entry::Occupied(v) => v.into_mut(),
                    };

                    self.rx_data += data.len();

                    if self.rx_data > self.max_rx_data {
                        return Err(Error::FlowControl);
                    }

                    stream.recv_push(data)?;

                    do_ack = true;
                },

                frame::Frame::MaxData { max } => {
                    self.max_tx_data = cmp::max(self.max_tx_data, max as usize);

                    do_ack = true;
                },

                frame::Frame::MaxStreamData { stream_id, max } => {
                    let max_rx_data = self
                        .local_transport_params
                        .initial_max_stream_data_bidi_remote
                        as usize;
                    let max_tx_data = self
                        .peer_transport_params
                        .initial_max_stream_data_bidi_local
                        as usize;

                    // Get existing stream or create a new one.
                    let stream = match self.streams.entry(stream_id) {
                        hash_map::Entry::Vacant(v) => {
                            // Peer is not supposed to create this stream.
                            if stream::is_local(stream_id, self.is_server) {
                                return Err(Error::InvalidStreamState);
                            }

                            // Enforce stream count limits.
                            if stream::is_bidi(stream_id) {
                                self.local_max_streams_bidi
                                    .checked_sub(1)
                                    .ok_or(Error::StreamLimit)?;
                            } else {
                                self.local_max_streams_uni
                                    .checked_sub(1)
                                    .ok_or(Error::StreamLimit)?;
                            }

                            let s = stream::Stream::new(max_rx_data, max_tx_data);
                            v.insert(s)
                        },

                        hash_map::Entry::Occupied(v) => v.into_mut(),
                    };

                    stream.send_max_data(max as usize);

                    do_ack = true;
                },

                frame::Frame::MaxStreamsBidi { max } => {
                    self.peer_max_streams_bidi =
                        cmp::max(self.peer_max_streams_bidi, max as usize);

                    do_ack = true;
                },

                frame::Frame::MaxStreamsUni { max } => {
                    self.peer_max_streams_uni =
                        cmp::max(self.peer_max_streams_uni, max as usize);

                    do_ack = true;
                },

                // TODO: implement connection migration
                frame::Frame::NewConnectionId { .. } => {
                    do_ack = true;
                },

                // TODO: implement connection migration
                frame::Frame::RetireConnectionId { .. } => {
                    do_ack = true;
                },

                frame::Frame::PathChallenge { data } => {
                    self.challenge = Some(data);

                    do_ack = true;
                },

                frame::Frame::PathResponse { .. } => {
                    do_ack = true;
                },

                frame::Frame::ConnectionClose { .. } => {
                    self.draining = true;
                    self.draining_timer = Some(now + DRAINING_TIMEOUT);
                },

                frame::Frame::ApplicationClose { .. } => {
                    self.draining = true;
                    self.draining_timer = Some(now + DRAINING_TIMEOUT);
                },
            }
        }

        // Process ACK'd frames.
        for acked in space.flight.acked.drain(..) {
            match acked {
                // Stop acknowledging packets less than or equal to the
                // largest acknowledged in the sent ACK frame that, in
                // turn, got ACK'd.
                frame::Frame::ACK { ranges, .. } => {
                    let largest_acked = ranges.largest().unwrap();
                    space.recv_pkt_need_ack.remove_until(largest_acked);
                },

                // This does nothing. It's here to avoid a warning.
                frame::Frame::Ping => (),

                _ => (),
            }
        }

        // We only record the time of arrival of the largest packet number
        // that still needs to be ACK'd, to be used for ACK delay calculation.
        if space.recv_pkt_need_ack.largest() < Some(pn) {
            space.largest_rx_pkt_time = now;
        }

        space.recv_pkt_num.insert(pn);

        space.recv_pkt_need_ack.push_item(pn);
        space.do_ack = cmp::max(space.do_ack, do_ack);

        space.largest_rx_pkt_num = cmp::max(space.largest_rx_pkt_num, pn);

        self.idle_timer = Some(
            now + time::Duration::from_secs(
                self.local_transport_params.idle_timeout,
            ),
        );

        let read = b.off() + aead.alg().tag_len();

        // On the server, drop initial state after receiving and successfully
        // processing an Handshake packet.
        if self.is_server && hdr.ty == packet::Type::Handshake {
            self.drop_initial_state();
        }

        Ok(read)
    }

    /// Writes a single QUIC packet to be sent to the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned, or [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn send(&mut self, out: &mut [u8]) -> Result<usize> {
        let now = time::Instant::now();

        if out.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.draining {
            return Err(Error::Done);
        }

        let is_closing = self.error.is_some() || self.app_error.is_some();

        if !is_closing {
            self.do_handshake()?;
        }

        // Use max_packet_size as sent by the peer, except during the handshake
        // when we haven't parsed transport parameters yet, so use a default
        // value then.
        let max_pkt_len = if self.handshake_completed {
            // We cap the maximum packet size to 16KB or so, so that it can be
            // always encoded with a 2-byte varint.
            cmp::min(16383, self.peer_transport_params.max_packet_size) as usize
        } else {
            // Allow for 1200 bytes (minimum QUIC packet size) during the
            // handshake.
            1200
        };

        // Cap output buffer to respect peer's max_packet_size limit.
        let avail = cmp::min(max_pkt_len, out.len());

        let mut b = octets::Octets::with_slice(&mut out[..avail]);

        let pkt_type = self.select_egress_pkt_type()?;

        let space = match pkt_type {
            packet::Type::Initial => &mut self.initial,

            packet::Type::Handshake => &mut self.handshake,

            packet::Type::Application => &mut self.application,

            _ => unreachable!(),
        };

        // Process lost frames.
        for lost in space.flight.lost.drain(..) {
            match lost {
                frame::Frame::Crypto { data } => {
                    space.crypto_stream.send_push_front(data)?;
                },

                frame::Frame::Stream { stream_id, data } => {
                    let stream = match self.streams.get_mut(&stream_id) {
                        Some(v) => v,
                        None => continue,
                    };

                    self.tx_data -= data.len();

                    stream.send_push_front(data)?;
                },

                frame::Frame::ACK { .. } => {
                    space.do_ack = true;
                },

                _ => (),
            }
        }

        // Update global lost packets counter. This prevents us from losing
        // information when the Initial state is dropped.
        self.lost_count += space.flight.lost_count;
        space.flight.lost_count = 0;

        // Calculate available space in the packet based on congestion window.
        let mut left = cmp::min(self.recovery.cwnd(), b.cap());

        let pn = space.next_pkt_num;
        let pn_len = packet::pkt_num_len(pn)?;

        let hdr = Header {
            ty: pkt_type,
            version: self.version,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            pkt_num: 0,
            pkt_num_len: pn_len,
            odcid: None,
            token: self.token.clone(),
            versions: None,
            key_phase: false,
        };

        hdr.to_bytes(&mut b)?;

        // Make sure we have enough space left for the header, the payload
        // length, the packet number and the AEAD overhead. We assume that
        // the payload length can always be encoded with a 2-byte varint.
        left = left
            .checked_sub(b.off() + 2 + pn_len + space.overhead())
            .ok_or(Error::Done)?;

        let mut frames: Vec<frame::Frame> = Vec::new();

        let mut ack_eliciting = false;
        let mut is_crypto = false;

        let mut payload_len = 0;

        // Create ACK frame.
        if space.do_ack {
            let ack_delay = space.largest_rx_pkt_time.elapsed();

            let ack_delay = ack_delay.as_secs() * 1_000_000 +
                u64::from(ack_delay.subsec_micros());

            let ack_delay = ack_delay /
                2_u64.pow(self.local_transport_params.ack_delay_exponent as u32);

            let frame = frame::Frame::ACK {
                ack_delay,
                ranges: space.recv_pkt_need_ack.clone(),
            };

            if frame.wire_len() <= left {
                space.do_ack = false;

                payload_len += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);
            }
        }

        // Create MAX_DATA frame, when the new limit is at least double the
        // amount of data that can be received before blocking.
        if pkt_type == packet::Type::Application &&
            !is_closing &&
            (self.new_max_rx_data != self.max_rx_data &&
                self.new_max_rx_data / 2 > self.max_rx_data - self.rx_data)
        {
            let frame = frame::Frame::MaxData {
                max: self.new_max_rx_data as u64,
            };

            if frame.wire_len() <= left {
                self.max_rx_data = self.new_max_rx_data;

                payload_len += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);

                ack_eliciting = true;
            }
        }

        // Create MAX_STREAM_DATA frames as needed.
        if pkt_type == packet::Type::Application && !is_closing {
            for (id, stream) in
                self.streams.iter_mut().filter(|(_, s)| s.more_credit())
            {
                let frame = frame::Frame::MaxStreamData {
                    stream_id: *id,
                    max: stream.recv_update_max_data() as u64,
                };

                if frame.wire_len() > left {
                    break;
                }

                payload_len += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);

                ack_eliciting = true;
            }
        }

        // Create PING and PADDING for TLP.
        if self.recovery.probes > 0 && left >= 1 {
            let frame = frame::Frame::Ping;

            payload_len += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.recovery.probes -= 1;

            ack_eliciting = true;
        }

        // Create CONNECTION_CLOSE frame.
        if let Some(err) = self.error {
            let frame = frame::Frame::ConnectionClose {
                error_code: err,
                frame_type: 0,
                reason: Vec::new(),
            };

            payload_len += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.draining = true;
            self.draining_timer = Some(now + DRAINING_TIMEOUT);
        }

        // Create APPLICAtiON_CLOSE frame.
        if let Some(err) = self.app_error {
            let frame = frame::Frame::ApplicationClose {
                error_code: err,
                reason: self.app_reason.clone(),
            };

            payload_len += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.draining = true;
            self.draining_timer = Some(now + DRAINING_TIMEOUT);
        }

        // Create PATH_RESPONSE frame.
        if let Some(ref challenge) = self.challenge {
            let frame = frame::Frame::PathResponse {
                data: challenge.clone(),
            };

            payload_len += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            self.challenge = None;
        }

        // Create CRYPTO frame.
        if space.crypto_stream.writable() && !is_closing {
            let crypto_len = left - frame::MAX_CRYPTO_OVERHEAD;
            let crypto_buf = space.crypto_stream.send_pop(crypto_len)?;

            let frame = frame::Frame::Crypto { data: crypto_buf };

            payload_len += frame.wire_len();
            left -= frame.wire_len();

            frames.push(frame);

            ack_eliciting = true;
            is_crypto = true;
        }

        // Create a single STREAM frame for the first stream that is writable.
        if pkt_type == packet::Type::Application &&
            !is_closing &&
            self.max_tx_data > self.tx_data &&
            left > frame::MAX_STREAM_OVERHEAD
        {
            // TODO: round-robin selected stream instead of picking the first
            for (id, stream) in self.streams.iter_mut().filter(|(_, s)| s.writable())
            {
                // Make sure we can fit the data in the packet.
                let stream_len = cmp::min(
                    left - frame::MAX_STREAM_OVERHEAD,
                    self.max_tx_data - self.tx_data,
                );

                let stream_buf = stream.send_pop(stream_len)?;

                if stream_buf.is_empty() {
                    continue;
                }

                self.tx_data += stream_buf.len();

                let frame = frame::Frame::Stream {
                    stream_id: *id,
                    data: stream_buf,
                };

                payload_len += frame.wire_len();
                left -= frame.wire_len();

                frames.push(frame);

                ack_eliciting = true;
                break;
            }
        }

        if frames.is_empty() {
            return Err(Error::Done);
        }

        // Pad the client's initial packet.
        if !self.is_server && pkt_type == packet::Type::Initial {
            let pkt_len = pn_len + payload_len + space.overhead();

            let frame = frame::Frame::Padding {
                len: cmp::min(CLIENT_INITIAL_MIN_LEN - pkt_len, left),
            };

            payload_len += frame.wire_len();

            frames.push(frame);
        }

        // Pad payload so that it's always at least 4 bytes.
        if payload_len < PAYLOAD_MIN_LEN {
            let frame = frame::Frame::Padding {
                len: PAYLOAD_MIN_LEN - payload_len,
            };

            payload_len += frame.wire_len();

            frames.push(frame);
        }

        payload_len += space.overhead();

        // Only long header packets have an explicit length field.
        if pkt_type != packet::Type::Application {
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

        let sent_pkt =
            recovery::Sent::new(pn, frames, written, ack_eliciting, is_crypto, now);

        self.recovery.on_packet_sent(
            sent_pkt,
            &mut space.flight,
            now,
            &self.trace_id,
        );

        space.next_pkt_num += 1;

        self.sent_count += 1;

        // On the client, drop initial state after sending an Handshake packet.
        if !self.is_server && hdr.ty == packet::Type::Handshake {
            self.drop_initial_state();
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
    pub fn stream_recv(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool)> {
        // TODO: test !is_bidi && is_local

        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return Err(Error::InvalidStreamState),
        };

        if !stream.readable() {
            return Err(Error::Done);
        }

        let (read, fin) = stream.recv_pop(out)?;

        self.new_max_rx_data = self.max_rx_data + read;

        Ok((read, fin))
    }

    /// Writes data to a stream.
    ///
    /// On success the number of bytes written is returned.
    pub fn stream_send(
        &mut self, stream_id: u64, buf: &[u8], fin: bool,
    ) -> Result<usize> {
        // We can't write on the peer's unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            !stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState);
        }

        let max_rx_data = self
            .local_transport_params
            .initial_max_stream_data_bidi_local as usize;
        let max_tx_data = self
            .peer_transport_params
            .initial_max_stream_data_bidi_remote as usize;

        // Get existing stream or create a new one.
        let stream = match self.streams.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                if !stream::is_local(stream_id, self.is_server) {
                    return Err(Error::InvalidStreamState);
                }

                // Enforce stream count limits.
                if stream::is_bidi(stream_id) {
                    self.peer_max_streams_bidi
                        .checked_sub(1)
                        .ok_or(Error::StreamLimit)?;
                } else {
                    self.peer_max_streams_uni
                        .checked_sub(1)
                        .ok_or(Error::StreamLimit)?;
                }

                let s = stream::Stream::new(max_rx_data, max_tx_data);
                v.insert(s)
            },

            hash_map::Entry::Occupied(v) => v.into_mut(),
        };

        // TODO: implement backpressure based on peer's flow control

        stream.send_push(buf, fin)?;

        Ok(buf.len())
    }

    /// Creates an iterator over streams that have outstanding data to read.
    pub fn readable(&mut self) -> Readable {
        stream::Readable::new(&self.streams)
    }

    /// Returns the amount of time until the next timeout event.
    ///
    /// Once the given duration has elapsed, the [`on_timeout()`] method should
    /// be called. A timeout of `None` means that the timer should be disarmed.
    ///
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    pub fn timeout(&self) -> Option<std::time::Duration> {
        if self.closed {
            return None;
        }

        let timeout = if self.draining {
            self.draining_timer
        } else if self.recovery.loss_detection_timer().is_some() {
            self.recovery.loss_detection_timer()
        } else if self.idle_timer.is_some() {
            self.idle_timer
        } else {
            None
        };

        if let Some(timeout) = timeout {
            let now = time::Instant::now();

            if timeout <= now {
                return Some(std::time::Duration::new(0, 0));
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

        if self.draining {
            if self.draining_timer.is_some() && self.draining_timer.unwrap() <= now {
                trace!("{} draining timeout expired", self.trace_id);

                self.closed = true;
            }

            return;
        }

        if self.idle_timer.is_some() && self.idle_timer.unwrap() <= now {
            trace!("{} idle timeout expired", self.trace_id);

            self.closed = true;
            return;
        }

        if self.recovery.loss_detection_timer().is_some() &&
            self.recovery.loss_detection_timer().unwrap() <= now
        {
            trace!("{} loss detection timeout expired", self.trace_id);

            self.recovery.on_loss_detection_timer(
                &mut self.initial.flight,
                &mut self.handshake.flight,
                &mut self.application.flight,
                now,
                &self.trace_id,
            );

            return;
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
    pub fn close(&mut self, app: bool, err: u16, reason: &[u8]) -> Result<()> {
        if self.draining {
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
        self.tls_state.get_alpn_protocol()
    }

    /// Returns true if the connection handshake is complete.
    pub fn is_established(&self) -> bool {
        self.handshake_completed
    }

    /// Returns true if the connection is resumed.
    pub fn is_resumed(&self) -> bool {
        self.tls_state.is_resumed()
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
            sent: self.sent_count,
            lost: self.lost_count,
            rtt: self.recovery.rtt(),
        }
    }

    /// Continues the handshake.
    ///
    /// If the connection is already established, it does nothing.
    fn do_handshake(&mut self) -> Result<()> {
        if !self.handshake_completed {
            match self.tls_state.do_handshake() {
                Ok(_) => {
                    // Handshake is complete!
                    self.handshake_completed = true;

                    let mut raw_params =
                        self.tls_state.get_quic_transport_params().to_vec();

                    let peer_params = TransportParams::decode(
                        &mut raw_params,
                        self.version,
                        self.is_server,
                    )?;

                    if peer_params.original_connection_id != self.odcid {
                        return Err(Error::InvalidTransportParam);
                    }

                    self.max_tx_data = peer_params.initial_max_data as usize;

                    self.peer_max_streams_bidi =
                        peer_params.initial_max_streams_bidi as usize;
                    self.peer_max_streams_uni =
                        peer_params.initial_max_streams_uni as usize;

                    self.recovery.max_ack_delay =
                        time::Duration::from_millis(peer_params.max_ack_delay);

                    self.peer_transport_params = peer_params;

                    trace!("{} connection established: cipher={:?} proto={:?} resumed={} {:?}",
                           &self.trace_id,
                           self.tls_state.cipher(),
                           std::str::from_utf8(self.application_proto()),
                           self.is_resumed(),
                           self.peer_transport_params);
                },

                Err(tls::Error::TlsFail) => {
                    // If we have an error to send (e.g. a TLS alert), ignore
                    // the error so we send a CONNECTION_CLOSE to the peer.
                    if self.error.is_none() {
                        return Err(Error::TlsFail);
                    }
                },

                Err(tls::Error::SyscallFail) => return Err(Error::TlsFail),

                Err(_) => (),
            }
        }

        Ok(())
    }

    /// Selects the type for the outgoing packet depending on whether there is
    /// handshake data to send, whether there are packets to ACK, or whether
    /// there are streams that can be written or that needs to increase flow
    /// control credit.
    fn select_egress_pkt_type(&self) -> Result<Type> {
        let ty =
            // On error or probe, send packet in the latest space available.
            if self.error.is_some() || self.recovery.probes > 0 {
                match self.tls_state.get_write_level() {
                    crypto::Level::Initial     => Type::Initial,
                    crypto::Level::ZeroRTT     => unreachable!(),
                    crypto::Level::Handshake   => Type::Handshake,
                    crypto::Level::Application => Type::Application,
                }
            } else if self.initial.ready() {
                Type::Initial
            } else if self.handshake.ready() {
                Type::Handshake
            } else if self.handshake_completed &&
                      (self.application.ready() ||
                       self.streams.values().any(|s| s.writable()) ||
                       self.streams.values().any(|s| s.more_credit())) {
                Type::Application
            } else {
                return Err(Error::Done);
            };

        Ok(ty)
    }

    /// Drops the initial keys and recovery state.
    fn drop_initial_state(&mut self) {
        if self.initial.crypto_open.is_none() {
            return;
        }

        self.recovery.drop_unacked_data(&mut self.initial.flight);
        self.initial.crypto_open = None;
        self.initial.crypto_seal = None;
        self.initial.clear();

        trace!("{} dropped initial state", self.trace_id);
    }
}

/// Statistics about the connection.
///
/// A connections's statistics can be collected using the [`stats()`] method.
///
/// [`stats()`]: struct.Connection.html#method.stats
#[derive(Clone)]
pub struct Stats {
    /// The number of QUIC packets sent on this connection.
    pub sent: usize,

    /// The number of QUIC packets that were lost.
    pub lost: usize,

    /// The estimated round-trip time of the connection.
    pub rtt: time::Duration,
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "sent={} lost={} rtt={:?}",
            self.sent, self.lost, self.rtt
        )
    }
}

#[derive(Clone, PartialEq)]
struct TransportParams {
    pub original_connection_id: Option<Vec<u8>>,
    pub idle_timeout: u64,
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
    pub disable_migration: bool,
    // pub preferred_address: ...
}

impl Default for TransportParams {
    fn default() -> TransportParams {
        TransportParams {
            original_connection_id: None,
            idle_timeout: 0,
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
            disable_migration: false,
        }
    }
}

impl TransportParams {
    fn decode(
        buf: &mut [u8], _version: u32, is_server: bool,
    ) -> Result<TransportParams> {
        let mut b = octets::Octets::with_slice(buf);

        // TODO: check version
        let _tp_version = b.get_u32()?;

        if !is_server {
            // Ignore supported versions from server.
            b.get_bytes_with_u8_length()?;
        }

        let mut tp = TransportParams::default();

        let mut params = b.get_bytes_with_u16_length()?;

        while params.cap() > 0 {
            let id = params.get_u16()?;

            let mut val = params.get_bytes_with_u16_length()?;

            // TODO: forbid duplicated param

            match id {
                0x0000 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.original_connection_id = Some(val.to_vec());
                },

                0x0001 => {
                    tp.idle_timeout = val.get_varint()?;
                },

                0x0002 => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    tp.stateless_reset_token = Some(val.get_bytes(16)?.to_vec());
                },

                0x0003 => {
                    tp.max_packet_size = val.get_varint()?;
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
                    tp.initial_max_streams_bidi = val.get_varint()?;
                },

                0x0009 => {
                    tp.initial_max_streams_uni = val.get_varint()?;
                },

                0x000a => {
                    tp.ack_delay_exponent = val.get_varint()?;
                },

                0x000b => {
                    tp.max_ack_delay = val.get_varint()?;
                },

                0x000c => {
                    tp.disable_migration = true;
                },

                0x000d => {
                    if is_server {
                        return Err(Error::InvalidTransportParam);
                    }

                    // TODO: decode preferred_address
                },

                // Ignore unknown parameters.
                _ => (),
            }
        }

        Ok(tp)
    }

    fn encode<'a>(
        tp: &TransportParams, version: u32, is_server: bool, out: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let mut params = [0; 128];

        let params_len = {
            let mut b = octets::Octets::with_slice(&mut params);

            if is_server {
                if let Some(ref odcid) = tp.original_connection_id {
                    b.put_u16(0x0000)?;
                    b.put_u16(odcid.len() as u16)?;
                    b.put_bytes(&odcid)?;
                }
            };

            if tp.idle_timeout != 0 {
                b.put_u16(0x0001)?;
                b.put_u16(octets::varint_len(tp.idle_timeout) as u16)?;
                b.put_varint(tp.idle_timeout)?;
            }

            if let Some(ref token) = tp.stateless_reset_token {
                if is_server {
                    b.put_u16(0x0002)?;
                    b.put_u16(token.len() as u16)?;
                    b.put_bytes(&token)?;
                }
            }

            if tp.max_packet_size != 0 {
                b.put_u16(0x0003)?;
                b.put_u16(octets::varint_len(tp.max_packet_size) as u16)?;
                b.put_varint(tp.max_packet_size)?;
            }

            if tp.initial_max_data != 0 {
                b.put_u16(0x0004)?;
                b.put_u16(octets::varint_len(tp.initial_max_data) as u16)?;
                b.put_varint(tp.initial_max_data)?;
            }

            if tp.initial_max_stream_data_bidi_local != 0 {
                b.put_u16(0x0005)?;
                b.put_u16(
                    octets::varint_len(tp.initial_max_stream_data_bidi_local) as u16,
                )?;
                b.put_varint(tp.initial_max_stream_data_bidi_local)?;
            }

            if tp.initial_max_stream_data_bidi_remote != 0 {
                b.put_u16(0x0006)?;
                b.put_u16(
                    octets::varint_len(tp.initial_max_stream_data_bidi_remote)
                        as u16,
                )?;
                b.put_varint(tp.initial_max_stream_data_bidi_remote)?;
            }

            if tp.initial_max_stream_data_uni != 0 {
                b.put_u16(0x0007)?;
                b.put_u16(octets::varint_len(tp.initial_max_stream_data_uni) as u16)?;
                b.put_varint(tp.initial_max_stream_data_uni)?;
            }

            if tp.initial_max_streams_bidi != 0 {
                b.put_u16(0x0008)?;
                b.put_u16(octets::varint_len(tp.initial_max_streams_bidi) as u16)?;
                b.put_varint(tp.initial_max_streams_bidi)?;
            }

            if tp.initial_max_streams_uni != 0 {
                b.put_u16(0x0009)?;
                b.put_u16(octets::varint_len(tp.initial_max_streams_uni) as u16)?;
                b.put_varint(tp.initial_max_streams_uni)?;
            }

            if tp.ack_delay_exponent != 0 {
                b.put_u16(0x000a)?;
                b.put_u16(octets::varint_len(tp.ack_delay_exponent) as u16)?;
                b.put_varint(tp.ack_delay_exponent)?;
            }

            if tp.max_ack_delay != 0 {
                b.put_u16(0x000b)?;
                b.put_u16(octets::varint_len(tp.max_ack_delay) as u16)?;
                b.put_varint(tp.max_ack_delay)?;
            }

            if tp.disable_migration {
                b.put_u16(0x000c)?;
                b.put_u16(0)?;
            }

            // TODO: encode preferred_address

            b.off()
        };

        let out_len = {
            let mut b = octets::Octets::with_slice(out);

            b.put_u32(version)?;

            if is_server {
                b.put_u8(mem::size_of::<u32>() as u8)?;
                b.put_u32(version)?;
            };

            b.put_u16(params_len as u16)?;
            b.put_bytes(&params[..params_len])?;

            b.off()
        };

        Ok(&mut out[..out_len])
    }
}

impl std::fmt::Debug for TransportParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "idle_timeout={} ", self.idle_timeout)?;
        write!(f, "max_packet_size={} ", self.max_packet_size)?;
        write!(f, "initial_max_data={} ", self.initial_max_data)?;
        write!(
            f,
            "initial_max_stream_data_bidi_local={} ",
            self.initial_max_stream_data_bidi_local
        )?;
        write!(
            f,
            "initial_max_stream_data_bidi_remote={} ",
            self.initial_max_stream_data_bidi_remote
        )?;
        write!(
            f,
            "initial_max_stream_data_uni={} ",
            self.initial_max_stream_data_uni
        )?;
        write!(
            f,
            "initial_max_streams_bidi={} ",
            self.initial_max_streams_bidi
        )?;
        write!(
            f,
            "initial_max_streams_uni={} ",
            self.initial_max_streams_uni
        )?;
        write!(f, "ack_delay_exponent={} ", self.ack_delay_exponent)?;
        write!(f, "disable_migration={}", self.disable_migration)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_params() {
        let tp = TransportParams {
            original_connection_id: None,
            idle_timeout: 30,
            stateless_reset_token: Some(vec![0xba; 16]),
            max_packet_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 123,
            max_ack_delay: 1234,
            disable_migration: true,
        };

        let mut raw_params = [42; 256];
        let mut raw_params =
            TransportParams::encode(&tp, VERSION_DRAFT17, true, &mut raw_params)
                .unwrap();
        assert_eq!(raw_params.len(), 106);

        let new_tp =
            TransportParams::decode(&mut raw_params, VERSION_DRAFT17, false)
                .unwrap();

        assert_eq!(new_tp, tp);
    }

    fn create_conn(is_server: bool) -> Box<Connection> {
        let mut scid = [0; 16];
        rand::rand_bytes(&mut scid[..]);

        let mut config = Config::new(VERSION_DRAFT17).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.verify_peer(false);

        Connection::new(&scid, None, &mut config, is_server).unwrap()
    }

    fn recv_send(conn: &mut Connection, buf: &mut [u8], len: usize) -> usize {
        let mut left = len;

        while left > 0 {
            let read = conn.recv(&mut buf[len - left..len]).unwrap();

            left -= read;
        }

        let mut off = 0;

        while off < buf.len() {
            let write = match conn.send(&mut buf[off..]) {
                Ok(v) => v,

                Err(Error::Done) => {
                    break;
                },

                Err(e) => panic!("SEND FAILED: {:?}", e),
            };

            off += write;
        }

        off
    }

    #[test]
    fn self_handshake() {
        let mut buf = [0; 65535];

        let mut cln = create_conn(false);
        let mut srv = create_conn(true);

        let mut len = cln.send(&mut buf).unwrap();

        while !cln.is_established() && !srv.is_established() {
            len = recv_send(&mut srv, &mut buf, len);
            len = recv_send(&mut cln, &mut buf, len);
        }

        assert!(true);
    }
}

pub use crate::packet::Header;
pub use crate::packet::Type;
pub use crate::stream::Readable;

mod crypto;
mod ffi;
mod frame;
mod octets;
mod packet;
mod rand;
mod ranges;
mod recovery;
mod stream;
mod tls;
