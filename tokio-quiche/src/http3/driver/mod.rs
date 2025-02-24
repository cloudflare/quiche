// Copyright (C) 2025, Cloudflare, Inc.
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

mod client;
/// Wrapper for running HTTP/3 connections.
pub mod connection;
mod datagram;
// `DriverHooks` must stay private to prevent users from creating their own
// H3Drivers.
mod hooks;
mod server;
mod streams;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use datagram_socket::StreamClosureKind;
use foundations::telemetry::log;
use futures::FutureExt;
use futures_util::stream::FuturesUnordered;
use quiche::h3;
use tokio::select;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::{
    self,
};
use tokio_stream::StreamExt;
use tokio_util::sync::PollSender;

use self::hooks::DriverHooks;
use self::hooks::InboundHeaders;
use self::streams::FlowCtx;
use self::streams::HaveUpstreamCapacity;
use self::streams::ReceivedDownstreamData;
use self::streams::StreamCtx;
use self::streams::StreamReady;
use self::streams::WaitForDownstreamData;
use self::streams::WaitForStream;
use self::streams::WaitForUpstreamCapacity;
use crate::buf_factory::BufFactory;
use crate::buf_factory::PooledBuf;
use crate::buf_factory::PooledDgram;
use crate::http3::settings::Http3Settings;
use crate::http3::H3AuditStats;
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::QuicCommand;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

pub use self::client::ClientEventStream;
pub use self::client::ClientH3Command;
pub use self::client::ClientH3Controller;
pub use self::client::ClientH3Driver;
pub use self::client::ClientH3Event;
pub use self::client::ClientRequestSender;
pub use self::client::NewClientRequest;
pub use self::server::ServerEventStream;
pub use self::server::ServerH3Command;
pub use self::server::ServerH3Controller;
pub use self::server::ServerH3Driver;
pub use self::server::ServerH3Event;

// The priority of all HTTP/3 responses is currently fixed at this value.
// TODO: make this configurable as part of `OutboundFrame::Headers`
const DEFAULT_PRIO: h3::Priority = h3::Priority::new(3, true);

// For a stream use a channel with 16 entries, which works out to 16 * 64KB =
// 1MB of max buffered data.
#[cfg(not(any(test, debug_assertions)))]
const STREAM_CAPACITY: usize = 16;
#[cfg(any(test, debug_assertions))]
const STREAM_CAPACITY: usize = 1; // Set to 1 to stress write_pending under test conditions

// For *all* flows use a shared channel with 2048 entries, which works out
// to 3MB of max buffered data at 1500 bytes per datagram.
const FLOW_CAPACITY: usize = 2048;

/// Used by a local task to send [`OutboundFrame`]s to a peer on the
/// stream or flow associated with this channel.
pub type OutboundFrameSender = PollSender<OutboundFrame>;

/// Used internally to receive [`OutboundFrame`]s which should be sent to a peer
/// on the stream or flow associated with this channel.
type OutboundFrameStream = mpsc::Receiver<OutboundFrame>;

/// Used internally to send [`InboundFrame`]s (data) from the peer to a local
/// task on the stream or flow associated with this channel.
type InboundFrameSender = PollSender<InboundFrame>;

/// Used by a local task to receive [`InboundFrame`]s (data) on the stream or
/// flow associated with this channel.
pub type InboundFrameStream = mpsc::Receiver<InboundFrame>;

/// The error type used internally in [H3Driver].
///
/// Note that [`ApplicationOverQuic`] errors are not exposed to users at this
/// time. The type is public to document the failure modes in [H3Driver].
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3ConnectionError {
    /// The controller task was shut down and is no longer listening.
    ControllerWentAway,
    /// Other error at the connection, but not stream level.
    H3(h3::Error),
    /// Received a GOAWAY frame from the peer.
    GoAway,
    /// Received data for a stream that was closed or never opened.
    NonexistentStream,
    /// The server's post-accept timeout was hit.
    /// The timeout can be configured in [`Http3Settings`].
    PostAcceptTimeout,
}

impl From<h3::Error> for H3ConnectionError {
    fn from(err: h3::Error) -> Self {
        H3ConnectionError::H3(err)
    }
}

impl From<quiche::Error> for H3ConnectionError {
    fn from(err: quiche::Error) -> Self {
        H3ConnectionError::H3(h3::Error::TransportError(err))
    }
}

impl Error for H3ConnectionError {}

impl fmt::Display for H3ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s: &dyn fmt::Display = match self {
            Self::ControllerWentAway => &"controller went away",
            Self::H3(e) => e,
            Self::GoAway => &"goaway",
            Self::NonexistentStream => &"nonexistent stream",
            Self::PostAcceptTimeout => &"post accept timeout hit",
        };

        write!(f, "H3ConnectionError: {s}")
    }
}

type H3ConnectionResult<T> = Result<T, H3ConnectionError>;

/// HTTP/3 headers that were received on a stream.
///
/// `recv` is used to read the message body, while `send` is used to transmit
/// data back to the peer.
#[derive(Debug)]
pub struct IncomingH3Headers {
    /// Stream ID of the frame.
    pub stream_id: u64,
    /// The actual [`h3::Header`]s which were received.
    pub headers: Vec<h3::Header>,
    /// An [`OutboundFrameSender`] for streaming body data to the peer. For
    /// [ClientH3Driver], note that the request body can also be passed a
    /// cloned sender via [`NewClientRequest`].
    pub send: OutboundFrameSender,
    /// An [`InboundFrameStream`] of body data received from the peer.
    pub recv: InboundFrameStream,
    /// Whether there is a body associated with the incoming headers.
    pub read_fin: bool,
    /// Handle to the [`H3AuditStats`] for the message's stream.
    pub h3_audit_stats: Arc<H3AuditStats>,
}

/// [`H3Event`]s are produced by an [H3Driver] to describe HTTP/3 state updates.
///
/// Both [ServerH3Driver] and [ClientH3Driver] may extend this enum with
/// endpoint-specific variants. The events must be consumed by users of the
/// drivers, like a higher-level `Server` or `Client` controller.
#[derive(Debug)]
pub enum H3Event {
    /// A SETTINGS frame was received.
    IncomingSettings {
        /// Raw HTTP/3 setting pairs, in the order received from the peer.
        settings: Vec<(u64, u64)>,
    },

    /// A HEADERS frame was received on the given stream. This is either a
    /// request or a response depending on the perspective of the [`H3Event`]
    /// receiver.
    IncomingHeaders(IncomingH3Headers),

    /// A DATAGRAM flow was created and associated with the given `flow_id`.
    /// This event is fired before a HEADERS event for CONNECT[-UDP] requests.
    NewFlow {
        /// Flow ID of the new flow.
        flow_id: u64,
        /// An [`OutboundFrameSender`] for transmitting datagrams to the peer.
        send: OutboundFrameSender,
        /// An [`InboundFrameStream`] for receiving datagrams from the peer.
        recv: InboundFrameStream,
    },
    /// A RST_STREAM frame was seen on the given `stream_id`. The user of the
    /// driver should clean up any state allocated for this stream.
    ResetStream { stream_id: u64 },
    /// The connection has irrecoverably errored and is shutting down.
    ConnectionError(h3::Error),
    /// The connection has been shutdown, optionally due to an
    /// [`H3ConnectionError`].
    ConnectionShutdown(Option<H3ConnectionError>),
    /// Body data has been received over a stream.
    BodyBytesReceived {
        /// Stream ID of the body data.
        stream_id: u64,
        /// Number of bytes received.
        num_bytes: u64,
        /// Whether the stream is finished and won't yield any more data.
        fin: bool,
    },
    /// The stream has been closed. This is used to signal stream closures that
    /// don't result from RST_STREAM frames, unlike the
    /// [`H3Event::ResetStream`] variant.
    StreamClosed { stream_id: u64 },
}

impl H3Event {
    /// Generates an event from an applicable [`H3ConnectionError`].
    fn from_error(err: &H3ConnectionError) -> Option<Self> {
        Some(match err {
            H3ConnectionError::H3(e) => Self::ConnectionError(*e),
            H3ConnectionError::PostAcceptTimeout => Self::ConnectionShutdown(
                Some(H3ConnectionError::PostAcceptTimeout),
            ),
            _ => return None,
        })
    }
}

/// An [`OutboundFrame`] is a data frame that should be sent from a local task
/// to a peer over a [`quiche::h3::Connection`].
///
/// This is used, for example, to send response body data to a peer, or proxied
/// UDP datagrams.
#[derive(Debug)]
pub enum OutboundFrame {
    /// Response headers to be sent to the peer.
    Headers(Vec<h3::Header>),
    /// Response body/CONNECT downstream data plus FIN flag.
    #[cfg(feature = "zero-copy")]
    Body(crate::buf_factory::QuicheBuf, bool),
    /// Response body/CONNECT downstream data plus FIN flag.
    #[cfg(not(feature = "zero-copy"))]
    Body(PooledBuf, bool),
    /// CONNECT-UDP (DATAGRAM) downstream data plus flow ID.
    Datagram(PooledDgram, u64),
    /// An error encountered when serving the request. Stream should be closed.
    PeerStreamError,
    /// DATAGRAM flow explicitly closed.
    FlowShutdown { flow_id: u64, stream_id: u64 },
}

impl OutboundFrame {
    /// Creates a body frame with the provided buffer.
    pub fn body(body: PooledBuf, fin: bool) -> Self {
        #[cfg(feature = "zero-copy")]
        let body = crate::buf_factory::QuicheBuf::new(body);

        OutboundFrame::Body(body, fin)
    }
}

/// An [`InboundFrame`] is a data frame that was received from the peer over a
/// [`quiche::h3::Connection`]. This is used by peers to send body or datagrams
/// to the local task.
#[derive(Debug)]
pub enum InboundFrame {
    /// Request body/CONNECT upstream data plus FIN flag.
    Body(PooledBuf, bool),
    /// CONNECT-UDP (DATAGRAM) upstream data.
    Datagram(PooledDgram),
}

/// A ready-made [`ApplicationOverQuic`] which can handle HTTP/3 and MASQUE.
/// Depending on the `DriverHooks` in use, it powers either a client or a
/// server.
///
/// Use the [ClientH3Driver] and [ServerH3Driver] aliases to access the
/// respective driver types. The driver is passed into an I/O loop and
/// communicates with the driver's user (e.g., an HTTP client or a server) via
/// its associated [H3Controller]. The controller allows the application to both
/// listen for [`H3Event`]s of note and send [`H3Command`]s into the I/O loop.
pub struct H3Driver<H: DriverHooks> {
    /// Configuration used to initialize `conn`. Created from [`Http3Settings`]
    /// in the constructor.
    h3_config: h3::Config,
    /// The underlying HTTP/3 connection. Initialized in
    /// `ApplicationOverQuic::on_conn_established`.
    conn: Option<h3::Connection>,
    /// State required by the client/server hooks.
    hooks: H,
    /// Sends [`H3Event`]s to the [H3Controller] paired with this driver.
    h3_event_sender: mpsc::UnboundedSender<H::Event>,
    /// Receives [`H3Command`]s from the [H3Controller] paired with this driver.
    cmd_recv: mpsc::UnboundedReceiver<H::Command>,

    /// A map of stream IDs to their [StreamCtx]. This is mainly used to
    /// retrieve the internal Tokio channels associated with the stream.
    stream_map: BTreeMap<u64, StreamCtx>,
    /// A map of flow IDs to their [FlowCtx]. This is mainly used to retrieve
    /// the internal Tokio channels associated with the flow.
    flow_map: BTreeMap<u64, FlowCtx>,
    /// Set of [`WaitForStream`] futures. A stream is added to this set if
    /// we need to send to it and its channel is at capacity, or if we need
    /// data from its channel and the channel is empty.
    waiting_streams: FuturesUnordered<WaitForStream>,

    /// Receives [`OutboundFrame`]s from all datagram flows on the connection.
    dgram_recv: OutboundFrameStream,
    /// Keeps the datagram channel open such that datagram flows can be created.
    dgram_send: OutboundFrameSender,

    /// The buffer used to interact with the underlying IoWorker.
    pooled_buf: PooledBuf,
    /// The maximum HTTP/3 stream ID seen on this connection.
    max_stream_seen: u64,

    /// Tracks whether we have forwarded the HTTP/3 SETTINGS frame
    /// to the [H3Controller] once.
    settings_received_and_forwarded: bool,
}

impl<H: DriverHooks> H3Driver<H> {
    /// Builds a new [H3Driver] and an associated [H3Controller].
    ///
    /// The driver should then be passed to
    /// [`InitialQuicConnection`](crate::InitialQuicConnection)'s `start`
    /// method.
    pub fn new(http3_settings: Http3Settings) -> (Self, H3Controller<H>) {
        let (dgram_send, dgram_recv) = mpsc::channel(FLOW_CAPACITY);
        let (cmd_sender, cmd_recv) = mpsc::unbounded_channel();
        let (h3_event_sender, h3_event_recv) = mpsc::unbounded_channel();

        (
            H3Driver {
                h3_config: (&http3_settings).into(),
                conn: None,
                hooks: H::new(&http3_settings),
                h3_event_sender,
                cmd_recv,

                stream_map: BTreeMap::new(),
                flow_map: BTreeMap::new(),

                dgram_recv,
                dgram_send: PollSender::new(dgram_send),
                pooled_buf: BufFactory::get_max_buf(),
                max_stream_seen: 0,

                waiting_streams: FuturesUnordered::new(),

                settings_received_and_forwarded: false,
            },
            H3Controller {
                cmd_sender,
                h3_event_recv: Some(h3_event_recv),
            },
        )
    }

    /// Retrieve the [FlowCtx] associated with the given `flow_id`. If no
    /// context is found, a new one will be created.
    fn get_or_insert_flow(
        &mut self, flow_id: u64,
    ) -> H3ConnectionResult<&mut FlowCtx> {
        use std::collections::btree_map::Entry;
        Ok(match self.flow_map.entry(flow_id) {
            Entry::Vacant(e) => {
                // This is a datagram for a new flow we haven't seen before
                let (flow, recv) = FlowCtx::new(FLOW_CAPACITY);
                let flow_req = H3Event::NewFlow {
                    flow_id,
                    recv,
                    send: self.dgram_send.clone(),
                };
                self.h3_event_sender
                    .send(flow_req.into())
                    .map_err(|_| H3ConnectionError::ControllerWentAway)?;
                e.insert(flow)
            },
            Entry::Occupied(e) => e.into_mut(),
        })
    }

    /// Adds a [StreamCtx] to the stream map with the given `stream_id`.
    fn insert_stream(&mut self, stream_id: u64, ctx: StreamCtx) {
        self.stream_map.insert(stream_id, ctx);
        self.max_stream_seen = self.max_stream_seen.max(stream_id);
    }

    /// Fetches body chunks from the [`quiche::h3::Connection`] and forwards
    /// them to the stream's associated [`InboundFrameStream`].
    fn process_h3_data(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        // Split self borrow between conn and stream_map
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let ctx = self
            .stream_map
            .get_mut(&stream_id)
            .ok_or(H3ConnectionError::NonexistentStream)?;

        enum StreamStatus {
            Done { close: bool },
            Blocked,
        }

        let status = loop {
            let Some(sender) = ctx.send.as_ref().and_then(PollSender::get_ref)
            else {
                // already waiting for capacity
                break StreamStatus::Done { close: false };
            };

            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(TrySendError::Closed(())) => {
                    break StreamStatus::Done {
                        close: ctx.fin_sent && ctx.fin_recv,
                    };
                },
                Err(TrySendError::Full(())) => {
                    if ctx.fin_recv || qconn.stream_readable(stream_id) {
                        break StreamStatus::Blocked;
                    }
                    break StreamStatus::Done { close: false };
                },
            };

            if ctx.fin_recv {
                // Signal end-of-body to upstream
                permit
                    .send(InboundFrame::Body(BufFactory::get_empty_buf(), true));
                break StreamStatus::Done {
                    close: ctx.fin_sent,
                };
            }

            match conn.recv_body(qconn, stream_id, &mut self.pooled_buf) {
                Ok(n) => {
                    let mut body = std::mem::replace(
                        &mut self.pooled_buf,
                        BufFactory::get_max_buf(),
                    );
                    body.truncate(n);

                    ctx.audit_stats.add_downstream_bytes_recvd(n as u64);
                    let event = H3Event::BodyBytesReceived {
                        stream_id,
                        num_bytes: n as u64,
                        fin: false,
                    };
                    let _ = self.h3_event_sender.send(event.into());

                    permit.send(InboundFrame::Body(body, false));
                },
                Err(h3::Error::Done) =>
                    break StreamStatus::Done { close: false },
                Err(_) => break StreamStatus::Done { close: true },
            }
        };

        match status {
            StreamStatus::Done { close } => {
                if close {
                    return self.finish_stream(qconn, stream_id, None, None);
                }

                // The QUIC stream is finished, manually invoke `process_h3_fin`
                // in case `h3::poll()` is never called again.
                //
                // Note that this case will not conflict with StreamStatus::Done
                // being returned due to the body channel being
                // blocked. qconn.stream_finished() will guarantee
                // that we've fully parsed the body as it only returns true
                // if we've seen a Fin for the read half of the stream.
                if !ctx.fin_recv && qconn.stream_finished(stream_id) {
                    return self.process_h3_fin(qconn, stream_id);
                }
            },
            StreamStatus::Blocked => {
                self.waiting_streams.push(ctx.wait_for_send(stream_id));
            },
        }

        Ok(())
    }

    /// Processes an end-of-stream event from the [`quiche::h3::Connection`].
    fn process_h3_fin(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let ctx = self.stream_map.get_mut(&stream_id).filter(|c| !c.fin_recv);
        let Some(ctx) = ctx else {
            // Stream is already finished, nothing to do
            return Ok(());
        };

        ctx.fin_recv = true;
        ctx.audit_stats
            .set_recvd_stream_fin(StreamClosureKind::Explicit);

        // It's important to send this H3Event before process_h3_data so that
        // a server can (potentially) generate the control response before the
        // corresponding receiver drops.
        let event = H3Event::BodyBytesReceived {
            stream_id,
            num_bytes: 0,
            fin: true,
        };
        let _ = self.h3_event_sender.send(event.into());

        // Communicate fin to upstream. Since `ctx.fin_recv` is true now,
        // there can't be a recursive loop.
        self.process_h3_data(qconn, stream_id)
    }

    /// Processes a single [`quiche::h3::Event`] received from the underlying
    /// [`quiche::h3::Connection`]. Some events are dispatched to helper
    /// methods.
    fn process_read_event(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64, event: h3::Event,
    ) -> H3ConnectionResult<()> {
        self.forward_settings()?;

        match event {
            // Requests/responses are exclusively handled by hooks.
            #[cfg(not(feature = "gcongestion"))]
            h3::Event::Headers { list, more_frames } =>
                H::headers_received(self, qconn, InboundHeaders {
                    stream_id,
                    headers: list,
                    has_body: more_frames,
                }),

            #[cfg(feature = "gcongestion")]
            h3::Event::Headers { list, has_body } =>
                H::headers_received(self, qconn, InboundHeaders {
                    stream_id,
                    headers: list,
                    has_body,
                }),

            h3::Event::Data => self.process_h3_data(qconn, stream_id),
            h3::Event::Finished => self.process_h3_fin(qconn, stream_id),

            h3::Event::Reset(code) => {
                if let Some(ctx) = self.stream_map.get(&stream_id) {
                    ctx.audit_stats.set_recvd_reset_stream_error_code(code as _);
                }

                self.h3_event_sender
                    .send(H3Event::ResetStream { stream_id }.into())
                    .map_err(|_| H3ConnectionError::ControllerWentAway)?;

                self.finish_stream(qconn, stream_id, None, None)
            },

            h3::Event::PriorityUpdate => Ok(()),
            h3::Event::GoAway => Err(H3ConnectionError::GoAway),
        }
    }

    /// The SETTINGS frame can be received at any point, so we
    /// need to check `peer_settings_raw` to decide if we've received it.
    ///
    /// Settings should only be sent once, so we generate a single event
    /// when `peer_settings_raw` transitions from None to Some.
    fn forward_settings(&mut self) -> H3ConnectionResult<()> {
        if self.settings_received_and_forwarded {
            return Ok(());
        }

        // capture the peer settings and forward it
        if let Some(settings) = self.conn_mut()?.peer_settings_raw() {
            let incoming_settings = H3Event::IncomingSettings {
                settings: settings.to_vec(),
            };

            self.h3_event_sender
                .send(incoming_settings.into())
                .map_err(|_| H3ConnectionError::ControllerWentAway)?;

            self.settings_received_and_forwarded = true;
        }
        Ok(())
    }

    /// Send an individual frame to the underlying [`quiche::h3::Connection`] to
    /// be flushed at a later time.
    ///
    /// `Self::process_writes` will iterate over all writable streams and call
    /// this method in a loop for each stream to send all writable packets.
    fn process_write_frame(
        conn: &mut h3::Connection, qconn: &mut QuicheConnection,
        ctx: &mut StreamCtx,
    ) -> h3::Result<()> {
        let Some(frame) = &mut ctx.queued_frame else {
            return Ok(());
        };

        let audit_stats = &ctx.audit_stats;
        let stream_id = audit_stats.stream_id();

        match frame {
            // Initial headers were already sent, send additional headers now.
            #[cfg(not(feature = "gcongestion"))]
            OutboundFrame::Headers(headers) if ctx.initial_headers_sent => conn
                .send_additional_headers(qconn, stream_id, headers, false, false),

            // Send initial headers.
            OutboundFrame::Headers(headers) => conn
                .send_response_with_priority(
                    qconn,
                    stream_id,
                    headers,
                    &DEFAULT_PRIO,
                    false,
                )
                .inspect(|_| ctx.initial_headers_sent = true),

            OutboundFrame::Body(body, fin) => {
                let len = body.as_ref().len();
                if *fin {
                    // If this is the last body frame, close the receiver in the
                    // stream map to signal that we shouldn't
                    // receive any more frames.
                    ctx.recv.as_mut().expect("channel").close();
                }
                #[cfg(feature = "zero-copy")]
                let n = conn.send_body_zc(qconn, stream_id, body, *fin)?;

                #[cfg(not(feature = "zero-copy"))]
                let n = conn.send_body(qconn, stream_id, body, *fin)?;

                audit_stats.add_downstream_bytes_sent(n as _);
                if n != len {
                    // Couldn't write the entire body, keep what remains for
                    // future retry.
                    #[cfg(not(feature = "zero-copy"))]
                    body.pop_front(n);

                    Err(h3::Error::StreamBlocked)
                } else {
                    if *fin {
                        ctx.fin_sent = true;
                        audit_stats
                            .set_sent_stream_fin(StreamClosureKind::Explicit);
                        if ctx.fin_recv {
                            // Return a TransportError to trigger stream cleanup
                            // instead of h3::Error::Done
                            return Err(h3::Error::TransportError(
                                quiche::Error::Done,
                            ));
                        }
                    }
                    Ok(())
                }
            },

            OutboundFrame::PeerStreamError => Err(h3::Error::MessageError),

            OutboundFrame::FlowShutdown { .. } => {
                unreachable!("Only flows send shutdowns")
            },

            OutboundFrame::Datagram(..) => {
                unreachable!("Only flows send datagrams")
            },
        }
    }

    /// Resumes reads or writes to the connection when a stream channel becomes
    /// unblocked.
    ///
    /// If we were waiting for more data from a channel, we resume writing to
    /// the connection. Otherwise, we were blocked on channel capacity and
    /// continue reading from the connection. `Upstream` in this context is
    /// the consumer of the stream.
    fn upstream_ready(
        &mut self, qconn: &mut QuicheConnection, ready: StreamReady,
    ) -> H3ConnectionResult<()> {
        match ready {
            StreamReady::Downstream(r) => self.upstream_read_ready(qconn, r),
            StreamReady::Upstream(r) => self.upstream_write_ready(qconn, r),
        }
    }

    fn upstream_read_ready(
        &mut self, qconn: &mut QuicheConnection,
        read_ready: ReceivedDownstreamData,
    ) -> H3ConnectionResult<()> {
        let ReceivedDownstreamData {
            stream_id,
            chan,
            data,
        } = read_ready;

        match self.stream_map.get_mut(&stream_id) {
            None => Ok(()),
            Some(stream) => {
                stream.recv = Some(chan);
                stream.queued_frame = data;
                self.process_writable_stream(qconn, stream_id)
            },
        }
    }

    fn upstream_write_ready(
        &mut self, qconn: &mut QuicheConnection,
        write_ready: HaveUpstreamCapacity,
    ) -> H3ConnectionResult<()> {
        let HaveUpstreamCapacity {
            stream_id,
            mut chan,
        } = write_ready;

        match self.stream_map.get_mut(&stream_id) {
            None => Ok(()),
            Some(stream) => {
                chan.abort_send(); // Have to do it to release the associated permit
                stream.send = Some(chan);
                self.process_h3_data(qconn, stream_id)
            },
        }
    }

    /// Processes all queued outbound datagrams from the `dgram_recv` channel.
    fn dgram_ready(
        &mut self, qconn: &mut QuicheConnection, frame: OutboundFrame,
    ) -> H3ConnectionResult<()> {
        let mut frame = Ok(frame);

        loop {
            match frame {
                Ok(OutboundFrame::Datagram(dgram, flow_id)) => {
                    // Drop datagrams if there is no capacity
                    let _ = datagram::send_h3_dgram(qconn, flow_id, dgram);
                },
                Ok(OutboundFrame::FlowShutdown { flow_id, stream_id }) => {
                    self.finish_stream(
                        qconn,
                        stream_id,
                        Some(quiche::h3::WireErrorCode::NoError as u64),
                        Some(quiche::h3::WireErrorCode::NoError as u64),
                    )?;
                    self.flow_map.remove(&flow_id);
                    break;
                },
                Ok(_) => unreachable!("Flows can't send frame of other types"),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) =>
                    return Err(H3ConnectionError::ControllerWentAway),
            }

            frame = self.dgram_recv.try_recv();
        }

        Ok(())
    }

    /// Return a mutable reference to the driver's HTTP/3 connection.
    ///
    /// If the connection doesn't exist yet, this function returns
    /// a `Self::connection_not_present()` error.
    fn conn_mut(&mut self) -> H3ConnectionResult<&mut h3::Connection> {
        self.conn.as_mut().ok_or(Self::connection_not_present())
    }

    /// Alias for [`quiche::Error::TlsFail`], which is used in the case where
    /// this driver doesn't have an established HTTP/3 connection attached
    /// to it yet.
    const fn connection_not_present() -> H3ConnectionError {
        H3ConnectionError::H3(h3::Error::TransportError(quiche::Error::TlsFail))
    }

    /// Removes a stream from the stream map if it exists. Also optionally sends
    /// `RESET` or `STOP_SENDING` frames if `write` or `read` is set to an
    /// error code, respectively.
    fn finish_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        read: Option<u64>, write: Option<u64>,
    ) -> H3ConnectionResult<()> {
        let Some(stream_ctx) = self.stream_map.remove(&stream_id) else {
            return Ok(());
        };

        let audit_stats = &stream_ctx.audit_stats;

        if let Some(err) = read {
            audit_stats.set_sent_stop_sending_error_code(err as _);
            let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Read, err);
        }

        if let Some(err) = write {
            audit_stats.set_sent_reset_stream_error_code(err as _);
            let _ =
                qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, err);
        }

        // Find if the stream also has any pending futures associated with it
        for pending in self.waiting_streams.iter_mut() {
            match pending {
                WaitForStream::Downstream(WaitForDownstreamData {
                    stream_id: id,
                    chan: Some(chan),
                }) if stream_id == *id => {
                    chan.close();
                },
                WaitForStream::Upstream(WaitForUpstreamCapacity {
                    stream_id: id,
                    chan: Some(chan),
                }) if stream_id == *id => {
                    chan.close();
                },
                _ => {},
            }
        }

        // Close any DATAGRAM-proxying channels when we close the stream, if they
        // exist
        if let Some(mapped_flow_id) = stream_ctx.associated_dgram_flow_id {
            self.flow_map.remove(&mapped_flow_id);
        }

        if qconn.is_server() {
            // Signal the server to remove the stream from its map
            let _ = self
                .h3_event_sender
                .send(H3Event::StreamClosed { stream_id }.into());
        }

        Ok(())
    }

    /// Handles a regular [`H3Command`]. May be called internally by
    /// [DriverHooks] for non-endpoint-specific [`H3Command`]s.
    fn handle_core_command(
        &mut self, qconn: &mut QuicheConnection, cmd: H3Command,
    ) -> H3ConnectionResult<()> {
        match cmd {
            H3Command::QuicCmd(cmd) => cmd.execute(qconn),
            H3Command::GoAway => {
                let max_id = self.max_stream_seen;
                self.conn_mut()
                    .expect("connection should be established")
                    .send_goaway(qconn, max_id)?;
            },
        }
        Ok(())
    }
}

impl<H: DriverHooks> H3Driver<H> {
    /// Reads all buffered datagrams out of `qconn` and distributes them to
    /// their flow channels.
    fn process_available_dgrams(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        loop {
            match datagram::receive_h3_dgram(qconn) {
                Ok((flow_id, dgram)) => {
                    self.get_or_insert_flow(flow_id)?.send_best_effort(dgram);
                },
                Err(quiche::Error::Done) => return Ok(()),
                Err(err) => return Err(H3ConnectionError::from(err)),
            }
        }
    }

    /// Flushes any queued-up frames for `stream_id` into `qconn` until either
    /// there is no more capacity in `qconn` or no more frames to send.
    fn process_writable_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        // Split self borrow between conn and stream_map
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let Some(ctx) = self.stream_map.get_mut(&stream_id) else {
            return Ok(()); // Unknown stream_id
        };

        loop {
            // Process each writable frame, queue the next frame for processing
            // and shut down any errored streams.
            match Self::process_write_frame(conn, qconn, ctx) {
                Ok(()) => ctx.queued_frame = None,
                Err(h3::Error::StreamBlocked | h3::Error::Done) => break,
                Err(h3::Error::MessageError) => {
                    return self.finish_stream(
                        qconn,
                        stream_id,
                        Some(quiche::h3::WireErrorCode::MessageError as u64),
                        Some(quiche::h3::WireErrorCode::MessageError as u64),
                    );
                },
                Err(h3::Error::TransportError(quiche::Error::StreamStopped(
                    e,
                ))) => {
                    ctx.audit_stats.set_recvd_stop_sending_error_code(e as i64);
                    return self.finish_stream(qconn, stream_id, Some(e), None);
                },
                Err(h3::Error::TransportError(
                    quiche::Error::InvalidStreamState(stream),
                )) => {
                    return self.finish_stream(qconn, stream, None, None);
                },
                Err(_) => {
                    return self.finish_stream(qconn, stream_id, None, None);
                },
            }

            let Some(recv) = ctx.recv.as_mut() else {
                return Ok(()); // This stream is already waiting for data
            };

            // Attempt to queue the next frame for processing. The corresponding
            // sender is created at the same time as the `StreamCtx`
            // and ultimately ends up in an `H3Body`. The body then
            // determines which frames to send to the peer via
            // this processing loop.
            match recv.try_recv() {
                Ok(frame) => ctx.queued_frame = Some(frame),
                Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {
                    self.waiting_streams.push(ctx.wait_for_recv(stream_id));
                    break;
                },
            }
        }

        Ok(())
    }

    /// Tests `qconn` for either a local or peer error and increments
    /// the associated HTTP/3 or QUIC error counter.
    fn record_quiche_error(qconn: &mut QuicheConnection, metrics: &impl Metrics) {
        // split metrics between local/peer and QUIC/HTTP/3 level errors
        if let Some(err) = qconn.local_error() {
            if err.is_app {
                metrics.local_h3_conn_close_error_count(err.error_code.into())
            } else {
                metrics.local_quic_conn_close_error_count(err.error_code.into())
            }
            .inc();
        } else if let Some(err) = qconn.peer_error() {
            if err.is_app {
                metrics.peer_h3_conn_close_error_count(err.error_code.into())
            } else {
                metrics.peer_quic_conn_close_error_count(err.error_code.into())
            }
            .inc();
        }
    }
}

impl<H: DriverHooks> ApplicationOverQuic for H3Driver<H> {
    fn on_conn_established(
        &mut self, quiche_conn: &mut QuicheConnection,
        handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        let conn = h3::Connection::with_transport(quiche_conn, &self.h3_config)?;
        self.conn = Some(conn);

        H::conn_established(self, quiche_conn, handshake_info)?;
        Ok(())
    }

    #[inline]
    fn should_act(&self) -> bool {
        self.conn.is_some()
    }

    #[inline]
    fn buffer(&mut self) -> &mut [u8] {
        &mut self.pooled_buf
    }

    /// Poll the underlying [`quiche::h3::Connection`] for
    /// [`quiche::h3::Event`]s and DATAGRAMs, delegating processing to
    /// `Self::process_read_event`.
    ///
    /// If a DATAGRAM is found, it is sent to the receiver on its channel.
    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        loop {
            match self.conn_mut()?.poll(qconn) {
                Ok((stream_id, event)) =>
                    self.process_read_event(qconn, stream_id, event)?,
                Err(h3::Error::Done) => break,
                Err(err) => {
                    // Don't bubble error up, instead keep the worker loop going
                    // until quiche reports the connection is
                    // closed.
                    log::debug!("connection closed due to h3 protocol error"; "error"=>?err);
                    return Ok(());
                },
            };
        }

        self.process_available_dgrams(qconn)?;
        Ok(())
    }

    /// Write as much data as possible into the [`quiche::h3::Connection`] from
    /// all sources. This will attempt to write any queued frames into their
    /// respective streams, if writable.
    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Some(stream_id) = qconn.stream_writable_next() {
            self.process_writable_stream(qconn, stream_id)?;
        }

        // Also optimistically check for any ready streams
        while let Some(Some(ready)) = self.waiting_streams.next().now_or_never() {
            self.upstream_ready(qconn, ready)?;
        }

        Ok(())
    }

    /// Reports connection-level error metrics and forwards
    /// IOWorker errors to the associated [H3Controller].
    fn on_conn_close<M: Metrics>(
        &mut self, quiche_conn: &mut QuicheConnection, metrics: &M,
        work_loop_result: &QuicResult<()>,
    ) {
        let max_stream_seen = self.max_stream_seen;
        metrics
            .maximum_writable_streams()
            .observe(max_stream_seen as f64);

        let Err(work_loop_error) = work_loop_result else {
            return;
        };

        Self::record_quiche_error(quiche_conn, metrics);

        let Some(h3_err) = work_loop_error.downcast_ref::<H3ConnectionError>()
        else {
            log::error!("Found non-H3ConnectionError"; "error" => %work_loop_error);
            return;
        };

        if matches!(h3_err, H3ConnectionError::ControllerWentAway) {
            // Inform client that we won't (can't) respond anymore
            let _ =
                quiche_conn.close(true, h3::WireErrorCode::NoError as u64, &[]);
            return;
        }

        if let Some(ev) = H3Event::from_error(h3_err) {
            let _ = self.h3_event_sender.send(ev.into());
            #[expect(clippy::needless_return)]
            return; // avoid accidental fallthrough in the future
        }
    }

    /// Wait for incoming data from the [H3Controller]. The next iteration of
    /// the I/O loop commences when one of the `select!`ed futures triggers.
    #[inline]
    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        select! {
            biased;
            Some(ready) = self.waiting_streams.next() => self.upstream_ready(qconn, ready),
            Some(dgram) = self.dgram_recv.recv() => self.dgram_ready(qconn, dgram),
            Some(cmd) = self.cmd_recv.recv() => H::conn_command(self, qconn, cmd),
            r = self.hooks.wait_for_action(qconn), if H::has_wait_action(self) => r,
        }?;

        // Make sure controller is not starved, but also not prioritized in the
        // biased select. So poll it last, however also perform a try_recv
        // each iteration.
        if let Ok(cmd) = self.cmd_recv.try_recv() {
            H::conn_command(self, qconn, cmd)?;
        }

        Ok(())
    }
}

impl<H: DriverHooks> Drop for H3Driver<H> {
    fn drop(&mut self) {
        for stream in self.stream_map.values() {
            stream
                .audit_stats
                .set_recvd_stream_fin(StreamClosureKind::Implicit);
        }
    }
}

/// [`H3Command`]s are sent by the [H3Controller] to alter the [H3Driver]'s
/// state.
///
/// Both [ServerH3Driver] and [ClientH3Driver] may extend this enum with
/// endpoint-specific variants.
#[derive(Debug)]
pub enum H3Command {
    /// A connection-level command that executes directly on the
    /// [`quiche::Connection`].
    QuicCmd(QuicCommand),
    /// Send a GOAWAY frame to the peer to initiate a graceful connection
    /// shutdown.
    GoAway,
}

/// Sends [`H3Command`]s to an [H3Driver]. The sender is typed and internally
/// wraps instances of `T` in the appropriate `H3Command` variant.
pub struct RequestSender<C, T> {
    sender: UnboundedSender<C>,
    // Required to work around dangling type parameter
    _r: PhantomData<fn() -> T>,
}

impl<C, T: Into<C>> RequestSender<C, T> {
    /// Send a request to the [H3Driver]. This can only fail if the driver is
    /// gone.
    #[inline(always)]
    pub fn send(&self, v: T) -> Result<(), mpsc::error::SendError<C>> {
        self.sender.send(v.into())
    }
}

impl<C, T> Clone for RequestSender<C, T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            _r: Default::default(),
        }
    }
}

/// Interface to communicate with a paired [H3Driver].
///
/// An [H3Controller] receives [`H3Event`]s from its driver, which must be
/// consumed by the application built on top of the driver to react to incoming
/// events. The controller also allows the application to send ad-hoc
/// [`H3Command`]s to the driver, which will be processed when the driver waits
/// for incoming data.
pub struct H3Controller<H: DriverHooks> {
    /// Sends [`H3Command`]s to the [H3Driver], like [`QuicCommand`]s or
    /// outbound HTTP requests.
    cmd_sender: UnboundedSender<H::Command>,
    /// Receives [`H3Event`]s from the [H3Driver]. Can be extracted and
    /// used independently of the [H3Controller].
    h3_event_recv: Option<UnboundedReceiver<H::Event>>,
}

impl<H: DriverHooks> H3Controller<H> {
    /// Gets a mut reference to the [`H3Event`] receiver for the paired
    /// [H3Driver].
    pub fn event_receiver_mut(&mut self) -> &mut UnboundedReceiver<H::Event> {
        self.h3_event_recv
            .as_mut()
            .expect("No event receiver on H3Controller")
    }

    /// Takes the [`H3Event`] receiver for the paired [H3Driver].
    pub fn take_event_receiver(&mut self) -> UnboundedReceiver<H::Event> {
        self.h3_event_recv
            .take()
            .expect("No event receiver on H3Controller")
    }

    /// Creates a [`QuicCommand`] sender for the paired [H3Driver].
    pub fn cmd_sender(&self) -> RequestSender<H::Command, QuicCommand> {
        RequestSender {
            sender: self.cmd_sender.clone(),
            _r: Default::default(),
        }
    }

    /// Sends a GOAWAY frame to initiate a graceful connection shutdown.
    pub fn send_goaway(&self) {
        let _ = self.cmd_sender.send(H3Command::GoAway.into());
    }
}
