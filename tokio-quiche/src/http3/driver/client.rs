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

use std::collections::BTreeMap;
use std::sync::Arc;

use foundations::telemetry::log;
use quiche::h3;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use super::datagram;
use super::DriverHooks;
use super::H3Command;
use super::H3ConnectionError;
use super::H3ConnectionResult;
use super::H3Controller;
use super::H3Driver;
use super::H3Event;
use super::InboundFrameStream;
use super::InboundHeaders;
use super::IncomingH3Headers;
use super::OutboundFrameSender;
use super::RequestSender;
use super::StreamCtx;
use super::STREAM_CAPACITY;
use crate::http3::settings::Http3Settings;
use crate::quic::HandshakeInfo;
use crate::quic::QuicCommand;
use crate::quic::QuicheConnection;

/// An [H3Driver] for a client-side HTTP/3 connection. See [H3Driver] for
/// details. Emits [`ClientH3Event`]s and expects [`ClientH3Command`]s for
/// control.
pub type ClientH3Driver = H3Driver<ClientHooks>;
/// The [H3Controller] type paired with [ClientH3Driver]. See [H3Controller] for
/// details.
pub type ClientH3Controller = H3Controller<ClientHooks>;
/// Receives [`ClientH3Event`]s from a [ClientH3Driver]. This is the control
/// stream which describes what is happening on the connection, but does not
/// transfer data.
pub type ClientEventStream = mpsc::UnboundedReceiver<ClientH3Event>;
/// A [RequestSender] to send HTTP requests over a [ClientH3Driver]'s
/// connection.
pub type ClientRequestSender = RequestSender<ClientH3Command, NewClientRequest>;

/// An HTTP request sent using a [ClientRequestSender] to the [ClientH3Driver].
#[derive(Debug)]
pub struct NewClientRequest {
    /// A user-defined identifier to match [`ClientH3Event::NewOutboundRequest`]
    /// to its original [`NewClientRequest`]. This ID is not used anywhere else.
    pub request_id: u64,
    /// The [`h3::Header`]s that make up this request.
    pub headers: Vec<h3::Header>,
    /// A sender to pass the request's [`OutboundFrameSender`] to the request
    /// body.
    pub body_writer: Option<oneshot::Sender<OutboundFrameSender>>,
}

/// Events produced by [ClientH3Driver].
#[derive(Debug)]
pub enum ClientH3Event {
    Core(H3Event),
    /// Headers for the request with the given `request_id` were sent on
    /// `stream_id`. The body, if there is one, could still be sending.
    NewOutboundRequest {
        stream_id: u64,
        request_id: u64,
    },
}

impl From<H3Event> for ClientH3Event {
    fn from(ev: H3Event) -> Self {
        Self::Core(ev)
    }
}

/// Commands accepted by [ClientH3Driver].
#[derive(Debug)]
pub enum ClientH3Command {
    Core(H3Command),
    /// Send a new HTTP request over the [`quiche::h3::Connection`]. The driver
    /// will allocate a stream ID and report it back to the controller via
    /// [`ClientH3Event::NewOutboundRequest`].
    ClientRequest(NewClientRequest),
}

impl From<H3Command> for ClientH3Command {
    fn from(cmd: H3Command) -> Self {
        Self::Core(cmd)
    }
}

impl From<QuicCommand> for ClientH3Command {
    fn from(cmd: QuicCommand) -> Self {
        Self::Core(H3Command::QuicCmd(cmd))
    }
}

impl From<NewClientRequest> for ClientH3Command {
    fn from(req: NewClientRequest) -> Self {
        Self::ClientRequest(req)
    }
}

/// A [`PendingClientRequest`] is a request which has not yet received a
/// response.
///
/// The `send` and `recv` halves are passed to the [ClientH3Controller] in an
/// [`H3Event::IncomingHeaders`] once the server's response has been received.
struct PendingClientRequest {
    send: OutboundFrameSender,
    recv: InboundFrameStream,
}

pub struct ClientHooks {
    /// Mapping from stream IDs to the associated [`PendingClientRequest`].
    pending_requests: BTreeMap<u64, PendingClientRequest>,
}

impl ClientHooks {
    /// Initiates a client-side request. This sends the request, stores the
    /// [`PendingClientRequest`] and allocates a new stream plus potential
    /// DATAGRAM flow (CONNECT-{UDP,IP}).
    fn initiate_request(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        request: NewClientRequest,
    ) -> H3ConnectionResult<()> {
        let body_finished = request.body_writer.is_none();

        // TODO: retry the request if the error is not fatal
        let stream_id = driver.conn_mut()?.send_request(
            qconn,
            &request.headers,
            body_finished,
        )?;

        // log::info!("sent h3 request"; "stream_id" => stream_id);
        let (mut stream_ctx, send, recv) =
            StreamCtx::new(stream_id, STREAM_CAPACITY);

        if let Some(flow_id) =
            datagram::extract_flow_id(stream_id, &request.headers)
        {
            log::info!(
                "creating new flow for MASQUE request";
                "stream_id" => stream_id,
                "flow_id" => flow_id,
            );
            let _ = driver.get_or_insert_flow(flow_id)?;
            stream_ctx.associated_dgram_flow_id = Some(flow_id);
        }

        if let Some(body_writer) = request.body_writer {
            let _ = body_writer.send(send.clone());
            driver
                .waiting_streams
                .push(stream_ctx.wait_for_recv(stream_id));
        }

        driver.insert_stream(stream_id, stream_ctx);
        driver
            .hooks
            .pending_requests
            .insert(stream_id, PendingClientRequest { send, recv });

        // Notify the H3Controller that we've allocated a stream_id for a
        // given request_id.
        let _ = driver
            .h3_event_sender
            .send(ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id: request.request_id,
            });

        Ok(())
    }

    /// Handles a response from the peer by sending a relevant [`H3Event`] to
    /// the [ClientH3Controller] for application-level processing.
    fn handle_response(
        driver: &mut H3Driver<Self>, headers: InboundHeaders,
        pending_request: PendingClientRequest,
    ) -> H3ConnectionResult<()> {
        let InboundHeaders {
            stream_id,
            headers,
            has_body,
        } = headers;

        let Some(stream_ctx) = driver.stream_map.get(&stream_id) else {
            // todo(fisher): send better error to client
            return Err(H3ConnectionError::NonexistentStream);
        };

        let headers = IncomingH3Headers {
            stream_id,
            headers,
            send: pending_request.send,
            recv: pending_request.recv,
            read_fin: !has_body,
            h3_audit_stats: Arc::clone(&stream_ctx.audit_stats),
            latest_priority_update: None,
        };

        driver
            .h3_event_sender
            .send(H3Event::IncomingHeaders(headers).into())
            .map_err(|_| H3ConnectionError::ControllerWentAway)
    }
}

#[allow(private_interfaces)]
impl DriverHooks for ClientHooks {
    type Command = ClientH3Command;
    type Event = ClientH3Event;

    fn new(_settings: &Http3Settings) -> Self {
        Self {
            pending_requests: BTreeMap::new(),
        }
    }

    fn conn_established(
        _driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> H3ConnectionResult<()> {
        assert!(
            !qconn.is_server(),
            "ClientH3Driver requires a client-side QUIC connection"
        );
        Ok(())
    }

    fn headers_received(
        driver: &mut H3Driver<Self>, _qconn: &mut QuicheConnection,
        headers: InboundHeaders,
    ) -> H3ConnectionResult<()> {
        let Some(pending_request) =
            driver.hooks.pending_requests.remove(&headers.stream_id)
        else {
            // todo(fisher): better handling when an unknown stream_id is
            // encountered.
            return Ok(());
        };
        Self::handle_response(driver, headers, pending_request)
    }

    fn conn_command(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        cmd: Self::Command,
    ) -> H3ConnectionResult<()> {
        match cmd {
            ClientH3Command::Core(c) => driver.handle_core_command(qconn, c),
            ClientH3Command::ClientRequest(req) =>
                Self::initiate_request(driver, qconn, req),
        }
    }
}

impl ClientH3Controller {
    /// Creates a [`NewClientRequest`] sender for the paired [ClientH3Driver].
    pub fn request_sender(&self) -> ClientRequestSender {
        RequestSender {
            sender: self.cmd_sender.clone(),
            _r: Default::default(),
        }
    }
}
