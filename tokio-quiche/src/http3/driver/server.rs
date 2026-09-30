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

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use foundations::telemetry::log;
use tokio::sync::mpsc;

use super::datagram;
use super::DriverHooks;
use super::H3Command;
use super::H3ConnectionError;
use super::H3ConnectionResult;
use super::H3Controller;
use super::H3Driver;
use super::H3Event;
use super::InboundHeaders;
use super::IncomingH3Headers;
use super::StreamCtx;
use super::StreamShutdown;
use super::STREAM_CAPACITY;
use crate::http3::settings::Http3Settings;
use crate::http3::settings::Http3SettingsEnforcer;
use crate::http3::settings::Http3TimeoutType;
use crate::http3::settings::TimeoutKey;
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::QuicCommand;
use crate::quic::QuicheConnection;

/// An [H3Driver] for a server-side HTTP/3 connection. See [H3Driver] for
/// details. Emits [`ServerH3Event`]s and expects [`ServerH3Command`]s for
/// control.
pub type ServerH3Driver = H3Driver<ServerHooks>;
/// The [H3Controller] type paired with [ServerH3Driver]. See [H3Controller] for
/// details.
pub type ServerH3Controller = H3Controller<ServerHooks>;
/// Receives [`ServerH3Event`]s from a [ServerH3Driver]. This is the control
/// stream which describes what is happening on the connection, but does not
/// transfer data.
pub type ServerEventStream = mpsc::UnboundedReceiver<ServerH3Event>;

#[derive(Clone, Debug)]
pub struct RawPriorityValue(Vec<u8>);

impl From<Vec<u8>> for RawPriorityValue {
    fn from(value: Vec<u8>) -> Self {
        RawPriorityValue(value)
    }
}

impl Deref for RawPriorityValue {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The request was received during early data (0-RTT).
#[derive(Clone, Debug)]
pub struct IsInEarlyData(bool);

impl IsInEarlyData {
    fn new(is_in_early_data: bool) -> Self {
        IsInEarlyData(is_in_early_data)
    }
}

impl Deref for IsInEarlyData {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Events produced by [ServerH3Driver].
#[derive(Debug)]
pub enum ServerH3Event {
    Core(H3Event),

    Headers {
        incoming_headers: IncomingH3Headers,
        /// The latest PRIORITY_UPDATE frame value, if any.
        priority: Option<RawPriorityValue>,
        is_in_early_data: IsInEarlyData,
    },
}

impl From<H3Event> for ServerH3Event {
    fn from(ev: H3Event) -> Self {
        match ev {
            H3Event::IncomingHeaders(incoming_headers) => {
                // Server `incoming_headers` are exclusively created in
                // `ServerHooks::handle_request`, which correctly serializes the
                // `RawPriorityValue` and `IsInEarlyData` values.
                //
                // `H3Driver::process_read_event` implements this behavior.
                Self::Headers {
                    incoming_headers,
                    priority: None,
                    is_in_early_data: IsInEarlyData::new(false),
                }
            },
            _ => Self::Core(ev),
        }
    }
}

/// Commands accepted by [ServerH3Driver].
#[derive(Debug)]
pub enum ServerH3Command {
    Core(H3Command),
}

impl From<H3Command> for ServerH3Command {
    fn from(cmd: H3Command) -> Self {
        Self::Core(cmd)
    }
}

impl From<QuicCommand> for ServerH3Command {
    fn from(cmd: QuicCommand) -> Self {
        Self::Core(H3Command::QuicCmd(cmd))
    }
}

// Quiche urgency is an 8-bit space. Internally, quiche reserves 0 for HTTP/3
// control streams and request are shifted up by 124. Any value in that range is
// suitable here.
const PRE_HEADERS_BOOSTED_PRIORITY_URGENCY: u8 = 64;
// Non-incremental streams are served in stream ID order, matching the client
// FIFO expectation.
const PRE_HEADERS_BOOSTED_PRIORITY_INCREMENTAL: bool = false;

pub struct ServerHooks {
    /// Helper to enforce limits and timeouts on an HTTP/3 connection.
    settings_enforcer: Http3SettingsEnforcer,
    /// Tracks the number of requests that have been handled by this driver.
    requests: u64,

    /// Handle to the post-accept timeout entry. If present, the server must
    /// receive a HEADERS frame before this timeout.
    post_accept_timeout: Option<TimeoutKey>,
    /// Handles to the client header timeout entries of the request streams
    /// whose headers haven't been received yet, keyed by stream ID.
    client_header_timeouts: HashMap<u64, TimeoutKey>,
    /// Value of `peer_opened_streams_bidi()` when client header timeouts were
    /// last started, i.e. the number of request streams that already have one.
    peer_opened_streams_seen: u64,
    /// Number of request streams abandoned due to the client header timeout.
    client_header_timeout_count: u64,
    /// Whether the extended CONNECT protocol is enabled. When disabled,
    /// skip DATAGRAM flow creation for `:protocol` requests.
    extended_connect_enabled: bool,
}

#[cfg(test)]
impl ServerHooks {
    /// Returns the number of client header timeouts still pending.
    pub(super) fn pending_client_header_timeouts(&self) -> usize {
        self.client_header_timeouts.len()
    }

    /// Returns the number of request streams abandoned due to the client
    /// header timeout.
    pub(super) fn client_header_timeout_count(&self) -> u64 {
        self.client_header_timeout_count
    }
}

impl ServerHooks {
    /// Starts the client header timeout for the request streams that the
    /// client opened since the last call, including the implicitly opened
    /// ones.
    fn start_client_header_timeouts(&mut self, qconn: &QuicheConnection) {
        let Some(timeout) = self.settings_enforcer.client_header_timeout() else {
            return;
        };

        let opened = qconn.peer_opened_streams_bidi();

        while self.peer_opened_streams_seen < opened {
            // Client-initiated bidirectional streams are opened in order, so
            // the n-th one has ID n * 4.
            let stream_id = self.peer_opened_streams_seen << 2;

            let key = self
                .settings_enforcer
                .add_timeout(Http3TimeoutType::ClientHeader(stream_id), timeout);
            self.client_header_timeouts.insert(stream_id, key);

            self.peer_opened_streams_seen += 1;
        }
    }

    /// Abandons a request stream whose headers weren't received in time,
    /// and closes the connection if it caused too many of these timeouts.
    fn client_header_timed_out(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) {
        // The entry expired, so there's nothing left to cancel.
        self.client_header_timeouts.remove(&stream_id);

        // This is also true for streams that were only opened implicitly,
        // since quiche has no state for them yet.
        let finished = qconn.stream_finished(stream_id);

        let err = quiche::h3::WireErrorCode::RequestRejected as u64;

        let shut_down = H3Driver::<Self>::shutdown_quiche_stream(
            qconn,
            stream_id,
            StreamShutdown::Both {
                read_error_code: err,
                write_error_code: err,
            },
        );

        // Don't count streams that the client already finished or reset.
        // Streams that quiche has no state for were only opened implicitly and
        // never received any data, so they're counted.
        if shut_down && finished {
            return;
        }

        log::debug!("request headers not received in time"; "scid" => ?qconn.source_id(), "stream_id" => stream_id);

        self.client_header_timeout_count += 1;

        if self.settings_enforcer.enforce_client_header_timeouts_limit(
            self.client_header_timeout_count,
        ) {
            log::debug!("closing connection due to too many client header timeouts"; "scid" => ?qconn.source_id());

            let _ = qconn.close(
                true,
                quiche::h3::WireErrorCode::ExcessiveLoad as u64,
                b"too many client header timeouts",
            );
        }
    }

    /// Handles a new request, creating a stream context, checking for a
    /// potential DATAGRAM flow (CONNECT-{UDP,IP}) and sending a relevant
    /// [`H3Event`] to the [ServerH3Controller] for application-level
    /// processing.
    fn handle_request(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        headers: InboundHeaders,
    ) -> H3ConnectionResult<()> {
        let InboundHeaders {
            stream_id,
            headers,
            has_body,
        } = headers;

        // Multiple HEADERS frames can be received on a single stream, but only
        // the first one is an actual request. For now ignore any additional
        // HEADERS (e.g. "trailers").
        if driver.stream_map.contains_key(&stream_id) {
            return Ok(());
        }

        let (mut stream_ctx, send, recv) =
            StreamCtx::new(stream_id, STREAM_CAPACITY);

        // When Extended CONNECT is enabled, extract the datagram flow ID
        // from the request headers and register it in flow_map. This
        // allows incoming DATAGRAMs to be routed to the correct stream.
        // Note: flow_map entries are considered active work, so the
        // connection will not be closed in cleanup_stream() while
        // flows remain.
        if driver.hooks.extended_connect_enabled() {
            if let Some(flow_id) =
                datagram::extract_quarter_stream_id(stream_id, &headers)
            {
                let _ = driver.get_or_insert_flow(flow_id)?;
                stream_ctx.associated_dgram_flow_id = Some(flow_id);
            }
        }

        let latest_priority_update: Option<RawPriorityValue> = driver
            .conn_mut()?
            .take_last_priority_update(stream_id)
            .ok()
            .map(|v| v.into());

        // Boost the priority of the stream until we write response headers via
        // process_write_frame(), which will set the desired priority. Since it
        // will get set later, just swallow any error here.
        qconn
            .stream_priority(
                stream_id,
                PRE_HEADERS_BOOSTED_PRIORITY_URGENCY,
                PRE_HEADERS_BOOSTED_PRIORITY_INCREMENTAL,
            )
            .ok();

        let headers = IncomingH3Headers {
            stream_id,
            headers,
            send,
            recv,
            read_fin: !has_body,
            h3_audit_stats: Arc::clone(&stream_ctx.audit_stats),
        };

        driver
            .waiting_streams
            .push(stream_ctx.wait_for_recv(stream_id));
        driver.insert_stream(stream_id, stream_ctx);

        driver
            .h3_event_sender
            .send(ServerH3Event::Headers {
                incoming_headers: headers,
                priority: latest_priority_update,
                is_in_early_data: IsInEarlyData::new(qconn.is_in_early_data()),
            })
            .map_err(|_| H3ConnectionError::ControllerWentAway)?;
        driver.hooks.requests += 1;

        Ok(())
    }
}

#[allow(private_interfaces)]
impl DriverHooks for ServerHooks {
    type Command = ServerH3Command;
    type Event = ServerH3Event;

    fn new(settings: &Http3Settings) -> Self {
        Self {
            settings_enforcer: settings.into(),
            requests: 0,
            post_accept_timeout: None,
            client_header_timeouts: HashMap::new(),
            peer_opened_streams_seen: 0,
            client_header_timeout_count: 0,
            extended_connect_enabled: settings.enable_extended_connect,
        }
    }

    fn extended_connect_enabled(&self) -> bool {
        self.extended_connect_enabled
    }

    fn conn_established(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        handshake_info: &HandshakeInfo,
    ) -> H3ConnectionResult<()> {
        assert!(
            qconn.is_server(),
            "ServerH3Driver requires a server-side QUIC connection"
        );

        if let Some(post_accept_timeout) =
            driver.hooks.settings_enforcer.post_accept_timeout()
        {
            let remaining = post_accept_timeout
                .checked_sub(handshake_info.elapsed())
                .ok_or(H3ConnectionError::PostAcceptTimeout)?;

            let key = driver
                .hooks
                .settings_enforcer
                .add_timeout(Http3TimeoutType::PostAccept, remaining);
            driver.hooks.post_accept_timeout = Some(key);
        }

        Ok(())
    }

    fn headers_received(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        headers: InboundHeaders,
    ) -> H3ConnectionResult<()> {
        if let Some(timeout) = driver
            .hooks
            .client_header_timeouts
            .remove(&headers.stream_id)
        {
            // The request headers were received in time.
            driver.hooks.settings_enforcer.cancel_timeout(timeout);
        }

        if driver
            .hooks
            .settings_enforcer
            .enforce_requests_limit(driver.hooks.requests)
        {
            let _ =
                qconn.close(true, quiche::h3::WireErrorCode::NoError as u64, &[]);
            return Ok(());
        }

        if let Some(timeout) = driver.hooks.post_accept_timeout.take() {
            // We've seen the first Headers event for the connection,
            // so we can abort the post-accept timeout
            driver.hooks.settings_enforcer.cancel_timeout(timeout);
        }

        Self::handle_request(driver, qconn, headers)
    }

    fn conn_command(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        cmd: Self::Command,
    ) -> H3ConnectionResult<()> {
        let ServerH3Command::Core(cmd) = cmd;
        driver.handle_core_command(qconn, cmd)
    }

    fn has_wait_action(driver: &mut H3Driver<Self>) -> bool {
        driver.hooks.settings_enforcer.has_pending_timeouts()
    }

    async fn wait_for_action(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        let expired = self.settings_enforcer.enforce_timeouts(qconn).await?;

        for stream_id in expired {
            // The connection might have been closed by a previous timeout.
            if qconn.local_error().is_some() {
                break;
            }

            self.client_header_timed_out(qconn, stream_id);
        }

        Ok(())
    }

    fn before_process_reads(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        driver.hooks.start_client_header_timeouts(qconn);
        Ok(())
    }

    fn conn_closed<M: Metrics>(driver: &H3Driver<Self>, metrics: &M) {
        let count = driver.hooks.client_header_timeout_count;

        if count > 0 {
            metrics.client_header_timeouts().inc_by(count);
        }
    }
}
