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

use quiche::h3;
use std::future::Future;

use super::H3Command;
use super::H3ConnectionResult;
use super::H3Driver;
use super::H3Event;
use crate::http3::settings::Http3Settings;
use crate::quic::HandshakeInfo;
use crate::quic::QuicheConnection;

/// A HEADERS frame received from the [`h3::Connection`], to be processed by
/// the [DriverHooks].
pub(crate) struct InboundHeaders {
    pub(crate) stream_id: u64,
    pub(crate) headers: Vec<h3::Header>,
    pub(crate) has_body: bool,
}

/// Private trait to customize [H3Driver] for server or client operations.
///
/// Wherever endpoint-specific logic is required, a hook should be created in
/// this trait and this hook then called in the appropriate [H3Driver] code.
/// The hook can store its own data inside the [H3Driver] struct.
#[allow(private_interfaces, unused)]
pub trait DriverHooks: Sized + Send + 'static {
    /// The type of [`H3Event`]s emitted by an [H3Driver] using these hooks.
    /// The concrete type is expected to wrap [`H3Event`].
    type Event: From<H3Event> + Send;
    /// The type of [`H3Command`]s accepted by an [H3Driver] using these hooks.
    /// The concrete type is expected to wrap [`H3Command`].
    type Command: From<H3Command> + Send;

    /// Initializes the storage for these hooks.
    fn new(settings: &Http3Settings) -> Self;

    /// Called in `ApplicationOverQuic::on_conn_established` after [H3Driver]
    /// has been initialized. Used to verify connection settings and set up
    /// post-accept state like timeouts.
    fn conn_established(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        handshake_info: &HandshakeInfo,
    ) -> H3ConnectionResult<()>;

    /// Processes any received [`h3::Event::Headers`]. There is no default
    /// processing of HEADERS frames in [H3Driver].
    fn headers_received(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        headers: InboundHeaders,
    ) -> H3ConnectionResult<()>;

    /// Processes any command received from the
    /// [`H3Controller`](super::H3Controller). May use
    /// `H3Driver::handle_core_command` to handle regular [`H3Command`]s.
    fn conn_command(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        cmd: Self::Command,
    ) -> H3ConnectionResult<()>;

    /// Determines whether the hook's `wait_for_action` future will be polled
    /// as part of `ApplicationOverQuic::wait_for_data`. Defaults to `false` and
    /// must be overridden if `wait_for_action` is overridden.
    fn has_wait_action(driver: &mut H3Driver<Self>) -> bool {
        false
    }

    /// Returns a future that will be polled in
    /// `ApplicationOverQuic::wait_for_data`, along with the other input
    /// sources for the [H3Driver]. Note that the future will be dropped
    /// before it resolves if another input is available first.
    fn wait_for_action(
        &mut self, qconn: &mut QuicheConnection,
    ) -> impl Future<Output = H3ConnectionResult<()>> + Send {
        std::future::pending()
    }
}
