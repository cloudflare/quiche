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

//! Helper to wrap existing [quiche::Connection]s.
//!
//! This is a low-level interface for users who either need to heavily customize
//! the [`quiche::Connection`] beyond what is possible via the crate's
//! [`settings`](crate::settings), or need more control over how to pass data
//! into the connection.
//!
//! Most use cases are much better served by our
//! [`connect`](crate::quic::connect) (for clients) or [`listen`](crate::listen)
//! (for servers) API.

use datagram_socket::DatagramSocketSend;
use std::sync::Arc;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;
use tokio::sync::mpsc;

use super::connection::InitialQuicConnection;
use super::connection::QuicConnectionParams;
use super::io::worker::WriterConfig;
use super::router::ConnectionMapCommand;
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::Incoming;
use crate::quic::QuicheConnection;
use crate::socket::Socket;

/// Result of manually wrapping a [`quiche::Connection`] in an
/// [`InitialQuicConnection`].
///
/// This struct bundles the interfaces which interact with the connection.
pub struct ConnWrapperResult<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    /// The connection wrapper.
    pub conn: InitialQuicConnection<Tx, M>,
    /// Sender for inbound packets on the connection.
    pub incoming_tx: mpsc::Sender<Incoming>,
    /// Receiver for `connection closed` notifications. This fires
    /// after a `CONNECTION_CLOSE` frame has been sent on the connection,
    /// but before `worker_shutdown_rx`.
    pub conn_close_rx: ConnCloseReceiver,
    /// Receiver which fires only when its associated sender is dropped.
    /// This happens when the connection's IO task exits.
    pub worker_shutdown_rx: mpsc::Receiver<()>,
}

/// Wraps an existing [`quiche::Connection`] in an [`InitialQuicConnection`],
/// bypassing the regular packet router workflow.
///
/// Connections wrapped in this way require the user to manually pass inbound
/// packets via the channel returned in [`ConnWrapperResult`]. The passed
/// `tx_socket` is only used to _send_ outbound packets and to extract the
/// endpoint's addresses.
///
/// # Note
/// This function does not attempt any I/O when wrapping the
/// [`quiche::Connection`]. To start handshaking and consuming packets from the
/// returned channel, use the methods on [`InitialQuicConnection`].
pub fn wrap_quiche_conn<Tx, R, M>(
    quiche_conn: QuicheConnection, tx_socket: Socket<Arc<Tx>, R>, metrics: M,
) -> ConnWrapperResult<Tx, M>
where
    Tx: DatagramSocketSend + Send + 'static + ?Sized,
    M: Metrics,
{
    let Socket {
        send: socket,
        local_addr,
        peer_addr,
        ..
    } = tx_socket;
    let (shutdown_tx, worker_shutdown_rx) = mpsc::channel(1);
    let (conn_map_cmd_tx, conn_map_rx) = mpsc::unbounded_channel();

    let scid = quiche_conn.source_id().into_owned();

    let writer_cfg = WriterConfig {
        pending_cid: None, // only used for unmapping in IPR
        peer_addr,
        local_addr,
        // TODO: try to read Tx' SocketCaps. false is always a safe default.
        with_gso: false,
        pacing_offload: false,
        with_pktinfo: false,
    };

    let conn_params = QuicConnectionParams {
        writer_cfg,
        initial_pkt: None,
        shutdown_tx,
        conn_map_cmd_tx,
        scid,
        metrics,
        #[cfg(feature = "perf-quic-listener-metrics")]
        init_rx_time: None,
        handshake_info: HandshakeInfo::new(Instant::now(), None),
        quiche_conn,
        socket,
        local_addr,
        peer_addr,
    };

    let conn = InitialQuicConnection::new(conn_params);
    let incoming_tx = conn.incoming_ev_sender.clone();

    ConnWrapperResult {
        conn,
        incoming_tx,
        conn_close_rx: ConnCloseReceiver(conn_map_rx),
        worker_shutdown_rx,
    }
}

/// Pollable receiver for `connection closed` notifications from a QUIC
/// connection.
///
/// This receiver also fires if the corresponding sender has been dropped
/// without a `CONNECTION_CLOSE` frame on the connection.
pub struct ConnCloseReceiver(mpsc::UnboundedReceiver<ConnectionMapCommand>);

impl ConnCloseReceiver {
    /// Polls to receive a `connection closed` notification.
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<()> {
        loop {
            let cmd = ready!(self.0.poll_recv(cx));
            if matches!(cmd, None | Some(ConnectionMapCommand::RemoveScid(_))) {
                return Poll::Ready(());
            }
        }
    }

    /// Waits for a `connection closed` notification.
    pub async fn recv(&mut self) {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}
