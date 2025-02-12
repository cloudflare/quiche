use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use datagram_socket::{AsSocketStats, QuicAuditStats, ShutdownConnection, SocketStats};
use quiche::ConnectionId;

use super::{client, server, DriverHooks, H3Controller};
use crate::quic::QuicConnectionStats;
use crate::QuicConnection;

pub type ClientH3Connection = H3Connection<client::ClientHooks>;
pub type ServerH3Connection = H3Connection<server::ServerHooks>;

/// A wrapper for an h3-driven [QuicConnection] together with the driver's [H3Controller].
pub struct H3Connection<H: DriverHooks> {
    pub quic_connection: QuicConnection,
    pub h3_controller: H3Controller<H>,
}

impl<H: DriverHooks> H3Connection<H> {
    /// Bundles `quic_connection` and `h3_controller` into a new [H3Connection].
    pub fn new(quic_connection: QuicConnection, h3_controller: H3Controller<H>) -> Self {
        Self {
            quic_connection,
            h3_controller,
        }
    }

    /// The local address this connection listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.quic_connection.local_addr()
    }

    /// The remote address for this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.quic_connection.peer_addr()
    }

    /// The [QuicConnection]'s audit stats.
    pub fn audit_log_stats(&self) -> &Arc<QuicAuditStats> {
        self.quic_connection.audit_log_stats()
    }

    /// The [QuicConnection]'s [`quiche`] stats.
    pub fn stats(&self) -> &Arc<Mutex<QuicConnectionStats>> {
        self.quic_connection.stats()
    }

    /// The [QuicConnection]'s source connection ID.
    pub fn scid(&self) -> &ConnectionId<'static> {
        self.quic_connection.scid()
    }
}

impl<H: DriverHooks> ShutdownConnection for H3Connection<H> {
    #[inline]
    fn poll_shutdown(&mut self, _cx: &mut std::task::Context) -> Poll<std::io::Result<()>> {
        // TODO: does nothing at the moment
        Poll::Ready(Ok(()))
    }
}

impl<H: DriverHooks> AsSocketStats for H3Connection<H> {
    #[inline]
    fn as_socket_stats(&self) -> SocketStats {
        self.quic_connection.as_socket_stats()
    }

    #[inline]
    fn as_quic_stats(&self) -> Option<&Arc<QuicAuditStats>> {
        self.quic_connection.as_quic_stats()
    }
}
