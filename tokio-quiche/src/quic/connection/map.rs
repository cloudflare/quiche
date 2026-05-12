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

use super::Incoming;
use super::InitialQuicConnection;
use crate::metrics::Metrics;

use datagram_socket::DatagramSocketSend;
use quiche::ConnectionId;
use quiche::MAX_CONN_ID_LEN;
use std::collections::BTreeMap;
use tokio::sync::mpsc;

/// Newtype wrapper for `ConnectionId<'static>` to allow `Borrow` with a
/// different lifetime. This impl would conflict with `impl<T> Borrow<T> for T`
/// directly on `ConnectionId`.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct CidOwned(ConnectionId<'static>);

impl<'a> std::borrow::Borrow<ConnectionId<'a>> for CidOwned {
    fn borrow(&self) -> &ConnectionId<'a> {
        &self.0
    }
}

/// A map for QUIC connections.
///
/// Due to the fact that QUIC connections can be identified by multiple QUIC
/// connection IDs, we have to be able to map multiple IDs to the same
/// connection.
#[derive(Default)]
pub(crate) struct ConnectionMap {
    quic_id_map: BTreeMap<CidOwned, mpsc::Sender<Incoming>>,
}

impl ConnectionMap {
    pub(crate) fn insert<Tx, M>(
        &mut self, cid: ConnectionId<'static>,
        conn: &InitialQuicConnection<Tx, M>,
    ) where
        Tx: DatagramSocketSend + Send + 'static,
        M: Metrics,
    {
        let ev_sender = conn.incoming_ev_sender.clone();
        self.quic_id_map.insert(CidOwned(cid), ev_sender);
    }

    pub(crate) fn map_cid(
        &mut self, existing_cid: &ConnectionId, new_cid: ConnectionId<'static>,
    ) {
        if let Some(ev_sender) = self.quic_id_map.get(existing_cid) {
            self.quic_id_map
                .insert(CidOwned(new_cid), ev_sender.clone());
        }
    }

    pub(crate) fn unmap_cid(&mut self, cid: &ConnectionId) {
        self.quic_id_map.remove(cid);
    }

    pub(crate) fn get(
        &self, id: &ConnectionId,
    ) -> Option<&mpsc::Sender<Incoming>> {
        if id.len() == MAX_CONN_ID_LEN {
            // Although both branches run the same code, the one here will
            // generate an optimized version for the length we are
            // using, as opposed to temporary cids sent by clients.
            self.quic_id_map.get(id)
        } else {
            self.quic_id_map.get(id)
        }
    }
}
