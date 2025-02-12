use super::{Incoming, InitialQuicConnection};
use crate::metrics::Metrics;

use datagram_socket::DatagramSocketSend;
use quiche::{ConnectionId, MAX_CONN_ID_LEN};
use std::collections::{BTreeMap, HashMap};
use tokio::sync::mpsc;

const U64_SZ: usize = std::mem::size_of::<u64>();
const MAX_CONN_ID_QUADS: usize = MAX_CONN_ID_LEN.div_ceil(U64_SZ);
const CONN_ID_USABLE_LEN: usize = min_usize(
    // Last byte in CidOwned::Optimized stores CID length
    MAX_CONN_ID_QUADS * U64_SZ - 1,
    // CID length must fit in 1 byte
    min_usize(MAX_CONN_ID_LEN, u8::MAX as _),
);

const fn min_usize(v1: usize, v2: usize) -> usize {
    if v1 < v2 {
        v1
    } else {
        v2
    }
}

/// A non unique connection identifier, multiple Cids can map to the same conenction.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum CidOwned {
    /// The QUIC connections IDs theoretically have unbounded length, so for the generic case
    /// a boxed slice is used to store the ID.
    Generic(Box<[u8]>),
    /// For QUIC version 1 (the one that actually exists) the maximal ID size is `20`, which
    /// should correspond to the `MAX_CONN_ID_LEN` value. For this common case, we store the
    /// ID in a u64 array for faster comparison (and therefore BTreeMap lookups).
    Optimized([u64; MAX_CONN_ID_QUADS]),
}

impl From<&ConnectionId<'_>> for CidOwned {
    #[inline(always)]
    fn from(value: &ConnectionId<'_>) -> Self {
        if value.len() > CONN_ID_USABLE_LEN {
            return CidOwned::Generic(value.as_ref().into());
        }

        let mut cid = [0; MAX_CONN_ID_QUADS];

        value
            .chunks(U64_SZ)
            .map(|c| match c.try_into() {
                Ok(v) => u64::from_le_bytes(v),
                Err(_) => {
                    let mut remainder = [0u8; U64_SZ];
                    remainder[..c.len()].copy_from_slice(c);
                    u64::from_le_bytes(remainder)
                }
            })
            .enumerate()
            .for_each(|(i, v)| cid[i] = v);

        // In order to differentiate cids with zeroes as opposed to shorter cids,
        // append the cid length.
        *cid.last_mut().unwrap() |= (value.len() as u64) << 56;

        CidOwned::Optimized(cid)
    }
}

/// A unique idetifier quiche assigns to a connection.
type QuicheId = u64;

/// A map for QUIC connections.
///
/// Due to the fact that QUIC connections can be identified by multiple QUIC
/// connection IDs, we have to be able to map multiple IDs to the same connection.
///
#[derive(Default)]
pub(crate) struct ConnectionMap {
    quic_id_map: BTreeMap<CidOwned, (QuicheId, mpsc::Sender<Incoming>)>,
    conn_map: HashMap<QuicheId, mpsc::Sender<Incoming>>,
}

impl ConnectionMap {
    pub(crate) fn insert<Tx, M>(
        &mut self,
        cid: ConnectionId<'_>,
        conn: &InitialQuicConnection<Tx, M>,
    ) where
        Tx: DatagramSocketSend + Send + 'static,
        M: Metrics,
    {
        let id = conn.id;
        let ev_sender = conn.incoming_ev_sender.clone();

        self.conn_map.insert(id, ev_sender.clone());
        self.quic_id_map.insert((&cid).into(), (id, ev_sender));
    }

    pub(crate) fn remove(&mut self, cid: &ConnectionId<'_>) {
        if let Some((id, _)) = self.quic_id_map.remove(&cid.into()) {
            self.conn_map.remove(&id);
        }
    }

    pub(crate) fn map_cid<Tx, M>(
        &mut self,
        cid: ConnectionId<'_>,
        conn: &InitialQuicConnection<Tx, M>,
    ) where
        Tx: DatagramSocketSend + Send + 'static,
        M: Metrics,
    {
        let id = conn.id;

        if let Some(ev_sender) = self.conn_map.get(&id) {
            self.quic_id_map
                .insert((&cid).into(), (id, ev_sender.clone()));
        }
    }

    pub(crate) fn unmap_cid(&mut self, cid: &ConnectionId<'_>) {
        self.quic_id_map.remove(&cid.into());
    }

    pub(crate) fn get(&self, id: &ConnectionId) -> Option<&mpsc::Sender<Incoming>> {
        if id.len() == MAX_CONN_ID_LEN {
            // Although both branches run the same code, the one here will generate an optimized version
            // for the length we are using, as opposed to temporary cids sent by clients.
            self.quic_id_map.get(&id.into()).map(|(_id, sender)| sender)
        } else {
            self.quic_id_map.get(&id.into()).map(|(_id, sender)| sender)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::ConnectionId;

    #[test]
    fn cid_storage() {
        let max_v1_cid = ConnectionId::from_ref(&[0xfa; MAX_CONN_ID_LEN]);
        let optimized = CidOwned::from(&max_v1_cid);
        assert!(
            matches!(optimized, CidOwned::Optimized(_)),
            "QUIC v1 CID is not stored inline"
        );

        let oversize_cid = ConnectionId::from_ref(&[0x1b; MAX_CONN_ID_LEN + 20]);
        let boxed = CidOwned::from(&oversize_cid);
        assert!(
            matches!(boxed, CidOwned::Generic(_)),
            "Oversized CID is not boxed"
        );
    }
}
