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
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use datagram_socket::DgramBuffer;
use hashlink::LinkedHashMap;
use quiche::h3::NameValue;
use quiche::h3::{
    self,
};

use super::streams::FlowCtx;
use super::DgramFlowId;
use super::InboundFrame;
use crate::buf_factory::BufFactory;
use crate::quic::QuicheConnection;

/// Maximum number of datagrams that may be held in the server's pending
/// buffer across all flows while awaiting the corresponding CONNECT request.
/// Once this limit is reached the oldest entry is dropped to make room.
pub(crate) const PENDING_DGRAM_CAPACITY: usize = 2048;

/// How long a datagram may sit in the pending buffer before it is discarded.
/// RFC 9297 §2.1 permits buffering "on the order of a round trip". This doesn't
/// need to be precise, just something to avoid buffering forever.
/// We pick 333ms since it happens to be QUIC's initial RTT :-)
pub(crate) const PENDING_DGRAM_TIMEOUT: Duration = Duration::from_millis(333);

/// Extracts the DATAGRAM flow ID or quarter stream id proxied over the given
/// `stream_id`, or `None` if this is not a proxy request.
pub(crate) fn extract_quarter_stream_id(
    stream_id: u64, headers: &[h3::Header],
) -> Option<DgramFlowId> {
    let mut method = None;
    let mut datagram_flow_id: Option<u64> = None;
    let mut protocol = None;

    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            b"datagram-flow-id" =>
                datagram_flow_id = std::str::from_utf8(header.value())
                    .ok()
                    .and_then(|v| v.parse().ok()),
            _ => {},
        };

        // We have all of the information needed to get a flow_id or
        // quarter_stream_id
        if method.is_some() && (datagram_flow_id.is_some() || protocol.is_some())
        {
            break;
        }
    }

    // Legacy: draft-ietf-masque-connect-udp-03 CONNECT-UDP
    // This draft is obsolete and has been replaced by quarter-stream-id, but
    // we still need to support it.
    if method == Some(b"CONNECT-UDP") && datagram_flow_id.is_some() {
        datagram_flow_id.and_then(DgramFlowId::new)
    // RFC 9298 CONNECT-UDP
    } else if method == Some(b"CONNECT") && protocol.is_some() {
        // we use the quarter_stream_id for RFC 9297
        // https://www.rfc-editor.org/rfc/rfc9297.html#name-http-3-datagrams
        DgramFlowId::new(stream_id / 4)
    } else {
        None
    }
}

/// Sends an HTTP/3 datagram over the QUIC connection with the given
/// `quarter_stream_id`.
#[inline]
pub(crate) fn send_h3_dgram(
    conn: &mut QuicheConnection, quarter_stream_id: DgramFlowId,
    dgram: DgramBuffer,
) -> quiche::Result<()> {
    conn.dgram_send_buf(h3_dgram_add_quarter_stream_id(
        quarter_stream_id.id(),
        dgram,
    )?)
}

/// Prepend the `quarter_stream_id` to `dgram`
fn h3_dgram_add_quarter_stream_id(
    quarter_stream_id: u64, mut dgram: DgramBuffer,
) -> quiche::Result<DgramBuffer> {
    let mut prefix_buf = [0u8; 8];
    let mut enc = octets::OctetsMut::with_slice(&mut prefix_buf);
    let prefix = enc.put_varint(quarter_stream_id)?;

    if dgram.try_add_prefix(prefix).is_err() {
        // There wasn't enough room. Let's add more headroom and add the
        // prefix again. DGRAM_HEADROOM is large enough, so
        // try_add_prefix cannot fail after splice_headroom.
        const {
            // Note, since this is const, it asserts at compile time.
            assert!(BufFactory::DGRAM_HEADROOM >= /* max varint len */ 8);
        }
        dgram.splice_headroom(BufFactory::DGRAM_HEADROOM);
        dgram.try_add_prefix(prefix).unwrap();
    }
    Ok(dgram)
}

/// Strips the varint-encoded quarter stream ID from the front of `dgram` and
/// returns `(quarter_stream_id, dgram)` with the cursor advanced past the
/// prefix.
fn h3_dgram_remove_quarter_stream_id(
    mut dgram: DgramBuffer,
) -> quiche::Result<(u64, DgramBuffer)> {
    let mut b = octets::Octets::with_slice(dgram.as_slice());
    let quarter_stream_id = b.get_varint()?;
    // Advance the cursor past the varint prefix — zero copy.
    let advance = b.off();
    dgram.advance(advance);
    Ok((quarter_stream_id, dgram))
}

/// Reads the next HTTP/3 datagram from the QUIC connection.
///
/// [`quiche::Error::Done`] is returned if there is no datagram to read.
#[inline]
pub(crate) fn receive_h3_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, InboundFrame)> {
    let dgram = conn.dgram_recv_buf()?;
    let (quarter_stream_id, dgram) = h3_dgram_remove_quarter_stream_id(dgram)?;
    Ok((quarter_stream_id, InboundFrame::Datagram(dgram)))
}

/// A single datagram pending delivery to a flow that has not yet been
/// established. Used on the server to handle datagrams that arrive before
/// the corresponding CONNECT request.
pub(crate) struct PendingDgram {
    /// The RFC 9297 Quarter Stream ID or legacy datagram-flow-id for this
    /// flow.
    pub(crate) flow_id: DgramFlowId,
    /// The datagram payload.
    dgram: InboundFrame,
    /// Absolute deadline after which this datagram should be dropped.
    expires_at: Instant,
}

/// Unique, opaque identifier for stored pending datagrams in
/// [`PendingDgramBuffer`]. We simply increment the id
/// for each datagram.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingDgramId(u64);

/// Bounded buffer of datagrams received before their corresponding CONNECT
/// request has been processed. Entries expire after
/// [`PENDING_DGRAM_TIMEOUT`] and the total count is capped at
/// [`PENDING_DGRAM_CAPACITY`].
///
/// The cleanup / expiration is performed opportunistically. We don't set
/// or await the timeout.
pub(crate) struct PendingDgramBuffer {
    /// Pending datagrams in global arrival order.
    dgrams: LinkedHashMap<PendingDgramId, PendingDgram>,
    /// Per-flow indexes that map a flow_id to entries in `dgrams`.
    by_flow_idx: HashMap<DgramFlowId, VecDeque<PendingDgramId>>,
    /// Monotonic ID source for pending datagram keys.
    next_id: u64,
}

impl PendingDgramBuffer {
    /// Creates an empty buffer.
    pub(crate) fn new() -> Self {
        Self {
            dgrams: LinkedHashMap::new(),
            by_flow_idx: HashMap::new(),
            next_id: 0,
        }
    }

    /// Returns the number of buffered datagrams. Test-only.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.dgrams.len()
    }

    /// Drain expired entries from the front of the buffer.
    pub(crate) fn expire(&mut self) {
        let now = Instant::now();
        while let Some((&id, pending)) = self.dgrams.front() {
            if pending.expires_at > now {
                break;
            }

            let (_, pending) = self
                .dgrams
                .pop_front()
                .expect("front() returned Some so pop_front must succeed");
            self.remove_from_flow_index(pending.flow_id, id);
        }
    }

    /// Buffer a datagram for `flow_id`. Expired entries are drained first;
    /// if the buffer is still at capacity the oldest entry is dropped.
    pub(crate) fn push(&mut self, flow_id: DgramFlowId, dgram: InboundFrame) {
        self.expire();
        if self.dgrams.len() >= PENDING_DGRAM_CAPACITY {
            // This debug_assert is not possible in the current but we have
            // it here as a defensive measure. It being a no-op in prod is
            // fine in any case.
            debug_assert_eq!(self.dgrams.len(), PENDING_DGRAM_CAPACITY);
            self.pop_oldest();
        }

        let id = PendingDgramId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);

        self.dgrams.insert(id, PendingDgram {
            flow_id,
            dgram,
            expires_at: Instant::now() + PENDING_DGRAM_TIMEOUT,
        });
        self.by_flow_idx.entry(flow_id).or_default().push_back(id);
    }

    /// Flush non-expired pending datagrams for `flow_id` into `flow_ctx`,
    /// removing them from the buffer. Expired entries for this flow are
    /// silently discarded.
    pub(crate) fn flush_to_flow(
        &mut self, flow_id: DgramFlowId, flow_ctx: &FlowCtx,
    ) {
        let now = Instant::now();
        let Some(ids) = self.by_flow_idx.remove(&flow_id) else {
            return;
        };

        for id in ids {
            let Some(pending) = self.dgrams.remove(&id) else {
                continue;
            };

            if pending.expires_at > now {
                flow_ctx.send_best_effort(pending.dgram);
            }
        }
    }

    /// Drop the oldest pending datagram and remove its flow index entry.
    fn pop_oldest(&mut self) {
        if let Some((id, pending)) = self.dgrams.pop_front() {
            self.remove_from_flow_index(pending.flow_id, id);
        }
    }

    /// Remove a pending datagram ID from its per-flow index.
    fn remove_from_flow_index(
        &mut self, flow_id: DgramFlowId, id: PendingDgramId,
    ) {
        let Some(ids) = self.by_flow_idx.get_mut(&flow_id) else {
            return;
        };

        debug_assert_eq!(ids.front(), Some(&id));

        if ids.front() == Some(&id) {
            ids.pop_front();
        } else if let Some(pos) =
            ids.iter().position(|candidate| *candidate == id)
        {
            ids.remove(pos);
        }

        if ids.is_empty() {
            self.by_flow_idx.remove(&flow_id);
        }
    }

    /// Returns the flow ID of the oldest buffered datagram. Test-only.
    #[cfg(test)]
    pub(crate) fn oldest_flow_id(&self) -> Option<DgramFlowId> {
        self.dgrams.front().map(|(_, pending)| pending.flow_id)
    }

    /// Returns the flow ID of the newest buffered datagram. Test-only.
    #[cfg(test)]
    pub(crate) fn newest_flow_id(&self) -> Option<DgramFlowId> {
        self.dgrams.back().map(|(_, pending)| pending.flow_id)
    }

    /// Push a datagram with a custom deadline. Test-only; bypasses
    /// expiry and capacity enforcement.
    #[cfg(test)]
    pub(crate) fn push_with_deadline(
        &mut self, flow_id: DgramFlowId, dgram: InboundFrame, expires_at: Instant,
    ) {
        let id = PendingDgramId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);

        self.dgrams.insert(id, PendingDgram {
            flow_id,
            dgram,
            expires_at,
        });
        self.by_flow_idx.entry(flow_id).or_default().push_back(id);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use datagram_socket::DgramBuffer;

    use super::*;

    #[test]
    fn h3_dgram_add_quarter_stream_id_enough_headroom() {
        let mut dgram = DgramBuffer::with_capacity_and_headroom(16, 8);
        dgram.put_slice(&[0xaa, 0xbb, 0xcc]);

        // 67 requires two bytes to encode
        let result = h3_dgram_add_quarter_stream_id(67, dgram).unwrap();
        assert_eq!(result.as_slice(), &[64, 67, 0xaa, 0xbb, 0xcc]);
    }

    /// When there is no headroom, splice_headroom is invoked automatically.
    #[test]
    fn h3_dgram_add_quarter_stream_id_need_more_headroom() {
        let dgram = DgramBuffer::from_slice(&[1, 2]);

        // 42 requires a single byte for encoding
        let result = h3_dgram_add_quarter_stream_id(42, dgram).unwrap();
        assert_eq!(result.as_slice(), &[42, 1, 2]);
    }

    #[test]
    fn h3_dgram_remove_quarter_stream_id_tests() {
        let dgram = DgramBuffer::from_slice(&[1, 2, 3, 4]);
        let dgram = h3_dgram_add_quarter_stream_id(67, dgram).unwrap();
        let (quarter_stream_id, rest) =
            h3_dgram_remove_quarter_stream_id(dgram).unwrap();

        assert_eq!(quarter_stream_id, 67);
        assert_eq!(rest.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn h3_dgram_remove_quarter_stream_id_non_minimal_varint() {
        // Quarter Stream ID = 0 encoded NON-minimally as a 2-byte varint (0x40
        // 0x00), followed by application payload [1, 2, 3, 4].
        // RFC 9000 §16 permits non-minimal encodings; quiche's get_varint()
        // accepts them.
        let dgram = DgramBuffer::from_slice(&[0x40, 0x00, 1, 2, 3, 4]);
        let (qsid, rest) = h3_dgram_remove_quarter_stream_id(dgram).unwrap();
        assert_eq!(qsid, 0);

        assert_eq!(
            rest.as_slice(),
            &[1, 2, 3, 4],
            "leftover non-minimal varint byte leaked into payload prefix"
        );
    }

    /// remove_quarter_stream_id on an empty buffer returns an error (buffer too
    /// short).
    #[test]
    fn remove_quarter_stream_id_empty_buffer_errors() {
        let dgram = DgramBuffer::new();
        assert!(h3_dgram_remove_quarter_stream_id(dgram).is_err());
    }

    /// PendingDgramBuffer unit tests
    mod pending_datagram_buffer {

        use super::*;
        use crate::http3::driver::streams::FlowCtx;
        use crate::http3::driver::InboundFrame;
        use tokio::sync::mpsc::error::TryRecvError;

        fn mk_flow_id(id: u64) -> DgramFlowId {
            DgramFlowId::new(id).unwrap()
        }

        fn mk_dgram(payload: &[u8]) -> InboundFrame {
            InboundFrame::Datagram(DgramBuffer::from_slice(payload))
        }

        /// Pushing beyond capacity evicts the oldest entry.
        #[test]
        fn pending_buffer_push_drops_oldest_at_capacity() {
            let mut buf = PendingDgramBuffer::new();
            for i in 0..PENDING_DGRAM_CAPACITY {
                buf.push(mk_flow_id(i as u64), mk_dgram(b"x"));
            }
            assert_eq!(buf.len(), PENDING_DGRAM_CAPACITY);

            // One more triggers eviction of the oldest (flow_id=0).
            buf.push(mk_flow_id(9999), mk_dgram(b"new"));
            assert_eq!(buf.len(), PENDING_DGRAM_CAPACITY);
            assert_eq!(buf.oldest_flow_id().unwrap(), mk_flow_id(1));
            assert_eq!(buf.newest_flow_id().unwrap(), mk_flow_id(9999));
        }

        /// `expire()` removes past-deadline entries from the front.
        #[test]
        fn pending_buffer_expire_drains_stale_front() {
            let mut buf = PendingDgramBuffer::new();
            let past = Instant::now() - Duration::from_millis(1);
            let far = Instant::now() + Duration::from_secs(3600);

            buf.push_with_deadline(mk_flow_id(0), mk_dgram(b"old1"), past);
            buf.push_with_deadline(mk_flow_id(1), mk_dgram(b"old2"), past);
            buf.push_with_deadline(mk_flow_id(2), mk_dgram(b"ok"), far);
            assert_eq!(buf.len(), 3);

            buf.expire();
            assert_eq!(buf.len(), 1);
            assert_eq!(buf.oldest_flow_id().unwrap(), mk_flow_id(2));
        }

        /// `expire()` is a no-op when all entries are still valid.
        #[test]
        fn pending_buffer_expire_noop_when_all_valid() {
            let mut buf = PendingDgramBuffer::new();
            buf.push(mk_flow_id(0), mk_dgram(b"a"));
            buf.push(mk_flow_id(1), mk_dgram(b"b"));
            buf.expire();
            assert_eq!(buf.len(), 2);
        }

        /// `push()` drains all stale entries before the capacity check.
        #[test]
        fn pending_buffer_expires_before_push() {
            let mut buf = PendingDgramBuffer::new();
            let past = Instant::now() - Duration::from_millis(1);
            for i in 0..PENDING_DGRAM_CAPACITY {
                buf.push_with_deadline(
                    mk_flow_id(i as u64),
                    mk_dgram(b"stale"),
                    past,
                );
            }
            assert_eq!(buf.len(), PENDING_DGRAM_CAPACITY);

            // push() calls expire() first — all stale entries are drained
            buf.push(mk_flow_id(42), mk_dgram(b"fresh"));
            assert_eq!(buf.len(), 1);
            assert_eq!(buf.oldest_flow_id().unwrap(), mk_flow_id(42));
        }

        /// `flush_to_flow()` delivers buffered datagrams to the flow channel.
        #[test]
        fn pending_buffer_flush_delivers_to_flow() {
            let mut buf = PendingDgramBuffer::new();
            buf.push(mk_flow_id(0), mk_dgram(b"hello"));
            buf.push(mk_flow_id(0), mk_dgram(b"world"));

            let (flow_ctx, mut recv) = FlowCtx::new(0, 16);
            buf.flush_to_flow(mk_flow_id(0), &flow_ctx);

            assert_eq!(buf.len(), 0);

            let f1 = recv.try_recv().unwrap();
            let f2 = recv.try_recv().unwrap();
            assert_matches::assert_matches!(f1, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"hello");
            });
            assert_matches::assert_matches!(f2, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"world");
            });
            assert_eq!(recv.try_recv().unwrap_err(), TryRecvError::Empty);
        }

        /// `flush_to_flow()` discards expired entries without delivering them.
        #[test]
        fn pending_buffer_flush_skips_expired() {
            let mut buf = PendingDgramBuffer::new();
            let past = Instant::now() - Duration::from_millis(1);
            buf.push_with_deadline(mk_flow_id(0), mk_dgram(b"stale"), past);
            buf.push(mk_flow_id(0), mk_dgram(b"fresh"));

            let (flow_ctx, mut recv) = FlowCtx::new(0, 16);
            buf.flush_to_flow(mk_flow_id(0), &flow_ctx);

            // Both entries removed from buffer.
            assert_eq!(buf.len(), 0);
            // Only the fresh one was delivered.
            let f = recv.try_recv().unwrap();
            assert_matches::assert_matches!(f, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"fresh");
            });
            assert_eq!(recv.try_recv().unwrap_err(), TryRecvError::Empty);
        }

        /// `flush_to_flow()` only removes entries for the targeted flow.
        #[test]
        fn pending_buffer_flush_leaves_other_flows() {
            let mut buf = PendingDgramBuffer::new();
            buf.push(mk_flow_id(0), mk_dgram(b"f0"));
            buf.push(mk_flow_id(1), mk_dgram(b"f1"));
            buf.push(mk_flow_id(0), mk_dgram(b"f0b"));

            let (flow_ctx, mut recv) = FlowCtx::new(0, 16);
            buf.flush_to_flow(mk_flow_id(0), &flow_ctx);

            // Flow 1 entry remains.
            assert_eq!(buf.len(), 1);
            assert_eq!(buf.oldest_flow_id().unwrap(), mk_flow_id(1));
            // Two datagrams delivered for flow 0.
            assert!(recv.try_recv().is_ok());
            assert!(recv.try_recv().is_ok());
            assert_eq!(recv.try_recv().unwrap_err(), TryRecvError::Empty);
        }

        /// `flush_to_flow()` only touches datagrams for the target flow even
        /// when many flows are interleaved in the global arrival order.
        #[test]
        fn pending_buffer_flushes_interleaved_flow_directly() {
            let mut buf = PendingDgramBuffer::new();
            buf.push(mk_flow_id(0), mk_dgram(b"f0-a"));
            buf.push(mk_flow_id(1), mk_dgram(b"f1-a"));
            buf.push(mk_flow_id(0), mk_dgram(b"f0-b"));
            buf.push(mk_flow_id(1), mk_dgram(b"f1-b"));

            let (flow_ctx_1, mut recv_1) = FlowCtx::new(4, 16);
            buf.flush_to_flow(mk_flow_id(1), &flow_ctx_1);

            assert_eq!(buf.len(), 2);
            assert_eq!(buf.oldest_flow_id().unwrap(), mk_flow_id(0));
            assert_eq!(buf.newest_flow_id().unwrap(), mk_flow_id(0));

            let f1_a = recv_1.try_recv().unwrap();
            let f1_b = recv_1.try_recv().unwrap();
            assert_matches::assert_matches!(f1_a, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"f1-a");
            });
            assert_matches::assert_matches!(f1_b, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"f1-b");
            });
            assert_eq!(recv_1.try_recv().unwrap_err(), TryRecvError::Empty);

            let (flow_ctx_0, mut recv_0) = FlowCtx::new(0, 16);
            buf.flush_to_flow(mk_flow_id(0), &flow_ctx_0);

            assert_eq!(buf.len(), 0);
            let f0_a = recv_0.try_recv().unwrap();
            let f0_b = recv_0.try_recv().unwrap();
            assert_matches::assert_matches!(f0_a, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"f0-a");
            });
            assert_matches::assert_matches!(f0_b, InboundFrame::Datagram(d) => {
                assert_eq!(d.as_slice(), b"f0-b");
            });
            assert_eq!(recv_0.try_recv().unwrap_err(), TryRecvError::Empty);
        }

        /// `flush_to_flow()` is a no-op when no entries match the flow.
        #[test]
        fn pending_buffer_flush_noop_when_no_match() {
            let mut buf = PendingDgramBuffer::new();
            buf.push(mk_flow_id(1), mk_dgram(b"a"));

            let (flow_ctx, mut recv) = FlowCtx::new(0, 16);
            buf.flush_to_flow(mk_flow_id(99), &flow_ctx);

            assert_eq!(buf.len(), 1);
            assert_eq!(recv.try_recv().unwrap_err(), TryRecvError::Empty);
        }
    }
}
