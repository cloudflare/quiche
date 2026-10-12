// Copyright (C) 2026, Cloudflare, Inc.
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
use std::pin::Pin;
use std::task::ready;
use std::task::Context;
use std::task::Poll;

use foundations::telemetry::log;
use futures::future::AbortHandle;
use futures::future::Abortable;
use futures_util::stream::FuturesUnordered;
use quiche::h3;
use tokio_stream::Stream;

use super::streams::StreamReady;
use super::streams::WaitForStream;
use super::H3ConnectionError;
use super::H3ConnectionResult;

/// Tracks streams that are waiting on the application.
///
/// This tracks streams that are either waiting for upstream capacity (to write
/// more data to the app) or downstream data, i.e., data from the app to send
/// to the peer.
pub(super) struct WaitingStreams {
    /// Pending waits. A wait is aborted if the stream is cleaned up or reset
    /// by the peer.
    waits: FuturesUnordered<Abortable<WaitForStream>>,
    /// Abort handles for waits on capacity to deliver inbound data upstream.
    upstream: HashMap<u64, AbortHandle>,
    /// Abort handles for waits on outbound data from the app.
    downstream: HashMap<u64, AbortHandle>,
}

impl WaitingStreams {
    pub(super) fn new() -> Self {
        Self {
            waits: FuturesUnordered::new(),
            upstream: HashMap::new(),
            downstream: HashMap::new(),
        }
    }

    /// Registers a pending stream and stores its abort handle by stream ID.
    pub(super) fn push(&mut self, wait: WaitForStream) -> H3ConnectionResult<()> {
        let (handle, registration) = AbortHandle::new_pair();

        let (stream_id, prev, direction) = match &wait {
            WaitForStream::Downstream(d) => (
                d.stream_id,
                self.downstream.insert(d.stream_id, handle),
                "downstream",
            ),
            WaitForStream::Upstream(u) => (
                u.stream_id,
                self.upstream.insert(u.stream_id, handle),
                "upstream",
            ),
        };
        if prev.is_some() {
            // There was an entry for this stream already. This should never
            // happen.
            let msg = format!(
                "Added a waiting stream id={}, direction={},\
                    but we were already waiting for it. Should never happen",
                stream_id, direction
            );
            debug_assert!(false, "{}", msg);
            log::error!(ratelimit=60/m; "{}", msg);
            return Err(H3ConnectionError::H3(h3::Error::InternalError));
        }

        self.waits.push(Abortable::new(wait, registration));
        Ok(())
    }

    /// Cancels the upstream-capacity wait for `stream_id`, if present.
    pub(super) fn cancel_upstream(&mut self, stream_id: u64) {
        if let Some(handle) = self.upstream.remove(&stream_id) {
            handle.abort();
        }
    }

    /// Cancels the downstream-data wait for `stream_id`, if present.
    pub(super) fn cancel_downstream(&mut self, stream_id: u64) {
        if let Some(handle) = self.downstream.remove(&stream_id) {
            handle.abort();
        }
    }

    /// Returns the number of live upstream-capacity waits.
    #[cfg(test)]
    pub fn upstream_len(&self) -> usize {
        self.upstream.len()
    }

    /// Returns the number of live downstream-data waits.
    #[cfg(test)]
    pub fn downstream_len(&self) -> usize {
        self.downstream.len()
    }
}

impl Stream for WaitingStreams {
    type Item = StreamReady;

    fn poll_next(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.waits).poll_next(cx)) {
                Some(Ok(ready)) => {
                    match &ready {
                        StreamReady::Downstream(r) => {
                            self.downstream.remove(&r.stream_id);
                        },
                        StreamReady::Upstream(r) => {
                            self.upstream.remove(&r.stream_id);
                        },
                    }

                    return Poll::Ready(Some(ready));
                },
                Some(Err(_aborted)) => {
                    // Wait was cancelled. Ignore.
                },
                None => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt as _;
    use tokio::sync::mpsc;
    use tokio_stream::StreamExt as _;
    use tokio_util::sync::PollSender;

    use super::*;
    use crate::http3::driver::streams::WaitForDownstreamData;
    use crate::http3::driver::streams::WaitForUpstreamCapacity;
    use crate::http3::driver::InboundFrame;
    use crate::http3::driver::OutboundFrame;

    fn downstream_wait(
        stream_id: u64,
    ) -> (mpsc::Sender<OutboundFrame>, WaitForStream) {
        let (tx, rx) = mpsc::channel(1);
        let wait = WaitForStream::Downstream(WaitForDownstreamData {
            stream_id,
            chan: Some(rx),
        });

        (tx, wait)
    }

    fn upstream_wait(
        stream_id: u64,
    ) -> (mpsc::Receiver<InboundFrame>, WaitForStream) {
        let (tx, rx) = mpsc::channel(1);
        let wait = WaitForStream::Upstream(WaitForUpstreamCapacity {
            stream_id,
            chan: Some(PollSender::new(tx)),
        });

        (rx, wait)
    }

    #[test]
    fn successful_readiness_removes_handle() {
        let mut waiting = WaitingStreams::new();
        let (tx, wait) = downstream_wait(4);

        waiting.push(wait).unwrap();
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 1);

        tx.try_send(OutboundFrame::PeerStreamError).unwrap();

        let ready = waiting.next().now_or_never();
        assert!(matches!(
            ready,
            Some(Some(StreamReady::Downstream(r))) if r.stream_id == 4
        ));
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
    }

    #[test]
    fn canceled_wait_produces_no_readiness() {
        let mut waiting = WaitingStreams::new();
        let (_tx, wait) = downstream_wait(4);

        waiting.push(wait).unwrap();
        waiting.cancel_downstream(4);

        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
        assert!(matches!(waiting.next().now_or_never(), Some(None)));
    }

    #[test]
    fn upstream_cancel_preserves_downstream_wait() {
        let mut waiting = WaitingStreams::new();
        let (_rx, upstream) = upstream_wait(4);
        let (tx, downstream) = downstream_wait(4);

        waiting.push(upstream).unwrap();
        waiting.push(downstream).unwrap();
        waiting.cancel_upstream(4);

        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 1);
        assert!(waiting.next().now_or_never().is_none());

        tx.try_send(OutboundFrame::PeerStreamError).unwrap();

        let ready = waiting.next().now_or_never();
        assert!(matches!(
            ready,
            Some(Some(StreamReady::Downstream(r))) if r.stream_id == 4
        ));
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
    }

    #[test]
    fn cancel_then_register_same_direction() {
        let mut waiting = WaitingStreams::new();
        let (_tx, wait) = downstream_wait(4);

        waiting.push(wait).unwrap();
        waiting.cancel_downstream(4);

        let (tx, wait) = downstream_wait(4);
        waiting.push(wait).unwrap();

        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 1);
        assert!(waiting.next().now_or_never().is_none());

        tx.try_send(OutboundFrame::PeerStreamError).unwrap();

        let ready = waiting.next().now_or_never();
        assert!(matches!(
            ready,
            Some(Some(StreamReady::Downstream(r))) if r.stream_id == 4
        ));
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
    }

    #[test]
    #[should_panic]
    fn duplicate_registration_panics() {
        let mut waiting = WaitingStreams::new();
        let (_tx, wait) = downstream_wait(4);
        let (_tx2, wait2) = downstream_wait(4);

        waiting.push(wait).unwrap();
        let _ = waiting.push(wait2);
    }
}
