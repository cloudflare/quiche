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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::InboundFrame;
use super::InboundFrameSender;
use super::InboundFrameStream;
use super::OutboundFrame;
use super::OutboundFrameSender;
use super::OutboundFrameStream;
use crate::http3::H3AuditStats;

pub(crate) struct StreamCtx {
    /// Sends [`InboundFrame`]s to a local task, for example an `H3Body`.
    pub(crate) send: Option<InboundFrameSender>,
    /// Receives [`OutboundFrame`]s from a local task.
    pub(crate) recv: Option<OutboundFrameStream>,
    /// Stores the next [`OutboundFrame`] to write to the connection.
    /// This is used as temporary storage when waiting for `recv`.
    pub(crate) queued_frame: Option<OutboundFrame>,
    pub(crate) audit_stats: Arc<H3AuditStats>,
    /// Indicates the stream sent initial headers.
    pub(crate) initial_headers_sent: bool,
    /// First time that a HEADERS frame was not fully flushed.
    pub(crate) first_full_headers_flush_fail_time: Option<Instant>,
    /// Indicates the stream received fin. No more data will be received.
    pub(crate) fin_or_reset_recv: bool,
    /// Indicates the stream sent fin. No more data will be sent.
    pub(crate) fin_or_reset_sent: bool,
    /// The flow ID for proxying datagrams over this stream. If `None`,
    /// the stream has no associated DATAGRAM flow.
    pub(crate) associated_dgram_flow_id: Option<u64>,
}

impl StreamCtx {
    /// Creates a new [StreamCtx]. This method returns the [StreamCtx] itself
    /// as well as the sender/receiver that it communicates with.
    pub(crate) fn new(
        stream_id: u64, capacity: usize,
    ) -> (Self, OutboundFrameSender, InboundFrameStream) {
        let (forward_sender, forward_receiver) = mpsc::channel(capacity);
        let (backward_sender, backward_receiver) = mpsc::channel(capacity);

        let ctx = StreamCtx {
            send: Some(PollSender::new(forward_sender)),
            recv: Some(backward_receiver),
            queued_frame: None,
            audit_stats: Arc::new(H3AuditStats::new(stream_id)),

            initial_headers_sent: false,
            first_full_headers_flush_fail_time: None,

            fin_or_reset_recv: false,
            fin_or_reset_sent: false,

            associated_dgram_flow_id: None,
        };

        (ctx, PollSender::new(backward_sender), forward_receiver)
    }

    /// Creates a [Future] that resolves when `send` has capacity again.
    pub(crate) fn wait_for_send(&mut self, stream_id: u64) -> WaitForStream {
        WaitForStream::Upstream(WaitForUpstreamCapacity {
            stream_id,
            chan: self.send.take(),
        })
    }

    /// Creates a [Future] that resolves when `recv` has data again.
    pub(crate) fn wait_for_recv(&mut self, stream_id: u64) -> WaitForStream {
        WaitForStream::Downstream(WaitForDownstreamData {
            stream_id,
            chan: self.recv.take(),
        })
    }

    pub(crate) fn both_directions_done(&self) -> bool {
        self.fin_or_reset_recv && self.fin_or_reset_sent
    }
}

pub(crate) struct FlowCtx {
    /// Sends inbound datagrams to a local task.
    send: mpsc::Sender<InboundFrame>,
    // No `recv`: all outbound datagrams are sent on a shared channel in H3Driver
}

impl FlowCtx {
    /// Creates a new [FlowCtx]. This method returns the context itself
    /// as well as the datagram receiver for this flow.
    pub(crate) fn new(capacity: usize) -> (Self, InboundFrameStream) {
        let (forward_sender, forward_receiver) = mpsc::channel(capacity);
        let ctx = FlowCtx {
            send: forward_sender,
        };
        (ctx, forward_receiver)
    }

    /// Tries to send a datagram to the flow receiver, but drops it if the
    /// channel is full.
    pub(crate) fn send_best_effort(&self, datagram: InboundFrame) {
        let _ = self.send.try_send(datagram);
    }
}

pub(crate) enum WaitForStream {
    Downstream(WaitForDownstreamData),
    Upstream(WaitForUpstreamCapacity),
}

pub(crate) enum StreamReady {
    Downstream(ReceivedDownstreamData),
    Upstream(HaveUpstreamCapacity),
}

impl Future for WaitForStream {
    type Output = StreamReady;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            WaitForStream::Downstream(d) =>
                Pin::new(d).poll(cx).map(StreamReady::Downstream),
            WaitForStream::Upstream(u) =>
                Pin::new(u).poll(cx).map(StreamReady::Upstream),
        }
    }
}

pub(crate) struct WaitForDownstreamData {
    pub(crate) stream_id: u64,
    pub(crate) chan: Option<OutboundFrameStream>,
}

pub(crate) struct ReceivedDownstreamData {
    pub(crate) stream_id: u64,
    pub(crate) chan: OutboundFrameStream,
    pub(crate) data: Option<OutboundFrame>,
}

impl Future for WaitForDownstreamData {
    type Output = ReceivedDownstreamData;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        // Unwraps below are Ok because chan will only be None after first
        // Poll::Ready, which is fine to panic for non fused future.
        self.chan.as_mut().unwrap().poll_recv(cx).map(|data| {
            ReceivedDownstreamData {
                stream_id: self.stream_id,
                chan: self.chan.take().unwrap(),
                data,
            }
        })
    }
}

pub(crate) struct WaitForUpstreamCapacity {
    pub(crate) stream_id: u64,
    pub(crate) chan: Option<InboundFrameSender>,
}

pub(crate) struct HaveUpstreamCapacity {
    pub(crate) stream_id: u64,
    pub(crate) chan: InboundFrameSender,
}

impl Future for WaitForUpstreamCapacity {
    type Output = HaveUpstreamCapacity;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        // Unwraps below are Ok because chan will only be None after first
        // Poll::Ready, which is fine to panic for non fused future.
        match self.chan.as_mut().unwrap().poll_reserve(cx) {
            Poll::Ready(_) => Poll::Ready(HaveUpstreamCapacity {
                stream_id: self.stream_id,
                chan: self.chan.take().unwrap(),
            }),
            Poll::Pending => Poll::Pending,
        }
    }
}
