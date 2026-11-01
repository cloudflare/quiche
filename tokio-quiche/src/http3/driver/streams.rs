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

use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::time::Instant;

use quiche::h3;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::H3ConnectionError;
use super::H3ConnectionResult;
use super::InboundFrame;
use super::InboundFrameSender;
use super::InboundFrameStream;
use super::OutboundFrame;
use super::OutboundFrameSender;
use super::OutboundFrameStream;
use crate::http3::H3AuditStats;

/// Receive-side application-delivery state.
#[derive(Debug)]
pub(super) enum RecvState {
    /// Peer body data or a terminal event can still be delivered.
    Open(InboundDelivery),
    /// Peer FIN was received but has not been queued to the application.
    ///
    /// Retain the sender to await capacity and enqueue the explicit FIN frame.
    FinPending(InboundDelivery),
    /// No further frames will be delivered; the sender has been dropped.
    Closed,
}

/// Application delivery owns both its sender and its capacity wait.
#[derive(Debug)]
pub(super) struct InboundDelivery {
    sender: InboundFrameSender,
    waiting_for_capacity: bool,
}

impl InboundDelivery {
    fn new(sender: InboundFrameSender) -> Self {
        Self {
            sender,
            waiting_for_capacity: false,
        }
    }

    fn poll_waiting_capacity(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.waiting_for_capacity {
            return false;
        }

        if self.sender.poll_reserve(cx).is_ready() {
            // Reads use try_reserve, so release the wake-up permit.
            self.sender.abort_send();
            self.waiting_for_capacity = false;
            return true;
        }

        false
    }
}

impl RecvState {
    /// Records peer FIN once, preserving pending or closed delivery states.
    pub(super) fn mark_fin_pending(&mut self) -> bool {
        match self {
            Self::Open(_) => {
                let Self::Open(delivery) = mem::replace(self, Self::Closed)
                else {
                    unreachable!("the receive state was just matched as open");
                };
                *self = Self::FinPending(delivery);
                true
            },
            Self::FinPending(_) | Self::Closed => false,
        }
    }

    fn delivery(&self) -> Option<&InboundDelivery> {
        match self {
            Self::Open(delivery) | Self::FinPending(delivery) => Some(delivery),
            Self::Closed => None,
        }
    }

    fn delivery_mut(&mut self) -> Option<&mut InboundDelivery> {
        match self {
            Self::Open(delivery) | Self::FinPending(delivery) => Some(delivery),
            Self::Closed => None,
        }
    }

    /// Returns the inbound sender only when no capacity wait is registered.
    /// Closed delivery or a closed PollSender has no available sender.
    pub(super) fn inbound_sender_if_not_waiting(
        &self,
    ) -> Option<&mpsc::Sender<InboundFrame>> {
        self.delivery()
            .filter(|delivery| !delivery.waiting_for_capacity)
            .and_then(|delivery| delivery.sender.get_ref())
    }

    #[cfg(test)]
    fn channel_sender(&self) -> Option<&InboundFrameSender> {
        self.delivery().map(|delivery| &delivery.sender)
    }

    /// Marks capacity waiting only while an application endpoint exists.
    fn wait_for_capacity(&mut self) -> bool {
        self.delivery_mut()
            .map(|delivery| delivery.waiting_for_capacity = true)
            .is_some()
    }

    #[cfg(test)]
    fn waiting_for_capacity(&self) -> bool {
        self.delivery()
            .is_some_and(|delivery| delivery.waiting_for_capacity)
    }

    fn poll_waiting_capacity(&mut self, cx: &mut Context<'_>) -> bool {
        self.delivery_mut()
            .is_some_and(|delivery| delivery.poll_waiting_capacity(cx))
    }
}

/// The transport write direction is closed by FIN, reset, or peer STOP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SendState {
    /// Transport writes have not yet finished or been canceled.
    Open,
    /// Transport writes ended through FIN, local reset, or peer STOP_SENDING.
    Closed,
}

/// Receives coalesced stream notifications and rearms their wake state.
///
/// The raw receiver is private: dequeueing always clears the notification's
/// queued flag, independently of whether the driver subsequently polls it.
pub(crate) struct ReadyStreams {
    receiver: mpsc::UnboundedReceiver<Arc<StreamWake>>,
}

/// Creates per-stream wakers that share a coalescing ready queue.
#[derive(Clone)]
pub(crate) struct ReadyStreamSender(mpsc::UnboundedSender<Arc<StreamWake>>);

impl ReadyStreams {
    pub(crate) fn new() -> (ReadyStreamSender, Self) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (ReadyStreamSender(sender), Self { receiver })
    }

    /// Clears the queued flag before returning the stream ID.
    ///
    /// A wake racing with subsequent channel polling can then queue a fresh
    /// notification. This future retains Tokio's cooperative receive budget.
    pub(crate) async fn recv(&mut self) -> Option<u64> {
        self.receiver
            .recv()
            .await
            .map(|wake| Self::acknowledge(&wake))
    }

    fn acknowledge(wake: &StreamWake) -> u64 {
        wake.queued.store(false, Ordering::Release);
        wake.stream_id
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&mut self) -> Result<u64, mpsc::error::TryRecvError> {
        self.receiver
            .try_recv()
            .map(|wake| Self::acknowledge(&wake))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.receiver.len()
    }
}

/// Coalesces both channel directions using one allocation per stream.
///
/// `queued` is true from the enqueue claim until `ReadyStreams` dequeues the
/// notification. Only a false-to-true transition enqueues. The wake metadata
/// owns no channel endpoints, so stale notifications cannot retain them.
struct StreamWake {
    stream_id: u64,
    queued: AtomicBool,
    ready_streams: mpsc::UnboundedSender<Arc<Self>>,
}

impl Wake for StreamWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            let _ = self.ready_streams.send(Arc::clone(self));
        }
    }
}

pub(crate) struct StreamCtx {
    /// Receives [`OutboundFrame`]s from a local task.
    /// Dropped before transport completion when a FIN-bearing body is queued.
    pub(crate) recv: Option<OutboundFrameStream>,
    /// Stores the next [`OutboundFrame`] to write to the connection.
    /// Retained here when the transport cannot write the complete frame.
    pub(crate) queued_frame: Option<OutboundFrame>,
    pub(crate) audit_stats: Arc<H3AuditStats>,
    /// Indicates the stream sent initial headers.
    pub(crate) initial_headers_sent: bool,
    /// First time that a HEADERS frame was not fully flushed.
    pub(crate) first_full_headers_flush_fail_time: Option<Instant>,
    /// Receive-side lifecycle and the sender for local application delivery.
    pub(super) recv_state: RecvState,
    /// Transport write-side lifecycle.
    pub(super) send_state: SendState,
    /// The flow ID for proxying datagrams over this stream. If `None`,
    /// the stream has no associated DATAGRAM flow.
    pub(crate) associated_dgram_flow_id: Option<u64>,
    /// Whether the outbound channel needs to be re-polled for application data.
    waiting_for_recv: bool,
    waker: Waker,
}

impl StreamCtx {
    /// Creates a new [StreamCtx]. This method returns the [StreamCtx] itself
    /// as well as the sender/receiver that it communicates with.
    pub(crate) fn new(
        stream_id: u64, capacity: usize, ready_streams: ReadyStreamSender,
    ) -> (Self, OutboundFrameSender, InboundFrameStream) {
        let (forward_sender, forward_receiver) = mpsc::channel(capacity);
        let (backward_sender, backward_receiver) = mpsc::channel(capacity);
        let wake = Arc::new(StreamWake {
            stream_id,
            queued: AtomicBool::new(false),
            ready_streams: ready_streams.0,
        });

        let ctx = StreamCtx {
            recv: Some(backward_receiver),
            queued_frame: None,
            audit_stats: Arc::new(H3AuditStats::new(stream_id)),

            initial_headers_sent: false,
            first_full_headers_flush_fail_time: None,

            recv_state: RecvState::Open(InboundDelivery::new(PollSender::new(
                forward_sender,
            ))),
            send_state: SendState::Open,

            associated_dgram_flow_id: None,
            waiting_for_recv: false,
            waker: Waker::from(wake),
        };

        (ctx, PollSender::new(backward_sender), forward_receiver)
    }

    /// Cleanup requires closed transport writes and closed app delivery.
    pub(super) fn fully_closed(&self) -> bool {
        match (&self.recv_state, self.send_state) {
            (RecvState::Closed, SendState::Closed) => true,
            (RecvState::Open(_) | RecvState::FinPending(_), _) |
            (RecvState::Closed, SendState::Open) => false,
        }
    }

    /// Schedules the initial poll to register for upstream channel capacity.
    /// Subsequent readiness uses the same coalescing ready queue.
    pub(crate) fn wait_for_send(&mut self) {
        if self.recv_state.wait_for_capacity() {
            self.waker.wake_by_ref();
        }
    }

    /// Schedules the initial poll to register for downstream channel data.
    /// Subsequent readiness uses the same coalescing ready queue.
    pub(crate) fn wait_for_recv(&mut self) {
        self.waiting_for_recv = true;
        self.waker.wake_by_ref();
    }

    #[cfg(test)]
    pub(super) fn waiting_for_send(&self) -> bool {
        self.recv_state.waiting_for_capacity()
    }

    pub(super) fn waiting_for_recv(&self) -> bool {
        self.waiting_for_recv
    }

    pub(super) fn cancel_recv_wait(&mut self) {
        self.waiting_for_recv = false;
    }

    /// Re-polls waiting endpoints, retaining waits on spurious wakes or when
    /// Tokio's cooperative budget is exhausted. Returns (recv ready, send
    /// ready).
    ///
    /// Queue acknowledgment belongs to `ReadyStreams`, not this method. Direct
    /// or spurious polling leaves the queue's coalescing state unchanged.
    pub(super) fn poll_waiting(&mut self) -> H3ConnectionResult<(bool, bool)> {
        let mut cx = Context::from_waker(&self.waker);
        let mut recv_ready = false;

        if self.waiting_for_recv() {
            let Some(recv) = self.recv.as_mut() else {
                debug_assert!(false, "Outbound waiting requires a receiver");
                return Err(H3ConnectionError::H3(h3::Error::InternalError));
            };
            if let Poll::Ready(data) = recv.poll_recv(&mut cx) {
                if self.queued_frame.is_some() {
                    debug_assert!(
                            false,
                            "channel readiness cannot replace a queued outbound frame"
                        );
                    return Err(H3ConnectionError::H3(h3::Error::InternalError));
                }
                self.queued_frame = data;
                self.waiting_for_recv = false;
                recv_ready = true;
            }
        }

        let send_ready = self.recv_state.poll_waiting_capacity(&mut cx);

        Ok((recv_ready, send_ready))
    }

    /// Handle the case when we received a STOP_SENDING frame. Note, that
    /// we'll only learn about a STOP_SENDING frame from the write path.
    /// Also note, that quiche will automatically send a RESET_STREAM frame
    /// in response when it receives a STOP_SENDING (as recommended by the
    /// RFC)
    pub(crate) fn handle_recvd_stop_sending(&mut self, wire_err_code: u64) {
        // Update stats even if the stream is already closing.
        self.audit_stats
            .set_recvd_stop_sending_error_code(wire_err_code as i64);

        match self.send_state {
            SendState::Closed => {
                // STOP may arrive after FIN or reset has closed the write side.
                return;
            },
            SendState::Open => self.send_state = SendState::Closed,
        }

        // We received a STOP_SENDING frame. This indicates that the
        // write direction has closed. We still need to continue
        // reading from the stream until we receive a RESET_FRAME or
        // `fin`.
        // Close immediately, but preserve a buffered application error: it
        // shuts down the read direction too. All ordinary outbound data is
        // discarded after STOP_SENDING.
        let mut peer_error =
            matches!(self.queued_frame, Some(OutboundFrame::PeerStreamError));
        if let Some(mut recv) = self.recv.take() {
            recv.close();
            // Retain errors already buffered at STOP. A sender holding a
            // reserved permit can still send later; dropping this receiver
            // rejects that late output, including any late PeerStreamError.
            while let Ok(frame) = recv.try_recv() {
                peer_error |= matches!(frame, OutboundFrame::PeerStreamError);
            }
        }
        self.waiting_for_recv = false;
        self.queued_frame = peer_error.then_some(OutboundFrame::PeerStreamError);
    }

    pub(crate) fn handle_recvd_reset(
        &mut self, wire_err_code: u64,
    ) -> H3ConnectionResult<()> {
        // The body reader and HTTP/3 polling can report the same reset.
        // We received a RESET_STREAM frame, which closes the read direction
        // but not the write direction. If the peer wants to shut down write,
        // it must also send STOP_SENDING
        self.audit_stats
            .set_recvd_reset_stream_error_code(wire_err_code as i64);
        self.recv_state = RecvState::Closed;
        Ok(())
    }

    pub(crate) fn handle_sent_reset(
        &mut self, wire_err_code: u64,
    ) -> H3ConnectionResult<()> {
        match self.send_state {
            SendState::Open => {},
            SendState::Closed => {
                debug_assert!(
                    false,
                    "A local reset requires an open send direction"
                );
                return Err(H3ConnectionError::H3(h3::Error::InternalError));
            },
        }
        self.audit_stats
            .set_sent_reset_stream_error_code(wire_err_code as i64);
        self.send_state = SendState::Closed;
        self.waiting_for_recv = false;
        Ok(())
    }

    pub(crate) fn handle_sent_stop_sending(
        &mut self, wire_err_code: u64,
    ) -> H3ConnectionResult<()> {
        match self.recv_state {
            RecvState::Open(_) => {},
            RecvState::FinPending(_) | RecvState::Closed => {
                debug_assert!(
                    false,
                    "A local STOP requires an open receive direction"
                );
                return Err(H3ConnectionError::H3(h3::Error::InternalError));
            },
        }
        self.audit_stats
            .set_sent_stop_sending_error_code(wire_err_code as i64);
        // Closing the receive state here is safe. The peer must still send
        // FIN or RESET_STREAM with its final size, but `quiche` handles
        // that without an application read.
        self.recv_state = RecvState::Closed;
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;

    #[tokio::test]
    async fn queue_acknowledgment_is_independent_of_channel_polling() {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, _outbound, _inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.wait_for_recv();
        assert_eq!(ready_rx.len(), 1);

        // Polling directly must not clear a notification still in the queue.
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        ctx.waker.wake_by_ref();
        assert_eq!(ready_rx.len(), 1);

        assert_eq!(ready_rx.recv().await, Some(4));
        // Dequeue rearms even if the notification is not followed by a poll.
        ctx.waker.wake_by_ref();
        ctx.waker.wake_by_ref();
        assert_eq!(ready_rx.len(), 1);
        assert_eq!(ready_rx.recv().await, Some(4));
        assert_eq!(ready_rx.len(), 0);
    }

    #[rstest]
    #[case::upstream(true, false)]
    #[case::downstream(false, true)]
    #[case::both(true, true)]
    fn channel_wakes_coalesce_and_resume_waiting_endpoints(
        #[case] send_wait: bool, #[case] recv_wait: bool,
    ) {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, mut inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), false))
            .unwrap();

        if send_wait {
            ctx.wait_for_send();
            ctx.wait_for_send();
        }
        if recv_wait {
            ctx.wait_for_recv();
            ctx.wait_for_recv();
        }
        // Re-registering either direction still queues only one notification.
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert!(ready_rx.try_recv().is_err());
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));

        // Repeated spurious wakes coalesce and leave both waits registered.
        for _ in 0..2 {
            for _ in 0..10 {
                ctx.waker.wake_by_ref();
            }
            assert_eq!(ready_rx.try_recv().unwrap(), 4);
            assert!(ready_rx.try_recv().is_err());
            assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
            assert_eq!(ctx.waiting_for_send(), send_wait);
            assert_eq!(ctx.waiting_for_recv(), recv_wait);
        }
        assert!(ctx.recv_state.channel_sender().is_some());
        assert!(ctx.recv.is_some());

        // Real channel wakes after dequeue must produce a fresh notification.
        inbound.try_recv().unwrap();
        outbound
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::PeerStreamError)
            .unwrap();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert!(ready_rx.try_recv().is_err());
        assert_eq!(ctx.poll_waiting().unwrap(), (recv_wait, send_wait));
        assert!(!ctx.waiting_for_send());
        assert!(!ctx.waiting_for_recv());
        assert_eq!(
            matches!(ctx.queued_frame, Some(OutboundFrame::PeerStreamError)),
            recv_wait
        );
        // The capacity reservation used for readiness has been released.
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), false))
            .unwrap();
    }

    enum ReceiveClosure {
        PeerReset,
        LocalStop,
        Direct,
    }

    #[rstest]
    #[case::peer_reset(ReceiveClosure::PeerReset)]
    #[case::local_stop(ReceiveClosure::LocalStop)]
    #[case::direct_closed(ReceiveClosure::Direct)]
    fn receive_closure_drops_capacity_wait_only(#[case] closure: ReceiveClosure) {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), false))
            .unwrap();
        ctx.wait_for_send();
        ctx.wait_for_recv();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));

        assert!(ctx.waiting_for_send());
        assert!(ctx.waiting_for_recv());
        match closure {
            ReceiveClosure::PeerReset => {
                ctx.handle_recvd_reset(42).unwrap();
                assert_eq!(ctx.audit_stats.recvd_reset_stream_error_code(), 42);
                assert_eq!(ctx.audit_stats.sent_stop_sending_error_code(), -1);
            },
            ReceiveClosure::LocalStop => {
                ctx.handle_sent_stop_sending(42).unwrap();
                assert_eq!(ctx.audit_stats.sent_stop_sending_error_code(), 42);
                assert_eq!(ctx.audit_stats.recvd_reset_stream_error_code(), -1);
            },
            ReceiveClosure::Direct => {
                ctx.recv_state = RecvState::Closed;
                assert_eq!(ctx.audit_stats.recvd_reset_stream_error_code(), -1);
                assert_eq!(ctx.audit_stats.sent_stop_sending_error_code(), -1);
            },
        }
        assert!(inbound.is_closed());
        assert!(matches!(ctx.recv_state, RecvState::Closed));
        assert!(!ctx.waiting_for_send());
        assert!(ctx.waiting_for_recv());
        assert!(ready_rx.try_recv().is_err());
        // A closed receive state cannot register another capacity wait.
        ctx.wait_for_send();
        assert!(!ctx.waiting_for_send());
        assert!(ready_rx.try_recv().is_err());

        ctx.waker.wake_by_ref();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert!(ready_rx.try_recv().is_err());
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        assert!(ctx.waiting_for_recv());
        assert!(ctx.queued_frame.is_none());

        let tx = outbound.get_ref().unwrap();
        assert!(!tx.is_closed());
        tx.try_send(OutboundFrame::PeerStreamError).unwrap();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert!(ready_rx.try_recv().is_err());
        assert_eq!(ctx.poll_waiting().unwrap(), (true, false));
        assert!(matches!(
            ctx.queued_frame,
            Some(OutboundFrame::PeerStreamError)
        ));
    }

    enum ErrorPlacement {
        None,
        Channel(usize),
        Queued,
        LatePermit,
    }

    #[rstest]
    #[case::no_error(ErrorPlacement::None)]
    #[case::error_first(ErrorPlacement::Channel(0))]
    #[case::error_middle(ErrorPlacement::Channel(1))]
    #[case::error_last(ErrorPlacement::Channel(2))]
    #[case::error_queued(ErrorPlacement::Queued)]
    #[case::late_reserved_permit_error(ErrorPlacement::LatePermit)]
    fn stop_discards_data_but_preserves_error(#[case] error: ErrorPlacement) {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, inbound) = StreamCtx::new(4, 4, ready_tx);
        let tx = outbound.get_ref().unwrap();
        ctx.wait_for_send();
        ctx.wait_for_recv();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        if matches!(error, ErrorPlacement::Queued) {
            // Queued output waits on transport, not on channel receive.
            ctx.cancel_recv_wait();
            ctx.queued_frame = Some(OutboundFrame::PeerStreamError);
        }
        for position in 0..3 {
            let frame = if matches!(error, ErrorPlacement::Channel(p) if p == position)
            {
                OutboundFrame::PeerStreamError
            } else {
                OutboundFrame::Body(Default::default(), false)
            };
            tx.try_send(frame).unwrap();
        }

        let late_error = if matches!(error, ErrorPlacement::LatePermit) {
            Some(tx.try_reserve().unwrap())
        } else {
            None
        };
        ctx.handle_recvd_stop_sending(42);
        if let Some(permit) = late_error {
            // Sending through a pre-STOP permit is infallible, but its late
            // error must not become retained output after the receiver drops.
            permit.send(OutboundFrame::PeerStreamError);
        }
        assert!(!inbound.is_closed());
        assert!(tx.is_closed());
        assert!(ctx.waiting_for_send());
        assert!(!ctx.waiting_for_recv());
        assert!(ctx.recv_state.channel_sender().is_some());
        assert!(ctx.recv.is_none());
        let has_error =
            matches!(error, ErrorPlacement::Channel(_) | ErrorPlacement::Queued);
        assert_eq!(
            matches!(ctx.queued_frame, Some(OutboundFrame::PeerStreamError)),
            has_error
        );

        // A stale wake cannot receive canceled data or erase the error.
        assert_eq!(ctx.poll_waiting().unwrap(), (false, true));
        assert_eq!(
            matches!(ctx.queued_frame, Some(OutboundFrame::PeerStreamError)),
            has_error
        );
    }

    #[test]
    fn retained_waker_does_not_own_endpoints() {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (ctx, outbound, inbound) = StreamCtx::new(4, 1, ready_tx);
        let waker = ctx.waker.clone();
        drop(ctx);
        assert!(inbound.is_closed());
        assert!(outbound.get_ref().unwrap().is_closed());
        waker.wake_by_ref();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert!(ready_rx.try_recv().is_err());
    }

    #[test]
    fn local_reset_clears_only_outbound_wait() {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), false))
            .unwrap();
        ctx.wait_for_send();
        ctx.wait_for_recv();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        // The driver resets after its outbound channel disconnects.
        drop(outbound);
        ctx.handle_sent_reset(42).unwrap();
        assert!(!inbound.is_closed());
        assert!(ctx.waiting_for_send());
        assert!(!ctx.waiting_for_recv());
        assert_eq!(ctx.audit_stats.sent_reset_stream_error_code(), 42);
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        assert!(ctx.queued_frame.is_none());
    }

    #[rstest]
    #[case::open(false)]
    #[case::pending_fin(true)]
    fn peer_reset_closes_delivery_idempotently(#[case] fin_pending: bool) {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), false))
            .unwrap();
        ctx.wait_for_send();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        if fin_pending {
            assert!(ctx.recv_state.mark_fin_pending());
        }

        for code in [42, 43] {
            ctx.handle_recvd_reset(code).unwrap();
            assert_eq!(
                ctx.audit_stats.recvd_reset_stream_error_code(),
                code as i64
            );
            assert!(matches!(ctx.recv_state, RecvState::Closed));
            assert!(inbound.is_closed());
            assert!(!ctx.waiting_for_send());
            assert!(!outbound.get_ref().unwrap().is_closed());
            assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        }
    }

    #[rstest]
    #[case::local_stop(StreamCtx::handle_sent_stop_sending, true)]
    #[case::local_reset(StreamCtx::handle_sent_reset, false)]
    fn local_cancellation_requires_open_direction(
        #[case] cancel: fn(&mut StreamCtx, u64) -> H3ConnectionResult<()>,
        #[case] closes_receive: bool,
    ) {
        let (ready_tx, _ready_rx) = ReadyStreams::new();
        let (mut ctx, _outbound, _inbound) = StreamCtx::new(4, 1, ready_tx);
        cancel(&mut ctx, 42).unwrap();
        assert_eq!(matches!(ctx.recv_state, RecvState::Closed), closes_receive);
        assert_eq!(ctx.send_state == SendState::Closed, !closes_receive);

        // Only the second call is allowed to reject the closed direction.
        let result = catch_unwind(AssertUnwindSafe(|| cancel(&mut ctx, 43)));
        if cfg!(debug_assertions) {
            let panic = result.expect_err("repeated cancellation must assert");
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .expect("the assertion must have a string panic message");
            assert!(message.contains("requires an open"), "{message}");
        } else {
            assert_matches!(
                result,
                Ok(Err(H3ConnectionError::H3(h3::Error::InternalError)))
            );
        }
    }

    #[tokio::test]
    async fn concurrent_channel_wakes_survive_repeated_parking() {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, _inbound) = StreamCtx::new(4, 1, ready_tx);
        let producer = std::thread::spawn(move || {
            let tx = outbound.get_ref().unwrap();
            (0..256).try_for_each(|_| {
                tx.blocking_send(OutboundFrame::Body(Default::default(), false))
            })
        });

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..256 {
                ctx.wait_for_recv();
                loop {
                    assert_eq!(ready_rx.recv().await.unwrap(), 4);
                    if ctx.poll_waiting().unwrap().0 {
                        assert!(matches!(
                            ctx.queued_frame.take(),
                            Some(OutboundFrame::Body(..))
                        ));
                        break;
                    }
                }
            }
        })
        .await;
        // Unblock the producer even if a lost wake caused the timeout.
        drop(ctx);
        let produced = producer.join().unwrap();
        result.expect("a channel wake was lost while repeatedly parking");
        produced.unwrap();
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "waiting requires"))]
    fn outbound_waiting_requires_channel_endpoint() {
        let (ready_tx, _ready_rx) = ReadyStreams::new();
        let (mut ctx, _outbound, _inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.recv = None;
        ctx.wait_for_recv();
        assert!(matches!(
            ctx.poll_waiting(),
            Err(H3ConnectionError::H3(h3::Error::InternalError))
        ));
    }

    #[test]
    fn pending_fin_preserves_capacity_wait() {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, _outbound, mut inbound) = StreamCtx::new(4, 1, ready_tx);
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), false))
            .unwrap();
        ctx.wait_for_send();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));

        assert!(ctx.recv_state.mark_fin_pending());
        assert!(!ctx.recv_state.mark_fin_pending());
        assert!(ctx.waiting_for_send());
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));

        inbound.try_recv().unwrap();
        assert_eq!(ready_rx.try_recv().unwrap(), 4);
        assert_eq!(ctx.poll_waiting().unwrap(), (false, true));
        assert!(!ctx.waiting_for_send());
        assert!(matches!(ctx.recv_state, RecvState::FinPending(_)));
        // Readiness polling must release its permit for the explicit FIN.
        ctx.recv_state
            .channel_sender()
            .unwrap()
            .get_ref()
            .unwrap()
            .try_send(InboundFrame::Body(Default::default(), true))
            .unwrap();
    }

    #[rstest]
    #[case::inbound_capacity(true)]
    #[case::outbound_data(false)]
    #[tokio::test]
    async fn cooperative_yield_keeps_wait_registered(
        #[case] capacity_wait: bool,
    ) {
        let (ready_tx, mut ready_rx) = ReadyStreams::new();
        let (mut ctx, outbound, _inbound) = StreamCtx::new(4, 1, ready_tx);
        if capacity_wait {
            ctx.wait_for_send();
        } else {
            ctx.wait_for_recv();
            outbound
                .get_ref()
                .unwrap()
                .try_send(OutboundFrame::PeerStreamError)
                .unwrap();
        }
        assert_eq!(ready_rx.try_recv().unwrap(), 4);

        while tokio::task::coop::has_budget_remaining() {
            tokio::task::coop::consume_budget().await;
        }
        assert_eq!(ctx.poll_waiting().unwrap(), (false, false));
        assert_eq!(ctx.waiting_for_send(), capacity_wait);
        assert_eq!(ctx.waiting_for_recv(), !capacity_wait);
        tokio::task::yield_now().await;
        let ready = tokio::time::timeout(Duration::from_secs(5), ready_rx.recv())
            .await
            .expect("a channel wake was lost after the cooperative yield");
        assert_eq!(ready.unwrap(), 4);
        assert_eq!(ctx.poll_waiting().unwrap(), (!capacity_wait, capacity_wait));
        assert!(!ctx.waiting_for_send());
        assert!(!ctx.waiting_for_recv());
        assert_eq!(
            matches!(ctx.queued_frame, Some(OutboundFrame::PeerStreamError)),
            !capacity_wait
        );
    }
}
