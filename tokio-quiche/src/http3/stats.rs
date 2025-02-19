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

use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crossbeam::atomic::AtomicCell;
use datagram_socket::StreamClosureKind;

/// Stream-level HTTP/3 audit statistics recorded by
/// [H3Driver](crate::http3::driver::H3Driver).
#[derive(Debug)]
pub struct H3AuditStats {
    /// The stream ID of this session.
    stream_id: u64,
    /// The number of bytes sent over the stream.
    downstream_bytes_sent: AtomicU64,
    /// The number of bytes received over the stream.
    downstream_bytes_recvd: AtomicU64,
    /// A STOP_SENDING error code received from the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    recvd_stop_sending_error_code: AtomicI64,
    /// A RESET_STREAM error code received from the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    recvd_reset_stream_error_code: AtomicI64,
    /// A STOP_SENDING error code sent to the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    sent_stop_sending_error_code: AtomicI64,
    /// A RESET_STREAM error code sent to the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    sent_reset_stream_error_code: AtomicI64,
    /// Stream FIN received from the peer.
    recvd_stream_fin: AtomicCell<StreamClosureKind>,
    /// Stream FIN sent to the peer.
    sent_stream_fin: AtomicCell<StreamClosureKind>,
}

impl H3AuditStats {
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            downstream_bytes_sent: AtomicU64::new(0),
            downstream_bytes_recvd: AtomicU64::new(0),
            recvd_stop_sending_error_code: AtomicI64::new(-1),
            recvd_reset_stream_error_code: AtomicI64::new(-1),
            sent_stop_sending_error_code: AtomicI64::new(-1),
            sent_reset_stream_error_code: AtomicI64::new(-1),
            recvd_stream_fin: AtomicCell::new(StreamClosureKind::None),
            sent_stream_fin: AtomicCell::new(StreamClosureKind::None),
        }
    }

    /// The stream ID of this session.
    #[inline]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// The number of bytes sent over the stream.
    #[inline]
    pub fn downstream_bytes_sent(&self) -> u64 {
        self.downstream_bytes_sent.load(Ordering::SeqCst)
    }

    /// The number of bytes received over the stream.
    #[inline]
    pub fn downstream_bytes_recvd(&self) -> u64 {
        self.downstream_bytes_recvd.load(Ordering::SeqCst)
    }

    /// A STOP_SENDING error code received from the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    #[inline]
    pub fn recvd_stop_sending_error_code(&self) -> i64 {
        self.recvd_stop_sending_error_code.load(Ordering::SeqCst)
    }

    /// A RESET_STREAM error code received from the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    #[inline]
    pub fn recvd_reset_stream_error_code(&self) -> i64 {
        self.recvd_reset_stream_error_code.load(Ordering::SeqCst)
    }

    /// A STOP_SENDING error code sent to the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    #[inline]
    pub fn sent_stop_sending_error_code(&self) -> i64 {
        self.sent_stop_sending_error_code.load(Ordering::SeqCst)
    }

    /// A RESET_STREAM error code sent to the peer.
    ///
    /// -1 indicates that this error code was not received yet.
    #[inline]
    pub fn sent_reset_stream_error_code(&self) -> i64 {
        self.sent_reset_stream_error_code.load(Ordering::SeqCst)
    }

    /// Stream FIN received from the peer.
    #[inline]
    pub fn recvd_stream_fin(&self) -> StreamClosureKind {
        self.recvd_stream_fin.load()
    }

    /// Stream FIN sent to the peer.
    #[inline]
    pub fn sent_stream_fin(&self) -> StreamClosureKind {
        self.sent_stream_fin.load()
    }

    #[inline]
    pub fn add_downstream_bytes_sent(&self, bytes_sent: u64) {
        self.downstream_bytes_sent
            .fetch_add(bytes_sent, Ordering::SeqCst);
    }

    #[inline]
    pub fn add_downstream_bytes_recvd(&self, bytes_recvd: u64) {
        self.downstream_bytes_recvd
            .fetch_add(bytes_recvd, Ordering::SeqCst);
    }

    #[inline]
    pub fn set_recvd_stop_sending_error_code(
        &self, recvd_stop_sending_error_code: i64,
    ) {
        self.recvd_stop_sending_error_code
            .store(recvd_stop_sending_error_code, Ordering::SeqCst);
    }

    #[inline]
    pub fn set_recvd_reset_stream_error_code(
        &self, recvd_reset_stream_error_code: i64,
    ) {
        self.recvd_reset_stream_error_code
            .store(recvd_reset_stream_error_code, Ordering::SeqCst);
    }

    #[inline]
    pub fn set_sent_stop_sending_error_code(
        &self, sent_stop_sending_error_code: i64,
    ) {
        self.sent_stop_sending_error_code
            .store(sent_stop_sending_error_code, Ordering::SeqCst);
    }

    #[inline]
    pub fn set_sent_reset_stream_error_code(
        &self, sent_reset_stream_error_code: i64,
    ) {
        self.sent_reset_stream_error_code
            .store(sent_reset_stream_error_code, Ordering::SeqCst);
    }

    #[inline]
    pub fn set_recvd_stream_fin(&self, recvd_stream_fin: StreamClosureKind) {
        self.recvd_stream_fin.store(recvd_stream_fin);
    }

    #[inline]
    pub fn set_sent_stream_fin(&self, sent_stream_fin: StreamClosureKind) {
        self.sent_stream_fin.store(sent_stream_fin);
    }
}
