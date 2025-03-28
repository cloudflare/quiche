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

use std::ops::Deref;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::SystemTime;

pub trait AsSocketStats {
    fn as_socket_stats(&self) -> SocketStats;

    fn as_quic_stats(&self) -> Option<&Arc<QuicAuditStats>> {
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SocketStats {
    pub pmtu: u16,
    pub rtt_us: i64,
    pub min_rtt_us: i64,
    pub rtt_var_us: i64,
    pub cwnd: u64,
    pub packets_sent: u64,
    pub packets_recvd: u64,
    pub packets_lost: u64,
    pub packets_retrans: u64,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
    pub bytes_lost: u64,
    pub bytes_retrans: u64,
    pub bytes_unsent: u64,
    pub delivery_rate: u64,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub struct QuicAuditStats {
    /// A transport-level connection error code received from the client
    recvd_conn_close_transport_error_code: AtomicI64,
    /// A transport-level connection error code sent to the client
    sent_conn_close_transport_error_code: AtomicI64,
    /// An application-level connection error code received from the client
    recvd_conn_close_application_error_code: AtomicI64,
    /// An application-level connection error code sent to the client
    sent_conn_close_application_error_code: AtomicI64,
    /// Time taken for the QUIC handshake in microseconds
    transport_handshake_duration_us: AtomicI64,
    /// The start time of the handshake.
    transport_handshake_start: Arc<RwLock<Option<SystemTime>>>,
    /// The reason the QUIC connection was closed
    connection_close_reason: RwLock<Option<BoxError>>,
    /// The server's chosen QUIC connection ID
    /// The QUIC connection ID is presently an array of 20 bytes (160 bits)
    pub quic_connection_id: Vec<u8>,
}

impl QuicAuditStats {
    #[inline]
    pub fn new(quic_connection_id: Vec<u8>) -> Self {
        Self {
            recvd_conn_close_transport_error_code: AtomicI64::new(-1),
            sent_conn_close_transport_error_code: AtomicI64::new(-1),
            recvd_conn_close_application_error_code: AtomicI64::new(-1),
            sent_conn_close_application_error_code: AtomicI64::new(-1),
            transport_handshake_duration_us: AtomicI64::new(-1),
            transport_handshake_start: Arc::new(RwLock::new(None)),
            connection_close_reason: RwLock::new(None),
            quic_connection_id,
        }
    }

    #[inline]
    pub fn recvd_conn_close_transport_error_code(&self) -> i64 {
        self.recvd_conn_close_transport_error_code
            .load(Ordering::SeqCst)
    }

    #[inline]
    pub fn sent_conn_close_transport_error_code(&self) -> i64 {
        self.sent_conn_close_transport_error_code
            .load(Ordering::SeqCst)
    }

    #[inline]
    pub fn recvd_conn_close_application_error_code(&self) -> i64 {
        self.recvd_conn_close_application_error_code
            .load(Ordering::SeqCst)
    }

    #[inline]
    pub fn sent_conn_close_application_error_code(&self) -> i64 {
        self.sent_conn_close_application_error_code
            .load(Ordering::SeqCst)
    }

    #[inline]
    pub fn set_recvd_conn_close_transport_error_code(
        &self, recvd_conn_close_transport_error_code: i64,
    ) {
        self.recvd_conn_close_transport_error_code
            .store(recvd_conn_close_transport_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn set_sent_conn_close_transport_error_code(
        &self, sent_conn_close_transport_error_code: i64,
    ) {
        self.sent_conn_close_transport_error_code
            .store(sent_conn_close_transport_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn set_recvd_conn_close_application_error_code(
        &self, recvd_conn_close_application_error_code: i64,
    ) {
        self.recvd_conn_close_application_error_code
            .store(recvd_conn_close_application_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn set_sent_conn_close_application_error_code(
        &self, sent_conn_close_application_error_code: i64,
    ) {
        self.sent_conn_close_application_error_code
            .store(sent_conn_close_application_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn transport_handshake_duration_us(&self) -> i64 {
        self.transport_handshake_duration_us.load(Ordering::SeqCst)
    }

    #[inline]
    pub fn set_transport_handshake_start(&self, start_time: SystemTime) {
        *self.transport_handshake_start.write().unwrap() = Some(start_time);
    }

    #[inline]
    pub fn set_transport_handshake_duration(&self, duration: Duration) {
        let dur = i64::try_from(duration.as_micros()).unwrap_or(-1);
        self.transport_handshake_duration_us
            .store(dur, Ordering::SeqCst);
    }

    #[inline]
    pub fn transport_handshake_start(&self) -> Arc<RwLock<Option<SystemTime>>> {
        Arc::clone(&self.transport_handshake_start)
    }

    #[inline]
    pub fn connection_close_reason(
        &self,
    ) -> impl Deref<Target = Option<BoxError>> + '_ {
        self.connection_close_reason.read().unwrap()
    }

    #[inline]
    pub fn set_connection_close_reason(&self, error: BoxError) {
        *self.connection_close_reason.write().unwrap() = Some(error);
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StreamClosureKind {
    None,
    Implicit,
    Explicit,
}
