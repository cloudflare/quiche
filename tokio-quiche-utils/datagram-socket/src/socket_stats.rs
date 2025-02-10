use std::ops::Deref;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

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
    pub cwnd: u64,
    pub packets_sent: u64,
    pub packets_recvd: u64,
    pub packets_lost: u64,
    pub packets_retrans: u64,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
    pub bytes_lost: u64,
    pub bytes_retrans: u64,
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
        &self,
        recvd_conn_close_transport_error_code: i64,
    ) {
        self.recvd_conn_close_transport_error_code
            .store(recvd_conn_close_transport_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn set_sent_conn_close_transport_error_code(
        &self,
        sent_conn_close_transport_error_code: i64,
    ) {
        self.sent_conn_close_transport_error_code
            .store(sent_conn_close_transport_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn set_recvd_conn_close_application_error_code(
        &self,
        recvd_conn_close_application_error_code: i64,
    ) {
        self.recvd_conn_close_application_error_code
            .store(recvd_conn_close_application_error_code, Ordering::SeqCst)
    }

    #[inline]
    pub fn set_sent_conn_close_application_error_code(
        &self,
        sent_conn_close_application_error_code: i64,
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
    pub fn connection_close_reason(&self) -> impl Deref<Target = Option<BoxError>> + '_ {
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
