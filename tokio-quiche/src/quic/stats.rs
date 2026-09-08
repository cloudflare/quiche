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

use std::sync::Arc;
use std::sync::Mutex;

use datagram_socket::AsSocketStats;
use datagram_socket::SocketStats;

use crate::quic::QuicheConnection;

/// Counts of path events consumed by tokio-quiche.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathEventStats {
    /// The number of new network paths observed.
    pub new_path_count: usize,
    /// The number of network paths validated.
    pub validated_count: usize,
    /// The number of network paths that failed validation.
    pub failed_validation_count: usize,
    /// The number of network paths closed.
    pub closed_count: usize,
    /// The number of source connection IDs reused on a different path.
    pub reused_source_connection_id_count: usize,
    /// The number of peer migrations completed.
    pub peer_migrated_count: usize,
}

impl PathEventStats {
    pub(crate) fn record(&mut self, event: quiche::PathEvent) {
        match event {
            quiche::PathEvent::New(..) => self.new_path_count += 1,
            quiche::PathEvent::Validated(..) => self.validated_count += 1,
            quiche::PathEvent::FailedValidation(..) =>
                self.failed_validation_count += 1,
            quiche::PathEvent::Closed(..) => self.closed_count += 1,
            quiche::PathEvent::ReusedSourceConnectionId(..) =>
                self.reused_source_connection_id_count += 1,
            quiche::PathEvent::PeerMigrated(..) => self.peer_migrated_count += 1,
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.new_path_count += other.new_path_count;
        self.validated_count += other.validated_count;
        self.failed_validation_count += other.failed_validation_count;
        self.closed_count += other.closed_count;
        self.reused_source_connection_id_count +=
            other.reused_source_connection_id_count;
        self.peer_migrated_count += other.peer_migrated_count;
    }
}

/// Wrapper for connection statistics recorded by [quiche] and tokio-quiche.
#[derive(Debug)]
pub struct QuicConnectionStats {
    /// Aggregate connection statistics across all paths.
    pub stats: quiche::Stats,
    /// Specific statistics about the connection's active path.
    pub path_stats: Option<quiche::PathStats>,
    /// Counts of path events consumed by tokio-quiche.
    pub path_event_stats: PathEventStats,
}
pub(crate) type QuicConnectionStatsShared = Arc<Mutex<QuicConnectionStats>>;

impl QuicConnectionStats {
    pub(crate) fn from_conn(qconn: &QuicheConnection) -> Self {
        Self {
            stats: qconn.stats(),
            path_stats: qconn.path_stats().next(),
            path_event_stats: PathEventStats::default(),
        }
    }

    pub(crate) fn update_from_conn(&mut self, qconn: &QuicheConnection) {
        self.stats = qconn.stats();
        self.path_stats = qconn.path_stats().next();
    }

    fn startup_exit_to_socket_stats(
        value: quiche::StartupExit,
    ) -> datagram_socket::StartupExit {
        let reason = match value.reason {
            quiche::StartupExitReason::Loss =>
                datagram_socket::StartupExitReason::Loss,
            quiche::StartupExitReason::BandwidthPlateau =>
                datagram_socket::StartupExitReason::BandwidthPlateau,
            quiche::StartupExitReason::PersistentQueue =>
                datagram_socket::StartupExitReason::PersistentQueue,
            quiche::StartupExitReason::ConservativeSlowStartRounds =>
                datagram_socket::StartupExitReason::ConservativeSlowStartRounds,
        };

        datagram_socket::StartupExit {
            cwnd: value.cwnd,
            bandwidth: value.bandwidth,
            reason,
        }
    }
}

impl AsSocketStats for QuicConnectionStats {
    fn as_socket_stats(&self) -> SocketStats {
        SocketStats {
            pmtu: self
                .path_stats
                .as_ref()
                .map(|p| p.pmtu as u16)
                .unwrap_or_default(),
            rtt_us: self
                .path_stats
                .as_ref()
                .map(|p| p.rtt.as_micros() as i64)
                .unwrap_or_default(),
            min_rtt_us: self
                .path_stats
                .as_ref()
                .and_then(|p| p.min_rtt.map(|x| x.as_micros() as i64))
                .unwrap_or_default(),
            max_rtt_us: self
                .path_stats
                .as_ref()
                .and_then(|p| p.max_rtt.map(|x| x.as_micros() as i64))
                .unwrap_or_default(),
            rtt_var_us: self
                .path_stats
                .as_ref()
                .map(|p| p.rttvar.as_micros() as i64)
                .unwrap_or_default(),
            cwnd: self
                .path_stats
                .as_ref()
                .map(|p| p.cwnd as u64)
                .unwrap_or_default(),
            total_pto_count: self
                .path_stats
                .as_ref()
                .map(|p| p.total_pto_count as u64)
                .unwrap_or_default(),
            packets_sent: self.stats.sent as u64,
            packets_recvd: self.stats.recv as u64,
            packets_lost: self.stats.lost as u64,
            packets_lost_spurious: self.stats.spurious_lost as u64,
            packets_retrans: self.stats.retrans as u64,
            bytes_sent: self.stats.sent_bytes,
            bytes_recvd: self.stats.recv_bytes,
            bytes_lost: self.stats.lost_bytes,
            bytes_retrans: self.stats.stream_retrans_bytes,
            bytes_unsent: 0, /* not implemented yet, kept for compatibility
                              * with TCP */
            delivery_rate: self
                .path_stats
                .as_ref()
                .map(|p| p.delivery_rate)
                .unwrap_or_default(),
            max_bandwidth: self.path_stats.as_ref().and_then(|p| p.max_bandwidth),
            startup_exit: self
                .path_stats
                .as_ref()
                .and_then(|p| p.startup_exit)
                .map(QuicConnectionStats::startup_exit_to_socket_stats),
            bytes_in_flight_duration_us: self
                .stats
                .bytes_in_flight_duration
                .as_micros() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PathEventStats;

    #[test]
    fn records_each_path_event() {
        let local = "127.0.0.1:1234".parse().unwrap();
        let peer = "127.0.0.1:5678".parse().unwrap();
        let migrated_peer = "127.0.0.1:9012".parse().unwrap();
        let mut stats = PathEventStats::default();

        let events = [
            quiche::PathEvent::New(local, peer),
            quiche::PathEvent::Validated(local, peer),
            quiche::PathEvent::FailedValidation(local, peer),
            quiche::PathEvent::Closed(local, peer),
            quiche::PathEvent::ReusedSourceConnectionId(
                0,
                (local, peer),
                (local, migrated_peer),
            ),
            quiche::PathEvent::PeerMigrated(local, migrated_peer),
        ];

        for event in events {
            stats.record(event);
        }

        let expected = PathEventStats {
            new_path_count: 1,
            validated_count: 1,
            failed_validation_count: 1,
            closed_count: 1,
            reused_source_connection_id_count: 1,
            peer_migrated_count: 1,
        };
        assert_eq!(stats, expected);
    }
}
