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

use foundations::settings::settings;
use serde_with::serde_as;
use serde_with::DurationMilliSeconds;
use std::time::Duration;

/// QUIC configuration parameters.
#[serde_as]
#[settings]
#[non_exhaustive]
pub struct QuicSettings {
    /// Configures the list of supported application protocols.
    ///
    /// Defaults to `[b"h3"]`.
    #[serde(skip, default = "QuicSettings::default_alpn")]
    pub alpn: Vec<Vec<u8>>,

    /// Configures whether to enable DATAGRAM frame support. H3 connections
    /// copy this setting from the underlying QUIC connection.
    ///
    /// Defaults to `true`.
    #[serde(default = "QuicSettings::default_enable_dgram")]
    pub enable_dgram: bool,

    /// Max queue length for received DATAGRAM frames.
    ///
    /// Defaults to `2^16`.
    #[serde(default = "QuicSettings::default_dgram_max_queue_len")]
    pub dgram_recv_max_queue_len: usize,

    /// Max queue length for sending DATAGRAM frames.
    ///
    /// Defaults to `2^16`.
    #[serde(default = "QuicSettings::default_dgram_max_queue_len")]
    pub dgram_send_max_queue_len: usize,

    /// Sets the `initial_max_data` transport parameter.
    ///
    /// Defaults to 10 MB.
    #[serde(default = "QuicSettings::default_initial_max_data")]
    pub initial_max_data: u64,

    /// Sets the `initial_max_stream_data_bidi_local` transport parameter.
    ///
    /// Defaults to 1 MB.
    #[serde(default = "QuicSettings::default_initial_max_stream_data")]
    pub initial_max_stream_data_bidi_local: u64,

    /// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
    ///
    /// Defaults to 1 MB.
    #[serde(default = "QuicSettings::default_initial_max_stream_data")]
    pub initial_max_stream_data_bidi_remote: u64,

    /// Sets the `initial_max_stream_data_uni` transport parameter.
    ///
    /// Defaults to 1 MB.
    #[serde(default = "QuicSettings::default_initial_max_stream_data")]
    pub initial_max_stream_data_uni: u64,

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// Defaults to `100`.
    #[serde(default = "QuicSettings::default_initial_max_streams")]
    pub initial_max_streams_bidi: u64,

    /// Sets the `initial_max_streams_uni` transport parameter.
    ///
    /// Defaults to `100`.
    #[serde(default = "QuicSettings::default_initial_max_streams")]
    pub initial_max_streams_uni: u64,

    /// Configures the max idle timeout of the connection in milliseconds. The
    /// real idle timeout is the minimum of this and the peer's
    /// `max_idle_timeout`.
    ///
    /// Defaults to 56 seconds.
    #[serde(
        rename = "max_idle_timeout_ms",
        default = "QuicSettings::default_max_idle_timeout"
    )]
    #[serde_as(as = "Option<DurationMilliSeconds>")]
    pub max_idle_timeout: Option<Duration>,

    /// Configures whether the local endpoint supports active connection
    /// migration.
    ///
    /// Defaults to `true` (meaning disabled).
    #[serde(default = "QuicSettings::default_disable_active_migration")]
    pub disable_active_migration: bool,

    /// Sets the `active_connection_id_limit` transport parameter.
    ///
    /// Defaults to 2. Note that values less than 2 will be ignored.
    #[serde(default = "QuicSettings::default_active_connection_id_limit")]
    pub active_connection_id_limit: u64,

    /// Sets the maximum incoming UDP payload size.
    ///
    /// Defaults to 1350 bytes.
    #[serde(default = "QuicSettings::default_max_recv_udp_payload_size")]
    pub max_recv_udp_payload_size: usize,

    /// Sets the maximum outgoing UDP payload size.
    ///
    /// Defaults to 1350 bytes.
    #[serde(default = "QuicSettings::default_max_send_udp_payload_size")]
    pub max_send_udp_payload_size: usize,

    /// Whether to validate client IPs in QUIC initials.
    ///
    /// If set to `true`, any received QUIC initial will immediately spawn a
    /// connection and start crypto operations for the handshake. Otherwise,
    /// the client is asked to execute a stateless retry first (the default).
    pub disable_client_ip_validation: bool,

    /// Path to a file in which TLS secrets will be logged in
    /// [SSLKEYLOGFILE format](https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html).
    pub keylog_file: Option<String>,

    /// Path to a directory where QLOG files will be saved.
    pub qlog_dir: Option<String>,

    /// Congestion control algorithm to use.
    ///
    /// For available values, see
    /// [`CongestionControlAlgorithm`](quiche::CongestionControlAlgorithm).
    ///
    /// Defaults to `cubic`.
    #[serde(default = "QuicSettings::default_cc_algorithm")]
    pub cc_algorithm: String,

    /// The default initial congestion window size in terms of packet count.
    ///
    /// Defaults to 10.
    #[serde(default = "QuicSettings::default_initial_congestion_window_packets")]
    pub initial_congestion_window_packets: usize,

    /// Configures whether to enable relaxed loss detection on spurious loss.
    ///
    /// Defaults to `false`.
    pub enable_relaxed_loss_threshold: bool,

    /// Configures whether to do path MTU discovery.
    ///
    /// Defaults to `false`.
    pub discover_path_mtu: bool,

    /// Whether to use HyStart++ (only with `cubic` and `reno` CC).
    ///
    /// Defaults to `true`.
    #[serde(default = "QuicSettings::default_enable_hystart")]
    pub enable_hystart: bool,

    /// Optionally enables pacing for outgoing packets.
    ///
    /// Note: this also requires pacing-compatible
    /// [`SocketCapabilities`](crate::socket::SocketCapabilities).
    pub enable_pacing: bool,

    /// Sets the max value for pacing rate.
    ///
    /// By default, there is no limit.
    pub max_pacing_rate: Option<u64>,

    /// Optionally enables expensive versions of the
    /// `accepted_initial_quic_packet_count`
    /// and `rejected_initial_quic_packet_count` metrics.
    ///
    /// The expensive versions add a label for the peer IP subnet (`/24` for
    /// IPv4, `/32` for IPv6). They thus generate many more time series if
    /// peers are arbitrary eyeballs from the global Internet.
    pub enable_expensive_packet_count_metrics: bool,

    /// Forwards [`quiche`] logs into the logging system currently used by
    /// [`foundations`].
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    /// This should **only be used for local debugging**. `quiche` can emit lots
    /// (and lots, and lots) of logs (the TRACE level emits a log record for
    /// every packet and frame) and you can very easily overwhelm your
    /// logging pipeline.
    pub capture_quiche_logs: bool,

    /// A timeout for the QUIC handshake, in milliseconds.
    ///
    /// Disabled by default.
    #[serde(rename = "handshake_timeout_ms")]
    #[serde_as(as = "Option<DurationMilliSeconds>")]
    pub handshake_timeout: Option<Duration>,

    /// The maximum number of newly-created connections that will be queued for
    /// the application to receive. Not applicable to client-side usage.
    ///
    /// Defaults to 1024 connections.
    #[serde(default = "QuicSettings::default_listen_backlog")]
    pub listen_backlog: usize,

    /// Whether or not to verify the peer's certificate.
    ///
    /// Defaults to `false`, meaning no peer verification is performed. Note
    /// that clients should usually set this value to `true` - see
    /// [`verify_peer()`] for more.
    ///
    /// [`verify_peer()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.verify_peer
    pub verify_peer: bool,

    /// The maximum size of the receiver connection flow control window.
    ///
    /// Defaults to 24MB.
    #[serde(default = "QuicSettings::default_max_connection_window")]
    pub max_connection_window: u64,

    /// The maximum size of the receiveer stream flow control window.
    ///
    /// Defaults to 16MB.
    #[serde(default = "QuicSettings::default_max_stream_window")]
    pub max_stream_window: u64,

    /// Configures whether to send GREASE values.
    ///
    /// Defaults to true.
    #[serde(default = "QuicSettings::default_grease")]
    pub grease: bool,

    /// Sets the anti-amplification limit factor.
    ///
    /// Defaults to 3.
    #[serde(default = "QuicSettings::default_amplification_factor")]
    pub max_amplification_factor: usize,

    /// Sets the send capacity factor.
    ///
    /// A factor greater than 1 allows the connection to buffer more outbound
    /// data than can be sent at this moment. This can improve throughput by
    /// reducing time spent waiting for new data.
    ///
    /// Defaults to 1.
    #[serde(default = "QuicSettings::default_send_capacity_factor")]
    pub send_capacity_factor: f64,

    /// Sets the `ack_delay_exponent` transport parameter.
    ///
    /// Defaults to 3.
    #[serde(default = "QuicSettings::default_ack_delay_exponent")]
    pub ack_delay_exponent: u64,

    /// Sets the `max_ack_delay` transport parameter.
    ///
    /// Defaults to 25.
    #[serde(default = "QuicSettings::default_max_ack_delay")]
    pub max_ack_delay: u64,

    /// Configures the max number of queued received PATH_CHALLENGE frames.
    ///
    /// Defaults to 3.
    #[serde(default = "QuicSettings::default_max_path_challenge_recv_queue_len")]
    pub max_path_challenge_recv_queue_len: usize,

    /// Sets the initial stateless reset token.
    ///
    /// Note that this applies only to server-side connections - on client-side
    /// connections, this is a no-op.
    ///
    /// Defaults to `None`.
    pub stateless_reset_token: Option<u128>,

    /// Sets whether the QUIC connection should avoid reusing DCIDs over
    /// different paths.
    ///
    /// Defaults to `false`. See [`set_disable_dcid_reuse()`] for more.
    ///
    /// [`set_disable_dcid_reuse()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.disable_dcid_reuse
    pub disable_dcid_reuse: bool,

    /// Specifies the number of bytes used to track unknown transport
    /// parameters.
    ///
    /// Defaults to `None`, e.g., unknown transport parameters will not be
    /// tracked. See [`enable_track_unknown_transport_parameters()`] for
    /// more.
    ///
    /// [`enable_track_unknown_transport_parameters()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.enable_track_unknown_transport_parameters
    pub track_unknown_transport_parameters: Option<usize>,
}

impl QuicSettings {
    #[inline]
    fn default_alpn() -> Vec<Vec<u8>> {
        quiche::h3::APPLICATION_PROTOCOL
            .iter()
            .map(|v| v.to_vec())
            .collect()
    }

    #[inline]
    fn default_enable_dgram() -> bool {
        true
    }

    #[inline]
    fn default_dgram_max_queue_len() -> usize {
        65536
    }

    #[inline]
    fn default_initial_max_data() -> u64 {
        10_000_000
    }

    #[inline]
    fn default_initial_max_stream_data() -> u64 {
        1_000_000
    }

    #[inline]
    fn default_initial_max_streams() -> u64 {
        100
    }

    #[inline]
    fn default_max_idle_timeout() -> Option<Duration> {
        Some(Duration::from_secs(56))
    }

    #[inline]
    fn default_max_recv_udp_payload_size() -> usize {
        1350
    }

    #[inline]
    fn default_max_send_udp_payload_size() -> usize {
        1350
    }

    #[inline]
    fn default_disable_active_migration() -> bool {
        true
    }

    #[inline]
    fn default_cc_algorithm() -> String {
        "cubic".to_string()
    }

    #[inline]
    fn default_initial_congestion_window_packets() -> usize {
        10
    }

    #[inline]
    fn default_enable_hystart() -> bool {
        true
    }

    #[inline]
    fn default_listen_backlog() -> usize {
        // Given a worst-case 1 minute handshake timeout and up to 4096 concurrent
        // handshakes, we will dequeue at least 70 connections per second.
        // This means this backlog size limits the queueing latency to
        // ~15s.
        1024
    }

    #[inline]
    fn default_max_connection_window() -> u64 {
        24 * 1024 * 1024
    }

    #[inline]
    fn default_max_stream_window() -> u64 {
        16 * 1024 * 1024
    }

    #[inline]
    fn default_grease() -> bool {
        true
    }

    #[inline]
    fn default_amplification_factor() -> usize {
        3
    }

    #[inline]
    fn default_send_capacity_factor() -> f64 {
        1.0
    }

    #[inline]
    fn default_ack_delay_exponent() -> u64 {
        3
    }

    #[inline]
    fn default_max_ack_delay() -> u64 {
        25
    }

    #[inline]
    fn default_active_connection_id_limit() -> u64 {
        2
    }

    #[inline]
    fn default_max_path_challenge_recv_queue_len() -> usize {
        3
    }
}

#[cfg(test)]
mod test {
    use super::QuicSettings;
    use std::time::Duration;

    #[test]
    fn timeouts_parse_as_milliseconds() {
        let quic = serde_json::from_str::<QuicSettings>(
            r#"{ "handshake_timeout_ms": 5000, "max_idle_timeout_ms": 7000 }"#,
        )
        .unwrap();

        assert_eq!(quic.handshake_timeout.unwrap(), Duration::from_secs(5));
        assert_eq!(quic.max_idle_timeout.unwrap(), Duration::from_secs(7));
    }
}
