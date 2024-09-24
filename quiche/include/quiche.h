// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

#ifndef QUICHE_H
#define QUICHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#endif

#ifdef __unix__
#include <sys/types.h>
#endif
#ifdef _MSC_VER
#include <BaseTsd.h>
#define ssize_t SSIZE_T
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// QUIC transport API.
//

// The current QUIC wire version.
#define QUICHE_PROTOCOL_VERSION 0x00000001

// The maximum length of a connection ID.
#define QUICHE_MAX_CONN_ID_LEN 20

// The minimum length of Initial packets sent by a client.
#define QUICHE_MIN_CLIENT_INITIAL_LEN 1200

enum quiche_error {
    // There is no more work to do.
    QUICHE_ERR_DONE = -1,

    // The provided buffer is too short.
    QUICHE_ERR_BUFFER_TOO_SHORT = -2,

    // The provided packet cannot be parsed because its version is unknown.
    QUICHE_ERR_UNKNOWN_VERSION = -3,

    // The provided packet cannot be parsed because it contains an invalid
    // frame.
    QUICHE_ERR_INVALID_FRAME = -4,

    // The provided packet cannot be parsed.
    QUICHE_ERR_INVALID_PACKET = -5,

    // The operation cannot be completed because the connection is in an
    // invalid state.
    QUICHE_ERR_INVALID_STATE = -6,

    // The operation cannot be completed because the stream is in an
    // invalid state.
    QUICHE_ERR_INVALID_STREAM_STATE = -7,

    // The peer's transport params cannot be parsed.
    QUICHE_ERR_INVALID_TRANSPORT_PARAM = -8,

    // A cryptographic operation failed.
    QUICHE_ERR_CRYPTO_FAIL = -9,

    // The TLS handshake failed.
    QUICHE_ERR_TLS_FAIL = -10,

    // The peer violated the local flow control limits.
    QUICHE_ERR_FLOW_CONTROL = -11,

    // The peer violated the local stream limits.
    QUICHE_ERR_STREAM_LIMIT = -12,

    // The specified stream was stopped by the peer.
    QUICHE_ERR_STREAM_STOPPED = -15,

    // The specified stream was reset by the peer.
    QUICHE_ERR_STREAM_RESET = -16,

    // The received data exceeds the stream's final size.
    QUICHE_ERR_FINAL_SIZE = -13,

    // Error in congestion control.
    QUICHE_ERR_CONGESTION_CONTROL = -14,

    // Too many identifiers were provided.
    QUICHE_ERR_ID_LIMIT = -17,

    // Not enough available identifiers.
    QUICHE_ERR_OUT_OF_IDENTIFIERS = -18,

    // Error in key update.
    QUICHE_ERR_KEY_UPDATE = -19,

    // The peer sent more data in CRYPTO frames than we can buffer.
    QUICHE_ERR_CRYPTO_BUFFER_EXCEEDED = -20,
};

// Returns a human readable string with the quiche version number.
const char *quiche_version(void);

// Enables logging. |cb| will be called with log messages
int quiche_enable_debug_logging(void (*cb)(const char *line, void *argp),
                                void *argp);

// Stores configuration shared between multiple connections.
typedef struct quiche_config quiche_config;

// Creates a config object with the given version.
quiche_config *quiche_config_new(uint32_t version);

// Configures the given certificate chain.
int quiche_config_load_cert_chain_from_pem_file(quiche_config *config,
                                                const char *path);

// Configures the given private key.
int quiche_config_load_priv_key_from_pem_file(quiche_config *config,
                                              const char *path);

// Specifies a file where trusted CA certificates are stored for the purposes of certificate verification.
int quiche_config_load_verify_locations_from_file(quiche_config *config,
                                                  const char *path);

// Specifies a directory where trusted CA certificates are stored for the purposes of certificate verification.
int quiche_config_load_verify_locations_from_directory(quiche_config *config,
                                                       const char *path);

// Configures whether to verify the peer's certificate.
void quiche_config_verify_peer(quiche_config *config, bool v);

// Configures whether to send GREASE.
void quiche_config_grease(quiche_config *config, bool v);

// Configures whether to do path MTU discovery.
void quiche_config_discover_pmtu(quiche_config *config, bool v);

// Enables logging of secrets.
void quiche_config_log_keys(quiche_config *config);

// Enables sending or receiving early data.
void quiche_config_enable_early_data(quiche_config *config);

// Configures the list of supported application protocols.
int quiche_config_set_application_protos(quiche_config *config,
                                         const uint8_t *protos,
                                         size_t protos_len);

// Sets the anti-amplification limit factor.
void quiche_config_set_max_amplification_factor(quiche_config *config, size_t v);

// Sets the `max_idle_timeout` transport parameter, in milliseconds, default is
// no timeout.
void quiche_config_set_max_idle_timeout(quiche_config *config, uint64_t v);

// Sets the `max_udp_payload_size transport` parameter.
void quiche_config_set_max_recv_udp_payload_size(quiche_config *config, size_t v);

// Sets the maximum outgoing UDP payload size.
void quiche_config_set_max_send_udp_payload_size(quiche_config *config, size_t v);

// Sets the `initial_max_data` transport parameter.
void quiche_config_set_initial_max_data(quiche_config *config, uint64_t v);

// Sets the `initial_max_stream_data_bidi_local` transport parameter.
void quiche_config_set_initial_max_stream_data_bidi_local(quiche_config *config, uint64_t v);

// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
void quiche_config_set_initial_max_stream_data_bidi_remote(quiche_config *config, uint64_t v);

// Sets the `initial_max_stream_data_uni` transport parameter.
void quiche_config_set_initial_max_stream_data_uni(quiche_config *config, uint64_t v);

// Sets the `initial_max_streams_bidi` transport parameter.
void quiche_config_set_initial_max_streams_bidi(quiche_config *config, uint64_t v);

// Sets the `initial_max_streams_uni` transport parameter.
void quiche_config_set_initial_max_streams_uni(quiche_config *config, uint64_t v);

// Sets the `ack_delay_exponent` transport parameter.
void quiche_config_set_ack_delay_exponent(quiche_config *config, uint64_t v);

// Sets the `max_ack_delay` transport parameter.
void quiche_config_set_max_ack_delay(quiche_config *config, uint64_t v);

// Sets the `disable_active_migration` transport parameter.
void quiche_config_set_disable_active_migration(quiche_config *config, bool v);

// Sets the congestion control algorithm used by string.
int quiche_config_set_cc_algorithm_name(quiche_config *config, const char *algo);

// Sets the initial cwnd for the connection in terms of packet count.
void quiche_config_set_initial_congestion_window_packets(quiche_config *config, size_t packets);

enum quiche_cc_algorithm {
    QUICHE_CC_RENO = 0,
    QUICHE_CC_CUBIC = 1,
    QUICHE_CC_BBR = 2,
    QUICHE_CC_BBR2 = 3,
};

// Sets the congestion control algorithm used.
void quiche_config_set_cc_algorithm(quiche_config *config, enum quiche_cc_algorithm algo);

// Configures whether to use HyStart++.
void quiche_config_enable_hystart(quiche_config *config, bool v);

// Configures whether to enable pacing (enabled by default).
void quiche_config_enable_pacing(quiche_config *config, bool v);

// Configures max pacing rate to be used.
void quiche_config_set_max_pacing_rate(quiche_config *config, uint64_t v);

// Configures whether to enable receiving DATAGRAM frames.
void quiche_config_enable_dgram(quiche_config *config, bool enabled,
                                size_t recv_queue_len,
                                size_t send_queue_len);

// Sets the maximum connection window.
void quiche_config_set_max_connection_window(quiche_config *config, uint64_t v);

// Sets the maximum stream window.
void quiche_config_set_max_stream_window(quiche_config *config, uint64_t v);

// Sets the limit of active connection IDs.
void quiche_config_set_active_connection_id_limit(quiche_config *config, uint64_t v);

// Sets the initial stateless reset token. |v| must contain 16 bytes, otherwise the behaviour is undefined.
void quiche_config_set_stateless_reset_token(quiche_config *config, const uint8_t *v);

// Sets whether the QUIC connection should avoid reusing DCIDs over different paths.
void quiche_config_set_disable_dcid_reuse(quiche_config *config, bool v);

// Configures the session ticket key material.
int quiche_config_set_ticket_key(quiche_config *config, const uint8_t *key, size_t key_len);

// Frees the config object.
void quiche_config_free(quiche_config *config);

// Extracts version, type, source / destination connection ID and address
// verification token from the packet in |buf|.
int quiche_header_info(const uint8_t *buf, size_t buf_len, size_t dcil,
                       uint32_t *version, uint8_t *type,
                       uint8_t *scid, size_t *scid_len,
                       uint8_t *dcid, size_t *dcid_len,
                       uint8_t *token, size_t *token_len);

// A QUIC connection.
typedef struct quiche_conn quiche_conn;

// Creates a new server-side connection.
quiche_conn *quiche_accept(const uint8_t *scid, size_t scid_len,
                           const uint8_t *odcid, size_t odcid_len,
                           const struct sockaddr *local, socklen_t local_len,
                           const struct sockaddr *peer, socklen_t peer_len,
                           quiche_config *config);

// Creates a new client-side connection.
quiche_conn *quiche_connect(const char *server_name,
                            const uint8_t *scid, size_t scid_len,
                            const struct sockaddr *local, socklen_t local_len,
                            const struct sockaddr *peer, socklen_t peer_len,
                            quiche_config *config);

// Writes a version negotiation packet.
ssize_t quiche_negotiate_version(const uint8_t *scid, size_t scid_len,
                                 const uint8_t *dcid, size_t dcid_len,
                                 uint8_t *out, size_t out_len);

// Writes a retry packet.
ssize_t quiche_retry(const uint8_t *scid, size_t scid_len,
                     const uint8_t *dcid, size_t dcid_len,
                     const uint8_t *new_scid, size_t new_scid_len,
                     const uint8_t *token, size_t token_len,
                     uint32_t version, uint8_t *out, size_t out_len);

// Returns true if the given protocol version is supported.
bool quiche_version_is_supported(uint32_t version);

quiche_conn *quiche_conn_new_with_tls(const uint8_t *scid, size_t scid_len,
                                      const uint8_t *odcid, size_t odcid_len,
                                      const struct sockaddr *local, socklen_t local_len,
                                      const struct sockaddr *peer, socklen_t peer_len,
                                      const quiche_config *config, void *ssl,
                                      bool is_server);

// Enables keylog to the specified file path. Returns true on success.
bool quiche_conn_set_keylog_path(quiche_conn *conn, const char *path);

// Enables keylog to the specified file descriptor. Unix only.
void quiche_conn_set_keylog_fd(quiche_conn *conn, int fd);

// Enables qlog to the specified file path. Returns true on success.
bool quiche_conn_set_qlog_path(quiche_conn *conn, const char *path,
                          const char *log_title, const char *log_desc);

// Enables qlog to the specified file descriptor. Unix only.
void quiche_conn_set_qlog_fd(quiche_conn *conn, int fd, const char *log_title,
                             const char *log_desc);

// Configures the given session for resumption.
int quiche_conn_set_session(quiche_conn *conn, const uint8_t *buf, size_t buf_len);

typedef struct {
    // The remote address the packet was received from.
    struct sockaddr *from;
    socklen_t from_len;

    // The local address the packet was received on.
    struct sockaddr *to;
    socklen_t to_len;
} quiche_recv_info;

// Processes QUIC packets received from the peer.
ssize_t quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len,
                         const quiche_recv_info *info);

typedef struct {
    // The local address the packet should be sent from.
    struct sockaddr_storage from;
    socklen_t from_len;

    // The remote address the packet should be sent to.
    struct sockaddr_storage to;
    socklen_t to_len;

    // The time to send the packet out.
    struct timespec at;
} quiche_send_info;

// Writes a single QUIC packet to be sent to the peer.
ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len,
                         quiche_send_info *out_info);

// Returns the size of the send quantum, in bytes.
size_t quiche_conn_send_quantum(const quiche_conn *conn);

// Writes a single QUIC packet to be sent to the peer from the specified
// local address "from" to the destination address "to".
ssize_t quiche_conn_send_on_path(quiche_conn *conn, uint8_t *out, size_t out_len,
                                 const struct sockaddr *from, socklen_t from_len,
                                 const struct sockaddr *to, socklen_t to_len,
                                 quiche_send_info *out_info);

// Returns the size of the send quantum over the given 4-tuple, in bytes.
size_t quiche_conn_send_quantum_on_path(const quiche_conn *conn,
                                        const struct sockaddr *local_addr, socklen_t local_len,
                                        const struct sockaddr *peer_addr, socklen_t peer_len);


// Reads contiguous data from a stream.
// out_error_code is only set when STREAM_STOPPED or STREAM_RESET are returned.
// Set to the reported error code associated with STOP_SENDING or STREAM_RESET.
ssize_t quiche_conn_stream_recv(quiche_conn *conn, uint64_t stream_id,
                                uint8_t *out, size_t buf_len, bool *fin,
                                uint64_t *out_error_code);

// Writes data to a stream.
// out_error_code is only set when STREAM_STOPPED or STREAM_RESET are returned.
// Set to the reported error code associated with STOP_SENDING or STREAM_RESET.
ssize_t quiche_conn_stream_send(quiche_conn *conn, uint64_t stream_id,
                                const uint8_t *buf, size_t buf_len, bool fin,
                                uint64_t *out_error_code);

// The side of the stream to be shut down.
enum quiche_shutdown {
    QUICHE_SHUTDOWN_READ = 0,
    QUICHE_SHUTDOWN_WRITE = 1,
};

// Sets the priority for a stream.
int quiche_conn_stream_priority(quiche_conn *conn, uint64_t stream_id,
                                uint8_t urgency, bool incremental);

// Shuts down reading or writing from/to the specified stream.
int quiche_conn_stream_shutdown(quiche_conn *conn, uint64_t stream_id,
                                enum quiche_shutdown direction, uint64_t err);

// Returns the stream's send capacity in bytes.
ssize_t quiche_conn_stream_capacity(const quiche_conn *conn, uint64_t stream_id);

// Returns true if the stream has data that can be read.
bool quiche_conn_stream_readable(const quiche_conn *conn, uint64_t stream_id);

// Returns the next stream that has data to read, or -1 if no such stream is
// available.
int64_t quiche_conn_stream_readable_next(quiche_conn *conn);

// Returns true if the stream has enough send capacity.
//
// On error a value lower than 0 is returned.
int quiche_conn_stream_writable(quiche_conn *conn, uint64_t stream_id, size_t len);

// Returns the next stream that can be written to, or -1 if no such stream is
// available.
int64_t quiche_conn_stream_writable_next(quiche_conn *conn);

// Returns true if all the data has been read from the specified stream.
bool quiche_conn_stream_finished(const quiche_conn *conn, uint64_t stream_id);

typedef struct quiche_stream_iter quiche_stream_iter;

// Returns an iterator over streams that have outstanding data to read.
quiche_stream_iter *quiche_conn_readable(const quiche_conn *conn);

// Returns an iterator over streams that can be written to.
quiche_stream_iter *quiche_conn_writable(const quiche_conn *conn);

// Returns the maximum possible size of egress UDP payloads.
size_t quiche_conn_max_send_udp_payload_size(const quiche_conn *conn);

// Returns the amount of time until the next timeout event, in nanoseconds.
uint64_t quiche_conn_timeout_as_nanos(const quiche_conn *conn);

// Returns the amount of time until the next timeout event, in milliseconds.
uint64_t quiche_conn_timeout_as_millis(const quiche_conn *conn);

// Processes a timeout event.
void quiche_conn_on_timeout(quiche_conn *conn);

// Closes the connection with the given error and reason.
int quiche_conn_close(quiche_conn *conn, bool app, uint64_t err,
                      const uint8_t *reason, size_t reason_len);

// Returns a string uniquely representing the connection.
void quiche_conn_trace_id(const quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the source connection ID.
void quiche_conn_source_id(const quiche_conn *conn, const uint8_t **out, size_t *out_len);

typedef struct quiche_connection_id_iter quiche_connection_id_iter;

// Returns all active source connection IDs.
quiche_connection_id_iter *quiche_conn_source_ids(quiche_conn *conn);

// Fetches the next id from the given iterator. Returns false if there are
// no more elements in the iterator.
bool quiche_connection_id_iter_next(quiche_connection_id_iter *iter,  const uint8_t **out, size_t *out_len);

// Frees the given path iterator object.
void quiche_connection_id_iter_free(quiche_connection_id_iter *iter);

// Returns the destination connection ID.
void quiche_conn_destination_id(const quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the negotiated ALPN protocol.
void quiche_conn_application_proto(const quiche_conn *conn, const uint8_t **out,
                                   size_t *out_len);

// Returns the peer's leaf certificate (if any) as a DER-encoded buffer.
void quiche_conn_peer_cert(const quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the serialized cryptographic session for the connection.
void quiche_conn_session(const quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns true if the connection handshake is complete.
bool quiche_conn_is_established(const quiche_conn *conn);

// Returns true if the connection is resumed.
bool quiche_conn_is_resumed(const quiche_conn *conn);

// Returns true if the connection has a pending handshake that has progressed
// enough to send or receive early data.
bool quiche_conn_is_in_early_data(const quiche_conn *conn);

// Returns whether there is stream or DATAGRAM data available to read.
bool quiche_conn_is_readable(const quiche_conn *conn);

// Returns true if the connection is draining.
bool quiche_conn_is_draining(const quiche_conn *conn);

// Returns the number of bidirectional streams that can be created
// before the peer's stream count limit is reached.
uint64_t quiche_conn_peer_streams_left_bidi(const quiche_conn *conn);

// Returns the number of unidirectional streams that can be created
// before the peer's stream count limit is reached.
uint64_t quiche_conn_peer_streams_left_uni(const quiche_conn *conn);

// Returns true if the connection is closed.
bool quiche_conn_is_closed(const quiche_conn *conn);

// Returns true if the connection was closed due to the idle timeout.
bool quiche_conn_is_timed_out(const quiche_conn *conn);

// Returns true if a connection error was received, and updates the provided
// parameters accordingly.
bool quiche_conn_peer_error(const quiche_conn *conn,
                            bool *is_app,
                            uint64_t *error_code,
                            const uint8_t **reason,
                            size_t *reason_len);

// Returns true if a connection error was queued or sent, and updates the provided
// parameters accordingly.
bool quiche_conn_local_error(const quiche_conn *conn,
                             bool *is_app,
                             uint64_t *error_code,
                             const uint8_t **reason,
                             size_t *reason_len);

// Fetches the next stream from the given iterator. Returns false if there are
// no more elements in the iterator.
bool quiche_stream_iter_next(quiche_stream_iter *iter, uint64_t *stream_id);

// Frees the given stream iterator object.
void quiche_stream_iter_free(quiche_stream_iter *iter);

typedef struct {
    // The number of QUIC packets received on this connection.
    size_t recv;

    // The number of QUIC packets sent on this connection.
    size_t sent;

    // The number of QUIC packets that were lost.
    size_t lost;

    // The number of sent QUIC packets with retransmitted data.
    size_t retrans;

    // The number of sent bytes.
    uint64_t sent_bytes;

    // The number of received bytes.
    uint64_t recv_bytes;

    // The number of bytes acked.
    uint64_t acked_bytes;

    // The number of bytes lost.
    uint64_t lost_bytes;

    // The number of stream bytes retransmitted.
    uint64_t stream_retrans_bytes;

    // The number of known paths for the connection.
    size_t paths_count;

    // The number of streams reset by local.
    uint64_t reset_stream_count_local;

    // The number of streams stopped by local.
    uint64_t stopped_stream_count_local;

    // The number of streams reset by remote.
    uint64_t reset_stream_count_remote;

    // The number of streams stopped by remote.
    uint64_t stopped_stream_count_remote;
} quiche_stats;

// Collects and returns statistics about the connection.
void quiche_conn_stats(const quiche_conn *conn, quiche_stats *out);

typedef struct {
    // The maximum idle timeout.
    uint64_t peer_max_idle_timeout;

    // The maximum UDP payload size.
    uint64_t peer_max_udp_payload_size;

    // The initial flow control maximum data for the connection.
    uint64_t peer_initial_max_data;

    // The initial flow control maximum data for local bidirectional streams.
    uint64_t peer_initial_max_stream_data_bidi_local;

    // The initial flow control maximum data for remote bidirectional streams.
    uint64_t peer_initial_max_stream_data_bidi_remote;

    // The initial flow control maximum data for unidirectional streams.
    uint64_t peer_initial_max_stream_data_uni;

    // The initial maximum bidirectional streams.
    uint64_t peer_initial_max_streams_bidi;

    // The initial maximum unidirectional streams.
    uint64_t peer_initial_max_streams_uni;

    // The ACK delay exponent.
    uint64_t peer_ack_delay_exponent;

    // The max ACK delay.
    uint64_t peer_max_ack_delay;

    // Whether active migration is disabled.
    bool peer_disable_active_migration;

    // The active connection ID limit.
    uint64_t peer_active_conn_id_limit;

    // DATAGRAM frame extension parameter, if any.
    ssize_t peer_max_datagram_frame_size;
} quiche_transport_params;

// Returns the peer's transport parameters in |out|. Returns false if we have
// not yet processed the peer's transport parameters.
bool quiche_conn_peer_transport_params(const quiche_conn *conn, quiche_transport_params *out);

typedef struct {
    // The local address used by this path.
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;

    // The peer address seen by this path.
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    // The validation state of the path.
    ssize_t validation_state;

    // Whether this path is active.
    bool active;

    // The number of QUIC packets received on this path.
    size_t recv;

    // The number of QUIC packets sent on this path.
    size_t sent;

    // The number of QUIC packets that were lost on this path.
    size_t lost;

    // The number of sent QUIC packets with retransmitted data on this path.
    size_t retrans;

    // The estimated round-trip time of the path (in nanoseconds).
    uint64_t rtt;

    // The size of the path's congestion window in bytes.
    size_t cwnd;

    // The number of sent bytes on this path.
    uint64_t sent_bytes;

    // The number of received bytes on this path.
    uint64_t recv_bytes;

    // The number of bytes lost on this path.
    uint64_t lost_bytes;

    // The number of stream bytes retransmitted on this path.
    uint64_t stream_retrans_bytes;

    // The current PMTU for the path.
    size_t pmtu;

    // The most recent data delivery rate estimate in bytes/s.
    uint64_t delivery_rate;
} quiche_path_stats;


// Collects and returns statistics about the specified path for the connection.
//
// The `idx` argument represent the path's index (also see the `paths_count`
// field of `quiche_stats`).
int quiche_conn_path_stats(const quiche_conn *conn, size_t idx, quiche_path_stats *out);

// Returns whether or not this is a server-side connection.
bool quiche_conn_is_server(const quiche_conn *conn);

// Returns the maximum DATAGRAM payload that can be sent.
ssize_t quiche_conn_dgram_max_writable_len(const quiche_conn *conn);

// Returns the length of the first stored DATAGRAM.
ssize_t quiche_conn_dgram_recv_front_len(const quiche_conn *conn);

// Returns the number of items in the DATAGRAM receive queue.
ssize_t quiche_conn_dgram_recv_queue_len(const quiche_conn *conn);

// Returns the total size of all items in the DATAGRAM receive queue.
ssize_t quiche_conn_dgram_recv_queue_byte_size(const quiche_conn *conn);

// Returns the number of items in the DATAGRAM send queue.
ssize_t quiche_conn_dgram_send_queue_len(const quiche_conn *conn);

// Returns the total size of all items in the DATAGRAM send queue.
ssize_t quiche_conn_dgram_send_queue_byte_size(const quiche_conn *conn);

// Reads the first received DATAGRAM.
ssize_t quiche_conn_dgram_recv(quiche_conn *conn, uint8_t *buf,
                               size_t buf_len);

// Sends data in a DATAGRAM frame.
ssize_t quiche_conn_dgram_send(quiche_conn *conn, const uint8_t *buf,
                               size_t buf_len);

// Purges queued outgoing DATAGRAMs matching the predicate.
void quiche_conn_dgram_purge_outgoing(quiche_conn *conn,
                                      bool (*f)(uint8_t *, size_t));

// Returns whether or not the DATAGRAM send queue is full.
bool quiche_conn_is_dgram_send_queue_full(const quiche_conn *conn);

// Returns whether or not the DATAGRAM recv queue is full.
bool quiche_conn_is_dgram_recv_queue_full(const quiche_conn *conn);

// Schedule an ack-eliciting packet on the active path.
ssize_t quiche_conn_send_ack_eliciting(quiche_conn *conn);

// Schedule an ack-eliciting packet on the specified path.
ssize_t quiche_conn_send_ack_eliciting_on_path(quiche_conn *conn,
                           const struct sockaddr *local, socklen_t local_len,
                           const struct sockaddr *peer, socklen_t peer_len);

// Returns true if there are retired source connection ids and fill the parameters
bool quiche_conn_retired_scid_next(const quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the number of source Connection IDs that are retired.
size_t quiche_conn_retired_scids(const quiche_conn *conn);

// Returns the number of spare Destination Connection IDs, i.e.,
// Destination Connection IDs that are still unused.
size_t quiche_conn_available_dcids(const quiche_conn *conn);

// Returns the number of source Connection IDs that should be provided
// to the peer without exceeding the limit it advertised.
size_t quiche_conn_scids_left(quiche_conn *conn);

// Returns the number of source Connection IDs that are active. This is
// only meaningful if the host uses non-zero length Source Connection IDs.
size_t quiche_conn_active_scids(quiche_conn *conn);

// Provides additional source Connection IDs that the peer can use to reach
// this host. Writes the sequence number to "scid_seq" and returns 0.
int quiche_conn_new_scid(quiche_conn *conn,
                           const uint8_t *scid, size_t scid_len,
                           const uint8_t *reset_token, bool retire_if_needed, uint64_t *scid_seq);

// Requests the stack to perform path validation of the proposed 4-tuple.
int quiche_conn_probe_path(quiche_conn *conn,
                                const struct sockaddr *local, socklen_t local_len,
                                const struct sockaddr *peer, socklen_t peer_len, uint64_t *seq);

// Migrates the connection to a new local address.
int quiche_conn_migrate_source(quiche_conn *conn, const struct sockaddr *local, socklen_t local_len, uint64_t *seq);

// Migrates the connection over the given network path between "local"
// and "peer".
int quiche_conn_migrate(quiche_conn *conn,
                             const struct sockaddr *local, socklen_t local_len,
                             const struct sockaddr *peer, socklen_t peer_len,
                             uint64_t *seq);

enum quiche_path_event_type {
    QUICHE_PATH_EVENT_NEW,
    QUICHE_PATH_EVENT_VALIDATED,
    QUICHE_PATH_EVENT_FAILED_VALIDATION,
    QUICHE_PATH_EVENT_CLOSED,
    QUICHE_PATH_EVENT_REUSED_SOURCE_CONNECTION_ID,
    QUICHE_PATH_EVENT_PEER_MIGRATED,
};

typedef struct quiche_path_event quiche_path_event;

// Retrieves the next event. Returns NULL if there is no event to process.
const quiche_path_event *quiche_conn_path_event_next(quiche_conn *conn);

// Returns the type of the event.
enum quiche_path_event_type quiche_path_event_type(quiche_path_event *ev);

// Should be called if the quiche_path_event_type(...) returns QUICHE_PATH_EVENT_NEW.
void quiche_path_event_new(quiche_path_event *ev,
                           struct sockaddr_storage *local, socklen_t *local_len, struct sockaddr_storage *peer, socklen_t *peer_len);

// Should be called if the quiche_path_event_type(...) returns QUICHE_PATH_EVENT_VALIDATED.
void quiche_path_event_validated(quiche_path_event *ev,
                           struct sockaddr_storage *local, socklen_t *local_len, struct sockaddr_storage *peer, socklen_t *peer_len);

// Should be called if the quiche_path_event_type(...) returns QUICHE_PATH_EVENT_FAILED_VALIDATION.
void quiche_path_event_failed_validation(quiche_path_event *ev,
                           struct sockaddr_storage *local, socklen_t *local_len, struct sockaddr_storage *peer, socklen_t *peer_len);

// Should be called if the quiche_path_event_type(...) returns QUICHE_PATH_EVENT_CLOSED.
void quiche_path_event_closed(quiche_path_event *ev,
                           struct sockaddr_storage *local, socklen_t *local_len, struct sockaddr_storage *peer, socklen_t *peer_len);

// Should be called if the quiche_path_event_type(...) returns QUICHE_PATH_EVENT_REUSED_SOURCE_CONNECTION_ID.
void quiche_path_event_reused_source_connection_id(quiche_path_event *ev, uint64_t *id,
                           struct sockaddr_storage *old_local, socklen_t *old_local_len,
                           struct sockaddr_storage *old_peer, socklen_t *old_peer_len,
                           struct sockaddr_storage *local, socklen_t *local_len,
                           struct sockaddr_storage *peer, socklen_t *peer_len);

// Should be called if the quiche_path_event_type(...) returns QUICHE_PATH_EVENT_PEER_MIGRATED.
void quiche_path_event_peer_migrated(quiche_path_event *ev,
                           struct sockaddr_storage *local, socklen_t *local_len,
                           struct sockaddr_storage *peer, socklen_t *peer_len);

// Frees the path event object.
void quiche_path_event_free(quiche_path_event *ev);

// Requests the retirement of the destination Connection ID used by the
// host to reach its peer.
int quiche_conn_retire_dcid(quiche_conn *conn, uint64_t dcid_seq);

typedef struct quiche_socket_addr_iter quiche_socket_addr_iter;

// Returns an iterator over destination `SockAddr`s whose association
// with "from" forms a known QUIC path on which packets can be sent to.
quiche_socket_addr_iter *quiche_conn_paths_iter(quiche_conn *conn, const struct sockaddr *from, size_t from_len);

// Fetches the next peer from the given iterator. Returns false if there are
// no more elements in the iterator.
bool quiche_socket_addr_iter_next(quiche_socket_addr_iter *iter, struct sockaddr_storage *peer, size_t *peer_len);

// Frees the given path iterator object.
void quiche_socket_addr_iter_free(quiche_socket_addr_iter *iter);

// Returns whether the network path with local address "from and remote address "to" has been validated.
// If the 4-tuple does not exist over the connection, returns an InvalidState.
int quiche_conn_is_path_validated(const quiche_conn *conn, const struct sockaddr *from, size_t from_len, const struct sockaddr *to, size_t to_len);

// Frees the connection object.
void quiche_conn_free(quiche_conn *conn);

// Writes an unsigned variable-length integer in network byte-order into
// the provided buffer.
int quiche_put_varint(uint8_t *buf, size_t buf_len,
                      uint64_t val);

// Reads an unsigned variable-length integer in network byte-order from
// the provided buffer and returns the wire length.
ssize_t quiche_get_varint(const uint8_t *buf, size_t buf_len,
                          uint64_t *val);

// HTTP/3 API
//

// List of ALPN tokens of supported HTTP/3 versions.
#define QUICHE_H3_APPLICATION_PROTOCOL "\x02h3"

enum quiche_h3_error {
    // There is no error or no work to do
    QUICHE_H3_ERR_DONE = -1,

    // The provided buffer is too short.
    QUICHE_H3_ERR_BUFFER_TOO_SHORT = -2,

    // Internal error in the HTTP/3 stack.
    QUICHE_H3_ERR_INTERNAL_ERROR = -3,

    // Endpoint detected that the peer is exhibiting behavior that causes.
    // excessive load.
    QUICHE_H3_ERR_EXCESSIVE_LOAD = -4,

    // Stream ID or Push ID greater that current maximum was
    // used incorrectly, such as exceeding a limit, reducing a limit,
    // or being reused.
    QUICHE_H3_ERR_ID_ERROR= -5,

    // The endpoint detected that its peer created a stream that it will not
    // accept.
    QUICHE_H3_ERR_STREAM_CREATION_ERROR = -6,

    // A required critical stream was closed.
    QUICHE_H3_ERR_CLOSED_CRITICAL_STREAM = -7,

    // No SETTINGS frame at beginning of control stream.
    QUICHE_H3_ERR_MISSING_SETTINGS = -8,

    // A frame was received which is not permitted in the current state.
    QUICHE_H3_ERR_FRAME_UNEXPECTED = -9,

    // Frame violated layout or size rules.
    QUICHE_H3_ERR_FRAME_ERROR = -10,

    // QPACK Header block decompression failure.
    QUICHE_H3_ERR_QPACK_DECOMPRESSION_FAILED = -11,

    // -12 was previously used for TransportError, skip it

    // The underlying QUIC stream (or connection) doesn't have enough capacity
    // for the operation to complete. The application should retry later on.
    QUICHE_H3_ERR_STREAM_BLOCKED = -13,

    // Error in the payload of a SETTINGS frame.
    QUICHE_H3_ERR_SETTINGS_ERROR = -14,

    // Server rejected request.
    QUICHE_H3_ERR_REQUEST_REJECTED = -15,

    // Request or its response cancelled.
    QUICHE_H3_ERR_REQUEST_CANCELLED = -16,

    // Client's request stream terminated without containing a full-formed
    // request.
    QUICHE_H3_ERR_REQUEST_INCOMPLETE = -17,

    // An HTTP message was malformed and cannot be processed.
    QUICHE_H3_ERR_MESSAGE_ERROR = -18,

    // The TCP connection established in response to a CONNECT request was
    // reset or abnormally closed.
    QUICHE_H3_ERR_CONNECT_ERROR = -19,

    // The requested operation cannot be served over HTTP/3. Peer should retry
    // over HTTP/1.1.
    QUICHE_H3_ERR_VERSION_FALLBACK = -20,

    // The following QUICHE_H3_TRANSPORT_ERR_* errors are propagated
    // from the QUIC transport layer.

    // See QUICHE_ERR_DONE.
    QUICHE_H3_TRANSPORT_ERR_DONE = QUICHE_ERR_DONE - 1000,

    // See QUICHE_ERR_BUFFER_TOO_SHORT.
    QUICHE_H3_TRANSPORT_ERR_BUFFER_TOO_SHORT = QUICHE_ERR_BUFFER_TOO_SHORT - 1000,

    // See QUICHE_ERR_UNKNOWN_VERSION.
    QUICHE_H3_TRANSPORT_ERR_UNKNOWN_VERSION = QUICHE_ERR_UNKNOWN_VERSION - 1000,

    // See QUICHE_ERR_INVALID_FRAME.
    QUICHE_H3_TRANSPORT_ERR_INVALID_FRAME = QUICHE_ERR_INVALID_FRAME - 1000,

    // See QUICHE_ERR_INVALID_PACKET.
    QUICHE_H3_TRANSPORT_ERR_INVALID_PACKET = QUICHE_ERR_INVALID_PACKET - 1000,

    // See QUICHE_ERR_INVALID_STATE.
    QUICHE_H3_TRANSPORT_ERR_INVALID_STATE = QUICHE_ERR_INVALID_STATE - 1000,

    // See QUICHE_ERR_INVALID_STREAM_STATE.
    QUICHE_H3_TRANSPORT_ERR_INVALID_STREAM_STATE = QUICHE_ERR_INVALID_STREAM_STATE - 1000,

    // See QUICHE_ERR_INVALID_TRANSPORT_PARAM.
    QUICHE_H3_TRANSPORT_ERR_INVALID_TRANSPORT_PARAM = QUICHE_ERR_INVALID_TRANSPORT_PARAM - 1000,

    // See QUICHE_ERR_CRYPTO_FAIL.
    QUICHE_H3_TRANSPORT_ERR_CRYPTO_FAIL = QUICHE_ERR_CRYPTO_FAIL - 1000,

    // See QUICHE_ERR_TLS_FAIL.
    QUICHE_H3_TRANSPORT_ERR_TLS_FAIL = QUICHE_ERR_TLS_FAIL - 1000,

    // See QUICHE_ERR_FLOW_CONTROL.
    QUICHE_H3_TRANSPORT_ERR_FLOW_CONTROL = QUICHE_ERR_FLOW_CONTROL - 1000,

    // See QUICHE_ERR_STREAM_LIMIT.
    QUICHE_H3_TRANSPORT_ERR_STREAM_LIMIT = QUICHE_ERR_STREAM_LIMIT - 1000,

    // See QUICHE_ERR_STREAM_STOPPED.
    QUICHE_H3_TRANSPORT_ERR_STREAM_STOPPED = QUICHE_ERR_STREAM_STOPPED - 1000,

    // See QUICHE_ERR_STREAM_RESET.
    QUICHE_H3_TRANSPORT_ERR_STREAM_RESET = QUICHE_ERR_STREAM_RESET - 1000,

    // See QUICHE_ERR_FINAL_SIZE.
    QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE = QUICHE_ERR_FINAL_SIZE - 1000,

    // See QUICHE_ERR_CONGESTION_CONTROL.
    QUICHE_H3_TRANSPORT_ERR_CONGESTION_CONTROL = QUICHE_ERR_CONGESTION_CONTROL - 1000,

    // See QUICHE_ERR_ID_LIMIT.
    QUICHE_H3_TRANSPORT_ERR_ID_LIMIT = QUICHE_ERR_ID_LIMIT - 1000,

    // See QUICHE_ERR_OUT_OF_IDENTIFIERS.
    QUICHE_H3_TRANSPORT_ERR_OUT_OF_IDENTIFIERS = QUICHE_ERR_OUT_OF_IDENTIFIERS - 1000,

    // See QUICHE_ERR_KEY_UPDATE.
    QUICHE_H3_TRANSPORT_ERR_KEY_UPDATE = QUICHE_ERR_KEY_UPDATE - 1000,
};

// Stores configuration shared between multiple connections.
typedef struct quiche_h3_config quiche_h3_config;

// Creates an HTTP/3 config object with default settings values.
quiche_h3_config *quiche_h3_config_new(void);

// Sets the `SETTINGS_MAX_FIELD_SECTION_SIZE` setting.
void quiche_h3_config_set_max_field_section_size(quiche_h3_config *config, uint64_t v);

// Sets the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
void quiche_h3_config_set_qpack_max_table_capacity(quiche_h3_config *config, uint64_t v);

// Sets the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
void quiche_h3_config_set_qpack_blocked_streams(quiche_h3_config *config, uint64_t v);

// Sets the `SETTINGS_ENABLE_CONNECT_PROTOCOL` setting.
void quiche_h3_config_enable_extended_connect(quiche_h3_config *config, bool enabled);

// Frees the HTTP/3 config object.
void quiche_h3_config_free(quiche_h3_config *config);

// An HTTP/3 connection.
typedef struct quiche_h3_conn quiche_h3_conn;

// Creates a new HTTP/3 connection using the provided QUIC connection.
quiche_h3_conn *quiche_h3_conn_new_with_transport(quiche_conn *quiche_conn,
                                                  quiche_h3_config *config);

enum quiche_h3_event_type {
    QUICHE_H3_EVENT_HEADERS,
    QUICHE_H3_EVENT_DATA,
    QUICHE_H3_EVENT_FINISHED,
    QUICHE_H3_EVENT_GOAWAY,
    QUICHE_H3_EVENT_RESET,
    QUICHE_H3_EVENT_PRIORITY_UPDATE,
};

typedef struct quiche_h3_event quiche_h3_event;

// Processes HTTP/3 data received from the peer.
int64_t quiche_h3_conn_poll(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            quiche_h3_event **ev);

// Returns the type of the event.
enum quiche_h3_event_type quiche_h3_event_type(quiche_h3_event *ev);

// Iterates over the headers in the event.
//
// The `cb` callback will be called for each header in `ev`. `cb` should check
// the validity of pseudo-headers and headers. If `cb` returns any value other
// than `0`, processing will be interrupted and the value is returned to the
// caller.
int quiche_h3_event_for_each_header(quiche_h3_event *ev,
                                    int (*cb)(uint8_t *name, size_t name_len,
                                              uint8_t *value, size_t value_len,
                                              void *argp),
                                    void *argp);

// Iterates over the peer's HTTP/3 settings.
//
// The `cb` callback will be called for each setting in `conn`.
// If `cb` returns any value other than `0`, processing will be interrupted and
// the value is returned to the caller.
int quiche_h3_for_each_setting(quiche_h3_conn *conn,
                               int (*cb)(uint64_t identifier,
                                         uint64_t value, void *argp),
                               void *argp);

// Check whether more frames will follow the headers on the stream.
bool quiche_h3_event_headers_has_more_frames(quiche_h3_event *ev);

// Check whether or not extended connection is enabled by the peer
bool quiche_h3_extended_connect_enabled_by_peer(quiche_h3_conn *conn);

// Frees the HTTP/3 event object.
void quiche_h3_event_free(quiche_h3_event *ev);

typedef struct {
    const uint8_t *name;
    size_t name_len;

    const uint8_t *value;
    size_t value_len;
} quiche_h3_header;

// Extensible Priorities parameters.
typedef struct {
    uint8_t urgency;
    bool incremental;
} quiche_h3_priority;

// Sends an HTTP/3 request.
int64_t quiche_h3_send_request(quiche_h3_conn *conn, quiche_conn *quic_conn,
                               const quiche_h3_header *headers, size_t headers_len,
                               bool fin);

// Sends an HTTP/3 response on the specified stream with default priority.
int quiche_h3_send_response(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, const quiche_h3_header *headers,
                            size_t headers_len, bool fin);

// Sends an HTTP/3 response on the specified stream with specified priority.
int quiche_h3_send_response_with_priority(quiche_h3_conn *conn,
                            quiche_conn *quic_conn, uint64_t stream_id,
                            const quiche_h3_header *headers, size_t headers_len,
                            quiche_h3_priority *priority, bool fin);

// Sends additional HTTP/3 headers on the specified stream.
int quiche_h3_send_additional_headers(quiche_h3_conn *conn,
                            quiche_conn *quic_conn, uint64_t stream_id,
                            quiche_h3_header *headers, size_t headers_len,
                            bool is_trailer_section, bool fin);

// Sends an HTTP/3 body chunk on the given stream.
ssize_t quiche_h3_send_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, const uint8_t *body, size_t body_len,
                            bool fin);

// Reads request or response body data into the provided buffer.
ssize_t quiche_h3_recv_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, uint8_t *out, size_t out_len);

// Sends a GOAWAY frame to initiate graceful connection closure.
int quiche_h3_send_goaway(quiche_h3_conn *conn, quiche_conn *quic_conn,
                          uint64_t id);

// Try to parse an Extensible Priority field value.
int quiche_h3_parse_extensible_priority(uint8_t *priority,
                                        size_t priority_len,
                                        quiche_h3_priority *parsed);

/// Sends a PRIORITY_UPDATE frame on the control stream with specified
/// request stream ID and priority.
int quiche_h3_send_priority_update_for_request(quiche_h3_conn *conn,
                                               quiche_conn *quic_conn,
                                               uint64_t stream_id,
                                               quiche_h3_priority *priority);

// Take the last received PRIORITY_UPDATE frame for a stream.
//
// The `cb` callback will be called once. `cb` should check the validity of
// priority field value contents. If `cb` returns any value other than `0`,
// processing will be interrupted and the value is returned to the caller.
int quiche_h3_take_last_priority_update(quiche_h3_conn *conn,
                                        uint64_t prioritized_element_id,
                                        int (*cb)(uint8_t  *priority_field_value,
                                                  uint64_t priority_field_value_len,
                                                  void *argp),
                                        void *argp);

// Returns whether the peer enabled HTTP/3 DATAGRAM frame support.
bool quiche_h3_dgram_enabled_by_peer(quiche_h3_conn *conn,
                                     quiche_conn *quic_conn);

typedef struct {
    // The number of bytes received on the QPACK encoder stream.
    uint64_t qpack_encoder_stream_recv_bytes;

    // The number of bytes received on the QPACK decoder stream.
    uint64_t qpack_decoder_stream_recv_bytes;
} quiche_h3_stats;

// Collects and returns statistics about the connection.
void quiche_h3_conn_stats(const quiche_h3_conn *conn, quiche_h3_stats *out);

// Frees the HTTP/3 connection object.
void quiche_h3_conn_free(quiche_h3_conn *conn);

#if defined(__cplusplus)
}  // extern C
#endif

#endif // QUICHE_H
