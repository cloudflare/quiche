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

#if defined(__cplusplus)
extern "C" {
#endif

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

// Enables logging of secrets.
void quiche_config_log_keys(quiche_config *config);

// Enables sending or receiving early data.
void quiche_config_enable_early_data(quiche_config *config);

// Configures the list of supported application protocols.
int quiche_config_set_application_protos(quiche_config *config,
                                         const uint8_t *protos,
                                         size_t protos_len);

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

enum quiche_cc_algorithm {
    QUICHE_CC_RENO = 0,
    QUICHE_CC_CUBIC = 1,
    QUICHE_CC_BBR = 2,
};

// Sets the congestion control algorithm used.
void quiche_config_set_cc_algorithm(quiche_config *config, enum quiche_cc_algorithm algo);

// Configures whether to use HyStart++.
void quiche_config_enable_hystart(quiche_config *config, bool v);

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
                           const struct sockaddr *local, size_t local_len,
                           const struct sockaddr *peer, size_t peer_len,
                           quiche_config *config);

// Creates a new client-side connection.
quiche_conn *quiche_connect(const char *server_name,
                            const uint8_t *scid, size_t scid_len,
                            const struct sockaddr *local, size_t local_len,
                            const struct sockaddr *peer, size_t peer_len,
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
                                      const struct sockaddr *local, size_t local_len,
                                      const struct sockaddr *peer, size_t peer_len,
                                      quiche_config *config, void *ssl,
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
size_t quiche_conn_send_quantum(quiche_conn *conn);

// Reads contiguous data from a stream.
ssize_t quiche_conn_stream_recv(quiche_conn *conn, uint64_t stream_id,
                                uint8_t *out, size_t buf_len, bool *fin);

// Writes data to a stream.
ssize_t quiche_conn_stream_send(quiche_conn *conn, uint64_t stream_id,
                                const uint8_t *buf, size_t buf_len, bool fin);

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

ssize_t quiche_conn_stream_capacity(quiche_conn *conn, uint64_t stream_id);

bool quiche_conn_stream_readable(quiche_conn *conn, uint64_t stream_id);

// Returns true if all the data has been read from the specified stream.
bool quiche_conn_stream_finished(quiche_conn *conn, uint64_t stream_id);

typedef struct quiche_stream_iter quiche_stream_iter;

// Returns an iterator over streams that have outstanding data to read.
quiche_stream_iter *quiche_conn_readable(quiche_conn *conn);

// Returns an iterator over streams that can be written to.
quiche_stream_iter *quiche_conn_writable(quiche_conn *conn);

// Returns the maximum possible size of egress UDP payloads.
size_t quiche_conn_max_send_udp_payload_size(quiche_conn *conn);

// Returns the amount of time until the next timeout event, in nanoseconds.
uint64_t quiche_conn_timeout_as_nanos(quiche_conn *conn);

// Returns the amount of time until the next timeout event, in milliseconds.
uint64_t quiche_conn_timeout_as_millis(quiche_conn *conn);

// Processes a timeout event.
void quiche_conn_on_timeout(quiche_conn *conn);

// Closes the connection with the given error and reason.
int quiche_conn_close(quiche_conn *conn, bool app, uint64_t err,
                      const uint8_t *reason, size_t reason_len);

// Returns a string uniquely representing the connection.
void quiche_conn_trace_id(quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the source connection ID.
void quiche_conn_source_id(quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the destination connection ID.
void quiche_conn_destination_id(quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the negotiated ALPN protocol.
void quiche_conn_application_proto(quiche_conn *conn, const uint8_t **out,
                                   size_t *out_len);

// Returns the peer's leaf certificate (if any) as a DER-encoded buffer.
void quiche_conn_peer_cert(quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns the serialized cryptographic session for the connection.
void quiche_conn_session(quiche_conn *conn, const uint8_t **out, size_t *out_len);

// Returns true if the connection handshake is complete.
bool quiche_conn_is_established(const quiche_conn *conn);

// Returns true if the connection has a pending handshake that has progressed
// enough to send or receive early data.
bool quiche_conn_is_in_early_data(const quiche_conn *conn);

// Returns whether there is stream or DATAGRAM data available to read.
bool quiche_conn_is_readable(const quiche_conn *conn);

// Returns true if the connection is draining.
bool quiche_conn_is_draining(const quiche_conn *conn);

// Returns the number of bidirectional streams that can be created
// before the peer's stream count limit is reached.
uint64_t quiche_conn_peer_streams_left_bidi(quiche_conn *conn);

// Returns the number of unidirectional streams that can be created
// before the peer's stream count limit is reached.
uint64_t quiche_conn_peer_streams_left_uni(quiche_conn *conn);

// Returns true if the connection is closed.
bool quiche_conn_is_closed(const quiche_conn *conn);

// Returns true if the connection was closed due to the idle timeout.
bool quiche_conn_is_timed_out(const quiche_conn *conn);

// Returns true if a connection error was received, and updates the provided
// parameters accordingly.
bool quiche_conn_peer_error(quiche_conn *conn,
                            bool *is_app,
                            uint64_t *error_code,
                            const uint8_t **reason,
                            size_t *reason_len);

// Returns true if a connection error was queued or sent, and updates the provided
// parameters accordingly.
bool quiche_conn_local_error(quiche_conn *conn,
                            bool *is_app,
                            uint64_t *error_code,
                            const uint8_t **reason,
                            size_t *reason_len);

// Initializes the stream's application data.
//
// Stream data can only be initialized once. Additional calls to this method
// will fail.
//
// Note that the application is responsible for freeing the data.
int quiche_conn_stream_init_application_data(quiche_conn *conn,
                                             uint64_t stream_id,
                                             void *data);

// Returns the stream's application data, if any was initialized.
void *quiche_conn_stream_application_data(quiche_conn *conn, uint64_t stream_id);

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

    // The number of bytes lost.
    uint64_t lost_bytes;

    // The number of stream bytes retransmitted.
    uint64_t stream_retrans_bytes;

    // The number of known paths for the connection.
    size_t paths_count;

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
} quiche_stats;

// Collects and returns statistics about the connection.
void quiche_conn_stats(quiche_conn *conn, quiche_stats *out);

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
int quiche_conn_path_stats(quiche_conn *conn, size_t idx, quiche_path_stats *out);

// Returns the maximum DATAGRAM payload that can be sent.
ssize_t quiche_conn_dgram_max_writable_len(quiche_conn *conn);

// Returns the length of the first stored DATAGRAM.
ssize_t quiche_conn_dgram_recv_front_len(quiche_conn *conn);

// Returns the number of items in the DATAGRAM receive queue.
ssize_t quiche_conn_dgram_recv_queue_len(quiche_conn *conn);

// Returns the total size of all items in the DATAGRAM receive queue.
ssize_t quiche_conn_dgram_recv_queue_byte_size(quiche_conn *conn);

// Returns the number of items in the DATAGRAM send queue.
ssize_t quiche_conn_dgram_send_queue_len(quiche_conn *conn);

// Returns the total size of all items in the DATAGRAM send queue.
ssize_t quiche_conn_dgram_send_queue_byte_size(quiche_conn *conn);

// Reads the first received DATAGRAM.
ssize_t quiche_conn_dgram_recv(quiche_conn *conn, uint8_t *buf,
                               size_t buf_len);

// Sends data in a DATAGRAM frame.
ssize_t quiche_conn_dgram_send(quiche_conn *conn, const uint8_t *buf,
                               size_t buf_len);

// Purges queued outgoing DATAGRAMs matching the predicate.
void quiche_conn_dgram_purge_outgoing(quiche_conn *conn,
                                      bool (*f)(uint8_t *, size_t));

// Frees the connection object.
void quiche_conn_free(quiche_conn *conn);


// HTTP/3 API
//

// List of ALPN tokens of supported HTTP/3 versions.
#define QUICHE_H3_APPLICATION_PROTOCOL "\x02h3\x05h3-29\x05h3-28\x05h3-27"

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

// A QUIC connection.
typedef struct quiche_h3_conn quiche_h3_conn;

// Creates a new server-side connection.
quiche_h3_conn *quiche_h3_accept(quiche_conn *quiche_conn,
                                 quiche_h3_config *config);

// Creates a new HTTP/3 connection using the provided QUIC connection.
quiche_h3_conn *quiche_h3_conn_new_with_transport(quiche_conn *quiche_conn,
                                                  quiche_h3_config *config);

enum quiche_h3_event_type {
    QUICHE_H3_EVENT_HEADERS,
    QUICHE_H3_EVENT_DATA,
    QUICHE_H3_EVENT_FINISHED,
    QUICHE_H3_EVENT_DATAGRAM,
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

// Check whether data will follow the headers on the stream.
bool quiche_h3_event_headers_has_body(quiche_h3_event *ev);

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
                               quiche_h3_header *headers, size_t headers_len,
                               bool fin);

// Sends an HTTP/3 response on the specified stream with default priority.
int quiche_h3_send_response(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, quiche_h3_header *headers,
                            size_t headers_len, bool fin);

// Sends an HTTP/3 response on the specified stream with specified priority.
int quiche_h3_send_response_with_priority(quiche_h3_conn *conn,
                            quiche_conn *quic_conn, uint64_t stream_id,
                            quiche_h3_header *headers, size_t headers_len,
                            quiche_h3_priority *priority, bool fin);

// Sends an HTTP/3 body chunk on the given stream.
ssize_t quiche_h3_send_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, uint8_t *body, size_t body_len,
                            bool fin);

// Reads request or response body data into the provided buffer.
ssize_t quiche_h3_recv_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, uint8_t *out, size_t out_len);

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

// Writes data to the DATAGRAM send queue.
ssize_t quiche_h3_send_dgram(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t flow_id, uint8_t *data, size_t data_len);

// Reads data from the DATAGRAM receive queue.
ssize_t quiche_h3_recv_dgram(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t *flow_id, size_t *flow_id_len,
                            uint8_t *out, size_t out_len);

// Frees the HTTP/3 connection object.
void quiche_h3_conn_free(quiche_h3_conn *conn);

#if defined(__cplusplus)
}  // extern C
#endif

#endif // QUICHE_H
