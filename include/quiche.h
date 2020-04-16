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
#define QUICHE_PROTOCOL_VERSION 0xff00001d

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
typedef struct Config quiche_config;

// Creates a config object with the given version.
quiche_config *quiche_config_new(uint32_t version);

// Configures the given certificate chain.
int quiche_config_load_cert_chain_from_pem_file(quiche_config *config,
                                                const char *path);

// Configures the given private key.
int quiche_config_load_priv_key_from_pem_file(quiche_config *config,
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

// Sets the `max_idle_timeout` transport parameter.
void quiche_config_set_max_idle_timeout(quiche_config *config, uint64_t v);

// Sets the `max_udp_payload_size transport` parameter.
void quiche_config_set_max_udp_payload_size(quiche_config *config, uint64_t v);

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
};

// Sets the congestion control algorithm used.
void quiche_config_set_cc_algorithm(quiche_config *config, enum quiche_cc_algorithm algo);

// Configures whether to use HyStart++.
void quiche_config_enable_hystart(quiche_config *config, bool v);

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
typedef struct Connection quiche_conn;

// Creates a new server-side connection.
quiche_conn *quiche_accept(const uint8_t *scid, size_t scid_len,
                           const uint8_t *odcid, size_t odcid_len,
                           quiche_config *config);

// Creates a new client-side connection.
quiche_conn *quiche_connect(const char *server_name, const uint8_t *scid,
                            size_t scid_len, quiche_config *config);

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

// Processes QUIC packets received from the peer.
ssize_t quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len);

// Writes a single QUIC packet to be sent to the peer.
ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len);

// Buffer holding data at a specific offset.
typedef struct RangeBuf quiche_rangebuf;

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

// Shuts down reading or writing from/to the specified stream.
int quiche_conn_stream_shutdown(quiche_conn *conn, uint64_t stream_id,
                                enum quiche_shutdown direction, uint64_t err);

ssize_t quiche_conn_stream_capacity(quiche_conn *conn, uint64_t stream_id);

// Returns true if all the data has been read from the specified stream.
bool quiche_conn_stream_finished(quiche_conn *conn, uint64_t stream_id);

typedef struct StreamIter quiche_stream_iter;

// Returns an iterator over streams that have outstanding data to read.
quiche_stream_iter *quiche_conn_readable(quiche_conn *conn);

// Returns an iterator over streams that can be written to.
quiche_stream_iter *quiche_conn_writable(quiche_conn *conn);

// Returns the amount of time until the next timeout event, in nanoseconds.
uint64_t quiche_conn_timeout_as_nanos(quiche_conn *conn);

// Returns the amount of time until the next timeout event, in milliseconds.
uint64_t quiche_conn_timeout_as_millis(quiche_conn *conn);

// Processes a timeout event.
void quiche_conn_on_timeout(quiche_conn *conn);

// Closes the connection with the given error and reason.
int quiche_conn_close(quiche_conn *conn, bool app, uint64_t err,
                      const uint8_t *reason, size_t reason_len);

// Returns the negotiated ALPN protocol.
void quiche_conn_application_proto(quiche_conn *conn, const uint8_t **out,
                                   size_t *out_len);

// Returns true if the connection handshake is complete.
bool quiche_conn_is_established(quiche_conn *conn);

// Returns true if the connection has a pending handshake that has progressed
// enough to send or receive early data.
bool quiche_conn_is_in_early_data(quiche_conn *conn);

// Returns true if the connection is closed.
bool quiche_conn_is_closed(quiche_conn *conn);

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

    // The estimated round-trip time of the connection (in nanoseconds).
    uint64_t rtt;

    // The size of the connection's congestion window in bytes.
    size_t cwnd;

    // The estimated data delivery rate in bytes/s.
    uint64_t delivery_rate;
} quiche_stats;

// Collects and returns statistics about the connection.
void quiche_conn_stats(quiche_conn *conn, quiche_stats *out);

// Frees the connection object.
void quiche_conn_free(quiche_conn *conn);


// HTTP/3 API
//

// List of ALPN tokens of supported HTTP/3 versions.
#define QUICHE_H3_APPLICATION_PROTOCOL "\x05h3-29\x05h3-28\x05h3-27"

enum quiche_h3_error {
    /// There is no error or no work to do
    QUICHE_H3_ERR_DONE = -1,

    /// The provided buffer is too short.
    QUICHE_H3_ERR_BUFFER_TOO_SHORT = -2,

    /// Internal error in the HTTP/3 stack.
    QUICHE_H3_ERR_INTERNAL_ERROR = -3,

    /// Endpoint detected that the peer is exhibiting behavior that causes.
    /// excessive load.
    QUICHE_H3_ERR_EXCESSIVE_LOAD = -4,

    /// Stream ID or Push ID greater that current maximum was
    /// used incorrectly, such as exceeding a limit, reducing a limit,
    /// or being reused.
    QUICHE_H3_ERR_ID_ERROR= -5,

    /// The endpoint detected that its peer created a stream that it will not
    /// accept.
    QUICHE_H3_ERR_STREAM_CREATION_ERROR = -6,

    /// A required critical stream was closed.
    QUICHE_H3_ERR_CLOSED_CRITICAL_STREAM = -7,

    /// No SETTINGS frame at beginning of control stream.
    QUICHE_H3_ERR_MISSING_SETTINGS = -8,

    /// A frame was received which is not permitted in the current state.
    QUICHE_H3_ERR_FRAME_UNEXPECTED = -9,

    /// Frame violated layout or size rules.
    QUICHE_H3_ERR_FRAME_ERROR = -10,

    /// QPACK Header block decompression failure.
    QUICHE_H3_ERR_QPACK_DECOMPRESSION_FAILED = -11,

    /// Error originated from the transport layer.
    QUICHE_H3_ERR_TRANSPORT_ERROR = -12,

    /// The underlying QUIC stream (or connection) doesn't have enough capacity
    /// for the operation to complete. The application should retry later on.
    QUICHE_H3_ERR_STREAM_BLOCKED = -13,
};

// Stores configuration shared between multiple connections.
typedef struct Http3Config quiche_h3_config;

// Creates an HTTP/3 config object with default settings values.
quiche_h3_config *quiche_h3_config_new(void);

// Sets the `SETTINGS_MAX_HEADER_LIST_SIZE` setting.
void quiche_h3_config_set_max_header_list_size(quiche_h3_config *config, uint64_t v);

// Sets the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
void quiche_h3_config_set_qpack_max_table_capacity(quiche_h3_config *config, uint64_t v);

// Sets the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
void quiche_h3_config_set_qpack_blocked_streams(quiche_h3_config *config, uint64_t v);

// Frees the HTTP/3 config object.
void quiche_h3_config_free(quiche_h3_config *config);

// A QUIC connection.
typedef struct Http3Connection quiche_h3_conn;

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
};

typedef struct Http3Event quiche_h3_event;

// Processes HTTP/3 data received from the peer.
int quiche_h3_conn_poll(quiche_h3_conn *conn, quiche_conn *quic_conn,
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

// Check whether data will follow the headers on the stream.
bool quiche_h3_event_headers_has_body(quiche_h3_event *ev);

// Frees the HTTP/3 event object.
void quiche_h3_event_free(quiche_h3_event *ev);

typedef struct {
    const uint8_t *name;
    size_t name_len;

    const uint8_t *value;
    size_t value_len;
} quiche_h3_header;

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
                            const char *priority, bool fin);

// Sends an HTTP/3 body chunk on the given stream.
ssize_t quiche_h3_send_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, uint8_t *body, size_t body_len,
                            bool fin);

// Reads request or response body data into the provided buffer.
ssize_t quiche_h3_recv_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, uint8_t *out, size_t out_len);

// Frees the HTTP/3 connection object.
void quiche_h3_conn_free(quiche_h3_conn *conn);

#if defined(__cplusplus)
}  // extern C
#endif

#endif // QUICHE_H
