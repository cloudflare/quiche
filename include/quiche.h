// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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

// QUIC transport API.
//

// The current QUIC wire version.
#define QUICHE_VERSION_DRAFT19 0xff000013

// The maximum length of a connection ID.
#define QUICHE_MAX_CONN_ID_LEN 18

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
};

// Enables logging. |cb| will be called with log messages
void quiche_enable_debug_logging(void (*cb)(const char *line, void *argp),
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

// Configures the list of supported application protocols.
int quiche_config_set_application_protos(quiche_config *config,
                                         uint8_t *protos,
                                         size_t protos_len);

// Sets the `idle_timeout` transport parameter.
void quiche_config_set_idle_timeout(quiche_config *config, uint64_t v);

// Sets the `max_packet_size` transport parameter.
void quiche_config_set_max_packet_size(quiche_config *config, uint64_t v);

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

// Sets the `disable_migration` transport parameter.
void quiche_config_set_disable_migration(quiche_config *config, bool v);

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
                     uint8_t *out, size_t out_len);

quiche_conn *quiche_conn_new_with_tls(const uint8_t *scid, size_t scid_len,
                                      const uint8_t *odcid, size_t odcid_len,
                                      quiche_config *config, void *ssl,
                                      bool is_server);

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

// Returns true if all the data has been read from the specified stream.
bool quiche_conn_stream_finished(quiche_conn *conn, uint64_t stream_id);

// Fetches the next stream that has outstanding data to read. Returns false if
// there are no readable streams.
bool quiche_readable_next(quiche_conn *conn, uint64_t *stream_id);

// Returns the amount of time until the next timeout event, as nanoseconds.
uint64_t quiche_conn_timeout_as_nanos(quiche_conn *conn);

// Processes a timeout event.
void quiche_conn_on_timeout(quiche_conn *conn);

// Closes the connection with the given error and reason.
int quiche_conn_close(quiche_conn *conn, bool app, uint16_t err,
                      const uint8_t *reason, size_t reason_len);

// Returns the negotiated ALPN protocol.
uint8_t *quiche_conn_application_proto(quiche_conn *conn, uint8_t **out,
                                       size_t *out_len);

// Returns true if the connection handshake is complete.
bool quiche_conn_is_established(quiche_conn *conn);

// Returns true if the connection is closed.
bool quiche_conn_is_closed(quiche_conn *conn);

// Collects and returns statistics about the connection.
void quiche_conn_stats_recv(quiche_conn *conn, uint64_t *out);
void quiche_conn_stats_sent(quiche_conn *conn, uint64_t *out);
void quiche_conn_stats_lost(quiche_conn *conn, uint64_t *out);
void quiche_conn_stats_rtt_as_nanos(quiche_conn *conn, uint64_t *out);

// Frees the connection object.
void quiche_conn_free(quiche_conn *conn);


// HTTP/3 API
//

/// The current HTTP/3 ALPN token.
#define QUICHE_H3_APPLICATION_PROTOCOL "\x05h3-18"

// Stores configuration shared between multiple connections.
typedef struct Http3Config quiche_h3_config;

// Creates a HTTP/3 config object with the given version.
quiche_h3_config *quiche_h3_config_new(uint64_t num_placeholders,
                                       uint64_t max_header_list_size,
                                       uint64_t qpack_max_table_capacity,
                                       uint64_t qpack_blaocked_streams);

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
};

typedef struct Http3Event quiche_h3_event;

// Processes HTTP/3 data received from the peer.
int quiche_h3_conn_poll(quiche_h3_conn *conn, quiche_conn *quic_conn,
                        quiche_h3_event **ev);

// Returns the type of the event.
enum quiche_h3_event_type quiche_h3_event_type(quiche_h3_event *ev);

// Iterates over the headers in the event.
void quiche_h3_event_for_each_header(quiche_h3_event *ev,
                                     void (*cb)(uint8_t *name, size_t name_len,
                                                uint8_t *value, size_t value_len,
                                                void *argp),
                                     void *argp);

// Returns the data from the event.
size_t quiche_h3_event_data(quiche_h3_event *ev, uint8_t **out);

// Frees the HTTP/3 event object.
void quiche_h3_event_free(quiche_h3_event *ev);

typedef struct {
    const char *name;
    const char *value;
} quiche_h3_header;

// Sends an HTTP/3 request.
int64_t quiche_h3_send_request(quiche_h3_conn *conn, quiche_conn *quic_conn,
                               quiche_h3_header *headers, size_t headers_len,
                               bool fin);

// sends an http/3 response on the specified stream.
int quiche_h3_send_response(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, quiche_h3_header *headers,
                            size_t headers_len, bool fin);

// Sends an HTTP/3 body chunk on the given stream.
ssize_t quiche_h3_send_body(quiche_h3_conn *conn, quiche_conn *quic_conn,
                            uint64_t stream_id, uint8_t *body, size_t body_len,
                            bool fin);

// Frees the HTTP/3 connection object.
void quiche_h3_conn_free(quiche_h3_conn *conn);

#if defined(__cplusplus)
}  // extern C
#endif

#endif // QUICHE_H
