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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <getopt.h>
#include <regex.h>

#include <ev.h>
#include <uthash.h>

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1452

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

regex_t request_regex;

struct connections {
    int sock;

    const char *root;

    struct conn_io *h;
};

struct conn_io {
    ev_timer timer;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    UT_hash_handle hh;
};

static quiche_config *config = NULL;

static struct connections *conns = NULL;

static void handle_stream(quiche_conn *conn, uint64_t s,
                          uint8_t *buf, size_t len,
                          const char *root);

static void timeout_cb(EV_P_ ev_timer *w, int revents);

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %ld\n", written);
            return;
        }

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &conn_io->peer_addr,
                              conn_io->peer_addr_len);
        if (sent != written) {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %lu bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static struct conn_io *create_conn(uint8_t *odcid, size_t odcid_len) {
    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, conn_io->cid, LOCAL_CONN_ID_LEN);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len, config);
    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    fprintf(stderr, "new connection\n");

    return conn_io;
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *tmp, *conn_io = NULL;

    static uint8_t buf[65535];
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            fprintf(stderr, "failed to parse header: %d\n", rc);
            return;
        }

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            if (version != QUICHE_VERSION_DRAFT17) {
                fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create vneg packet: %ld\n",
                            written);
                    return;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    return;
                }

                fprintf(stderr, "sent %lu bytes\n", sent);
                return;
            }

            if (token_len == 0) {
                fprintf(stderr, "stateless retry\n");

                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len,
                           token, &token_len);

                ssize_t written = quiche_retry(scid, scid_len,
                                               dcid, dcid_len,
                                               dcid, dcid_len,
                                               token, token_len,
                                               out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create retry packet: %ld\n",
                            written);
                    return;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    return;
                }

                fprintf(stderr, "sent %lu bytes\n", sent);
                return;
            }


            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                fprintf(stderr, "invalid address validation token\n");
                return;
            }

            conn_io = create_conn(odcid, odcid_len);
            if (conn_io == NULL) {
                return;
            }

            memcpy(&conn_io->peer_addr, &peer_addr, peer_addr_len);
            conn_io->peer_addr_len = peer_addr_len;
        }

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);

        if (done == QUICHE_ERR_DONE) {
            fprintf(stderr, "done reading\n");
            break;
        }

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %ld\n", done);
            return;
        }

        fprintf(stderr, "recv %lu bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn)) {
            uint64_t s = 0;

            quiche_readable *iter = quiche_conn_readable(conn_io->conn);

            while (quiche_readable_next(iter, &s)) {
                fprintf(stderr, "stream %zu is readable\n", s);

                bool fin = false;
                ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                           buf, sizeof(buf),
                                                           &fin);
                if (recv_len < 0) {
                    break;
                }

                buf[recv_len] = 0;

                fprintf(stderr, "stream %lu has bytes (fin? %s)\n",
                        s, fin ? "true" : "false");

                handle_stream(conn_io->conn, s, buf, recv_len, conns->root);
            }

            quiche_readable_free(iter);
        }
    }

    HASH_ITER(hh, conns->h, conn_io, tmp) {
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn)) {
            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }
}

static void handle_error(quiche_conn *conn, uint64_t s,
                         uint8_t *buf, int err, const char *msg,
                         bool use_http09) {
    if (use_http09) {
        return;
    }

    int res_len = snprintf((char*)buf, 65535,
                           "HTTP/1.1 %d %s\r\n"
                           "Server: quiche-c\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n",
                           err, msg);
    if (res_len >= 65535) {
       return;
    }

    quiche_conn_stream_send(conn, s, buf, res_len, true);
}

static void handle_stream(quiche_conn *conn, uint64_t s,
                          uint8_t *buf, size_t len,
                          const char *root) {
    regmatch_t path_match[4];
    struct stat path_stat;
    char full_path[256];
    int use_http09 = 0;

    if (regexec(&request_regex, (const char*)buf, 4, path_match, 0)) {
        fprintf(stderr, "invalid request line\n");

        handle_error(conn, s, buf, 400, "Bad Request", false);

        return;
    }

    if (path_match[3].rm_so == -1) {
        fprintf(stderr, "received HTTP/0.9 request\n");

        use_http09 = 1;
    } else {
        fprintf(stderr, "received HTTP/1.{0,1} request\n");
    }

    if (((path_match[1].rm_eo - path_match[1].rm_so) != 3) ||
        memcmp(buf + path_match[1].rm_so, "GET", 3)) {
        fprintf(stderr, "request method is not: GET\n");

        handle_error(conn, s, buf, 405, "Method Not Allowed", use_http09);

        return;
    }

    char *path = (char*)buf + path_match[2].rm_so;
    size_t path_len = path_match[2].rm_eo - path_match[2].rm_so;
    if ((path_len == 1) && (path[0] == '/')) {
        path = "/index.html";
        path_len = strlen(path);
    }

    size_t root_len = strlen(root);
    if (root_len + 1 + path_len >= 256) {
        fprintf(stderr, "request path too long\n");

        handle_error(conn, s, buf, 414, "Request-URI Too Long", use_http09);

        return;
    }

    fprintf(stderr, "got GET request for %s\n", path);

    memcpy(full_path, root, root_len);
    full_path[root_len] = '/';
    memcpy(full_path + root_len + 1, path, path_len);
    full_path[root_len + 1 + path_len] = '\0';

    if (stat(full_path, &path_stat)) {
        fprintf(stderr, "request path not found\n");

        handle_error(conn, s, buf, 404, "Not Found", use_http09);

        return;
    }

    off_t path_size = path_stat.st_size;

    int path_fd = open(full_path, O_RDONLY);
    if (path_fd == -1) {
        fprintf(stderr, "failed to open requested file\n");

        handle_error(conn, s, buf, 500, "Internal Server Error", use_http09);

        return;
    }

    if (!use_http09) {
        ssize_t head_len = snprintf((char*)buf, 65535,
                                    "HTTP/1.1 200 OK\r\n"
                                    "Server: quiche-c\r\n"
                                    "Content-Length: %lu\r\n"
                                    "\r\n",
                                    path_size);
        if (head_len >= 65535) {
            close(path_fd);

            fprintf(stderr, "response header exceeds buffer\n");

            handle_error(conn, s, buf, 500, "Internal Server Error", use_http09);

            return;
        }

        fprintf(stderr, "sending response headers of size %ld\n", head_len);

        if (quiche_conn_stream_send(conn, s, buf, head_len, false) < head_len) {
            fprintf(stderr, "error sending response headers, aborting");

            goto finish_handle_stream;
        }
    }

    fprintf(stderr, "sending response body\n");

    while (path_size > 0) {
        off_t to_read = path_size <= 65535 ? path_size : 65535;
        bool fin = path_size <= 65535;

        size_t path_read = read(path_fd, buf, to_read);
        if (path_read < 0) {
            path_read = 0;
            path_size = 0;
        }

        fprintf(stderr, "sending %lu bytes\n", path_read);

        if (quiche_conn_stream_send(conn, s, buf, path_read, fin) < path_read) {
            fprintf(stderr, "error sending response body, aborting");

            goto finish_handle_stream;
        }

        path_size -= path_read;
    }

    fprintf(stderr, "response complete\n");

finish_handle_stream:
    close(path_fd);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

        return;
    }
}

static void usage(const char *argv0) {
    printf(
"Usage: %s [options]\n"
"Options:\n"
"  --addr <IP/HOST>        Listen on the given ip address [defaut: 127.0.0.1]\n"
"  --port <PORT>           Listen on the given port [default: 443].\n"
"  --name <HOST>           Name of the server [default: quic.tech]\n"
"  --cert <FILE>           TLS certificate file path [default: examples/cert.crt]\n"
"  --key <FILE>            TLS certificate key file path [default: examples/cert.key]\n"
"  --root <DIR>            Root directory [default: examples/root/]\n"
"  --help                  Show this screen.\n",
           argv0);
}

int main(int argc, char *argv[]) {
    char *addr = NULL;
    char *port = NULL;
    char *name = NULL;
    char *cert = NULL;
    char *key = NULL;
    char *root = NULL;

    int option_index = 0;
    int o;

    struct option long_options[] = {
        { "addr", required_argument, NULL, 'a' },
        { "port", required_argument, NULL, 'p' },
        { "name", required_argument, NULL, 'n' },
        { "cert", required_argument, NULL, 'c' },
        { "key", required_argument, NULL, 'k' },
        { "root", required_argument, NULL, 'r' },
        { "help" , no_argument, NULL, 'h'},
        { 0, 0, 0, 0}
    };

    char *optstring = "a:p:n:c:k:r:h";

    while (1) {
        o = getopt_long_only(argc, argv, optstring, long_options, &option_index);
        if (o == -1)
            break;

        switch (o) {
        case 'a':
            addr = optarg;
            break;

        case 'p':
            port = optarg;
            break;

        case 'n':
            name = optarg;
            break;

        case 'c':
            cert = optarg;
            break;

        case 'k':
            key = optarg;
            break;

        case 'r':
            root = optarg;
            break;

        case 'h':
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc == 0) {
        usage(argv[0]);
        return 1;
    }

    (void)name;

    assert(regcomp(&request_regex, "^([A-Z]+) ([^ ]+)( HTTP/1\\.[01])?\r\n",
                   REG_EXTENDED) == 0);

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *local;
    if (getaddrinfo(addr ? addr : "127.0.0.1", port ? port : "443",
                    &hints, &local) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    config = quiche_config_new(QUICHE_VERSION_DRAFT17);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config,
                                                cert?cert:"examples/cert.crt");
    quiche_config_load_priv_key_from_pem_file(config,
                                              key ? key : "examples/cert.key");

    quiche_config_set_idle_timeout(config, 30);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 5);
    quiche_config_set_disable_migration(config, true);

    struct connections c;
    c.sock = sock;
    c.root = root ? root : "examples/root/";
    c.h = NULL;

    conns = &c;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = &c;

    ev_loop(loop, 0);

    freeaddrinfo(local);

    quiche_config_free(config);

    regfree(&request_regex);

    return 0;
}
