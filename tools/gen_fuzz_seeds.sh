#!/bin/bash

set -e

cleanup() {
    echo "Cleaning up..."
    rm -r $CLIENT_DIR $SERVER_DIR
    kill %1
}

trap cleanup EXIT

CLIENT_DIR=$(mktemp -d)
SERVER_DIR=$(mktemp -d)

# Build apps first.
cargo build --features fuzzing -p quiche_apps

# Run server in the background.
target/debug/quiche-server --cert fuzz/cert.crt --key fuzz/cert.key --dump-packets $SERVER_DIR &

# Wait for server to be ready.
sleep 1

# Run client.
RUST_LOG=trace target/debug/quiche-client --no-verify https://127.0.0.1:4433 --dump-packets $CLIENT_DIR

# Combine client-received packets into client's seed.
cat $CLIENT_DIR/*.pkt > fuzz/corpus/packet_recv_client/seed

# Combine server-received packets into client's seed.
cat $SERVER_DIR/*.pkt > fuzz/corpus/packet_recv_server/seed

# Minimize fuzz corpora.
cargo +nightly fuzz cmin -Oa packet_recv_client
cargo +nightly fuzz cmin -Oa packet_recv_server
