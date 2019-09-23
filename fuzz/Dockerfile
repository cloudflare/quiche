FROM debian:bullseye
LABEL maintainer="alessandro@cloudflare.com"

WORKDIR /home/mayhem/

COPY ./cert.crt ./
COPY ./cert.key ./

COPY ./target/x86_64-unknown-linux-gnu/debug/packet_recv_client ./
COPY ./target/x86_64-unknown-linux-gnu/debug/packet_recv_server ./
COPY ./target/x86_64-unknown-linux-gnu/debug/qpack_decode ./
