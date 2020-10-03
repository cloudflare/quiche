FROM debian:bullseye
LABEL maintainer="alessandro@cloudflare.com"

WORKDIR /home/mayhem/

# Install llvm-symbolizer to have source code information in stack traces
RUN apt-get update && apt-get install llvm -y

COPY ./cert.crt ./
COPY ./cert.key ./

COPY ./target/x86_64-unknown-linux-gnu/release/packet_recv_client ./
COPY ./target/x86_64-unknown-linux-gnu/release/packet_recv_server ./
COPY ./target/x86_64-unknown-linux-gnu/release/qpack_decode ./
