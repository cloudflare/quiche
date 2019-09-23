FROM forallsecure/debian-buster:latest
LABEL maintainer="alessandro@cloudflare.com"

WORKDIR /home/mayhem/

COPY ./cert.crt ./
COPY ./cert.key ./

COPY ./hfuzz_target/x86_64-unknown-linux-gnu/release/packet_recv_client ./
COPY ./hfuzz_target/x86_64-unknown-linux-gnu/release/packet_recv_server ./
