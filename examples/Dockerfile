FROM rust:1.35 as build

WORKDIR /usr/src/

RUN apt-get update && apt-get install -y \
    git \
    cmake \
    golang \
 && rm -rf /var/lib/apt/lists/*

RUN git clone --recurse-submodules --depth 1 https://github.com/cloudflare/quiche

RUN cd quiche && cargo build --release --examples

FROM debian:latest
RUN apt-get update && apt-get install -y \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates
WORKDIR /usr/src/
COPY --from=build /usr/src/quiche/target/release/examples/http3-client ./
COPY --from=build /usr/src/quiche/target/release/examples/http3-server ./
COPY --from=build /usr/src/quiche/target/release/examples/client ./
COPY --from=build /usr/src/quiche/target/release/examples/server ./
ENV RUST_LOG=trace
