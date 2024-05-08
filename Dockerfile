FROM rust:1.85 AS build

WORKDIR /build

COPY Cargo.toml ./
COPY apps/ ./apps/
COPY buffer-pool ./buffer-pool/
COPY datagram-socket/ ./datagram-socket/
COPY h3i/ ./h3i/
COPY netlog/ ./netlog/
COPY octets/ ./octets/
COPY qlog/ ./qlog/
COPY qlog-dancer/ ./qlog-dancer/
COPY quiche/ ./quiche/
COPY task-killswitch ./task-killswitch/
COPY tokio-quiche ./tokio-quiche/

RUN apt-get update && apt-get install -y clang cmake && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --manifest-path apps/Cargo.toml

##
## quiche-base: quiche image for apps
##
FROM debian:latest AS quiche-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/target/release/quiche-client \
     /build/target/release/quiche-server \
     /usr/local/bin/

ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=info

##
## quiche-qns: quiche image for quic-interop-runner
## https://github.com/marten-seemann/quic-network-simulator
## https://github.com/marten-seemann/quic-interop-runner
##
FROM martenseemann/quic-network-simulator-endpoint:latest AS quiche-qns

WORKDIR /quiche

RUN apt-get update && apt-get install -y wait-for-it && rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/target/release/quiche-client \
     /build/target/release/quiche-server \
     /build/apps/run_endpoint.sh \
     ./

ENV RUST_LOG=trace

ENTRYPOINT [ "./run_endpoint.sh" ]
