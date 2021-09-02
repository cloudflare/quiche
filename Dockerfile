FROM rust:1.53 as build

WORKDIR /build

COPY deps/ ./deps/
COPY src/ ./src/
COPY tools/ ./tools/
COPY Cargo.toml .

RUN apt-get update && apt-get install -y cmake && \
    rm -rf /var/lib/apt/lists/*

RUN cargo build --manifest-path tools/apps/Cargo.toml

##
## quiche-base: quiche image for apps
##
FROM debian:latest as quiche-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/tools/apps/target/debug/quiche-client \
     /build/tools/apps/target/debug/quiche-server \
     /usr/local/bin/

ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=info

##
## quiche-qns: quiche image for quic-interop-runner
## https://github.com/marten-seemann/quic-network-simulator
## https://github.com/marten-seemann/quic-interop-runner
##
FROM martenseemann/quic-network-simulator-endpoint:latest as quiche-qns

WORKDIR /quiche

COPY --from=build \
     /build/tools/apps/target/debug/quiche-client \
     /build/tools/apps/target/debug/quiche-server \
     /build/tools/qns/run_endpoint.sh \
     ./

ENV RUST_LOG=trace

ENTRYPOINT [ "./run_endpoint.sh" ]
