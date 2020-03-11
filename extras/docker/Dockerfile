FROM rust:1.39 as build

WORKDIR /build

RUN apt-get update && apt-get install -y git cmake golang && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --recurse-submodules --depth 1 https://github.com/cloudflare/quiche
RUN cd quiche && \
    git log --oneline -n 1 && \
    cargo build --manifest-path tools/apps/Cargo.toml

##
## quiche-base: base quiche image
##
FROM debian:latest as quiche-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /build/quiche/tools/apps/target/debug/quiche-client \
     /build/quiche/tools/apps/target/debug/quiche-server \
     /usr/local/bin/
ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=info

##
## quiche-qns: quiche build image for quic-interop-runner
## https://github.com/marten-seemann/quic-network-simulator
## https://github.com/marten-seemann/quic-interop-runner
##

# setup interop image
FROM martenseemann/quic-network-simulator-endpoint:latest as quiche-qns

WORKDIR /quiche

# copy binaries and sample certificate for server
COPY --from=build /build/quiche/examples/cert.crt \
     /build/quiche/examples/cert.key \
     examples/
COPY --from=build /build/quiche/tools/apps/target/debug/quiche-client \
    /build/quiche/tools/apps/target/debug/quiche-server \
     ./
ENV RUST_LOG=trace

# copy interop test script
COPY qns/run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
