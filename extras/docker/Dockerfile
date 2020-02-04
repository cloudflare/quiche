FROM rust:1.39 as build

WORKDIR /build

RUN apt-get update && apt-get install -y git cmake golang && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --recurse-submodules --depth 1 https://github.com/cloudflare/quiche
RUN cd quiche && \
    cargo build --release --examples
RUN cd quiche && \
    cargo build --manifest-path tools/apps/Cargo.toml --release

##
## quiche-base: base quiche image
##
FROM debian:latest as quiche-base
RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates
COPY --from=build /build/quiche/target/release/examples/http3-client \
     /build/quiche/target/release/examples/http3-server \
     /build/quiche/target/release/examples/client \
     /build/quiche/target/release/examples/server \
     /build/quiche/tools/apps/target/release/quiche-client \
     /build/quiche/tools/apps/target/release/quiche-server \
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
COPY --from=build /build/quiche/tools/apps/target/release/quiche-client \
    /build/quiche/tools/apps/target/release/quiche-server \
     ./
ENV RUST_LOG=trace

# copy interop test script
COPY qns/run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
