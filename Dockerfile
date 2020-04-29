##
## quiche-base: quiche image for apps
##
FROM debian:latest as quiche-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY tools/apps/target/debug/quiche-client \
     tools/apps/target/debug/quiche-server \
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

# copy binaries and sample certificate for server
COPY examples/cert.crt examples/cert.key examples/

COPY tools/apps/target/debug/quiche-client \
     tools/apps/target/debug/quiche-server \
     tools/qns/run_endpoint.sh \
     ./

ENV RUST_LOG=trace

ENTRYPOINT [ "./run_endpoint.sh" ]
