FROM rust:1.39 as build

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
COPY --from=build /usr/src/quiche/target/release/examples/http3-client /usr/local/quiche/bin/
COPY --from=build /usr/src/quiche/target/release/examples/http3-server /usr/local/quiche/bin/
COPY --from=build /usr/src/quiche/target/release/examples/client /usr/local/quiche/bin/
COPY --from=build /usr/src/quiche/target/release/examples/server /usr/local/quiche/bin/
ENV PATH="/usr/local/quiche/bin/:${PATH}"
ENV RUST_LOG=info
