FROM rust:1.74-slim as builder

RUN apt-get update && apt-get -y install protobuf-compiler
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get -y --no-install-recommends install \
    iproute2 wireguard-tools sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/defguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/defguard-gateway"]
