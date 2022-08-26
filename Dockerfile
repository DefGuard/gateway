FROM rust:slim as builder

RUN apt-get update && apt-get -y install protobuf-compiler
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get -y install \
    iproute2 wireguard-tools sudo && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/wireguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/wireguard-gateway"]
