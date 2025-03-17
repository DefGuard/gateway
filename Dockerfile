FROM rust:1-slim as builder

RUN apt-get update && apt-get -y install protobuf-compiler libnftnl-dev libmnl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get -y --no-install-recommends install \
    iproute2 wireguard-tools sudo ca-certificates iptables ebtables nftables && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/defguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/defguard-gateway"]
