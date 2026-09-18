FROM public.ecr.aws/docker/library/rust:1-slim AS builder
# Bust the cache for the layer below on every build so OS security updates are always applied.
ARG CACHEBUST=0
RUN apt-get update && apt-get -y install protobuf-compiler libnftnl-dev libmnl-dev pkg-config libssl-dev libudev-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM public.ecr.aws/docker/library/debian:13-slim
# Bust the cache for the layer below on every build so OS security updates are always applied.
ARG CACHEBUST=0
RUN apt-get update && apt-get -y --no-install-recommends install \
    iproute2 wireguard-tools sudo ca-certificates iptables ebtables nftables lsb-release libudev1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/defguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/defguard-gateway"]
