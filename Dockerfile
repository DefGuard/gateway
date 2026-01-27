FROM public.ecr.aws/docker/library/rust:1-slim AS builder

RUN apt-get update && apt-get -y install protobuf-compiler libnftnl-dev libmnl-dev pkg-config libssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM public.ecr.aws/docker/library/debian:13-slim
RUN apt-get update && apt-get -y --no-install-recommends install \
    iproute2 wireguard-tools sudo ca-certificates iptables ebtables nftables lsb-release && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/defguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/defguard-gateway"]
