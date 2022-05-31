FROM rust:1.61-slim as builder

RUN apt-get update && apt-get -y install cmake g++

WORKDIR /app
COPY . .
RUN rustup component add rustfmt
RUN cargo build --release

FROM rust:1.61-slim as runtime
WORKDIR /app
COPY --from=builder /app/target/release/wireguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/wireguard-gateway"]
