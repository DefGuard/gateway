FROM rust:1.60-slim as planner
WORKDIR /app
RUN cargo install cargo-chef 
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM rust:1.60-slim as cacher
WORKDIR /app
RUN cargo install cargo-chef
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust:1.60-slim as builder
WORKDIR /app
COPY . .

# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
RUN rustup component add rustfmt
RUN cargo build --release

FROM rust:1.60-slim as runtime
WORKDIR /app
COPY --from=builder /app/target/release/wireguard-gateway /usr/local/bin
ENTRYPOINT ["/usr/local/bin/wireguard-gateway"]
