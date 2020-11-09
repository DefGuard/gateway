FROM rust:1.47.0-slim as planner
WORKDIR app
# We only pay the installation cost once, 
# it will be cached from the second build onwards
# To ensure a reproducible build consider pinning 
# the cargo-chef version with `--version X.X.X`
RUN cargo install cargo-chef --version 0.1.6
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM rust:1.47.0-slim as cacher
WORKDIR app
RUN cargo install cargo-chef --version 0.1.6
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust:1.47.0-slim as builder
WORKDIR app
COPY . .
# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
RUN rustup component add rustfmt
RUN cargo build --release --bin wgserver

FROM rust:1.47.0-slim as runtime
WORKDIR app
COPY --from=builder /app/target/release/wgserver /usr/local/bin
ENTRYPOINT ["./usr/local/bin/wgserver"]
