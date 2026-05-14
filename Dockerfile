FROM rust:1.95-trixie AS rust-builder

WORKDIR /usr/src/dns-server

RUN apt update && apt install -y ca-certificates

COPY Cargo.toml .
RUN cargo fetch

COPY src src
RUN cargo build --release

FROM debian:trixie-slim

ENV RUST_LOG=warn

RUN apt update && apt install -y ca-certificates

COPY bin/docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=rust-builder /usr/src/dns-server/target/release/dns-server /bin/
COPY --from=rust-builder /usr/src/dns-server/target/release/dns-resolve /bin/

ENTRYPOINT ["/docker-entrypoint.sh"]