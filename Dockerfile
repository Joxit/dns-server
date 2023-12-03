FROM debian:bookworm

ENV RUST_LOG=warn

RUN apt update && apt install -y ca-certificates

COPY bin/docker-entrypoint.sh /docker-entrypoint.sh
COPY target/release/dns-server /bin/

ENTRYPOINT ["/docker-entrypoint.sh"]