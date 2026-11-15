# BGFlow — multi-stage build
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release --locked -p bgflowd

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/bgflow --shell /usr/sbin/nologin bgflow \
 && install -d -o bgflow -g bgflow /var/lib/bgflow \
 && mkdir -p /etc/bgflow
COPY --from=build /src/target/release/bgflowd /usr/local/bin/bgflowd
COPY bgflow.example.toml /etc/bgflow/bgflow.toml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
USER bgflow
EXPOSE 8080/tcp 2055/udp 4739/tcp
VOLUME ["/var/lib/bgflow"]
# BGFLOW_HTTP_LISTEN may change the port — probe it at runtime.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- "http://${BGFLOW_HTTP_LISTEN:-127.0.0.1:8080}/api/v1/health" >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
