# BGFlow — multi-stage build
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release --locked -p bgflowd

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/bgflow --shell /usr/sbin/nologin bgflow \
 && install -d -o bgflow -g bgflow /var/lib/bgflow \
 && mkdir -p /etc/bgflow
COPY --from=build /src/target/release/bgflowd /usr/local/bin/bgflowd
COPY bgflow.example.toml /etc/bgflow/bgflow.toml
USER bgflow
EXPOSE 8080/tcp 2055/udp
VOLUME ["/var/lib/bgflow"]
ENTRYPOINT ["bgflowd", "--config", "/etc/bgflow/bgflow.toml"]
