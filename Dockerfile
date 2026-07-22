# Standalone container for the Layrs CLOB service. Build from this repository's
# root: docker build -t layrs-clob-service:local .
FROM rustlang/rust:nightly-bookworm-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --release --bin layrs-clob-service

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 clob

COPY --from=builder /build/target/release/layrs-clob-service /app/layrs-clob-service

USER clob
EXPOSE 8081 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8081/health || exit 1

ENTRYPOINT ["/app/layrs-clob-service"]
