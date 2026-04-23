# Multi-stage build for minimal production image.
#
# Build context: layrs-backend/  (one level UP from this file)
# Example:
#   docker build -f clob-service/Dockerfile -t clob-service:latest .
#
# This is required so we can COPY the ZK circuit artifacts (../circuits/) which
# live outside the clob-service/ sub-directory.
FROM rustlang/rust:nightly-bookworm-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests (from clob-service/ sub-directory relative to build context)
COPY clob-service/Cargo.toml clob-service/Cargo.lock ./

# Create dummy main + lib to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release && \
    rm -rf src

# Copy migrations (embedded at compile time by sqlx::migrate!)
COPY clob-service/migrations ./migrations

# Copy actual source code
COPY clob-service/src ./src

# Touch source files so their mtime is newer than the cached dummy binary,
# forcing cargo to detect the change and recompile the real binary.
RUN touch src/main.rs src/lib.rs

# Build release binary with full optimizations
RUN cargo build --release

# --- Node.js circuit builder stage ------------------------------------------
# Install snarkjs so it is available at a known absolute path in production.
FROM node:20-bookworm-slim AS node-builder

WORKDIR /circuits

# Copy only the circuits directory (wasm + zkey artifacts)
COPY circuits ./

# Install snarkjs locally -- we only need the CLI
RUN npm install snarkjs && npm cache clean --force

# --- Barretenberg bb stage --------------------------------------------------
# Download the bb binary matching bb version 0.15.3 (nargo 1.0.0-beta.20).
# Uses ubuntu:24.04 (GLIBC 2.39) which satisfies bb's runtime requirements.
FROM ubuntu:24.04 AS bb-stage

ARG BB_VERSION=0.15.3
RUN apt-get update -qq && \
    apt-get install -y -qq curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
    "https://github.com/AztecProtocol/aztec-packages/releases/download/aztec-packages-v${BB_VERSION}/barretenberg-x86_64-linux-gnu.tar.gz" \
    | tar -xzC /usr/local/bin/ bb && \
    chmod +x /usr/local/bin/bb

# --- Production image --------------------------------------------------------
# ubuntu:24.04 provides GLIBC 2.39, required by the bb binary.
FROM ubuntu:24.04

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Node.js runtime from official image (needed to run snarkjs)
COPY --from=node:20-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:20-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules

# Copy snarkjs and its node_modules
COPY --from=node-builder /circuits/node_modules /app/node_modules

# Copy ZK circuit artifacts (wasm + zkey for each circuit)
COPY --from=node-builder /circuits/private_deposit/circuit_js/circuit.wasm /app/circuits/private_deposit/circuit_js/circuit.wasm
COPY --from=node-builder /circuits/private_deposit/circuit_final.zkey /app/circuits/private_deposit/circuit_final.zkey
COPY --from=node-builder /circuits/private_withdraw/circuit_js/circuit.wasm /app/circuits/private_withdraw/circuit_js/circuit.wasm
COPY --from=node-builder /circuits/private_withdraw/circuit_final.zkey /app/circuits/private_withdraw/circuit_final.zkey
COPY --from=node-builder /circuits/private_order_commitment/circuit_js/circuit.wasm /app/circuits/private_order_commitment/circuit_js/circuit.wasm
COPY --from=node-builder /circuits/private_order_commitment/circuit_final.zkey /app/circuits/private_order_commitment/circuit_final.zkey
COPY --from=node-builder /circuits/private_transfer_settlement/circuit_js/circuit.wasm /app/circuits/private_transfer_settlement/circuit_js/circuit.wasm
COPY --from=node-builder /circuits/private_transfer_settlement/circuit_final.zkey /app/circuits/private_transfer_settlement/circuit_final.zkey
COPY --from=node-builder /circuits/private_market_claim/circuit_js/circuit.wasm /app/circuits/private_market_claim/circuit_js/circuit.wasm
COPY --from=node-builder /circuits/private_market_claim/circuit_final.zkey /app/circuits/private_market_claim/circuit_final.zkey
COPY --from=node-builder /circuits/private_yield_distribution/circuit_js/circuit.wasm /app/circuits/private_yield_distribution/circuit_js/circuit.wasm
COPY --from=node-builder /circuits/private_yield_distribution/circuit_final.zkey /app/circuits/private_yield_distribution/circuit_final.zkey

# Copy bb binary
COPY --from=bb-stage /usr/local/bin/bb /app/bb

# Copy Noir circuit ACIR JSON files (used by bb prove at runtime)
COPY circuits/noir/pm_balance_proof/target/pm_balance_proof.json /app/circuits/noir/pm_balance_proof/target/pm_balance_proof.json
COPY circuits/noir/pm_claim/target/pm_claim.json /app/circuits/noir/pm_claim/target/pm_claim.json
COPY circuits/noir/pm_deposit/target/pm_deposit.json /app/circuits/noir/pm_deposit/target/pm_deposit.json
COPY circuits/noir/pm_order_commitment/target/pm_order_commitment.json /app/circuits/noir/pm_order_commitment/target/pm_order_commitment.json
COPY circuits/noir/pm_settlement/target/pm_settlement.json /app/circuits/noir/pm_settlement/target/pm_settlement.json
COPY circuits/noir/pm_withdraw/target/pm_withdraw.json /app/circuits/noir/pm_withdraw/target/pm_withdraw.json
COPY circuits/noir/pm_yield_distribution/target/pm_yield_distribution.json /app/circuits/noir/pm_yield_distribution/target/pm_yield_distribution.json
COPY circuits/noir/vault_spend/target/vault_spend.json /app/circuits/noir/vault_spend/target/vault_spend.json

# Copy Noir VK files (used by bb verify at runtime)
COPY circuits/noir/pm_balance_proof/target/vk/vk /app/circuits/noir/pm_balance_proof/target/vk/vk
COPY circuits/noir/pm_claim/target/vk/vk /app/circuits/noir/pm_claim/target/vk/vk
COPY circuits/noir/pm_deposit/target/vk/vk /app/circuits/noir/pm_deposit/target/vk/vk
COPY circuits/noir/pm_order_commitment/target/vk/vk /app/circuits/noir/pm_order_commitment/target/vk/vk
COPY circuits/noir/pm_settlement/target/vk/vk /app/circuits/noir/pm_settlement/target/vk/vk
COPY circuits/noir/pm_withdraw/target/vk/vk /app/circuits/noir/pm_withdraw/target/vk/vk
COPY circuits/noir/pm_yield_distribution/target/vk/vk /app/circuits/noir/pm_yield_distribution/target/vk/vk
COPY circuits/noir/vault_spend/target/vk/vk /app/circuits/noir/vault_spend/target/vk/vk

# Copy binary from builder
COPY --from=builder /build/target/release/clob-service /app/clob-service

# Create non-root user
RUN useradd -m -u 1000 clob && chown -R clob:clob /app
USER clob

# Expose ports
EXPOSE 8080
EXPOSE 9090

# Health check (use PORT env var which defaults to 8081)
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:${PORT:-8081}/health || exit 1

# Run the service
CMD ["/app/clob-service"]
