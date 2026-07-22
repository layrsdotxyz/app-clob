# Layrs CLOB Service

Rust/Axum central-limit-order-book and private-ledger service for Layrs.

> Layrs v2 implementation note: the production ZEN path is documented in
> [PRIVATE_CLOB_ARCHITECTURE.md](PRIVATE_CLOB_ARCHITECTURE.md). Predifi/Hedera-era modules remain
> only as migration reference and are not part of the release enclave.

This repository was extracted from the mature Predifi CLOB implementation at
commit `82c2241ec318ae5aa83bda99093b59849aa6a469`. See
[`UPSTREAM_SOURCE.md`](UPSTREAM_SOURCE.md) for provenance and the extraction
rules.

## Current capabilities

- Price-time-priority matching with GTC, IOC, FOK, and post-only behavior.
- Redis/Valkey order-book operations and PostgreSQL durable order, fill, trade,
  balance, and lifecycle records.
- REST and WebSocket interfaces with private user channels.
- Balance reservation, settlement, retry workers, oracle-driven markets,
  circuit breakers, and Prometheus metrics.
- Existing ZK proof and EVM settlement adapters retained as migration inputs.

## Important privacy status

This code is **not yet a confidential CLOB merely because it runs in Rust**.
The present implementation can persist full order and ledger metadata in
Redis/Valkey and PostgreSQL. Before production, the private matching and ledger
boundary must run inside an attested AWS Nitro Enclave, with private state kept
inside the enclave or written externally only as authenticated ciphertext.
Public stores and APIs may expose aggregate depth, public prices, market status,
and deliberately disclosed settlement artifacts only.

The planned separation is:

- `clob-core`: deterministic matching and risk logic;
- `enclave-clob`: attested private order, matching, and balance authority;
- `clob-gateway`: untrusted network proxy and public aggregate publisher;
- external persistence: encrypted journal/checkpoints plus non-sensitive public
  projections.

That separation will be implemented without silently treating Redis isolation
as cryptographic confidentiality.

## Local build

Prerequisites are a Rust toolchain, Redis/Valkey, and PostgreSQL. Copy
`.env.example` to an untracked `.env`, then run:

```bash
cargo build
cargo run --bin layrs-clob-service
```

The real-backend integration harness and lifecycle matrix live under `tests/`
and `LIFECYCLE_VERDICT_MATRIX.md`.

## Deployment naming

All new AWS infrastructure, secrets, images, roles, logs, and data stores for
this generation must use the `layrsv2` prefix. The public product and source
code remain branded **Layrs**; `layrsv2` is the infrastructure-generation
identifier.

No legacy Layrs AWS resource is a deployment target for this repository.

## License

Proprietary — Layrs.
