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

## Privacy boundary

The production path is `layrs-enclave`, not the retained migration server. The measured Nitro
image owns private principals, balances, orders, matching, positions, withdrawals, resolution
state, the bootstrapping Polymarket account, and the two audited-pool transaction signers. The
EC2 parent relays encrypted frames and a fixed Polymarket TLS tunnel only; it has no AWS
credentials, KMS permission, database access, object-store access, chain signing key, or
plaintext application secret. External persistence contains authenticated ciphertext and
deliberately public aggregates.

The planned separation is:

- `clob-core`: deterministic matching and risk logic;
- `enclave-clob`: attested private order, matching, and balance authority;
- `clob-gateway`: untrusted network proxy and public aggregate publisher;
- external persistence: encrypted journal/checkpoints plus non-sensitive public
  projections.

The legacy Redis/PostgreSQL modules are not eligible for production private-order routing.
The EIF and parent are compiled from separate locked manifests under `enclave/`; see
[`SECURITY_ADVISORIES.md`](SECURITY_ADVISORIES.md) for their enforced dependency boundaries.

## Production custody path

The enclave accepts one sealed chain-signer bundle containing exactly two domains: Base
`8453`/USDC and Horizen `26514`/ZEN. Each domain pins a chain, asset, audited `LayrsPool`
address, an independently pinned `AdminOracle`, separate ledger/oracle EOA keys, and one
cross-domain Ed25519 resolution-evidence key. A ledger signer can produce only an EIP-1559 call
to `withdraw(address,uint256)` on its pinned pool after private-core authorization. An oracle
signer can produce only `AdminOracle.resolve(bytes32,uint8,string)` after the core verifies the
exact signed Pyth/Polymarket evidence and outcome. The Ed25519 key signs that evidence inside the
enclave; only its public verifier enters ordinary service configuration. Nonces, raw transactions
and fees are persisted before broadcast so recovery rebroadcasts identical bytes. New Layrs V2
markets use the versioned `C * rate * p * (1-p)` taker-fee curve, zero winning fee, and
private maker-rebate attribution; already-open V1 markets retain their original 20 bps
taker and winning-fee policy byte-for-byte.

Outcome-contract quantities and prices use six protocol decimals. Settlement balances always
use token atomics: six decimals for USDC and eighteen decimals for ZEN. The enclave converts
every ZEN notional, fee, collateral and payout leg by exactly `10^12`; deposit and withdrawal
amounts cross the custody boundary without rescaling. Fields ending in `_micros` represent
contract/quote units, while fields ending in `_atomic` represent the settlement token.

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
