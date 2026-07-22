# Upstream source and extraction record

## Selected baseline

- Upstream repository: `https://github.com/Predifi-com/clob-service`
- Baseline commit: `82c2241ec318ae5aa83bda99093b59849aa6a469`
- Extraction date: 2026-07-22

This baseline was selected instead of
`predifi/Hedera/clob-service` (`fd776a4638e3dc17a5c46edf39c2d4726e6a24f1`)
because the latter is an older three-commit prototype. The selected baseline
contains later durability, lifecycle, authorization, private-ledger, settlement,
and real Redis/PostgreSQL integration work.

## Extraction policy

The first Layrs commit changes repository metadata, documentation, container
packaging, and brand names only. It does not intentionally change matching,
pricing, order priority, balance accounting, or settlement behavior.

One uncommitted line in the legacy working tree
(`src/proof_generation/prover_worker.rs`, adding an EVM verifier target to a
Barretenberg command) was deliberately not imported. It remains untouched at
its original location and must be reviewed separately if the ZK worker is
retained.

The historical EIP-712 domain `Predifi CLOB` is deliberately not renamed in
this extraction. Changing a signing domain is a protocol change requiring a
coordinated contract/client migration and replay-domain review; it is not a
cosmetic rename.

## Required production refactor

The baseline is reusable engineering, not a production privacy attestation.
Private order and ledger records currently cross Redis/PostgreSQL boundaries.
The Nitro Enclave refactor, key-release policy, encrypted persistence format,
recovery protocol, and attestation verification must be completed and audited
before the service can be marketed as a confidential order book.
