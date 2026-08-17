# E09-S06 fee and reward postings

## Scope

- Every fill stores its immutable category profile and canonical fee-policy family.
- `LAYRS_FEE_V2` covers NORMAL, MINT and MERGE without changing the S04/S05 fee-revenue postings.
- Maker rebates and program rewards post equal expense debits and payable credits per custody rail and asset.
- Fill IDs and reward evidence hashes, rather than transport idempotency keys, provide exact-once replay identity.
- Private owner commitments remain enclave-private and are not added to public receipts or projections.

## Recovery and invariants

- Identical fill/evidence replay is a no-op; altered replay fails closed.
- Snapshot restore preserves attribution, accrual and posting replay guards.
- A response-lost retry under a new operator key cannot double-accrue.
- Cross-chain and cross-token postings never net against each other.

## Local evidence

- `cargo fmt --all -- --check`
- `cargo test --lib private_core::rewards::tests` (8 passed)
- `cargo test --test private_core private_rewards_accrue_cumulatively_and_authorize_only_the_bound_account` (passed; includes snapshot/response-lost retry)
- `cargo test --all`

Authoritative GitLab pipeline evidence is linked from the merge request.
