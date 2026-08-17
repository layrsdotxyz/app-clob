# E09-S11 Attested Custody Reconciliation Snapshot

## Scope

This story exposes a privacy-minimal, read-only custody snapshot over the
authenticated enclave operator channel. It does not deploy an enclave, apply a
database migration, move funds, or alter public APIs.

## Enclave guarantees

- Only aggregate `POOL_CASH`, `VAULT_CASH`,
  `VAULT_STRATEGY_IN_TRANSIT`, `VAULT_STRATEGY_RECEIVABLE`, and
  `BRIDGE_IN_TRANSIT` totals leave the enclave.
- The response omits owner, wallet, identity, order, market, outcome, position,
  and individual posting fields.
- Checked addition fails closed on aggregate overflow.
- Every snapshot is Ed25519-signed over the checkpoint commitment, exactly two
  distinct chain-finality commitments, enclave sequence, private state root,
  custody totals, and receipt public key.
- Repeated reads at one sequence/root are cached and deterministic; financial
  mutations change the sequence/root and invalidate the cached view.
- A reconciliation freeze blocks order placement, complete-set operations, and
  new withdrawal reservations. Cancellation remains available so holds can be
  released while the protocol is cancel-only.

## Test evidence

- `tests/custody_reconciliation.rs` covers aggregate privacy, checked overflow,
  deterministic signed snapshot binding, and invalid/ambiguous finality.
- `tests/private_core.rs` proves cancel remains available while new orders and
  withdrawal reservations are blocked.
- Full `cargo test --all-targets` is the local regression gate.

Exact commit and authoritative GitLab pipeline/job links are recorded on the
merge request after both mandatory jobs complete successfully.
