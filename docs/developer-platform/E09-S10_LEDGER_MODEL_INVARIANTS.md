# E09-S10 Enclave Ledger Model Invariants

## Scope

This story hardens the existing private ledger model. It does not deploy an
enclave, alter custody, apply a database migration, or move funds.

## Enforced invariants

- Snapshot restore rejects duplicate accounts, zero rows, malformed private
  key components and malformed replay keys instead of normalizing attacker-
  controlled state.
- Genesis rejects zero balances, duplicate accounts and invalid keys.
- Every generic transfer is nonzero, same-asset, non-self, checked for debit
  underflow and credit overflow, and committed atomically.
- All commit paths prune spent zero-balance accounts before hashing or
  serialization, preventing unbounded zero-dust growth in the private tree.
- Diagnostic asset totals saturate rather than wrapping; callers that require
  exact totals use `checked_total_for_asset` and receive an explicit error on
  aggregate overflow.
- A transfer into `RoundingReserve` must target the protocol-owned, unscoped
  reserve and is bounded to 0.001 token per transaction. A larger residual is
  treated as a broken settlement invariant, not silently absorbed.
- Evidence-derived replay keys remain independent of transport idempotency
  and are validated before any mutation.

## Privacy boundary

No public response changes. Account owners, balances, postings, replay keys and
snapshot validation remain inside the encrypted enclave journal.

## Test evidence

- `tests/ledger_model_invariants.rs` covers malformed snapshots, duplicate and
  zero genesis, underflow/overflow, replay, self-transfer, atomic rejection,
  bounded dust and canonical zero pruning.
- A 5,000-case property suite runs up to 127 transfers across eight opaque
  accounts and proves exact conservation and model equivalence after every
  successful mutation.
- Full `cargo test --all-targets` remains the local regression gate.

Exact commit and authoritative GitLab pipeline/job links are recorded on the
merge request after both mandatory jobs complete successfully.
