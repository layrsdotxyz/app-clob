# Confirmed withdrawal release correction

## Scope

This release adds an evidence-bound operator command that reverses only an
erroneous `RELEASE_WITHDRAWAL` reconciliation for a withdrawal already proven
paid on chain. It also keeps the Base ZEN bridge-back withdrawal support from
release `090f8fc22238bcdfe20a0b8b0c3b8c14c9e4c8be`.

## Persisted-state compatibility

- No snapshot field, journal variant, serialized ledger type, or replay ordering
  changes.
- The correction uses the existing `ExternalFlow` journal entry.
- The enclave accepts the correction only when the exact prior release
  idempotency key already exists in enclave state.
- A unique correction idempotency key prevents replay.
- Insufficient user-available balance fails before journal/state mutation.

The encrypted snapshot and journal produced by
`090f8fc22238bcdfe20a0b8b0c3b8c14c9e4c8be` remain replay-compatible.

## Security boundary

The backend must independently prove that the withdrawal is `CONFIRMED`, has a
pool transaction and final enclave receipt, has no competing live withdrawal,
and supplies the domain-separated evidence hash. The enclave then additionally
requires the exact prior release marker before it can debit the duplicate
available balance.

## Rollback

Rollback to `090f8fc22238bcdfe20a0b8b0c3b8c14c9e4c8be` is snapshot-compatible after
the correction journal entry has been replayed because it is encoded as the
pre-existing `ExternalFlow` variant.
