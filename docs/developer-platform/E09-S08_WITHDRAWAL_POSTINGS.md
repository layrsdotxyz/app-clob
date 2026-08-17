# E09-S08 Withdrawal Postings Evidence

## Scope

This story makes the enclave ledger authoritative for the complete withdrawal
accounting lifecycle. It does not deploy, migrate, broadcast, or move funds.

## Financial invariants

- Reservation remains an atomic same-asset transfer from the opaque user's
  `UserAvailable` account to `UserWithdrawalHold`.
- Successful finality atomically decreases both `UserWithdrawalHold` and the
  canonical same-asset `PoolCash` balance.
- A confirmed withdrawal emits `DR UserWithdrawalHold / CR PoolCash`; the two
  posting amounts must be equal.
- A proven terminal failure returns the hold to the same opaque user's
  `UserAvailable` account without changing `PoolCash`.
- Confirmation and release are mutually exclusive because both consume the
  same hold. No balance may become negative.
- Financial replay keys derive from independent finality/failure evidence, not
  only an operator-provided idempotency key, and survive snapshot restore.
- One-atomic-unit withdrawals remain exact; no rounding or dust is introduced.

## Privacy boundary

The ledger stores only the enclave-derived opaque owner. Wallet, email,
destination, provider route, transaction payload, and individual postings do
not leave the encrypted journal through any new public response.

## Source and tests

- `src/private_core/ledger.rs`: balanced confirmation and failure-release
  primitives with evidence-derived replay protection.
- `src/private_core/engine.rs`: dedicated confirmed-withdrawal journal command;
  existing receipt command ID remains stable for deterministic archive lookup.
- `tests/withdrawal_postings.rs`: posting shape, conservation, insufficient
  balance atomicity, malformed input, replay, snapshot/lost-response, dust,
  partial amounts, and confirm/release race ordering.
- `tests/private_core.rs`: signed authorization, reservation, prepared
  transaction recovery, confirmation, failure release, and restored replay.

## CI evidence

Exact commit and authoritative GitLab pipeline/job links are recorded on the
merge request after both fast and full pipelines complete successfully.
