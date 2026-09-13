# Final external activation boundaries — 2026-09-12

Read-only final recheck after the isolated final-candidate verification.

## Controls still intact

- The final isolated verifier for `ami-0134f2ff9e2faecab` was terminated after
  attestation; it was tagged `WriterEnabled=false` and had no customer state.
- Legacy Layrs public API, deposit/withdrawal worker, operator coordinator,
  and Green coordinator remain desired/running `0`.
- No production writer, custody transaction, customer balance, production
  database row, wallet, signer, or operational key was created or changed.

## Exact external authorization boundaries

1. **Governance WriterGrant:** the existing KMS ECDSA authority needs the
   approved single-use activation/change identifier, bounded expiry, and
   external governance signature over the exact final binding in
   `FINAL_DIRECT_BFF_CANDIDATE_20260912.md`.  No such approved values exist in
   the activation artifacts, so none was fabricated or signed.
2. **SNS recipient:** the existing production topic
   `layrs-production-operational-alerts` has zero confirmed subscriptions.
   No authorized recipient/configuration exists in the production metadata or
   recorded Subscribe/Unsubscribe history.  An authorized existing-recipient
   subscription and controlled delivery confirmation are required.
3. **Alarm acceptance/remediation:** the exact 20 Layrs production alarms are
   still in `ALARM`; the existing per-alarm checklist remains applicable.  In
   particular, the fenced deposit/withdrawal DLQ has 916 visible messages and
   must not be redriven or deleted; stale telemetry and Horizen funding alarms
   require their documented owners or time-bounded acceptance.
4. **Funded canary:** separate authority for the exact pre-recorded source,
   destination, amount, fee cap, nonce strategy, observers and rollback owner
   is absent.  No payout was broadcast.

These boundaries are governance/operations approvals, not implementation
shortcuts.  They intentionally prevent writer enablement and the funded
canary.
