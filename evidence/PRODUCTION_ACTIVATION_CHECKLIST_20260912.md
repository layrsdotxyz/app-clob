# Final production activation checklist — prepared, not executed

Candidate: `ami-0781a67a374dc8a70`; EIF:
`6f1cc6cd61492e7b2d3c34d75256412542de640fefbf3b6f4aad7021cc742542`.
The measured commitments and isolated canary evidence are in
`STEP_5_FINAL_ISOLATED_ARCHIVE_EVIDENCE_20260912.md`.

## Gate order

1. An authorized governance signer supplies a single-use activation ID, bounded
   Unix expiry, and signature for `PRODUCTION_WRITER_GRANT_REQUEST_20260912.json`.
   Independently verify the signature with the approved governance verification
   material, equality of every measurement field, unexpired time, and
   `b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364`
   as the current fence-evidence hash.  Reject any mismatch; do not substitute
   an AMI, EIF, PCR, fence, epoch, or runtime value.
2. Provision the reviewed EC2/Nitro fixture in
   `deployment/layrs-direct-execution-production.template.yaml` at desired
   capacity zero.  It is intentionally an EC2 launch template, not an ECS task
   definition: Nitro enclaves require an EC2 Nitro parent.  Validate its private
   subnet, BFF-only security-group ingress, IMDSv2, archive/KMS least privilege,
   CloudWatch log group, disabled writer tag, and no route before any capacity.
3. The final dormant runtime has completed the authorized read-only custody/RPC
   preflight using existing secret references: it resolved the existing signer
   configuration and Base pool-ledger wallet, reached the authenticated Base RPC,
   and retained the 20-confirmation policy without submitting or signing a
   transaction.  A funded canary remains required to observe a new intent-bound
   payout; no historical transaction may be substituted for that evidence.
4. A named alert owner creates and confirms a subscription on
   `layrs-production-operational-alerts`; test delivery with a non-financial
   alert.  No endpoint is assumed in this package.
5. Every alarm below is remediated or explicitly accepted by its responsible
   owner and recorded with expiry.  Alarms must not be disabled or silenced to
   satisfy this gate.
6. Only after gates 1-5, separately authorize the funded canary below.  The
   writer remains disabled until the grant, route, custody preflight, alert
   delivery, and attestation checks all pass immediately before execution.

## Current alarm audit

All entries below were independently read from CloudWatch at 2026-09-12 IST.
Every action points at the existing `layrs-production-operational-alerts` topic,
which has zero subscriptions.  No alarm was disabled, altered, or suppressed.

| Alarm | observed root condition | disposition required before activation |
|---|---|---|
| `active-market-publication-pending` | 10 missing periods treated as breaching; refreshed 2026-09-12. | Restore/retire its publisher and prove a fresh metric, or named owner accepts a bounded exception. |
| `audit-dlq-not-empty` | 2 messages, last breach 2026-08-24. | Preserve, classify, and reconcile the messages under an approved DLQ procedure; name owner/expiry if retained. |
| `chain-indexer-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |
| `control-scheduler-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |
| `deposit-withdrawal-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve and classify; do not redrive the fenced legacy financial writer. Name owner/expiry if retained. |
| `direct-runtime-health-missing` | 2 missing periods treated as breaching; refreshed 2026-09-12. | Wire the dormant runtime health metric, validate a fresh datapoint, and preserve fail-closed alerting. |
| `horizen-admin-treasury-low-eth` | Last observed 0.000999573 ETH, below 0.003 threshold. | Read current balance; treasury owner funds only if separately authorized, or explicitly retires/accepts with expiry. |
| `horizen-market-registrar-batch-funding-shortfall` | One missing period treated as breaching; refreshed 2026-09-12. | Restore/retire the reporter and prove a fresh metric, or named owner accepts a bounded exception. |
| `horizen-oracle-resolver-low-eth` | Last observed 0.001997341 ETH, below 0.003 threshold. | Read current balance; treasury owner funds only if separately authorized, or explicitly retires/accepts with expiry. |
| `horizen-pool-ledger-signer-low-eth` | Last observed 0.001997731 ETH, below 0.003 threshold. | Read current balance; treasury owner funds only if separately authorized, or explicitly retires/accepts with expiry. |
| `horizen-settlement-audit-signer-low-eth` | Last observed 0.001374823 ETH, below 0.003 threshold. | Read current balance; treasury owner funds only if separately authorized, or explicitly retires/accepts with expiry. |
| `horizen-zen-bridge-sweeper-low-eth` | Last observed 0.001377778 ETH, below 0.003 threshold. | Read current balance; treasury owner funds only if separately authorized, or explicitly retires/accepts with expiry. |
| `horizen-zen-market-maker-low-eth` | Last observed 0.001999078 ETH, below 0.003 threshold. | Read current balance; treasury owner funds only if separately authorized, or explicitly retires/accepts with expiry. |
| `market-data-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |
| `milestone-adoption-report-stale` | One missing period treated as breaching; refreshed 2026-09-12. | Restore/retire its reporter and prove a fresh metric, or named owner accepts a bounded exception. |
| `outbox-dispatcher-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |
| `reconciliation-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |
| `resolution-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |
| `rolling-market-current-inventory-missing` | 3 missing periods treated as breaching; refreshed 2026-09-08. | Restore/retire its reporter and prove a fresh metric, or named owner accepts a bounded exception. |
| `vault-accounting-dlq-not-empty` | 6 messages, last breach 2026-08-26. | Preserve, classify, and reconcile under an approved DLQ procedure; name owner/expiry if retained. |

## Funded-canary approval record — intentionally incomplete

No source account, destination, amount, or authorization has been supplied.
The approver must populate all fields before execution; blank values prohibit it.

```text
approval ID / two named approvers:
source controlled account and verified identity:
destination (verified embedded Privy EVM wallet):
asset / exact atomic amount / maximum fee:
single idempotency key and session nonce:
expected receipt ID, accounting event, custody reference, and finality threshold:
independent observer and reconciliation owner:
stop conditions: missing or corrupt archive; ACK mismatch; attestation/PCR mismatch;
writer-fence or grant mismatch; pending/reverted/ambiguous custody; missing alert delivery;
any duplicate artifact, receipt, accounting, custody, or projection event.
```

On success, the observer must prove `request -> immutable artifact -> ACK ->
adoption -> receipt -> accounting -> custody finalized -> PostgreSQL projection
-> parent/enclave restart -> exact replay with no second effect`. PostgreSQL is
only a projection and must never reconstruct private financial state.

## Read-only findings at preparation time

- The old public API, deposit/withdrawal service, and Green core coordinator are
  each steady at desired/running `0/0`; no legacy writer is restored.
- The alert topic has zero confirmed subscriptions.
- The direct runtime has a completed read-only preflight against existing
  production references.  It remains dormant and no custody request, signature,
  intent, or archive write was created.
- Neither this checklist nor the dormant deployment fixture activates a writer,
  route, capacity, funded canary, or customer balance change.
