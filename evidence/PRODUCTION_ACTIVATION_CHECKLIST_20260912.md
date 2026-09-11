# Final production activation checklist — prepared, not executed

Candidate: `ami-0a26d307d4920f05b`; EIF:
`a71f54ccc2b420b8771d16a1607582e72c7394171d7d3217a86cc7c772eafa74`.
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
3. An authorized custody owner injects the direct-runtime-only credential and
   fixed Base finality configuration.  Run a read-only query of a named historic
   transaction and retain only its transaction hash, observed state, block/finality
   threshold, adapter version, and timestamp.  It must distinguish pending,
   finalized, and reverted; it must not send a transaction or expose a secret.
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

| Alarm(s) | condition and impact | required remediation / acceptance |
|---|---|---|
| `active-market-publication-pending`; `horizen-market-registrar-batch-funding-shortfall`; `milestone-adoption-report-stale`; `rolling-market-current-inventory-missing` | Missing telemetry is treated as breaching; operational state cannot be trusted as current. | Restore the specific publisher/reporter, verify fresh datapoints, or obtain time-bounded owner acceptance with an alternative monitored signal. |
| `audit-dlq-not-empty`; `chain-indexer-dlq-not-empty`; `control-scheduler-dlq-not-empty`; `deposit-withdrawal-dlq-not-empty`; `market-data-dlq-not-empty`; `outbox-dispatcher-dlq-not-empty`; `reconciliation-dlq-not-empty`; `resolution-dlq-not-empty`; `vault-accounting-dlq-not-empty` | All point to the same legacy DLQ, currently 916 visible messages. The alarm history is stale, but the queue condition is current and unresolved. | Preserve and classify every message, reconcile any financial impact, then drain/replay only under an approved procedure; otherwise record explicit owners and a bounded exception. |
| `horizen-admin-treasury-low-eth`; `horizen-oracle-resolver-low-eth`; `horizen-pool-ledger-signer-low-eth`; `horizen-settlement-audit-signer-low-eth`; `horizen-zen-bridge-sweeper-low-eth`; `horizen-zen-market-maker-low-eth` | Last observed values were below the 0.003 ETH threshold; observations are stale but could block required operational actions. | Independently read current balances, fund only with treasury authorization if still low, or record owner acceptance if each role is retired. |

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
- No direct-runtime-specific production custody credential was identified
  without reading secret values.  The available `layrs/production/providers/rpc`
  is legacy-provider metadata only and is not approved for this path.
- Neither this checklist nor the dormant deployment fixture activates a writer,
  route, capacity, funded canary, or customer balance change.
