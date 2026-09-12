# Final activation boundary — final dormant candidate

Candidate source is `6f0389e39c51cd383ac86791a0c59e59a310f181` and the
evidence-package commit is `5769261`.  The only deployed target is the
private, writer-disabled dormant instance from `ami-0781a67a374dc8a70`.

## Completed without financial mutation

- Exact AMI, parent binary, EIF, PCR0/PCR1/PCR2 and sealed opening evidence
  were independently attested in `us-east-1`.
- A dedicated runtime role can read only the existing runtime and Base-RPC
  secret references.  Secret values were never output or recorded.
- The role has only the required Object-Lock archive, archive KMS and
  context-restricted operational-identity KMS permissions.
- The parent loads the existing Base pool-ledger wallet configuration, Privy
  application configuration, Base RPC configuration and confirmation policy
  through those references.  Read-only Privy lookup and Base RPC chain,
  pending-nonce and latest-block checks succeeded; no signature or submission
  occurred.
- The private dormant target restarted successfully with the sealed state and
  no archive artifacts.  It has no public route and no WriterGrant.
- Every recorded legacy financial service currently has desired and running
  count zero.  The direct-runtime executable identifier audit found no
  Durable Command or `DURABLE_PREPARATION` executable identifier.

## Exact external authorization gates

1. A governance signer must issue the bounded, single-use WriterGrant in
   `PRODUCTION_WRITER_GRANT_REQUEST_20260912.json` for this exact AMI, EIF,
   PCRs, opening state and legacy-writer-fence hash.  No signature has been
   fabricated.
2. An authorized alert recipient is required for the production operational
   SNS topic.  It has no confirmed subscription.  The 20 active alarms,
   including legacy DLQ, stale telemetry and Horizen funding alarms, require
   remediation or explicit owner acceptance; none were silenced.
3. Before the writer can be enabled, the approved direct BFF/session route and
   the production projection credential/configuration must be supplied under
   their own governed deployment approvals.  The present target intentionally
   has neither public route nor production projection database access.
4. A separately authorized funded canary is required to create the first
   production immutable external-effect intent and to prove a real
   intent-to-provider pending/finalized/reverted binding.  The read-only
   preflight cannot create that irreversible effect, and no historical
   direct-runtime intent exists to substitute for it.

`PRODUCTION_ACTIVATION_STATUS = WAITING_FOR_EXTERNAL_AUTHORIZATION`
