# Production custody execution blocker — 2026-09-12

This is a source-level, fail-closed finding against approved runtime source
`d6202ae`.  It was discovered while inventorying existing production signer
and secret *references* only; no secret value was read and no production
writer, wallet, custody operation, or balance was changed.

## Evidence

`enclave/direct-execution-v1/src/bin/parent.rs`, lines 332-362:

- every `RESERVE_WITHDRAWAL` request returns HTTP 503
  `CUSTODY_ADAPTER_NOT_ENABLED` when `state.isolated_test` is false;
- the only succeeding branch constructs `mock-custody:<sha256>`;
- there is no production custody client, existing-signer invocation, Base RPC
  finality reader, or submitted/pending/finalized/reverted implementation in
  the direct-runtime crate.

The runtime therefore cannot perform a real production withdrawal or meet the
required custody-finality semantics.  This is independent of whether existing
AWS secret references and operational wallets are available.

## Why no workaround is safe

- Re-enabling or calling the fenced `layrs-production-deposit-withdrawal`
  legacy worker would violate the persistent legacy-writer fence and reintroduce
  the old command path.
- Treating `mock-custody` as a production receipt would fabricate custody
  evidence.
- PostgreSQL projection records cannot supply missing private-ledger authority
  or custody finality.

## Required next authorization and work

Authorize a bounded implementation and independent review of a production
direct-runtime custody adapter that reuses the exact inventoried production
wallet/signer and AWS Secrets Manager references, performs an actual read-only
finality preflight, and makes no wallet/key/identity creation.  It must retain
the synchronous candidate -> immutable archive -> ACK -> adoption flow and
must not call the legacy Durable/worker path.  A fresh isolated build,
attestation, and production WriterGrant would then be required.

Until that work is complete, a WriterGrant or funded canary must not be issued
for this candidate.
