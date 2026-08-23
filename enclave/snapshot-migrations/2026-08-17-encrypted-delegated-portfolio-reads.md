# Encrypted delegated portfolio reads

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 97614f37c05089708f93bf50ac8831adde98ab2f
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs platform and financial-core owners, subject to the normal
measured-EIF, signed-manifest, PCR and production certification gates.

## Change

This release adds a non-mutating `DELEGATED_PORTFOLIO_READ` operator command.
The coordinator supplies an API-key subject's current private-session identity
commitment over the existing authenticated operator channel. The enclave
derives that identity's private owner, creates a current `PortfolioSnapshot`
projection, and encrypts the requested balances, positions, or active orders
directly to a caller-generated ephemeral X25519 public key.

The command accepts only an exact environment/audience/scope combination, a
30-to-300-second capability lifetime, and an API-key revocation check no more
than ten seconds old. The response uses context-bound X25519, SHA-256 and
AES-256-GCM, contains no owner identity, and excludes historical fills. The
operator nonce and encrypted transport replay caches remain unchanged and
reject duplicate authenticated envelopes before command execution.

## State compatibility

No snapshot, journal, ledger, balance, hold, position, order, fill, market,
session, reward, fee, resolution, replay-cache, state-root, or persisted enum
field is added, removed, reordered, or reinterpreted. The new engine method is
read-only and operates on the existing in-memory state. It does not journal,
advance the private-core sequence, modify a replay cache, emit a snapshot, or
change the state root.

Release `97614f37c05089708f93bf50ac8831adde98ab2f` remains the exact source
commit of the recorded production fee-v2 enclave release; its manifest declares
snapshot compatibility against `bfc71fea48aa11e9f220ae9e461bf4c93b0b0321`.
The candidate restores that lineage without transformation.

## Production replay plan

1. Fence private mutations and retain the immutable production snapshot,
   encrypted journal, sequence, journal head, state root, parent binary, EIF,
   measurements, signed manifest, and PCR policy.
2. Restore the retained snapshot and replay the journal in the candidate.
   Require exact equality of sequence, journal head, state root, balances,
   holds, positions, active orders, fills, fees, rewards, and resolutions.
3. Execute repeated delegated reads for two controlled identities. Require
   strict cross-identity separation and no change to sequence, journal head,
   state root, replayable state, or snapshot publication.
4. Exercise wrong scope, audience, environment, expiry, stale revocation check,
   all-zero recipient key, response-key substitution, ciphertext tampering,
   operator-envelope replay, and transport-nonce replay. Every invalid case
   must fail closed without returning plaintext or changing state.
5. Decrypt successful responses only with the intended recipient key and exact
   request/capability context. Reconcile balances, positions and active orders
   against authenticated browser portfolio reads for the same controlled user.
6. Build and measure the candidate EIF, rotate the signed manifest and PCR
   allowlist together, then run a capped read-only canary before enabling MCP
   private tools. Require no new DLQ messages, stale jobs, privacy alarms, or
   financial reconciliation differences.

## Rollback plan

Before the candidate accepts any mutating command, fence it and restore the
retained production parent AMI, EIF, signed manifest and PCR policy. Delegated
reads create no durable transition, so successful reads require no ledger
reconciliation before rollback.

If any unrelated mutating candidate command has been accepted, stop intake,
preserve the candidate snapshot and encrypted journal, reconcile every custody
and ledger boundary, and repair forward. Never truncate, edit, or reconstruct
the journal to force rollback.

## Approval

The guarded engine change is intentional but not a persisted-state migration.
It may activate only after exact production-lineage replay, recipient-only
encryption and adversarial authorization tests, a measured EIF release, signed
manifest/PCR rotation, and a controlled readback with unchanged financial
state.
