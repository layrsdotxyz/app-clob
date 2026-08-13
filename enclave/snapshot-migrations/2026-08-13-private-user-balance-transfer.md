# 2026-08-13 — private user balance transfer

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: c5f017a19a09ef12c7e48529edcbad2b10c8d0ed
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

The private core adds an authenticated `TRANSFER_FUNDS` user command that moves
an available USDC or ZEN balance from one enclave-local user account to another
in one ledger transaction. Recipients are addressed by stable opaque
`layrs_<sha256>` handles. A separate journaled system command registers each
handle against the existing eligibility-bound private user identity, while a
read-only status command makes registration retries safe.

The transfer command cannot consume order holds, withdrawal holds, positions,
vault shares, or protocol accounts. It rejects zero amounts, unsupported assets,
self-transfers, unknown or non-canonical handles, and insufficient available
balances. Successful commands use the existing signed receipt, encrypted
journal, snapshot, replay cache, and receipt-batching paths.

## State compatibility

No field is added to `CoreStateSnapshot`, no account bucket changes, and no
journal encryption or snapshot envelope changes. Existing snapshots and journal
records deserialize and replay without transformation. Transfer-account
bindings are stored as domain-separated entries in the existing committed
`system_keys` set and therefore begin empty after restoring the live snapshot.
The coordinator deterministically registers a binding once for each existing
or newly created private session.

Serde adds new enum variants only. Historical variants retain their exact
encoding and state-root behavior. Registration is deliberately separate from
the historical `REGISTER_SESSION` command so replaying old session records does
not change their roots.

## Production replay plan

1. Fence new private mutations and preserve the live encrypted snapshot,
   journal head, parent binary, EIF, measurements, checksums, and signed release
   manifest for the base commit above.
2. Restore the retained snapshot and replay the encrypted journal into the
   candidate EIF. Require the exact live sequence, journal head, state root,
   balances, holds, books, sessions, resolutions, and rewards.
3. Query transfer-account status for an existing session and verify the query
   does not change sequence, root, journal, or snapshot.
4. Register two controlled transfer accounts and verify each registration
   advances exactly one sequence and survives encrypted snapshot restore.
5. Deposit a small controlled amount, reserve part of it, transfer only from
   available balance, and verify exact sender debit, recipient credit, unchanged
   holds, conservation, signed receipt, journal replay, and receipt publication.
6. Replay the exact command and require the identical response with no second
   debit. Exercise unknown recipient, self-transfer, insufficient balance, zero
   amount, unsupported asset, and malformed handle failures with unchanged root.
7. Rotate the signed release manifest, PCR policy, and parent AMI together.
   Verify fresh nonce-bound Nitro attestation before deploying the compatible
   backend and frontend, then enable only the controlled canary.

## Rollback plan

Before any successful candidate mutation, restore the retained parent AMI, EIF,
PCR policy, and signed release manifest directly. After a successful transfer or
account registration, never roll the private ledger backward: retain the
candidate journal and snapshot, freeze new commands, reconcile the exact
balances and receipt evidence, and recover forward with the candidate or a
compatible successor EIF.

If backend or frontend deployment fails after the enclave cutover, keep the new
EIF and deploy the prior clients only if they do not require mutation; otherwise
freeze the affected surface until compatible clients are restored.

## Approval

This is an intentional money-moving private-core extension requested for the
controlled Layrs launch. It requires the measured EIF build, immutable artifact
retention, signed manifest and PCR rotation, restore/replay canary, funded
two-user transfer proof, and exact post-canary reconciliation.
