# 2026-08-11 - bounded authenticated-session state

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: a20054760953213ac2117cc42b9e7ef4f9826fb9
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly authorized repairing the
production private-session and funded-flow failure before certification resumes.

## Change

Before registering a new authenticated browser session, the private core removes
registered sessions whose signed expiry time is at or before the command time. It
also removes the corresponding replay-sequence entries. Active sessions and their
replay sequence are retained exactly.

The new command time is included in newly journaled `REGISTER_SESSION` commands,
so pruning is deterministic and replay does not depend on an enclave wall clock.
No persisted struct gains or loses a field: `SessionGuard`, balances, holds,
orders, fills, markets, withdrawals, rewards and resolution state keep their
existing snapshot representation.

The encrypted journal and snapshot ciphertext vectors additionally use CBOR byte
strings on the enclave-to-parent wire instead of CBOR arrays of integers. JSON
archive compatibility is retained, including the existing integer-array form.
This avoids expanding a production checkpoint by several times while it crosses
VSOCK, without changing the authenticated ciphertext, snapshot plaintext,
journal AAD, snapshot AAD, state-root material or immutable archive schema.

## State compatibility

The candidate restores the snapshot emitted by release
`a20054760953213ac2117cc42b9e7ef4f9826fb9` without transformation. Expired
sessions remain present immediately after restore, preserving the committed
state root. The first successful new registration deterministically removes only
expired entries and commits the resulting state through the normal journal and
checkpoint path.

Existing sessions with an expiry after the new command time remain valid. An
expired session cannot authorize a command before or after this release. A
pruned session identifier may be registered again only with a fresh signed
registration command.

## Production replay plan

1. Fence new private mutations and retain the latest immutable snapshot,
   sequence, journal head and state root from the deployed base release.
2. Restore that exact snapshot in the candidate EIF and require equality of the
   sequence, journal head, state root, balances, holds, positions, open orders,
   market registrations and resolutions before accepting a command.
3. Export the restored state through the candidate and verify the compact CBOR
   frame round-trips to the same encrypted snapshot.
4. Register one controlled authenticated session. Require completion within the
   bounded parent/API deadlines, removal of expired sessions only, a durable
   journal record and checkpoint, and a valid enclave-signed registration
   receipt.
5. Restore the resulting checkpoint into the same candidate and require exact
   sequence, journal-head and state-root equality.
6. Run one funded order/cancel and one user withdrawal canary, then restore
   workers sequentially. Require no new private-command timeout, DLQ message,
   stale job, balance mismatch or critical alarm during the soak.

The release suite covers active-versus-expired pruning, replay-sequence cleanup,
session-id reuse after expiry, full private-core tests, production binary tests,
and a 7 MiB compact-CBOR snapshot round trip while retaining JSON compatibility.

## Rollback plan

Before the candidate accepts a command, fence it and restore the prior AMI, EIF,
parent binary, signed manifest and PCR allowlist for release
`a20054760953213ac2117cc42b9e7ef4f9826fb9` using the retained immutable
checkpoint.

After the candidate accepts a command, stop intake and preserve its checkpoint
and encrypted journal. Because the persisted state schema and JSON archive wire
shape are unchanged, the previous release can decode the post-prune snapshot;
nevertheless, do not reopen until sequence, root, balances, holds and external
custody are reconciled. Never truncate the journal or recreate expired sessions.

## Approval

This is an intentional private-core liveness and state-bounding release. It must
use the measured EIF build, exact production replay, signed-manifest and PCR
rotation, controlled registration/funds canaries and staged worker restoration.
