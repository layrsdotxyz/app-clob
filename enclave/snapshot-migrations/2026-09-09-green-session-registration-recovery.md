# Green direct session-registration recovery

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 3f389df6b7e75caa89e6b6f280c476a465441664
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

This declaration covers the cumulative Green direct-execution release that
removes Durable command preparation from signup/session registration and the
financial core. It records a required compatibility boundary; it does not
authorize production traffic, a second financial writer, a PCR/KMS rotation,
or a funded operation.

## Exact persisted-state delta

`CoreStateSnapshot` adds the default-empty
`session_registration_results` map. Each entry retains the exact successful
`REGISTER_SESSION` response only until its session expiry and binds the
idempotency key, session ID, identity commitment, public key, expiry, command
time, signed receipt, encrypted journal record, and registration evidence.
The same transition adds a domain-separated result marker to the existing
`system_keys` set.

Historical snapshots omit the new field and therefore decode to an empty map
without rewriting balances, holds, orders, positions, fills, markets,
withdrawals, sessions, replay keys, sequence, state root, or journal head. New
entries close the commit/response crash window: an exact retry returns the
original signed result after response loss or restart, while a tuple mismatch
is rejected without a second registration. A read-only status command checks
the complete immutable registration tuple and does not mutate session sequence
or private-core state.

## Production replay plan

1. Keep the candidate in the isolated Green stack with no public traffic,
   custody broadcast authority, queue consumption, or second-writer lease.
2. Retain the active production EIF, parent binary, PCR measurements, signed
   manifest, encrypted snapshot object/version, complete journal boundary,
   sequence, journal head, state root, and aggregate reconciliation evidence.
3. Restore that exact snapshot and replay its encrypted journal into the
   measured candidate. Require equality of sequence, journal head, state root,
   asset and bucket totals, balances, holds, orders, positions, fills, markets,
   resolutions, withdrawals, sessions, direct final results, and all historical
   replay keys. The new result map must be empty before its first Green signup.
4. Register one allowlisted Green session, deliberately lose the coordinator
   response, retry the exact tuple, and require the original byte-identical
   signed response with one journal transition and one result marker. Retry a
   changed command time, key, commitment, expiry, and session ID and require
   no effect.
5. Restart the enclave from the archived post-registration snapshot and repeat
   the exact retry and read-only status query. Require the same response,
   unchanged sequence/root/head, and no duplicate registration or evidence
   publication.
6. Exercise the Green deposit, withdrawal, order, cancel/replace, match, trade,
   resolution, and settlement paths only after restore equality and attestation
   pass. Require exactly-once financial effects and clean reconciliation after
   retry and restart vectors.
7. Immediately before any production cohort, repeat the passive restore and
   equality checks against the then-current production boundary. Any unknown
   outcome, missing artifact, replay mismatch, or second writer is a hard stop.

Only privacy-safe hashes, aggregate reconciliations, and pass/fail evidence may
leave the enclave. No private account-level snapshot or identity binding is
published.

## Rollback plan

Before the candidate accepts its first session-registration transition, stop
the dark Green task and retain the existing production release unchanged. No
state conversion is required because the new map remains empty.

After a candidate registration is journaled, do not load that Green state into
an older EIF that cannot validate the result map and marker. Disable new Green
commands, retain the candidate snapshot, journal, receipt, and immutable
artifacts, and recover forward with this schema or a reviewed compatible
successor. Never delete a result, marker, receipt, or journal record, truncate
the journal, or edit a balance to force rollback.

The existing production API, funding workers, enclave writer, custody path,
market maker, balances, and user traffic remain outside this Green migration
until the separately governed cohort gate is approved and certified.
