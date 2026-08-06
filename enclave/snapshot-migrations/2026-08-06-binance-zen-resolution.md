# 2026-08-06 - Binance ZEN resolution evidence

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 8072fe5805078d0e9b6755d2257b9a46eb325b58
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who approved replacing the paid/trial Pyth
dependency for new ZEN markets with deterministic Binance Spot ZEN/USDT
one-second candle evidence on 2026-08-06.

## Change

The private core adds a versioned Binance resolution statement and public
evidence variant for new `layrs:v4:ZEN:*` markets. A primary statement commits
the five completed one-second candle closes at each market boundary, their
median, two independent delivery paths, and the final outcome. If one or both
boundary manifests remain unavailable for 120 seconds after close, a distinct
signed timeout statement can resolve only to `PUSH_REFUND`.

The enclave validates the configured Binance feed identifier, source profile,
boundary timing, sample count, evidence-path count, statement signature,
outcome, nonce and deadline before committing the existing resolution ledger
transition. Legacy Pyth resolution variants and all existing v1-v3 market
namespaces remain decodable and retain their original semantics.

## State compatibility

No existing balance, hold, order, fill, position, fee, session, replay-cache or
journal field is removed, reordered or reinterpreted. Existing snapshots and
journals contain no Binance evidence variant and therefore decode and replay
unchanged. The new enum variant can occur only after an authenticated v4 ZEN
market registration and a Binance resolution command accepted by this release.

An older binary cannot decode or replay a Binance resolution accepted after
cutover. Once the first v4 Binance command is committed, rollback therefore
requires fencing v4 intake and repairing forward rather than replaying that
command through the older release.

## Production replay plan

1. Freeze new private commands and retain the running release's immutable
   encrypted snapshot, journal head, sequence and state root.
2. Restore and replay that exact state in the candidate EIF. Require equality
   of sequence, journal head, state root, balances, positions, holds and open
   orders before accepting a command.
3. Register an isolated `layrs:v4:ZEN:*` canary with Binance feed id `9001` and
   source `BINANCE_SPOT_ZENUSDT_1S_V1`. Require malformed namespaces, wrong
   feeds, wrong sources, missing paths and non-canonical statements to fail
   before state mutation.
4. Resolve one funded canary with two matching five-candle boundary manifests.
   Verify the signed evidence, median/outcome, Horizen publication, payout
   conservation, owner balances, journal replay and final state root.
5. Run a separate missing-evidence canary. Require rejection before the exact
   close-plus-120-second deadline and require `PUSH_REFUND` at or after it.
6. Rotate PCR0, signed release manifest and approved KMS attestation policy as
   one release. Enable v4 rolling-market creation only after attestation,
   database migration, API, AppSync, Horizen publication, reconciliation, DLQ
   and alarm checks are green.

## Rollback plan

Before any v4 Binance command is accepted, fence the candidate and restore
release `8072fe5805078d0e9b6755d2257b9a46eb325b58` with its prior PCR allowlist
and signed manifest.

After a v4 command is accepted, stop new v4 market registration and order
intake, cancel and reconcile every affected order and hold through authenticated
commands, retain the candidate snapshot and encrypted journal, and repair
forward. Never truncate the journal or reinterpret a Binance resolution as
legacy Pyth evidence.

## Approval

This is an intentional additive private-core release. It must use the normal
measured EIF build, exact snapshot replay, signed manifest and PCR rotation,
funded resolution/refund canaries and capped activation process.
