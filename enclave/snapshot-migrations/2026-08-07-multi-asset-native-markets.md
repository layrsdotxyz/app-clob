# 2026-08-07 - multi-asset native crypto markets

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 7b10f77b66423594d026730c38407510dfc80b06
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who approved production-native BTC, ETH,
SOL, ZEN, ZEC and HYPE rolling markets with ZEN and USDC collateral on
2026-08-07.

## Change

The private core accepts the additive
`layrs:v5:<asset>:<settlement-asset>:<window>:<epoch>` namespace and binds each
asset namespace to one immutable spot feed identifier. Binance Spot provides
ZEN, BTC, ETH, SOL and ZEC evidence. Kraken Spot provides HYPE evidence. The
chain signer also accepts canonical v4/v5 event-market identifiers so Sports,
Esports, Politics and Macro markets can publish their final outcome through the
existing Horizen settlement path.

## State compatibility

No encrypted snapshot field, journal entry, balance, hold, order, fill,
position, fee, receipt, replay-cache or resolution representation is removed,
reordered or reinterpreted. The new market identifiers create independent
market buckets. Existing v1-v4 rolling markets and v4/v5 event markets retain
their existing state and replay semantics.

The existing spot-resolution evidence representation is reused. The signed
oracle source and feed identifier distinguish each provider/asset combination,
and the enclave rejects a namespace/feed mismatch before state mutation.

## Production replay plan

1. Fence new private commands and retain the current immutable snapshot,
   journal head, sequence and state root.
2. Restore and replay that exact state in the candidate EIF. Require exact
   equality of sequence, journal head, state root, balances, positions, holds,
   open orders and historical resolutions.
3. Register one isolated v5 market per approved asset/feed pair and one native
   event market. Require wrong feeds, malformed identifiers and unapproved
   sources to fail before mutation.
4. Execute controlled order/cancel/fill canaries and resolve one Binance and one
   Kraken market. Verify payout conservation, Horizen publication, AppSync
   transition and deterministic replay.
5. Rotate PCR0, signed release manifest and KMS attestation policy before the
   scheduler emits v5 releases. Confirm alarms, DLQs and reconciliation are
   green before enabling order intake.

## Rollback plan

Before a v5 command is accepted, fence the candidate and restore release
`7b10f77b66423594d026730c38407510dfc80b06` with its prior PCR allowlist and
signed manifest.

After a v5 command is accepted, stop v5 registration and intake, preserve the
candidate snapshot and journal, reconcile every affected order and hold, and
repair forward. Never truncate the journal or reinterpret v5 state through an
older release.

## Approval

This additive namespace/provider release must use the measured EIF build,
snapshot replay, signed-manifest and PCR rotation ceremony. Production
activation requires live provider data, tradable-book, resolution, Horizen
publication, AppSync, reconciliation, DLQ and alarm canaries.
