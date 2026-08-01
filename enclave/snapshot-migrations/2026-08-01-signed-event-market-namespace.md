# 2026-08-01 — signed event market namespace

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 37b3b35fd3c0700dddbeae91a2d9be3039d89438
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who approved Base-USDC sports, esports
and politics markets from signed market releases.

## Change

The private core accepts the additive, category-scoped market identifiers
`layrs:v4:SPORTS:*`, `layrs:v4:ESPORTS:*` and `layrs:v4:POLITICS:*`. Existing
v1, v2 and v3 identifiers remain valid. Every v4 market still enters through
the existing authenticated operator registration command and must satisfy the
same immutable configuration, collateral, time-window, condition, oracle and
settlement-domain validation as earlier namespaces.

The category is deliberately allowlisted. Arbitrary v4 prefixes, Macro and
Events remain rejected. Public category, subcategory, series, slug and tag
metadata are signed by the backend release signer; the enclave receives only
the canonical market configuration needed for private matching and custody.

## State compatibility

This release changes no serialized type, snapshot field, journal record,
state-root preimage, order, fill, balance, position, session or replay-cache
schema. Existing encrypted snapshots and journals restore byte-for-byte.

The only private-core change is the namespace predicate applied when a new
market registration command is validated. No existing market identifier is
rewritten. Matching, NORMAL/MINT/MERGE priority, complete-set accounting,
collateral holds, fees, withdrawals, resolution and signed receipts are
unchanged.

## Production replay plan

1. Freeze new private commands and retain the running release's immutable
   snapshot, journal head, sequence and state root.
2. Restore the same snapshot in the candidate EIF and replay every later
   journal record. Require exact equality of sequence, journal head, state
   root, balances, positions and open orders.
3. Re-register a read-only fixture for one valid market from each allowed v4
   category and require deterministic acceptance. Require rejection of an
   unknown v4 category, malformed condition, wrong settlement domain and an
   expired release.
4. Re-run NORMAL, MINT and MERGE conservation/replay tests plus owner-isolated
   signed-receipt tests before rotating PCR0 and the signed release manifest.
5. Register the production signed release only after the candidate is healthy;
   open capped Base-USDC trading only after API, registry and custody
   reconciliation agree.

## Rollback plan

Before any v4 market accepts an order, fence the candidate and restore release
`37b3b35fd3c0700dddbeae91a2d9be3039d89438` with its prior PCR allowlist.

After a v4 order is accepted, freeze new commands and cancel/reconcile every
v4 order and hold before rollback. The older release cannot register v4
markets, so rollback must never silently orphan a live v4 book. Existing v1,
v2 and v3 markets and their snapshots require no transformation.

