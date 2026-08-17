# Thin-book public projection privacy

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: b682c9384a8d0c45d6b10992547e65afa9efb1b5
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner. This change implements E10-S07 only and
does not authorize an EIF build, promotion, deployment, or funded operation.

## Change

This release changes no snapshot, journal, ledger, order, fill, receipt, or
state-root field. It narrows the read-only public-depth projection:

- a price level requires at least three distinct private owners;
- its aggregate must reach the enclave-owned 25,000,000-micro floor;
- every qualifying level emits exactly that constant threshold marker;
- caller-supplied threshold values cannot lower, raise, or binary-search it;
- orders created after the quantized `asOf` boundary are excluded; and
- depth is empty before open and at or after market close.

Private orders, exact remaining quantities, owners, price-time priority,
matching, holds, balances, fees, and journal contents are unchanged. The
existing authenticated request field remains accepted for wire compatibility,
but it no longer controls the enclave privacy policy.

## Production replay plan

1. Retain the immutable pre-release encrypted snapshot, journal sequence,
   journal head, state root, active-order set, holds, balances, positions,
   fills, fees, and resolution state.
2. Restore that snapshot with the candidate binary and replay every retained
   encrypted journal record. Require byte-for-byte parity for the sequence,
   journal head, state root, and all private financial state.
3. Query adversarial public-depth vectors using thresholds from zero through
   `u128::MAX`. Require identical constant-marker output for qualifying levels
   and no output for fewer than three owners or less than 25 shares.
4. Repeat reads within one quantized boundary and after encrypted snapshot
   recovery. Require identical output and an unchanged state root.
5. At the exact close boundary, require empty bids and asks regardless of
   resting GTC/GTD liquidity. Verify the downstream durable projection is also
   cleared before any public response is served.

Any financial-state, replay, or state-root difference is a release blocker.

## Rollback plan

Because serialization is unchanged, roll back by restoring the retained prior
binary, signed manifest, PCR policy, and encrypted snapshot before accepting a
new mutation. If the candidate has accepted mutations, first freeze new writes,
retain its snapshot and full journal, and prove that the prior binary replays
them to the same state root. Never edit, truncate, or reconstruct the journal.
