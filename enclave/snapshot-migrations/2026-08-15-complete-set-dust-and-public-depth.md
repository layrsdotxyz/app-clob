# Complete-set dust and privacy-safe public depth

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: bfc71fea48aa11e9f220ae9e461bf4c93b0b0321
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who requested that complementary matching
must not strand one-micro-share residuals and that a thin public book must not
reveal an individual order's effective size or arrival delta.

## Change

This release changes matching and public-read behavior, but adds no serialized
field and changes no snapshot, journal, ledger, market, order, fill, receipt or
state-root schema.

For MINT and MERGE candidates, the book deterministically skips a quantity that
cannot allocate at least one settlement micro to each complementary leg. FOK
liquidity calculation applies the same rule. NORMAL transfer matching is
unchanged. Existing orders, quantities, holds and price-time ordering are not
rewritten.

Public depth now leaves the enclave only while a market is open, only when a
level contains at least three distinct private owners, and only after the exact
aggregate quantity has been floored to the configured public bucket. Private
book state is unchanged; this is a narrower public projection.

## Production replay plan

1. Drain new private mutations and retain the immutable snapshot, journal
   sequence, journal head, state root and active-order/hold reconciliation from
   release `bfc71fea48aa11e9f220ae9e461bf4c93b0b0321`.
2. Restore that exact snapshot in the candidate EIF and replay every retained
   encrypted journal record. Before accepting a new command, require identical
   sequence, journal head, state root, balances, holds, positions, orders,
   fills, fees, rewards and resolution state.
3. Re-run the deterministic NORMAL/MINT/MERGE vectors, the exact 35/65 and
   36/64 one-micro residual regressions, FOK/FAK behavior, conservation checks
   and deterministic journal replay.
4. Verify public depth is empty before open and at/after close, suppressed for
   one or two owners, bucketed for three or more owners, and never contains a
   private owner or individual-order identifier.
5. Rotate the EIF, signed manifest, PCR allowlist and parent AMI together. Run
   capped funded USDC and ZEN canaries only after restored-root parity and fresh
   nonce-bound attestation pass.

Because the candidate does not alter serialization, replay of previously
committed records must remain byte-for-byte identical. Any sequence, journal
head or state-root difference is a release blocker; it must not be bypassed.

## Rollback plan

Before the candidate accepts a command, restore the retained parent AMI, EIF,
signed release manifest and prior PCR policy directly.

After the candidate accepts a command, freeze new private mutations, cancel or
settle open exposure, retain the candidate snapshot and journal, and reconcile
all balances, holds, positions, fees, rewards and custody boundaries. Roll back
only if the retained journal can be replayed by the prior release with the same
sequence, journal head and state root. Never truncate, edit or reconstruct the
encrypted journal to force compatibility.

