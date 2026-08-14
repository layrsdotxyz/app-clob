# Polymarket-style fee and private-reward release

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: a711f808b66ee70fcef30b17e35ad230fb29fa45
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly approved the Polymarket-style
fee, maker-rebate, user-reward, referral and retrospective-accounting rollout.

This additive enclave release introduces immutable `POLYMARKET_*_V2` fee profiles for
every supported current and future market category. Existing V1 market configurations
are not rewritten: their fixed 20 bps taker charge and historical winning-fee behavior
remain replay-compatible.

V2 taker fees use `contracts * price * rate * (1-price)`, rounded half-up to five
settlement-asset decimal places. Winning fees are zero. A configured portion of each
taker fee accrues privately to the resting maker as a cumulative claim entitlement.
Daily maker/taker volume and fee attribution are retained inside the encrypted snapshot
so later retrospective programs do not require reconstructing private order ownership.

The reward-book schema is backward compatible. New fields use serde defaults and are
omitted while zero, so a historical empty reward book retains its exact serialized form.
The V2 enum variants were appended; historical variants and discriminants were not
reordered. Snapshot restore, deterministic replay, MINT/MERGE conservation and live-shape
partial matching are covered by the release tests.

Activation order is fail closed:

1. deploy compatible backend and frontend code while the scheduler remains on `V1`;
2. build, measure and attest this enclave release;
3. verify the restored production snapshot and signer domains;
4. switch only newly created market releases to `POLYMARKET_V2`;
5. keep existing V1 markets pinned to their recorded fee profile.

## Production replay plan

1. Fence private mutations and preserve the production snapshot, journal head,
   parent binary, EIF, measurements and signed manifest for base release
   `a711f808b66ee70fcef30b17e35ad230fb29fa45`.
2. Restore that exact snapshot in the candidate EIF and require equality of the
   sequence, journal head, balances, holds, positions, open orders, resolutions
   and every existing V1 fee/reward account before accepting any command.
3. Query the restored reward book and require every historical user entitlement
   to remain unchanged. Register isolated V2 USDC and ZEN markets only after the
   restore comparison passes.
4. Exercise low, midpoint and high price NORMAL fills plus complementary MINT
   and MERGE fills. Reconcile collected fees, maker rebates, collateral, holds,
   payouts and deterministic replay roots exactly.
5. Verify Base and Horizen claim authorizations against the governed distributor,
   chain id, token allowlist, cumulative amount, nonce/deadline and enclave signer.
6. Rotate PCR0, the signed manifest and KMS attestation policy together, then
   reopen capped traffic and begin the nonblocking 48-hour soak.

## Rollback plan

Before a V2 market is registered or a candidate mutation is committed, restore
the retained base release, manifest, PCR allowlist and snapshot. After any V2
market or reward mutation is committed, never replay it with an older binary:
freeze new mutations, retain the candidate snapshot and encrypted journal, and
repair forward using a compatible measured EIF. Existing V1 markets are never
rewritten or reinterpreted.
