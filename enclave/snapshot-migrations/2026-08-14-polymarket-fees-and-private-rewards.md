# Polymarket-style fee and private-reward release

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
