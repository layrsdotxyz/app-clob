# Quest BTC depth publication

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: b487d94737b11e9a77b9f195877f19a62f8733ad
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true

This declaration satisfies the repository's conservative `engine.rs` release
guard for the exact production base above. The change does not add, remove or
reinterpret any persisted snapshot field. It changes only the public depth
owner-count threshold for the build-gated recurring BTC 1H quest namespace;
the existing minimum public quantity bucket and all private order, balance,
position, fill, journal and settlement state remain unchanged.

## Production replay plan

Restore the existing encrypted cumulative snapshot through the unchanged
provisioning path, require the prior sequence and state root, then query the
same BTC 1H book through both the owner-private order projection and the public
aggregate-depth projection. The private projection must retain the exact open
orders while the public projection exposes only price and bucketed aggregate
quantity. Non-BTC and non-1H fixtures must retain the three-owner threshold.

The activated production candidate restored the existing state on 2026-09-03,
retained the sequence across restart, rolled the maker to the next BTC 1H
market, and published three bucketed levels for each outcome without exposing
an owner identifier.

## Rollback plan

Retain the preceding enclave AMI and EIF while the bounded PCR transition is
open. If restore, private read, order mutation or public-depth validation fails,
stop the candidate writer and return the Auto Scaling Group to the retained
launch-template version. This public-projection-only change requires no state
rewrite, journal truncation or reverse migration.
