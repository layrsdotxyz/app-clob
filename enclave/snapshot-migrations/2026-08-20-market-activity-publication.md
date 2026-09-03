# Market activity publication signal

BASE_RELEASE_COMMIT: bfc71fea48aa11e9f220ae9e461bf4c93b0b0321

Accepted submit-order task qualification artifacts now include an optional `market_id`.
The field is a privacy-safe demand signal used to publish only markets with actual order
activity. It does not expose the owner, side, outcome, price, quantity, or order identifier.

`market_id` is `serde(default)` and omitted when absent, so recovery capsules and snapshots
created before this release restore byte-compatibly. Existing task qualification signatures
remain verifiable over their historical payload. New artifacts sign the market identifier as
part of the existing `layrs.task-qualification-artifact.v1` domain payload.

No ledger, book, order, balance, position, fee, receipt, or resolution state changes.
