# Enclave-trusted time and journaled position close

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: ecae35c0bde5be479d5f21dbf5a4da0c0bbae671
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
FUNDED_CANARY_REQUIRED: true

Release owner: Layrs financial-core owner. This approval covers a new
state-rooted trusted-time high-water marker, exact full-command recovery
markers, and journaled account-private position-close previews. It does not
authorize deployment, snapshot migration, or funded traffic without the
release evidence below.

## Compatibility

The encrypted snapshot wire schema is unchanged. The trusted-time high-water
and exact processed-command commitments are encoded as domain-separated
entries in the existing encrypted `system_keys` set. A legacy snapshot without
those markers restores with its historical root. The first successful user
command using fresh Nitro NSM time installs the marker and enters the explicit
`layrs.trusted-time-state.v1` root domain. Legacy processed commands without an
exact commitment remain non-recoverable and fail as `PreviouslyProcessed`.

Position-close previews are intentionally no longer read-only transitions.
They advance the private session sequence, trusted-time fence, encrypted
journal and root while remaining financially neutral and ineligible for public
receipt publication. A close quote binds the exact executable protected slice
and expires on a half-open 30-second boundary.

## Required release evidence

Before activation:

1. restore the latest production snapshot and verify its pre-upgrade root and
   journal head without modification;
2. prove the first fresh NSM-timed command creates one monotonic marker and a
   regressed timestamp cannot commit;
3. prove exact lost-response recovery succeeds before another NSM read while a
   same-key different command fails closed;
4. prove failed, stale and partial fill-or-kill closes leave the journal, book,
   balances, time fence and root unchanged;
5. prove preview receipts remain private and publication-ineligible;
6. reconcile USDC and 18-decimal ZEN close economics, fees, rebates, rewards,
   cost basis, claims and custody conservation;
7. restore the candidate snapshot and repeat the monotonic-time, replay and
   close vectors; and
8. build and attest the candidate EIF, then complete capped funded canaries.

## Rollback

Before the candidate accepts a user command, restore the prior parent AMI,
EIF, manifest and PCR policy. After the first trusted-time marker or journaled
preview commits, freeze new financial mutations and retain the candidate
snapshot and journal. Do not delete markers or rewrite encrypted history to
recover the legacy root. Roll back only by reconciling the candidate state,
restoring the last independently anchored compatible snapshot, and preserving
all later records for operator review.
