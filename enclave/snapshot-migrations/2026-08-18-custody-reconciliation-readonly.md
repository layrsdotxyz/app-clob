SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: ecae35c0bde5be479d5f21dbf5a4da0c0bbae671
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

# Attested custody reconciliation release

## Compatibility classification

This release adds the read-only `CUSTODY_RECONCILIATION_SNAPSHOT` operator
command and an in-memory aggregate cache. It does **not** add, remove or reorder
any field in `CoreStateSnapshot`, the encrypted journal, state-root material or
the persisted command response schema. The cache is deliberately absent from
`CoreStateSnapshot` and is recreated empty after restore.

The base commit above is the exact deployed release recorded by the preceding
balanced-deposit migration. Release operations must compare it with the live
signed manifest before building. A different live commit is a hard stop: update
this document through review instead of substituting a convenient merge base.

## Production replay and release

1. Fence private mutations and retain the highest immutable encrypted snapshot,
   journal head, confirmed audit anchor, current signed release manifest, parent
   AMI and PCR allowlist.
2. Build the candidate from the exact reviewed commit with
   `enclave/build-host-artifacts.sh`; retain the EIF, parent binary, SHA-384
   checksums, source commit and `nitro-cli` measurements.
3. Restore the retained production snapshot into the candidate and replay every
   later archived journal record. Require equality of sequence, journal head,
   state root, balances, holds, positions and custody totals.
4. Request two custody snapshots for one non-zero checkpoint commitment and two
   distinct finalized-chain commitments. Verify deterministic totals, Ed25519
   signatures and the absence of user, wallet, order, market and position data.
5. Add the candidate PCR to the KMS attestation allowlist while retaining the
   prior PCR, rotate the signed manifest, start one passive parent, and verify a
   fresh nonce-bound NSM attestation and both bound public keys.
6. Promote only after the backend schema and coordinator are compatible. Keep a
   single writable core, run the controlled cancel-only drill, and remove the
   prior PCR only after the reconciliation soak passes.

## Rollback

Before the first post-promotion financial command, rollback is a direct return
to the retained base AMI, EIF, manifest and PCR policy after snapshot/root
readback. After any financial command, freeze new mutations, retain the
candidate snapshot and journal, prove that the prior release restores and
replays them to the same sequence/root, then promote the prior release. Never
truncate the journal, rewrite a snapshot, run two writable enclaves, or remove
the candidate PCR before rollback evidence is archived.
