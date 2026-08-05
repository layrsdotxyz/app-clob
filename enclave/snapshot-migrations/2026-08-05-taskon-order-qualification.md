# 2026-08-05 - TaskOn order-qualification evidence

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 369558fbc3d14245619ad502c5258b453945f3bb
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

Accepted `SubmitOrder` commands now return one privacy-minimized, enclave-signed
`TaskQualificationArtifact`. The artifact is bound to the command receipt and state root and
contains the settlement asset, accepted notional, filled quantity, timestamp, and a one-way
commitment to the private order. It omits user identity, market, side, outcome, and limit price.

`CoreResponse` gains an additive `task_qualifications` vector with `serde(default)` and omission
when empty. The parent wire response gains the corresponding `taskArtifacts` sidecar. No ledger,
book, market, session, journal-key, state-root, fee, resolution, or withdrawal field changes.

## State compatibility

Encrypted snapshots can contain processed-command responses. Old responses deserialize with an
empty `task_qualifications` vector because the field is explicitly defaulted. Replaying historical
commands therefore preserves their original response and root; it does not synthesize quest
evidence retroactively. Only newly accepted orders under the new measured release produce an
artifact.

The added sidecar is outside state-root material and does not change command request hashes,
journal AAD, snapshot AAD, order matching, collateral accounting, or receipt signatures.

## Production replay plan

Before traffic cutover:

1. restore the latest immutable production snapshot and replay its encrypted journal under the
   candidate enclave;
2. confirm the restored state root and sequence match the currently published checkpoint;
3. submit a controlled accepted order and verify exactly one sidecar signature against the
   nonce-bound attested receipt key;
4. confirm a rejected order emits no sidecar and that the serialized sidecar contains none of the
   prohibited private fields;
5. archive the EIF, parent binary, measurements, checksums, source commit, and replay result before
   rotating the signed release manifest.

## Rollback plan

If snapshot restore, journal replay, signature verification, or the production canary fails, stop
the cutover and retain the prior `369558fbc3d14245619ad502c5258b453945f3bb` release and its PCR
allowlist. Because the database migration only stores new artifacts and no historical state is
rewritten, the backend can remain fail-closed for TaskOn order quests while the previous enclave
continues trading. Revert the parent and EIF together; do not mix wire versions.

## Approval

The Layrs owner authorized end-to-end implementation and release of the TaskOn signup, credited
deposit, and order-verification integration on 2026-08-05. Production activation remains subject
to replay equivalence, signed manifest, attestation, and live canary gates above.
