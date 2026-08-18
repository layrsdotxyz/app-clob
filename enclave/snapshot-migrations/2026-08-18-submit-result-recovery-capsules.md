# Submit-result recovery capsule migration

Story: E07-S06. This migration is separate from the GTD expiry migration and
must be reviewed against the exact deployed pre-E07-S06 enclave release.

## State change

- Legacy snapshots restore with an empty `recovery_capsules` map through the
  explicit `serde(default)` compatibility path.
- Candidate snapshots include bounded SubmitOrder result capsules, the single
  trusted-time high-water marker, full-command replay bindings, and rooted
  archive-ack state.
- Restore rejects capsules whose count, individual encoded size, aggregate
  encoded map size, fill count, request binding, or result digest is invalid.
- The state-root domain/version commits the candidate fields. The legacy root
  is accepted only while restoring a snapshot that predates these fields; a
  candidate snapshot is never silently interpreted as legacy.

## Roll forward

1. Build the EIF with an explicit canonical
   `LAYRS_RECOVERY_ENVIRONMENT` (`development`, `staging`, or `production`).
2. Measure and approve the new PCR0 using the existing release ceremony.
3. Restore the last anchored legacy snapshot and run the migration vectors.
4. Export and durably retain the first candidate snapshot before enabling the
   public SubmitOrder recovery path.
5. Reconcile every durable response archive/SQL ACK against the enclave rooted
   ACK status after provisioning and periodically thereafter.

## Rollback boundary

Rollback to the pre-E07-S06 binary is prohibited after the first candidate
snapshot contains a recovery capsule or archive ACK. Such a binary cannot
interpret the new result-recovery contract and could make a committed result
unavailable. Operational rollback is to a previously measured E07-S06 image
and the latest independently anchored E07-S06 snapshot.

## Failure and capacity policy

- Capsule capacity is checked before any financial mutation. Full or oversized
  recovery state fails closed.
- A failed command, response encoding, response encryption, or snapshot export
  rolls the live core back to its exact pre-command clone.
- Exact recovery is guaranteed once the enclave produced a recoverable capsule
  response or the backend durably archived its padded envelope. Recovery means
  the exact signed semantic result, receipt and state-root binding; authenticated
  journal/snapshot ciphertext is intentionally regenerated with a fresh nonce.
  Durable
  accepted-command two-phase persistence before any response leaves the enclave
  remains E07-S07 scope.
- The pre-existing processed-command marker set remains append-only. Its
  measured production capacity and compaction design are tracked as a separate
  E18 release-capacity constraint; E07-S06 adds no unbounded response body map.
- Public padded response payloads are retained for 24 hours, signed metadata
  for 90 additional days and SQL rooted-ACK markers for 365 days. Enclave ACK
  removes the response capsule but retains the pre-existing minimal processed
  command replay fence. Database triggers forbid deleting an unacknowledged
  payload or metadata row.
- Snapshot ciphertext is encrypted but not fixed-size padded. Its length is
  visible only to the trusted parent/artifact store and can reveal coarse
  aggregate private-state growth; snapshots are never exposed through the
  public API.
- Cloning the full core is required to roll back response/snapshot construction
  failures. Promotion requires a measured maximum-state memory and p95/p99
  latency gate within the configured EIF memory budget.

## Required evidence

- legacy and candidate restore vectors;
- maximum-count, maximum-byte and oversize rejection vectors;
- exact lost-response retry and changed-envelope replay rejection;
- archive-before-ACK, ACK-response-loss and restart reconciliation vectors;
- rollback below the independently anchored minimum sequence rejection;
- environment mismatch and expired-payload rejection;
- PCR0 manifest, build arguments and image digest for the promoted environment.
