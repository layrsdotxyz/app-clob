# Production activation package — prepared, not executed

This package is bound to Step 5 evidence SHA-256
`872b41e03ca2a892dafdbc8c8b7b2c8a68a67535a3c9c27ce2cb448bde70588d`.
It authorizes no production action.  In particular, it does not enable a
writer, route traffic, read a secret value, execute a funded canary, or move a
customer asset.

## Fixed target commitments

| commitment | required value |
|---|---|
| epoch | `layrs-opening-epoch-20260911-941107537728c98b` |
| opening state | `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590` |
| opening evidence | `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957` |
| transaction model | `layrs.direct-execution.v1` |
| EIF | `138d35cb576bd07f2dcf37652d436fa4d2acdc5aa3431c6c4934a0ff8cbc1548` |
| enclave binary | `fcbba5e7a469aa54de63ddb836b1c8ae95fb43282a626f753cfb9b95f00f46b5` |
| parent binary | `697823b3de72c82432c715df12103d6811443f6c5f9733c6db8d41a66a135ad7` |
| PCR0 | `d2a9db65dbcdc682f02b3023321aa9b1c9272a52cbe4ec8d36c112eadc48a351cfc0b11ca0af4dd744290836e31dba13` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `08f5b0adbcb270fd159b3f73630676415a6f30df3c8b7aeeb0ac34a1597f668f845f302463557cab8c9483feda2213bf` |

The original candidate AMI, `ami-00b5f08fce6be9018`, did not return from
`DescribeImages` during this precheck.  It must not be replaced silently.  A
fresh artifact requires an isolated rebuild, matching EIF/PCR verification,
and a new governed approval before this runbook can be used.

## Pre-activation gates — all must pass in order

1. Approvers sign a change record that names every legacy financial writer and
   the fixed commitments above.  The record must include the currently active
   `layrs-production-green-core-coordinator`, legacy public API financial
   route, and deposit/withdrawal service.  Green is not recreated or used as a
   rollback target.
2. The approved operator disables those writers and removes their financial
   routes.  Independently observe no writer task, queue consumer, or legacy
   endpoint can accept a financial command.  Hash the observations into the
   old-writer-fence evidence.
3. Only then create the projection fence row with `old_writer_authorized=false`
   and `target_writer_enabled=false`; independently read it back.  This is a
   controlled activation record, not a balance update.
4. Provision a *dormant* direct-runtime target from the newly approved artifact.
   Its identity must attest to every fixed PCR and must load exactly the sealed
   opening state/evidence.  It must have no public financial route and no
   writer grant at this point.
5. Before routing, install a production immutable encrypted archive adapter.
   It must prove create-if-absent, encrypted durable storage, authenticated
   readback, lineage/head recovery, and missing/corrupt-head failure closed.
   The bundled `FilesystemImmutableArtifactStore` is an isolated-test adapter,
   not evidence of a production archive.
6. Configure the live custody adapter with an approved authenticated Base RPC
   credential, exact finality threshold, signer authority and destination
   controls.  Run an authenticated *read-only* finality preflight against a
   fixed prior transaction; retain no secret value in this package.  The
   current `layrs/production/providers/rpc` secret was only metadata-checked
   and is used by a legacy workload.
7. Create direct-runtime health, artifact/recovery, VSOCK, custody-finality,
   projection-lag, replay, writer-fence and attestation alarms.  Confirm real
   recipient delivery.  Existing `layrs-production-operational-alerts` has
   zero confirmed subscriptions and sixteen relevant alarms are ALARM; clear
   and explain those conditions before any financial activation.
8. Establish the Privy BFF route with the real verifier, canonical mapping and
   epoch/wallet-bound session assertion.  Verify invalid JWT, wrong user,
   wrong wallet and expired assertion rejection against the dormant target.
9. The governance/key-release control must bind the exact AMI, EIF and PCR
   values above before releasing runtime keys.  The in-runtime `WriterGrant`
   independently verifies `activationId`, epoch, model, opening hash,
   old-writer-fence hash, expiry and signature; it does **not** itself carry
   AMI/EIF/PCR fields.  Do not claim those commitments are cryptographically
   enforced until the external attestation/key-release policy is verified.
10. After gates 1–9 pass, approvers may sign the canonical WriterGrant below.
    Persist the signed grant and fence in the projection, read both back, and
    then set the fence target writer flag once.  Never fabricate a signature.

## WriterGrant signing request (unsigned template)

```json
{
  "activationId": "GOVERNANCE_ASSIGNED_NONCE",
  "epochId": "layrs-opening-epoch-20260911-941107537728c98b",
  "runtime": "layrs.direct-execution.v1",
  "openingEpochSha256": "84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590",
  "oldWriterFenceEvidenceSha256": "FENCE_EVIDENCE_SHA256_AFTER_INDEPENDENT_VERIFICATION",
  "expiresAtUnix": "APPROVED_BOUNDED_EXPIRY",
  "signature": "GOVERNANCE_SIGNATURE_NOT_YET_ISSUED"
}
```

This is deliberately unsigned and invalid.  The external approval/key-release
record must additionally name the AMI/EIF/PCR commitments in this package.

## Funded canary — separately authorized procedure

The canary is prohibited until every preceding gate is evidenced and a separate
approval fixes the source, destination, asset, amount, maximum fee, request
nonce, expected custody transaction, success criteria and rollback owner.

1. Reconfirm target attestation, sealed epoch, archive head, writer fence,
   signed grant, BFF session binding, custody finality configuration, health
   checks and alert delivery immediately before the canary.
2. Submit one approved authenticated direct request.  Observe the complete
   `request → candidate → archive write/readback → ACK → adoption → receipt →
   custody finality → accounting → projection` chain.
3. Restart the parent/enclave.  Independently verify the recovered state and
   replay the exact request; it must produce no second receipt, custody event,
   accounting event, projection event or artifact.
4. Reconcile exact custody reference, terminal receipt, archive head, and
   projection.  A missing/corrupt archive, ACK mismatch, finality shortfall,
   route ambiguity, or alert-delivery failure is a fail-closed stop.

## Rollback and stop rules

Before a successful funded canary, remove the target route and terminate the
target writer; do not restore any legacy writer automatically.  Preserve the
archive, receipts, fence evidence and logs for independent review.  After a
funded canary, rollback requires a governed recovery decision; it is not a
traffic rollback and must not reconstruct private state from PostgreSQL.

Current status: **not executable**.  No production resource was changed while
preparing this package.
