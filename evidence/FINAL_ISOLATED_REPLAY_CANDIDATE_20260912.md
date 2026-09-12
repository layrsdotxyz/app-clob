# Final isolated replay candidate — 2026-09-12

This evidence supersedes earlier candidate-specific records.  It covers only
the isolated, writer-disabled validation candidate; it is not an activation
record and does not authorize financial writing.

## Immutable package identity

| Field | Value |
|---|---|
| Source commit | `365f299e18220a7eae3e37d555d9596615d3d660` |
| AMI | `ami-0a1dc1839d623e326` |
| AMI role | `isolated-replay-validation`, `ProductionAccess=denied`, `WriterEnabled=false` |
| AMI/root-snapshot metadata | `layrs.direct-execution.v1`, source commit and sealed epoch/evidence hashes tagged identically |
| EIF SHA-256 | `c622e2ad1b3a8b6dade00b957a9ff14f44467425578b0a617361a0e15e45ab2b` |
| Parent SHA-256 | `0b69d4de65c597cafbb2fe2b10c0c375b800d8a1e45f1b8f4a961737dd99a3dd` |
| Enclave release-input SHA-256 | `4f6edc00a8d19637c723efa55516a3d2fc6b12ef58a7efb1832c6971f8a8b38a` |
| Packer template SHA-256 | `6e4238614ba6f26a87ff794c49ffd5c65b4527e8b2907c166d0c13c38a78a682` |
| Opening epoch SHA-256 | `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590` |
| Evidence manifest SHA-256 | `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957` |
| PCR0 | `069cf300806081754ffe8e346054540efdcf1c128e4aa4912f676f0f56f2e4cd9f8738d95f38ca6339bb3258cffbbc48` |
| PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 | `46cf055fe9df4c08096b1f3b659f6f23908446cde95f79d9fb7fdfd53a537d6c6f352eb6f6a19650756ff872ce9344c9` |

The measurements and on-instance hashes were collected from a fresh instance
of that AMI (`i-0df0a5c53ff260381`) with `ProductionAccess=denied`.  The
attestation endpoint returned a document and bound the sealed epoch/evidence,
genesis ordinal zero, and `layrs.direct-execution.v1`.  The instance used
ephemeral isolated-test keys only; it did not resolve production secrets,
connect to production PostgreSQL, submit custody, or enable a production
writer.

Packer cleanup was also verified: the temporary source AMI and its source
snapshot used for the encrypted final-copy workflow no longer exist.  The
final AMI and its retained root snapshot are tagged with the same source,
epoch, evidence, transaction-model, writer-disabled, and production-denied
metadata.

## Packaged restart/replay acceptance

The actual packaged parent/enclave VSOCK boundary was tested with a
synthetic isolated signed session and a fixture account with 5,000,000 atomic
USDC available:

1. `PLACE_ORDER` reserved 1,000,000 atomic USDC and synchronously persisted
   one immutable state artifact before adoption.
2. The parent was restarted.
3. Recovery restored 4,000,000 atomic USDC from that artifact before serving.
4. The exact command was replayed.  Balance remained 4,000,000 atomic USDC,
   receipt `21703b5f79e0556b823e5ed0406d333cf657097632a2322fa5818a235d39f003`
   was reused, and the artifact count remained one.

This was an isolated order-reservation test, not a custody payout and not a
production balance mutation.

## Projection boundary

`LAYRS_DIRECT_ISOLATED_NO_PROJECTION=true` is a named package-test fixture
and is usable only together with `LAYRS_DIRECT_ISOLATED_TEST=true`.
Production-enabled startup independently requires a cryptographically valid
WriterGrant, approved runtime binding, and a configured projection; without a
projection it exits with `production projection is required`.  A normal
non-isolated runtime without a projection returns
`PROJECTION_NOT_CONFIGURED` for financial responses.  Thus no-projection
mode cannot activate or serve the production direct writer.

The production deployment template continues to require the runtime/projection
configuration and keeps PostgreSQL as receipt/accounting projection only;
recovery is from the immutable encrypted artifact archive, never PostgreSQL.

## Executable-path and compatibility audit

* `cargo test` passed: 30 direct-runtime/enclave/parent tests, including
  VSOCK ACK/adoption, restart boundaries, missing/corrupt artifact fail-closed,
  immutable intent crash windows, custody terminality, writer grants, and
  idempotency.
* The clean BFF bridge at `30ab5913` passed 10 deterministic Privy/JWKS,
  signed-session, direct-route tests and TypeScript typecheck.
* The exact packaged parent binary passed the Durable executable-path string
  audit: no `DURABLE_PREPARATION`, `RELEASE_READY`, legacy durable command,
  command queue, lease, or coordinator identifier was present.  Source hits
  are negative assertions/comments and a test that rejects a legacy runtime.
* The deployment template validates.  Its current live dormant stack remains
  writer-disabled and pinned to the prior AMI; it has not been changed by this
  validation.  Promotion of this AMI requires the separately governed grant
  and deployment change.

## Production compatibility recheck

Read-only verification confirmed the existing production archive/KMS,
runtime-secret reference, RPC-secret reference, Base confirmation policy
(`20`), dormant role/profile, and existing alert topic remain available.
Secret values were not retrieved.  The deployed direct parent is still
loopback/dormant until a valid WriterGrant enables the governed production
listener.  The BFF uses the existing Privy verifier and derives the
epoch-bound direct-session assertion from existing Privy authority material;
the direct runtime never accepts raw Privy JWTs.

No source or production-path change was required by this recheck, so no
additional rebuild was performed after this AMI's attestation.

## Remaining external activation boundaries

1. Authorized governance must assign the approved activation/change ID and
   expiry, then sign the exact WriterGrant for this AMI/EIF/PCR tuple, opening
   epoch, runtime identity, and active legacy-writer fence.
2. An authorized recipient must be attached to the existing production SNS
   topic and controlled delivery confirmed.  The topic currently has zero
   confirmed subscriptions.
3. Operations must remediate or explicitly time-bound accept the 20 active
   Layrs production alarms, including the 915-message fenced legacy DLQ,
   missing telemetry, and Horizen funding alarms.  No alarm was silenced,
   deleted, or weakened here.
4. The separately governed funded-canary authorization and observer/rollback
   record must be issued.  No custody transaction, customer fund movement, or
   production writer enablement occurred.

`PRODUCTION_ACTIVATION_STATUS = WAITING_FOR_EXTERNAL_AUTHORIZATION`.
The isolated candidate is technically verified but is not
`READY_FOR_FUNDED_CANARY` until all four boundaries above are satisfied.
