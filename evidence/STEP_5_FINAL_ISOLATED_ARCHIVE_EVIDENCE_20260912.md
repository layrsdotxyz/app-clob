# Step 5 final isolated archive evidence — 2026-09-12

This record is confined to the isolated Step 5 account path.  It did not
activate a production writer, use production database/custody credentials, or
move customer funds.

## Candidate

- Source commit: `d6202ae`.
- AMI: `ami-0a26d307d4920f05b`
  (`layrs-opening-epoch-direct-archive-20260912-d6202ae`, encrypted,
  `ProductionAccess=denied`, `WriterEnabled=false`).
- EIF SHA-256: `a71f54ccc2b420b8771d16a1607582e72c7394171d7d3217a86cc7c772eafa74`.
- Enclave binary SHA-256:
  `cf693b97b1ce8e0906bbb6b572811c36b608b0c1d9c731681427a88c208629b8`.
- Parent binary SHA-256:
  `29b374bcbaeb1cf8cb80478c46a262cf625e2f3ee402c812a9b362f097616b32`.
- PCR0:
  `28b343ca5357abc638a1536d097e03c47daf264920d998ee3ad4b180238b0ee88a4630750ff1535c998970fbe8ed46bb`.
- PCR1:
  `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`.
- PCR2:
  `85bb69be9eea43dbd96d100dc8dd44600b24a4d7f5e6f18a69c43011fa56ee4ab3ce296813583d8369e21d246b8788eb`.
- Sealed opening epoch state SHA-256:
  `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590`.
- Sealed evidence-manifest SHA-256:
  `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957`.

## Archive and recovery checks

The verifier used a dedicated isolated S3 bucket with Object Lock in
COMPLIANCE mode and dedicated isolated KMS key access.  The role had only the
archive operations needed for that test.

- Candidate -> S3 encrypted immutable artifact -> parent readback -> bound ACK
  -> enclave adoption completed once.
- Final canary: `5,000,000 -> 4,000,000 -> parent restart -> 4,000,000 ->
  exact replay -> 4,000,000`.
- Exactly one receipt, accounting event, custody projection, session, artifact,
  and head were recorded.
- Missing head/object fixture failed closed.
- Corrupt artifact fixture failed closed.
- Duplicate differently-keyed artifact fixture failed closed before recovery.
- The final attestation endpoint produced a document with SHA-256
  `d3fb4530495574c1aee3ce05fbfccd28ec8ddbf57e7f1be27da6800eacb79f7b`.

## Security controls verified

- Direct withdrawal destination is required to equal the signed session's
  verified embedded Privy wallet; the wrong-wallet unit test rejects it.
- `WriterGrant` source binding includes AMI, EIF, PCR0/1/2, source commit,
  enclave and parent hashes, opening epoch/evidence, runtime, and legacy fence
  evidence.  No production grant was minted or enabled.
- Legacy financial writer ECS services remain scaled to zero under the
  separately recorded governed fence.  This evidence does not authorize their
  reactivation.
- The isolated runtime reported `writerEnabled=true` only because it was
  explicitly bootstrapped in `isolated-test` mode for this canary.  The AMI is
  tagged writer-disabled and has not received a production WriterGrant.

## Activation blockers, not waived

- An independently approved, signed production WriterGrant bound to the exact
  candidate measurements is absent.
- Production custody credentials/finality preflight has not been authorized;
  no credential was retrieved or fabricated.
- Production alert topic has no confirmed subscription, and current production
  alarms include a 916-message legacy DLQ plus stale/missing operational and
  Horizen-funding signals.  They require owner remediation, not suppression.
- Production deployment/routing, health-check, monitoring and funded-canary
  authorization remain separate controlled activation work.
