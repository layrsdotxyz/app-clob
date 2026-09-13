# P0 hash-preserving runtime production change set

Status: `VERIFIED_PREPARED_NOT_CREATED_NOT_EXECUTED`

This package replaces only the measured direct-runtime candidate and its exact
governed startup authorization. It preserves the established direct-execution
architecture and the current private-state lineage. No AWS resource was
created, updated, or deleted while preparing or reviewing this package.

## Exact candidate and authorization

- Source commit: `0d0d560e3a3e271c6f46a130369f01e497998946`
- AMI: `ami-07bc5e5703da58ace`
- EIF SHA-256: `c18bbd7c01e163d358e1913f02ffb8514f0026592589c5983d38bbd5c0ef0ec6`
- Enclave binary SHA-256: `cd32464ebfe95828e1d1cc40988049c68b59da988b62644a961802157d6b984e`
- Parent binary SHA-256: `fc0ecc2543667e7265689ad7afd141c9de69dbe02f7ff6922953d09b672c084b`
- PCR0: `7b8f7d691ea7dff214414da22e6d5e4e68ffc4831d47c255601f3729c57ff56a7755f6833a607d74674585d37f9dd334`
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- PCR2: `a21f699dd58e303ead1039e6ed9635d62a07e9968ea38575c92f90f418b708b050bb7e70427284c7ac27598102105be6`
- Opening epoch: `layrs-opening-epoch-20260911-941107537728c98b`
- Opening state SHA-256: `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590`
- Opening evidence SHA-256: `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957`
- Signed WriterGrant: `evidence/WRITER_GRANT_P0_HASHFIX_SIGNED_20260914.json`
- WriterGrant commitment: `26d7f36a2fdae599105e896766b21424ac98a55ab00024f02208b1c339a5fd76`
- WriterGrant expiry: `2026-09-15T00:00:00Z` (`1789430400`)
- Parameter file: `evidence/P0_HASHFIX_PRODUCTION_RUNTIME_PARAMETERS_20260914.json`
- Stack: `layrs-production-direct-execution-dormant`

## Independent WriterGrant verification

The reviewed unsigned and signed JSON differ only in `signature`. The signed
payload has exactly the fields and camel-case encoding of the Rust
`WriterGrant`, `RuntimeMeasurementBinding`, and `KeyReleasePredecessor` structs.
All fixed runtime constants match: production environment,
`production-enabled` scope, epoch, transaction model, opening hashes,
governance key alias, and `ECDSA_SHA_256`.

- Canonical unsigned JSON SHA-256:
  `9c7299111cae6fea041edb3880fe29d8cf449d81ef55db01a556cf77be98ad16`
- The existing governance KMS key returned `SignatureValid=true` for those
  exact no-newline canonical bytes.
- The public key returned by KMS exactly matches the DER public key compiled
  into the measured runtime. DER SHA-256:
  `a001a573309c778b0b1f90ecd93eaf1cb07a37f4bea501c32c43afd754871f22`.
- OpenSSL independently returned `Verified OK` against the compiled public
  key and exact canonical bytes.
- A temporary, subsequently removed integration test deserialized this exact
  signed file as the Rust `WriterGrant`, called `WriterGrant::verify` with the
  exact runtime binding, and confirmed the commitment above. Result: `1 passed,
  0 failed`.
- The existing runtime negative/expiry WriterGrant test also passed.

## Current predecessor proof

Read-only production inspection established the immediate predecessor rather
than relying on an older evidence note:

- current stack WriterGrant commitment:
  `f577563b8d72afae62d168bb21bb91a79ceaf6480ac5f41a5533a0faf3a15aad`;
- activation: `layrs-direct-4d14163-p0-withdrawal-20260914`;
- immutable object:
  `direct-execution/layrs-opening-epoch-20260911-941107537728c98b/authorization/layrs-direct-4d14163-p0-withdrawal-20260914.cbor`;
- downloaded object SHA-256:
  `c6772995ac1570866ac53b6ddf2c8162a0bc73fadd67ff2ac3efcdd561ed1cc4`;
- server-side encryption: `aws:kms`;
- Object Lock: `COMPLIANCE`, retained through
  `2026-09-16T04:47:06Z`.

Those three exact predecessor values are signed into the new WriterGrant.
The old-writer fence commitment also resolves to the retained file
`evidence/LEGACY_WRITER_FENCE_20260912.json`, whose SHA-256 is exactly
`b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364`.

## Candidate measurement proof

Read-only AMI inspection confirmed the image is available, account-owned,
EBS-encrypted, writer-disabled, and tagged with the exact source, opening
hashes, enclave hash, and parent hash above.

Retained SSM invocation `8bcf6243-1be1-485d-88e1-3f5ed807ecac` independently
hashed the installed EIF, parent binary, opening state, and evidence manifest
and reported the exact values above. Retained nonce-bound attestation invocation
`a0b6f55b-b0b2-4d7b-80cf-25b5a1c388ff` was reverified locally against the AWS
Nitro root and produced:

- `coseSignatureVerified=true`;
- five verified certificate-chain signatures;
- `nonceMatches=true`;
- `bindingMatches=true`;
- module `i-0fbc74c4b1f410864-enc01a09cfe217c0d3a`;
- attestation SHA-256
  `7c0a552938310e063e166799f2c0dd28dcd843cf3ba2ed72bee47274bbeb0d0f`.

## Parameter equality

The parameter file contains 31 parameters:

- 23 retain `UsePreviousValue=true`, exactly the same key set as the prior P0
  runtime parameter file;
- eight explicit values are limited to `CandidateAmiId`, `ExecutionMode`,
  `WriterGrantBase64`, `ApprovedRuntimeBindingBase64`,
  `WriterGrantCommitment`, and `ApprovedPcr0/1/2`;
- the base64 WriterGrant round-trips byte-for-byte to the signed grant's JSON
  value;
- the base64 runtime binding round-trips field-for-field to
  `runtimeMeasurement`;
- each PCR parameter equals the corresponding signed measurement;
- the template passes CloudFormation validation;
- no secret value was resolved or added. The grant and runtime binding remain
  `NoEcho` CloudFormation parameters.

## Review-only change-set command

The following creates a reviewable change set but does not execute it. It was
not run during this preparation:

```bash
set +x
aws --profile predifi-root cloudformation create-change-set \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name p0-hashfix-0d0d560-20260914 \
  --change-set-type UPDATE \
  --description 'P0 hash-preserving direct runtime with exact governed grant' \
  --template-body file://deployment/layrs-direct-execution-production.template.yaml \
  --parameters file://evidence/P0_HASHFIX_PRODUCTION_RUNTIME_PARAMETERS_20260914.json \
  --capabilities CAPABILITY_IAM
```

Before creation, re-read and require the exact predecessor tuple above, the
same opening hashes and current private-ledger head, an unexpired new grant,
and all legacy financial writers at desired/running `0/0`. Any mismatch stops
the rollout and requires a freshly signed grant; it does not authorize changing
the predecessor or private state.

Review must reject any change outside the runtime IAM measurement condition,
launch-template/ASG replacement, and their direct dependencies. The execution
command is intentionally absent from this evidence package. No deployment was
performed.
