# Governed WriterGrant execution — 2026-09-12

The existing governance KMS authority
`alias/layrs/production/recovery-evidence-signing` was used to sign the exact
canonical unsigned JSON in `WRITER_GRANT_UNSIGNED_20260912.json` with
`ECDSA_SHA_256`.  AWS KMS `Verify` returned `SignatureValid=true` for the
result in `WRITER_GRANT_SIGNED_20260912.json`.

The activation identifier is `layrs-direct-c0af327-365f299-20260912`; it
links evidence commit `c0af327` and the actual measured-runtime source
lineage `365f299`.  The `runtimeMeasurement.sourceCommit` is deliberately
the actual packaged runtime source `365f299e18220a7eae3e37d555d9596615d3d660`,
not the evidence-only commit: substituting `c0af327` there would falsely
describe the measured binary.

The grant binds the final AMI, EIF, PCR0/PCR1/PCR2, parent/enclave hashes,
sealed opening epoch/evidence, direct runtime identity, and current legacy
writer-fence hash.  Its bounded expiry is `1789292377` Unix seconds.

This operation only exercised the existing KMS signing authority.  It did
not inject the grant into production, enable the writer, update a projection
fence/grant row, launch a production route, sign or submit custody, or move
funds.  The required final pre-canary controls remain enforced.
