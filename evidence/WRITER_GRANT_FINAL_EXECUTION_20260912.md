# Final governed WriterGrant — 2026-09-12

The existing production governance KMS authority
`alias/layrs/production/recovery-evidence-signing` signed the exact canonical
unsigned JSON in `WRITER_GRANT_FINAL_UNSIGNED_20260912.json` with
`ECDSA_SHA_256`. AWS KMS independently returned `SignatureValid=true`.

The grant binds activation `layrs-direct-40ca230-20260912` to source commit
`40ca230d40799f0d45a488cf220d863699c0051a`, AMI
`ami-0a0c4d0e2608aa701`, EIF
`28c4f8ad242ebb5b0525961cc5994b6b6426c98dd48a39ae133e7cac476912c2`,
the measured PCR0/PCR1/PCR2 tuple, the exact parent/enclave hashes, the sealed
opening epoch, the evidence manifest, and the independently retained legacy
writer-fence evidence. Its bounded expiry is Unix `1789492554`.

Unsigned payload SHA-256:
`f02913a91dc353a8cb6b89028aaf31372f48b1b2a60992e8cd5721895f76a34e`.

The signature was prepared and verified only. It was not installed to enable
financial writing; the deployed final candidate remains writer-disabled and
admission-disabled.
