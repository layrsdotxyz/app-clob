# Final direct-execution BFF candidate — 2026-09-12

This is a dormant, writer-disabled candidate.  It is not an activation
authorization and it did not submit a custody transaction or alter a customer
balance.

## Exact measured candidate

- Direct-runtime source: `e287c37` (following ECDSA WriterGrant support at
  `6283df0` and Privy-derived session binding at `c327cf9`).
- Direct BFF source: `8c9d73dc`.
- AMI: `ami-0134f2ff9e2faecab`.
- EIF SHA-256: `564f8f36611edc9a851dc90eca51b0816765bacace4da38e3689f0b0115ad2ac`.
- Enclave binary SHA-256: `4f6edc00a8d19637c723efa55516a3d2fc6b12ef58a7efb1832c6971f8a8b38a`.
- Parent binary SHA-256: `995104b0b2f24df333adeca2112329ca47f3da9327c5dafbdf1401a80012d70c`.
- PCR0: `3e90e68fef843c8a799fadaefbe2bd6739c475a06af69aa7e019a534147b7508d19fac0305101258f21c9b3eb79c398f`.
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`.
- PCR2: `ba63e3b47a15554e4ff05b7a02cf099cd36aff99dc8716eb7561f9c69b1d8fc91d1e66ab73f058d69c74bcfdb0a2b67e`.
- Opening epoch state SHA-256:
  `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590`.
- Opening evidence-manifest SHA-256:
  `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957`.

## Independent dormant verification

An isolated, tagged `WriterEnabled=false` verifier launched from the exact
AMI confirmed all active services, loaded EIF checksum and measurements, the
two sealed opening hashes, fresh genesis ordinal `0`, runtime identity
`layrs.direct-execution.v1`, and `writerEnabled=false`.  The runtime returned
a Nitro attestation document.  The packaged parent executable audit found no
Durable Command, `DURABLE_PREPARATION`, `RELEASE_READY`, queue, lease, or
coordinator path.

## WriterGrant binding

The existing governance authority is KMS alias
`alias/layrs/production/recovery-evidence-signing`, using `ECDSA_SHA_256`.
The request must bind exactly the measurements above, the sealed epoch and
evidence hashes above, runtime `layrs.direct-execution.v1`, and active legacy
fence hash `b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364`.

No grant is present: the authorized change identifier, bounded expiry, and
governance signature remain intentionally absent.  They must be supplied and
signed by the existing governance authority; this record does not substitute
placeholders or manufacture an approval.
