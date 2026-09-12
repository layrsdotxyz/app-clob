# WriterGrant and attested key-release closeout

Status: `VERIFIED_PACKAGED_ATTESTED_DORMANT_NOT_ACTIVATED`

Machine evidence: `WRITER_GRANT_KEY_RELEASE_FINAL_20260913.json`  
Machine evidence SHA-256: `6574322aba0759f8ff5fb5dce1ede5ca7458fac3f87dd57345ce2e0e450890c5`

## Root cause and correction

The parent loaded its WriterGrant and runtime keys from a host-only systemd
EnvironmentFile. A Nitro EIF does not inherit that environment, and the only
VSOCK bootstrap previously present was explicitly isolated-test-only. The
measured enclave therefore always remained dormant in a production-style
startup.

Commit `df846b8dbf0a0fbbb71700ac6cdb154dd42bb980` adds the missing bounded
startup authorization chain:

1. Parent verifies the signed WriterGrant and projection writer fence.
2. Parent delivers the exact grant and measurement binding over VSOCK.
3. Enclave independently verifies signature, expiry, environment, capability,
   opening epoch, lineage, AMI/EIF/binary hashes, and PCR tuple.
4. Enclave creates an ephemeral RSA recipient key and binds its public key,
   grant commitment, runtime, epoch, and requested mode into an NSM
   attestation.
5. AWS KMS releases only `CiphertextForRecipient` under the exact PCR and
   encryption-context policy. Parent plaintext is rejected.
6. The immutable KMS ciphertext artifact is written with S3 Object Lock and
   read back before completion.
7. Only the measured enclave can unwrap the runtime root and change from
   dormant to the grant-authorized mode.

This is startup authorization, not a financial command lifecycle. Direct
commands remain one synchronous clone, external-finality, immutable-artifact,
ACK, adopt, receipt flow. No queue, lease, coordinator, Durable Command, or
PostgreSQL financial authority was added.

## Final packaged candidate

- AMI: `ami-02b000f068cf6b5a9`
- EIF SHA-256: `e08c2005a107b5cdbd84969c43863d895b2651597e304a42fa9cc4a80188e569`
- Enclave binary SHA-256: `65fd07d6a7461a6bf9945ad5df57bb74858382d9dc62890588c5e7c5d13f12b2`
- Parent binary SHA-256: `c2359e34f5abb816c83927e8d161ff42e76361a38c44b7b47052932710ef2687`
- PCR0: `448ef35d38923ad72d25b9f208981219588308f8b0a5bb75be698c4d6bc420ffd30d669c8711acd87964691475a8a75c`
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- PCR2: `acfb6c886b10d60e7ef821f0c4645e7fd7f0ad061129ac389367e7bea78904876af0aa810bcf43a6f983d243e598a7c2`

Nonce-bound Nitro attestation verified ES384 COSE, five certificate-chain
signatures, the exact PCR tuple, and exact runtime binding. Attestation
SHA-256: `ea3202b0b01ae47e9a06d9d0c79f0f7be499f0f1af6c62406333341602ec5f25`.

## Acceptance

Tests A-L passed. The real packaged verifier additionally proved:

- valid governed startup and enclave-only key release;
- parent-only restart with the same grant commitment;
- enclave plus parent restart using the same immutable release artifact;
- missing grant returns a dormant writer-disabled runtime;
- denied KMS release leaves the parent unavailable and the enclave
  non-authoritative;
- restoring the exact PCR-bound policy recovers the committed state;
- one zero-value synthetic admission produced exactly one immutable successor,
  receipt, accounting projection, admission, and session;
- restart plus exact replay returned the identical encrypted result without a
  duplicate artifact or projection row.

All 40 Rust tests passed. Source and packaged-binary executable-path audits
found no Durable Preparation, release-ready, command queue, lease coordinator,
or Durable Command coordinator path.

## Final safety state

The verifier was returned to dormant mode, its temporary secret-bearing
EnvironmentFile and signed-session fixture were securely removed, and its
temporary key-release/archive/Secrets Manager inline permission was revoked.
Production remains on `ami-0a0c4d0e2608aa701`; it was not updated or enabled.
No customer funds moved, no custody transaction was submitted, no trade was
created, and the funded canary was not executed.
