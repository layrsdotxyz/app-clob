# Clean direct-execution integration contract

The image starts with writer authority disabled.  It can serve health, status,
and attestation without authentication material.  Customer endpoints require a
short-lived BFF session whose HMAC is verified by the parent; the BFF is where
Privy authentication is verified and the canonical subject hash is selected.

The parent constructs a `DirectRequest` from that session and forwards it over
VSOCK.  The enclave verifies the sealed subject-to-identity and
subject-to-embedded-Privy-wallet mappings before applying a single terminal
result.  The parent returns an encrypted ChaCha20-Poly1305 envelope.  A client
cannot select a different subject, inject a custody reference, or receive a
plaintext receipt.

## Projection

`sql/001_direct_execution_projection.sql` is the required PostgreSQL receipt
projection.  It is append-only by receipt ID and has an epoch/subject/request
unique key for replay recovery.  It contains no private balance fields.  A
projection outage returns no customer success; retrying the same request is
safe because the enclave returns the same signed terminal receipt.

## Custody

Only the isolated mock custody adapter is enabled in this package.  It creates
`mock-custody:` references and is rejected outside isolated-test mode.  A live
adapter must present a finality-qualified transaction reference before the
enclave accepts a deposit or withdrawal result.  No real RPC endpoint, signer,
or custody credential is packaged here.

## Governed writer bootstrap and rollback

No HTTP route can enable the writer. The EIF always starts dormant and does
not inherit the parent's environment. Production mode requires all of:

1. a valid, time-bounded `WriterGrant` for this epoch;
2. an ECDSA signature verified against the governance public key compiled into
   the measured EIF;
3. a 64-hex old-writer-fence evidence hash contained in that grant; and
4. an explicit `LAYRS_DIRECT_EXECUTION_MODE=production-enabled` parent start;
5. an NSM attestation whose ephemeral RSA recipient key and user data bind the
   exact grant, epoch, requested scope and KMS reference; and
6. a KMS `CiphertextForRecipient` release under the exact PCR-conditioned
   existing CMK.

The grant and all key material are absent from the AMI/EIF. The parent receives
the signed public grant and approved measurement binding, but it never receives
the KMS plaintext runtime root key. It immutably stores only the KMS ciphertext
blob; the enclave derives its receipt and private-state keys after decrypting
the recipient ciphertext. The existing receipt-share material derives only the
parent/enclave durability-ACK credential and is never a custody signer or
private-ledger decryption key.

The activation operator must first write and independently verify the
`direct_execution_writer_fence` row, disable and prove the old writer, verify
the target attestation and sealed epoch hashes, and only then provide the
grant. Rollback removes target routing and terminates the target writer before
restoring the previously fenced writer; it is not a traffic-only reversal.
