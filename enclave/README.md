# Layrs Nitro enclave

This image contains the only process allowed to see private principals, balances, orders,
positions, fills and Pyth resolution inputs. It has no TCP networking or persistent block device.
The parent instance can transport only length-prefixed encrypted frames over VSOCK port `5003`.

## Trust bootstrap

1. Build the EIF with a release Ed25519 operator public key. The key is compiled into the image,
   so changing it changes PCR0.
2. Publish the `nitro-cli build-enclave` PCR measurements and source commit.
3. A client requests an NSM attestation with a fresh nonce. The signed document binds PCRs to the
   enclave X25519 transport key and the enclave receipt-verification key.
4. Only after validating the AWS certificate chain, nonce, PCR allowlist and both key bindings may
   a client encrypt a request.
5. The operator sends a signed, replay-protected provisioning command through that channel. The
   command contains the journal key returned to the enclave through the KMS attested-recipient
   flow and the Pyth resolution-verifier public key.

All administrative commands require the compiled operator signature. User commands additionally
require a registered, enclave-local Ed25519 session and monotonically increasing sequence. The
enclave never accepts a wallet address as a private ledger owner.

## Release rules

- Never build a release EIF with the test key shown in local verification commands.
- Never enable Nitro debug mode; debug EIF PCR values are zero and must be denied by KMS.
- KMS policy must allow decrypt only for the published PCR0 and the dedicated `layrsv2` parent
  instance role.
- Store encrypted journal records outside the enclave, but restore them only after verifying their
  AEAD and hash chain. A snapshot/replay implementation is required before production launch.
- Rotate the EIF by overlapping old and new PCR allowlists, draining orders, reconciling state,
  then removing the old PCR.

Build on a Nitro-enabled Linux host:

```sh
LAYRS_OPERATOR_PUBLIC_KEY_HEX=<release-public-key> ./enclave/build-eif.sh
```
