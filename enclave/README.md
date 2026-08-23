# Layrs Nitro enclave

This image contains the only process allowed to see private principals, balances, orders,
positions, fills and Pyth resolution inputs. It has no TCP networking or persistent block device.
The parent instance can transport only length-prefixed encrypted frames over VSOCK port `5003`.

`layrs-enclave-parent` is the deliberately untrusted HTTP-to-VSOCK adapter. It validates bounds,
applies timeouts and concurrency limits, but has no decryption key. `GET /v1/attestation` returns
the raw NSM document and bound public keys; `POST /v1/private/relay` passes only base64url
ciphertext. It must be reachable only from the `layrsv2` internal load balancer/security group.

## Trust bootstrap

1. Build the EIF with a release Ed25519 operator public key. The key is compiled into the image,
   so changing it changes PCR0.
2. Publish the `nitro-cli build-enclave` PCR measurements and source commit.
3. A client requests an NSM attestation with a fresh nonce. The signed document binds PCRs to the
   enclave X25519 transport key and the enclave receipt-verification key.
4. Only after validating the AWS certificate chain, nonce, PCR allowlist and both key bindings may
   a client encrypt a request.
5. The operator sends a signed, replay-protected provisioning command through that channel. The
   command contains KMS `CiphertextForRecipient` material for the journal, Polymarket credential,
   and pool-chain-signer bundles, plus the resolution-verifier public key. The verifier key must
   match the Ed25519 key sealed inside the chain-signer bundle. Only the enclave
   can unwrap those recipient ciphertexts.

All administrative commands require the compiled operator signature. User commands additionally
require a registered, enclave-local Ed25519 session and monotonically increasing sequence. The
enclave never accepts a wallet address as a private ledger owner.

## Release rules

- Never build a release EIF with the test key shown in local verification commands.
- Never enable Nitro debug mode; debug EIF PCR values are zero and must be denied by KMS.
- The coordinator task may call KMS only with a fresh attestation recipient document. KMS policy
  must require the published PCR measurements through Nitro attestation condition keys and return
  `CiphertextForRecipient`; plaintext key material must never be returned to the coordinator.
- The parent instance has no AWS credentials and no KMS, S3, database, RPC, or Secrets Manager
  permission. Its only outbound application tunnel is the fixed Polymarket TLS endpoint used by
  enclave-owned bootstrap execution.
- Store every encrypted journal record and same-sequence encrypted snapshot in the immutable
  `layrsv2` S3 archive before releasing the corresponding response. On replacement, restore the
  highest archived snapshot and reject any checkpoint behind the latest confirmed audit anchor.
- Run exactly one active private core. The Auto Scaling Group may replace a failed host, but a
  replacement must restore and reconcile immutable ciphertext before traffic is moved. Two
  independently writable enclaves must never share a load balancer.
- Rotate the EIF by overlapping old and new PCR allowlists, draining orders, reconciling state,
  then removing the old PCR. If a deployment must roll an already-DURABLE command across PCRs,
  the target EIF must be built with the exact governed
  `LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256` for source PCR, target PCR and snapshot schema. The
  policy changes PCR0 and belongs in the signed release manifest. An empty policy requires a
  complete DURABLE drain and retention of the old EIF; arbitrary operator authorization cannot
  relax this gate.
- Import exactly one Base/USDC and one Horizen/ZEN domain. Each has distinct ledger and
  `AdminOracle` resolver keys; their addresses must equal the corresponding audited-contract role
  holders. The bundle also carries a distinct Ed25519 resolution key whose public half is bound
  into core provisioning. The import source is an
  ephemeral offline host over stdin; never put a signer key in an environment variable, ECS task,
  parent instance, log, image, or plaintext secret.
- Build and audit the EIF only through `enclave/runtime/Cargo.toml`. This intentionally excludes
  the retained migration server's database, provider and public HTTP dependency graph from the
  production trust boundary. A root-package build is not an enclave release artifact.

Before building, the production runtime lock must pass its independent advisory gate:

```sh
./scripts/audit-enclave-dependencies.sh
cargo test --locked --manifest-path enclave/runtime/Cargo.toml
cargo test --locked --manifest-path enclave/parent-runtime/Cargo.toml
```

The audit script permits `RUSTSEC-2026-0235` only while `rkyv` is absent from the runtime's
active dependency graph. `rust_decimal` declares `rkyv` as an optional feature, which causes Cargo
to record it in the lockfile even though the production enclave does not compile or link it. The
script fails closed if a future dependency or feature activates `rkyv`; the exception must then be
removed and the dependency upgraded before release.

Build on a Nitro-enabled Linux host:

```sh
LAYRS_OPERATOR_PUBLIC_KEY_HEX=<release-public-key> ./enclave/build-eif.sh
```

To bake the parent AMI, build the locked parent binary and EIF, verify the PCR manifest, and then
run Packer. Never supply the operator private key to this repository or the AMI build:

```sh
LAYRS_OPERATOR_PUBLIC_KEY_HEX=<release-public-key> ./enclave/build-host-artifacts.sh
packer init enclave/packer/layrsv2-enclave-parent.pkr.hcl
packer build -var aws_region=<region> -var release_id=<immutable-release-id> enclave/packer/layrsv2-enclave-parent.pkr.hcl
```
