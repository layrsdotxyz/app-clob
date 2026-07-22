# Dependency security boundaries

Layrs does not ship the root Cargo package as a production confidential-computing artifact. That
package intentionally retains the original migration server, proof adapters and broad EVM provider
stack for reference and parity testing.

The two deployable Nitro artifacts have independent, locked dependency closures:

- `enclave/runtime/Cargo.lock` — the measured EIF and all code allowed to hold private state or
  signing material.
- `enclave/parent-runtime/Cargo.lock` — the untrusted HTTP/VSOCK relay installed on the parent EC2
  host.

CI and the release job run `cargo audit` against both locks. The parent closure is clean. The EIF
closure has no known vulnerability; `cargo-audit` currently reports only the upstream
`serde_cbor` maintenance warning inherited from AWS's official
`aws-nitro-enclaves-nsm-api 0.5.2`. It is confined to NSM request/response encoding and is tracked
for replacement when AWS publishes a maintained compatible API crate.

The root lock currently includes advisories inherited by retained non-release components,
including the old `ethers-providers`/`jsonwebtoken` TLS chain and the `mini-redis` test helper.
These are not allowlisted into either production lock, and any attempt to build a deployable image
from the root package violates the release process. New code must not expand the root migration
surface; it belongs in one of the explicit runtime packages or a separate service repository.

Run the release-boundary checks locally with:

```sh
cargo audit --file enclave/runtime/Cargo.lock
cargo audit --file enclave/parent-runtime/Cargo.lock
cargo test --locked --manifest-path enclave/runtime/Cargo.toml
cargo test --locked --manifest-path enclave/parent-runtime/Cargo.toml
```
