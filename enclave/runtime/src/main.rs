// Keep the security-critical implementation single-sourced while compiling it inside the
// production-only dependency boundary declared by enclave/runtime/Cargo.toml.
include!("../../../src/bin/layrs-enclave.rs");
