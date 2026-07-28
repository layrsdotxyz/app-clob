// Keep the security-critical implementation single-sourced while compiling it inside the
// production-only dependency boundary declared by enclave/runtime/Cargo.toml.
#[allow(dead_code, clippy::large_enum_variant)]
mod enclave_binary {
    include!("../../../src/bin/layrs-enclave.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enclave_binary::main()
}
