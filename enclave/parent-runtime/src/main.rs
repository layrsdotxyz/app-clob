// Keep the transport implementation single-sourced while compiling it without migration-server
// dependencies.
#[allow(dead_code, clippy::large_enum_variant)]
mod parent_binary {
    include!("../../../src/bin/layrs-enclave-parent.rs");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    parent_binary::main()
}
