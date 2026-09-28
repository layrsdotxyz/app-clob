//! Parent/enclave VSOCK transport limits. Both binaries include this exact
//! file by path so the two sides of the finite frame cannot drift.

/// Startup recovery and checkpoint sealing carry the verified immutable
/// lineage in finite parent-only VSOCK frames with a u32 length prefix.
pub const MAX_FRAME_BYTES: usize = 768 * 1024 * 1024;
const _: () = assert!(MAX_FRAME_BYTES <= u32::MAX as usize);

/// Enclave refusal for a sealed checkpoint that could not travel back in a
/// startup restore frame. The parent skips that refresh; nothing is persisted.
pub const CHECKPOINT_FRAME_OVERSIZED: &str = "CHECKPOINT_FRAME_OVERSIZED";

#[cfg(test)]
mod tests {
    #[test]
    fn shared_frame_limit_is_768_mib() {
        assert_eq!(super::MAX_FRAME_BYTES, 805_306_368);
    }
}
