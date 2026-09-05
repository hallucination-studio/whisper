//! Regression coverage for the RF-01 Cargo artifact boundary.

#[test]
fn package_has_no_legacy_host_binary_target() {
    assert!(option_env!("CARGO_BIN_EXE_whisper").is_none());
}
