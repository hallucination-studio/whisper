//! Effective configuration validation and command-line smoke tests.

use std::process::Command;

use sha2::{Digest, Sha256};
use whisper::{ConfigError, parse_config};

fn valid_source() -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/config/valid-two-esp32.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("valid fixture")
}

#[test]
fn valid_s3_config_has_stable_digest_and_exact_routes() {
    let source = valid_source();
    let first = parse_config(&source).expect("valid config");
    let second = parse_config(&source).expect("valid config");
    assert_eq!(first.replay().digest(), second.replay().digest());
    let bytes = first.replay().canonical_bytes().expect("bytes");
    assert_eq!(bytes, second.replay().canonical_bytes().expect("bytes"));
    let encoded = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let fixture_dir = format!("{}/tests/fixtures/config", env!("CARGO_MANIFEST_DIR"));
    let expected_bytes =
        std::fs::read_to_string(format!("{fixture_dir}/replay-config-canonical.hex"))
            .expect("replay config byte fixture")
            .trim()
            .to_owned();
    assert_eq!(encoded, expected_bytes);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(first.replay().digest(), digest);
    let digest_hex = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let expected_digest =
        std::fs::read_to_string(format!("{fixture_dir}/replay-config-canonical.sha256"))
            .expect("replay config digest fixture")
            .trim()
            .to_owned();
    assert_eq!(digest_hex, expected_digest);
    assert_eq!(first.capture().bind().to_string(), "127.0.0.1:9000");
    assert_eq!(first.capture().secret_root().to_string_lossy(), "./data/secrets");
    assert_eq!(first.registry().sensors().len(), 2);
    assert_eq!(first.registry().links().len(), 2);
    assert_eq!(first.registry().routes().len(), 2);
}

#[test]
fn configuration_omits_flush_policy_and_rejects_legacy_values() {
    let source = valid_source();
    parse_config(&source).expect("config without flush_policy must be valid");

    for legacy in ["every_record", "window"] {
        let legacy_source = source.replace(
            "retention_max_sessions = 8",
            &format!("retention_max_sessions = 8\nflush_policy = \"{legacy}\""),
        );
        match parse_config(&legacy_source) {
            Err(ConfigError::Parse(message)) => assert!(
                message.contains("unknown field `flush_policy`"),
                "legacy value {legacy} produced the wrong parse error: {message}"
            ),
            Err(error) => panic!("legacy value {legacy} produced the wrong error: {error}"),
            Ok(_) => panic!("legacy value {legacy} was accepted"),
        }
    }
}

#[test]
fn runtime_only_changes_do_not_change_replay_digest() {
    let source = valid_source();
    let original = parse_config(&source).expect("valid config");
    let changed = parse_config(
        &source
            .replace("bind = \"127.0.0.1:9000\"", "bind = \"127.0.0.1:9001\"")
            .replace(
                "database_path = \"./data/whisper.sqlite3\"",
                "database_path = \"./other.sqlite3\"",
            )
            .replace("retention_max_sessions = 8", "retention_max_sessions = 7"),
    )
    .expect("runtime-only mutation");
    assert_eq!(original.replay().digest(), changed.replay().digest());

    let semantic = parse_config(
        &source.replace("allowed_lateness_ns = 100000000", "allowed_lateness_ns = 100000001"),
    )
    .expect("semantic mutation");
    assert_ne!(original.replay().digest(), semantic.replay().digest());
}

#[test]
fn configuration_rejects_unknown_fields_duplicate_ids_and_unknown_references() {
    let source = valid_source();
    assert!(parse_config(&format!("{source}\n[unexpected]\nvalue = true\n")).is_err());
    assert!(parse_config(&source
        .replace(
            "secret_root = \"./data/secrets\"",
            "secret_root = \"./data/secrets\"\nkey = \"0000000000000000000000000000000000000000000000000000000000000000\"",
        ))
        .is_err());
    assert!(parse_config(&source.replacen("id = \"tx-b\"", "id = \"tx-a\"", 1)).is_err());
    assert!(matches!(
        parse_config(&source.replacen("device_id = 2", "device_id = 1", 1)),
        Err(ConfigError::Duplicate { kind: "device", id }) if id == "1"
    ));
    assert!(
        parse_config(&source.replacen("transmitter = \"tx-a\"", "transmitter = \"missing\"", 1))
            .is_err()
    );
}

#[test]
fn configuration_rejects_legacy_or_ambiguous_route_fields() {
    let source = valid_source();
    assert!(parse_config(&source.replace("database_path =", "directory =")).is_err());
    assert!(parse_config(&source.replacen("device_id = 1", "node_id = 1", 1)).is_err());
    assert!(parse_config(&source.replacen("peer = \"192.0.2.10\"", "peer = \"*\"", 1)).is_err());
    assert!(
        parse_config(&source.replacen(
            "expected_transmitter_mac = \"02:00:00:00:00:0a\"",
            "source_contract = true",
            1,
        ))
        .is_err()
    );
    let duplicate = format!(
        "{source}\n[[routes]]\npeer = \"192.0.2.10\"\ndevice_id = 1\nkey_epoch = 1\nlink = \"link-a\"\npeak_packets_per_second = 1\nmaximum_valid_datagram_bytes = 64\nmaximum_authenticated_bytes_per_second = 64\nreplay_window_packets = 1\n"
    );
    assert!(parse_config(&duplicate).is_err());
}

#[test]
fn configuration_rejects_invalid_s3_pins_and_hardware() {
    let source = valid_source();
    assert!(parse_config(&source.replacen("key_epoch = 1", "key_epoch = 0", 1)).is_err());
    assert!(parse_config(&source.replacen(
        "firmware_build_digest = \"0101010101010101010101010101010101010101010101010101010101010101\"",
        "firmware_build_digest = \"00\"",
        1,
    )).is_err());
    assert!(
        parse_config(&source.replacen(
            "expected_transmitter_mac = \"02:00:00:00:00:0a\"",
            "expected_transmitter_mac = \"00:00:00:00:00:00\"",
            1,
        ))
        .is_err()
    );
    assert!(matches!(
        parse_config(&source.replacen(
            "hardware_kind = \"esp32-s3\"",
            "hardware_kind = \"intel-5300\"",
            1
        )),
        Err(ConfigError::UnsupportedHardware { .. })
    ));
}

#[test]
fn configuration_keeps_existing_numeric_guards() {
    let source = valid_source();
    assert!(
        parse_config(&source.replacen("deviation_quantile = 0.95", "deviation_quantile = 0.0", 1))
            .is_err()
    );
    assert!(
        parse_config(&source.replacen(
            "rf_dynamics_quantile = 0.95",
            "rf_dynamics_quantile = 0.0",
            1
        ))
        .is_err()
    );
    assert!(parse_config(&source.replacen("allowed = [6, 11]", "allowed = [6, 36]", 1)).is_err());
}

#[test]
fn cli_check_config_reports_success_and_failure() {
    let fixture =
        format!("{}/tests/fixtures/config/valid-two-esp32.toml", env!("CARGO_MANIFEST_DIR"));
    let success = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["check-config", &fixture])
        .output()
        .expect("run check-config");
    assert!(success.status.success());

    let failure_fixture =
        std::env::temp_dir().join(format!("whisper-invalid-config-{}.toml", std::process::id()));
    std::fs::write(
        &failure_fixture,
        valid_source().replace("deviation_quantile = 0.95", "deviation_quantile = 0.0"),
    )
    .expect("write invalid fixture");
    let failure = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args(["check-config", failure_fixture.to_str().expect("path")])
        .output()
        .expect("run check-config");
    assert!(!failure.status.success());
    std::fs::remove_file(failure_fixture).expect("remove temporary invalid fixture");
}
