//! Effective configuration validation and CLI smoke tests.

use std::net::IpAddr;
use std::process::Command;

use sha2::{Digest, Sha256};
use world::{ConfigError, RouteError, parse_config};

fn valid_source() -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/config/valid-two-esp32.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("valid fixture")
}

#[test]
fn valid_two_esp32_config_has_stable_digest_and_registry() {
    let source = valid_source();
    let first = parse_config(&source).expect("valid config");
    let second = parse_config(&source).expect("valid config");
    assert_eq!(first.digest(), second.digest());
    let bytes = first.canonical_bytes().expect("bytes");
    assert_eq!(bytes, second.canonical_bytes().expect("bytes"));
    let encoded = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let fixture_dir = format!("{}/tests/fixtures/config", env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        encoded,
        std::fs::read_to_string(format!("{fixture_dir}/effective-config-canonical.hex"))
            .expect("canonical byte fixture")
            .trim()
    );
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let digest_hex = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    assert_eq!(
        digest_hex,
        std::fs::read_to_string(format!("{fixture_dir}/effective-config-canonical.sha256"))
            .expect("canonical digest fixture")
            .trim()
    );
    assert_eq!(first.digest(), digest);
    assert_eq!(first.capture().bind().to_string(), "127.0.0.1:9000");
    assert_eq!(first.registry().sensors().len(), 2);
    assert_eq!(first.registry().links().len(), 2);
    assert_eq!(first.registry().routes().len(), 2);
}

#[test]
fn configuration_rejects_unknown_fields_duplicate_ids_and_unknown_references() {
    let source = valid_source();
    assert!(parse_config(&format!("{source}\n[unexpected]\nvalue = true\n")).is_err());
    assert!(parse_config(&source.replacen("id = \"tx-b\"", "id = \"tx-a\"", 1)).is_err());
    assert!(
        parse_config(&source.replacen("transmitter = \"tx-a\"", "transmitter = \"missing\"", 1))
            .is_err()
    );
}

#[test]
fn configuration_rejects_legacy_raw_shorthands_and_implicit_source_fields() {
    let source = valid_source();
    let deployment_string =
        source.replacen("[deployment]\nid = \"lab\"", "deployment = \"lab\"", 1);
    assert!(parse_config(&deployment_string).is_err());

    let hardware_alias =
        source.replacen("hardware_kind = \"esp32-s3\"", "hardware_kind = \"esp32_s3\"", 1);
    assert!(parse_config(&hardware_alias).is_err());

    let channel_array = source.replacen(
        "[links.source_contract]\nprovisioned = true\nfixed_source_mac_filter = false\n\n[links.channel_policy]\nallowed = [1, 6]\nexpected = 1",
        "channel_policy = [1, 6]\n\n[links.source_contract]\nprovisioned = true\nfixed_source_mac_filter = false",
        1,
    );
    assert!(parse_config(&channel_array).is_err());

    let missing_source_field = source.replacen("fixed_source_mac_filter = false\n", "", 1);
    assert!(parse_config(&missing_source_field).is_err());
}

#[test]
fn configuration_rejects_ambiguous_route_channel_and_candidate_shadow() {
    let source = valid_source();
    let duplicate_route = format!(
        "{source}\n[[routes]]\npeer = \"192.0.2.10\"\nnode_id = 1\nlink = \"link-a\"\npeak_packets_per_second = 1\nmaximum_valid_datagram_bytes = 64\nchannel = 1\n"
    );
    assert!(parse_config(&duplicate_route).is_err());
    assert!(parse_config(&source.replacen("channel = 1", "channel = 6", 1)).is_err());
    assert!(parse_config(&source.replacen("mode = \"disabled\"", "mode = \"shadow\"", 1)).is_err());
}

#[test]
fn configuration_rejects_unreachable_esp32_wifi_channel() {
    let source = valid_source().replacen(
        "allowed = [6, 11]\nexpected = 6",
        "allowed = [6, 36]\nexpected = 6",
        1,
    );
    let error = parse_config(&source).expect_err("channel 36 is unreachable on ESP32 Wi-Fi");
    assert!(matches!(
        error,
        ConfigError::Invalid { field, reason }
            if field == "links[].channel_policy.allowed"
                && reason == "must contain only ESP32 Wi-Fi channels in 1..=14"
    ));
}

#[test]
fn configuration_rejects_multi_path_capability_without_wire_order() {
    let source = valid_source().replacen("multi_path = false", "multi_path = true", 1);
    let error = parse_config(&source).expect_err("multi-path wire order is not declared");
    assert!(matches!(
        error,
        ConfigError::Invalid { field, reason }
            if field == "sensors[].adr018.multi_path"
                && reason
                    == "must be false because the first-slice firmware has a fixed single-path wire layout"
    ));
}

#[test]
fn configuration_rejects_unknown_adr_capability() {
    let source = valid_source().replacen(
        "csi_acquire = \"wifi-csi\"",
        "csi_acquire = \"unsupported-acquisition\"",
        1,
    );
    assert!(parse_config(&source).is_err());
}

#[test]
fn baseline_quantiles_are_positive_and_adaptation_gate_is_a_score() {
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

    let score_above_one = source.replacen("adaptation_gate = 0.75", "adaptation_gate = 2.0", 1);
    assert!(parse_config(&score_above_one).is_ok());
    let score_above_stable =
        score_above_one.replacen("stable_threshold = 2.0", "stable_threshold = 1.0", 1);
    assert!(parse_config(&score_above_stable).is_err());
}

#[test]
fn intel_hardware_is_rejected_before_route_registry_creation() {
    let source = valid_source().replacen(
        "hardware_kind = \"esp32-s3\"",
        "hardware_kind = \"intel-5300\"",
        1,
    );
    assert!(parse_config(&source).is_err());
}

#[test]
fn source_contract_without_proof_remains_valid_but_not_inference_eligible() {
    let source = valid_source().replacen("provisioned = true", "provisioned = false", 1);
    let config = parse_config(&source).expect("raw source may be retained and rejected later");
    let route = config
        .registry()
        .resolve_route("192.0.2.10".parse::<IpAddr>().expect("peer"), 1)
        .expect("route");
    assert!(!route.link.inference_eligible());
}

#[test]
fn cli_check_config_reports_success_and_failure() {
    let fixture =
        format!("{}/tests/fixtures/config/valid-two-esp32.toml", env!("CARGO_MANIFEST_DIR"));
    let success = Command::new(env!("CARGO_BIN_EXE_world"))
        .args(["check-config", &fixture])
        .output()
        .expect("run check-config");
    assert!(success.status.success());

    let failure_fixture =
        std::env::temp_dir().join(format!("world-invalid-config-{}.toml", std::process::id()));
    std::fs::write(
        &failure_fixture,
        valid_source().replace("mode = \"disabled\"", "mode = \"shadow\""),
    )
    .expect("write invalid fixture");
    let failure = Command::new(env!("CARGO_BIN_EXE_world"))
        .args(["check-config", failure_fixture.to_str().expect("path")])
        .output()
        .expect("run check-config");
    assert!(!failure.status.success());
    std::fs::remove_file(&failure_fixture).expect("remove temporary invalid fixture");
}

#[test]
fn route_unknown_peer_is_rejected() {
    let config = parse_config(&valid_source()).expect("config");
    let result = config.registry().resolve_route("192.0.2.99".parse().expect("peer"), 1);
    assert!(matches!(result, Err(RouteError::Unknown { .. })));
}

#[test]
fn wildcard_route_only_matches_the_receiver_expected_peer() {
    let wildcard_source =
        valid_source().replacen("peer = \"192.0.2.10\"\nnode_id = 1", "node_id = 1", 1);
    let config = parse_config(&wildcard_source).expect("wildcard route config");
    assert!(
        config.registry().resolve_route("192.0.2.10".parse().expect("expected peer"), 1).is_ok()
    );
    assert!(matches!(
        config.registry().resolve_route("192.0.2.99".parse().expect("unexpected peer"), 1),
        Err(RouteError::Unknown { .. })
    ));
}

#[test]
fn exact_and_wildcard_routes_for_one_node_are_rejected() {
    let source = format!(
        "{}\n[[routes]]\nnode_id = 1\nlink = \"link-a\"\npeak_packets_per_second = 100\nmaximum_valid_datagram_bytes = 2048\nchannel = 1\n",
        valid_source()
    );
    assert!(parse_config(&source).is_err());
}
