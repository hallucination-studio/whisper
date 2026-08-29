//! Feature-gated CLI coverage for disposable development fixture provisioning.

#![cfg(all(feature = "development-fixture", unix))]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "whisper-fixture-cli-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn feature_cli_runs_inherited_handoff_without_disclosing_fixture_material() {
    let directory = fixture_directory();
    std::fs::create_dir(&directory).expect("create CLI fixture directory");
    let secret_root = directory.join("disposable-secret-root");
    let config_path = directory.join("runtime.toml");
    let source = include_str!("fixtures/config/valid-two-esp32.toml").replace(
        "secret_root = \"./data/secrets\"",
        &format!("secret_root = \"{}\"", secret_root.display()),
    );
    std::fs::write(&config_path, source).expect("write CLI fixture configuration");

    let output = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args([
            "development-fixture",
            config_path.to_str().expect("UTF-8 configuration path"),
            "sensor-a",
            "python3",
            "-c",
            "import hashlib,os,sys; data=sys.stdin.buffer.read(); ok=len(data)==32 and hashlib.sha256(data).hexdigest()==sys.argv[1] and os.environ.get('WHISPER_FIXTURE_SENSOR_ID')=='sensor-a' and os.environ.get('WHISPER_FIXTURE_DEVICE_ID')=='1' and os.environ.get('WHISPER_FIXTURE_KEY_EPOCH')=='1'; print('FIXTURE_PIPE_OK' if ok else 'FIXTURE_PIPE_FAIL'); raise SystemExit(0 if ok else 1)",
            "c2def135281b73b4040f7582db5379e74719224385ae20feec3dfea0fd6234f5",
        ])
        .output()
        .expect("run feature CLI");

    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "feature CLI failed: {combined}");
    assert!(combined.contains("FIXTURE_PIPE_OK"));
    assert!(!secret_root.exists());
    assert!(!combined.contains(&secret_root.to_string_lossy().to_string()));
    assert!(!combined.contains("65b0e5101c8f9f0c9c5ee7a77b959981e22ff95d001c98726f661827dd61de6f"));

    std::fs::remove_dir_all(directory).expect("remove CLI fixture directory");
}
