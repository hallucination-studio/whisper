//! Feature-gated CLI coverage for disposable development fixture provisioning.

#![cfg(all(feature = "development-fixture", unix))]

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

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
            "import hashlib,os,sys; data=sys.stdin.buffer.read(); ok=len(data)==32 and hashlib.sha256(data).hexdigest()==sys.argv[1] and os.environ.get('WHISPER_FIXTURE_SENSOR_ID')=='sensor-a' and os.environ.get('WHISPER_FIXTURE_DEVICE_ID')=='1' and os.environ.get('WHISPER_FIXTURE_KEY_EPOCH')=='1' and os.environ.get('WHISPER_FIXTURE_FIRMWARE_BUILD_DIGEST')=='01'*32 and os.environ.get('WHISPER_FIXTURE_CAPABILITY_DIGEST')=='02'*32 and os.environ.get('WHISPER_FIXTURE_CAPTURE_IP')=='127.0.0.1' and os.environ.get('WHISPER_FIXTURE_CAPTURE_PORT')=='9000'; print('FIXTURE_PIPE_OK' if ok else 'FIXTURE_PIPE_FAIL'); raise SystemExit(0 if ok else 1)",
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

#[test]
fn feature_cli_cleans_its_store_after_terminal_interrupt() {
    let directory = fixture_directory();
    std::fs::create_dir(&directory).expect("create CLI fixture directory");
    let secret_root = directory.join("disposable-secret-root");
    let ready = directory.join("child-ready");
    let config_path = directory.join("runtime.toml");
    let source = include_str!("fixtures/config/valid-two-esp32.toml").replace(
        "secret_root = \"./data/secrets\"",
        &format!("secret_root = \"{}\"", secret_root.display()),
    );
    std::fs::write(&config_path, source).expect("write CLI fixture configuration");

    let mut interrupted = Command::new(env!("CARGO_BIN_EXE_whisper"));
    interrupted
        .args([
            "development-fixture",
            config_path.to_str().expect("UTF-8 configuration path"),
            "sensor-a",
            "python3",
            "-c",
            "import pathlib,sys,time; sys.stdin.buffer.read(); pathlib.Path(sys.argv[1]).touch(); time.sleep(30)",
            ready.to_str().expect("UTF-8 readiness path"),
        ])
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = interrupted.spawn().expect("start interruptible fixture CLI");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < deadline {
        assert!(child.try_wait().expect("poll fixture CLI").is_none());
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "fixture child did not become ready");

    let group = rustix::process::Pid::from_raw(child.id() as _).expect("nonzero process group");
    rustix::process::kill_process_group(group, rustix::process::Signal::INT)
        .expect("interrupt fixture process group");
    child.wait().expect("reap interrupted fixture CLI");
    let cleaned = !secret_root.exists();

    let retry = Command::new(env!("CARGO_BIN_EXE_whisper"))
        .args([
            "development-fixture",
            config_path.to_str().expect("UTF-8 configuration path"),
            "sensor-a",
            "/usr/bin/true",
        ])
        .output()
        .expect("retry fixture CLI");
    std::fs::remove_dir_all(&directory).expect("remove CLI fixture directory");

    assert!(cleaned, "terminal interrupt must remove the disposable secret root");
    assert!(retry.status.success(), "fixture CLI must be reusable after interruption");
}
