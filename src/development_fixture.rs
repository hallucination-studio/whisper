//! Disposable development-fixture provisioning through the production key loader.

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::Config;
use crate::key_material::{
    EpochKey, FixtureKeyError, SecretStoreError, derive_public_development_fixture_key,
    load_epoch_key,
};

/// Failure while preparing or handing off disposable development fixture material.
#[derive(Debug)]
pub struct FixtureError {
    kind: FixtureErrorKind,
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for FixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

#[derive(Debug, thiserror::Error)]
enum FixtureErrorKind {
    #[error("configured Sensor {sensor_id} does not exist")]
    SensorNotFound { sensor_id: String },
    #[error("development fixture key derivation failed: {0}")]
    Derivation(#[source] FixtureKeyError),
    #[error("development fixture secret store could not be materialized: {0}")]
    Materialize(#[source] io::Error),
    #[error("development fixture key validation failed: {0}")]
    Validation(#[source] SecretStoreError),
    #[error("development fixture provisioner could not be started: {0}")]
    ChildStart(#[source] io::Error),
    #[error("development fixture key handoff failed: {0}")]
    Handoff(#[source] io::Error),
    #[error("development fixture provisioner could not be reaped: {0}")]
    ChildWait(#[source] io::Error),
    #[error("development fixture secret store cleanup failed: {0}")]
    Cleanup(#[source] io::Error),
}

impl From<FixtureErrorKind> for FixtureError {
    fn from(kind: FixtureErrorKind) -> Self {
        Self { kind }
    }
}

/// Runs a child provisioner with validated fixture facts and one inherited-stream key.
///
/// The child receives exactly 32 key bytes on standard input. Its environment
/// receives the non-secret Sensor, Device, key-epoch, firmware, capability,
/// and capture facts selected from `config`; raw key bytes never enter the
/// arguments or environment.
pub fn run(
    config: &Config,
    sensor_id: &str,
    command: &mut Command,
) -> Result<ExitStatus, FixtureError> {
    let (sensor_id, sensor) = config
        .registry()
        .sensors()
        .iter()
        .find(|(configured_id, _)| configured_id.as_str() == sensor_id)
        .ok_or_else(|| FixtureErrorKind::SensorNotFound { sensor_id: sensor_id.to_owned() })?;
    let device = sensor.device_id();
    let key_epoch = sensor.key_epoch();
    let firmware_build_digest = encode_digest(sensor.firmware_build_digest());
    let capability_digest = encode_digest(sensor.capability_digest());
    let capture = config.capture().bind();
    let derived = derive_public_development_fixture_key(sensor_id.as_str(), key_epoch.get())
        .map_err(FixtureErrorKind::Derivation)?;
    let store = FixtureStore::materialize(
        config.capture().secret_root(),
        device.get(),
        key_epoch.get(),
        &derived,
    )?;

    let operation = (|| {
        let key =
            load_epoch_key(config, device, key_epoch).map_err(FixtureErrorKind::Validation)?;
        command
            .env("WHISPER_FIXTURE_SENSOR_ID", sensor_id.as_str())
            .env("WHISPER_FIXTURE_DEVICE_ID", device.to_string())
            .env("WHISPER_FIXTURE_KEY_EPOCH", key_epoch.to_string())
            .env("WHISPER_FIXTURE_FIRMWARE_BUILD_DIGEST", firmware_build_digest)
            .env("WHISPER_FIXTURE_CAPABILITY_DIGEST", capability_digest)
            .env("WHISPER_FIXTURE_CAPTURE_IP", capture.ip().to_string())
            .env("WHISPER_FIXTURE_CAPTURE_PORT", capture.port().to_string());
        run_with_inherited_key(command, key)
    })();
    let cleanup = store.remove();
    match (operation, cleanup) {
        (Err(error), _) => Err(error.into()),
        (Ok(_), Err(source)) => Err(FixtureErrorKind::Cleanup(source).into()),
        (Ok(status), Ok(())) => Ok(status),
    }
}

fn encode_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_with_inherited_key(
    command: &mut Command,
    key: EpochKey,
) -> Result<ExitStatus, FixtureErrorKind> {
    let mut child = command.stdin(Stdio::piped()).spawn().map_err(FixtureErrorKind::ChildStart)?;
    let mut input = child.stdin.take().ok_or_else(|| {
        FixtureErrorKind::Handoff(io::Error::other("child stdin pipe was not created"))
    })?;
    let write_result = input.write_all(key.as_bytes());
    drop(input);
    let wait_result = child.wait();
    write_result.map_err(FixtureErrorKind::Handoff)?;
    wait_result.map_err(FixtureErrorKind::ChildWait)
}

struct FixtureStore {
    root: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    active: bool,
}

impl FixtureStore {
    fn materialize(
        root: &Path,
        device_id: u64,
        key_epoch: u16,
        key: &EpochKey,
    ) -> Result<Self, FixtureError> {
        create_private_directory(root).map_err(FixtureErrorKind::Materialize)?;
        let mut store = Self::new(root.to_path_buf())?;
        let device_directory = root.join(format!("device-{device_id}"));
        create_private_directory(&device_directory).map_err(FixtureErrorKind::Materialize)?;
        let key_path = device_directory.join(format!("key-{key_epoch}.bin"));
        let mut key_file = create_private_file(&key_path).map_err(FixtureErrorKind::Materialize)?;
        key_file.write_all(key.as_bytes()).map_err(FixtureErrorKind::Materialize)?;
        key_file.sync_all().map_err(FixtureErrorKind::Materialize)?;
        drop(key_file);
        store.active = true;
        Ok(store)
    }

    #[cfg(unix)]
    fn new(root: PathBuf) -> Result<Self, FixtureError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(&root).map_err(FixtureErrorKind::Materialize)?;
        Ok(Self { root, device: metadata.dev(), inode: metadata.ino(), active: true })
    }

    #[cfg(not(unix))]
    fn new(root: PathBuf) -> Result<Self, FixtureError> {
        Ok(Self { root, active: true })
    }

    fn remove(mut self) -> io::Result<()> {
        self.remove_if_owned()?;
        self.active = false;
        Ok(())
    }

    #[cfg(unix)]
    fn remove_if_owned(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(&self.root)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(io::Error::other("secret root identity changed before cleanup"));
        }
        fs::remove_dir_all(&self.root)
    }

    #[cfg(not(unix))]
    fn remove_if_owned(&self) -> io::Result<()> {
        fs::remove_dir_all(&self.root)
    }
}

impl Drop for FixtureStore {
    fn drop(&mut self) {
        if self.active {
            let _ = self.remove_if_owned();
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> io::Result<()> {
    Err(io::Error::other("platform cannot enforce Unix secret-store modes"))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn create_private_file(_path: &Path) -> io::Result<fs::File> {
    Err(io::Error::other("platform cannot enforce Unix secret-store modes"))
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::run;
    use crate::parse_config;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-development-fixture-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config_with_secret_root(path: &Path) -> crate::Config {
        let source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        parse_config(&source.replace(
            "secret_root = \"./data/secrets\"",
            &format!("secret_root = \"{}\"", path.display()),
        ))
        .expect("configuration with temporary secret root")
    }

    #[test]
    fn fixture_run_uses_the_loader_handoff_and_removes_its_store() {
        let root = fixture_root();
        let config = config_with_secret_root(&root);
        let mut command = Command::new("python3");
        command.args([
            "-c",
            "import hashlib,sys; data=sys.stdin.buffer.read(); raise SystemExit(0 if len(data) == 32 and hashlib.sha256(data).hexdigest() == sys.argv[1] else 1)",
            "c2def135281b73b4040f7582db5379e74719224385ae20feec3dfea0fd6234f5",
        ]);

        let status = run(&config, "sensor-a", &mut command).expect("fixture handoff");

        assert!(status.success());
        assert!(!root.exists(), "disposable secret root must be removed");
    }

    #[test]
    fn fixture_run_removes_its_store_when_the_child_cannot_start() {
        let root = fixture_root();
        let config = config_with_secret_root(&root);
        let mut command = Command::new(root.join("absent-provisioner"));

        let error =
            run(&config, "sensor-a", &mut command).expect_err("an absent provisioner must fail");

        assert!(!root.exists(), "failed handoff must remove the secret root");
        let diagnostic = format!("{error:?}\n{error}");
        assert!(!diagnostic.contains(&root.to_string_lossy().to_string()));
        assert!(
            !diagnostic
                .contains("65b0e5101c8f9f0c9c5ee7a77b959981e22ff95d001c98726f661827dd61de6f")
        );
    }

    #[test]
    fn fixture_run_removes_its_store_after_child_failure() {
        let root = fixture_root();
        let config = config_with_secret_root(&root);
        let mut command = Command::new("python3");
        command.args(["-c", "import sys; sys.stdin.buffer.read(); raise SystemExit(17)"]);

        let status = run(&config, "sensor-a", &mut command).expect("run failing provisioner");

        assert_eq!(status.code(), Some(17));
        assert!(!root.exists(), "child failure must remove the secret root");
    }
}
