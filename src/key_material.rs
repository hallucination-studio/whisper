//! Validated epoch-key material shared by Host admission and provisioning.

use std::fmt;
use std::fs;
use std::io::{self, Read};

#[cfg(feature = "development-fixture")]
use sha2::{Digest, Sha256};

use crate::Config;
use crate::domain::identity::{DeviceId, KeyEpoch};

pub(crate) struct EpochKey([u8; 32]);

impl EpochKey {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) const fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochKey([REDACTED])")
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SecretStoreError {
    #[error("key material is missing for device {device} and key epoch {key_epoch}")]
    Missing { device: DeviceId, key_epoch: KeyEpoch },
    #[error("a different key epoch exists for device {device}; requested epoch {key_epoch}")]
    WrongEpoch { device: DeviceId, key_epoch: KeyEpoch },
    #[error("secret root is untrusted for device {device} and key epoch {key_epoch}: {reason}")]
    UntrustedRoot { device: DeviceId, key_epoch: KeyEpoch, reason: &'static str },
    #[error(
        "device key directory is untrusted for device {device} and key epoch {key_epoch}: {reason}"
    )]
    UntrustedDeviceDirectory { device: DeviceId, key_epoch: KeyEpoch, reason: &'static str },
    #[error("key file is untrusted for device {device} and key epoch {key_epoch}: {reason}")]
    UntrustedKeyFile { device: DeviceId, key_epoch: KeyEpoch, reason: &'static str },
    #[error("key material for device {device} and key epoch {key_epoch} is not exactly 32 bytes")]
    WrongLength { device: DeviceId, key_epoch: KeyEpoch },
    #[error(
        "key material for device {device} and key epoch {key_epoch} could not be read: {source}"
    )]
    Io {
        device: DeviceId,
        key_epoch: KeyEpoch,
        #[source]
        source: io::Error,
    },
    #[error(
        "{object} changed while loading key material for device {device} and key epoch {key_epoch}"
    )]
    Replaced { device: DeviceId, key_epoch: KeyEpoch, object: &'static str },
}

pub(crate) fn load_epoch_key(
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<EpochKey, SecretStoreError> {
    load_epoch_key_with_after_read(config, device, key_epoch, || {})
}

#[cfg(unix)]
fn load_epoch_key_with_after_read(
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
    after_read: impl FnOnce(),
) -> Result<EpochKey, SecretStoreError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let root_path = config.capture().secret_root();
    let device_path = root_path.join(format!("device-{device}"));
    let key_path = device_path.join(format!("key-{key_epoch}.bin"));

    let root_before = directory_snapshot(root_path, DirectoryKind::Root, device, key_epoch)?;
    let device_before = directory_snapshot(&device_path, DirectoryKind::Device, device, key_epoch)?;
    let key_before = key_snapshot(&key_path, device, key_epoch)?;

    let directory_flags = libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(directory_flags)
        .open(root_path)
        .map_err(|source| SecretStoreError::Io { device, key_epoch, source })?;
    let opened_root = directory_snapshot_from_metadata(
        &root.metadata().map_err(|source| SecretStoreError::Io { device, key_epoch, source })?,
        DirectoryKind::Root,
        device,
        key_epoch,
    )?;
    require_same_snapshot(root_before, opened_root, "secret root", device, key_epoch)?;

    let device_directory = OpenOptions::new()
        .read(true)
        .custom_flags(directory_flags)
        .open(&device_path)
        .map_err(|source| SecretStoreError::Io { device, key_epoch, source })?;
    let opened_device = directory_snapshot_from_metadata(
        &device_directory.metadata().map_err(|source| SecretStoreError::Io {
            device,
            key_epoch,
            source,
        })?,
        DirectoryKind::Device,
        device,
        key_epoch,
    )?;
    require_same_snapshot(device_before, opened_device, "device directory", device, key_epoch)?;

    let mut key_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&key_path)
        .map_err(|source| SecretStoreError::Io { device, key_epoch, source })?;
    let opened_key = key_snapshot_from_metadata(
        &key_file.metadata().map_err(|source| SecretStoreError::Io {
            device,
            key_epoch,
            source,
        })?,
        device,
        key_epoch,
    )?;
    require_same_snapshot(key_before, opened_key, "key file", device, key_epoch)?;

    let mut bytes = [0_u8; 32];
    if let Err(source) = key_file.read_exact(&mut bytes) {
        return if source.kind() == io::ErrorKind::UnexpectedEof {
            Err(SecretStoreError::WrongLength { device, key_epoch })
        } else {
            Err(SecretStoreError::Io { device, key_epoch, source })
        };
    }
    let mut trailing = [0_u8; 1];
    match key_file.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(SecretStoreError::WrongLength { device, key_epoch }),
        Err(source) => return Err(SecretStoreError::Io { device, key_epoch, source }),
    }

    after_read();

    let root_after =
        post_directory_snapshot(root_path, DirectoryKind::Root, "secret root", device, key_epoch)?;
    let device_after = post_directory_snapshot(
        &device_path,
        DirectoryKind::Device,
        "device directory",
        device,
        key_epoch,
    )?;
    let key_after = post_key_snapshot(&key_path, device, key_epoch)?;
    require_same_snapshot(root_before, root_after, "secret root", device, key_epoch)?;
    require_same_snapshot(device_before, device_after, "device directory", device, key_epoch)?;
    require_same_snapshot(key_before, key_after, "key file", device, key_epoch)?;

    drop(key_file);
    drop(device_directory);
    drop(root);
    Ok(EpochKey(bytes))
}

#[cfg(not(unix))]
fn load_epoch_key_with_after_read(
    _config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
    _after_read: impl FnOnce(),
) -> Result<EpochKey, SecretStoreError> {
    Err(SecretStoreError::UntrustedRoot {
        device,
        key_epoch,
        reason: "platform cannot enforce the Unix secret-store contract",
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectorySnapshot {
    device: u64,
    inode: u64,
    mode: u32,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeySnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    length: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum DirectoryKind {
    Root,
    Device,
}

#[cfg(unix)]
fn directory_snapshot(
    path: &std::path::Path,
    kind: DirectoryKind,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<DirectorySnapshot, SecretStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SecretStoreError::Missing { device, key_epoch });
        }
        Err(source) => return Err(SecretStoreError::Io { device, key_epoch, source }),
    };
    directory_snapshot_from_metadata(&metadata, kind, device, key_epoch)
}

#[cfg(unix)]
fn directory_snapshot_from_metadata(
    metadata: &fs::Metadata,
    kind: DirectoryKind,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<DirectorySnapshot, SecretStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let invalid = |reason| match kind {
        DirectoryKind::Root => SecretStoreError::UntrustedRoot { device, key_epoch, reason },
        DirectoryKind::Device => {
            SecretStoreError::UntrustedDeviceDirectory { device, key_epoch, reason }
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid("terminal component is not a non-symlink directory"));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return Err(invalid("mode is not 0700"));
    }
    Ok(DirectorySnapshot { device: metadata.dev(), inode: metadata.ino(), mode })
}

#[cfg(unix)]
fn key_snapshot(
    path: &std::path::Path,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<KeySnapshot, SecretStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let directory = path.parent().ok_or(SecretStoreError::Missing { device, key_epoch })?;
            return Err(classify_missing_key(directory, device, key_epoch));
        }
        Err(source) => return Err(SecretStoreError::Io { device, key_epoch, source }),
    };
    key_snapshot_from_metadata(&metadata, device, key_epoch)
}

#[cfg(unix)]
fn key_snapshot_from_metadata(
    metadata: &fs::Metadata,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<KeySnapshot, SecretStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SecretStoreError::UntrustedKeyFile {
            device,
            key_epoch,
            reason: "terminal component is not a non-symlink regular file",
        });
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != 0o600 {
        return Err(SecretStoreError::UntrustedKeyFile {
            device,
            key_epoch,
            reason: "mode is not 0600",
        });
    }
    let links = metadata.nlink();
    if links != 1 {
        return Err(SecretStoreError::UntrustedKeyFile {
            device,
            key_epoch,
            reason: "link count is not one",
        });
    }
    let length = metadata.len();
    if length != 32 {
        return Err(SecretStoreError::WrongLength { device, key_epoch });
    }
    Ok(KeySnapshot { device: metadata.dev(), inode: metadata.ino(), mode, links, length })
}

#[cfg(unix)]
fn post_directory_snapshot(
    path: &std::path::Path,
    kind: DirectoryKind,
    object: &'static str,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<DirectorySnapshot, SecretStoreError> {
    directory_snapshot(path, kind, device, key_epoch).map_err(|_| SecretStoreError::Replaced {
        device,
        key_epoch,
        object,
    })
}

#[cfg(unix)]
fn post_key_snapshot(
    path: &std::path::Path,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<KeySnapshot, SecretStoreError> {
    key_snapshot(path, device, key_epoch).map_err(|_| SecretStoreError::Replaced {
        device,
        key_epoch,
        object: "key file",
    })
}

fn require_same_snapshot<T: Eq>(
    expected: T,
    actual: T,
    object: &'static str,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<(), SecretStoreError> {
    if expected != actual {
        return Err(SecretStoreError::Replaced { device, key_epoch, object });
    }
    Ok(())
}

fn classify_missing_key(
    device_directory: &std::path::Path,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> SecretStoreError {
    let entries = match fs::read_dir(device_directory) {
        Ok(entries) => entries,
        Err(source) => return SecretStoreError::Io { device, key_epoch, source },
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => return SecretStoreError::Io { device, key_epoch, source },
        };
        if is_canonical_epoch_key_name(&entry.file_name()) {
            return SecretStoreError::WrongEpoch { device, key_epoch };
        }
    }
    SecretStoreError::Missing { device, key_epoch }
}

fn is_canonical_epoch_key_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(epoch) = name.strip_prefix("key-").and_then(|name| name.strip_suffix(".bin")) else {
        return false;
    };
    let Ok(value) = epoch.parse::<u16>() else {
        return false;
    };
    value != 0 && epoch == value.to_string()
}

#[cfg(feature = "development-fixture")]
pub(crate) fn derive_public_development_fixture_key(
    sensor_id: &str,
    key_epoch: u16,
) -> Result<EpochKey, FixtureKeyError> {
    derive_development_fixture_key(PUBLIC_FIXTURE_SEED, sensor_id, key_epoch)
}

#[cfg(feature = "development-fixture")]
fn derive_development_fixture_key(
    fixture_seed: &[u8],
    sensor_id: &str,
    key_epoch: u16,
) -> Result<EpochKey, FixtureKeyError> {
    if key_epoch == 0 {
        return Err(FixtureKeyError::ZeroKeyEpoch);
    }
    let fixture_seed_length = u32::try_from(fixture_seed.len())
        .map_err(|_| FixtureKeyError::InputTooLong { field: "fixture seed" })?;
    let sensor_id = sensor_id.as_bytes();
    let sensor_id_length = u32::try_from(sensor_id.len())
        .map_err(|_| FixtureKeyError::InputTooLong { field: "sensor identifier" })?;
    let mut preimage = Vec::with_capacity(
        FIXTURE_KEY_DOMAIN.len() + 1 + 1 + 4 + fixture_seed.len() + 4 + sensor_id.len() + 2,
    );
    preimage.extend_from_slice(FIXTURE_KEY_DOMAIN);
    preimage.push(0);
    preimage.push(FIXTURE_KEY_DERIVATION_VERSION);
    preimage.extend_from_slice(&fixture_seed_length.to_be_bytes());
    preimage.extend_from_slice(fixture_seed);
    preimage.extend_from_slice(&sensor_id_length.to_be_bytes());
    preimage.extend_from_slice(sensor_id);
    preimage.extend_from_slice(&key_epoch.to_be_bytes());
    Ok(EpochKey(Sha256::digest(preimage).into()))
}

#[cfg(feature = "development-fixture")]
const FIXTURE_KEY_DOMAIN: &[u8] = b"whisper.development-fixture-key";
#[cfg(feature = "development-fixture")]
const FIXTURE_KEY_DERIVATION_VERSION: u8 = 1;
#[cfg(feature = "development-fixture")]
const PUBLIC_FIXTURE_SEED: &[u8] = b"whisper-v1-public-e2e-fixture-key";

#[cfg(feature = "development-fixture")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum FixtureKeyError {
    #[error("fixture key epoch must be nonzero")]
    ZeroKeyEpoch,
    #[error("{field} exceeds the fixture-key u32 length limit")]
    InputTooLong { field: &'static str },
}

#[cfg(all(test, feature = "development-fixture"))]
mod tests {
    use super::{FixtureKeyError, derive_development_fixture_key};

    const PUBLIC_FIXTURE_SEED: &[u8] = b"whisper-v1-public-e2e-fixture-key";

    #[test]
    fn development_fixture_key_matches_the_accepted_literal_vector() {
        let key = derive_development_fixture_key(PUBLIC_FIXTURE_SEED, "sensor-a", 1)
            .expect("accepted fixture inputs");

        assert_eq!(
            key.0,
            [
                0x65, 0xb0, 0xe5, 0x10, 0x1c, 0x8f, 0x9f, 0x0c, 0x9c, 0x5e, 0xe7, 0xa7, 0x7b, 0x95,
                0x99, 0x81, 0xe2, 0x2f, 0xf9, 0x5d, 0x00, 0x1c, 0x98, 0x72, 0x6f, 0x66, 0x18, 0x27,
                0xdd, 0x61, 0xde, 0x6f,
            ]
        );
    }

    #[test]
    fn development_fixture_key_binds_every_input_and_rejects_epoch_zero() {
        let canonical = derive_development_fixture_key(PUBLIC_FIXTURE_SEED, "sensor-a", 1)
            .expect("accepted fixture inputs");
        for changed in [
            derive_development_fixture_key(b"changed-public-seed", "sensor-a", 1),
            derive_development_fixture_key(PUBLIC_FIXTURE_SEED, "sensor-b", 1),
            derive_development_fixture_key(PUBLIC_FIXTURE_SEED, "sensor-a", 2),
        ] {
            assert_ne!(canonical.0, changed.expect("nonzero changed input").0);
        }
        assert!(matches!(
            derive_development_fixture_key(PUBLIC_FIXTURE_SEED, "sensor-a", 0),
            Err(FixtureKeyError::ZeroKeyEpoch)
        ));
    }
}

#[cfg(all(test, unix))]
mod loader_tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{load_epoch_key, load_epoch_key_with_after_read};
    use crate::domain::identity::{DeviceId, KeyEpoch};
    use crate::parse_config;

    static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

    fn store_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-secret-store-{}-{}",
            std::process::id(),
            NEXT_STORE.fetch_add(1, Ordering::Relaxed)
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

    fn create_directory(path: &Path) {
        fs::create_dir(path).expect("create secret-store directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("set secret-store directory mode");
    }

    fn write_key(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create key file");
        file.write_all(bytes).expect("write key file");
    }

    #[test]
    fn production_loader_reads_the_exact_configured_epoch_key() {
        let root = store_path();
        let device_directory = root.join("device-1");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&device_directory.join("key-1.bin"), &[0xa5; 32]);
        let config = config_with_secret_root(&root);

        let key = load_epoch_key(
            &config,
            DeviceId::new(1),
            KeyEpoch::try_new(1).expect("nonzero key epoch"),
        )
        .expect("valid secret store");

        assert_eq!(key.0, [0xa5; 32]);
        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_rejects_untrusted_secret_root_metadata() {
        use std::os::unix::fs::symlink;

        let root = store_path();
        let device_directory = root.join("device-1");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&device_directory.join("key-1.bin"), &[0xa5; 32]);
        let key_epoch = KeyEpoch::try_new(1).expect("nonzero key epoch");

        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("make root mode untrusted");
        assert!(matches!(
            load_epoch_key(&config_with_secret_root(&root), DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedRoot { .. })
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore root mode");

        let alias = root.with_extension("alias");
        symlink(&root, &alias).expect("create root alias");
        assert!(matches!(
            load_epoch_key(&config_with_secret_root(&alias), DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedRoot { .. })
        ));

        fs::remove_file(alias).expect("remove root alias");
        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_rejects_untrusted_device_directory_metadata() {
        use std::os::unix::fs::symlink;

        let root = store_path();
        let device_directory = root.join("device-1");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&device_directory.join("key-1.bin"), &[0xa5; 32]);
        let config = config_with_secret_root(&root);
        let key_epoch = KeyEpoch::try_new(1).expect("nonzero key epoch");

        fs::set_permissions(&device_directory, fs::Permissions::from_mode(0o755))
            .expect("make device directory mode untrusted");
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedDeviceDirectory { .. })
        ));
        fs::set_permissions(&device_directory, fs::Permissions::from_mode(0o700))
            .expect("restore device directory mode");

        let real_directory = root.join("real-device-directory");
        fs::rename(&device_directory, &real_directory).expect("move real device directory");
        symlink(&real_directory, &device_directory).expect("create device directory alias");
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedDeviceDirectory { .. })
        ));

        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_rejects_untrusted_key_file_metadata() {
        use std::os::unix::fs::symlink;

        let root = store_path();
        let device_directory = root.join("device-1");
        let key_path = device_directory.join("key-1.bin");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&key_path, &[0xa5; 32]);
        let config = config_with_secret_root(&root);
        let key_epoch = KeyEpoch::try_new(1).expect("nonzero key epoch");

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
            .expect("make key mode untrusted");
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedKeyFile { .. })
        ));
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("restore key mode");

        let hard_link = device_directory.join("key-hard-link.bin");
        fs::hard_link(&key_path, &hard_link).expect("create key hard link");
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedKeyFile { .. })
        ));
        fs::remove_file(hard_link).expect("remove key hard link");

        let real_key = device_directory.join("real-key.bin");
        fs::rename(&key_path, &real_key).expect("move real key file");
        symlink(&real_key, &key_path).expect("create key alias");
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::UntrustedKeyFile { .. })
        ));
        fs::remove_file(&key_path).expect("remove key alias");
        fs::rename(&real_key, &key_path).expect("restore key file");

        for length in [31, 33] {
            fs::write(&key_path, vec![0xa5; length]).expect("replace key bytes");
            assert!(matches!(
                load_epoch_key(&config, DeviceId::new(1), key_epoch),
                Err(super::SecretStoreError::WrongLength { .. })
            ));
        }

        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_distinguishes_missing_from_wrong_epoch() {
        let root = store_path();
        let key_epoch = KeyEpoch::try_new(1).expect("nonzero key epoch");
        assert!(matches!(
            load_epoch_key(&config_with_secret_root(&root), DeviceId::new(1), key_epoch,),
            Err(super::SecretStoreError::Missing { .. })
        ));

        let device_directory = root.join("device-1");
        create_directory(&root);
        create_directory(&device_directory);
        for name in ["key-0.bin", "key-01.bin", "key-65536.bin", "key-x.bin", "extra.bin"] {
            write_key(&device_directory.join(name), &[0xa5; 32]);
        }
        let config = config_with_secret_root(&root);
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::Missing { .. })
        ));

        write_key(&device_directory.join("key-2.bin"), &[0xa5; 32]);
        assert!(matches!(
            load_epoch_key(&config, DeviceId::new(1), key_epoch),
            Err(super::SecretStoreError::WrongEpoch { .. })
        ));

        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_rejects_key_replacement_after_read() {
        let root = store_path();
        let device_directory = root.join("device-1");
        let key_path = device_directory.join("key-1.bin");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&key_path, &[0xa5; 32]);
        let config = config_with_secret_root(&root);

        let result = load_epoch_key_with_after_read(
            &config,
            DeviceId::new(1),
            KeyEpoch::try_new(1).expect("nonzero key epoch"),
            || {
                let removed = device_directory.join("removed-key.bin");
                fs::rename(&key_path, &removed).expect("move original key");
                write_key(&key_path, &[0xa5; 32]);
            },
        );

        assert!(matches!(
            result,
            Err(super::SecretStoreError::Replaced { object: "key file", .. })
        ));
        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_rejects_root_replacement_after_read() {
        let root = store_path();
        let removed_root = root.with_extension("removed");
        let device_directory = root.join("device-1");
        let key_path = device_directory.join("key-1.bin");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&key_path, &[0xa5; 32]);
        let config = config_with_secret_root(&root);

        let result = load_epoch_key_with_after_read(
            &config,
            DeviceId::new(1),
            KeyEpoch::try_new(1).expect("nonzero key epoch"),
            || {
                fs::rename(&root, &removed_root).expect("move original secret root");
                create_directory(&root);
                let replacement_device = root.join("device-1");
                create_directory(&replacement_device);
                write_key(&replacement_device.join("key-1.bin"), &[0xa5; 32]);
            },
        );

        assert!(matches!(
            result,
            Err(super::SecretStoreError::Replaced { object: "secret root", .. })
        ));
        fs::remove_dir_all(root).expect("remove replacement secret root");
        fs::remove_dir_all(removed_root).expect("remove original secret root");
    }

    #[test]
    fn production_loader_rejects_device_directory_replacement_after_read() {
        let root = store_path();
        let device_directory = root.join("device-1");
        let removed_directory = root.join("removed-device");
        let key_path = device_directory.join("key-1.bin");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&key_path, &[0xa5; 32]);
        let config = config_with_secret_root(&root);

        let result = load_epoch_key_with_after_read(
            &config,
            DeviceId::new(1),
            KeyEpoch::try_new(1).expect("nonzero key epoch"),
            || {
                fs::rename(&device_directory, &removed_directory)
                    .expect("move original device directory");
                create_directory(&device_directory);
                write_key(&device_directory.join("key-1.bin"), &[0xa5; 32]);
            },
        );

        assert!(matches!(
            result,
            Err(super::SecretStoreError::Replaced { object: "device directory", .. })
        ));
        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }

    #[test]
    fn production_loader_diagnostics_redact_paths_and_key_material() {
        let root = store_path().with_extension("private-secret-path-marker");
        let device_directory = root.join("device-1");
        create_directory(&root);
        create_directory(&device_directory);
        write_key(&device_directory.join("key-1.bin"), &[0xa5; 32]);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("make root untrusted");

        let error = load_epoch_key(
            &config_with_secret_root(&root),
            DeviceId::new(1),
            KeyEpoch::try_new(1).expect("nonzero key epoch"),
        )
        .expect_err("untrusted root must fail");
        let diagnostic = format!("{error:?}\n{error}");

        assert!(!diagnostic.contains("private-secret-path-marker"));
        assert!(!diagnostic.contains(&"a5".repeat(32)));
        fs::remove_dir_all(root).expect("remove secret-store fixture");
    }
}
