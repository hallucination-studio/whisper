//! Validated secret key material for native-frame authentication epochs.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

/// One validated AES-256 key selected by a native-frame key epoch.
pub(crate) struct EpochKey([u8; 32]);

impl EpochKey {
    /// Borrows the exact key bytes for an authentication operation.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for EpochKey {
    type Error = EpochKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes =
            <[u8; 32]>::try_from(bytes).map_err(|_| EpochKeyError { actual: bytes.len() })?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochKey([REDACTED])")
    }
}

/// Invalid native-frame epoch key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("native-frame epoch key must be exactly 32 bytes, got {actual}")]
pub(crate) struct EpochKeyError {
    /// Supplied key length in bytes.
    pub(crate) actual: usize,
}

/// Failures while selecting and reading one filesystem-backed epoch key.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SecretStoreError {
    #[error("key epoch must be non-zero for device {device}")]
    ZeroKeyEpoch { device: u64 },
    #[error("key material is missing for device {device} and key epoch {key_epoch}")]
    Missing { device: u64, key_epoch: u16 },
    #[error("a different key epoch exists for device {device}; requested epoch {key_epoch}")]
    WrongEpoch { device: u64, key_epoch: u16 },
    #[error("secret root is untrusted for device {device} and key epoch {key_epoch}: {reason}")]
    UntrustedRoot { device: u64, key_epoch: u16, reason: &'static str },
    #[error(
        "device key directory is untrusted for device {device} and key epoch {key_epoch}: {reason}"
    )]
    UntrustedDeviceDirectory { device: u64, key_epoch: u16, reason: &'static str },
    #[error("key file is untrusted for device {device} and key epoch {key_epoch}: {reason}")]
    UntrustedKeyFile { device: u64, key_epoch: u16, reason: &'static str },
    #[error("key material for device {device} and key epoch {key_epoch} is not exactly 32 bytes")]
    WrongLength { device: u64, key_epoch: u16 },
    #[error(
        "key material for device {device} and key epoch {key_epoch} could not be read: {source}"
    )]
    Io {
        device: u64,
        key_epoch: u16,
        #[source]
        source: io::Error,
    },
    #[error(
        "{object} changed while loading key material for device {device} and key epoch {key_epoch}"
    )]
    Replaced { device: u64, key_epoch: u16, object: &'static str },
}

/// Loads the exact key selected by device and key epoch from a trusted Unix directory tree.
pub(crate) fn load_epoch_key(
    root: &Path,
    device: u64,
    key_epoch: u16,
) -> Result<EpochKey, SecretStoreError> {
    if key_epoch == 0 {
        return Err(SecretStoreError::ZeroKeyEpoch { device });
    }
    load_epoch_key_with_after_read(root, device, key_epoch, || {})
}

#[cfg(unix)]
pub(crate) fn load_epoch_key_with_after_read(
    root_path: &Path,
    device: u64,
    key_epoch: u16,
    after_read: impl FnOnce(),
) -> Result<EpochKey, SecretStoreError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

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

    Ok(EpochKey(bytes))
}

#[cfg(not(unix))]
fn load_epoch_key_with_after_read(
    _root_path: &Path,
    device: u64,
    key_epoch: u16,
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
    path: &Path,
    kind: DirectoryKind,
    device: u64,
    key_epoch: u16,
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
    device: u64,
    key_epoch: u16,
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
fn key_snapshot(path: &Path, device: u64, key_epoch: u16) -> Result<KeySnapshot, SecretStoreError> {
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
    device: u64,
    key_epoch: u16,
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
    path: &Path,
    kind: DirectoryKind,
    object: &'static str,
    device: u64,
    key_epoch: u16,
) -> Result<DirectorySnapshot, SecretStoreError> {
    directory_snapshot(path, kind, device, key_epoch).map_err(|_| SecretStoreError::Replaced {
        device,
        key_epoch,
        object,
    })
}

#[cfg(unix)]
fn post_key_snapshot(
    path: &Path,
    device: u64,
    key_epoch: u16,
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
    device: u64,
    key_epoch: u16,
) -> Result<(), SecretStoreError> {
    if expected != actual {
        return Err(SecretStoreError::Replaced { device, key_epoch, object });
    }
    Ok(())
}

fn classify_missing_key(device_directory: &Path, device: u64, key_epoch: u16) -> SecretStoreError {
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
