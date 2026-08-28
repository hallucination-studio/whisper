//! Application-owned lifecycle coordination for managed host persistence.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "external lifecycle wiring is implemented in a later work package")
)]

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::Config;
use crate::config::RouteConfig;
use crate::database::{Database, DatabaseError, EpochHandle, ReplayWindowIdentity};
use crate::domain::identity::{DeploymentId, DeviceId, KeyEpoch};
use sha2::{Digest, Sha256};

const REPLAY_WINDOW_IDENTITY_DOMAIN: &[u8] = b"whisper.replay-window.identity";
const REPLAY_WINDOW_IDENTITY_PREIMAGE_VERSION: u8 = 1;
const NATIVE_FRAME_WIRE_VERSION: u8 = 1;
// Fixed by the persistence-v1 managed-database path contract. Changing this splits
// cross-process sidecar identity and requires a contract change.
const MANAGED_DATABASE_LOCK_SUFFIX: &str = ".whisper.lock";

#[derive(Clone, Copy, Debug)]
enum ManagedTarget {
    Existing,
    Provisioning,
}

#[derive(Debug)]
struct ManagedDatabaseLock {
    database_path: PathBuf,
    _sidecar: File,
}

impl ManagedDatabaseLock {
    fn acquire(config: &Config, target: ManagedTarget) -> Result<Self, HostError> {
        let configured_path = config.session().database_path();
        let database_path = match target {
            ManagedTarget::Existing => canonical_existing_database(configured_path)?,
            ManagedTarget::Provisioning => canonical_provisioning_database(configured_path)?,
        };
        let lock_path = managed_lock_path(&database_path)?;
        let sidecar = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| HostError::ManagedDatabaseLockIo {
                path: lock_path.clone(),
                source,
            })?;
        sidecar.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => {
                HostError::ManagedDatabaseLockConflict { path: lock_path.clone() }
            }
            fs::TryLockError::Error(source) => {
                HostError::ManagedDatabaseLockIo { path: lock_path.clone(), source }
            }
        })?;

        let checked_path = match target {
            ManagedTarget::Existing => canonical_existing_database(configured_path)?,
            ManagedTarget::Provisioning => canonical_provisioning_database(configured_path)?,
        };
        if checked_path != database_path {
            return Err(HostError::ManagedDatabasePathInvalid {
                path: configured_path.to_path_buf(),
            });
        }

        Ok(Self { database_path, _sidecar: sidecar })
    }

    fn database_path(&self) -> &Path {
        &self.database_path
    }
}

fn canonical_existing_database(path: &Path) -> Result<PathBuf, HostError> {
    let canonical = fs::canonicalize(path)
        .map_err(|source| HostError::ManagedDatabasePathIo { path: path.to_path_buf(), source })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|source| HostError::ManagedDatabasePathIo { path: canonical.clone(), source })?;
    validate_existing_database(&canonical, &metadata)?;
    Ok(canonical)
}

fn canonical_provisioning_database(path: &Path) -> Result<PathBuf, HostError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| HostError::ManagedDatabasePathInvalid { path: path.to_path_buf() })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).map_err(|source| {
        HostError::ManagedDatabasePathIo { path: parent.to_path_buf(), source }
    })?;
    let parent_metadata = fs::metadata(&canonical_parent).map_err(|source| {
        HostError::ManagedDatabasePathIo { path: canonical_parent.clone(), source }
    })?;
    if !parent_metadata.is_dir() {
        return Err(HostError::ManagedDatabasePathInvalid { path: canonical_parent });
    }

    let database_path = canonical_parent.join(file_name);
    match fs::symlink_metadata(&database_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(HostError::ManagedDatabaseSymlink { path: database_path })
        }
        Ok(_) => Err(HostError::ManagedDatabaseAlreadyExists { path: database_path }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(database_path),
        Err(source) => Err(HostError::ManagedDatabasePathIo { path: database_path, source }),
    }
}

fn validate_existing_database(path: &Path, metadata: &Metadata) -> Result<(), HostError> {
    if !metadata.is_file() {
        return Err(HostError::ManagedDatabasePathInvalid { path: path.to_path_buf() });
    }
    let links = metadata_link_count(metadata);
    if links > 1 {
        return Err(HostError::ManagedDatabaseHardLinked { path: path.to_path_buf(), links });
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_link_count(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;

    metadata.nlink()
}

#[cfg(windows)]
fn metadata_link_count(metadata: &Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;

    metadata.number_of_links().map_or(1, u64::from)
}

#[cfg(not(any(unix, windows)))]
fn metadata_link_count(_metadata: &Metadata) -> u64 {
    1
}

fn managed_lock_path(database_path: &Path) -> Result<PathBuf, HostError> {
    let file_name = database_path.file_name().ok_or_else(|| {
        HostError::ManagedDatabasePathInvalid { path: database_path.to_path_buf() }
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(MANAGED_DATABASE_LOCK_SUFFIX);
    Ok(database_path.with_file_name(lock_name))
}

struct EpochKey([u8; 32]);

impl fmt::Debug for EpochKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochKey([REDACTED])")
    }
}

fn checked_deployment_length(length: usize) -> Result<u32, HostError> {
    u32::try_from(length).map_err(|_| HostError::DeploymentIdTooLong { length })
}

fn replay_window_identity_preimage(
    deployment: &DeploymentId,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<Vec<u8>, HostError> {
    let deployment = deployment.as_str().as_bytes();
    let deployment_len = checked_deployment_length(deployment.len())?;
    let mut preimage = Vec::with_capacity(
        REPLAY_WINDOW_IDENTITY_DOMAIN.len() + 1 + 1 + 1 + 4 + deployment.len() + 8 + 2 + 32,
    );
    preimage.extend_from_slice(REPLAY_WINDOW_IDENTITY_DOMAIN);
    preimage.push(0);
    preimage.push(REPLAY_WINDOW_IDENTITY_PREIMAGE_VERSION);
    preimage.push(NATIVE_FRAME_WIRE_VERSION);
    preimage.extend_from_slice(&deployment_len.to_be_bytes());
    preimage.extend_from_slice(deployment);
    preimage.extend_from_slice(&device.get().to_be_bytes());
    preimage.extend_from_slice(&key_epoch.get().to_be_bytes());
    preimage.extend_from_slice(&epoch_key.0);
    Ok(preimage)
}

fn replay_window_identity(
    deployment: &DeploymentId,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<ReplayWindowIdentity, HostError> {
    Ok(ReplayWindowIdentity::new(
        Sha256::digest(replay_window_identity_preimage(deployment, device, key_epoch, epoch_key)?)
            .into(),
    ))
}

fn replay_admission_config(
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<(&DeploymentId, u16), HostError> {
    let matches = config
        .registry()
        .routes()
        .iter()
        .filter(|route| route.device_id() == device && route.key_epoch() == key_epoch);
    let route = select_replay_admission_route(matches, device, key_epoch)?;
    Ok((config.deployment().id(), route.admission_limits().replay_window_packets()))
}

fn select_replay_admission_route<'a>(
    mut matches: impl Iterator<Item = &'a RouteConfig>,
    device: DeviceId,
    key_epoch: KeyEpoch,
) -> Result<&'a RouteConfig, HostError> {
    let route = matches.next().ok_or(HostError::MissingAdmissionRoute { device, key_epoch })?;
    if matches.next().is_some() {
        return Err(HostError::AmbiguousAdmissionRoute { device, key_epoch });
    }
    Ok(route)
}

fn provision_admission_epoch(
    database: &mut Database,
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<(), HostError> {
    let (deployment, replay_window_size) = replay_admission_config(config, device, key_epoch)?;
    let identity = replay_window_identity(deployment, device, key_epoch, epoch_key)?;
    database.provision_epoch(device, key_epoch, &identity, replay_window_size)?;
    Ok(())
}

fn validate_capture_epoch(
    database: &Database,
    config: &Config,
    device: DeviceId,
    key_epoch: KeyEpoch,
    epoch_key: &EpochKey,
) -> Result<EpochHandle, HostError> {
    let (deployment, replay_window_size) = replay_admission_config(config, device, key_epoch)?;
    let identity = replay_window_identity(deployment, device, key_epoch, epoch_key)?;
    Ok(database.validate_epoch(device, key_epoch, identity, replay_window_size)?)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HostError {
    #[error("deployment ID is {length} bytes, exceeding the replay identity u32 length limit")]
    DeploymentIdTooLong { length: usize },
    #[error("no replay-admission route for device {device} and key epoch {key_epoch}")]
    MissingAdmissionRoute { device: DeviceId, key_epoch: KeyEpoch },
    #[error("multiple replay-admission routes for device {device} and key epoch {key_epoch}")]
    AmbiguousAdmissionRoute { device: DeviceId, key_epoch: KeyEpoch },
    #[error("managed database path {path} could not be resolved or inspected: {source}")]
    ManagedDatabasePathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("managed database path {path} is not a supported database target")]
    ManagedDatabasePathInvalid { path: PathBuf },
    #[error("managed database path {path} has {links} hard links")]
    ManagedDatabaseHardLinked { path: PathBuf, links: u64 },
    #[error("managed database provisioning target {path} already exists")]
    ManagedDatabaseAlreadyExists { path: PathBuf },
    #[error("managed database provisioning target {path} is a symlink")]
    ManagedDatabaseSymlink { path: PathBuf },
    #[error("managed database lock {path} is already held")]
    ManagedDatabaseLockConflict { path: PathBuf },
    #[error("managed database lock {path} could not be opened or acquired: {source}")]
    ManagedDatabaseLockIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

pub(crate) fn open_capture_database(config: &Config) -> Result<Database, HostError> {
    Ok(Database::open_writer_existing(config.session().database_path())?)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::Connection;

    use super::{
        EpochKey, HostError, ManagedDatabaseLock, ManagedTarget, ReplayWindowIdentity,
        checked_deployment_length, open_capture_database, provision_admission_epoch,
        replay_admission_config, replay_window_identity, replay_window_identity_preimage,
        select_replay_admission_route, validate_capture_epoch,
    };
    use crate::database::{Database, DatabaseError};
    use crate::domain::identity::{DeploymentId, DeviceId, KeyEpoch};
    use crate::{Config, parse_config};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn database_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-application-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config_with_database_path(path: &Path) -> Config {
        let source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        parse_config(&source.replace(
            "database_path = \"./data/whisper.sqlite3\"",
            &format!("database_path = \"{}\"", path.display()),
        ))
        .expect("config with temporary database path")
    }

    #[cfg(unix)]
    fn relative_to_current(path: &Path) -> PathBuf {
        let current = std::env::current_dir().expect("current directory");
        let common = current
            .components()
            .zip(path.components())
            .take_while(|(left, right)| left == right)
            .count();
        let mut relative = PathBuf::new();
        relative.extend(current.components().skip(common).map(|_| ".."));
        relative.extend(path.components().skip(common));
        relative
    }

    #[cfg(unix)]
    #[test]
    fn existing_database_spellings_share_one_canonical_lock_identity() {
        use std::os::unix::fs::symlink;

        let root = database_path().with_extension("paths");
        let real_directory = root.join("real");
        let database = real_directory.join("whisper.sqlite3");
        std::fs::create_dir_all(&real_directory).expect("create real directory");
        std::fs::write(&database, b"database identity").expect("create database target");

        let directory_alias = root.join("directory-alias");
        symlink(&real_directory, &directory_alias).expect("create directory symlink");
        let final_alias = root.join("database-alias");
        symlink(&database, &final_alias).expect("create final symlink");
        let spellings = [
            real_directory.join("nested").join("..").join("whisper.sqlite3"),
            directory_alias.join("whisper.sqlite3"),
            final_alias,
        ];
        std::fs::create_dir(real_directory.join("nested")).expect("create nested directory");

        let relative = relative_to_current(&database);
        let owner = ManagedDatabaseLock::acquire(
            &config_with_database_path(&relative),
            ManagedTarget::Existing,
        )
        .expect("acquire canonical owner");
        assert_eq!(
            owner.database_path(),
            std::fs::canonicalize(&database).expect("canonical database")
        );

        for spelling in spellings {
            assert!(matches!(
                ManagedDatabaseLock::acquire(
                    &config_with_database_path(&spelling),
                    ManagedTarget::Existing,
                ),
                Err(HostError::ManagedDatabaseLockConflict { .. })
            ));
        }

        drop(owner);
        std::fs::remove_dir_all(root).expect("cleanup path fixtures");
    }

    #[cfg(unix)]
    #[test]
    fn provisioning_requires_an_existing_parent_and_absent_non_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = database_path().with_extension("provisioning");
        std::fs::create_dir(&root).expect("create provisioning parent");
        let canonical_root = std::fs::canonicalize(&root).expect("canonical parent");

        let available = root.join("new.sqlite3");
        let lock = ManagedDatabaseLock::acquire(
            &config_with_database_path(&available),
            ManagedTarget::Provisioning,
        )
        .expect("lock absent provisioning target");
        assert_eq!(lock.database_path(), canonical_root.join("new.sqlite3"));
        assert!(!available.exists());
        drop(lock);

        let existing = root.join("existing.sqlite3");
        std::fs::write(&existing, b"existing").expect("create existing target");
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&existing),
                ManagedTarget::Provisioning,
            ),
            Err(HostError::ManagedDatabaseAlreadyExists { .. })
        ));

        let final_symlink = root.join("final-symlink.sqlite3");
        symlink(&existing, &final_symlink).expect("create final symlink");
        let dangling_symlink = root.join("dangling-symlink.sqlite3");
        symlink(root.join("absent.sqlite3"), &dangling_symlink).expect("create dangling symlink");
        for path in [&final_symlink, &dangling_symlink] {
            assert!(matches!(
                ManagedDatabaseLock::acquire(
                    &config_with_database_path(path),
                    ManagedTarget::Provisioning,
                ),
                Err(HostError::ManagedDatabaseSymlink { .. })
            ));
        }

        let missing_parent = root.join("missing").join("database.sqlite3");
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&missing_parent),
                ManagedTarget::Provisioning,
            ),
            Err(HostError::ManagedDatabasePathIo { .. })
        ));

        std::fs::remove_dir_all(root).expect("cleanup provisioning fixtures");
    }

    #[test]
    fn managed_lock_sidecar_names_are_injective() {
        let root = database_path().with_extension("injective");
        std::fs::create_dir(&root).expect("create injective fixture directory");
        let first_path = root.join("foo");
        let second_path = root.join("foo.whisper.lock");
        std::fs::write(&first_path, b"first database").expect("create first database");
        std::fs::write(&second_path, b"second database").expect("create second database");

        let first = ManagedDatabaseLock::acquire(
            &config_with_database_path(&first_path),
            ManagedTarget::Existing,
        )
        .expect("lock first database");
        let second = ManagedDatabaseLock::acquire(
            &config_with_database_path(&second_path),
            ManagedTarget::Existing,
        )
        .expect("lock suffix-named database independently");
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&first_path),
                ManagedTarget::Existing,
            ),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));
        assert!(matches!(
            ManagedDatabaseLock::acquire(
                &config_with_database_path(&second_path),
                ManagedTarget::Existing,
            ),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));

        drop((first, second));
        std::fs::remove_dir_all(root).expect("cleanup injective fixtures");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn existing_database_hard_links_are_rejected_explicitly() {
        let root = database_path().with_extension("hard-links");
        std::fs::create_dir(&root).expect("create hard-link fixture directory");
        let database = root.join("database.sqlite3");
        let alias = root.join("alias.sqlite3");
        std::fs::write(&database, b"database").expect("create database");
        std::fs::hard_link(&database, &alias).expect("create hard link");

        for path in [&database, &alias] {
            assert!(matches!(
                ManagedDatabaseLock::acquire(
                    &config_with_database_path(path),
                    ManagedTarget::Existing,
                ),
                Err(HostError::ManagedDatabaseHardLinked { links: 2, .. })
            ));
        }

        std::fs::remove_dir_all(root).expect("cleanup hard-link fixtures");
    }

    #[test]
    fn stale_sidecar_content_is_preserved_and_dropped_locks_are_reusable() {
        let root = database_path().with_extension("stale-sidecar");
        std::fs::create_dir(&root).expect("create stale-sidecar fixture directory");
        let database = root.join("database.sqlite3");
        let sidecar = root.join("database.sqlite3.whisper.lock");
        let stale = b"stale sidecar content must survive";
        std::fs::write(&database, b"database").expect("create database");
        std::fs::write(&sidecar, stale).expect("create stale sidecar");
        let config = config_with_database_path(&database);

        let first = ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
            .expect("lock through stale sidecar");
        assert_eq!(std::fs::read(&sidecar).expect("read held sidecar"), stale);
        assert!(matches!(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));
        drop(first);

        drop(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
                .expect("reuse dropped lock"),
        );
        assert_eq!(std::fs::read(&sidecar).expect("read reused sidecar"), stale);
        assert!(sidecar.exists());

        std::fs::remove_dir_all(root).expect("cleanup stale-sidecar fixtures");
    }

    #[cfg(unix)]
    #[test]
    fn managed_database_permission_failures_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let root = database_path().with_extension("permissions");
        let blocked = root.join("blocked");
        std::fs::create_dir_all(&blocked).expect("create permission fixture directory");
        let inaccessible_database = blocked.join("database.sqlite3");
        std::fs::write(&inaccessible_database, b"database").expect("create inaccessible database");

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
            .expect("remove path permissions");
        let path_error = ManagedDatabaseLock::acquire(
            &config_with_database_path(&inaccessible_database),
            ManagedTarget::Existing,
        )
        .expect_err("inaccessible database path must fail");
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))
            .expect("restore path permissions");
        assert!(matches!(
            path_error,
            HostError::ManagedDatabasePathIo { source, .. }
                if source.kind() == std::io::ErrorKind::PermissionDenied
        ));

        let unwritable_database = root.join("unwritable.sqlite3");
        std::fs::write(&unwritable_database, b"database").expect("create unwritable database");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500))
            .expect("remove directory write permission");
        let lock_error = ManagedDatabaseLock::acquire(
            &config_with_database_path(&unwritable_database),
            ManagedTarget::Existing,
        )
        .expect_err("unwritable sidecar directory must fail");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("restore directory permissions");
        assert!(matches!(
            lock_error,
            HostError::ManagedDatabaseLockIo { source, .. }
                if source.kind() == std::io::ErrorKind::PermissionDenied
        ));

        std::fs::remove_dir_all(root).expect("cleanup permission fixtures");
    }

    #[test]
    fn managed_database_lock_conflicts_across_processes_and_reuses_after_release() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};

        let root = database_path().with_extension("cross-process");
        std::fs::create_dir(&root).expect("create cross-process fixture directory");
        let database = root.join("database.sqlite3");
        std::fs::write(&database, b"database").expect("create database");
        let config = config_with_database_path(&database);

        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--ignored",
                "--exact",
                "application::tests::managed_database_lock_child_process",
                "--nocapture",
            ])
            .env("WHISPER_MANAGED_LOCK_CHILD_PATH", &database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn lock child");
        let mut child_stdout =
            BufReader::new(child.stdout.take().expect("capture lock child stdout"));
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = child_stdout.read_line(&mut line).expect("read lock child output");
            assert_ne!(bytes, 0, "lock child exited before acquiring the lock");
            if line.contains("WHISPER_MANAGED_LOCK_ACQUIRED") {
                break;
            }
        }

        assert!(matches!(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing),
            Err(HostError::ManagedDatabaseLockConflict { .. })
        ));
        child
            .stdin
            .as_mut()
            .expect("lock child stdin")
            .write_all(b"release\n")
            .expect("release lock child");
        assert!(child.wait().expect("wait for lock child").success());

        drop(
            ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
                .expect("reuse child lock after release"),
        );
        std::fs::remove_dir_all(root).expect("cleanup cross-process fixtures");
    }

    #[test]
    #[ignore = "invoked as an exact child process by the cross-process lock test"]
    fn managed_database_lock_child_process() {
        use std::io::{Read, Write};

        let Some(path) = std::env::var_os("WHISPER_MANAGED_LOCK_CHILD_PATH") else {
            return;
        };
        let config = config_with_database_path(Path::new(&path));
        let lock = ManagedDatabaseLock::acquire(&config, ManagedTarget::Existing)
            .expect("child acquires managed database lock");
        println!("WHISPER_MANAGED_LOCK_ACQUIRED");
        std::io::stdout().flush().expect("flush lock child readiness");
        let mut release = [0_u8; 1];
        std::io::stdin().read_exact(&mut release).expect("wait for parent release signal");
        drop(lock);
    }

    fn vector_value(name: &str) -> &'static str {
        include_str!("../tests/fixtures/replay-window-identity/vector-v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix(name).and_then(|value| value.strip_prefix('=')))
            .expect("fixture field")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    fn epoch_key(name: &str) -> EpochKey {
        EpochKey(decode_hex(vector_value(name)).try_into().expect("32-byte epoch key"))
    }

    fn fixture_identity(name: &str) -> ReplayWindowIdentity {
        ReplayWindowIdentity::new(
            decode_hex(vector_value(name)).try_into().expect("32-byte replay identity"),
        )
    }

    fn config_identity(
        config: &Config,
        device: DeviceId,
        key_epoch: KeyEpoch,
        epoch_key: &EpochKey,
    ) -> ReplayWindowIdentity {
        let (deployment, _) =
            replay_admission_config(config, device, key_epoch).expect("matching route");
        replay_window_identity(deployment, device, key_epoch, epoch_key).expect("identity")
    }

    fn replace_first_setting(source: &str, name: &str, from: &str, to: &str) -> String {
        let from = format!("{name} = {from}");
        let to = format!("{name} = {to}");
        assert!(source.contains(&from), "missing fixture setting: {from}");
        source.replacen(&from, &to, 1)
    }

    #[test]
    fn epoch_key_debug_redacts_secret_bytes() {
        let debug = format!("{:?}", EpochKey([0xa5; 32]));

        assert_eq!(debug, "EpochKey([REDACTED])");
        assert!(!debug.contains("a5"));
    }

    #[test]
    fn replay_window_identity_rejects_deployment_lengths_above_u32() {
        let length = u32::MAX as usize + 1;

        assert!(matches!(
            checked_deployment_length(length),
            Err(HostError::DeploymentIdTooLong { length: actual }) if actual == length
        ));
    }

    #[test]
    fn replay_window_identity_matches_the_canonical_v1_vector() {
        let deployment = DeploymentId::new(vector_value("deployment_id")).expect("deployment");
        let device = DeviceId::new(vector_value("device_id").parse().expect("device"));
        let key_epoch = KeyEpoch::try_new(vector_value("key_epoch").parse().expect("key epoch"))
            .expect("nonzero key epoch");
        let epoch_key = epoch_key("epoch_key_hex");
        let config_source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        let config = parse_config(config_source).expect("valid config");
        let (configured_deployment, configured_window) =
            replay_admission_config(&config, device, key_epoch).expect("fixture route");
        let raw: toml::Value = toml::from_str(config_source).expect("fixture TOML");
        let route = &raw["routes"].as_array().expect("routes")[0];

        assert_eq!(configured_deployment, &deployment);
        assert_eq!(configured_window.to_string(), vector_value("replay_window_packets"));
        assert_eq!(route["peer"].as_str().expect("peer"), vector_value("peer"));
        assert_eq!(route["link"].as_str().expect("link"), vector_value("link_id"));
        assert_eq!(
            route["peak_packets_per_second"].as_integer().expect("packet rate").to_string(),
            vector_value("peak_packets_per_second")
        );
        assert_eq!(
            route["maximum_authenticated_bytes_per_second"]
                .as_integer()
                .expect("byte rate")
                .to_string(),
            vector_value("maximum_authenticated_bytes_per_second")
        );
        assert_eq!(
            route["maximum_valid_datagram_bytes"].as_integer().expect("datagram limit").to_string(),
            vector_value("maximum_valid_datagram_bytes")
        );

        assert_eq!(
            replay_window_identity_preimage(&deployment, device, key_epoch, &epoch_key)
                .expect("preimage"),
            decode_hex(vector_value("preimage_hex"))
        );
        assert_eq!(
            replay_window_identity(&deployment, device, key_epoch, &epoch_key).expect("identity"),
            fixture_identity("identity_sha256")
        );
    }

    #[test]
    fn included_epoch_key_mutation_changes_the_replay_window_identity() {
        let deployment = DeploymentId::new(vector_value("deployment_id")).expect("deployment");
        let device = DeviceId::new(vector_value("device_id").parse().expect("device"));
        let key_epoch = KeyEpoch::try_new(vector_value("key_epoch").parse().expect("key epoch"))
            .expect("nonzero key epoch");
        let canonical =
            replay_window_identity(&deployment, device, key_epoch, &epoch_key("epoch_key_hex"))
                .expect("canonical identity");
        let mutated = replay_window_identity(
            &deployment,
            device,
            key_epoch,
            &epoch_key("included_epoch_key_hex"),
        )
        .expect("mutated identity");

        assert_eq!(canonical, fixture_identity("identity_sha256"));
        assert_eq!(mutated, fixture_identity("included_identity_sha256"));
        assert_ne!(mutated, canonical);
    }

    #[test]
    fn excluded_route_mutations_do_not_change_the_replay_window_identity() {
        let source = include_str!("../tests/fixtures/config/valid-two-esp32.toml");
        let device = DeviceId::new(vector_value("device_id").parse().expect("device"));
        let key_epoch = KeyEpoch::try_new(vector_value("key_epoch").parse().expect("key epoch"))
            .expect("nonzero key epoch");
        let epoch_key = epoch_key("epoch_key_hex");
        let canonical = fixture_identity("identity_sha256");
        let peer_source = source.replace(vector_value("peer"), vector_value("mutated_peer"));
        let link_source = source.replace(vector_value("link_id"), vector_value("mutated_link_id"));
        let numeric_mutations = [
            ("replay_window_packets", "replay_window_packets", "mutated_replay_window_packets"),
            (
                "peak_packets_per_second",
                "peak_packets_per_second",
                "mutated_peak_packets_per_second",
            ),
            (
                "maximum_authenticated_bytes_per_second",
                "maximum_authenticated_bytes_per_second",
                "mutated_maximum_authenticated_bytes_per_second",
            ),
            (
                "maximum_valid_datagram_bytes",
                "maximum_valid_datagram_bytes",
                "mutated_maximum_valid_datagram_bytes",
            ),
        ];
        let mut mutated_sources = vec![peer_source, link_source];
        mutated_sources.extend(numeric_mutations.map(|(setting, from, to)| {
            replace_first_setting(source, setting, vector_value(from), vector_value(to))
        }));

        for mutated_source in mutated_sources {
            let config = parse_config(&mutated_source).expect("valid excluded-field mutation");
            assert_eq!(config_identity(&config, device, key_epoch, &epoch_key), canonical);
        }
    }

    #[test]
    fn application_derives_identity_for_provisioning_and_capture_validation() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let config = config_with_database_path(&path);
        let device = DeviceId::new(1);
        let key_epoch = KeyEpoch::try_new(1).expect("key epoch");
        let epoch_key = EpochKey([0x11; 32]);

        provision_admission_epoch(&mut database, &config, device, key_epoch, &epoch_key)
            .expect("provision");
        validate_capture_epoch(&database, &config, device, key_epoch, &epoch_key)
            .expect("capture validation");
        assert!(
            validate_capture_epoch(&database, &config, device, key_epoch, &EpochKey([0x12; 32]),)
                .is_err()
        );
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn admission_helpers_reject_a_missing_device_epoch_route() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let config = config_with_database_path(&path);
        let device = DeviceId::new(99);
        let key_epoch = KeyEpoch::try_new(1).expect("key epoch");

        assert!(matches!(
            provision_admission_epoch(
                &mut database,
                &config,
                device,
                key_epoch,
                &EpochKey([0x11; 32]),
            ),
            Err(HostError::MissingAdmissionRoute {
                device: actual_device,
                key_epoch: actual_epoch,
            }) if actual_device == device && actual_epoch == key_epoch
        ));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn admission_helpers_reject_ambiguous_device_epoch_routes() {
        let config = parse_config(include_str!("../tests/fixtures/config/valid-two-esp32.toml"))
            .expect("valid config");
        let device = DeviceId::new(1);
        let key_epoch = KeyEpoch::try_new(1).expect("key epoch");
        let route = &config.registry().routes()[0];

        assert!(matches!(
            select_replay_admission_route(
                [route, route].into_iter(),
                device,
                key_epoch,
            ),
            Err(HostError::AmbiguousAdmissionRoute {
                device: actual_device,
                key_epoch: actual_epoch,
            }) if actual_device == device && actual_epoch == key_epoch
        ));
    }

    #[test]
    fn capture_open_missing_store_is_non_creating() {
        let path = database_path();
        drop(Connection::open(&path).expect("create setup SQLite database"));
        std::fs::remove_file(&path).expect("remove setup SQLite database");
        let config = config_with_database_path(&path);

        assert!(matches!(
            open_capture_database(&config),
            Err(HostError::Database(DatabaseError::Missing))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn capture_open_rejects_non_sqlite_bytes_without_mutation_or_sidecars() {
        let path = database_path();
        let original = b"whisper-not-a-sqlite-database";
        std::fs::write(&path, original).expect("write non-SQLite fixture");
        let config = config_with_database_path(&path);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));

        assert!(matches!(
            open_capture_database(&config),
            Err(HostError::Database(DatabaseError::Sql(_)))
        ));
        assert_eq!(std::fs::read(&path).expect("read fixture after failed open"), original);
        assert!(!wal.exists());
        assert!(!shm.exists());

        std::fs::remove_file(path).expect("cleanup");
    }
}
