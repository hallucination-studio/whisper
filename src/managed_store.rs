//! Managed-root trust, cooperative leasing, and atomic Store publication.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::hex;

// Host persistence v1 fixes this root-relative name as the sole cooperative
// lifecycle lease. Changing it splits writers into independent lock domains.
const LEASE_NAME: &str = ".whisper.lease";
// Host persistence v1 requires an exact owner-only mode for Managed roots.
const ROOT_MODE: u32 = 0o700;
// Host persistence v1 requires an exact owner read/write mode for every file.
const FILE_MODE: u32 = 0o600;
// A normal managed file has exactly one directory entry. Any extra link means
// the object no longer has the lifecycle-owned identity required by the spec.
const SINGLE_LINK_COUNT: u64 = 1;
// Atomic no-replace publication temporarily gives the stage and final names to
// the same inode, so exactly two links must exist until the stage is unlinked.
const PUBLICATION_LINK_COUNT: u64 = 2;
// Private staging names use 128 operating-system-random bits. Changing this
// width changes their collision resistance and filename grammar.
const STAGE_NAME_RANDOM_BYTES: usize = 16;
// Sixteen create-new retries bound collision handling while providing ample
// headroom for names derived from 128 operating-system-random bits.
const MAX_STAGE_NAME_ATTEMPTS: usize = 16;
// Store, Session, and staging identities require operating-system randomness;
// replacement sources must preserve the same CSPRNG and availability contract.
const RANDOM_SOURCE: &str = "/dev/urandom";

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManagedStoreError {
    #[error("the Managed store root is not trusted")]
    RootTrust,
    #[error("the Managed store lease is not trusted")]
    LeaseTrust,
    #[error("the Managed store lease is already held")]
    LeaseConflict,
    #[error("the configured Store target already exists")]
    AlreadyExists,
    #[error("the configured Store target is not a supported final component")]
    InvalidTarget,
    #[error("a Managed store object is not trusted")]
    ObjectTrust,
    #[error("could not allocate a unique private staging name")]
    StageNameExhausted,
    #[error("Managed store I/O failed for {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(path: &Path, source: io::Error) -> ManagedStoreError {
    ManagedStoreError::Io { path: path.to_owned(), source }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct ManagedRoot {
    root_path: PathBuf,
    final_path: PathBuf,
    root: File,
    lease: File,
}

impl Drop for ManagedRoot {
    fn drop(&mut self) {
        let _ = self.lease.unlock();
    }
}

#[derive(Clone, Copy)]
enum ManagedTarget {
    Absent,
    Existing,
}

impl ManagedRoot {
    pub(crate) fn acquire_for_initialization(
        database_path: &Path,
    ) -> Result<Self, ManagedStoreError> {
        Self::acquire(database_path, ManagedTarget::Absent)
    }

    pub(crate) fn acquire_existing(database_path: &Path) -> Result<Self, ManagedStoreError> {
        Self::acquire(database_path, ManagedTarget::Existing)
    }

    fn acquire(database_path: &Path, target: ManagedTarget) -> Result<Self, ManagedStoreError> {
        let file_name = database_path.file_name().ok_or(ManagedStoreError::InvalidTarget)?;
        if file_name == LEASE_NAME {
            return Err(ManagedStoreError::InvalidTarget);
        }
        let configured_root = database_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let root_before = fs::symlink_metadata(configured_root)
            .map_err(|source| io_error(configured_root, source))?;
        validate_root(&root_before)?;
        let root_path = fs::canonicalize(configured_root)
            .map_err(|source| io_error(configured_root, source))?;
        let canonical_metadata =
            fs::symlink_metadata(&root_path).map_err(|source| io_error(&root_path, source))?;
        validate_root(&canonical_metadata)?;
        require_same_identity(&root_before, &canonical_metadata, ManagedStoreError::RootTrust)?;

        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&root_path)
            .map_err(|source| io_error(&root_path, source))?;
        let opened_root = root.metadata().map_err(|source| io_error(&root_path, source))?;
        validate_root(&opened_root)?;
        require_same_identity(&canonical_metadata, &opened_root, ManagedStoreError::RootTrust)?;

        let final_path = root_path.join(file_name);
        if matches!(target, ManagedTarget::Absent) {
            require_absent(&final_path)?;
        }
        let lease_path = root_path.join(LEASE_NAME);
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lease_path)
            .map_err(|source| io_error(&lease_path, source))?;
        let lease_metadata = lease.metadata().map_err(|source| io_error(&lease_path, source))?;
        validate_file(&lease_metadata, FILE_MODE).map_err(|_| ManagedStoreError::LeaseTrust)?;
        lease.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => ManagedStoreError::LeaseConflict,
            fs::TryLockError::Error(source) => io_error(&lease_path, source),
        })?;

        let lease_path_metadata =
            fs::symlink_metadata(&lease_path).map_err(|source| io_error(&lease_path, source))?;
        validate_file(&lease_path_metadata, FILE_MODE)
            .map_err(|_| ManagedStoreError::LeaseTrust)?;
        require_same_identity(
            &lease_metadata,
            &lease_path_metadata,
            ManagedStoreError::LeaseTrust,
        )?;
        let root_after =
            fs::symlink_metadata(&root_path).map_err(|source| io_error(&root_path, source))?;
        validate_root(&root_after)?;
        require_same_identity(&opened_root, &root_after, ManagedStoreError::RootTrust)?;
        match target {
            ManagedTarget::Absent => {
                require_absent(&final_path)?;
                require_absent(&companion_path(&final_path, "-wal"))?;
                require_absent(&companion_path(&final_path, "-shm"))?;
            }
            ManagedTarget::Existing => {
                validate_existing_file(&final_path)?;
                validate_optional_file(&companion_path(&final_path, "-wal"))?;
                validate_optional_file(&companion_path(&final_path, "-shm"))?;
            }
        }

        Ok(Self { root_path, final_path, root, lease })
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.final_path
    }

    pub(crate) fn create_stage(&self) -> Result<ManagedStage, ManagedStoreError> {
        for _ in 0..MAX_STAGE_NAME_ATTEMPTS {
            let mut random = [0_u8; STAGE_NAME_RANDOM_BYTES];
            fill_random(&mut random)?;
            let name = format!(".whisper-stage-{}.sqlite3", hex::encode(&random));
            let path = self.root_path.join(name);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => {
                    let metadata = file.metadata().map_err(|source| io_error(&path, source))?;
                    validate_file(&metadata, FILE_MODE)?;
                    return Ok(ManagedStage {
                        path,
                        identity: identity(&metadata),
                        published: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(io_error(&path, source)),
            }
        }
        Err(ManagedStoreError::StageNameExhausted)
    }

    pub(crate) fn publish(&self, mut stage: ManagedStage) -> Result<PathBuf, ManagedStoreError> {
        require_absent(&self.final_path)?;
        stage.prepare_for_publication()?;
        fs::hard_link(&stage.path, &self.final_path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                ManagedStoreError::AlreadyExists
            } else {
                io_error(&self.final_path, error)
            }
        })?;

        self.complete_publication(&mut stage)?;
        Ok(self.final_path.clone())
    }

    fn complete_publication(&self, stage: &mut ManagedStage) -> Result<(), ManagedStoreError> {
        let completion = (|| {
            let final_metadata = fs::symlink_metadata(&self.final_path)
                .map_err(|source| io_error(&self.final_path, source))?;
            validate_file_with_links(&final_metadata, FILE_MODE, PUBLICATION_LINK_COUNT)?;
            if identity(&final_metadata) != stage.identity {
                return Err(ManagedStoreError::ObjectTrust);
            }
            fs::remove_file(&stage.path).map_err(|source| io_error(&stage.path, source))?;
            let final_metadata = fs::symlink_metadata(&self.final_path)
                .map_err(|source| io_error(&self.final_path, source))?;
            validate_file(&final_metadata, FILE_MODE)?;
            if identity(&final_metadata) != stage.identity {
                return Err(ManagedStoreError::ObjectTrust);
            }
            self.root.sync_all().map_err(|source| io_error(&self.root_path, source))
        })();
        if let Err(error) = completion {
            remove_if_identity(&self.final_path, stage.identity)?;
            self.root.sync_all().map_err(|source| io_error(&self.root_path, source))?;
            return Err(error);
        }
        stage.published = true;
        Ok(())
    }

    pub(crate) fn remove_published_if_owned(
        &self,
        identity: Identity,
    ) -> Result<(), ManagedStoreError> {
        remove_sqlite_companion_checked(&self.final_path, "-wal", true)?;
        remove_sqlite_companion_checked(&self.final_path, "-shm", false)?;
        remove_if_identity(&self.final_path, identity)?;
        self.root.sync_all().map_err(|source| io_error(&self.root_path, source))
    }

    pub(crate) fn finish_closed_database(&self) -> Result<(), ManagedStoreError> {
        remove_sqlite_companion_checked(&self.final_path, "-wal", true)?;
        remove_sqlite_companion_checked(&self.final_path, "-shm", false)?;
        validate_existing_file(&self.final_path)?;
        self.root.sync_all().map_err(|source| io_error(&self.root_path, source))
    }
}

pub(crate) fn validate_existing_for_reader(
    database_path: &Path,
) -> Result<(PathBuf, Identity), ManagedStoreError> {
    let file_name = database_path.file_name().ok_or(ManagedStoreError::InvalidTarget)?;
    if file_name == LEASE_NAME {
        return Err(ManagedStoreError::InvalidTarget);
    }
    let configured_root = database_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root_before = fs::symlink_metadata(configured_root)
        .map_err(|source| io_error(configured_root, source))?;
    validate_root(&root_before)?;
    let root_path =
        fs::canonicalize(configured_root).map_err(|source| io_error(configured_root, source))?;
    let canonical_metadata =
        fs::symlink_metadata(&root_path).map_err(|source| io_error(&root_path, source))?;
    validate_root(&canonical_metadata)?;
    require_same_identity(&root_before, &canonical_metadata, ManagedStoreError::RootTrust)?;

    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&root_path)
        .map_err(|source| io_error(&root_path, source))?;
    let opened_root = root.metadata().map_err(|source| io_error(&root_path, source))?;
    validate_root(&opened_root)?;
    require_same_identity(&canonical_metadata, &opened_root, ManagedStoreError::RootTrust)?;

    let final_path = root_path.join(file_name);
    let final_identity = validate_existing_file_read_only(&final_path)?;
    validate_optional_file_read_only(&companion_path(&final_path, "-wal"))?;
    validate_optional_file_read_only(&companion_path(&final_path, "-shm"))?;
    let root_after =
        fs::symlink_metadata(&root_path).map_err(|source| io_error(&root_path, source))?;
    validate_root(&root_after)?;
    require_same_identity(&opened_root, &root_after, ManagedStoreError::RootTrust)?;
    Ok((final_path, final_identity))
}

#[derive(Debug)]
pub(crate) struct ManagedStage {
    path: PathBuf,
    identity: Identity,
    published: bool,
}

impl ManagedStage {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn identity(&self) -> Identity {
        self.identity
    }

    pub(crate) fn sync(&self) -> Result<(), ManagedStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|source| io_error(&self.path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(&self.path, source))?;
        validate_file(&metadata, FILE_MODE)?;
        if identity(&metadata) != self.identity {
            return Err(ManagedStoreError::ObjectTrust);
        }
        file.sync_all().map_err(|source| io_error(&self.path, source))
    }

    fn validate(&self) -> Result<(), ManagedStoreError> {
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|source| io_error(&self.path, source))?;
        validate_file(&metadata, FILE_MODE)?;
        if identity(&metadata) != self.identity {
            return Err(ManagedStoreError::ObjectTrust);
        }
        Ok(())
    }

    fn prepare_for_publication(&self) -> Result<(), ManagedStoreError> {
        remove_sqlite_companion_checked(&self.path, "-wal", true)?;
        remove_sqlite_companion_checked(&self.path, "-shm", false)?;
        self.validate()
    }
}

impl Drop for ManagedStage {
    fn drop(&mut self) {
        if !self.published {
            let _ = remove_if_identity(&self.path, self.identity);
            remove_sqlite_companion(&self.path, "-wal");
            remove_sqlite_companion(&self.path, "-shm");
        }
    }
}

pub(crate) fn fill_random(bytes: &mut [u8]) -> Result<(), ManagedStoreError> {
    let path = Path::new(RANDOM_SOURCE);
    let mut source = File::open(path).map_err(|source| io_error(path, source))?;
    source.read_exact(bytes).map_err(|source| io_error(path, source))
}

fn validate_root(metadata: &Metadata) -> Result<(), ManagedStoreError> {
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE
    {
        return Err(ManagedStoreError::RootTrust);
    }
    Ok(())
}

fn validate_file(metadata: &Metadata, mode: u32) -> Result<(), ManagedStoreError> {
    validate_file_with_links(metadata, mode, SINGLE_LINK_COUNT)
}

fn validate_file_with_links(
    metadata: &Metadata,
    mode: u32,
    expected_links: u64,
) -> Result<(), ManagedStoreError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != expected_links
    {
        return Err(ManagedStoreError::ObjectTrust);
    }
    Ok(())
}

fn validate_existing_file(path: &Path) -> Result<(), ManagedStoreError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_file(&path_metadata, FILE_MODE)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened_metadata = file.metadata().map_err(|source| io_error(path, source))?;
    validate_file(&opened_metadata, FILE_MODE)?;
    require_same_identity(&path_metadata, &opened_metadata, ManagedStoreError::ObjectTrust)?;
    let path_after = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_file(&path_after, FILE_MODE)?;
    require_same_identity(&opened_metadata, &path_after, ManagedStoreError::ObjectTrust)
}

fn validate_existing_file_read_only(path: &Path) -> Result<Identity, ManagedStoreError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_file(&path_metadata, FILE_MODE)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened_metadata = file.metadata().map_err(|source| io_error(path, source))?;
    validate_file(&opened_metadata, FILE_MODE)?;
    require_same_identity(&path_metadata, &opened_metadata, ManagedStoreError::ObjectTrust)?;
    let path_after = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_file(&path_after, FILE_MODE)?;
    require_same_identity(&opened_metadata, &path_after, ManagedStoreError::ObjectTrust)?;
    Ok(identity(&opened_metadata))
}

fn validate_optional_file(path: &Path) -> Result<(), ManagedStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_existing_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn validate_optional_file_read_only(path: &Path) -> Result<(), ManagedStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_existing_file_read_only(path).map(|_| ()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn require_same_identity(
    left: &Metadata,
    right: &Metadata,
    error: ManagedStoreError,
) -> Result<(), ManagedStoreError> {
    if identity(left) == identity(right) { Ok(()) } else { Err(error) }
}

fn identity(metadata: &Metadata) -> Identity {
    Identity { device: metadata.dev(), inode: metadata.ino() }
}

fn require_absent(path: &Path) -> Result<(), ManagedStoreError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(ManagedStoreError::AlreadyExists),
        Err(source) => Err(io_error(path, source)),
    }
}

fn remove_if_identity(path: &Path, expected: Identity) -> Result<(), ManagedStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if identity(&metadata) == expected => {
            fs::remove_file(path).map_err(|source| io_error(path, source))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(ManagedStoreError::ObjectTrust),
        Err(source) => Err(io_error(path, source)),
    }
}

fn remove_sqlite_companion(path: &Path, suffix: &str) {
    let companion = companion_path(path, suffix);
    if let Ok(metadata) = fs::symlink_metadata(&companion)
        && metadata.file_type().is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
    {
        let _ = fs::remove_file(companion);
    }
}

fn remove_sqlite_companion_checked(
    path: &Path,
    suffix: &str,
    require_empty: bool,
) -> Result<(), ManagedStoreError> {
    let companion = companion_path(path, suffix);
    match fs::symlink_metadata(&companion) {
        Ok(metadata) => {
            validate_file(&metadata, FILE_MODE)?;
            if require_empty && metadata.len() != 0 {
                return Err(ManagedStoreError::ObjectTrust);
            }
            fs::remove_file(&companion).map_err(|source| io_error(&companion, source))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(&companion, source)),
    }
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{ManagedRoot, ManagedStoreError};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "whisper-managed-stage-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create Managed root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("protect Managed root");
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tampered_private_stage_is_rejected_and_removed() {
        let root = TestRoot::new();
        let final_path = root.path().join("host.sqlite3");
        let managed =
            ManagedRoot::acquire_for_initialization(&final_path).expect("acquire lifecycle");
        let stage = managed.create_stage().expect("create private stage");
        let stage_path = PathBuf::from(stage.path());
        fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o644))
            .expect("tamper with private stage");

        assert!(matches!(managed.publish(stage), Err(ManagedStoreError::ObjectTrust)));
        assert!(!stage_path.exists());
        assert!(!final_path.exists());
    }

    #[test]
    fn post_link_trust_failure_removes_the_new_final_component() {
        let root = TestRoot::new();
        let final_path = root.path().join("host.sqlite3");
        let extra_path = root.path().join("unexpected-link.sqlite3");
        let managed =
            ManagedRoot::acquire_for_initialization(&final_path).expect("acquire lifecycle");
        let mut stage = managed.create_stage().expect("create private stage");
        fs::hard_link(stage.path(), &final_path).expect("publish final link");
        fs::hard_link(stage.path(), &extra_path).expect("inject extra post-publication link");

        assert!(matches!(
            managed.complete_publication(&mut stage),
            Err(ManagedStoreError::ObjectTrust)
        ));
        assert!(!final_path.exists(), "failed publication retained the final component");
    }
}
