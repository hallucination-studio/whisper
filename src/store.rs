//! Persistent identity and explicit lifecycle for RF world-model facts.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, params};

const DATABASE_NAME: &str = "facts.sqlite3";
const LEASE_NAME: &str = ".whisper.lease";
const STORE_APPLICATION_ID: u32 = 0x5752_4631;
const STORE_SCHEMA_VERSION: u32 = 1;
const SQLITE_HEADER_BYTES: usize = 100;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const STORE_ID_BYTES: usize = 16;
const ROOT_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const RANDOM_SOURCE: &str = "/dev/urandom";

/// A non-secret persistent identity for one Store.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreId([u8; STORE_ID_BYTES]);

impl fmt::Debug for StoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StoreId({self})")
    }
}

impl fmt::Display for StoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Failure to initialize or open the new RF world-model Store.
#[derive(Debug)]
pub struct StoreError {
    kind: StoreErrorKind,
}

#[derive(Debug, thiserror::Error)]
enum StoreErrorKind {
    #[error("the Store initialization target already exists")]
    AlreadyExists,
    #[error("the Store is not the recognized RF world-model format")]
    Unrecognized,
    #[error("the Store root or one of its owned files is not trusted")]
    Untrusted,
    #[error("the Store lease is already held by another process")]
    LeaseConflict,
    #[error("Store I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Store database operation failed: {0}")]
    Database(#[source] rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kind.source()
    }
}

impl StoreError {
    /// Reports that initialization refused to replace an existing target.
    #[must_use]
    pub const fn is_existing_target(&self) -> bool {
        matches!(self.kind, StoreErrorKind::AlreadyExists)
    }

    /// Reports that existing bytes do not identify the new Store format.
    #[must_use]
    pub const fn is_unrecognized_format(&self) -> bool {
        matches!(self.kind, StoreErrorKind::Unrecognized)
    }

    /// Reports that another cooperative process currently owns the Store.
    #[must_use]
    pub const fn is_lease_conflict(&self) -> bool {
        matches!(self.kind, StoreErrorKind::LeaseConflict)
    }
}

impl From<StoreErrorKind> for StoreError {
    fn from(kind: StoreErrorKind) -> Self {
        Self { kind }
    }
}

/// An exclusively leased RF world-model Store ready for Host ownership.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    id: StoreId,
    lease: File,
}

impl Store {
    /// Explicitly initializes a Store in an absent directory.
    ///
    /// # Errors
    ///
    /// Returns an error without replacing any object when `root` already exists,
    /// or when the new Store cannot be durably created and exclusively leased.
    pub fn initialize(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        match fs::create_dir(root) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreErrorKind::AlreadyExists.into());
            }
            Err(source) => return Err(io_error(root, source)),
        }

        let result = (|| {
            set_root_permissions(root)?;
            let lease = acquire_lease(root, true)?;
            let id = random_store_id()?;
            let database_path = root.join(DATABASE_NAME);
            initialize_database(&database_path, id)?;
            sync_directory(root)?;
            Ok(Self { root: root.to_owned(), id, lease })
        })();

        if result.is_err() {
            let _ = fs::remove_dir_all(root);
        }
        result
    }

    /// Opens one explicitly initialized Store and acquires its cooperative lease.
    ///
    /// Format recognition is performed by reading existing bytes before the
    /// lease or write-capable SQLite connection is opened, so old, unknown, and corrupt targets remain
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when the format or filesystem identity is not trusted,
    /// another process holds the lease, or SQLite validation fails.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        validate_root(root)?;
        let database_path = root.join(DATABASE_NAME);
        recognize_database_header(&database_path)?;
        let id = validate_database_read_only(&database_path)?;
        let lease = acquire_lease(root, false)?;
        validate_optional_regular_file(&database_path.with_extension("sqlite3-wal"))?;
        validate_optional_regular_file(&database_path.with_extension("sqlite3-shm"))?;
        Ok(Self { root: root.to_owned(), id, lease })
    }

    /// Returns the persistent non-secret Store identity.
    #[must_use]
    pub const fn id(&self) -> StoreId {
        self.id
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root.join(DATABASE_NAME)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.lease.unlock();
    }
}

fn initialize_database(path: &Path, id: StoreId) -> Result<(), StoreError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(database_error)?;
    set_file_permissions(path)?;
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {STORE_APPLICATION_ID};
             PRAGMA user_version = {STORE_SCHEMA_VERSION};
             CREATE TABLE store_identity (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 store_id BLOB NOT NULL CHECK (length(store_id) = {STORE_ID_BYTES})
             ) STRICT;
             CREATE TABLE replay_windows (
                 identity BLOB PRIMARY KEY CHECK (length(identity) = 32),
                 device_id BLOB NOT NULL CHECK (length(device_id) = 8),
                 key_epoch INTEGER NOT NULL,
                 state BLOB NOT NULL
             ) STRICT;
             CREATE TABLE raw_facts (
                 fact_id INTEGER PRIMARY KEY,
                 digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
                 received_utc_ns INTEGER NOT NULL,
                 peer TEXT NOT NULL,
                 device_id BLOB NOT NULL CHECK (length(device_id) = 8),
                 key_epoch INTEGER NOT NULL,
                 boot_generation INTEGER NOT NULL,
                 message_sequence BLOB NOT NULL CHECK (length(message_sequence) = 8),
                 kind INTEGER NOT NULL,
                 datagram BLOB NOT NULL
             ) STRICT;
             CREATE TABLE raw_losses (
                 loss_id INTEGER PRIMARY KEY,
                 observed_utc_ns INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 count INTEGER NOT NULL,
                 device_id BLOB,
                 boot_generation INTEGER,
                 first_sequence BLOB,
                 last_sequence BLOB
             ) STRICT;"
        ))
        .map_err(database_error)?;
    connection
        .execute("INSERT INTO store_identity (singleton, store_id) VALUES (1, ?1)", params![id.0])
        .map_err(database_error)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").map_err(database_error)?;
    drop(connection);
    File::open(path).and_then(|file| file.sync_all()).map_err(|source| io_error(path, source))
}

fn recognize_database_header(path: &Path) -> Result<(), StoreError> {
    validate_regular_file(path)?;
    let mut header = [0_u8; SQLITE_HEADER_BYTES];
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    file.read_exact(&mut header).map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    if &header[..SQLITE_MAGIC.len()] != SQLITE_MAGIC
        || u32::from_be_bytes(header[60..64].try_into().expect("fixed header offsets"))
            != STORE_SCHEMA_VERSION
        || u32::from_be_bytes(header[68..72].try_into().expect("fixed header offsets"))
            != STORE_APPLICATION_ID
    {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    Ok(())
}

fn validate_database_read_only(path: &Path) -> Result<StoreId, StoreError> {
    let uri = immutable_sqlite_uri(path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    if integrity != "ok" {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    let schema_count: u32 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'table'
               AND name IN ('store_identity', 'replay_windows', 'raw_facts', 'raw_losses')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    let total_user_tables: u32 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    if schema_count != 4 || total_user_tables != 4 {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    let bytes: Vec<u8> = connection
        .query_row("SELECT store_id FROM store_identity WHERE singleton = 1", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    let bytes: [u8; STORE_ID_BYTES] =
        bytes.try_into().map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    Ok(StoreId(bytes))
}

#[cfg(unix)]
fn immutable_sqlite_uri(path: &Path) -> Result<String, StoreError> {
    use std::os::unix::ffi::OsStrExt;

    let absolute = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let mut uri = String::from("file:");
    for byte in absolute.as_os_str().as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' => {
                uri.push(char::from(*byte));
            }
            _ => {
                use std::fmt::Write;
                write!(uri, "%{byte:02X}").expect("writing to a String cannot fail");
            }
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

#[cfg(not(unix))]
fn immutable_sqlite_uri(_path: &Path) -> Result<String, StoreError> {
    Err(StoreErrorKind::Untrusted.into())
}

fn acquire_lease(root: &Path, create: bool) -> Result<File, StoreError> {
    let path = root.join(LEASE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    options.mode(FILE_MODE).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let lease = options.open(&path).map_err(|source| io_error(&path, source))?;
    if create {
        set_file_permissions(&path)?;
    } else {
        validate_regular_file(&path)?;
    }
    lease.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => StoreError::from(StoreErrorKind::LeaseConflict),
        fs::TryLockError::Error(source) => io_error(&path, source),
    })?;
    Ok(lease)
}

fn random_store_id() -> Result<StoreId, StoreError> {
    let path = Path::new(RANDOM_SOURCE);
    let mut bytes = [0_u8; STORE_ID_BYTES];
    File::open(path)
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|source| io_error(path, source))?;
    Ok(StoreId(bytes))
}

#[cfg(unix)]
fn validate_root(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE
    {
        return Err(StoreErrorKind::Untrusted.into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_root(_path: &Path) -> Result<(), StoreError> {
    Err(StoreErrorKind::Untrusted.into())
}

#[cfg(unix)]
fn validate_regular_file(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(StoreErrorKind::Untrusted.into());
    }
    Ok(())
}

fn validate_optional_regular_file(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_regular_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

#[cfg(not(unix))]
fn validate_regular_file(_path: &Path) -> Result<(), StoreError> {
    Err(StoreErrorKind::Untrusted.into())
}

#[cfg(unix)]
fn set_root_permissions(path: &Path) -> Result<(), StoreError> {
    fs::set_permissions(path, fs::Permissions::from_mode(ROOT_MODE))
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn set_root_permissions(_path: &Path) -> Result<(), StoreError> {
    Err(StoreErrorKind::Untrusted.into())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), StoreError> {
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), StoreError> {
    Err(StoreErrorKind::Untrusted.into())
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: io::Error) -> StoreError {
    StoreErrorKind::Io { path: path.to_owned(), source }.into()
}

fn database_error(source: rusqlite::Error) -> StoreError {
    StoreErrorKind::Database(source).into()
}
