//! Persistent identity and explicit lifecycle for RF world-model facts.

use std::backtrace::Backtrace;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, params};

/// Stable Store database basename from the persistence layout contract.
const DATABASE_NAME: &str = "facts.sqlite3";
/// Cooperative process-ownership marker beside the database.
const LEASE_NAME: &str = ".whisper.lease";
/// SQLite application identifier (`WRF1`) written at header offset 68. Changing
/// it makes all existing Stores intentionally unrecognizable.
const STORE_APPLICATION_ID: u32 = 0x5752_4631;
/// Exact SQLite schema generation. Incrementing it requires an explicitly
/// scoped migration; this ticket recognizes only newly initialized generation 1.
const STORE_SCHEMA_VERSION: u32 = 1;
/// SQLite's fixed database header size in bytes. Changing this file-format
/// value would shift every recognition offset and misclassify database bytes.
const SQLITE_HEADER_BYTES: usize = 100;
/// SQLite's exact 16-byte database-header magic. Changing it would make valid
/// SQLite Stores unrecognizable or admit a different persistence format.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// Persistent Store identity width in bytes; 128 random bits are enough to make
/// accidental identity collision negligible without treating this as a secret.
const STORE_ID_BYTES: usize = 16;
/// Owner-only Unix directory permission bits required by the host
/// secret-adjacent trust policy. Changing them alters which Stores are trusted.
const ROOT_MODE: u32 = 0o700;
/// Owner read/write Unix file permission bits required by the host trust
/// policy. Changing them alters which Store-owned mutable files are trusted.
const FILE_MODE: u32 = 0o600;
/// Kernel CSPRNG byte source on supported Unix hosts. Replacing it changes the
/// Store-identity entropy trust boundary and must preserve blocking/error semantics.
const RANDOM_SOURCE: &str = "/dev/urandom";
/// SQLite WAL header width in bytes. Changing this file-format value would
/// shift frame validation and misclassify WAL companions.
const WAL_HEADER_BYTES: usize = 32;
/// SQLite's per-page WAL frame-header width in bytes. Changing it would alter
/// frame boundaries and admit corrupt or reject valid recovery state.
const WAL_FRAME_HEADER_BYTES: usize = 24;
/// Smallest legal SQLite database page in bytes. Changing this format boundary
/// alters which WAL page sizes Store recognition accepts.
const SQLITE_MINIMUM_PAGE_BYTES: usize = 512;
/// SQLite's page-size sentinel `1` denotes 65,536 bytes. Changing this mapping
/// would compute the wrong WAL frame boundaries for 64-KiB databases.
const SQLITE_SENTINEL_PAGE_BYTES: usize = 65_536;
/// SQLite wal-index shared-memory regions are fixed at 32 KiB. Changing this
/// would accept companion layouts SQLite itself cannot consume.
const WAL_INDEX_REGION_BYTES: u64 = 32_768;
/// SQLite's two WAL magic values for big- and little-endian checksums. Changing
/// this set alters which companion format Store recognition trusts.
const WAL_MAGIC_VALUES: [u32; 2] = [0x377f_0682, 0x377f_0683];

// These canonical DDL strings are both creation input and exact recognition
// identity. Fixed widths are protocol/schema bytes (Store 16, digest/identity
// 32, device/sequence 8, boot 4, epoch 2); changing any literal changes the
// accepted persistence contract and therefore requires a schema generation.
const STORE_IDENTITY_SCHEMA: &str = "CREATE TABLE store_identity (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 store_id BLOB NOT NULL CHECK (typeof(store_id) = 'blob' AND length(store_id) = 16),
                 admission_configured INTEGER NOT NULL CHECK (admission_configured IN (0, 1))
             ) STRICT";
const REPLAY_WINDOWS_SCHEMA: &str = "CREATE TABLE replay_windows (
                 device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 8),
                 key_epoch BLOB NOT NULL CHECK (typeof(key_epoch) = 'blob' AND length(key_epoch) = 2),
                 identity BLOB NOT NULL CHECK (typeof(identity) = 'blob' AND length(identity) = 32),
                 window_packets INTEGER NOT NULL CHECK (window_packets BETWEEN 1 AND 65535),
                 state BLOB NOT NULL CHECK (typeof(state) = 'blob'),
                 PRIMARY KEY (device_id, key_epoch)
             ) STRICT";
const RAW_FACTS_SCHEMA: &str = "CREATE TABLE raw_facts (
                 fact_id INTEGER PRIMARY KEY,
                 digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
                 received_utc_ns INTEGER NOT NULL,
                 peer TEXT NOT NULL,
                 device_id BLOB NOT NULL CHECK (length(device_id) = 8),
                 key_epoch BLOB NOT NULL CHECK (typeof(key_epoch) = 'blob' AND length(key_epoch) = 2),
                 boot_generation BLOB NOT NULL CHECK (typeof(boot_generation) = 'blob' AND length(boot_generation) = 4),
                 message_sequence BLOB NOT NULL CHECK (length(message_sequence) = 8),
                 kind INTEGER NOT NULL CHECK (kind BETWEEN 0 AND 255),
                 datagram BLOB NOT NULL CHECK (typeof(datagram) = 'blob')
             ) STRICT";
const RAW_LOSSES_SCHEMA: &str = "CREATE TABLE raw_losses (
                 loss_id INTEGER PRIMARY KEY,
                 observed_utc_ns INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 count INTEGER NOT NULL CHECK (count > 0),
                 device_id BLOB CHECK (device_id IS NULL OR (typeof(device_id) = 'blob' AND length(device_id) = 8)),
                 boot_generation BLOB CHECK (boot_generation IS NULL OR (typeof(boot_generation) = 'blob' AND length(boot_generation) = 4)),
                 first_sequence BLOB CHECK (first_sequence IS NULL OR (typeof(first_sequence) = 'blob' AND length(first_sequence) = 8)),
                 last_sequence BLOB CHECK (last_sequence IS NULL OR (typeof(last_sequence) = 'blob' AND length(last_sequence) = 8))
             ) STRICT";
const EXPECTED_SCHEMA: [(&str, &str); 4] = [
    ("store_identity", STORE_IDENTITY_SCHEMA),
    ("replay_windows", REPLAY_WINDOWS_SCHEMA),
    ("raw_facts", RAW_FACTS_SCHEMA),
    ("raw_losses", RAW_LOSSES_SCHEMA),
];
// SQLite owns these implicit indexes for the declared UNIQUE and composite
// PRIMARY KEY constraints. Their exact names, owning tables, and NULL SQL are
// part of schema generation 1; any other SQLite-owned object is unrecognized.
const EXPECTED_SQLITE_AUTO_INDEXES: [(&str, &str); 2] = [
    ("sqlite_autoindex_raw_facts_1", "raw_facts"),
    ("sqlite_autoindex_replay_windows_1", "replay_windows"),
];

trait Entropy {
    fn source_path(&self) -> &Path;
    fn fill(&self, bytes: &mut [u8]) -> io::Result<()>;
}

#[derive(Debug)]
struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn source_path(&self) -> &Path {
        Path::new(RANDOM_SOURCE)
    }

    fn fill(&self, bytes: &mut [u8]) -> io::Result<()> {
        File::open(RANDOM_SOURCE)?.read_exact(bytes)
    }
}

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

/// Internal Store failure retained as the source of operation-specific errors.
#[derive(Debug)]
struct StoreError {
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

/// Failure to explicitly initialize a new Store.
#[derive(Debug)]
pub struct StoreInitError {
    root: PathBuf,
    source: StoreError,
    backtrace: Box<Backtrace>,
}

impl StoreInitError {
    /// Returns the initialization root involved in the failure.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reports that initialization refused to replace an existing target.
    #[must_use]
    pub const fn is_existing_target(&self) -> bool {
        self.source.is_existing_target()
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        self.backtrace.as_ref()
    }
}

impl fmt::Display for StoreInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "could not initialize Store at {}: {}", self.root.display(), self.source)
    }
}

impl std::error::Error for StoreInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Failure to recognize, validate, or exclusively open an existing Store.
#[derive(Debug)]
pub struct StoreOpenError {
    root: PathBuf,
    source: StoreError,
    backtrace: Box<Backtrace>,
}

impl StoreOpenError {
    /// Returns the Store root involved in the failed open.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reports that existing bytes do not identify the exact Store format.
    #[must_use]
    pub const fn is_unrecognized_format(&self) -> bool {
        self.source.is_unrecognized_format()
    }

    /// Reports that another cooperative process currently owns the Store.
    #[must_use]
    pub const fn is_lease_conflict(&self) -> bool {
        self.source.is_lease_conflict()
    }

    /// Returns the captured open backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        self.backtrace.as_ref()
    }
}

impl fmt::Display for StoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "could not open Store at {}: {}", self.root.display(), self.source)
    }
}

impl std::error::Error for StoreOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// An exclusively leased RF world-model Store ready for Host ownership.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    id: StoreId,
    lease: File,
}

pub(crate) struct StoreSnapshot {
    root: PathBuf,
    database: PathBuf,
}

impl StoreSnapshot {
    pub(crate) fn database_path(&self) -> &Path {
        &self.database
    }
}

impl Drop for StoreSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Store {
    /// Explicitly initializes a Store in an absent directory.
    ///
    /// # Errors
    ///
    /// Returns an error without replacing any object when `root` already exists,
    /// or when the new Store cannot be durably created and exclusively leased.
    pub fn initialize(root: impl AsRef<Path>) -> Result<Self, StoreInitError> {
        Self::initialize_with_entropy(root.as_ref(), &SystemEntropy)
    }

    fn initialize_with_entropy(root: &Path, entropy: &dyn Entropy) -> Result<Self, StoreInitError> {
        match fs::create_dir(root) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreInitError {
                    root: root.to_owned(),
                    source: StoreErrorKind::AlreadyExists.into(),
                    backtrace: Box::new(Backtrace::capture()),
                });
            }
            Err(source) => {
                return Err(StoreInitError {
                    root: root.to_owned(),
                    source: io_error(root, source),
                    backtrace: Box::new(Backtrace::capture()),
                });
            }
        };

        let result = (|| {
            set_root_permissions(root)?;
            let lease = acquire_lease(root, true)?;
            let id = random_store_id(entropy)?;
            let database_path = root.join(DATABASE_NAME);
            initialize_database(&database_path, id)?;
            sync_directory(root)?;
            Ok(Self { root: root.to_owned(), id, lease })
        })();

        if result.is_err() {
            let _ = fs::remove_dir_all(root);
        }
        result.map_err(|source| StoreInitError {
            root: root.to_owned(),
            source,
            backtrace: Box::new(Backtrace::capture()),
        })
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
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreOpenError> {
        Self::open_with_entropy(root.as_ref(), &SystemEntropy)
    }

    fn open_with_entropy(root: &Path, entropy: &dyn Entropy) -> Result<Self, StoreOpenError> {
        (|| {
            validate_root(root)?;
            let database_path = root.join(DATABASE_NAME);
            recognize_database_header(&database_path)?;
            let lease = acquire_lease(root, false)?;
            let wal_path = database_path.with_extension("sqlite3-wal");
            let shm_path = database_path.with_extension("sqlite3-shm");
            validate_optional_regular_file(&wal_path)?;
            validate_optional_regular_file(&shm_path)?;
            validate_wal_shape(&wal_path)?;
            validate_shm_shape(&shm_path, wal_path.exists())?;
            let id = validate_database_snapshot(&database_path, &wal_path, &shm_path, entropy)?;
            Ok(Self { root: root.to_owned(), id, lease })
        })()
        .map_err(|source| StoreOpenError {
            root: root.to_owned(),
            source,
            backtrace: Box::new(Backtrace::capture()),
        })
    }

    /// Returns the persistent non-secret Store identity.
    #[must_use]
    pub const fn id(&self) -> StoreId {
        self.id
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root.join(DATABASE_NAME)
    }

    pub(crate) fn database_snapshot(&self) -> io::Result<StoreSnapshot> {
        self.database_snapshot_with_entropy(&SystemEntropy)
    }

    fn database_snapshot_with_entropy(&self, entropy: &dyn Entropy) -> io::Result<StoreSnapshot> {
        let mut nonce = [0_u8; 16];
        entropy.fill(&mut nonce)?;
        let name = nonce.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let root = std::env::temp_dir().join(format!("whisper-store-read-{name}"));
        fs::create_dir(&root)?;
        let database = root.join(DATABASE_NAME);
        let source = self.database_path();
        if let Err(error) = (|| {
            fs::copy(&source, &database)?;
            for extension in ["sqlite3-wal", "sqlite3-shm"] {
                let companion = source.with_extension(extension);
                if companion.exists() {
                    fs::copy(&companion, database.with_extension(extension))?;
                }
            }
            Ok::<(), io::Error>(())
        })() {
            let _ = fs::remove_dir_all(&root);
            return Err(error);
        }
        Ok(StoreSnapshot { root, database })
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
             PRAGMA user_version = {STORE_SCHEMA_VERSION};"
        ))
        .map_err(database_error)?;
    for (_, schema) in EXPECTED_SCHEMA {
        connection.execute_batch(schema).map_err(database_error)?;
    }
    connection
        .execute(
            "INSERT INTO store_identity (singleton, store_id, admission_configured) VALUES (1, ?1, 0)",
            params![id.0],
        )
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
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    if integrity != "ok" {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    let application_id: u32 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    let user_version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    if application_id != STORE_APPLICATION_ID || user_version != STORE_SCHEMA_VERSION {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    let total_schema_objects: u32 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    if total_schema_objects != (EXPECTED_SCHEMA.len() + EXPECTED_SQLITE_AUTO_INDEXES.len()) as u32 {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    for (name, expected_sql) in EXPECTED_SCHEMA {
        let (object_type, owning_table, actual_sql): (String, String, Option<String>) = connection
            .query_row(
                "SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
        if object_type != "table"
            || owning_table != name
            || actual_sql.as_deref() != Some(expected_sql)
        {
            return Err(StoreErrorKind::Unrecognized.into());
        }
    }
    for (name, expected_table) in EXPECTED_SQLITE_AUTO_INDEXES {
        let (object_type, owning_table, actual_sql): (String, String, Option<String>) = connection
            .query_row(
                "SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
        if object_type != "index" || owning_table != expected_table || actual_sql.is_some() {
            return Err(StoreErrorKind::Unrecognized.into());
        }
    }
    let bytes: Vec<u8> = connection
        .query_row("SELECT store_id FROM store_identity WHERE singleton = 1", [], |row| row.get(0))
        .map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    let bytes: [u8; STORE_ID_BYTES] =
        bytes.try_into().map_err(|_| StoreError::from(StoreErrorKind::Unrecognized))?;
    Ok(StoreId(bytes))
}

fn validate_database_snapshot(
    database: &Path,
    wal: &Path,
    shm: &Path,
    entropy: &dyn Entropy,
) -> Result<StoreId, StoreError> {
    let nonce = random_bytes::<16>(entropy)?;
    let name = nonce.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let root = std::env::temp_dir().join(format!("whisper-store-validation-{name}"));
    fs::create_dir(&root).map_err(|source| io_error(&root, source))?;
    let snapshot_database = root.join(DATABASE_NAME);
    let result = (|| {
        fs::copy(database, &snapshot_database).map_err(|source| io_error(database, source))?;
        if wal.exists() {
            fs::copy(wal, snapshot_database.with_extension("sqlite3-wal"))
                .map_err(|source| io_error(wal, source))?;
        }
        if shm.exists() {
            fs::copy(shm, snapshot_database.with_extension("sqlite3-shm"))
                .map_err(|source| io_error(shm, source))?;
        }
        validate_database_read_only(&snapshot_database)
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

fn validate_wal_shape(path: &Path) -> Result<(), StoreError> {
    let Ok(bytes) = fs::read(path) else {
        return if path.exists() { Err(StoreErrorKind::Unrecognized.into()) } else { Ok(()) };
    };
    // `PRAGMA wal_checkpoint(TRUNCATE)` leaves an empty WAL while a live
    // connection can retain the derived SHM index. SQLite accepts that crash
    // recovery state, and the snapshot validation below rebuilds it safely.
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() < WAL_HEADER_BYTES {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    let magic = u32::from_be_bytes(bytes[0..4].try_into().expect("fixed WAL magic width"));
    if !WAL_MAGIC_VALUES.contains(&magic) {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    let encoded_page_size =
        u32::from_be_bytes(bytes[8..12].try_into().expect("fixed WAL page width"));
    let page_size = if encoded_page_size == 1 {
        SQLITE_SENTINEL_PAGE_BYTES
    } else {
        encoded_page_size as usize
    };
    let frame_bytes =
        WAL_FRAME_HEADER_BYTES.checked_add(page_size).ok_or(StoreErrorKind::Unrecognized)?;
    if page_size < SQLITE_MINIMUM_PAGE_BYTES
        || !page_size.is_power_of_two()
        || !(bytes.len() - WAL_HEADER_BYTES).is_multiple_of(frame_bytes)
    {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    Ok(())
}

fn validate_shm_shape(path: &Path, wal_exists: bool) -> Result<(), StoreError> {
    let Ok(metadata) = fs::metadata(path) else {
        return if path.exists() { Err(StoreErrorKind::Unrecognized.into()) } else { Ok(()) };
    };
    // SQLite's wal-index uses 32 KiB regions and is only meaningful beside a WAL.
    if !wal_exists || metadata.len() == 0 || !metadata.len().is_multiple_of(WAL_INDEX_REGION_BYTES)
    {
        return Err(StoreErrorKind::Unrecognized.into());
    }
    Ok(())
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

fn random_store_id(entropy: &dyn Entropy) -> Result<StoreId, StoreError> {
    Ok(StoreId(random_bytes(entropy)?))
}

fn random_bytes<const N: usize>(entropy: &dyn Entropy) -> Result<[u8; N], StoreError> {
    let mut bytes = [0_u8; N];
    entropy.fill(&mut bytes).map_err(|source| io_error(entropy.source_path(), source))?;
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct FixedEntropy(Result<u8, io::ErrorKind>);

    impl Entropy for FixedEntropy {
        fn source_path(&self) -> &Path {
            Path::new("fixed-test-entropy")
        }

        fn fill(&self, bytes: &mut [u8]) -> io::Result<()> {
            match self.0 {
                Ok(value) => {
                    bytes.fill(value);
                    Ok(())
                }
                Err(kind) => Err(io::Error::from(kind)),
            }
        }
    }

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-store-capability-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn initialization_uses_the_injected_entropy_capability() {
        let root = root("fixed");
        let store = Store::initialize_with_entropy(&root, &FixedEntropy(Ok(0x5a))).unwrap();
        assert_eq!(store.id, StoreId([0x5a; STORE_ID_BYTES]));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_entropy_failure_retains_its_source_and_cleans_the_new_root() {
        let root = root("failure");
        let error = Store::initialize_with_entropy(
            &root,
            &FixedEntropy(Err(io::ErrorKind::PermissionDenied)),
        )
        .unwrap_err();
        let store_source = std::error::Error::source(&error).unwrap();
        assert!(store_source.source().is_some());
        assert!(!root.exists());
    }

    #[test]
    fn open_uses_the_injected_entropy_capability_without_changing_store_bytes() {
        let root = root("open-entropy-failure");
        drop(Store::initialize_with_entropy(&root, &FixedEntropy(Ok(0x5a))).unwrap());
        let database = root.join(DATABASE_NAME);
        let before = fs::read(&database).unwrap();

        let error =
            Store::open_with_entropy(&root, &FixedEntropy(Err(io::ErrorKind::PermissionDenied)))
                .unwrap_err();

        assert!(error.to_string().contains("fixed-test-entropy"));
        let store_source = std::error::Error::source(&error).unwrap();
        assert!(store_source.source().is_some());
        assert_eq!(fs::read(database).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
}
