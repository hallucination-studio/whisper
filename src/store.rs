//! Persistent identity and explicit lifecycle for RF world-model facts.

use std::backtrace::Backtrace;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, params};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Stable Store database basename from the persistence layout contract.
const DATABASE_NAME: &str = "facts.sqlite3";
/// Cooperative process-ownership marker beside the database.
const LEASE_NAME: &str = ".whisper.lease";
/// Store-private Ed25519 signing seed for the companion server identity.
const COMPANION_SIGNING_SEED_NAME: &str = ".whisper.companion-signing-seed";
/// SQLite application identifier (`WRF1`) written at header offset 68. Changing
/// it makes all existing Stores intentionally unrecognizable.
const STORE_APPLICATION_ID: u32 = 0x5752_4631;
/// Exact SQLite schema generation. Incrementing it requires an explicitly
/// scoped migration. Generation 4 combines native typed facts and immutable
/// spatial artifacts; earlier independent generations are deliberately rejected.
const STORE_SCHEMA_VERSION: u32 = 4;
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
/// Diagnostic identity for the platform CSPRNG capability.
const RANDOM_SOURCE: &str = "operating-system-randomness";
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
// identity. Fixed widths are protocol/schema bytes (Store 16, digest 32,
// identity/counter 8, boot 4, epoch 2); changing any literal changes the
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
const NATIVE_ROUTE_PINS_SCHEMA: &str = "CREATE TABLE native_route_pins (
                 device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 8),
                 key_epoch BLOB NOT NULL CHECK (typeof(key_epoch) = 'blob' AND length(key_epoch) = 2),
                 sensor_id TEXT NOT NULL CHECK (typeof(sensor_id) = 'text' AND length(sensor_id) > 0),
                 source_mac BLOB NOT NULL CHECK (typeof(source_mac) = 'blob' AND length(source_mac) = 6),
                 channel INTEGER NOT NULL CHECK (channel BETWEEN 1 AND 14),
                 secondary INTEGER NOT NULL CHECK (secondary BETWEEN 0 AND 2),
                 phy INTEGER NOT NULL CHECK (phy BETWEEN 1 AND 2),
                 bandwidth INTEGER NOT NULL CHECK (bandwidth BETWEEN 1 AND 2),
                 stbc INTEGER NOT NULL CHECK (stbc IN (0, 1)),
                 rate INTEGER NOT NULL CHECK (rate BETWEEN 0 AND 255),
                 mcs INTEGER NOT NULL CHECK (mcs BETWEEN 0 AND 255),
                 rx_antenna INTEGER NOT NULL CHECK (rx_antenna BETWEEN 0 AND 1),
                 firmware_build_digest BLOB NOT NULL CHECK (typeof(firmware_build_digest) = 'blob' AND length(firmware_build_digest) = 32),
                 capability_digest BLOB NOT NULL CHECK (typeof(capability_digest) = 'blob' AND length(capability_digest) = 32),
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
const NATIVE_CAPABILITY_FACTS_SCHEMA: &str = "CREATE TABLE native_capability_facts (
                 fact_id INTEGER PRIMARY KEY REFERENCES raw_facts(fact_id),
                 capability_digest BLOB NOT NULL CHECK (typeof(capability_digest) = 'blob' AND length(capability_digest) = 32),
                 firmware_build_digest BLOB NOT NULL CHECK (typeof(firmware_build_digest) = 'blob' AND length(firmware_build_digest) = 32),
                 idf_wifi_abi_digest BLOB NOT NULL CHECK (typeof(idf_wifi_abi_digest) = 'blob' AND length(idf_wifi_abi_digest) = 32),
                 datagram_budget_bytes INTEGER NOT NULL CHECK (datagram_budget_bytes BETWEEN 753 AND 65535)
             ) STRICT";
const NATIVE_CSI_FACTS_SCHEMA: &str = "CREATE TABLE native_csi_facts (
                 fact_id INTEGER PRIMARY KEY REFERENCES raw_facts(fact_id),
                 capability_digest BLOB NOT NULL CHECK (typeof(capability_digest) = 'blob' AND length(capability_digest) = 32),
                 capture_sequence BLOB NOT NULL CHECK (typeof(capture_sequence) = 'blob' AND length(capture_sequence) = 8 AND capture_sequence <> zeroblob(8)),
                 driver_rx_timestamp_us INTEGER NOT NULL CHECK (driver_rx_timestamp_us BETWEEN 0 AND 4294967295),
                 callback_tick_us BLOB NOT NULL CHECK (typeof(callback_tick_us) = 'blob' AND length(callback_tick_us) = 8),
                 source_mac BLOB NOT NULL CHECK (typeof(source_mac) = 'blob' AND length(source_mac) = 6),
                 channel INTEGER NOT NULL CHECK (channel BETWEEN 1 AND 14),
                 secondary INTEGER NOT NULL CHECK (secondary BETWEEN 0 AND 2),
                 phy INTEGER NOT NULL CHECK (phy BETWEEN 1 AND 2),
                 bandwidth INTEGER NOT NULL CHECK (bandwidth BETWEEN 1 AND 2),
                 stbc INTEGER NOT NULL CHECK (stbc IN (0, 1)),
                 rssi_dbm INTEGER NOT NULL CHECK (rssi_dbm BETWEEN -128 AND 127),
                 noise_floor_dbm INTEGER NOT NULL CHECK (noise_floor_dbm BETWEEN -128 AND 127),
                 rate INTEGER NOT NULL CHECK (rate BETWEEN 0 AND 255),
                 mcs INTEGER NOT NULL CHECK (mcs BETWEEN 0 AND 255),
                 rx_antenna INTEGER NOT NULL CHECK (rx_antenna BETWEEN 0 AND 1),
                 first_invalid_bytes INTEGER NOT NULL CHECK (first_invalid_bytes IN (0, 4)),
                 trailing_invalid_bytes INTEGER NOT NULL CHECK (trailing_invalid_bytes IN (0, 2)),
                 complex_sample_count INTEGER NOT NULL CHECK (complex_sample_count BETWEEN 1 AND 65535),
                 blocks BLOB NOT NULL CHECK (typeof(blocks) = 'blob' AND length(blocks) BETWEEN 6 AND 18 AND length(blocks) % 6 = 0),
                 raw_csi BLOB NOT NULL CHECK (typeof(raw_csi) = 'blob' AND length(raw_csi) <= 612)
             ) STRICT";
const NATIVE_HEALTH_FACTS_SCHEMA: &str = "CREATE TABLE native_health_facts (
                 fact_id INTEGER PRIMARY KEY REFERENCES raw_facts(fact_id),
                 capability_digest BLOB NOT NULL CHECK (typeof(capability_digest) = 'blob' AND length(capability_digest) = 32),
                 callback_tick_us BLOB NOT NULL CHECK (typeof(callback_tick_us) = 'blob' AND length(callback_tick_us) = 8),
                 capture_seen BLOB NOT NULL CHECK (typeof(capture_seen) = 'blob' AND length(capture_seen) = 8),
                 queue_drop_no_slot BLOB NOT NULL CHECK (typeof(queue_drop_no_slot) = 'blob' AND length(queue_drop_no_slot) = 8),
                 queue_drop_full BLOB NOT NULL CHECK (typeof(queue_drop_full) = 'blob' AND length(queue_drop_full) = 8),
                 oversize_reject BLOB NOT NULL CHECK (typeof(oversize_reject) = 'blob' AND length(oversize_reject) = 8),
                 encode_reject BLOB NOT NULL CHECK (typeof(encode_reject) = 'blob' AND length(encode_reject) = 8),
                 send_failure BLOB NOT NULL CHECK (typeof(send_failure) = 'blob' AND length(send_failure) = 8),
                 pool_high_water_slots INTEGER NOT NULL CHECK (pool_high_water_slots BETWEEN 0 AND 65535),
                 callback_max_us INTEGER NOT NULL CHECK (callback_max_us BETWEEN 0 AND 4294967295),
                 encoder_max_us INTEGER NOT NULL CHECK (encoder_max_us BETWEEN 0 AND 4294967295)
             ) STRICT";
const SPATIAL_ARTIFACTS_SCHEMA: &str = "CREATE TABLE spatial_artifacts (
                 artifact_row_id INTEGER PRIMARY KEY,
                 digest BLOB NOT NULL UNIQUE CHECK (typeof(digest) = 'blob' AND length(digest) = 32),
                 kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 3),
                 artifact_id TEXT NOT NULL CHECK (length(artifact_id) > 0),
                 revision INTEGER NOT NULL CHECK (revision BETWEEN 0 AND 4294967295),
                 imported_utc_ns INTEGER NOT NULL CHECK (imported_utc_ns >= 0),
                 origin TEXT NOT NULL CHECK (origin IN ('local', 'companion')),
                 sealed_bytes BLOB NOT NULL CHECK (typeof(sealed_bytes) = 'blob'),
                 UNIQUE (kind, artifact_id, revision)
             ) STRICT";
const EXPECTED_SCHEMA: [(&str, &str); 9] = [
    ("store_identity", STORE_IDENTITY_SCHEMA),
    ("replay_windows", REPLAY_WINDOWS_SCHEMA),
    ("native_route_pins", NATIVE_ROUTE_PINS_SCHEMA),
    ("raw_facts", RAW_FACTS_SCHEMA),
    ("raw_losses", RAW_LOSSES_SCHEMA),
    ("native_capability_facts", NATIVE_CAPABILITY_FACTS_SCHEMA),
    ("native_csi_facts", NATIVE_CSI_FACTS_SCHEMA),
    ("native_health_facts", NATIVE_HEALTH_FACTS_SCHEMA),
    ("spatial_artifacts", SPATIAL_ARTIFACTS_SCHEMA),
];
// SQLite owns these implicit indexes for the declared UNIQUE and composite
// PRIMARY KEY constraints. Their exact names, owning tables, and NULL SQL are
// part of schema generation 4; any other SQLite-owned object is unrecognized.
const EXPECTED_SQLITE_AUTO_INDEXES: [(&str, &str); 5] = [
    ("sqlite_autoindex_raw_facts_1", "raw_facts"),
    ("sqlite_autoindex_replay_windows_1", "replay_windows"),
    ("sqlite_autoindex_native_route_pins_1", "native_route_pins"),
    ("sqlite_autoindex_spatial_artifacts_1", "spatial_artifacts"),
    ("sqlite_autoindex_spatial_artifacts_2", "spatial_artifacts"),
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
        getrandom::fill(bytes).map_err(io::Error::other)
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
pub struct Store {
    root: PathBuf,
    id: StoreId,
    companion_signing_seed: Option<CompanionSigningSeed>,
    lease: File,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CompanionSigningSeed([u8; 32]);

impl CompanionSigningSeed {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CompanionSigningSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompanionSigningSeed([REDACTED])")
    }
}

impl fmt::Debug for Store {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Store")
            .field("root", &self.root)
            .field("id", &self.id)
            .field("companion_signing_seed", &"[REDACTED]")
            .finish_non_exhaustive()
    }
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
            let companion_signing_seed = random_companion_signing_seed(entropy)?;
            write_companion_signing_seed(root, &companion_signing_seed)?;
            let database_path = root.join(DATABASE_NAME);
            initialize_database(&database_path, id)?;
            sync_directory(root)?;
            Ok(Self {
                root: root.to_owned(),
                id,
                companion_signing_seed: Some(companion_signing_seed),
                lease,
            })
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
            let companion_signing_seed = read_companion_signing_seed(root)?;
            let lease = acquire_lease(root, false)?;
            let wal_path = database_path.with_extension("sqlite3-wal");
            let shm_path = database_path.with_extension("sqlite3-shm");
            validate_optional_regular_file(&wal_path)?;
            validate_optional_regular_file(&shm_path)?;
            validate_wal_shape(&wal_path)?;
            validate_shm_shape(&shm_path, wal_path.exists())?;
            let id = validate_database_snapshot(&database_path, &wal_path, &shm_path, entropy)?;
            Ok(Self {
                root: root.to_owned(),
                id,
                companion_signing_seed: Some(companion_signing_seed),
                lease,
            })
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

    pub(crate) fn take_companion_signing_seed(&mut self) -> CompanionSigningSeed {
        self.companion_signing_seed
            .take()
            .expect("a Store transfers its companion signing seed only once")
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

fn random_companion_signing_seed(
    entropy: &dyn Entropy,
) -> Result<CompanionSigningSeed, StoreError> {
    let mut seed = CompanionSigningSeed::new([0; 32]);
    entropy.fill(&mut seed.0).map_err(|source| io_error(entropy.source_path(), source))?;
    Ok(seed)
}

fn write_companion_signing_seed(
    root: &Path,
    signing_seed: &CompanionSigningSeed,
) -> Result<(), StoreError> {
    let path = root.join(COMPANION_SIGNING_SEED_NAME);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(FILE_MODE).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&path).map_err(|source| io_error(&path, source))?;
    use std::io::Write;
    file.write_all(signing_seed.as_bytes()).map_err(|source| io_error(&path, source))?;
    set_file_permissions(&path)?;
    file.sync_all().map_err(|source| io_error(&path, source))
}

fn read_companion_signing_seed(root: &Path) -> Result<CompanionSigningSeed, StoreError> {
    let path = root.join(COMPANION_SIGNING_SEED_NAME);
    validate_regular_file(&path)?;
    let mut signing_seed = CompanionSigningSeed::new([0; 32]);
    let mut file = File::open(&path).map_err(|source| io_error(&path, source))?;
    if let Err(source) = file.read_exact(&mut signing_seed.0) {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            return Err(StoreErrorKind::Unrecognized.into());
        }
        return Err(io_error(&path, source));
    }
    let mut trailing = [0_u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(signing_seed),
        Ok(_) => Err(StoreErrorKind::Unrecognized.into()),
        Err(source) => Err(io_error(&path, source)),
    }
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
    use std::error::Error as _;
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
        assert!(std::mem::needs_drop::<CompanionSigningSeed>());
        let mut disposable_seed = CompanionSigningSeed::new([0xab; 32]);
        assert_eq!(format!("{disposable_seed:?}"), "CompanionSigningSeed([REDACTED])");
        disposable_seed.zeroize();
        assert_eq!(disposable_seed.as_bytes(), &[0; 32]);

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

    #[test]
    fn signing_seed_open_failure_retains_seed_path_and_io_source() {
        let root = root("signing-seed-open-failure");
        fs::create_dir(&root).unwrap();
        write_companion_signing_seed(&root, &CompanionSigningSeed::new([1; 32])).unwrap();

        let error =
            write_companion_signing_seed(&root, &CompanionSigningSeed::new([2; 32])).unwrap_err();
        let expected_path = root.join(COMPANION_SIGNING_SEED_NAME);
        assert!(error.to_string().contains(expected_path.to_str().unwrap()));
        assert_eq!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<io::Error>())
                .map(io::Error::kind),
            Some(io::ErrorKind::AlreadyExists)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn signing_seed_chmod_failure_is_an_io_error_with_seed_path() {
        let root = root("signing-seed-chmod-failure");
        fs::create_dir(&root).unwrap();
        let seed_path = root.join(COMPANION_SIGNING_SEED_NAME);

        let error = set_file_permissions(&seed_path).unwrap_err();
        assert!(error.to_string().contains(seed_path.to_str().unwrap()));
        assert!(error.source().and_then(|source| source.downcast_ref::<io::Error>()).is_some());
        fs::remove_dir_all(root).unwrap();
    }
}
