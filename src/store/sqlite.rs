//! SQLite implementation of the Store interfaces.

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ciborium::ser::into_writer;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::managed::{ManagedRoot, ManagedStage, ManagedStoreError, fill_random};
use super::query::{QueryError, QueryStore};
use crate::Config;
use crate::database::{
    Admission, DatabaseError, EpochHandle, ReplayWindowIdentity, advance_admission,
};
use crate::domain::identity::{DeviceId, HardwareKind, KeyEpoch};
use crate::hex;
use crate::wire::{CandidateBody, WireCandidate};
use crate::{
    CaptureRecordSequence, CommitOutcome, CommitReceipt, PacketDisposition, ProjectionSequence,
};

// `WSPD` is the SQLite application identity. Changing it makes every existing
// Store incompatible.
const STORE_APPLICATION_ID: i64 = 0x5753_5044;
// Store schema version 1 is exact. Bump only with an explicit migration
// contract; the current delivery path intentionally performs no migration.
const STORE_USER_VERSION: i64 = 1;
// Host persistence v1 defines Store IDs as 32 operating-system-random bytes.
const STORE_ID_BYTES: usize = 32;
// Capture Session IDs use 16 random bytes rendered as 32 lowercase hexadecimal
// digits after this exact prefix.
const CAPTURE_SESSION_RANDOM_BYTES: usize = 16;
const CAPTURE_SESSION_ID_PREFIX: &str = "capture-";
// A new Store initializes its eight-byte big-endian Projection watermark to zero.
const PROJECTION_SEQUENCE_ZERO: [u8; 8] = [0; 8];
// SQLite reports synchronous=FULL as numeric pragma value 2. Changing this
// comparison would reject the Store's required durability mode.
const SQLITE_SYNCHRONOUS_FULL: i64 = 2;
// Host persistence v1 fixes StoreTopologyManifestV1 schema to 1. Changing it
// changes digest-covered bytes and makes every existing Store incompatible.
const TOPOLOGY_MANIFEST_SCHEMA_VERSION: u8 = 1;
// These Capture Session compatibility identities name the decoder and ingest
// behavior used for newly committed observations.
const DECODER_VERSION: &str = "native-frame-v1";
const CAPTURE_ALGORITHM_VERSION: &str = "native-coordinate-ingest-v1";
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionEpochSeed {
    pub(crate) device: DeviceId,
    pub(crate) key_epoch: KeyEpoch,
    pub(crate) replay_window_identity: ReplayWindowIdentity,
    pub(crate) replay_window_size: u16,
}

/// One validated Store and its retained Managed-root lifecycle lease.
#[derive(Debug)]
pub(crate) struct Store {
    managed: Arc<ManagedRoot>,
}

impl Store {
    pub(crate) fn acquire_for_initialization(config: &Config) -> Result<Self, StoreError> {
        let managed = ManagedRoot::acquire_for_initialization(config.session().database_path())?;
        Ok(Self { managed: Arc::new(managed) })
    }

    pub(crate) fn initialize(
        self,
        config: &Config,
        admissions: Vec<AdmissionEpochSeed>,
    ) -> Result<(), StoreError> {
        let stage = self.managed.create_stage()?;
        let stage_identity = stage.identity();
        let initialized = initialize_stage(&stage, config, admissions)?;
        let final_path = self.managed.publish(stage)?;
        if let Err(error) = initialized.validate(&final_path) {
            self.managed.remove_published_if_owned(stage_identity)?;
            return Err(error);
        }
        if let Err(error) = self.managed.finish_closed_database() {
            self.managed.remove_published_if_owned(stage_identity)?;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) fn acquire_existing(config: &Config) -> Result<Self, StoreError> {
        let managed = ManagedRoot::acquire_existing(config.session().database_path())?;
        Ok(Self { managed: Arc::new(managed) })
    }

    pub(crate) fn create_capture_session(
        &self,
        config: &Config,
        admissions: Vec<AdmissionEpochSeed>,
    ) -> Result<CaptureSession, StoreError> {
        open_and_create_capture_session(self.managed.database_path(), config, admissions)
    }

    pub(crate) fn query_store(&self) -> Result<QueryStore, QueryError> {
        QueryStore::from_managed(Arc::clone(&self.managed))
    }
}

pub(crate) struct StoreError {
    inner: Box<StoreErrorInner>,
}

struct StoreErrorInner {
    source: StoreErrorKind,
    backtrace: Backtrace,
}

impl fmt::Debug for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreError")
            .field("source", &self.inner.source)
            .field("backtrace", &self.inner.backtrace)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
enum StoreErrorKind {
    #[error("Store SQLite operation failed: {0}")]
    Sql(#[source] rusqlite::Error),
    #[error("Store configuration encoding failed")]
    Config(#[source] crate::ConfigError),
    #[error("Store topology encoding failed")]
    Topology(String),
    #[error("Store identity, schema, settings, or initial rows are incompatible")]
    Incompatible,
    #[error("Store WAL checkpoint did not fully complete")]
    Checkpoint,
    #[error("current UTC time cannot be represented as a capture timestamp")]
    Clock,
    #[error("Store replay admission failed: {0}")]
    Admission(#[source] DatabaseError),
    #[error("Managed Store operation failed: {0}")]
    Managed(#[source] ManagedStoreError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.source.fmt(formatter)
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.inner.source)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(source: rusqlite::Error) -> Self {
        Self::new(StoreErrorKind::Sql(source))
    }
}

impl From<crate::ConfigError> for StoreError {
    fn from(source: crate::ConfigError) -> Self {
        Self::new(StoreErrorKind::Config(source))
    }
}

impl From<ManagedStoreError> for StoreError {
    fn from(source: ManagedStoreError) -> Self {
        Self::new(StoreErrorKind::Managed(source))
    }
}

impl StoreError {
    fn new(source: StoreErrorKind) -> Self {
        Self { inner: Box::new(StoreErrorInner { source, backtrace: Backtrace::capture() }) }
    }

    fn incompatible() -> Self {
        Self::new(StoreErrorKind::Incompatible)
    }

    fn admission(source: DatabaseError) -> Self {
        Self::new(StoreErrorKind::Admission(source))
    }

    fn checkpoint() -> Self {
        Self::new(StoreErrorKind::Checkpoint)
    }

    fn clock() -> Self {
        Self::new(StoreErrorKind::Clock)
    }

    fn topology(message: String) -> Self {
        Self::new(StoreErrorKind::Topology(message))
    }

    pub(crate) const fn is_lease_conflict(&self) -> bool {
        matches!(self.inner.source, StoreErrorKind::Managed(ManagedStoreError::LeaseConflict))
    }
}

#[derive(Debug)]
struct InitializedStore {
    expected: ExpectedStore,
    store_id: [u8; STORE_ID_BYTES],
}

impl InitializedStore {
    pub(crate) fn validate(&self, path: &Path) -> Result<(), StoreError> {
        validate_closed(path, &self.expected, self.store_id)
    }
}

#[derive(Clone, Debug)]
struct ExpectedStore {
    topology: Vec<u8>,
    topology_digest: [u8; 32],
    replay: Vec<u8>,
    replay_digest: [u8; 32],
    admissions: Vec<AdmissionEpochSeed>,
}

#[derive(Debug)]
pub(crate) struct CaptureSession {
    store_id: [u8; STORE_ID_BYTES],
    session_id: String,
    monotonic_origin: Instant,
    connection: Connection,
    admissions: Vec<AdmissionEpochSeed>,
    config: Config,
}

impl CaptureSession {
    pub(crate) const fn store_id(&self) -> [u8; STORE_ID_BYTES] {
        self.store_id
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) const fn monotonic_origin(&self) -> Instant {
        self.monotonic_origin
    }

    pub(crate) fn commit(&mut self, candidate: WireCandidate) -> Result<CommitOutcome, StoreError> {
        self.commit_inner(candidate, false)
    }

    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) fn commit_with_domain_rejection(
        &mut self,
        candidate: WireCandidate,
    ) -> Result<CommitOutcome, StoreError> {
        self.commit_inner(candidate, true)
    }

    fn commit_inner(
        &mut self,
        candidate: WireCandidate,
        reject_csi_domain: bool,
    ) -> Result<CommitOutcome, StoreError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (cursor, previous_time, session_projection) = transaction
            .query_row(
                "SELECT committed_through_record_seq, last_session_time_ns, projection_commit_seq
                 FROM capture_sessions WHERE session_id = ?1",
                [&self.session_id],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::incompatible())?;
        let watermark: Vec<u8> = transaction
            .query_row(
                "SELECT projection_commit_seq FROM store_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::incompatible())?;
        let watermark = ProjectionSequence::new(decode_u64(&watermark)?);

        let route = candidate.header_route();
        let admission = self
            .admissions
            .iter()
            .find(|admission| {
                admission.device == route.device() && admission.key_epoch == route.key_epoch()
            })
            .ok_or(StoreError::incompatible())?;
        let epoch = EpochHandle::new(
            admission.device,
            admission.key_epoch,
            admission.replay_window_identity,
            admission.replay_window_size,
        );
        let header = candidate.header();
        match advance_admission(
            &transaction,
            Admission::new(&epoch, header.boot_generation(), header.message_seq()),
        ) {
            Ok(()) => {}
            Err(DatabaseError::Replay) => return Ok(CommitOutcome::ReplayRejected),
            Err(error) => return Err(StoreError::admission(error)),
        }

        let (record_sequence, previous_projection) = match (&cursor, &previous_time) {
            (None, None) => {
                if session_projection.is_some() {
                    return Err(StoreError::incompatible());
                }
                (CaptureRecordSequence::new(0), None)
            }
            (Some(cursor), Some(previous_time)) => {
                let cursor = CaptureRecordSequence::new(decode_u64(cursor)?);
                let previous_time =
                    crate::domain::time::SessionTime::from_nanos(decode_u64(previous_time)?);
                if candidate.session_time() < previous_time {
                    return Err(StoreError::incompatible());
                }
                let next = cursor.checked_next().ok_or(StoreError::incompatible())?;
                (next, session_projection.as_deref())
            }
            _ => return Err(StoreError::incompatible()),
        };
        if let Some(previous_projection) = previous_projection
            && ProjectionSequence::new(decode_u64(previous_projection)?) != watermark
        {
            return Err(StoreError::incompatible());
        }
        let projection_sequence = watermark.checked_next().ok_or(StoreError::incompatible())?;
        let mut capability_row = None;
        let mut observation_row = None;
        let disposition = match candidate.body() {
            CandidateBody::UnknownKind { .. } => PacketDisposition::UnknownKind,
            CandidateBody::MalformedKnownBody => PacketDisposition::MalformedKnownBody,
            CandidateBody::Capabilities(capability) => {
                let resolved = self
                    .config
                    .registry()
                    .resolve_authenticated_route(route)
                    .map_err(|_| StoreError::incompatible())?;
                if capability.descriptor().firmware_build_digest()
                    != resolved.sensor.firmware_build_digest()
                {
                    PacketDisposition::BuildMismatch
                } else if capability.capability_digest() != resolved.sensor.capability_digest()
                    || capability.descriptor().datagram_budget_bytes()
                        > resolved.route.admission_limits().maximum_datagram_bytes()
                {
                    PacketDisposition::CapabilityPinMismatch
                } else {
                    capability_row =
                        Some((capability.capability_digest(), capability.descriptor().to_bytes()));
                    PacketDisposition::CapabilityCommitted
                }
            }
            CandidateBody::Health(health) => {
                let resolved = self
                    .config
                    .registry()
                    .resolve_authenticated_route(route)
                    .map_err(|_| StoreError::incompatible())?;
                if health.capability_digest() == resolved.sensor.capability_digest() {
                    PacketDisposition::HealthCommitted
                } else {
                    PacketDisposition::CapabilityMismatch
                }
            }
            CandidateBody::CsiData(data) => {
                let capability_row = transaction
                    .query_row(
                        "SELECT capability_digest, descriptor_bytes FROM capability_epochs
                         WHERE device_id = ?1 AND key_epoch = ?2 AND boot_generation = ?3",
                        params![
                            header.device_id().to_be_bytes(),
                            header.key_epoch().to_be_bytes(),
                            header.boot_generation().to_be_bytes(),
                        ],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )
                    .optional()?;
                if let Some((digest, descriptor)) = capability_row {
                    let capability =
                        crate::wire::CapabilitiesV1::from_persisted(&digest, &descriptor)
                            .map_err(|_| StoreError::incompatible())?;
                    let resolved = self
                        .config
                        .registry()
                        .resolve_authenticated_route(route)
                        .map_err(|_| StoreError::incompatible())?;
                    let radio = data.radio();
                    let plaintext_bytes = crate::wire::CSI_FIXED_BODY_BYTES
                        .checked_add(
                            data.blocks()
                                .len()
                                .checked_mul(crate::wire::LTF_BLOCK_BYTES)
                                .ok_or(StoreError::incompatible())?,
                        )
                        .and_then(|bytes| bytes.checked_add(data.raw_csi().len()))
                        .ok_or(StoreError::incompatible())?;
                    if capability.descriptor().firmware_build_digest()
                        != resolved.sensor.firmware_build_digest()
                    {
                        PacketDisposition::BuildMismatch
                    } else if capability.capability_digest() != resolved.sensor.capability_digest()
                        || data.capability_digest() != capability.capability_digest()
                    {
                        PacketDisposition::CapabilityMismatch
                    } else if data.source_mac() != resolved.link.expected_transmitter_mac() {
                        PacketDisposition::SourceMismatch
                    } else if !resolved.link.channel_policy().allowed().contains(&radio.channel())
                        || resolved
                            .link
                            .channel_policy()
                            .expected()
                            .is_some_and(|expected| expected != radio.channel())
                    {
                        PacketDisposition::RadioMismatch
                    } else if data.raw_csi().len()
                        > usize::from(resolved.sensor.maximum_raw_csi_bytes())
                        || plaintext_bytes > usize::from(resolved.sensor.maximum_plaintext_bytes())
                    {
                        PacketDisposition::BodyBudgetMismatch
                    } else if reject_csi_domain {
                        PacketDisposition::DecodedDomainRejected
                    } else {
                        let input = crate::wire::ObservationCandidateInput::try_new(
                            &self.session_id,
                            record_sequence,
                            candidate.session_time(),
                        )
                        .map_err(|_| StoreError::incompatible())?;
                        match crate::wire::resolve_capture_csi(
                            input,
                            route,
                            header,
                            self.config.registry(),
                            data.clone(),
                            &capability,
                        ) {
                            Ok((profile, observation)) => {
                                let observation_cbor = crate::timeline::encode_csi_observation_root(
                                    self.config.replay().digest(),
                                    self.config.conditioning().version().as_str(),
                                    &observation,
                                );
                                observation_row = Some((
                                    observation.sensor().as_str().to_owned(),
                                    observation.link().as_str().to_owned(),
                                    profile.id().as_bytes(),
                                    observation_cbor,
                                ));
                                PacketDisposition::CsiCommitted
                            }
                            Err(_) => PacketDisposition::DecodedDomainRejected,
                        }
                    }
                } else {
                    PacketDisposition::CapabilityUnavailable
                }
            }
        };

        transaction.execute(
            "INSERT INTO packet_records
             (session_id, record_seq, session_time_ns, receive_utc_ns, peer_ip, peer_port,
              device_id, key_epoch, boot_generation, message_sequence, message_kind,
              disposition, encrypted_datagram)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &self.session_id,
                record_sequence.to_be_bytes(),
                candidate.session_time().as_nanos().to_be_bytes(),
                candidate.receive_utc_ns().to_be_bytes(),
                candidate.peer().ip().to_string(),
                candidate.peer().port(),
                header.device_id().to_be_bytes(),
                header.key_epoch().to_be_bytes(),
                header.boot_generation().to_be_bytes(),
                header.message_seq().to_be_bytes(),
                header.kind_byte(),
                disposition.as_store_text(),
                candidate.bytes(),
            ],
        )?;
        if let Some((digest, descriptor)) = capability_row {
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO capability_epochs
                 (device_id, key_epoch, boot_generation, capability_digest, descriptor_bytes,
                  first_session_id, first_record_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    header.device_id().to_be_bytes(),
                    header.key_epoch().to_be_bytes(),
                    header.boot_generation().to_be_bytes(),
                    digest,
                    descriptor,
                    &self.session_id,
                    record_sequence.to_be_bytes(),
                ],
            )?;
            if inserted == 0 {
                let existing: (Vec<u8>, Vec<u8>) = transaction
                    .query_row(
                        "SELECT capability_digest, descriptor_bytes FROM capability_epochs
                         WHERE device_id = ?1 AND key_epoch = ?2 AND boot_generation = ?3",
                        params![
                            header.device_id().to_be_bytes(),
                            header.key_epoch().to_be_bytes(),
                            header.boot_generation().to_be_bytes(),
                        ],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?
                    .ok_or(StoreError::incompatible())?;
                if existing.0.as_slice() != digest || existing.1.as_slice() != descriptor {
                    return Err(StoreError::incompatible());
                }
            }
        }
        if let Some((sensor, link, profile, observation_cbor)) = observation_row {
            transaction.execute(
                "INSERT INTO csi_observations
                 (session_id, record_seq, session_time_ns, sensor_id, link_id, profile_id,
                  observation_cbor, decoder_version, conditioning_version, replay_config_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    &self.session_id,
                    record_sequence.to_be_bytes(),
                    candidate.session_time().as_nanos().to_be_bytes(),
                    sensor,
                    link,
                    profile,
                    observation_cbor,
                    DECODER_VERSION,
                    self.config.conditioning().version().as_str(),
                    self.config.replay().digest(),
                ],
            )?;
        }
        let updated_session = transaction.execute(
            "UPDATE capture_sessions
             SET committed_through_record_seq = ?1, last_session_time_ns = ?2,
                 projection_commit_seq = ?3
             WHERE session_id = ?4
               AND committed_through_record_seq IS ?5
               AND last_session_time_ns IS ?6
               AND projection_commit_seq IS ?7",
            params![
                record_sequence.to_be_bytes(),
                candidate.session_time().as_nanos().to_be_bytes(),
                projection_sequence.to_be_bytes(),
                &self.session_id,
                cursor,
                previous_time,
                session_projection,
            ],
        )?;
        if updated_session != 1 {
            return Err(StoreError::incompatible());
        }
        let updated_store = transaction.execute(
            "UPDATE store_state SET projection_commit_seq = ?1
             WHERE singleton = 1 AND projection_commit_seq = ?2",
            params![projection_sequence.to_be_bytes(), watermark.to_be_bytes()],
        )?;
        if updated_store != 1 {
            return Err(StoreError::incompatible());
        }
        transaction.commit()?;
        Ok(CommitOutcome::Committed(CommitReceipt::new(
            disposition,
            record_sequence,
            projection_sequence,
        )))
    }
}

fn initialize_stage(
    stage: &ManagedStage,
    config: &Config,
    admissions: Vec<AdmissionEpochSeed>,
) -> Result<InitializedStore, StoreError> {
    let replay = config.replay().canonical_bytes()?;
    let replay_digest = config.replay().digest();
    let topology = encode_topology(config)?;
    let topology_digest = Sha256::digest(&topology).into();
    let mut store_id = [0_u8; STORE_ID_BYTES];
    fill_random(&mut store_id)?;
    let expected = ExpectedStore { topology, topology_digest, replay, replay_digest, admissions };

    let mut connection = Connection::open_with_flags(
        stage.path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    configure_writer(&connection)?;
    verify_journal_mode(&connection)?;
    verify_connection(&connection, ConnectionKind::Writer)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(STORE_SCHEMA)?;
    transaction.pragma_update(None, "application_id", STORE_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", STORE_USER_VERSION)?;
    transaction.execute(
        "INSERT INTO store_state
         (singleton, store_id, topology_manifest_cbor, topology_manifest_digest,
          replay_config_cbor, replay_config_digest, projection_commit_seq)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            store_id,
            expected.topology,
            expected.topology_digest,
            expected.replay,
            expected.replay_digest,
            PROJECTION_SEQUENCE_ZERO,
        ],
    )?;
    for admission in &expected.admissions {
        let bitmap = vec![0_u8; usize::from(admission.replay_window_size).div_ceil(8)];
        transaction.execute(
            "INSERT INTO admission_epochs
             (device_id, key_epoch, replay_window_identity, replay_window_size,
              highest_boot_generation, maximum_message_sequence, seen_bitmap)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
            params![
                admission.device.get().to_be_bytes(),
                admission.key_epoch.get().to_be_bytes(),
                admission.replay_window_identity.as_bytes(),
                admission.replay_window_size,
                bitmap,
            ],
        )?;
    }
    transaction.commit()?;

    let (busy, log_frames, checkpointed): (u32, u32, u32) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 || log_frames != checkpointed {
        return Err(StoreError::checkpoint());
    }
    connection.close().map_err(|(_, error)| StoreError::from(error))?;
    stage.sync()?;
    validate_closed(stage.path(), &expected, store_id)?;
    Ok(InitializedStore { expected, store_id })
}

fn open_and_create_capture_session(
    path: &Path,
    config: &Config,
    admissions: Vec<AdmissionEpochSeed>,
) -> Result<CaptureSession, StoreError> {
    let monotonic_origin = Instant::now();
    let replay = config.replay().canonical_bytes()?;
    let replay_digest = config.replay().digest();
    let topology = encode_topology(config)?;
    let topology_digest = Sha256::digest(&topology).into();
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::ZERO)?;
    verify_persistent_settings(&connection)?;
    configure_writer(&connection)?;
    verify_connection(&connection, ConnectionKind::Writer)?;
    validate_schema(&connection)?;
    let expected = ExpectedStore { topology, topology_digest, replay, replay_digest, admissions };
    let store_id = validate_state(&connection, &expected, AdmissionExpectation::Existing)?;

    let started_utc_ns =
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| StoreError::clock())?.as_nanos();
    let started_utc_ns =
        u64::try_from(started_utc_ns).map_err(|_| StoreError::clock())?.to_be_bytes();
    let mut random = [0_u8; CAPTURE_SESSION_RANDOM_BYTES];
    fill_random(&mut random)?;
    let session_id = format!("{CAPTURE_SESSION_ID_PREFIX}{}", hex::encode(&random));
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO capture_sessions
         (session_id, started_utc_ns, replay_config_digest, decoder_version,
          conditioning_version, algorithm_version, committed_through_record_seq,
          last_session_time_ns, projection_commit_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL)",
        params![
            &session_id,
            started_utc_ns,
            expected.replay_digest,
            DECODER_VERSION,
            config.conditioning().version().as_str(),
            CAPTURE_ALGORITHM_VERSION,
        ],
    )?;
    transaction.commit()?;
    Ok(CaptureSession {
        store_id,
        session_id,
        monotonic_origin,
        connection,
        admissions: expected.admissions,
        config: config.clone(),
    })
}

fn decode_u64(bytes: &[u8]) -> Result<u64, StoreError> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| StoreError::incompatible())?;
    Ok(u64::from_be_bytes(bytes))
}

fn validate_closed(
    path: &Path,
    expected: &ExpectedStore,
    expected_store_id: [u8; STORE_ID_BYTES],
) -> Result<(), StoreError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "query_only", true)?;
    verify_persistent_settings(&connection)?;
    verify_connection(&connection, ConnectionKind::Reader)?;
    validate_schema(&connection)?;
    let store_id = validate_state(&connection, expected, AdmissionExpectation::Empty)?;
    if store_id != expected_store_id {
        return Err(StoreError::incompatible());
    }
    connection.close().map_err(|(_, error)| StoreError::from(error))?;
    Ok(())
}

pub(super) fn open_query_reader(path: &Path) -> Result<Connection, StoreError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "query_only", true)?;
    verify_persistent_settings(&connection)?;
    verify_connection(&connection, ConnectionKind::Reader)?;
    validate_schema(&connection)?;
    Ok(connection)
}

fn configure_writer(connection: &Connection) -> Result<(), StoreError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum ConnectionKind {
    Writer,
    Reader,
}

fn verify_persistent_settings(connection: &Connection) -> Result<(), StoreError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != STORE_APPLICATION_ID || user_version != STORE_USER_VERSION {
        return Err(StoreError::incompatible());
    }
    verify_journal_mode(connection)
}

fn verify_journal_mode(connection: &Connection) -> Result<(), StoreError> {
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::incompatible());
    }
    Ok(())
}

fn verify_connection(connection: &Connection, kind: ConnectionKind) -> Result<(), StoreError> {
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    if foreign_keys != 1 || trusted_schema != 0 {
        return Err(StoreError::incompatible());
    }
    match kind {
        ConnectionKind::Writer => {
            let synchronous: i64 =
                connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
            if synchronous != SQLITE_SYNCHRONOUS_FULL {
                return Err(StoreError::incompatible());
            }
        }
        ConnectionKind::Reader => {
            let query_only: i64 =
                connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
            if query_only != 1 {
                return Err(StoreError::incompatible());
            }
        }
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), StoreError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(STORE_SCHEMA)?;
    if read_schema(connection)? != read_schema(&expected)? {
        return Err(StoreError::incompatible());
    }
    Ok(())
}

fn read_schema(
    connection: &Connection,
) -> Result<Vec<(String, String, String, String)>, StoreError> {
    Ok(connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE type IN ('table', 'index', 'view', 'trigger')
               AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
        .collect::<Result<Vec<_>, _>>()?)
}

#[derive(Clone, Copy)]
enum AdmissionExpectation {
    Empty,
    Existing,
}

#[derive(Debug)]
struct StoreStateRow {
    store_id: Vec<u8>,
    topology_manifest: Vec<u8>,
    topology_digest: Vec<u8>,
    replay_config: Vec<u8>,
    replay_digest: Vec<u8>,
    projection_commit_sequence: Vec<u8>,
}

#[derive(Debug)]
struct AdmissionStateRow {
    device_id: Vec<u8>,
    key_epoch: Vec<u8>,
    replay_window_identity: Vec<u8>,
    replay_window_size: u16,
    highest_boot_generation: Option<Vec<u8>>,
    maximum_message_sequence: Option<Vec<u8>>,
    seen_bitmap: Vec<u8>,
}

fn validate_state(
    connection: &Connection,
    expected: &ExpectedStore,
    admission_expectation: AdmissionExpectation,
) -> Result<[u8; STORE_ID_BYTES], StoreError> {
    let state = connection
        .query_row(
            "SELECT store_id, topology_manifest_cbor, topology_manifest_digest,
                    replay_config_cbor, replay_config_digest, projection_commit_seq
             FROM store_state WHERE singleton = 1",
            [],
            |row| {
                Ok(StoreStateRow {
                    store_id: row.get(0)?,
                    topology_manifest: row.get(1)?,
                    topology_digest: row.get(2)?,
                    replay_config: row.get(3)?,
                    replay_digest: row.get(4)?,
                    projection_commit_sequence: row.get(5)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::incompatible())?;
    let state_count: u64 =
        connection.query_row("SELECT count(*) FROM store_state", [], |row| row.get(0))?;
    if state_count != 1
        || state.store_id.len() != STORE_ID_BYTES
        || state.topology_manifest != expected.topology
        || state.topology_digest.as_slice() != expected.topology_digest
        || state.replay_config != expected.replay
        || state.replay_digest.as_slice() != expected.replay_digest
        || state.projection_commit_sequence.len() != PROJECTION_SEQUENCE_ZERO.len()
        || matches!(admission_expectation, AdmissionExpectation::Empty)
            && state.projection_commit_sequence.as_slice() != PROJECTION_SEQUENCE_ZERO
    {
        return Err(StoreError::incompatible());
    }
    let store_id = state.store_id.as_slice().try_into().map_err(|_| StoreError::incompatible())?;

    let rows = connection
        .prepare(
            "SELECT device_id, key_epoch, replay_window_identity, replay_window_size,
                    highest_boot_generation, maximum_message_sequence, seen_bitmap
             FROM admission_epochs ORDER BY device_id, key_epoch",
        )?
        .query_map([], |row| {
            Ok(AdmissionStateRow {
                device_id: row.get(0)?,
                key_epoch: row.get(1)?,
                replay_window_identity: row.get(2)?,
                replay_window_size: row.get(3)?,
                highest_boot_generation: row.get(4)?,
                maximum_message_sequence: row.get(5)?,
                seen_bitmap: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != expected.admissions.len() {
        return Err(StoreError::incompatible());
    }
    for (row, admission) in rows.iter().zip(&expected.admissions) {
        let bitmap_bytes = usize::from(admission.replay_window_size).div_ceil(8);
        if row.device_id.as_slice() != admission.device.get().to_be_bytes()
            || row.key_epoch.as_slice() != admission.key_epoch.get().to_be_bytes()
            || row.replay_window_identity.as_slice() != admission.replay_window_identity.as_bytes()
            || row.replay_window_size != admission.replay_window_size
            || row.seen_bitmap.len() != bitmap_bytes
        {
            return Err(StoreError::incompatible());
        }
        match admission_expectation {
            AdmissionExpectation::Empty => {
                if row.highest_boot_generation.is_some()
                    || row.maximum_message_sequence.is_some()
                    || row.seen_bitmap.iter().any(|byte| *byte != 0)
                {
                    return Err(StoreError::incompatible());
                }
            }
            AdmissionExpectation::Existing => validate_replay_state(
                row.highest_boot_generation.as_deref(),
                row.maximum_message_sequence.as_deref(),
                &row.seen_bitmap,
                admission.replay_window_size,
            )?,
        }
    }
    Ok(store_id)
}

fn validate_replay_state(
    boot_generation: Option<&[u8]>,
    maximum_message_sequence: Option<&[u8]>,
    bitmap: &[u8],
    window_size: u16,
) -> Result<(), StoreError> {
    match (boot_generation, maximum_message_sequence) {
        (None, None) if bitmap.iter().all(|byte| *byte == 0) => {}
        (Some(boot), Some(sequence)) => {
            let boot: [u8; 4] = boot.try_into().map_err(|_| StoreError::incompatible())?;
            let sequence: [u8; 8] = sequence.try_into().map_err(|_| StoreError::incompatible())?;
            if u32::from_be_bytes(boot) == 0
                || u64::from_be_bytes(sequence) == 0
                || bitmap.first().is_none_or(|byte| byte & 1 == 0)
            {
                return Err(StoreError::incompatible());
            }
        }
        _ => return Err(StoreError::incompatible()),
    }
    let unused_bits = bitmap
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(usize::from(window_size)))
        .ok_or(StoreError::incompatible())?;
    if unused_bits != 0 && bitmap.last().is_some_and(|byte| byte >> (8 - unused_bits) != 0) {
        return Err(StoreError::incompatible());
    }
    Ok(())
}

#[derive(Serialize)]
struct TopologyManifest<'a> {
    schema: u8,
    deployment: &'a str,
    spaces: Vec<&'a str>,
    transmitters: Vec<&'a str>,
    sensors: Vec<TopologySensor<'a>>,
    links: Vec<TopologyLink<'a>>,
}

#[derive(Serialize)]
struct TopologySensor<'a> {
    id: &'a str,
    hardware_kind: &'static str,
    device_id: u64,
}

#[derive(Serialize)]
struct TopologyLink<'a> {
    id: &'a str,
    space: &'a str,
    transmitter: &'a str,
    receiver: &'a str,
}

fn encode_topology(config: &Config) -> Result<Vec<u8>, StoreError> {
    let registry = config.registry();
    let spaces = registry.spaces().values().map(|space| space.id().as_str()).collect();
    let transmitters =
        registry.transmitters().values().map(|transmitter| transmitter.id().as_str()).collect();
    let sensors = registry
        .sensors()
        .values()
        .map(|sensor| TopologySensor {
            id: sensor.id().as_str(),
            hardware_kind: match sensor.hardware_kind() {
                HardwareKind::Esp32S3 => "esp32-s3",
                HardwareKind::Esp32C6 => "esp32-c6",
                HardwareKind::Intel5300 => "intel-5300",
            },
            device_id: sensor.device_id().get(),
        })
        .collect();
    let links = registry
        .links()
        .values()
        .map(|link| TopologyLink {
            id: link.id().as_str(),
            space: link.space().as_str(),
            transmitter: link.transmitter().as_str(),
            receiver: link.receiver().as_str(),
        })
        .collect();
    let manifest = TopologyManifest {
        schema: TOPOLOGY_MANIFEST_SCHEMA_VERSION,
        deployment: config.deployment().id().as_str(),
        spaces,
        transmitters,
        sensors,
        links,
    };
    let mut bytes = Vec::new();
    into_writer(&manifest, &mut bytes).map_err(|error| StoreError::topology(error.to_string()))?;
    Ok(bytes)
}

const STORE_SCHEMA: &str = r#"
CREATE TABLE store_state (
    singleton INTEGER NOT NULL CHECK(singleton = 1),
    store_id BLOB NOT NULL CHECK(length(store_id) = 32),
    topology_manifest_cbor BLOB NOT NULL,
    topology_manifest_digest BLOB NOT NULL CHECK(length(topology_manifest_digest) = 32),
    replay_config_cbor BLOB NOT NULL,
    replay_config_digest BLOB NOT NULL CHECK(length(replay_config_digest) = 32),
    projection_commit_seq BLOB NOT NULL CHECK(length(projection_commit_seq) = 8),
    PRIMARY KEY (singleton)
) WITHOUT ROWID;
CREATE TABLE admission_epochs (
    device_id BLOB NOT NULL CHECK(length(device_id) = 8),
    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 2),
    replay_window_identity BLOB NOT NULL CHECK(length(replay_window_identity) = 32),
    replay_window_size INTEGER NOT NULL CHECK(replay_window_size BETWEEN 1 AND 65535),
    highest_boot_generation BLOB CHECK(highest_boot_generation IS NULL OR length(highest_boot_generation) = 4),
    maximum_message_sequence BLOB CHECK(maximum_message_sequence IS NULL OR length(maximum_message_sequence) = 8),
    seen_bitmap BLOB NOT NULL,
    PRIMARY KEY (device_id, key_epoch),
    CHECK((highest_boot_generation IS NULL) = (maximum_message_sequence IS NULL)),
    CHECK(length(seen_bitmap) = (replay_window_size + 7) / 8)
) WITHOUT ROWID;
CREATE TABLE capture_sessions (
    session_id TEXT NOT NULL,
    started_utc_ns BLOB NOT NULL CHECK(length(started_utc_ns) = 8),
    replay_config_digest BLOB NOT NULL CHECK(length(replay_config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    committed_through_record_seq BLOB CHECK(committed_through_record_seq IS NULL OR length(committed_through_record_seq) = 8),
    last_session_time_ns BLOB CHECK(last_session_time_ns IS NULL OR length(last_session_time_ns) = 8),
    projection_commit_seq BLOB CHECK(projection_commit_seq IS NULL OR length(projection_commit_seq) = 8),
    PRIMARY KEY (session_id),
    CHECK((committed_through_record_seq IS NULL) = (last_session_time_ns IS NULL)),
    CHECK((committed_through_record_seq IS NULL) = (projection_commit_seq IS NULL))
) WITHOUT ROWID;
CREATE TABLE packet_records (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time_ns BLOB NOT NULL CHECK(length(session_time_ns) = 8),
    receive_utc_ns BLOB NOT NULL CHECK(length(receive_utc_ns) = 8),
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL CHECK(peer_port BETWEEN 0 AND 65535),
    device_id BLOB NOT NULL CHECK(length(device_id) = 8),
    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 2),
    boot_generation BLOB NOT NULL CHECK(length(boot_generation) = 4),
    message_sequence BLOB NOT NULL CHECK(length(message_sequence) = 8),
    message_kind INTEGER NOT NULL CHECK(message_kind BETWEEN 0 AND 255),
    disposition TEXT NOT NULL CHECK(disposition IN (
        'unknown_kind', 'malformed_known_body', 'capability_pin_mismatch',
        'capability_committed', 'health_committed', 'capability_unavailable',
        'build_mismatch', 'capability_mismatch', 'source_mismatch', 'radio_mismatch',
        'body_budget_mismatch', 'decoded_domain_rejected', 'csi_committed'
    )),
    encrypted_datagram BLOB NOT NULL,
    PRIMARY KEY (session_id, record_seq),
    UNIQUE (device_id, key_epoch, boot_generation, message_sequence),
    FOREIGN KEY (session_id) REFERENCES capture_sessions(session_id)
) WITHOUT ROWID;
CREATE INDEX packet_records_time ON packet_records(session_id, session_time_ns, record_seq);
CREATE TABLE capability_epochs (
    device_id BLOB NOT NULL CHECK(length(device_id) = 8),
    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 2),
    boot_generation BLOB NOT NULL CHECK(length(boot_generation) = 4),
    capability_digest BLOB NOT NULL CHECK(length(capability_digest) = 32),
    descriptor_bytes BLOB NOT NULL CHECK(length(descriptor_bytes) = 79),
    first_session_id TEXT NOT NULL,
    first_record_seq BLOB NOT NULL CHECK(length(first_record_seq) = 8),
    PRIMARY KEY (device_id, key_epoch, boot_generation),
    FOREIGN KEY (first_session_id, first_record_seq) REFERENCES packet_records(session_id, record_seq)
) WITHOUT ROWID;
CREATE TABLE csi_observations (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time_ns BLOB NOT NULL CHECK(length(session_time_ns) = 8),
    sensor_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    observation_cbor BLOB NOT NULL,
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    replay_config_digest BLOB NOT NULL CHECK(length(replay_config_digest) = 32),
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id, record_seq) REFERENCES packet_records(session_id, record_seq)
) WITHOUT ROWID;
CREATE INDEX csi_by_link_time ON csi_observations(
    session_id, sensor_id, link_id, profile_id, session_time_ns, record_seq
);
"#;
