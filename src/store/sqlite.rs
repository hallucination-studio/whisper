//! SQLite implementation of the Store interfaces.

use std::backtrace::Backtrace;
use std::collections::BTreeMap;
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
use super::relationship::{
    CoordinatorError, CoordinatorTransition, RelationshipCoordinator, algorithm_version,
};
use crate::Config;
use crate::database::{
    Admission, DatabaseError, EpochHandle, ReplayWindowIdentity, advance_admission,
};
use crate::domain::identity::{DeviceId, HardwareKind, KeyEpoch};
use crate::domain::world::{Knowledge, StableOrChanging, TargetedBaselineCommand, UnknownReason};
use crate::hex;
use crate::session::{
    SessionManifest, SessionRecordKind, WireAdmissionPin, encode_baseline_state, encode_manifest,
    encode_record_body,
};
use crate::wire::{CandidateBody, WireCandidate};
use crate::{
    CaptureRecordSequence, CommitOutcome, CommitReceipt, PacketDisposition, ProjectionSequence,
};

// `WSPD` is the SQLite application identity. Changing it makes every existing
// Store incompatible.
const STORE_APPLICATION_ID: i64 = 0x5753_5044;
// The bounded RF relationship Store profile is fresh-only and never migrated.
const STORE_USER_VERSION: i64 = 2;
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
        started_at: (Instant, SystemTime),
    ) -> Result<CaptureSession, StoreError> {
        open_and_create_capture_session(
            self.managed.database_path(),
            config,
            admissions,
            started_at,
        )
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
    #[error("Semantic Session encoding failed: {0}")]
    Session(#[source] crate::session::SessionError),
    #[error("relationship coordinator failed: {0}")]
    Coordinator(#[source] CoordinatorError),
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

impl From<crate::session::SessionError> for StoreError {
    fn from(source: crate::session::SessionError) -> Self {
        Self::new(StoreErrorKind::Session(source))
    }
}

impl From<CoordinatorError> for StoreError {
    fn from(source: CoordinatorError) -> Self {
        Self::new(StoreErrorKind::Coordinator(source))
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
    semantic_session_id: Option<crate::SessionId>,
    coordinator: Option<RelationshipCoordinator>,
    capabilities: BTreeMap<(DeviceId, KeyEpoch, u32), crate::wire::CapabilitiesV1>,
    next_timeline_advance_ns: Option<u64>,
    #[cfg(feature = "ingest-test-hooks")]
    relationship_failure: Option<RelationshipFailureStage>,
}

#[cfg(feature = "ingest-test-hooks")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelationshipFailureStage {
    TransactionA,
    TransactionB,
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

    pub(crate) fn commit_relationship_command(
        &mut self,
        command: TargetedBaselineCommand,
        now: (Instant, SystemTime),
    ) -> Result<ProjectionSequence, StoreError> {
        self.commit_command_inner(command, now)
    }

    pub(crate) fn next_timeline_deadline(&self) -> Option<Instant> {
        self.next_timeline_advance_ns
            .and_then(|at| self.monotonic_origin.checked_add(Duration::from_nanos(at)))
    }

    pub(crate) fn commit_timeline_advance(&mut self) -> Result<ProjectionSequence, StoreError> {
        let at = self.next_timeline_advance_ns.ok_or(StoreError::incompatible())?;
        let semantic_id = self.semantic_session_id.clone().ok_or(StoreError::incompatible())?;
        let at = crate::domain::time::SessionTime::from_nanos(at);
        let body = encode_record_body(&SessionRecordKind::TimelineAdvance)?;
        let fact = self.append_semantic_fact(&semantic_id, None, at, "timeline_advance", &body)?;
        let coordinator = self.coordinator.as_ref().ok_or(StoreError::incompatible())?;
        let (staged, transition) = coordinator.advance(fact.record_seq, at)?;
        let projection = self.persist_projection(&fact, "semantic", None, &transition)?;
        self.coordinator = Some(staged);
        self.next_timeline_advance_ns = Some(
            at.as_nanos()
                .checked_add(self.config.window().step_ns())
                .ok_or(StoreError::incompatible())?,
        );
        Ok(projection)
    }

    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) fn arm_relationship_failure(&mut self, stage: RelationshipFailureStage) {
        self.relationship_failure = Some(stage);
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
        let started_utc_ns =
            i64::try_from(candidate.receive_utc_ns()).map_err(|_| StoreError::clock())?;
        let prepared = self.prepare_semantic_session(started_utc_ns)?;
        let semantic_id = prepared
            .as_ref()
            .map_or_else(|| self.semantic_session_id.clone(), |value| Some(value.id.clone()))
            .ok_or(StoreError::incompatible())?;
        let semantic_record =
            self.append_packet_fact(&semantic_id, prepared.as_ref(), &candidate)?;
        if semantic_record.replay_rejected {
            return Ok(CommitOutcome::ReplayRejected);
        }
        if let Some(prepared) = prepared {
            self.semantic_session_id = Some(prepared.id);
            self.coordinator = Some(prepared.coordinator);
            self.schedule_first_timeline_advance(semantic_record.at)?;
        }

        let route = candidate.header_route();
        let header = candidate.header();
        let mut staged_capability = None;
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
                    staged_capability = Some((
                        (route.device(), route.key_epoch(), header.boot_generation()),
                        capability.clone(),
                    ));
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
                let key = (route.device(), route.key_epoch(), header.boot_generation());
                let Some(capability) = self.capabilities.get(&key) else {
                    return self.commit_projection(
                        semantic_record,
                        PacketDisposition::CapabilityUnavailable,
                        None,
                        None,
                    );
                };
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
                        semantic_id.as_str(),
                        CaptureRecordSequence::new(semantic_record.record_seq),
                        candidate.session_time(),
                    )
                    .map_err(|_| StoreError::incompatible())?;
                    match crate::wire::resolve_capture_csi(
                        input,
                        route,
                        header,
                        self.config.registry(),
                        data.clone(),
                        capability,
                    ) {
                        Ok((profile, observation)) => {
                            let observation_cbor = crate::timeline::encode_csi_observation_root(
                                self.config.replay().digest(),
                                self.config.conditioning().version().as_str(),
                                &observation,
                            );
                            observation_row = Some(ObservationRow {
                                sensor: observation.sensor().as_str().to_owned(),
                                link: observation.link().as_str().to_owned(),
                                profile: profile.id().as_bytes(),
                                cbor: observation_cbor,
                                observation,
                            });
                            PacketDisposition::CsiCommitted
                        }
                        Err(_) => PacketDisposition::DecodedDomainRejected,
                    }
                }
            }
        };
        let outcome = self.commit_projection(
            semantic_record,
            disposition,
            observation_row,
            staged_capability.as_ref().map(|(key, capability)| (*key, capability.clone())),
        )?;
        if let Some((key, capability)) = staged_capability {
            self.capabilities.insert(key, capability);
        }
        Ok(outcome)
    }

    fn commit_command_inner(
        &mut self,
        command: TargetedBaselineCommand,
        (monotonic_now, utc_now): (Instant, SystemTime),
    ) -> Result<ProjectionSequence, StoreError> {
        let now = utc_now.duration_since(UNIX_EPOCH).map_err(|_| StoreError::clock())?;
        let started_utc_ns = i64::try_from(now.as_nanos()).map_err(|_| StoreError::clock())?;
        let at = crate::domain::time::SessionTime::from_nanos(
            u64::try_from(
                monotonic_now
                    .checked_duration_since(self.monotonic_origin)
                    .ok_or(StoreError::clock())?
                    .as_nanos(),
            )
            .map_err(|_| StoreError::clock())?,
        );
        let prepared = self.prepare_semantic_session(started_utc_ns)?;
        let semantic_id = prepared
            .as_ref()
            .map_or_else(|| self.semantic_session_id.clone(), |value| Some(value.id.clone()))
            .ok_or(StoreError::incompatible())?;
        let body = encode_record_body(&SessionRecordKind::BaselineCommand(command.clone()))?;
        let fact = self.append_semantic_fact(
            &semantic_id,
            prepared.as_ref(),
            at,
            "baseline_command",
            &body,
        )?;
        if let Some(prepared) = prepared {
            self.semantic_session_id = Some(prepared.id);
            self.coordinator = Some(prepared.coordinator);
            self.schedule_first_timeline_advance(fact.at)?;
        }
        let coordinator = self.coordinator.as_ref().ok_or(StoreError::incompatible())?;
        let (staged, transition) = coordinator.command(&command)?;
        let projection = self.persist_projection(&fact, "semantic", None, &transition)?;
        self.coordinator = Some(staged);
        Ok(projection)
    }

    fn schedule_first_timeline_advance(
        &mut self,
        after: crate::domain::time::SessionTime,
    ) -> Result<(), StoreError> {
        let step = self.config.window().step_ns();
        let next = after
            .as_nanos()
            .checked_div(step)
            .and_then(|index| index.checked_add(1))
            .and_then(|index| index.checked_mul(step))
            .ok_or(StoreError::incompatible())?;
        self.next_timeline_advance_ns = Some(next);
        Ok(())
    }

    fn prepare_semantic_session(
        &self,
        started_utc_ns: i64,
    ) -> Result<Option<PreparedSession>, StoreError> {
        if self.semantic_session_id.is_some() {
            return Ok(None);
        }
        let mut random = [0_u8; CAPTURE_SESSION_RANDOM_BYTES];
        fill_random(&mut random)?;
        let id = crate::SessionId::new(format!("semantic-{}", hex::encode(&random)))
            .map_err(|_| StoreError::incompatible())?;
        let mut wire_admission = Vec::with_capacity(self.config.registry().routes().len());
        for route in self.config.registry().routes() {
            let link = self
                .config
                .registry()
                .links()
                .get(route.link())
                .ok_or(StoreError::incompatible())?;
            let sensor = self
                .config
                .registry()
                .sensors()
                .get(link.receiver())
                .ok_or(StoreError::incompatible())?;
            wire_admission.push(WireAdmissionPin {
                wire_version: 1,
                device_id: route.device_id(),
                key_epoch: route.key_epoch(),
                firmware_build_digest: sensor.firmware_build_digest(),
                capability_digest: sensor.capability_digest(),
                maximum_plaintext_bytes: sensor.maximum_plaintext_bytes(),
                transport_datagram_budget_bytes: route.admission_limits().maximum_datagram_bytes(),
            });
        }
        let manifest = SessionManifest {
            session_id: id.clone(),
            started_utc_ns,
            replay_config: self.config.replay().clone(),
            config_digest: self.config.replay().digest(),
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_fingerprint: Sha256::digest(env!("CARGO_PKG_VERSION").as_bytes()).into(),
            decoder_version: DECODER_VERSION.to_owned(),
            wire_admission,
            conditioning_version: self.config.conditioning().version().as_str().to_owned(),
            algorithm_version: algorithm_version().to_owned(),
            initial_baseline_states: Vec::new(),
        };
        let manifest_cbor = encode_manifest(&manifest)?;
        let coordinator = RelationshipCoordinator::new(&manifest, &self.config)?;
        Ok(Some(PreparedSession { id, started_utc_ns, manifest_cbor, coordinator }))
    }

    fn append_packet_fact(
        &mut self,
        semantic_id: &crate::SessionId,
        prepared: Option<&PreparedSession>,
        candidate: &WireCandidate,
    ) -> Result<PersistedFact, StoreError> {
        let receive_utc_ns =
            i64::try_from(candidate.receive_utc_ns()).map_err(|_| StoreError::clock())?;
        let body = encode_record_body(&SessionRecordKind::Packet {
            receive_utc_ns,
            peer: candidate.peer(),
            wire_format: crate::capture::WireFormat::NativeFrameUdp,
            bytes: candidate.bytes().to_vec().into_boxed_slice(),
        })?;
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_prepared_session(&transaction, semantic_id, prepared, &self.config)?;

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
            Err(DatabaseError::Replay) => return Ok(PersistedFact::replay()),
            Err(error) => return Err(StoreError::admission(error)),
        }

        let record_seq = next_semantic_record(&transaction, semantic_id.as_str())?;
        let capture_record_seq = next_capture_record(&transaction, &self.session_id)?;
        transaction.execute(
            "INSERT INTO session_records
             (session_id, record_seq, session_time, kind, body_cbor)
             VALUES (?1, ?2, ?3, 'packet', ?4)",
            params![
                semantic_id.as_str(),
                record_seq.to_be_bytes(),
                candidate.session_time().as_nanos().to_be_bytes(),
                body,
            ],
        )?;
        transaction.execute(
            "INSERT INTO packet_capture_membership
             (session_id, record_seq, capture_session_id, capture_record_seq, capture_session_time)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                semantic_id.as_str(),
                record_seq.to_be_bytes(),
                &self.session_id,
                capture_record_seq.to_be_bytes(),
                candidate.session_time().as_nanos().to_be_bytes(),
            ],
        )?;
        advance_fact_bytes(
            &transaction,
            semantic_id.as_str(),
            u64::try_from(body.len()).map_err(|_| StoreError::incompatible())?,
        )?;
        let updated = transaction.execute(
            "UPDATE capture_sessions
             SET durable_tail_record_seq = ?1, last_session_time = ?2
             WHERE capture_session_id = ?3",
            params![
                capture_record_seq.to_be_bytes(),
                candidate.session_time().as_nanos().to_be_bytes(),
                &self.session_id,
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::incompatible());
        }
        transaction.commit()?;
        Ok(PersistedFact {
            record_seq,
            capture_record_seq: Some(capture_record_seq),
            at: candidate.session_time(),
            replay_rejected: false,
        })
    }

    fn append_semantic_fact(
        &mut self,
        semantic_id: &crate::SessionId,
        prepared: Option<&PreparedSession>,
        at: crate::domain::time::SessionTime,
        kind: &'static str,
        body: &[u8],
    ) -> Result<PersistedFact, StoreError> {
        #[cfg(feature = "ingest-test-hooks")]
        let fail_transaction =
            if self.relationship_failure == Some(RelationshipFailureStage::TransactionA) {
                self.relationship_failure = None;
                true
            } else {
                false
            };
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_prepared_session(&transaction, semantic_id, prepared, &self.config)?;
        let record_seq = next_semantic_record(&transaction, semantic_id.as_str())?;
        transaction.execute(
            "INSERT INTO session_records
             (session_id, record_seq, session_time, kind, body_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                semantic_id.as_str(),
                record_seq.to_be_bytes(),
                at.as_nanos().to_be_bytes(),
                kind,
                body
            ],
        )?;
        advance_fact_bytes(
            &transaction,
            semantic_id.as_str(),
            u64::try_from(body.len()).map_err(|_| StoreError::incompatible())?,
        )?;
        #[cfg(feature = "ingest-test-hooks")]
        if fail_transaction {
            return Err(StoreError::incompatible());
        }
        transaction.commit()?;
        Ok(PersistedFact { record_seq, capture_record_seq: None, at, replay_rejected: false })
    }

    fn commit_projection(
        &mut self,
        fact: PersistedFact,
        disposition: PacketDisposition,
        observation: Option<ObservationRow>,
        _capability: Option<((DeviceId, KeyEpoch, u32), crate::wire::CapabilitiesV1)>,
    ) -> Result<CommitOutcome, StoreError> {
        if fact.replay_rejected {
            return Ok(CommitOutcome::ReplayRejected);
        }
        let coordinator = self.coordinator.as_ref().ok_or(StoreError::incompatible())?;
        let (staged, transition) = match observation.as_ref() {
            Some(row) => coordinator.observe(row.observation.clone())?,
            None => (coordinator.clone(), coordinator.unchanged()?),
        };
        let kind = if matches!(
            disposition,
            PacketDisposition::MalformedKnownBody | PacketDisposition::DecodedDomainRejected
        ) {
            "decode_rejected"
        } else {
            "semantic"
        };
        let projection = self.persist_projection(&fact, kind, observation.as_ref(), &transition)?;
        self.coordinator = Some(staged);
        Ok(CommitOutcome::Committed(CommitReceipt::new(
            disposition,
            fact.capture_record_seq.ok_or(StoreError::incompatible())?,
            projection,
        )))
    }

    fn persist_projection(
        &mut self,
        fact: &PersistedFact,
        kind: &'static str,
        observation: Option<&ObservationRow>,
        transition: &CoordinatorTransition,
    ) -> Result<ProjectionSequence, StoreError> {
        #[cfg(feature = "ingest-test-hooks")]
        let fail_transaction =
            if self.relationship_failure == Some(RelationshipFailureStage::TransactionB) {
                self.relationship_failure = None;
                true
            } else {
                false
            };
        let semantic_id = self.semantic_session_id.as_ref().ok_or(StoreError::incompatible())?;
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let watermark: Vec<u8> = transaction
            .query_row(
                "SELECT projection_commit_seq FROM store_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::incompatible())?;
        let watermark = ProjectionSequence::new(decode_u64(&watermark)?);
        let projection = watermark.checked_next().ok_or(StoreError::incompatible())?;
        if let Some(observation) = observation {
            transaction.execute(
                "INSERT INTO csi_observations
                 (session_id, record_seq, session_time, sensor_id, link_id, profile_id,
                  observation_cbor, decoder_version, conditioning_version, config_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    semantic_id.as_str(),
                    fact.record_seq.to_be_bytes(),
                    fact.at.as_nanos().to_be_bytes(),
                    observation.sensor,
                    observation.link,
                    observation.profile,
                    observation.cbor.as_ref(),
                    DECODER_VERSION,
                    self.config.conditioning().version().as_str(),
                    self.config.replay().digest(),
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO projection_commits
             (commit_seq, session_id, record_seq, kind, timeline_state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                projection.to_be_bytes(),
                semantic_id.as_str(),
                fact.record_seq.to_be_bytes(),
                kind,
                transition.timeline_digest,
            ],
        )?;
        for state in &transition.baseline_states {
            transaction.execute(
                "INSERT INTO baseline_states
                 (deployment_id, link_id, profile_id, estimator_state_cbor,
                  source_session_id, source_record_seq, config_digest,
                  decoder_version, conditioning_version, algorithm_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(deployment_id, link_id, profile_id) DO UPDATE SET
                   estimator_state_cbor=excluded.estimator_state_cbor,
                   source_session_id=excluded.source_session_id,
                   source_record_seq=excluded.source_record_seq,
                   config_digest=excluded.config_digest,
                   decoder_version=excluded.decoder_version,
                   conditioning_version=excluded.conditioning_version,
                   algorithm_version=excluded.algorithm_version",
                params![
                    self.config.deployment().id().as_str(),
                    state.key().link().as_str(),
                    state.key().profile().as_bytes(),
                    encode_baseline_state(state)?,
                    semantic_id.as_str(),
                    fact.record_seq.to_be_bytes(),
                    self.config.replay().digest(),
                    DECODER_VERSION,
                    self.config.conditioning().version().as_str(),
                    algorithm_version(),
                ],
            )?;
        }
        for relationship in &transition.relationships {
            let knowledge = encode_relationship_knowledge(&relationship.knowledge)?;
            transaction.execute(
                "INSERT INTO relationship_latest
                 (session_id, link_id, profile_id, knowledge_cbor, result_time,
                  change_previous_cbor, change_current_cbor, changed_at,
                  source_record_seq, creator_commit_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, ?6, ?7)
                 ON CONFLICT(session_id, link_id, profile_id) DO UPDATE SET
                   change_previous_cbor=CASE
                     WHEN relationship_latest.knowledge_cbor <> excluded.knowledge_cbor
                     THEN relationship_latest.knowledge_cbor
                     ELSE relationship_latest.change_previous_cbor
                   END,
                   change_current_cbor=CASE
                     WHEN relationship_latest.knowledge_cbor <> excluded.knowledge_cbor
                     THEN excluded.knowledge_cbor
                     ELSE relationship_latest.change_current_cbor
                   END,
                   changed_at=CASE
                     WHEN relationship_latest.knowledge_cbor <> excluded.knowledge_cbor
                     THEN excluded.result_time
                     ELSE relationship_latest.changed_at
                   END,
                   knowledge_cbor=excluded.knowledge_cbor,
                   result_time=excluded.result_time,
                   source_record_seq=excluded.source_record_seq,
                   creator_commit_seq=excluded.creator_commit_seq",
                params![
                    semantic_id.as_str(),
                    relationship.key.link().as_str(),
                    relationship.key.profile().as_bytes(),
                    knowledge,
                    relationship.result_time.as_nanos().to_be_bytes(),
                    fact.record_seq.to_be_bytes(),
                    projection.to_be_bytes(),
                ],
            )?;
        }
        let updated = transaction.execute(
            "UPDATE session_processing_state
             SET processed_through_record_seq=?1, timeline_state_digest=?2,
                 projection_commit_seq=?3
             WHERE session_id=?4",
            params![
                fact.record_seq.to_be_bytes(),
                transition.timeline_digest,
                projection.to_be_bytes(),
                semantic_id.as_str(),
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::incompatible());
        }
        let updated = transaction.execute(
            "UPDATE store_state SET projection_commit_seq=?1
             WHERE singleton=1 AND projection_commit_seq=?2",
            params![projection.to_be_bytes(), watermark.to_be_bytes()],
        )?;
        if updated != 1 {
            return Err(StoreError::incompatible());
        }
        #[cfg(feature = "ingest-test-hooks")]
        if fail_transaction {
            return Err(StoreError::incompatible());
        }
        transaction.commit()?;
        Ok(projection)
    }
}

#[derive(Debug)]
struct PreparedSession {
    id: crate::SessionId,
    started_utc_ns: i64,
    manifest_cbor: Vec<u8>,
    coordinator: RelationshipCoordinator,
}

#[derive(Clone, Copy, Debug)]
struct PersistedFact {
    record_seq: u64,
    capture_record_seq: Option<CaptureRecordSequence>,
    at: crate::domain::time::SessionTime,
    replay_rejected: bool,
}

impl PersistedFact {
    const fn replay() -> Self {
        Self {
            record_seq: 0,
            capture_record_seq: None,
            at: crate::domain::time::SessionTime::from_nanos(0),
            replay_rejected: true,
        }
    }
}

#[derive(Debug)]
struct ObservationRow {
    sensor: String,
    link: String,
    profile: [u8; 32],
    cbor: Box<[u8]>,
    observation: crate::domain::csi::CsiObservation,
}

fn insert_prepared_session(
    transaction: &rusqlite::Transaction<'_>,
    semantic_id: &crate::SessionId,
    prepared: Option<&PreparedSession>,
    config: &Config,
) -> Result<(), StoreError> {
    if let Some(prepared) = prepared {
        transaction.execute(
            "INSERT INTO sessions
             (session_id, started_utc_ns, manifest_cbor, fact_bytes, lifecycle)
             VALUES (?1, ?2, ?3, ?4, 'active')",
            params![
                semantic_id.as_str(),
                prepared.started_utc_ns,
                &prepared.manifest_cbor,
                u64::try_from(prepared.manifest_cbor.len())
                    .map_err(|_| StoreError::incompatible())?
                    .to_be_bytes(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO session_processing_state
             (session_id, processed_through_record_seq, timeline_state_digest,
              projection_commit_seq, config_digest, decoder_version,
              conditioning_version, algorithm_version)
             VALUES (?1, NULL, NULL, NULL, ?2, ?3, ?4, ?5)",
            params![
                semantic_id.as_str(),
                config.replay().digest(),
                DECODER_VERSION,
                config.conditioning().version().as_str(),
                algorithm_version(),
            ],
        )?;
    }
    Ok(())
}

fn next_semantic_record(
    transaction: &rusqlite::Transaction<'_>,
    session_id: &str,
) -> Result<u64, StoreError> {
    let tail = transaction
        .query_row(
            "SELECT record_seq FROM session_records
             WHERE session_id=?1 ORDER BY record_seq DESC LIMIT 1",
            [session_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    tail.map_or(Ok(0), |bytes| decode_u64(&bytes)?.checked_add(1).ok_or(StoreError::incompatible()))
}

fn next_capture_record(
    transaction: &rusqlite::Transaction<'_>,
    capture_session_id: &str,
) -> Result<CaptureRecordSequence, StoreError> {
    let tail = transaction
        .query_row(
            "SELECT durable_tail_record_seq FROM capture_sessions WHERE capture_session_id=?1",
            [capture_session_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .ok_or(StoreError::incompatible())?;
    tail.map_or(Ok(CaptureRecordSequence::new(0)), |bytes| {
        CaptureRecordSequence::new(decode_u64(&bytes)?)
            .checked_next()
            .ok_or(StoreError::incompatible())
    })
}

fn advance_fact_bytes(
    transaction: &rusqlite::Transaction<'_>,
    session_id: &str,
    added: u64,
) -> Result<(), StoreError> {
    let current: Vec<u8> = transaction.query_row(
        "SELECT fact_bytes FROM sessions WHERE session_id=?1",
        [session_id],
        |row| row.get(0),
    )?;
    let next = decode_u64(&current)?.checked_add(added).ok_or(StoreError::incompatible())?;
    if transaction.execute(
        "UPDATE sessions SET fact_bytes=?1 WHERE session_id=?2 AND fact_bytes=?3",
        params![next.to_be_bytes(), session_id, current],
    )? != 1
    {
        return Err(StoreError::incompatible());
    }
    Ok(())
}

#[derive(Serialize)]
struct UnknownKnowledge {
    kind: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct KnownKnowledge {
    kind: &'static str,
    value: &'static str,
}

fn encode_relationship_knowledge(
    knowledge: &Knowledge<StableOrChanging>,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    match knowledge {
        Knowledge::Known(StableOrChanging::Stable) => {
            into_writer(&KnownKnowledge { kind: "known", value: "stable" }, &mut bytes)
        }
        Knowledge::Known(StableOrChanging::Changing) => {
            into_writer(&KnownKnowledge { kind: "known", value: "changing" }, &mut bytes)
        }
        Knowledge::Unknown { reason } => into_writer(
            &UnknownKnowledge { kind: "unknown", reason: unknown_reason_text(reason) },
            &mut bytes,
        ),
    }
    .map_err(|error| StoreError::topology(error.to_string()))?;
    Ok(bytes)
}

const fn unknown_reason_text(reason: &UnknownReason) -> &'static str {
    match reason {
        UnknownReason::BaselineMissing => "baseline_missing",
        UnknownReason::BaselineLearning => "baseline_learning",
        UnknownReason::InsufficientCoverage => "insufficient_coverage",
        UnknownReason::LowQuality => "low_quality",
        UnknownReason::AmbiguousEvidence => "ambiguous_evidence",
        UnknownReason::TimeUncertain => "time_uncertain",
        UnknownReason::MissingData => "missing_data",
        UnknownReason::ProfileMismatch => "profile_mismatch",
        UnknownReason::Stale => "stale",
        UnknownReason::Frozen => "frozen",
        UnknownReason::Inactive => "inactive",
        UnknownReason::NonFinite => "non_finite",
    }
}

fn initialize_stage(
    stage: &ManagedStage,
    config: &Config,
    admissions: Vec<AdmissionEpochSeed>,
) -> Result<InitializedStore, StoreError> {
    let topology = encode_topology(config)?;
    let topology_digest = Sha256::digest(&topology).into();
    let mut store_id = [0_u8; STORE_ID_BYTES];
    fill_random(&mut store_id)?;
    let expected = ExpectedStore { topology, topology_digest, admissions };

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
          projection_commit_seq)
         VALUES (1, ?1, ?2, ?3, ?4)",
        params![store_id, expected.topology, expected.topology_digest, PROJECTION_SEQUENCE_ZERO,],
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
    (monotonic_origin, started_utc): (Instant, SystemTime),
) -> Result<CaptureSession, StoreError> {
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
    let expected = ExpectedStore { topology, topology_digest, admissions };
    let store_id = validate_state(&connection, &expected, AdmissionExpectation::Existing)?;

    let started_utc_ns =
        started_utc.duration_since(UNIX_EPOCH).map_err(|_| StoreError::clock())?.as_nanos();
    let started_utc_ns = i64::try_from(started_utc_ns).map_err(|_| StoreError::clock())?;
    let mut random = [0_u8; CAPTURE_SESSION_RANDOM_BYTES];
    fill_random(&mut random)?;
    let session_id = format!("{CAPTURE_SESSION_ID_PREFIX}{}", hex::encode(&random));
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO capture_sessions
         (capture_session_id, started_utc_ns, durable_tail_record_seq, last_session_time,
          decoder_version, conditioning_version, algorithm_version)
         VALUES (?1, ?2, NULL, NULL, ?3, ?4, ?5)",
        params![
            &session_id,
            started_utc_ns,
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
        semantic_session_id: None,
        coordinator: None,
        capabilities: BTreeMap::new(),
        next_timeline_advance_ns: None,
        #[cfg(feature = "ingest-test-hooks")]
        relationship_failure: None,
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
                    projection_commit_seq
             FROM store_state WHERE singleton = 1",
            [],
            |row| {
                Ok(StoreStateRow {
                    store_id: row.get(0)?,
                    topology_manifest: row.get(1)?,
                    topology_digest: row.get(2)?,
                    projection_commit_sequence: row.get(3)?,
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
CREATE TABLE store_state (
    singleton INTEGER NOT NULL CHECK(singleton = 1),
    store_id BLOB NOT NULL CHECK(length(store_id) = 32),
    topology_manifest_cbor BLOB NOT NULL,
    topology_manifest_digest BLOB NOT NULL CHECK(length(topology_manifest_digest) = 32),
    projection_commit_seq BLOB NOT NULL CHECK(length(projection_commit_seq) = 8),
    PRIMARY KEY (singleton)
) WITHOUT ROWID;
CREATE TABLE capture_sessions (
    capture_session_id TEXT NOT NULL,
    started_utc_ns INTEGER NOT NULL CHECK(started_utc_ns >= 0),
    durable_tail_record_seq BLOB CHECK(durable_tail_record_seq IS NULL OR length(durable_tail_record_seq) = 8),
    last_session_time BLOB CHECK(last_session_time IS NULL OR length(last_session_time) = 8),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (capture_session_id),
    CHECK((durable_tail_record_seq IS NULL) = (last_session_time IS NULL))
) WITHOUT ROWID;
CREATE INDEX capture_sessions_started
    ON capture_sessions(started_utc_ns, capture_session_id);
CREATE TABLE sessions (
    session_id TEXT NOT NULL,
    started_utc_ns INTEGER NOT NULL CHECK(started_utc_ns >= 0),
    manifest_cbor BLOB NOT NULL,
    fact_bytes BLOB NOT NULL CHECK(length(fact_bytes) = 8),
    lifecycle TEXT NOT NULL CHECK(lifecycle = 'active'),
    PRIMARY KEY (session_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX one_active_session
    ON sessions(lifecycle) WHERE lifecycle = 'active';
CREATE TABLE session_records (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time BLOB NOT NULL CHECK(length(session_time) = 8),
    kind TEXT NOT NULL CHECK(kind IN ('packet', 'baseline_command', 'timeline_advance')),
    body_cbor BLOB NOT NULL,
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX session_records_time
    ON session_records(session_id, session_time, record_seq);
CREATE TABLE packet_capture_membership (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    capture_session_id TEXT NOT NULL,
    capture_record_seq BLOB NOT NULL CHECK(length(capture_record_seq) = 8),
    capture_session_time BLOB NOT NULL CHECK(length(capture_session_time) = 8),
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id, record_seq) REFERENCES session_records(session_id, record_seq) ON DELETE CASCADE,
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(capture_session_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX capture_record_identity
    ON packet_capture_membership(capture_session_id, capture_record_seq);
CREATE TABLE projection_commits (
    commit_seq BLOB NOT NULL CHECK(length(commit_seq) = 8),
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    kind TEXT NOT NULL CHECK(kind IN ('semantic', 'decode_rejected')),
    timeline_state_digest BLOB NOT NULL CHECK(length(timeline_state_digest) = 32),
    PRIMARY KEY (commit_seq),
    UNIQUE (session_id, record_seq, commit_seq),
    FOREIGN KEY (session_id, record_seq) REFERENCES session_records(session_id, record_seq) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE UNIQUE INDEX one_commit_per_record
    ON projection_commits(session_id, record_seq);
CREATE TABLE session_processing_state (
    session_id TEXT NOT NULL,
    processed_through_record_seq BLOB CHECK(processed_through_record_seq IS NULL OR length(processed_through_record_seq) = 8),
    timeline_state_digest BLOB CHECK(timeline_state_digest IS NULL OR length(timeline_state_digest) = 32),
    projection_commit_seq BLOB CHECK(projection_commit_seq IS NULL OR length(projection_commit_seq) = 8),
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (session_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (session_id, processed_through_record_seq, projection_commit_seq)
        REFERENCES projection_commits(session_id, record_seq, commit_seq),
    CHECK((processed_through_record_seq IS NULL) = (timeline_state_digest IS NULL)),
    CHECK((processed_through_record_seq IS NULL) = (projection_commit_seq IS NULL))
) WITHOUT ROWID;
CREATE TABLE csi_observations (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time BLOB NOT NULL CHECK(length(session_time) = 8),
    sensor_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    observation_cbor BLOB NOT NULL,
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id, record_seq) REFERENCES session_records(session_id, record_seq) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX csi_by_link_time
    ON csi_observations(link_id, profile_id, session_time, record_seq);
CREATE INDEX csi_by_sensor_time
    ON csi_observations(sensor_id, session_time, record_seq);
CREATE TABLE baseline_states (
    deployment_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    estimator_state_cbor BLOB NOT NULL,
    source_session_id TEXT NOT NULL,
    source_record_seq BLOB NOT NULL CHECK(length(source_record_seq) = 8),
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (deployment_id, link_id, profile_id),
    FOREIGN KEY (source_session_id, source_record_seq)
        REFERENCES session_records(session_id, record_seq)
) WITHOUT ROWID;
CREATE INDEX baseline_by_source
    ON baseline_states(source_session_id, source_record_seq);
CREATE TABLE relationship_latest (
    session_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    knowledge_cbor BLOB NOT NULL,
    result_time BLOB NOT NULL CHECK(length(result_time) = 8),
    change_previous_cbor BLOB,
    change_current_cbor BLOB,
    changed_at BLOB CHECK(changed_at IS NULL OR length(changed_at) = 8),
    source_record_seq BLOB NOT NULL CHECK(length(source_record_seq) = 8),
    creator_commit_seq BLOB NOT NULL CHECK(length(creator_commit_seq) = 8),
    PRIMARY KEY (session_id, link_id, profile_id),
    FOREIGN KEY (session_id, source_record_seq, creator_commit_seq)
        REFERENCES projection_commits(session_id, record_seq, commit_seq),
    CHECK((change_previous_cbor IS NULL) = (change_current_cbor IS NULL)),
    CHECK((change_previous_cbor IS NULL) = (changed_at IS NULL))
) WITHOUT ROWID;
CREATE VIEW visible_sessions AS
SELECT s.session_id, s.started_utc_ns,
       p.processed_through_record_seq, p.projection_commit_seq,
       p.config_digest, p.decoder_version,
       p.conditioning_version, p.algorithm_version
FROM sessions AS s
JOIN session_processing_state AS p USING (session_id)
WHERE p.projection_commit_seq IS NOT NULL;
CREATE VIEW visible_records AS
SELECT r.session_id, r.record_seq, r.session_time, r.kind, r.body_cbor
FROM session_records AS r
JOIN session_processing_state AS p USING (session_id)
WHERE p.processed_through_record_seq IS NOT NULL
  AND r.record_seq <= p.processed_through_record_seq;
CREATE VIEW visible_capture_records AS
SELECT m.capture_session_id, m.capture_record_seq, m.capture_session_time,
       r.session_id, r.record_seq, r.body_cbor
FROM packet_capture_membership AS m
JOIN visible_records AS r
  ON r.session_id = m.session_id AND r.record_seq = m.record_seq;
"#;
