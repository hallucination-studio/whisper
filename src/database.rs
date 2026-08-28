//! SQLite schema and atomic persistence primitives for sessions and replay admission.

#![cfg_attr(not(test), expect(dead_code, reason = "consumed by work-package 2.2"))]

use std::path::Path;

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::capture::CapturedPacket;
use crate::domain::identity::{DeviceId, KeyEpoch, SessionId};
use crate::domain::world::BaselineState;
use crate::session::{
    ControlRecordInput, RecordKind, SessionError, SessionManifest, SessionRecord,
    SessionRecordKind, decode_baseline_state, decode_manifest, decode_record_body,
    encode_baseline_state, encode_manifest, encode_record_body,
};

const SCHEMA_VERSION: i64 = 1;
const LIFECYCLE_ACTIVE: &str = "active";
const LIFECYCLE_SEALED: &str = "sealed";
const LIFECYCLE_RECOVERY_SEALED: &str = "recovery_sealed";
// The persistence-v1 Session fact bytes contract fixes Closed at 23 logical bytes.
// Changing this alters admission and rotation boundaries and requires a contract change.
const CLOSED_RECORD_LOGICAL_BYTES: u64 = 23;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayWindowIdentity([u8; 32]);

impl ReplayWindowIdentity {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionFactBytes(u64);

impl SessionFactBytes {
    const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DatabaseError {
    #[error("database file does not exist")]
    Missing,
    #[error("SQLite operation failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("session encoding failed: {0}")]
    Session(#[from] SessionError),
    #[error("database schema version {actual} does not match required version {expected}")]
    SchemaVersion { actual: i64, expected: i64 },
    #[error("database pragma {name} is {actual}, expected {expected}")]
    Pragma { name: &'static str, actual: String, expected: &'static str },
    #[error("admission epoch is not initialized")]
    MissingEpoch,
    #[error("admission epoch configuration conflicts with the database")]
    EpochConflict,
    #[error("packet was already admitted or is older than the replay window")]
    Replay,
    #[error("session is not active")]
    NotActive,
    #[error("session record sequence {actual} does not equal expected {expected}")]
    Sequence { expected: u64, actual: u64 },
    #[error("session record time {actual} precedes previous time {previous}")]
    TimeReversed { previous: u64, actual: u64 },
    #[error("session manifest or record exceeds its configured byte limit")]
    TooLarge,
    #[error(
        "fatal session limit: manifest uses {manifest_bytes} logical bytes and reserves \
         {reserved_closed_bytes} bytes for Closed, exceeding max_session_bytes {max_session_bytes}"
    )]
    SessionLimit { manifest_bytes: usize, reserved_closed_bytes: u64, max_session_bytes: u64 },
    #[error("stored unsigned integer has an invalid width")]
    UnsignedWidth,
}

/// The sole synchronous SQLite writer connection.
#[derive(Debug)]
pub(crate) struct Database {
    connection: Connection,
}

impl Database {
    pub(crate) fn create_new(path: &Path) -> Result<Self, DatabaseError> {
        if path.exists() {
            return Err(DatabaseError::EpochConflict);
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        configure_writer(&connection)?;
        connection.execute_batch(SCHEMA)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        verify_store_identity(&connection)?;
        verify_connection(&connection, true)?;
        Ok(Self { connection })
    }

    pub(crate) fn open_writer_existing(path: &Path) -> Result<Self, DatabaseError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| classify_existing_open_error(path, error))?;
        verify_store_identity(&connection)?;
        configure_writer(&connection)?;
        verify_connection(&connection, true)?;
        Ok(Self { connection })
    }

    pub(crate) fn provision_epoch(
        &mut self,
        device: DeviceId,
        key_epoch: KeyEpoch,
        replay_window_identity: &ReplayWindowIdentity,
        replay_window_size: u16,
    ) -> Result<(), DatabaseError> {
        if replay_window_size == 0 {
            return Err(DatabaseError::EpochConflict);
        }
        let bitmap = vec![0_u8; usize::from(replay_window_size).div_ceil(8)];
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO admission_epochs
             (device_id, key_epoch, replay_window_identity, replay_window_size,
              highest_boot_generation, maximum_message_sequence, seen_bitmap)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
            params![
                u64_bytes(device.get()),
                u16_bytes(key_epoch.get()),
                replay_window_identity.as_bytes(),
                replay_window_size,
                bitmap
            ],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.connection.query_row(
            "SELECT replay_window_identity, replay_window_size,
                    highest_boot_generation IS NULL, maximum_message_sequence IS NULL, seen_bitmap
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            params![u64_bytes(device.get()), u16_bytes(key_epoch.get())],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u16>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )?;
        if existing
            == (replay_window_identity.as_bytes().to_vec(), replay_window_size, true, true, bitmap)
        {
            Ok(())
        } else {
            Err(DatabaseError::EpochConflict)
        }
    }

    pub(crate) fn validate_epoch(
        &self,
        device: DeviceId,
        key_epoch: KeyEpoch,
        replay_window_identity: ReplayWindowIdentity,
        replay_window_size: u16,
    ) -> Result<EpochHandle, DatabaseError> {
        if replay_window_size == 0 {
            return Err(DatabaseError::EpochConflict);
        }
        let row = self
            .connection
            .query_row(
                "SELECT replay_window_identity, replay_window_size, highest_boot_generation,
                        maximum_message_sequence, seen_bitmap
                 FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
                params![u64_bytes(device.get()), u16_bytes(key_epoch.get())],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u16>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(DatabaseError::MissingEpoch)?;
        if row.0.as_slice() != replay_window_identity.as_bytes() || row.1 != replay_window_size {
            return Err(DatabaseError::EpochConflict);
        }
        validate_admission_state(replay_window_size, row.2.as_deref(), row.3.as_deref(), &row.4)?;
        Ok(EpochHandle { device, key_epoch, replay_window_identity, replay_window_size })
    }

    pub(crate) fn create_session(
        &mut self,
        manifest: &SessionManifest,
        max_manifest_bytes: u64,
        max_session_bytes: u64,
    ) -> Result<SessionFactBytes, DatabaseError> {
        let bytes = encode_manifest(manifest)?;
        if bytes.len() as u64 > max_manifest_bytes {
            return Err(DatabaseError::TooLarge);
        }
        let manifest_fact_bytes =
            u64::try_from(bytes.len()).map_err(|_| DatabaseError::SessionLimit {
                manifest_bytes: bytes.len(),
                reserved_closed_bytes: CLOSED_RECORD_LOGICAL_BYTES,
                max_session_bytes,
            })?;
        let required_bytes = manifest_fact_bytes.checked_add(CLOSED_RECORD_LOGICAL_BYTES).ok_or(
            DatabaseError::SessionLimit {
                manifest_bytes: bytes.len(),
                reserved_closed_bytes: CLOSED_RECORD_LOGICAL_BYTES,
                max_session_bytes,
            },
        )?;
        if required_bytes > max_session_bytes {
            return Err(DatabaseError::SessionLimit {
                manifest_bytes: bytes.len(),
                reserved_closed_bytes: CLOSED_RECORD_LOGICAL_BYTES,
                max_session_bytes,
            });
        }
        let fact_bytes = SessionFactBytes::new(manifest_fact_bytes);
        let stored_fact_bytes = fact_bytes.to_be_bytes();
        let states = manifest
            .initial_baseline_states
            .iter()
            .map(|state| Ok((state, encode_baseline_state(state)?)))
            .collect::<Result<Vec<_>, DatabaseError>>()?;
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO sessions
             (session_id, started_utc_ns, manifest_cbor, fact_bytes, lifecycle)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                manifest.session_id.as_str(),
                manifest.started_utc_ns,
                bytes,
                stored_fact_bytes,
                LIFECYCLE_ACTIVE
            ],
        )?;
        transaction.execute(
            "INSERT INTO session_processing_state
             (session_id, processed_through_record_seq, timeline_state_cbor, config_digest,
              decoder_version, conditioning_version, algorithm_version)
             VALUES (?1, NULL, NULL, ?2, ?3, ?4, ?5)",
            params![
                manifest.session_id.as_str(),
                manifest.config_digest,
                manifest.decoder_version,
                manifest.conditioning_version,
                manifest.algorithm_version,
            ],
        )?;
        for (state, state_bytes) in states {
            transaction.execute(
                "INSERT INTO baseline_states
                 (deployment_id, link_id, profile_id, estimator_state_cbor, source_session_id,
                  source_record_seq, config_digest, decoder_version, conditioning_version,
                  algorithm_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9)",
                params![
                    state.compatibility().deployment().as_str(),
                    state.key().link().as_str(),
                    state.key().profile().as_bytes(),
                    state_bytes,
                    manifest.session_id.as_str(),
                    manifest.config_digest,
                    manifest.decoder_version,
                    state.compatibility().conditioning_version().as_str(),
                    manifest.algorithm_version,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(fact_bytes)
    }

    pub(crate) fn admit_and_append(
        &mut self,
        admission: Admission<'_>,
        packet: &CapturedPacket,
        max_record_bytes: u64,
    ) -> Result<(), DatabaseError> {
        let record = SessionRecord {
            record_seq: packet.record_seq(),
            at: crate::domain::time::SessionTime::from_nanos(packet.receive_monotonic_ns()),
            kind: SessionRecordKind::Packet {
                receive_utc_ns: packet.receive_utc_ns(),
                peer: packet.peer(),
                wire_format: packet.wire_format(),
                bytes: packet.bytes().into(),
            },
        };
        let body = encode_record_body(&record.kind)?;
        if body.len() as u64 > max_record_bytes {
            return Err(DatabaseError::TooLarge);
        }
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_admission(&transaction, admission)?;
        append_record(&transaction, packet.session_id(), &record, &body)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn append_control(
        &mut self,
        session: &SessionId,
        record: &ControlRecordInput,
        max_record_bytes: u64,
    ) -> Result<(), DatabaseError> {
        let record = record.record();
        let body = encode_record_body(&record.kind)?;
        if body.len() as u64 > max_record_bytes {
            return Err(DatabaseError::TooLarge);
        }
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        append_record(&transaction, session, record, &body)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn manifest(
        &self,
        session: &SessionId,
        max_bytes: u64,
    ) -> Result<SessionManifest, DatabaseError> {
        let bytes = bounded_blob(
            &self.connection,
            "SELECT length(manifest_cbor), manifest_cbor FROM sessions WHERE session_id = ?1",
            session.as_str(),
            max_bytes,
        )?;
        Ok(decode_manifest(&bytes, 0)?)
    }

    pub(crate) fn baseline_states(
        &self,
        session: &SessionId,
        max_manifest_bytes: u64,
        max_state_bytes: u64,
    ) -> Result<Vec<BaselineState>, DatabaseError> {
        let manifest = self.manifest(session, max_manifest_bytes)?;
        let processing: (Vec<u8>, String, String, String) = self.connection.query_row(
            "SELECT config_digest, decoder_version, conditioning_version, algorithm_version
             FROM session_processing_state WHERE session_id = ?1",
            [session.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if processing.0.as_slice() != manifest.config_digest
            || processing.1 != manifest.decoder_version
            || processing.2 != manifest.conditioning_version
            || processing.3 != manifest.algorithm_version
        {
            return Err(DatabaseError::Session(SessionError::Schema(
                "processing state receipts do not match manifest".into(),
            )));
        }
        let mut statement = self.connection.prepare(
            "SELECT deployment_id, link_id, profile_id, length(estimator_state_cbor),
                    source_record_seq, config_digest, decoder_version, conditioning_version,
                    algorithm_version, estimator_state_cbor
             FROM baseline_states WHERE source_session_id = ?1 ORDER BY link_id, profile_id",
        )?;
        let mut rows = statement.query([session.as_str()])?;
        let mut states = Vec::new();
        while let Some(row) = rows.next()? {
            let length: u64 = row.get(3)?;
            if length > max_state_bytes {
                return Err(DatabaseError::TooLarge);
            }
            let deployment: String = row.get(0)?;
            let link: String = row.get(1)?;
            let profile: Vec<u8> = row.get(2)?;
            let source_record: Option<Vec<u8>> = row.get(4)?;
            let config: Vec<u8> = row.get(5)?;
            let decoder: String = row.get(6)?;
            let conditioning: String = row.get(7)?;
            let algorithm: String = row.get(8)?;
            let state = decode_baseline_state(&row.get::<_, Vec<u8>>(9)?)?;
            let source_record = source_record.as_deref().map(decode_u64).transpose()?;
            if deployment != state.compatibility().deployment().as_str()
                || link != state.key().link().as_str()
                || profile.as_slice() != state.key().profile().as_bytes()
                || config != processing.0
                || decoder != processing.1
                || conditioning != state.compatibility().conditioning_version().as_str()
                || algorithm != processing.3
            {
                return Err(DatabaseError::Session(SessionError::Schema(
                    "stored baseline state receipts do not match body".into(),
                )));
            }
            if source_record.is_none()
                && !manifest.initial_baseline_states.iter().any(|seed| seed == &state)
            {
                return Err(DatabaseError::Session(SessionError::Schema(
                    "manifest-seeded baseline state does not match manifest".into(),
                )));
            }
            states.push(state);
        }
        if states.windows(2).any(|pair| pair[0].key() >= pair[1].key()) {
            return Err(DatabaseError::Session(SessionError::Schema(
                "stored baseline state keys are not strictly ordered".into(),
            )));
        }
        Ok(states)
    }

    pub(crate) fn records(
        &self,
        session: &SessionId,
        max_record_bytes: u64,
        sealed_only: bool,
    ) -> Result<Vec<SessionRecord>, DatabaseError> {
        if sealed_only {
            let lifecycle: String = self.connection.query_row(
                "SELECT lifecycle FROM sessions WHERE session_id = ?1",
                [session.as_str()],
                |row| row.get(0),
            )?;
            if lifecycle != LIFECYCLE_SEALED && lifecycle != LIFECYCLE_RECOVERY_SEALED {
                return Err(DatabaseError::NotActive);
            }
        }
        let mut statement = self.connection.prepare(
            "SELECT record_seq, session_time, kind, length(body_cbor), body_cbor FROM session_records
             WHERE session_id = ?1 ORDER BY record_seq",
        )?;
        let mut rows = statement.query([session.as_str()])?;
        let mut records = Vec::new();
        let mut expected = 0_u64;
        let mut previous_time = None;
        let mut closed = false;
        while let Some(row) = rows.next()? {
            if closed {
                return Err(DatabaseError::Session(SessionError::Schema(
                    "stored record follows closed".into(),
                )));
            }
            let record_seq = decode_u64(&row.get::<_, Vec<u8>>(0)?)?;
            let session_time = decode_u64(&row.get::<_, Vec<u8>>(1)?)?;
            let stored_kind = RecordKind::parse(&row.get::<_, String>(2)?)?;
            let length: u64 = row.get(3)?;
            if length > max_record_bytes {
                return Err(DatabaseError::TooLarge);
            }
            let kind = decode_record_body(stored_kind, &row.get::<_, Vec<u8>>(4)?)?;
            if record_seq != expected {
                return Err(DatabaseError::Sequence { expected, actual: record_seq });
            }
            if let Some(previous) = previous_time.filter(|previous| session_time < *previous) {
                return Err(DatabaseError::TimeReversed { previous, actual: session_time });
            }
            expected = expected.saturating_add(1);
            previous_time = Some(session_time);
            closed = matches!(kind, crate::session::SessionRecordKind::Closed);
            records.push(SessionRecord {
                record_seq,
                at: crate::domain::time::SessionTime::from_nanos(session_time),
                kind,
            });
        }
        Ok(records)
    }

    pub(crate) fn incomplete_sessions(&self) -> Result<Vec<SessionId>, DatabaseError> {
        let mut statement = self.connection.prepare(
            "SELECT session_id FROM sessions WHERE lifecycle = ?1 ORDER BY started_utc_ns, session_id",
        )?;
        statement
            .query_map([LIFECYCLE_ACTIVE], |row| row.get::<_, String>(0))?
            .map(|result| {
                SessionId::new(result?).map_err(|error| {
                    DatabaseError::Session(SessionError::Schema(error.to_string()))
                })
            })
            .collect()
    }

    pub(crate) fn recovery_seal(
        &mut self,
        session: &SessionId,
        sealed_utc_ns: i64,
    ) -> Result<(), DatabaseError> {
        let changed = self.connection.execute(
            "UPDATE sessions SET lifecycle = ?1, sealed_utc_ns = ?2
             WHERE session_id = ?3 AND lifecycle = ?4",
            params![LIFECYCLE_RECOVERY_SEALED, sealed_utc_ns, session.as_str(), LIFECYCLE_ACTIVE],
        )?;
        if changed == 1 { Ok(()) } else { Err(DatabaseError::NotActive) }
    }

    pub(crate) fn seal(
        &mut self,
        session: &SessionId,
        sealed_utc_ns: i64,
    ) -> Result<(), DatabaseError> {
        let changed = self.connection.execute(
            "UPDATE sessions SET lifecycle = ?1, sealed_utc_ns = ?2
             WHERE session_id = ?3 AND lifecycle = ?4
               AND EXISTS (SELECT 1 FROM session_records r
                           WHERE r.session_id = sessions.session_id AND r.kind = 'closed')",
            params![LIFECYCLE_SEALED, sealed_utc_ns, session.as_str(), LIFECYCLE_ACTIVE],
        )?;
        if changed == 1 { Ok(()) } else { Err(DatabaseError::NotActive) }
    }

    pub(crate) fn retain_sealed(&mut self, keep: u32) -> Result<u64, DatabaseError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = transaction.execute(
            "DELETE FROM sessions WHERE session_id IN (
                 SELECT session_id FROM sessions
                 WHERE lifecycle IN ('sealed', 'recovery_sealed')
                   AND NOT EXISTS (
                       SELECT 1 FROM baseline_states
                       WHERE source_session_id = sessions.session_id
                   )
                 ORDER BY started_utc_ns DESC, session_id DESC
                 LIMIT -1 OFFSET ?1
             )",
            [keep],
        )?;
        transaction.commit()?;
        Ok(removed as u64)
    }

    #[cfg(test)]
    fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// A read-only SQLite connection for committed projections.
#[derive(Debug)]
pub(crate) struct DatabaseReader {
    connection: Connection,
}

impl DatabaseReader {
    pub(crate) fn open_existing(path: &Path) -> Result<Self, DatabaseError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| classify_existing_open_error(path, error))?;
        verify_store_identity(&connection)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        verify_connection(&connection, false)?;
        Ok(Self { connection })
    }

    #[cfg(test)]
    fn connection(&self) -> &Connection {
        &self.connection
    }
}

fn classify_existing_open_error(path: &Path, error: rusqlite::Error) -> DatabaseError {
    if matches!(path.try_exists(), Ok(false)) {
        DatabaseError::Missing
    } else {
        DatabaseError::Sql(error)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EpochHandle {
    device: DeviceId,
    key_epoch: KeyEpoch,
    replay_window_identity: ReplayWindowIdentity,
    replay_window_size: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Admission<'a> {
    epoch: &'a EpochHandle,
    boot_generation: u32,
    message_sequence: u64,
}

impl<'a> Admission<'a> {
    pub(crate) const fn new(
        epoch: &'a EpochHandle,
        boot_generation: u32,
        message_sequence: u64,
    ) -> Self {
        Self { epoch, boot_generation, message_sequence }
    }
}

fn validate_admission_state(
    replay_window_size: u16,
    boot_generation: Option<&[u8]>,
    maximum_message_sequence: Option<&[u8]>,
    bitmap: &[u8],
) -> Result<(), DatabaseError> {
    if bitmap.len() != usize::from(replay_window_size).div_ceil(8) {
        return Err(DatabaseError::EpochConflict);
    }
    let used_bits = replay_window_size % 8;
    if used_bits != 0 {
        let padding_mask = !((1_u8 << used_bits) - 1);
        if bitmap.last().is_some_and(|byte| byte & padding_mask != 0) {
            return Err(DatabaseError::EpochConflict);
        }
    }
    match (boot_generation, maximum_message_sequence) {
        (None, None) if bitmap.iter().all(|byte| *byte == 0) => Ok(()),
        (Some(boot), Some(maximum))
            if decode_u32(boot)? != 0 && decode_u64(maximum)? != 0 && is_seen(bitmap, 0) =>
        {
            Ok(())
        }
        _ => Err(DatabaseError::EpochConflict),
    }
}

fn configure_writer(connection: &Connection) -> Result<(), DatabaseError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn verify_store_identity(connection: &Connection) -> Result<(), DatabaseError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(DatabaseError::SchemaVersion { actual: version, expected: SCHEMA_VERSION });
    }
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(DatabaseError::Pragma {
            name: "journal_mode",
            actual: journal,
            expected: "wal",
        });
    }
    Ok(())
}

fn verify_connection(connection: &Connection, writer: bool) -> Result<(), DatabaseError> {
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(DatabaseError::Pragma {
            name: "foreign_keys",
            actual: foreign_keys.to_string(),
            expected: "1",
        });
    }
    if writer {
        let synchronous: i64 =
            connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        if synchronous != 2 {
            return Err(DatabaseError::Pragma {
                name: "synchronous",
                actual: synchronous.to_string(),
                expected: "2 (FULL)",
            });
        }
    }
    Ok(())
}

fn advance_admission(
    transaction: &Transaction<'_>,
    admission: Admission<'_>,
) -> Result<(), DatabaseError> {
    if admission.boot_generation == 0 || admission.message_sequence == 0 {
        return Err(DatabaseError::Replay);
    }
    let row = transaction
        .query_row(
            "SELECT replay_window_identity, replay_window_size, highest_boot_generation,
                    maximum_message_sequence, seen_bitmap
             FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
            params![
                u64_bytes(admission.epoch.device.get()),
                u16_bytes(admission.epoch.key_epoch.get())
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u16>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::MissingEpoch)?;
    if row.0.as_slice() != admission.epoch.replay_window_identity.as_bytes()
        || row.1 != admission.epoch.replay_window_size
    {
        return Err(DatabaseError::EpochConflict);
    }
    let mut bitmap = row.4;
    validate_admission_state(
        admission.epoch.replay_window_size,
        row.2.as_deref(),
        row.3.as_deref(),
        &bitmap,
    )?;
    let previous_boot = row.2.as_deref().map(decode_u32).transpose()?;
    let previous_maximum = row.3.as_deref().map(decode_u64).transpose()?;
    let (boot, maximum) = match (previous_boot, previous_maximum) {
        (None, None) => {
            bitmap.fill(0);
            set_seen(&mut bitmap, 0);
            (admission.boot_generation, admission.message_sequence)
        }
        (Some(previous_boot), Some(_)) if admission.boot_generation > previous_boot => {
            bitmap.fill(0);
            set_seen(&mut bitmap, 0);
            (admission.boot_generation, admission.message_sequence)
        }
        (Some(previous_boot), Some(_)) if admission.boot_generation < previous_boot => {
            return Err(DatabaseError::Replay);
        }
        (Some(previous_boot), Some(previous_maximum)) => {
            if admission.message_sequence > previous_maximum {
                shift_seen(
                    &mut bitmap,
                    admission.message_sequence - previous_maximum,
                    admission.epoch.replay_window_size,
                );
                set_seen(&mut bitmap, 0);
                (previous_boot, admission.message_sequence)
            } else {
                let age = previous_maximum - admission.message_sequence;
                if age >= u64::from(admission.epoch.replay_window_size) || is_seen(&bitmap, age) {
                    return Err(DatabaseError::Replay);
                }
                set_seen(&mut bitmap, age);
                (previous_boot, previous_maximum)
            }
        }
        _ => return Err(DatabaseError::EpochConflict),
    };
    transaction.execute(
        "UPDATE admission_epochs SET highest_boot_generation = ?1,
                maximum_message_sequence = ?2, seen_bitmap = ?3
         WHERE device_id = ?4 AND key_epoch = ?5",
        params![
            u32_bytes(boot),
            u64_bytes(maximum),
            bitmap,
            u64_bytes(admission.epoch.device.get()),
            u16_bytes(admission.epoch.key_epoch.get())
        ],
    )?;
    Ok(())
}

fn append_record(
    transaction: &Transaction<'_>,
    session: &SessionId,
    record: &SessionRecord,
    body: &[u8],
) -> Result<(), DatabaseError> {
    let lifecycle = transaction
        .query_row(
            "SELECT lifecycle FROM sessions WHERE session_id = ?1",
            [session.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(DatabaseError::NotActive)?;
    if lifecycle != LIFECYCLE_ACTIVE {
        return Err(DatabaseError::NotActive);
    }
    let previous = transaction
        .query_row(
            "SELECT record_seq, session_time, kind FROM session_records
             WHERE session_id = ?1 ORDER BY record_seq DESC LIMIT 1",
            [session.as_str()],
            |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?))
            },
        )
        .optional()?;
    let (expected, previous_time) = match previous {
        None => (0, None),
        Some((_, _, ref kind)) if kind == "closed" => return Err(DatabaseError::NotActive),
        Some((sequence, time, _)) => {
            let sequence = decode_u64(&sequence)?;
            (
                sequence.checked_add(1).ok_or(DatabaseError::Sequence {
                    expected: u64::MAX,
                    actual: record.record_seq,
                })?,
                Some(decode_u64(&time)?),
            )
        }
    };
    if record.record_seq != expected {
        return Err(DatabaseError::Sequence { expected, actual: record.record_seq });
    }
    if let Some(previous) = previous_time.filter(|previous| record.at.as_nanos() < *previous) {
        return Err(DatabaseError::TimeReversed { previous, actual: record.at.as_nanos() });
    }
    transaction.execute(
        "INSERT INTO session_records (session_id, record_seq, session_time, kind, body_cbor)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            session.as_str(),
            u64_bytes(record.record_seq),
            u64_bytes(record.at.as_nanos()),
            RecordKind::from_record(&record.kind).as_str(),
            body
        ],
    )?;
    Ok(())
}

fn bounded_blob(
    connection: &Connection,
    sql: &str,
    key: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, DatabaseError> {
    let length: u64 = connection.query_row(sql, [key], |row| row.get(0))?;
    if length > max_bytes {
        return Err(DatabaseError::TooLarge);
    }
    Ok(connection.query_row(sql, [key], |row| row.get(1))?)
}

fn shift_seen(bitmap: &mut [u8], amount: u64, replay_window_size: u16) {
    if amount >= u64::from(replay_window_size) {
        bitmap.fill(0);
        return;
    }
    for bit in (0..usize::from(replay_window_size)).rev() {
        let source = bit.checked_sub(amount as usize);
        let value = source.is_some_and(|source| is_seen(bitmap, source as u64));
        if value { set_seen(bitmap, bit as u64) } else { clear_seen(bitmap, bit as u64) }
    }
}

fn is_seen(bitmap: &[u8], age: u64) -> bool {
    bitmap[age as usize / 8] & (1 << (age % 8)) != 0
}

fn set_seen(bitmap: &mut [u8], age: u64) {
    bitmap[age as usize / 8] |= 1 << (age % 8);
}

fn clear_seen(bitmap: &mut [u8], age: u64) {
    bitmap[age as usize / 8] &= !(1 << (age % 8));
}

fn u16_bytes(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}
fn u32_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}
fn u64_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u32(bytes: &[u8]) -> Result<u32, DatabaseError> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| DatabaseError::UnsignedWidth)?))
}

fn decode_u64(bytes: &[u8]) -> Result<u64, DatabaseError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| DatabaseError::UnsignedWidth)?))
}

const SCHEMA: &str = r#"
BEGIN;
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
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    started_utc_ns INTEGER NOT NULL,
    manifest_cbor BLOB NOT NULL,
    fact_bytes BLOB NOT NULL CHECK(length(fact_bytes) = 8),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active', 'sealed', 'recovery_sealed')),
    sealed_utc_ns INTEGER,
    CHECK((lifecycle = 'active') = (sealed_utc_ns IS NULL))
);
CREATE UNIQUE INDEX one_active_session ON sessions(lifecycle) WHERE lifecycle = 'active';
CREATE INDEX sessions_retention ON sessions(lifecycle, started_utc_ns, session_id);
CREATE TABLE session_records (
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time BLOB NOT NULL CHECK(length(session_time) = 8),
    kind TEXT NOT NULL CHECK(kind IN ('packet', 'baseline_command', 'timeline_advance', 'closed')),
    body_cbor BLOB NOT NULL,
    PRIMARY KEY (session_id, record_seq)
) WITHOUT ROWID;
CREATE INDEX session_records_time ON session_records(session_id, session_time, record_seq);
CREATE TABLE session_processing_state (
    session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
    processed_through_record_seq BLOB
        CHECK(processed_through_record_seq IS NULL OR length(processed_through_record_seq) = 8),
    timeline_state_cbor BLOB,
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    FOREIGN KEY (session_id, processed_through_record_seq)
        REFERENCES session_records(session_id, record_seq)
);
CREATE INDEX processing_by_cursor
    ON session_processing_state(processed_through_record_seq, session_id);
CREATE TABLE csi_observations (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time BLOB NOT NULL CHECK(length(session_time) = 8),
    sensor_id TEXT NOT NULL, link_id TEXT NOT NULL, profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    observation_cbor BLOB NOT NULL, decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id, record_seq) REFERENCES session_records(session_id, record_seq) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX csi_by_link_time ON csi_observations(link_id, profile_id, session_time, record_seq);
CREATE INDEX csi_by_sensor_time ON csi_observations(sensor_id, session_time, record_seq);
CREATE TABLE world_snapshots (
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    snapshot_id BLOB NOT NULL CHECK(length(snapshot_id) = 8),
    interval_start BLOB NOT NULL CHECK(length(interval_start) = 8),
    interval_end BLOB NOT NULL CHECK(length(interval_end) = 8),
    snapshot_cbor BLOB NOT NULL,
    source_record_start BLOB NOT NULL CHECK(length(source_record_start) = 8),
    source_record_end BLOB NOT NULL CHECK(length(source_record_end) = 8),
    algorithm_version TEXT NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    PRIMARY KEY (session_id, snapshot_id)
) WITHOUT ROWID;
CREATE INDEX snapshots_by_interval ON world_snapshots(interval_start, interval_end, snapshot_id);
CREATE TABLE snapshot_link_evidence (
    session_id TEXT NOT NULL, snapshot_id BLOB NOT NULL CHECK(length(snapshot_id) = 8),
    link_id TEXT NOT NULL, profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    evidence_cbor BLOB NOT NULL,
    source_record_start BLOB NOT NULL CHECK(length(source_record_start) = 8),
    source_record_end BLOB NOT NULL CHECK(length(source_record_end) = 8),
    conditioning_version TEXT NOT NULL, algorithm_version TEXT NOT NULL,
    PRIMARY KEY (session_id, snapshot_id, link_id, profile_id),
    FOREIGN KEY (session_id, snapshot_id) REFERENCES world_snapshots(session_id, snapshot_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX evidence_by_link ON snapshot_link_evidence(link_id, profile_id, session_id, snapshot_id);
CREATE TABLE baseline_states (
    deployment_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    estimator_state_cbor BLOB NOT NULL,
    source_session_id TEXT NOT NULL REFERENCES sessions(session_id),
    source_record_seq BLOB
        CHECK(source_record_seq IS NULL OR length(source_record_seq) = 8),
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    FOREIGN KEY (source_session_id, source_record_seq)
        REFERENCES session_records(session_id, record_seq),
    PRIMARY KEY (deployment_id, link_id, profile_id)
) WITHOUT ROWID;
CREATE INDEX baseline_by_source ON baseline_states(source_session_id, source_record_seq);
COMMIT;
"#;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::capture::{CapturedPacket, WireFormat};
    use crate::domain::csi::{CaptureProfileId, CsiPath, CsiSampleCoordinate};
    use crate::domain::identity::{
        BaselineContractId, BaselineRevision, BaselineStateSequence, ConditioningVersion,
        DeploymentId, LinkProfileKey, RadioLinkId, SessionId, SpaceId,
    };
    use crate::domain::time::SessionTime;
    use crate::domain::world::{
        BaselineCommand, BaselineCompatibilityReceipt, BaselineCoordinateKey, BaselineLifecycle,
        EwState, TargetedBaselineCommand, WelfordState,
    };
    use crate::session::WireAdmissionPin;

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn database_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-database-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn set_journal_mode(path: &Path, mode: &str) {
        let connection = Connection::open(path).expect("open raw database");
        connection.pragma_update(None, "journal_mode", mode).expect("set journal mode");
    }

    fn journal_mode(path: &Path) -> String {
        let connection = Connection::open(path).expect("open raw database");
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0)).expect("journal mode")
    }

    fn set_user_version(path: &Path, version: i64) {
        let connection = Connection::open(path).expect("open raw database");
        connection.pragma_update(None, "user_version", version).expect("set user version");
    }

    fn user_version(path: &Path) -> i64 {
        let connection = Connection::open(path).expect("open raw database");
        connection.pragma_query_value(None, "user_version", |row| row.get(0)).expect("user version")
    }

    fn manifest(id: &str, started_utc_ns: i64) -> SessionManifest {
        manifest_with_states(id, started_utc_ns, Vec::new())
    }

    fn manifest_with_states(
        id: &str,
        started_utc_ns: i64,
        initial_baseline_states: Vec<BaselineState>,
    ) -> SessionManifest {
        let replay_config = crate::config::parse_config(include_str!(
            "../tests/fixtures/config/valid-two-esp32.toml"
        ))
        .expect("valid config")
        .replay()
        .clone();
        SessionManifest {
            session_id: SessionId::new(id).expect("session id"),
            started_utc_ns,
            config_digest: replay_config.digest(),
            replay_config,
            application_version: "0.1.0".into(),
            build_fingerprint: [0x22; 32],
            decoder_version: "native-frame-v1".into(),
            wire_admission: vec![
                WireAdmissionPin {
                    wire_version: 1,
                    device_id: DeviceId::new(1),
                    key_epoch: KeyEpoch::try_new(1).expect("key epoch"),
                    firmware_build_digest: [0x01; 32],
                    capability_digest: [0x02; 32],
                    maximum_plaintext_bytes: 705,
                    transport_datagram_budget_bytes: 2048,
                },
                WireAdmissionPin {
                    wire_version: 1,
                    device_id: DeviceId::new(2),
                    key_epoch: KeyEpoch::try_new(1).expect("key epoch"),
                    firmware_build_digest: [0x03; 32],
                    capability_digest: [0x04; 32],
                    maximum_plaintext_bytes: 705,
                    transport_datagram_budget_bytes: 4096,
                },
            ],
            conditioning_version: "amplitude-v1".into(),
            algorithm_version: "baseline-v1".into(),
            initial_baseline_states,
        }
    }

    fn compatibility() -> BaselineCompatibilityReceipt {
        BaselineCompatibilityReceipt::new(
            DeploymentId::new("lab").expect("deployment"),
            SpaceId::new("room").expect("space"),
            ConditioningVersion::new("amplitude-v1").expect("conditioning"),
            BaselineContractId::from_bytes([0x66; 32]),
        )
    }

    fn coordinate() -> BaselineCoordinateKey {
        BaselineCoordinateKey::new(
            CsiPath::RawPathOrdinal(0),
            CsiSampleCoordinate::OpaqueSampleOrdinal(0),
        )
    }

    fn learning_seed_state() -> BaselineState {
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            BaselineLifecycle::Learning { accepted_windows: 4, accepted_exposure_ns: 40 },
            BTreeMap::from([(
                coordinate(),
                WelfordState::try_new(8, 1.5, 2.75, 35).expect("welford"),
            )]),
            BTreeMap::new(),
            None,
            None,
            false,
            None,
            compatibility(),
        )
        .expect("learning")
    }

    fn active_seed_state() -> BaselineState {
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new("link-b").expect("link"),
                CaptureProfileId::from_bytes([0x56; 32]),
            ),
            BaselineLifecycle::Active,
            BTreeMap::new(),
            BTreeMap::from([(coordinate(), EwState::try_new(12, 2.5, 0.75, 80).expect("EW"))]),
            Some(BaselineRevision::new(3)),
            Some(BaselineStateSequence::new(9)),
            false,
            None,
            compatibility(),
        )
        .expect("active")
    }

    fn packet(session: &SessionId, record_seq: u64, at: u64) -> CapturedPacket {
        CapturedPacket::new(
            session.clone(),
            record_seq,
            at,
            -5,
            "192.0.2.1:9000".parse::<SocketAddr>().expect("peer"),
            WireFormat::NativeFrameUdp,
            vec![1, 2, 3].into_boxed_slice(),
        )
    }

    #[test]
    fn session_creation_reserves_closed_and_returns_committed_manifest_fact_bytes() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("fact-byte-limit", 0);
        let encoded_manifest = encode_manifest(&manifest).expect("encode manifest");
        let manifest_len = encoded_manifest.len();
        let manifest_bytes = u64::try_from(manifest_len).expect("manifest length fits u64");
        let exact_limit = manifest_bytes.checked_add(23).expect("specified Closed reservation");

        let error = database
            .create_session(&manifest, manifest_bytes, exact_limit - 1)
            .expect_err("one byte below the reserved Closed limit must fail");
        assert!(matches!(
            error,
            DatabaseError::SessionLimit {
                manifest_bytes: actual_manifest,
                reserved_closed_bytes: 23,
                max_session_bytes,
            } if actual_manifest == manifest_len && max_session_bytes == exact_limit - 1
        ));
        assert_eq!(
            database
                .connection()
                .query_row(
                    "SELECT count(*) FROM sessions WHERE session_id = ?1",
                    [manifest.session_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .expect("session count after rejected creation"),
            0
        );

        let committed = database
            .create_session(&manifest, manifest_bytes, exact_limit)
            .expect("exact reserved Closed limit succeeds");
        assert_eq!(committed.get(), manifest_bytes);

        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn provisioning_is_exactly_idempotent_only_while_the_epoch_is_fresh() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let device = DeviceId::new(7);
        let key_epoch = KeyEpoch::try_new(3).expect("epoch");
        let identity = ReplayWindowIdentity::new([0x11; 32]);

        database.provision_epoch(device, key_epoch, &identity, 9).expect("provision");
        database.provision_epoch(device, key_epoch, &identity, 9).expect("exact retry");
        assert!(matches!(
            database.provision_epoch(device, key_epoch, &ReplayWindowIdentity::new([0x12; 32]), 9,),
            Err(DatabaseError::EpochConflict)
        ));
        assert!(matches!(
            database.provision_epoch(device, key_epoch, &identity, 8),
            Err(DatabaseError::EpochConflict)
        ));

        database
            .connection()
            .execute(
                "UPDATE admission_epochs
                 SET highest_boot_generation = ?1, maximum_message_sequence = ?2,
                     seen_bitmap = ?3
                 WHERE device_id = ?4 AND key_epoch = ?5",
                params![
                    u32_bytes(1),
                    u64_bytes(1),
                    vec![1_u8, 0],
                    u64_bytes(device.get()),
                    u16_bytes(key_epoch.get())
                ],
            )
            .expect("advance epoch");
        assert!(matches!(
            database.provision_epoch(device, key_epoch, &identity, 9),
            Err(DatabaseError::EpochConflict)
        ));
        let stored: (Vec<u8>, Vec<u8>, Vec<u8>) = database
            .connection()
            .query_row(
                "SELECT highest_boot_generation, maximum_message_sequence, seen_bitmap
                 FROM admission_epochs WHERE device_id = ?1 AND key_epoch = ?2",
                params![u64_bytes(device.get()), u16_bytes(key_epoch.get())],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("stored epoch");
        assert_eq!(stored, (u32_bytes(1).to_vec(), u64_bytes(1).to_vec(), vec![1, 0]));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn capture_validation_returns_owned_handles_for_fresh_and_advanced_epochs() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let device = DeviceId::new(7);
        let key_epoch = KeyEpoch::try_new(3).expect("epoch");
        let identity = ReplayWindowIdentity::new([0x11; 32]);
        database.provision_epoch(device, key_epoch, &identity, 9).expect("provision");

        let fresh = database.validate_epoch(device, key_epoch, identity, 9).expect("fresh handle");
        assert_eq!(fresh.device, device);
        assert_eq!(fresh.key_epoch, key_epoch);
        assert_eq!(fresh.replay_window_identity, identity);
        assert_eq!(fresh.replay_window_size, 9);

        database
            .connection()
            .execute(
                "UPDATE admission_epochs
                 SET highest_boot_generation = ?1, maximum_message_sequence = ?2,
                     seen_bitmap = ?3
                 WHERE device_id = ?4 AND key_epoch = ?5",
                params![
                    u32_bytes(1),
                    u64_bytes(2),
                    vec![1_u8, 0],
                    u64_bytes(device.get()),
                    u16_bytes(key_epoch.get())
                ],
            )
            .expect("advance epoch");
        let advanced =
            database.validate_epoch(device, key_epoch, identity, 9).expect("advanced handle");
        assert_eq!(advanced.replay_window_identity, identity);
        assert_eq!(advanced.replay_window_size, 9);
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn capture_validation_rejects_missing_mismatched_and_corrupt_epochs() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let device = DeviceId::new(7);
        let key_epoch = KeyEpoch::try_new(3).expect("epoch");
        let identity = ReplayWindowIdentity::new([0x11; 32]);
        database.provision_epoch(device, key_epoch, &identity, 9).expect("provision");
        assert!(matches!(
            database.validate_epoch(DeviceId::new(8), key_epoch, identity, 9),
            Err(DatabaseError::MissingEpoch)
        ));
        assert!(matches!(
            database.validate_epoch(device, key_epoch, ReplayWindowIdentity::new([0x12; 32]), 9,),
            Err(DatabaseError::EpochConflict)
        ));
        assert!(matches!(
            database.validate_epoch(device, key_epoch, identity, 8),
            Err(DatabaseError::EpochConflict)
        ));

        database
            .connection()
            .pragma_update(None, "ignore_check_constraints", true)
            .expect("allow corruption setup");
        database
            .connection()
            .execute("UPDATE admission_epochs SET replay_window_identity = x'11'", [])
            .expect("malform stored identity");
        assert!(database.validate_epoch(device, key_epoch, identity, 9).is_err());
        database
            .connection()
            .execute(
                "UPDATE admission_epochs SET replay_window_identity = ?1",
                [identity.as_bytes()],
            )
            .expect("restore stored identity");
        let corruptions = [
            "highest_boot_generation = x'00000001', maximum_message_sequence = NULL,
             seen_bitmap = x'0000'",
            "highest_boot_generation = x'01', maximum_message_sequence = x'0000000000000001',
             seen_bitmap = x'0100'",
            "highest_boot_generation = x'00000000', maximum_message_sequence = x'0000000000000001',
             seen_bitmap = x'0100'",
            "highest_boot_generation = x'00000001', maximum_message_sequence = x'0000000000000000',
             seen_bitmap = x'0100'",
            "highest_boot_generation = NULL, maximum_message_sequence = NULL,
             seen_bitmap = x'0100'",
            "highest_boot_generation = x'00000001', maximum_message_sequence = x'0000000000000001',
             seen_bitmap = x'0000'",
            "highest_boot_generation = x'00000001', maximum_message_sequence = x'0000000000000001',
             seen_bitmap = x'01'",
            "highest_boot_generation = x'00000001', maximum_message_sequence = x'0000000000000001',
             seen_bitmap = x'0102'",
        ];
        for corruption in corruptions {
            database
                .connection()
                .execute(&format!("UPDATE admission_epochs SET {corruption}"), [])
                .expect("corrupt epoch");
            assert!(
                database.validate_epoch(device, key_epoch, identity, 9).is_err(),
                "accepted corruption: {corruption}"
            );
        }
        database
            .connection()
            .pragma_update(None, "ignore_check_constraints", false)
            .expect("restore constraints");
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn admission_requires_a_validated_handle_and_transaction_a_rereads_it() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("validated-admission", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        let device = DeviceId::new(7);
        let key_epoch = KeyEpoch::try_new(3).expect("epoch");
        let identity = ReplayWindowIdentity::new([0x11; 32]);
        database.provision_epoch(device, key_epoch, &identity, 9).expect("provision");
        let handle = database.validate_epoch(device, key_epoch, identity, 9).expect("handle");
        let admission = Admission::new(&handle, 1, 1);
        let packet = packet(&manifest.session_id, 0, 10);

        database
            .connection()
            .execute(
                "UPDATE admission_epochs SET replay_window_identity = ?1
                 WHERE device_id = ?2 AND key_epoch = ?3",
                params![[0x12_u8; 32], u64_bytes(device.get()), u16_bytes(key_epoch.get())],
            )
            .expect("replace stored identity");
        assert!(matches!(
            database.admit_and_append(admission, &packet, 64 * 1024),
            Err(DatabaseError::EpochConflict)
        ));
        assert!(
            database.records(&manifest.session_id, 64 * 1024, false).expect("records").is_empty()
        );

        database
            .connection()
            .execute(
                "UPDATE admission_epochs SET replay_window_identity = ?1
                 WHERE device_id = ?2 AND key_epoch = ?3",
                params![identity.as_bytes(), u64_bytes(device.get()), u16_bytes(key_epoch.get())],
            )
            .expect("restore stored identity");
        database
            .admit_and_append(admission, &packet, 64 * 1024)
            .expect("append with validated handle");
        assert_eq!(
            database.records(&manifest.session_id, 64 * 1024, false).expect("records").len(),
            1
        );
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn admission_advance_discards_ages_that_leave_the_configured_window() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("window-padding", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        let device = DeviceId::new(7);
        let key_epoch = KeyEpoch::try_new(3).expect("epoch");
        let identity = ReplayWindowIdentity::new([0x11; 32]);
        database.provision_epoch(device, key_epoch, &identity, 9).expect("provision");
        let handle = database.validate_epoch(device, key_epoch, identity, 9).expect("handle");

        for (record_seq, at, message_sequence) in [(0, 10, 9), (1, 11, 1), (2, 12, 10)] {
            database
                .admit_and_append(
                    Admission::new(&handle, 1, message_sequence),
                    &packet(&manifest.session_id, record_seq, at),
                    64 * 1024,
                )
                .expect("admit packet");
        }
        database
            .validate_epoch(device, key_epoch, identity, 9)
            .expect("transaction produced a valid bounded window");
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn append_interfaces_persist_captured_packets_and_strong_control_inputs() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("strong-append-inputs", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        let replay_window_identity = ReplayWindowIdentity::new([0x11; 32]);
        database
            .provision_epoch(
                DeviceId::new(7),
                KeyEpoch::try_new(3).expect("epoch"),
                &replay_window_identity,
                8,
            )
            .expect("initialize epoch");
        let handle = database
            .validate_epoch(
                DeviceId::new(7),
                KeyEpoch::try_new(3).expect("epoch"),
                replay_window_identity,
                8,
            )
            .expect("validate epoch");
        let packet = CapturedPacket::new(
            manifest.session_id.clone(),
            0,
            10,
            -5,
            "192.0.2.1:9000".parse().expect("peer"),
            WireFormat::NativeFrameUdp,
            vec![1, 2, 3].into_boxed_slice(),
        );
        database
            .admit_and_append(Admission::new(&handle, 1, 1), &packet, 64 * 1024)
            .expect("append packet");
        database
            .append_control(
                &manifest.session_id,
                &ControlRecordInput::closed(1, SessionTime::from_nanos(11)),
                64 * 1024,
            )
            .expect("append control");
        let records = database.records(&manifest.session_id, 64 * 1024, false).expect("records");
        assert_eq!(records[0].record_seq, packet.record_seq());
        assert_eq!(records[0].at, SessionTime::from_nanos(packet.receive_monotonic_ns()));
        assert!(matches!(
            &records[0].kind,
            SessionRecordKind::Packet {
                receive_utc_ns,
                peer,
                wire_format,
                bytes,
            } if *receive_utc_ns == packet.receive_utc_ns()
                && *peer == packet.peer()
                && *wire_format == packet.wire_format()
                && bytes.as_ref() == packet.bytes()
        ));
        assert!(matches!(records[1].kind, SessionRecordKind::Closed));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn record_rows_store_only_strict_kind_specific_bodies() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("record-bodies", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        let replay_window_identity = ReplayWindowIdentity::new([0x11; 32]);
        database
            .provision_epoch(
                DeviceId::new(7),
                KeyEpoch::try_new(3).expect("epoch"),
                &replay_window_identity,
                8,
            )
            .expect("initialize epoch");
        let handle = database
            .validate_epoch(
                DeviceId::new(7),
                KeyEpoch::try_new(3).expect("epoch"),
                replay_window_identity,
                8,
            )
            .expect("validate epoch");
        let packet = packet(&manifest.session_id, 0, 10);
        let controls = [
            ControlRecordInput::baseline_command(
                1,
                SessionTime::from_nanos(11),
                TargetedBaselineCommand::new(
                    LinkProfileKey::new(
                        RadioLinkId::new("link-a").expect("link"),
                        CaptureProfileId::from_bytes([0x55; 32]),
                    ),
                    BaselineCommand::Freeze,
                ),
            ),
            ControlRecordInput::timeline_advance(2, SessionTime::from_nanos(12)),
            ControlRecordInput::closed(3, SessionTime::from_nanos(13)),
        ];
        let expected_records = vec![
            SessionRecord {
                record_seq: 0,
                at: SessionTime::from_nanos(10),
                kind: SessionRecordKind::Packet {
                    receive_utc_ns: -5,
                    peer: "192.0.2.1:9000".parse().expect("peer"),
                    wire_format: WireFormat::NativeFrameUdp,
                    bytes: vec![1, 2, 3].into_boxed_slice(),
                },
            },
            controls[0].record().clone(),
            controls[1].record().clone(),
            controls[2].record().clone(),
        ];
        database
            .admit_and_append(Admission::new(&handle, 1, 1), &packet, 64 * 1024)
            .expect("append packet");
        for record in &controls {
            database
                .append_control(&manifest.session_id, record, 64 * 1024)
                .expect("append control");
        }

        assert_eq!(
            database.records(&manifest.session_id, 64 * 1024, false).expect("records"),
            expected_records
        );
        let stored: Vec<(String, Vec<u8>)> = {
            let mut statement = database
                .connection()
                .prepare(
                    "SELECT kind, body_cbor FROM session_records
                     WHERE session_id = ?1 ORDER BY record_seq",
                )
                .expect("prepare rows");
            statement
                .query_map([manifest.session_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))
                .expect("query rows")
                .collect::<Result<_, _>>()
                .expect("stored rows")
        };
        let mut packet_body = vec![
            0xa4, 0x6e, b'r', b'e', b'c', b'e', b'i', b'v', b'e', b'_', b'u', b't', b'c', b'_',
            b'n', b's', 0x24, 0x64, b'p', b'e', b'e', b'r', 0x6e, b'1', b'9', b'2', b'.', b'0',
            b'.', b'2', b'.', b'1', b':', b'9', b'0', b'0', b'0', 0x6b, b'w', b'i', b'r', b'e',
            b'_', b'f', b'o', b'r', b'm', b'a', b't', 0x70, b'n', b'a', b't', b'i', b'v', b'e',
            b'_', b'f', b'r', b'a', b'm', b'e', b'_', b'u', b'd', b'p', 0x65, b'b', b'y', b't',
            b'e', b's', 0x43, 1, 2, 3,
        ];
        let mut command_body = vec![
            0xa3, 0x64, b'l', b'i', b'n', b'k', 0x66, b'l', b'i', b'n', b'k', b'-', b'a', 0x67,
            b'p', b'r', b'o', b'f', b'i', b'l', b'e', 0x58, 0x20,
        ];
        command_body.extend_from_slice(&[0x55; 32]);
        command_body.extend_from_slice(&[
            0x67, b'c', b'o', b'm', b'm', b'a', b'n', b'd', 0x66, b'f', b'r', b'e', b'e', b'z',
            b'e',
        ]);
        assert_eq!(
            stored,
            vec![
                ("packet".into(), std::mem::take(&mut packet_body)),
                ("baseline_command".into(), command_body),
                ("timeline_advance".into(), vec![0xf6]),
                ("closed".into(), vec![0xf6]),
            ]
        );
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn record_reader_rejects_a_row_after_closed() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("after-closed", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        database
            .append_control(
                &manifest.session_id,
                &ControlRecordInput::closed(0, SessionTime::from_nanos(10)),
                64 * 1024,
            )
            .expect("append closed");
        database
            .connection()
            .execute(
                "INSERT INTO session_records
                 (session_id, record_seq, session_time, kind, body_cbor)
                 VALUES (?1, ?2, ?3, 'timeline_advance', x'f6')",
                params![manifest.session_id.as_str(), u64_bytes(1), u64_bytes(10)],
            )
            .expect("insert corrupt row after closed");

        assert!(matches!(
            database.records(&manifest.session_id, 64 * 1024, false),
            Err(DatabaseError::Session(SessionError::Schema(_)))
        ));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn append_control_rejects_a_duplicate_sequence_and_preserves_the_first_record() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("duplicate-control-sequence", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        database
            .append_control(
                &manifest.session_id,
                &ControlRecordInput::timeline_advance(0, SessionTime::from_nanos(10)),
                64 * 1024,
            )
            .expect("append first record");

        assert!(matches!(
            database.append_control(
                &manifest.session_id,
                &ControlRecordInput::timeline_advance(0, SessionTime::from_nanos(11)),
                64 * 1024,
            ),
            Err(DatabaseError::Sequence { expected: 1, actual: 0 })
        ));
        let records = database.records(&manifest.session_id, 64 * 1024, false).expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_seq, 0);
        assert_eq!(records[0].at, SessionTime::from_nanos(10));

        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn record_reader_rejects_duplicate_sequences_from_a_corrupt_row_source() {
        let connection = Connection::open_in_memory().expect("open corrupt row source");
        connection
            .execute_batch(
                "CREATE TABLE session_records (
                    session_id TEXT NOT NULL,
                    record_seq BLOB NOT NULL,
                    session_time BLOB NOT NULL,
                    kind TEXT NOT NULL,
                    body_cbor BLOB NOT NULL
                );",
            )
            .expect("create corrupt row source");
        let session = SessionId::new("duplicate-stored-sequence").expect("session");
        for time in [10, 11] {
            connection
                .execute(
                    "INSERT INTO session_records
                     (session_id, record_seq, session_time, kind, body_cbor)
                     VALUES (?1, ?2, ?3, 'timeline_advance', x'f6')",
                    params![session.as_str(), u64_bytes(0), u64_bytes(time)],
                )
                .expect("insert duplicate stored sequence");
        }
        let database = Database { connection };

        assert!(matches!(
            database.records(&session, 64 * 1024, false),
            Err(DatabaseError::Sequence { expected: 1, actual: 0 })
        ));
    }

    #[test]
    fn record_reader_rejects_unknown_kinds_and_bounds_bodies_before_decode() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("corrupt-record", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        database
            .append_control(
                &manifest.session_id,
                &ControlRecordInput::timeline_advance(0, SessionTime::from_nanos(10)),
                64 * 1024,
            )
            .expect("append timeline advance");
        database
            .connection()
            .pragma_update(None, "ignore_check_constraints", true)
            .expect("allow corruption setup");
        database
            .connection()
            .execute(
                "UPDATE session_records SET kind = 'unknown' WHERE session_id = ?1",
                [manifest.session_id.as_str()],
            )
            .expect("set unknown kind");
        database
            .connection()
            .pragma_update(None, "ignore_check_constraints", false)
            .expect("restore constraints");
        assert!(matches!(
            database.records(&manifest.session_id, 64 * 1024, false),
            Err(DatabaseError::Session(SessionError::Schema(_)))
        ));

        database
            .connection()
            .execute(
                "UPDATE session_records SET kind = 'timeline_advance', body_cbor = zeroblob(1024)
                 WHERE session_id = ?1",
                [manifest.session_id.as_str()],
            )
            .expect("set oversized invalid body");
        assert!(matches!(
            database.records(&manifest.session_id, 1, false),
            Err(DatabaseError::TooLarge)
        ));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn record_reader_rejects_the_legacy_full_session_record_envelope() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("legacy-record-envelope", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        let legacy_envelope = vec![
            0xa5, 0x66, b's', b'c', b'h', b'e', b'm', b'a', 0x01, 0x6a, b'r', b'e', b'c', b'o',
            b'r', b'd', b'_', b's', b'e', b'q', 0x00, 0x62, b'a', b't', 0x0a, 0x64, b'k', b'i',
            b'n', b'd', 0x66, b'c', b'l', b'o', b's', b'e', b'd', 0x64, b'b', b'o', b'd', b'y',
            0xf6,
        ];
        database
            .connection()
            .execute(
                "INSERT INTO session_records
                 (session_id, record_seq, session_time, kind, body_cbor)
                 VALUES (?1, ?2, ?3, 'closed', ?4)",
                params![manifest.session_id.as_str(), u64_bytes(0), u64_bytes(10), legacy_envelope],
            )
            .expect("insert legacy envelope");

        assert!(matches!(
            database.records(&manifest.session_id, 64 * 1024, false),
            Err(DatabaseError::Session(SessionError::Schema(_)))
        ));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn schema_v1_enforces_writer_pragmas_foreign_keys_and_indexes() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        assert_eq!(
            database
                .connection()
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("version"),
            SCHEMA_VERSION
        );
        assert_eq!(
            database
                .connection()
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .expect("journal"),
            "wal"
        );
        assert_eq!(
            database
                .connection()
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .expect("foreign keys"),
            1
        );
        assert_eq!(
            database
                .connection()
                .pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))
                .expect("sync"),
            2
        );
        let tables: i64 = database
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name IN
             ('admission_epochs','sessions','session_records','session_processing_state',
              'csi_observations','world_snapshots','snapshot_link_evidence','baseline_states')",
                [],
                |row| row.get(0),
            )
            .expect("tables");
        assert_eq!(tables, 8);
        let indexes: i64 = database
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name IN
             ('session_records_time','csi_by_link_time','csi_by_sensor_time',
              'snapshots_by_interval','evidence_by_link','baseline_by_source',
              'processing_by_cursor')",
                [],
                |row| row.get(0),
            )
            .expect("indexes");
        assert_eq!(indexes, 7);
        assert!(database.connection().execute(
            "INSERT INTO session_records (session_id, record_seq, session_time, kind, body_cbor)
             VALUES ('missing', zeroblob(8), zeroblob(8), 'closed', x'00')",
            [],
        ).is_err());
        let session = manifest("cursor-fk", 0);
        database.create_session(&session, 64 * 1024, u64::MAX).expect("create session");
        let stored_fact_bytes: (String, u64, Vec<u8>) = database
            .connection()
            .query_row(
                "SELECT typeof(fact_bytes), length(fact_bytes), fact_bytes
                 FROM sessions WHERE session_id = ?1",
                [session.session_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("stored session fact bytes");
        let expected_manifest_bytes =
            u64::try_from(encode_manifest(&session).expect("encode stored session manifest").len())
                .expect("manifest length fits u64");
        assert_eq!(
            stored_fact_bytes,
            ("blob".into(), 8, u64_bytes(expected_manifest_bytes).to_vec())
        );
        assert!(
            database
                .connection()
                .execute(
                    "UPDATE sessions SET fact_bytes = x'00' WHERE session_id = ?1",
                    [session.session_id.as_str()],
                )
                .is_err()
        );
        assert!(
            database
                .connection()
                .execute(
                    "UPDATE session_processing_state
                     SET processed_through_record_seq = zeroblob(8)
                     WHERE session_id = ?1",
                    [session.session_id.as_str()],
                )
                .is_err()
        );
        drop(database);
        let database = Database::open_writer_existing(&path).expect("open existing writer");
        assert!(!database.connection().is_readonly("main").expect("writer flags"));
        let reader = DatabaseReader::open_existing(&path).expect("open existing reader");
        assert!(reader.connection().is_readonly("main").expect("reader flags"));
        drop(reader);
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn v1_record_sequence_blob_ordering_covers_the_full_u64_adapter_range() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let manifest = manifest("full-u64-blob-order", 0);
        database.create_session(&manifest, 64 * 1024, u64::MAX).expect("create session");
        let values = [0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff];

        // Sparse sequences probe the storage adapter only; they are not a replayable session.
        for (time, value) in values.into_iter().rev().enumerate() {
            database
                .connection()
                .execute(
                    "INSERT INTO session_records
                     (session_id, record_seq, session_time, kind, body_cbor)
                     VALUES (?1, ?2, ?3, 'timeline_advance', x'f6')",
                    params![
                        manifest.session_id.as_str(),
                        u64_bytes(value),
                        u64_bytes(time as u64),
                    ],
                )
                .expect("insert full-width sequence");
        }
        let mut statement = database
            .connection()
            .prepare(
                "SELECT record_seq FROM session_records
                 WHERE session_id = ?1 ORDER BY record_seq",
            )
            .expect("prepare ordered adapter read");
        let stored = statement
            .query_map([manifest.session_id.as_str()], |row| row.get::<_, Vec<u8>>(0))
            .expect("query ordered adapter rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect ordered adapter rows");
        let ordered = stored
            .iter()
            .map(|bytes| decode_u64(bytes))
            .collect::<Result<Vec<_>, _>>()
            .expect("decode ordered adapter rows");

        assert_eq!(ordered, values);
        drop(statement);
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn writer_open_rejects_delete_journal_without_repair() {
        let path = database_path();
        drop(Database::create_new(&path).expect("create WAL database"));
        set_journal_mode(&path, "DELETE");
        assert_eq!(journal_mode(&path), "delete");

        assert!(matches!(
            Database::open_writer_existing(&path),
            Err(DatabaseError::Pragma {
                name: "journal_mode",
                actual,
                expected: "wal",
            }) if actual.eq_ignore_ascii_case("delete")
        ));
        assert_eq!(journal_mode(&path), "delete");
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn reader_open_rejects_delete_journal_without_repair() {
        let path = database_path();
        drop(Database::create_new(&path).expect("create WAL database"));
        set_journal_mode(&path, "DELETE");
        assert_eq!(journal_mode(&path), "delete");

        assert!(matches!(
            DatabaseReader::open_existing(&path),
            Err(DatabaseError::Pragma {
                name: "journal_mode",
                actual,
                expected: "wal",
            }) if actual.eq_ignore_ascii_case("delete")
        ));
        assert_eq!(journal_mode(&path), "delete");
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn writer_and_reader_check_version_before_journal_without_repair() {
        let path = database_path();
        drop(Database::create_new(&path).expect("create WAL database"));
        set_journal_mode(&path, "DELETE");
        set_user_version(&path, 2);

        assert!(matches!(
            Database::open_writer_existing(&path),
            Err(DatabaseError::SchemaVersion { actual: 2, expected: 1 })
        ));
        assert_eq!(user_version(&path), 2);
        assert_eq!(journal_mode(&path), "delete");

        assert!(matches!(
            DatabaseReader::open_existing(&path),
            Err(DatabaseError::SchemaVersion { actual: 2, expected: 1 })
        ));
        assert_eq!(user_version(&path), 2);
        assert_eq!(journal_mode(&path), "delete");
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn valid_wal_writer_and_reader_apply_connection_local_settings() {
        let path = database_path();
        drop(Database::create_new(&path).expect("create WAL database"));

        let writer = Database::open_writer_existing(&path).expect("open writer");
        assert_eq!(
            writer
                .connection()
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .expect("writer foreign keys"),
            1
        );
        assert_eq!(
            writer
                .connection()
                .pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))
                .expect("writer synchronous"),
            2
        );

        let reader = DatabaseReader::open_existing(&path).expect("open reader");
        assert_eq!(
            reader
                .connection()
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .expect("reader foreign keys"),
            1
        );
        drop(reader);
        drop(writer);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn transaction_a_rolls_back_admission_and_enforces_raw_order() {
        let path = database_path();
        let mut database = Database::create_new(&path).expect("create database");
        let session =
            manifest_with_states("session-a", -1, vec![learning_seed_state(), active_seed_state()]);
        database.create_session(&session, 64 * 1024, u64::MAX).expect("create session");
        let fresh: (bool, bool) = database
            .connection()
            .query_row(
                "SELECT processed_through_record_seq IS NULL, timeline_state_cbor IS NULL
                 FROM session_processing_state WHERE session_id = ?1",
                [session.session_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("fresh processing state");
        assert_eq!(fresh, (true, true));
        let stored_states = database
            .baseline_states(&session.session_id, 64 * 1024, 64 * 1024)
            .expect("baseline states");
        assert_eq!(stored_states, session.initial_baseline_states);
        assert_eq!(stored_states[0].learning()[&coordinate()].m2(), 2.75);
        assert_eq!(stored_states[1].active()[&coordinate()].variance(), 0.75);
        assert_eq!(
            database
                .connection()
                .query_row(
                    "SELECT count(*) FROM baseline_states WHERE source_record_seq IS NULL",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .expect("manifest-seeded sources"),
            2
        );
        database
            .connection()
            .execute_batch(
                "UPDATE session_processing_state SET config_digest = zeroblob(32);
                 UPDATE baseline_states SET config_digest = zeroblob(32);",
            )
            .expect("paired receipt corruption");
        assert!(matches!(
            database.baseline_states(&session.session_id, 64 * 1024, 64 * 1024),
            Err(DatabaseError::Session(SessionError::Schema(_)))
        ));
        database
            .connection()
            .execute(
                "UPDATE session_processing_state SET config_digest = ?1",
                [session.config_digest],
            )
            .expect("restore processing receipt");
        database
            .connection()
            .execute("UPDATE baseline_states SET config_digest = ?1", [session.config_digest])
            .expect("restore baseline receipt");
        let identity = ReplayWindowIdentity::new([0x11; 32]);
        assert!(matches!(
            database.validate_epoch(
                DeviceId::new(7),
                KeyEpoch::try_new(3).expect("epoch"),
                identity,
                9
            ),
            Err(DatabaseError::MissingEpoch)
        ));
        database
            .provision_epoch(DeviceId::new(7), KeyEpoch::try_new(3).expect("epoch"), &identity, 9)
            .expect("initialize epoch");
        let handle = database
            .validate_epoch(DeviceId::new(7), KeyEpoch::try_new(3).expect("epoch"), identity, 9)
            .expect("validate epoch");
        let admission = Admission::new(&handle, 1, 1);
        assert!(matches!(
            database.admit_and_append(admission, &packet(&session.session_id, 1, 10), 64 * 1024),
            Err(DatabaseError::Sequence { expected: 0, actual: 1 })
        ));
        database
            .admit_and_append(admission, &packet(&session.session_id, 0, 10), 64 * 1024)
            .expect("rollback preserved admission and raw");
        assert!(matches!(
            database.admit_and_append(
                Admission::new(&handle, 1, 1),
                &packet(&session.session_id, 1, 11),
                64 * 1024
            ),
            Err(DatabaseError::Replay)
        ));
        assert!(matches!(
            database.admit_and_append(
                Admission::new(&handle, 1, 2),
                &packet(&session.session_id, 1, 9),
                64 * 1024
            ),
            Err(DatabaseError::TimeReversed { .. })
        ));
        database
            .admit_and_append(
                Admission::new(&handle, 1, u64::MAX),
                &packet(&session.session_id, 1, 11),
                64 * 1024,
            )
            .expect("full unsigned sequence");
        let maximum: Vec<u8> = database
            .connection()
            .query_row("SELECT maximum_message_sequence FROM admission_epochs", [], |row| {
                row.get(0)
            })
            .expect("maximum sequence");
        assert_eq!(decode_u64(&maximum).expect("u64"), u64::MAX);

        let closed = ControlRecordInput::closed(2, SessionTime::from_nanos(u64::MAX));
        database.append_control(&session.session_id, &closed, 64 * 1024).expect("close");
        assert!(matches!(
            database.append_control(
                &session.session_id,
                &ControlRecordInput::timeline_advance(3, SessionTime::from_nanos(u64::MAX),),
                64 * 1024,
            ),
            Err(DatabaseError::NotActive)
        ));
        assert!(matches!(
            database.records(&session.session_id, 64 * 1024, true),
            Err(DatabaseError::NotActive)
        ));
        assert_eq!(
            database.incomplete_sessions().expect("incomplete"),
            vec![session.session_id.clone()]
        );
        database.recovery_seal(&session.session_id, 50).expect("recovery seal");
        assert_eq!(
            database.records(&session.session_id, 64 * 1024, true).expect("records").len(),
            3
        );
        let decoded = database.manifest(&session.session_id, 64 * 1024).expect("manifest");
        assert_eq!(decoded.config_digest, session.config_digest);
        assert_eq!(decoded.replay_config.digest(), session.replay_config.digest());
        assert_eq!(decoded.initial_baseline_states, session.initial_baseline_states);
        database
            .connection()
            .execute_batch(
                "CREATE TRIGGER fail_processing_insert
                 BEFORE INSERT ON session_processing_state
                 BEGIN SELECT RAISE(ABORT, 'forced processing failure'); END;",
            )
            .expect("failure trigger");
        let rollback = manifest("rollback", 0);
        assert!(database.create_session(&rollback, 64 * 1024, u64::MAX).is_err());
        assert_eq!(
            database
                .connection()
                .query_row(
                    "SELECT count(*) FROM sessions WHERE session_id = 'rollback'",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .expect("rolled back session"),
            0
        );
        database
            .connection()
            .execute_batch("DROP TRIGGER fail_processing_insert")
            .expect("drop trigger");
        database
            .connection()
            .execute(
                "UPDATE session_records SET kind = 'closed'
                 WHERE session_id = ?1 AND record_seq = ?2",
                params![session.session_id.as_str(), u64_bytes(0)],
            )
            .expect("corrupt stored kind");
        assert!(matches!(
            database.records(&session.session_id, 64 * 1024, true),
            Err(DatabaseError::Session(SessionError::Schema(_)))
        ));
        database
            .connection()
            .execute(
                "UPDATE sessions SET manifest_cbor = zeroblob(1048576) WHERE session_id = ?1",
                [session.session_id.as_str()],
            )
            .expect("oversized corrupt manifest");
        assert!(matches!(
            database.manifest(&session.session_id, 64 * 1024),
            Err(DatabaseError::TooLarge)
        ));
        drop(database);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn open_fails_closed_and_retention_keeps_active_epoch_and_newest_sealed() {
        let missing = database_path();
        assert!(matches!(Database::open_writer_existing(&missing), Err(DatabaseError::Missing)));

        let path = database_path();
        let mut database = Database::create_new(&path).expect("create");
        let identity = ReplayWindowIdentity::new([0x55; 32]);
        database
            .provision_epoch(DeviceId::new(7), KeyEpoch::try_new(3).expect("epoch"), &identity, 8)
            .expect("epoch");
        assert!(matches!(
            database.provision_epoch(
                DeviceId::new(7),
                KeyEpoch::try_new(3).expect("epoch"),
                &ReplayWindowIdentity::new([0x56; 32]),
                8
            ),
            Err(DatabaseError::EpochConflict)
        ));

        for (id, started) in [("old", 1), ("new", 2)] {
            let session = if id == "new" {
                manifest_with_states(id, started, vec![learning_seed_state(), active_seed_state()])
            } else {
                manifest(id, started)
            };
            database.create_session(&session, 64 * 1024, u64::MAX).expect("session");
            database
                .append_control(
                    &session.session_id,
                    &ControlRecordInput::closed(0, SessionTime::from_nanos(0)),
                    64 * 1024,
                )
                .expect("closed");
            database.seal(&session.session_id, started + 10).expect("seal");
        }
        let active = manifest("active", 3);
        database.create_session(&active, 64 * 1024, u64::MAX).expect("active");
        assert_eq!(database.retain_sealed(0).expect("retention"), 1);
        let sessions: Vec<String> = {
            let mut statement = database
                .connection()
                .prepare("SELECT session_id FROM sessions ORDER BY session_id")
                .expect("statement");
            statement
                .query_map([], |row| row.get(0))
                .expect("rows")
                .collect::<Result<_, _>>()
                .expect("sessions")
        };
        assert_eq!(sessions, vec!["active", "new"]);
        assert_eq!(
            database
                .connection()
                .query_row("SELECT count(*) FROM baseline_states", [], |row| {
                    row.get::<_, u64>(0)
                })
                .expect("baseline states"),
            2
        );
        assert_eq!(
            database
                .connection()
                .query_row("SELECT count(*) FROM admission_epochs", [], |row| row.get::<_, u64>(0))
                .expect("epochs"),
            1
        );

        drop(database);
        std::fs::remove_file(path).expect("cleanup database");

        let wrong = database_path();
        let connection = Connection::open(&wrong).expect("wrong database");
        connection.pragma_update(None, "user_version", 2).expect("version");
        drop(connection);
        assert!(matches!(
            Database::open_writer_existing(&wrong),
            Err(DatabaseError::SchemaVersion { actual: 2, expected: 1 })
        ));
        std::fs::remove_file(wrong).expect("cleanup wrong schema");
    }
}
