//! Sanitized logical Store snapshots for bounded RF relationship evidence.

use std::collections::BTreeMap;

use ciborium::ser::into_writer;
use rusqlite::{Connection, OptionalExtension, Params, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::session::{RecordKind, SessionRecordKind, decode_record_body};

/// Domain separator for the privacy-safe body/ciphertext binding in evidence schema version 1.
// Producer hashing remains separate from the independent verifier implementation. Sharing this
// code would make a single drift self-consistent instead of detectable by the #147 evidence gate.
const PACKET_EVIDENCE_BINDING_DOMAIN: &[u8] = b"rf-relationship-packet-binding-v1\0";
/// Domain separator for the peer-free packet body digest retained by evidence schema version 1.
const PACKET_EVIDENCE_BODY_DOMAIN: &[u8] = b"rf-relationship-packet-body-v1\0";
/// Maximum rows selected into one evidence-only logical Store snapshot.
///
/// This evidence-v1 safety budget matches the package's 4096-member ceiling and is not a runtime
/// Store cardinality limit. Raising it increases query allocation and canonical export work;
/// lowering it can reject an otherwise valid bounded formal run.
const MAX_EVIDENCE_STORE_ROWS: u64 = 4096;
/// Maximum raw SQLite bytes selected into one evidence-only logical Store snapshot.
///
/// Eight MiB leaves serialization headroom beneath the evidence-v1 16 MiB artifact ceiling.
/// Raising it increases allocation before package sealing; lowering it reduces the retained run
/// history that the independent verifier can inspect.
const MAX_EVIDENCE_STORE_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum one SQLite text or BLOB value selected into an evidence snapshot.
///
/// The per-cell ceiling equals the total raw snapshot budget so a single bounded baseline value
/// can consume the allowance but never exceed it. Changing it alters which Store rows can be
/// exported and the maximum allocation performed for one SQLite value.
const MAX_EVIDENCE_STORE_CELL_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum transaction-B entries retained by one evidence-producing Host lifetime.
///
/// This matches the evidence package member/Store-row ceiling. Reaching it invalidates bounded
/// evidence capture without limiting the runtime Session or transaction-B writer. Raising it
/// increases development-fixture memory retained beside the single writer.
const MAX_EVIDENCE_TRANSACTION_B_ENTRIES: usize = 4096;

struct SnapshotBudget {
    bytes: u64,
    max_rows: u64,
    rows: u64,
}

impl SnapshotBudget {
    const fn new(max_rows: u64) -> Self {
        Self { bytes: 0, max_rows, rows: 0 }
    }

    fn include(
        &mut self,
        rows: i64,
        bytes: i64,
        max_cell: i64,
    ) -> Result<(), EvidenceSnapshotError> {
        let rows = u64::try_from(rows).map_err(|_| EvidenceSnapshotError::Bound)?;
        let bytes = u64::try_from(bytes).map_err(|_| EvidenceSnapshotError::Bound)?;
        let max_cell = u64::try_from(max_cell).map_err(|_| EvidenceSnapshotError::Bound)?;
        let total_rows = self.rows.checked_add(rows).ok_or(EvidenceSnapshotError::Bound)?;
        let total_bytes = self.bytes.checked_add(bytes).ok_or(EvidenceSnapshotError::Bound)?;
        if total_rows > self.max_rows
            || total_bytes > MAX_EVIDENCE_STORE_BYTES
            || max_cell > MAX_EVIDENCE_STORE_CELL_BYTES
        {
            return Err(EvidenceSnapshotError::Bound);
        }
        self.rows = total_rows;
        self.bytes = total_bytes;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceStoreSnapshot {
    pub(crate) active_session: EvidenceSession,
    pub(crate) baselines: Vec<EvidenceBaseline>,
    pub(crate) capture_sessions: Vec<EvidenceCaptureSession>,
    pub(crate) commits: Vec<EvidenceCommit>,
    pub(crate) config_digest: String,
    pub(crate) durable_tail: u64,
    pub(crate) facts: Vec<EvidenceFact>,
    pub(crate) observations: Vec<EvidenceObservation>,
    pub(crate) processed_cursor: u64,
    pub(crate) replay_identities: Vec<EvidenceReplayIdentity>,
    pub(crate) relationships: Vec<EvidenceRelationship>,
    pub(crate) schema_version: u8,
    pub(crate) selected_range: EvidenceRecordRange,
    pub(crate) store_id: String,
    pub(crate) timeline_digest: String,
    pub(crate) topology_digest: String,
    pub(crate) watermark: u64,
    #[serde(default, skip)]
    pub(crate) datagrams: Vec<EvidenceDatagram>,
}

#[derive(Clone, Debug)]
pub(crate) struct EvidenceRebuildSnapshot {
    pub(crate) audit: EvidenceRebuildAudit,
    pub(crate) store: EvidenceStoreSnapshot,
}

#[derive(Clone, Debug)]
pub(crate) struct EvidenceRebuildAudit {
    pub(crate) authorizer_write_deny: bool,
    pub(crate) no_mutex: bool,
    pub(crate) nofollow: bool,
    pub(crate) query_only: bool,
    pub(crate) read_only: bool,
    pub(crate) total_changes: u64,
    pub(crate) write_attempted: bool,
    pub(crate) writer_opens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceSession {
    pub(crate) manifest_sha256: String,
    pub(crate) session_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceCaptureSession {
    pub(crate) algorithm_version: String,
    pub(crate) capture_session_id: String,
    pub(crate) conditioning_version: String,
    pub(crate) decoder_version: String,
    pub(crate) durable_tail: Option<u64>,
    pub(crate) last_session_time: Option<u64>,
    pub(crate) started_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceReplayIdentity {
    pub(crate) device_id: u64,
    pub(crate) key_epoch: u16,
    pub(crate) replay_window_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceRecordRange {
    pub(crate) first_record_seq: u64,
    pub(crate) last_record_seq: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceCaptureMembership {
    pub(crate) capture_record_seq: u64,
    pub(crate) capture_session_id: String,
    pub(crate) capture_session_time: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceFact {
    pub(crate) body_sha256: String,
    pub(crate) capture: Option<EvidenceCaptureMembership>,
    pub(crate) command: Option<EvidenceBaselineCommand>,
    pub(crate) datagram_sha256: Option<String>,
    pub(crate) kind: String,
    pub(crate) record_seq: u64,
    pub(crate) session_time: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceBaselineCommand {
    pub(crate) command: String,
    pub(crate) link: String,
    pub(crate) profile: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceObservation {
    pub(crate) link: String,
    pub(crate) profile: String,
    pub(crate) record_seq: u64,
    pub(crate) session_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceDatagram {
    pub(crate) body_binding_sha256: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) capture_record_seq: u64,
    pub(crate) capture_session_id: String,
    pub(crate) capture_session_time: u64,
    pub(crate) device_id: u64,
    pub(crate) key_epoch: u16,
    pub(crate) receive_monotonic_ns: u64,
    pub(crate) receive_utc_ns: u64,
    pub(crate) record_seq: u64,
    pub(crate) session_time: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceCommit {
    pub(crate) commit_seq: u64,
    pub(crate) kind: String,
    pub(crate) record_seq: u64,
    pub(crate) timeline_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceTransactionBEffect {
    pub(crate) baseline_sha256: Option<String>,
    pub(crate) commit_seq: u64,
    pub(crate) creator_commit_seq: Option<u64>,
    pub(crate) record_seq: u64,
    pub(crate) relationship_sha256: Option<String>,
    pub(crate) timeline_digest: String,
}

pub(crate) struct EvidenceTransactionBEffectInput<'a> {
    baseline_changed: bool,
    commit_seq: u64,
    record_seq: u64,
    relationship_changed: bool,
    session_id: &'a str,
    snapshot_row_limit: u64,
    timeline_digest: &'a [u8; 32],
}

impl<'a> EvidenceTransactionBEffectInput<'a> {
    pub(crate) const fn new(
        session_id: &'a str,
        record_seq: u64,
        commit_seq: u64,
        timeline_digest: &'a [u8; 32],
        baseline_changed: bool,
        relationship_changed: bool,
        snapshot_row_limit: u64,
    ) -> Self {
        Self {
            baseline_changed,
            commit_seq,
            record_seq,
            relationship_changed,
            session_id,
            snapshot_row_limit,
            timeline_digest,
        }
    }
}

#[derive(Debug)]
pub(crate) struct EvidenceTransactionBAudit {
    complete: bool,
    entries: Vec<EvidenceTransactionBEffect>,
    snapshot_row_limit: u64,
}

impl EvidenceTransactionBAudit {
    pub(crate) fn new() -> Self {
        Self { complete: true, entries: Vec::new(), snapshot_row_limit: MAX_EVIDENCE_STORE_ROWS }
    }

    pub(crate) fn can_record(&self) -> bool {
        self.complete && self.entries.len() < MAX_EVIDENCE_TRANSACTION_B_ENTRIES
    }

    pub(crate) const fn snapshot_row_limit(&self) -> u64 {
        self.snapshot_row_limit
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }

    #[cfg(feature = "ingest-test-hooks")]
    pub(crate) fn set_snapshot_row_limit_for_test(&mut self, limit: u64) {
        assert!(self.entries.is_empty(), "evidence row limit must be set before Host input");
        assert_ne!(limit, 0, "evidence row limit must be positive");
        self.snapshot_row_limit = limit;
    }

    pub(crate) fn record_committed(&mut self, effect: Option<EvidenceTransactionBEffect>) {
        if !self.complete {
            return;
        }
        if let Some(effect) =
            effect.filter(|_| self.entries.len() < MAX_EVIDENCE_TRANSACTION_B_ENTRIES)
        {
            self.entries.push(effect);
        } else {
            self.complete = false;
            self.entries.clear();
        }
    }

    pub(crate) fn snapshot(&self) -> Option<Vec<EvidenceTransactionBEffect>> {
        self.complete.then(|| self.entries.clone())
    }
}

pub(crate) fn transaction_b_effect(
    connection: &Connection,
    input: EvidenceTransactionBEffectInput<'_>,
) -> Result<EvidenceTransactionBEffect, EvidenceSnapshotError> {
    let mut budget = SnapshotBudget::new(input.snapshot_row_limit);
    let baseline_sha256 = if input.baseline_changed {
        Some(canonical_sha256(&read_baselines(connection, input.session_id, &mut budget)?)?)
    } else {
        None
    };
    let relationship_sha256 = if input.relationship_changed {
        Some(canonical_sha256(&read_relationships(connection, input.session_id, &mut budget)?)?)
    } else {
        None
    };
    Ok(EvidenceTransactionBEffect {
        baseline_sha256,
        commit_seq: input.commit_seq,
        creator_commit_seq: input.relationship_changed.then_some(input.commit_seq),
        record_seq: input.record_seq,
        relationship_sha256,
        timeline_digest: hex(input.timeline_digest, 32)?,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceBaseline {
    pub(crate) deployment: String,
    pub(crate) link: String,
    pub(crate) profile: String,
    pub(crate) source_record_seq: u64,
    pub(crate) state_cbor: String,
    pub(crate) state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceRelationship {
    pub(crate) changed_at: Option<u64>,
    pub(crate) change_current: Option<EvidenceKnowledge>,
    pub(crate) change_previous: Option<EvidenceKnowledge>,
    pub(crate) creator_commit_seq: u64,
    pub(crate) knowledge: EvidenceKnowledge,
    pub(crate) link: String,
    pub(crate) profile: String,
    pub(crate) result_time: u64,
    pub(crate) source_record_seq: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EvidenceKnowledge {
    Known { value: String },
    Unknown { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub(super) enum EvidenceSnapshotError {
    #[error("Store evidence SQL failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("Store evidence session body failed: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("Store evidence values are incompatible")]
    Incompatible,
    #[error("Store evidence snapshot exceeds bounded allocation limits")]
    Bound,
}

fn reserve_rows<P: Params>(
    connection: &Connection,
    sql: &str,
    params: P,
    budget: &mut SnapshotBudget,
) -> Result<usize, EvidenceSnapshotError> {
    let (rows, bytes, max_cell): (i64, i64, i64) =
        connection.query_row(sql, params, |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    budget.include(rows, bytes, max_cell)?;
    usize::try_from(rows).map_err(|_| EvidenceSnapshotError::Bound)
}

pub(super) fn snapshot(
    connection: &Connection,
    expected_store_id: [u8; 32],
) -> Result<EvidenceStoreSnapshot, EvidenceSnapshotError> {
    let mut budget = SnapshotBudget::new(MAX_EVIDENCE_STORE_ROWS);
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(store_id) + length(topology_manifest_digest)
                             + length(projection_commit_seq)), 0),
                coalesce(max(max(length(store_id), length(topology_manifest_digest),
                                 length(projection_commit_seq))), 0)
         FROM store_state WHERE singleton=1",
        [],
        &mut budget,
    )?;
    let (store_id, topology_digest, watermark): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT store_id, topology_manifest_digest, projection_commit_seq
             FROM store_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(EvidenceSnapshotError::Incompatible)?;
    if store_id.as_slice() != expected_store_id {
        return Err(EvidenceSnapshotError::Incompatible);
    }
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(cast(session_id AS blob)) + length(manifest_cbor)), 0),
                coalesce(max(max(length(cast(session_id AS blob)), length(manifest_cbor))), 0)
         FROM sessions WHERE lifecycle='active'",
        [],
        &mut budget,
    )?;
    let (session_id, manifest): (String, Vec<u8>) = connection
        .query_row(
            "SELECT session_id, manifest_cbor FROM sessions WHERE lifecycle='active'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(EvidenceSnapshotError::Incompatible)?;
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(processed_through_record_seq) + length(timeline_state_digest)
                             + length(config_digest)), 0),
                coalesce(max(max(length(processed_through_record_seq),
                                 length(timeline_state_digest), length(config_digest))), 0)
         FROM session_processing_state WHERE session_id=?1",
        [&session_id],
        &mut budget,
    )?;
    let (processed, timeline_digest, config_digest): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT processed_through_record_seq, timeline_state_digest, config_digest
             FROM session_processing_state WHERE session_id=?1",
            [&session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(EvidenceSnapshotError::Incompatible)?;

    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(record_seq) + length(session_time)
                             + length(cast(kind AS blob)) + length(body_cbor)), 0),
                coalesce(max(max(length(record_seq), length(session_time),
                                 length(cast(kind AS blob)), length(body_cbor))), 0)
         FROM session_records WHERE session_id=?1",
        [&session_id],
        &mut budget,
    )?;
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(cast(capture_session_id AS blob))
                             + length(capture_record_seq) + length(capture_session_time)), 0),
                coalesce(max(max(length(cast(capture_session_id AS blob)),
                                 length(capture_record_seq), length(capture_session_time))), 0)
         FROM packet_capture_membership WHERE session_id=?1",
        [&session_id],
        &mut budget,
    )?;
    let rows = connection
        .prepare(
            "SELECT record_seq, session_time, kind, body_cbor
             FROM session_records WHERE session_id=?1 ORDER BY record_seq",
        )?
        .query_map([&session_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Err(EvidenceSnapshotError::Incompatible);
    }
    let mut facts = Vec::with_capacity(rows.len());
    let mut datagrams = Vec::new();
    for (record, session_time, kind, body) in rows {
        let record_seq = decode_u64(&record)?;
        let session_time = decode_u64(&session_time)?;
        let record_kind = match kind.as_str() {
            "packet" => RecordKind::Packet,
            "baseline_command" => RecordKind::BaselineCommand,
            "timeline_advance" => RecordKind::TimelineAdvance,
            _ => return Err(EvidenceSnapshotError::Incompatible),
        };
        let decoded = decode_record_body(record_kind, &body)?;
        let membership = read_membership(connection, &session_id, record_seq)?;
        let (body_sha256, datagram_sha256, command) = match decoded {
            SessionRecordKind::Packet { receive_utc_ns, bytes, .. } => {
                let membership = membership.as_ref().ok_or(EvidenceSnapshotError::Incompatible)?;
                let header = crate::wire::parse_header(&bytes)
                    .map_err(|_| EvidenceSnapshotError::Incompatible)?;
                let digest = sha256(&bytes);
                let body_sha256_bytes = packet_evidence_body_sha256(receive_utc_ns, &bytes);
                let body_sha256 = hex(&body_sha256_bytes, 32)?;
                datagrams.push(EvidenceDatagram {
                    body_binding_sha256: packet_evidence_binding_sha256(
                        receive_utc_ns,
                        &bytes,
                        &body_sha256_bytes,
                    ),
                    bytes: bytes.into_vec(),
                    capture_record_seq: membership.capture_record_seq,
                    capture_session_id: membership.capture_session_id.clone(),
                    capture_session_time: membership.capture_session_time,
                    device_id: header.device_id(),
                    key_epoch: header.key_epoch(),
                    receive_monotonic_ns: membership.capture_session_time,
                    receive_utc_ns: u64::try_from(receive_utc_ns)
                        .map_err(|_| EvidenceSnapshotError::Incompatible)?,
                    record_seq,
                    session_time,
                    sha256: digest.clone(),
                });
                (body_sha256, Some(digest), None)
            }
            SessionRecordKind::BaselineCommand(command) => {
                if membership.is_some() {
                    return Err(EvidenceSnapshotError::Incompatible);
                }
                let command_name = match command.command() {
                    crate::domain::world::BaselineCommand::BeginLearning => "begin_learning",
                    crate::domain::world::BaselineCommand::Commit => "commit",
                    _ => return Err(EvidenceSnapshotError::Incompatible),
                };
                (
                    sha256(&body),
                    None,
                    Some(EvidenceBaselineCommand {
                        command: command_name.to_owned(),
                        link: command.target().link().as_str().to_owned(),
                        profile: hex(&command.target().profile().as_bytes(), 32)?,
                    }),
                )
            }
            SessionRecordKind::TimelineAdvance => {
                if membership.is_some() {
                    return Err(EvidenceSnapshotError::Incompatible);
                }
                (sha256(&body), None, None)
            }
            _ => return Err(EvidenceSnapshotError::Incompatible),
        };
        facts.push(EvidenceFact {
            body_sha256,
            capture: membership,
            command,
            datagram_sha256,
            kind,
            record_seq,
            session_time,
        });
    }
    let durable_tail = facts.last().ok_or(EvidenceSnapshotError::Incompatible)?.record_seq;
    let first_record_seq = facts[0].record_seq;
    let processed_cursor = decode_u64(&processed)?;
    if durable_tail != processed_cursor {
        return Err(EvidenceSnapshotError::Incompatible);
    }

    Ok(EvidenceStoreSnapshot {
        active_session: EvidenceSession {
            manifest_sha256: sha256(&manifest),
            session_id: session_id.clone(),
        },
        baselines: read_baselines(connection, &session_id, &mut budget)?,
        capture_sessions: read_capture_sessions(connection, &mut budget)?,
        commits: read_commits(connection, &session_id, &mut budget)?,
        config_digest: hex(&config_digest, 32)?,
        durable_tail,
        facts,
        observations: read_observations(connection, &session_id, &mut budget)?,
        processed_cursor,
        replay_identities: read_replay_identities(connection, &mut budget)?,
        relationships: read_relationships(connection, &session_id, &mut budget)?,
        schema_version: 1,
        selected_range: EvidenceRecordRange { first_record_seq, last_record_seq: durable_tail },
        store_id: hex(&store_id, 32)?,
        timeline_digest: hex(&timeline_digest, 32)?,
        topology_digest: hex(&topology_digest, 32)?,
        watermark: decode_u64(&watermark)?,
        datagrams,
    })
}

fn read_observations(
    connection: &Connection,
    session_id: &str,
    budget: &mut SnapshotBudget,
) -> Result<Vec<EvidenceObservation>, EvidenceSnapshotError> {
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(record_seq) + length(session_time)
                             + length(cast(link_id AS blob)) + length(profile_id)), 0),
                coalesce(max(max(length(record_seq), length(session_time),
                                 length(cast(link_id AS blob)), length(profile_id))), 0)
         FROM csi_observations WHERE session_id=?1",
        [session_id],
        budget,
    )?;
    let rows = connection
        .prepare(
            "SELECT record_seq, session_time, link_id, profile_id
             FROM csi_observations WHERE session_id=?1 ORDER BY record_seq",
        )?
        .query_map([session_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(record, time, link, profile)| {
            Ok(EvidenceObservation {
                link,
                profile: hex(&profile, 32)?,
                record_seq: decode_u64(&record)?,
                session_time: decode_u64(&time)?,
            })
        })
        .collect()
}

fn read_membership(
    connection: &Connection,
    session_id: &str,
    record_seq: u64,
) -> Result<Option<EvidenceCaptureMembership>, EvidenceSnapshotError> {
    connection
        .query_row(
            "SELECT capture_session_id, capture_record_seq, capture_session_time
             FROM packet_capture_membership WHERE session_id=?1 AND record_seq=?2",
            params![session_id, record_seq.to_be_bytes()],
            |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
            },
        )
        .optional()?
        .map(|(capture_session_id, capture_record, capture_time)| {
            Ok(EvidenceCaptureMembership {
                capture_record_seq: decode_u64(&capture_record)?,
                capture_session_id,
                capture_session_time: decode_u64(&capture_time)?,
            })
        })
        .transpose()
}

fn read_capture_sessions(
    connection: &Connection,
    budget: &mut SnapshotBudget,
) -> Result<Vec<EvidenceCaptureSession>, EvidenceSnapshotError> {
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(cast(capture_session_id AS blob))
                             + coalesce(length(durable_tail_record_seq), 0)
                             + coalesce(length(last_session_time), 0)
                             + length(cast(decoder_version AS blob))
                             + length(cast(conditioning_version AS blob))
                             + length(cast(algorithm_version AS blob))), 0),
                coalesce(max(max(length(cast(capture_session_id AS blob)),
                                 coalesce(length(durable_tail_record_seq), 0),
                                 coalesce(length(last_session_time), 0),
                                 length(cast(decoder_version AS blob)),
                                 length(cast(conditioning_version AS blob)),
                                 length(cast(algorithm_version AS blob)))), 0)
         FROM capture_sessions",
        [],
        budget,
    )?;
    let rows = connection
        .prepare(
            "SELECT capture_session_id, started_utc_ns, durable_tail_record_seq, last_session_time,
                    decoder_version, conditioning_version, algorithm_version
             FROM capture_sessions ORDER BY started_utc_ns, capture_session_id",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(capture_session_id, started_utc_ns, tail, time, decoder, conditioning, algorithm)| {
                Ok(EvidenceCaptureSession {
                    algorithm_version: algorithm,
                    capture_session_id,
                    conditioning_version: conditioning,
                    decoder_version: decoder,
                    durable_tail: tail.as_deref().map(decode_u64).transpose()?,
                    last_session_time: time.as_deref().map(decode_u64).transpose()?,
                    started_utc_ns,
                })
            },
        )
        .collect()
}

fn read_replay_identities(
    connection: &Connection,
    budget: &mut SnapshotBudget,
) -> Result<Vec<EvidenceReplayIdentity>, EvidenceSnapshotError> {
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(device_id) + length(key_epoch)
                             + length(replay_window_identity)), 0),
                coalesce(max(max(length(device_id), length(key_epoch),
                                 length(replay_window_identity))), 0)
         FROM admission_epochs",
        [],
        budget,
    )?;
    let rows = connection
        .prepare(
            "SELECT device_id, key_epoch, replay_window_identity
             FROM admission_epochs ORDER BY device_id, key_epoch",
        )?
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(device, epoch, identity)| {
            let device: [u8; 8] =
                device.try_into().map_err(|_| EvidenceSnapshotError::Incompatible)?;
            let epoch: [u8; 2] =
                epoch.try_into().map_err(|_| EvidenceSnapshotError::Incompatible)?;
            Ok(EvidenceReplayIdentity {
                device_id: u64::from_be_bytes(device),
                key_epoch: u16::from_be_bytes(epoch),
                replay_window_sha256: hex(&identity, 32)?,
            })
        })
        .collect()
}

fn read_commits(
    connection: &Connection,
    session_id: &str,
    budget: &mut SnapshotBudget,
) -> Result<Vec<EvidenceCommit>, EvidenceSnapshotError> {
    reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(commit_seq) + length(record_seq)
                             + length(cast(kind AS blob)) + length(timeline_state_digest)), 0),
                coalesce(max(max(length(commit_seq), length(record_seq),
                                 length(cast(kind AS blob)), length(timeline_state_digest))), 0)
         FROM projection_commits WHERE session_id=?1",
        [session_id],
        budget,
    )?;
    let rows = connection
        .prepare(
            "SELECT commit_seq, record_seq, kind, timeline_state_digest
             FROM projection_commits WHERE session_id=?1 ORDER BY record_seq",
        )?
        .query_map([session_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(commit, record, kind, timeline)| {
            Ok(EvidenceCommit {
                commit_seq: decode_u64(&commit)?,
                kind,
                record_seq: decode_u64(&record)?,
                timeline_digest: hex(&timeline, 32)?,
            })
        })
        .collect()
}

fn read_baselines(
    connection: &Connection,
    session_id: &str,
    budget: &mut SnapshotBudget,
) -> Result<Vec<EvidenceBaseline>, EvidenceSnapshotError> {
    let capacity = reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(cast(deployment_id AS blob))
                             + length(cast(link_id AS blob)) + length(profile_id)
                             + length(estimator_state_cbor) + length(source_record_seq)), 0),
                coalesce(max(max(length(cast(deployment_id AS blob)),
                                 length(cast(link_id AS blob)), length(profile_id),
                                 length(estimator_state_cbor), length(source_record_seq))), 0)
         FROM baseline_states WHERE source_session_id=?1",
        [session_id],
        budget,
    )?;
    let mut statement = connection.prepare(
        "SELECT deployment_id, link_id, profile_id, estimator_state_cbor, source_record_seq
         FROM baseline_states WHERE source_session_id=?1
         ORDER BY link_id, profile_id, deployment_id",
    )?;
    let rows = statement.query_map([session_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    let mut baselines = Vec::with_capacity(capacity);
    for row in rows {
        let (deployment, link, profile, state, source) = row?;
        baselines.push(EvidenceBaseline {
            deployment,
            link,
            profile: hex(&profile, 32)?,
            source_record_seq: decode_u64(&source)?,
            state_cbor: hex(&state, state.len())?,
            state_sha256: sha256(&state),
        });
    }
    Ok(baselines)
}

fn read_relationships(
    connection: &Connection,
    session_id: &str,
    budget: &mut SnapshotBudget,
) -> Result<Vec<EvidenceRelationship>, EvidenceSnapshotError> {
    let capacity = reserve_rows(
        connection,
        "SELECT count(*),
                coalesce(sum(length(cast(link_id AS blob)) + length(profile_id)
                             + length(knowledge_cbor) + length(result_time)
                             + coalesce(length(change_previous_cbor), 0)
                             + coalesce(length(change_current_cbor), 0)
                             + coalesce(length(changed_at), 0)
                             + length(source_record_seq) + length(creator_commit_seq)), 0),
                coalesce(max(max(length(cast(link_id AS blob)), length(profile_id),
                                 length(knowledge_cbor), length(result_time),
                                 coalesce(length(change_previous_cbor), 0),
                                 coalesce(length(change_current_cbor), 0),
                                 coalesce(length(changed_at), 0),
                                 length(source_record_seq), length(creator_commit_seq))), 0)
         FROM relationship_latest WHERE session_id=?1",
        [session_id],
        budget,
    )?;
    type Row = (
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
    );
    let mut statement = connection.prepare(
        "SELECT link_id, profile_id, knowledge_cbor, result_time,
                change_previous_cbor, change_current_cbor, changed_at,
                source_record_seq, creator_commit_seq
         FROM relationship_latest WHERE session_id=?1 ORDER BY link_id, profile_id",
    )?;
    let rows = statement.query_map([session_id], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ))
    })?;
    let mut relationships = Vec::with_capacity(capacity);
    for row in rows {
        let (link, profile, knowledge, result, previous, current, changed, source, creator): Row =
            row?;
        let change_previous = previous.as_deref().map(knowledge_text).transpose()?;
        let change_current = current.as_deref().map(knowledge_text).transpose()?;
        let changed_at = changed.as_deref().map(decode_u64).transpose()?;
        if (change_previous.is_some(), change_current.is_some(), changed_at.is_some())
            != (true, true, true)
            && (change_previous.is_some() || change_current.is_some() || changed_at.is_some())
        {
            return Err(EvidenceSnapshotError::Incompatible);
        }
        relationships.push(EvidenceRelationship {
            changed_at,
            change_current,
            change_previous,
            creator_commit_seq: decode_u64(&creator)?,
            knowledge: knowledge_text(&knowledge)?,
            link,
            profile: hex(&profile, 32)?,
            result_time: decode_u64(&result)?,
            source_record_seq: decode_u64(&source)?,
        });
    }
    Ok(relationships)
}

fn knowledge_text(bytes: &[u8]) -> Result<EvidenceKnowledge, EvidenceSnapshotError> {
    let fields: BTreeMap<String, String> =
        ciborium::from_reader(bytes).map_err(|_| EvidenceSnapshotError::Incompatible)?;
    match (fields.get("kind").map(String::as_str), fields.get("value"), fields.get("reason")) {
        (Some("known"), Some(value), None) if matches!(value.as_str(), "stable" | "changing") => {
            Ok(EvidenceKnowledge::Known { value: value.clone() })
        }
        (Some("unknown"), None, Some(reason))
            if matches!(
                reason.as_str(),
                "baseline_missing"
                    | "baseline_learning"
                    | "insufficient_coverage"
                    | "low_quality"
                    | "ambiguous_evidence"
                    | "time_uncertain"
                    | "missing_data"
                    | "profile_mismatch"
                    | "stale"
                    | "frozen"
                    | "inactive"
                    | "non_finite"
            ) =>
        {
            Ok(EvidenceKnowledge::Unknown { reason: reason.clone() })
        }
        _ => Err(EvidenceSnapshotError::Incompatible),
    }
}

fn decode_u64(bytes: &[u8]) -> Result<u64, EvidenceSnapshotError> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| EvidenceSnapshotError::Incompatible)?;
    Ok(u64::from_be_bytes(bytes))
}

fn hex(bytes: &[u8], length: usize) -> Result<String, EvidenceSnapshotError> {
    if bytes.len() != length {
        return Err(EvidenceSnapshotError::Incompatible);
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, EvidenceSnapshotError> {
    let mut bytes = Vec::new();
    into_writer(value, &mut bytes).map_err(|_| EvidenceSnapshotError::Incompatible)?;
    Ok(sha256(&bytes))
}

fn packet_evidence_binding_sha256(
    receive_utc_ns: i64,
    bytes: &[u8],
    body_sha256: &[u8; 32],
) -> String {
    let mut digest = Sha256::new();
    digest.update(PACKET_EVIDENCE_BINDING_DOMAIN);
    digest.update(body_sha256);
    digest.update(receive_utc_ns.to_be_bytes());
    digest.update(u64::try_from(bytes.len()).expect("packet length fits u64").to_be_bytes());
    digest.update(bytes);
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn packet_evidence_body_sha256(receive_utc_ns: i64, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PACKET_EVIDENCE_BODY_DOMAIN);
    digest.update(receive_utc_ns.to_be_bytes());
    digest.update(b"native_frame_v1\0");
    digest.update(u64::try_from(bytes.len()).expect("packet length fits u64").to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}
