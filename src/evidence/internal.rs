//! Independent bounded RF relationship evidence verification.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value as CborValue;
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::key_material::derive_public_development_fixture_key;

const JSON_MEDIA_TYPE: &str = "application/json";
const CBOR_MEDIA_TYPE: &str = "application/cbor";
const BYTES_MEDIA_TYPE: &str = "application/octet-stream";
const PNG_MEDIA_TYPE: &str = "image/png";
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
// The formal run is intentionally small: JSON/CBOR traces, three viewport PNGs, and bounded
// native-frame ciphertexts. Raising either limit increases verifier allocation exposure.
const MAX_EVIDENCE_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVIDENCE_PACKAGE_MEMBERS: usize = 4096;
// Evidence screenshots are viewport captures; 64 MiB permits a 4096x4095 RGBA8 image.
// Raising this verification budget increases attacker-controlled allocation and decode work.
const MAX_SCREENSHOT_DECODED_BYTES: usize = 64 * 1024 * 1024;
// A fixed 64 KiB stack buffer bounds executable hashing memory without coupling it to file size.
const EXECUTABLE_HASH_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) enum EvidenceError {
    Io { path: PathBuf, source: io::Error },
    FileSet,
    Path(String),
    Artifact(String),
    Changed(String),
    ByteBound(String),
    MemberBound(String),
    Json(String),
    Cbor(String),
    Digest(String),
    Manifest(String),
    Ciphertext(String),
    Png(String),
    Sensitive(String),
    ExistingVerification,
    Clock,
    Store(crate::store::QueryError),
    RebuildUnavailable,
    Semantic(&'static str),
}

impl fmt::Debug for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EvidenceError").finish_non_exhaustive()
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.redacted_message())
    }
}

impl EvidenceError {
    pub(crate) fn redacted_message(&self) -> &'static str {
        match self {
            Self::Io { path, .. } => {
                let _ = path;
                "evidence package I/O failed"
            }
            Self::FileSet => "evidence package tree does not contain the exact allowed entries",
            Self::Path(context) => {
                let _ = context;
                "evidence artifact path is not portable and contained"
            }
            Self::Artifact(context) => {
                let _ = context;
                "evidence artifact is mutable, aliased, or not a regular file"
            }
            Self::Changed(context) => {
                let _ = context;
                "evidence artifact changed while it was being verified"
            }
            Self::ByteBound(context) => {
                let _ = context;
                "evidence package exceeds its bounded byte limit"
            }
            Self::MemberBound(context) => {
                let _ = context;
                "evidence package exceeds its bounded member limit"
            }
            Self::Json(context) => {
                let _ = context;
                "evidence JSON is not closed canonical schema version 1"
            }
            Self::Cbor(context) => {
                let _ = context;
                "evidence Store export is not deterministic canonical CBOR"
            }
            Self::Digest(context) => {
                let _ = context;
                "evidence artifact digest does not match its sealed manifest"
            }
            Self::Manifest(context) => {
                let _ = context;
                "evidence artifact manifest is incomplete, duplicated, or unordered"
            }
            Self::Ciphertext(context) => {
                let _ = context;
                "retained native-frame ciphertext did not authenticate under the normative fixture"
            }
            Self::Png(context) => {
                let _ = context;
                "evidence screenshot is not a PNG"
            }
            Self::Sensitive(context) => {
                let _ = context;
                "evidence artifact contains forbidden sensitive cleartext"
            }
            Self::ExistingVerification => "verification receipt already exists",
            Self::Clock => "system clock cannot represent the verification interval",
            Self::Store(source) => {
                let _ = source;
                "committed Store evidence snapshot failed"
            }
            Self::RebuildUnavailable => {
                "the Host did not perform a compatible active-session rebuild"
            }
            Self::Semantic(message) => message,
        }
    }
}

impl Error for EvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            // Query errors retain their full Store cause privately, but that nested public
            // representation can include a configured Managed Store path.
            Self::Store(_) => None,
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    media_type: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Interval {
    ended_utc_ns: String,
    started_utc_ns: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunReceipt {
    artifacts: Vec<Artifact>,
    identities: RunIdentities,
    interval: Interval,
    negative_claims: Vec<String>,
    privacy: Privacy,
    procedure_version: String,
    result: String,
    run_id: String,
    schema_version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunIdentities {
    asset_sha256: String,
    config_sha256: String,
    firmware: FirmwareIdentity,
    host: HostIdentity,
    provisioning_sha256: String,
    session_id: String,
    store_id: String,
    subject: Selection,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FirmwareIdentity {
    capability_sha256: String,
    image_sha256: String,
    source_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HostIdentity {
    executable_sha256: String,
    source_clean: bool,
    source_revision: String,
    source_sha256: String,
    target: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Privacy {
    ciphertext_source_mac_recoverable: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObserverReceipt {
    artifacts: Vec<Artifact>,
    browser: Browser,
    environment: String,
    interval: Interval,
    page_instance_id: String,
    schema_version: u8,
    selection: Selection,
    served_asset_sha256: String,
    viewport: Viewport,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Viewport {
    device_scale_factor: String,
    height: String,
    width: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Browser {
    application_id: String,
    executable_sha256: String,
    name: String,
    team_id: String,
    version: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    link: String,
    profile: String,
    session_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalInput {
    datagrams: Vec<PhysicalDatagram>,
    fixture: FixtureIdentity,
    schema_version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureIdentity {
    capability_sha256: String,
    firmware_image_sha256: String,
    kind: String,
    provisioning_sha256: String,
    sensor_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalDatagram {
    body_binding_sha256: String,
    context: PhysicalReceiveContext,
    device_id: String,
    key_epoch: String,
    path: String,
    receive_order: String,
    received_monotonic_ns: String,
    received_utc_ns: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalReceiveContext {
    capture_record_seq: String,
    capture_session_id: String,
    capture_session_time: String,
    semantic_record_seq: String,
    semantic_session_time: String,
    transport: String,
    wire_format: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostCommitTrace {
    facts: Vec<HostTraceFact>,
    schema_version: u8,
    session_id: String,
    store_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostTraceFact {
    body_sha256: String,
    capture: Option<HostTraceCapture>,
    command: Option<HostTraceCommand>,
    datagram_sha256: Option<String>,
    decoded_message: Option<DecodedMessage>,
    kind: String,
    record_seq: String,
    session_time: String,
    transaction_a: HostTraceTransactionA,
    transaction_b: HostTraceTransactionB,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DecodedMessage {
    Capabilities {
        capability_sha256: String,
        firmware_image_sha256: String,
    },
    CsiData {
        callback_tick_us: String,
        capability_sha256: String,
        capture_sequence: String,
        channel: String,
        complex_sample_count: String,
        driver_rx_timestamp_us: String,
    },
    Health {
        callback_tick_us: String,
        capability_sha256: String,
        capture_seen: String,
        queue_drop_full: String,
        queue_drop_no_slot: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostTraceCommand {
    command: String,
    link: String,
    profile: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostTraceCapture {
    capture_record_seq: String,
    capture_session_id: String,
    capture_session_time: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostTraceTransactionA {
    effects: Vec<String>,
    identity: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostTraceTransactionB {
    baseline_sha256: Option<String>,
    commit_seq: String,
    creator_commit_seq: Option<String>,
    effects: Vec<String>,
    identity: String,
    processed_cursor: String,
    relationship_sha256: Option<String>,
    timeline_digest: String,
    watermark: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestartTrace {
    continuation: RestartContinuation,
    rebuild: RestartRebuild,
    retained: RestartRetained,
    schema_version: u8,
    start: RestartEndpoint,
    stop: RestartEndpoint,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestartEndpoint {
    capture_session_id: String,
    durable_tail: String,
    host_executable_sha256: String,
    processed_cursor: String,
    utc_ns: String,
    watermark: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestartRetained {
    link: String,
    physical_sensor: String,
    profile: String,
    session_id: String,
    store_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestartRebuild {
    authorizer: String,
    comparisons: RestartComparisons,
    open_flags: Vec<String>,
    post_export_sha256: String,
    pre_export_sha256: String,
    query_only: bool,
    total_changes: String,
    write_attempted: bool,
    writer_opens: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestartComparisons {
    baseline: bool,
    bytes: bool,
    creator: bool,
    cursor: bool,
    relationship: bool,
    tail: bool,
    timeline: bool,
    watermark: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestartContinuation {
    first_commit_seq: String,
    first_datagram_sha256: String,
    first_record_seq: String,
    knowledge: String,
    later_commit_seq: String,
    later_record_seq: String,
    later_result_time: String,
    most_recent_change_preserved: bool,
    previous_result_time: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRelationship {
    data: HttpRelationshipData,
    http_schema_version: u8,
    kind: String,
    receipt: HttpViewReceipt,
    resource: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRelationshipData {
    creator_commit: HttpProjection,
    knowledge: HttpKnowledge,
    link: String,
    #[serde(default)]
    most_recent_change: Option<HttpChange>,
    profile: String,
    result_time: String,
    session_id: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum HttpKnowledge {
    Known { value: String },
    Unknown { reason: String },
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HttpChange {
    changed_at: String,
    current: HttpKnowledge,
    previous: HttpKnowledge,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpViewReceipt {
    algorithm_version: String,
    conditioning_version: String,
    decoder_version: String,
    first_record_seq: String,
    last_record_seq: String,
    projection_commit: HttpProjection,
    session_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpProjection {
    sequence: String,
    store_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebsocketTrace {
    events: Vec<WebsocketEvent>,
    schema_version: u8,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebsocketEvent {
    #[serde(default)]
    delivery_sequence: Option<String>,
    kind: String,
    order: String,
    #[serde(default)]
    raw_text_sha256: Option<String>,
    socket_id: String,
    #[serde(default)]
    store_id: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    watermark: Option<String>,
}

#[derive(Serialize)]
struct LiveEnvelopeEvidence<'a> {
    http_schema_version: u8,
    delivery_sequence: &'a str,
    projection_commit: LiveWatermarkEvidence<'a>,
    payload: LivePayloadEvidence,
}

#[derive(Serialize)]
struct LiveWatermarkEvidence<'a> {
    store_id: &'a str,
    sequence: &'a str,
}

#[derive(Serialize)]
struct LivePayloadEvidence {
    kind: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChromeTrace {
    document_id: String,
    events: Vec<ChromeEvent>,
    page_instance_id: String,
    schema_version: u8,
    selection: Selection,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StateBounds {
    height: u32,
    width: u32,
    x: u32,
    y: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChromeEvent {
    #[serde(default)]
    change_state: Option<String>,
    #[serde(default)]
    change_time: Option<String>,
    connection_detail: String,
    connection_state: String,
    connection_text: String,
    document_id: String,
    kind: String,
    knowledge: String,
    #[serde(default)]
    state_bounds: Option<StateBounds>,
    opaque_visual_surfaces: Vec<String>,
    order: String,
    #[serde(default)]
    result_time: Option<String>,
    #[serde(default)]
    screenshot: Option<String>,
    #[serde(default)]
    screenshot_sha256: Option<String>,
    selection: Selection,
    stale: bool,
    #[serde(default)]
    trigger_websocket_order: Option<String>,
    #[serde(default)]
    trigger_websocket_socket_id: Option<String>,
    #[serde(default)]
    trigger_websocket_watermark: Option<String>,
    visible_text: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadArtifact {
    identity: FileIdentity,
    bytes: Vec<u8>,
    digest: String,
}

#[derive(Default)]
struct ReadBudget {
    bytes: u64,
    members: usize,
}

impl ReadBudget {
    fn include(&mut self, relative: &str, bytes: u64) -> Result<(), EvidenceError> {
        let package_bytes = self.bytes.checked_add(bytes);
        let package_members = self.members.checked_add(1);
        if bytes > MAX_EVIDENCE_MEMBER_BYTES
            || package_bytes.is_none_or(|value| value > MAX_EVIDENCE_PACKAGE_BYTES)
        {
            return Err(EvidenceError::ByteBound(relative.to_owned()));
        }
        if package_members.is_none_or(|value| value > MAX_EVIDENCE_PACKAGE_MEMBERS) {
            return Err(EvidenceError::MemberBound(relative.to_owned()));
        }
        self.bytes = package_bytes.expect("checked evidence package bytes");
        self.members = package_members.expect("checked evidence package members");
        Ok(())
    }
}

#[derive(Serialize)]
struct VerificationReceipt<'a> {
    checks: [VerificationCheck<'a>; 15],
    interval: VerificationInterval,
    observer_artifacts: &'a [Artifact],
    observer_sha256: &'a str,
    producer_artifacts: &'a [Artifact],
    result: &'static str,
    run_sha256: &'a str,
    schema_version: u8,
    verifier: VerifierIdentity,
}

#[derive(Serialize)]
struct VerificationInterval {
    ended_utc_ns: String,
    started_utc_ns: String,
}

#[derive(Serialize)]
struct VerifierIdentity {
    executable_sha256: String,
    source_sha256: String,
}

#[derive(Serialize)]
struct VerificationCheck<'a> {
    name: &'a str,
    result: &'static str,
}

#[derive(Clone, Copy)]
enum ReadMode {
    SealProducer,
    SealObserver,
    Verify,
}

impl ReadMode {
    fn requires_readonly(self, path: &str) -> bool {
        match self {
            Self::SealProducer => false,
            Self::SealObserver => is_producer_path(path),
            Self::Verify => true,
        }
    }

    fn requires_readonly_directory(self, path: &str) -> bool {
        match self {
            Self::SealProducer => false,
            Self::SealObserver => path == "datagrams",
            Self::Verify => true,
        }
    }
}

mod format;
mod package;
mod producer;
mod semantics;
mod verifier;

use format::sensitive_string;
use package::{canonical_json, is_producer_path, parse_canonical_json};

pub(crate) use producer::{
    seal_observer, seal_producer, write_current_store_export, write_input_and_commit_artifacts,
    write_observer_receipt, write_rebuild_store_export, write_restart_artifact, write_run_receipt,
};
pub(crate) use semantics::validate_transaction_b_audit;
pub(crate) use verifier::verify;

pub(crate) fn validate_evidence_text_id(value: &str) -> Result<(), EvidenceError> {
    if value.trim().is_empty() || sensitive_string(value) {
        return Err(EvidenceError::Semantic("evidence text identity is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_evidence_run_id(value: &str) -> Result<(), EvidenceError> {
    validate_evidence_text_id(value)?;
    if value.contains(['/', '\\']) {
        return Err(EvidenceError::Semantic("evidence run identity is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_evidence_digest(value: &str) -> Result<(), EvidenceError> {
    if !is_sha256(value) {
        return Err(EvidenceError::Semantic("evidence digest is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_evidence_revision(value: &str) -> Result<(), EvidenceError> {
    if !is_revision(value) {
        return Err(EvidenceError::Semantic("evidence source revision is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_subject(
    subject: &crate::evidence::EvidenceSubject,
) -> Result<(), EvidenceError> {
    if validate_evidence_text_id(&subject.session_id).is_err()
        || validate_evidence_text_id(&subject.link).is_err()
        || validate_evidence_digest(&subject.profile).is_err()
    {
        return Err(EvidenceError::Semantic("evidence subject is incompatible"));
    }
    Ok(())
}

pub(crate) fn capture_unknown_observation(
    runtime: &crate::HostRuntime,
    subject: &crate::evidence::EvidenceSubject,
) -> Result<crate::evidence::EvidenceUnknownObservation, EvidenceError> {
    validate_subject(subject)?;
    let selection = crate::store::RelationshipSelection::try_new(
        &subject.session_id,
        &subject.link,
        &subject.profile,
    )
    .map_err(EvidenceError::Store)?;
    let response =
        runtime.evidence_relationship_latest(&selection).map_err(EvidenceError::Store)?;
    let value = serde_json::to_value(response)
        .map_err(|_| EvidenceError::Json("committed relationship response".to_owned()))?;
    let bytes = canonical_json(&value)?;
    let observation = unknown_observation_from_http(&bytes)?;
    if observation.subject != *subject {
        return Err(EvidenceError::Semantic("committed Unknown subject is incompatible"));
    }
    Ok(observation)
}

fn unknown_observation_from_http(
    bytes: &[u8],
) -> Result<crate::evidence::EvidenceUnknownObservation, EvidenceError> {
    let response: HttpRelationship =
        parse_canonical_json("committed relationship response", bytes)?;
    let subject = crate::evidence::EvidenceSubject {
        session_id: response.data.session_id.clone(),
        link: response.data.link.clone(),
        profile: response.data.profile.clone(),
    };
    validate_subject(&subject)?;
    let creator_commit_seq = response
        .data
        .creator_commit
        .sequence
        .parse::<u64>()
        .map_err(|_| EvidenceError::Semantic("Unknown creator commit is incompatible"))?;
    let result_time = response
        .data
        .result_time
        .parse::<u64>()
        .map_err(|_| EvidenceError::Semantic("Unknown result time is incompatible"))?;
    let watermark = response
        .receipt
        .projection_commit
        .sequence
        .parse::<u64>()
        .map_err(|_| EvidenceError::Semantic("Unknown receipt watermark is incompatible"))?;
    let valid = response.http_schema_version == 1
        && response.kind == "ok"
        && response.resource == "relationship_latest"
        && matches!(
            response.data.knowledge,
            HttpKnowledge::Unknown { ref reason } if reason == "baseline_learning"
        )
        && response.data.most_recent_change.is_none()
        && creator_commit_seq > 0
        && creator_commit_seq <= watermark
        && response.data.creator_commit.store_id == response.receipt.projection_commit.store_id
        && is_sha256(&response.data.creator_commit.store_id)
        && response.receipt.session_id == subject.session_id
        && response.receipt.first_record_seq == "0"
        && parse_decimal(&response.receipt.last_record_seq).is_some()
        && !response.receipt.decoder_version.is_empty()
        && !response.receipt.conditioning_version.is_empty()
        && !response.receipt.algorithm_version.is_empty();
    if !valid {
        return Err(EvidenceError::Semantic("committed Unknown observation is incompatible"));
    }
    Ok(crate::evidence::EvidenceUnknownObservation { creator_commit_seq, result_time, subject })
}

pub(crate) fn validate_run_identity(
    identity: &crate::evidence::EvidenceRunIdentity,
) -> Result<(), EvidenceError> {
    if !is_sha256(&identity.config_sha256)
        || !is_sha256(&identity.firmware_capability_sha256)
        || !is_sha256(&identity.firmware_image_sha256)
        || !is_sha256(&identity.provisioning_sha256)
        || !is_revision(&identity.firmware_source_revision)
    {
        return Err(EvidenceError::Semantic("producer run identity is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_run_metadata(
    metadata: &crate::evidence::EvidenceRunMetadata,
) -> Result<(), EvidenceError> {
    validate_run_identity(&metadata.identity)?;
    validate_subject(&metadata.subject)?;
    validate_subject(&metadata.unknown.subject)?;
    if validate_evidence_run_id(&metadata.run_id).is_err()
        || metadata.interval.ended_utc_ns <= metadata.interval.started_utc_ns
        || metadata.subject != metadata.unknown.subject
    {
        return Err(EvidenceError::Semantic("producer run metadata is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_viewport(
    viewport: &crate::evidence::EvidenceViewport,
) -> Result<(), EvidenceError> {
    if viewport.width == 0
        || viewport.height == 0
        || !valid_positive_decimal(&viewport.device_scale_factor)
    {
        return Err(EvidenceError::Semantic("observer viewport is incompatible"));
    }
    Ok(())
}

pub(crate) fn validate_observer_metadata(
    metadata: &crate::evidence::EvidenceObserverMetadata,
) -> Result<(), EvidenceError> {
    validate_subject(&metadata.subject)?;
    validate_viewport(&metadata.viewport)?;
    if validate_evidence_text_id(&metadata.page_instance_id).is_err()
        || validate_evidence_text_id(&metadata.chrome.version).is_err()
        || validate_evidence_digest(&metadata.chrome.executable_sha256).is_err()
        || metadata.interval.ended_utc_ns <= metadata.interval.started_utc_ns
    {
        return Err(EvidenceError::Semantic("observer metadata is incompatible"));
    }
    Ok(())
}

fn selected_relationship<'a>(
    snapshot: &'a crate::store::EvidenceStoreSnapshot,
    subject: &crate::evidence::EvidenceSubject,
    missing: &'static str,
) -> Result<&'a crate::store::EvidenceRelationship, EvidenceError> {
    if snapshot.active_session.session_id != subject.session_id {
        return Err(EvidenceError::Semantic(missing));
    }
    snapshot
        .relationships
        .iter()
        .find(|candidate| candidate.link == subject.link && candidate.profile == subject.profile)
        .ok_or(EvidenceError::Semantic(missing))
}

fn selected_relationship_from_selection<'a>(
    snapshot: &'a crate::store::EvidenceStoreSnapshot,
    selection: &Selection,
    missing: &'static str,
) -> Result<&'a crate::store::EvidenceRelationship, EvidenceError> {
    if snapshot.active_session.session_id != selection.session_id {
        return Err(EvidenceError::Semantic(missing));
    }
    snapshot
        .relationships
        .iter()
        .find(|candidate| {
            candidate.link == selection.link && candidate.profile == selection.profile
        })
        .ok_or(EvidenceError::Semantic(missing))
}

fn valid_positive_decimal(value: &str) -> bool {
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return false;
    }
    let mut parts = value.split('.');
    let Some(integer) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
                || fraction.ends_with('0')
        })
    {
        return false;
    }
    value.parse::<f64>().is_ok_and(|parsed| parsed.is_finite() && parsed > 0.0)
}

trait EvidenceEnvironment {
    fn executable_sha256(&self) -> Result<String, EvidenceError>;
    fn source_sha256(&self) -> String;
    fn utc_now_ns(&self) -> Result<u128, EvidenceError>;
}

struct SystemEvidenceEnvironment;

impl EvidenceEnvironment for SystemEvidenceEnvironment {
    fn executable_sha256(&self) -> Result<String, EvidenceError> {
        hash_running_executable()
    }

    fn source_sha256(&self) -> String {
        verifier_source_sha256()
    }

    fn utc_now_ns(&self) -> Result<u128, EvidenceError> {
        utc_now_ns()
    }
}

struct VerifierExecution {
    executable_sha256: String,
    host: HostIdentity,
    source_sha256: String,
    started_utc_ns: u128,
}

impl VerifierExecution {
    fn capture(environment: &dyn EvidenceEnvironment) -> Result<Self, EvidenceError> {
        let started_utc_ns = environment.utc_now_ns()?;
        let host = host_identity(environment)?;
        let executable_sha256 = host.executable_sha256.clone();
        let source_sha256 = host.source_sha256.clone();
        Ok(Self { executable_sha256, host, source_sha256, started_utc_ns })
    }
}

fn host_identity(environment: &dyn EvidenceEnvironment) -> Result<HostIdentity, EvidenceError> {
    Ok(HostIdentity {
        executable_sha256: capture_executable_sha256(environment)?,
        source_clean: env!("WHISPER_HOST_SOURCE_CLEAN") == "true",
        source_revision: env!("WHISPER_HOST_SOURCE_REVISION").to_owned(),
        source_sha256: environment.source_sha256(),
        target: env!("WHISPER_HOST_TARGET").to_owned(),
    })
}

fn capture_executable_sha256(
    environment: &dyn EvidenceEnvironment,
) -> Result<String, EvidenceError> {
    environment.executable_sha256()
}

fn verifier_source_sha256() -> String {
    env!("WHISPER_HOST_SOURCE_SHA256").to_owned()
}

fn hash_running_executable() -> Result<String, EvidenceError> {
    let path = std::env::current_exe().map_err(|source| EvidenceError::Io {
        path: PathBuf::from("current executable"),
        source,
    })?;
    let mut file =
        File::open(&path).map_err(|source| EvidenceError::Io { path: path.clone(), source })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; EXECUTABLE_HASH_BUFFER_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| EvidenceError::Io { path: path.clone(), source })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex_bytes(&digest.finalize()))
}

fn utc_now_ns() -> Result<u128, EvidenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|_| EvidenceError::Clock)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_decimal(value: &str) -> Option<u128> {
    let parsed = value.parse::<u128>().ok()?;
    (value == parsed.to_string()).then_some(parsed)
}

fn is_sha256(value: &str) -> bool {
    is_hex_64(value)
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

fn is_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{EvidenceEnvironment, EvidenceError, VerifierExecution, capture_executable_sha256};
    use std::io;

    struct FailingEnvironment {
        clock_fails: bool,
        executable_fails: bool,
    }

    impl EvidenceEnvironment for FailingEnvironment {
        fn executable_sha256(&self) -> Result<String, EvidenceError> {
            if self.executable_fails {
                Err(EvidenceError::Io {
                    path: "verifier executable".into(),
                    source: io::Error::other("unavailable"),
                })
            } else {
                Ok("00".repeat(32))
            }
        }

        fn source_sha256(&self) -> String {
            "11".repeat(32)
        }

        fn utc_now_ns(&self) -> Result<u128, EvidenceError> {
            if self.clock_fails { Err(EvidenceError::Clock) } else { Ok(1) }
        }
    }

    #[test]
    fn verifier_environment_fails_closed_when_clock_is_unavailable() {
        let environment = FailingEnvironment { clock_fails: true, executable_fails: false };
        assert!(matches!(VerifierExecution::capture(&environment), Err(EvidenceError::Clock)));
    }

    #[test]
    fn verifier_environment_fails_closed_when_executable_is_unavailable() {
        let environment = FailingEnvironment { clock_fails: false, executable_fails: true };
        assert!(matches!(VerifierExecution::capture(&environment), Err(EvidenceError::Io { .. })));
        assert!(matches!(capture_executable_sha256(&environment), Err(EvidenceError::Io { .. })));
    }
}
