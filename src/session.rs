//! Bounded, checksummed session storage for deterministic replay.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ciborium::value::{Integer, Value};

use crate::capture::WireFormat;
use crate::config::ReplayConfig;
use crate::domain::csi::{CaptureProfileId, CsiPath, CsiSampleCoordinate};
use crate::domain::identity::{
    BaselineContractId, BaselineRevision, ConditioningVersion, DeploymentId, DeviceId, KeyEpoch,
    LinkProfileKey, RadioLinkId, SessionId, SpaceId,
};
use crate::domain::time::SessionTime;
use crate::domain::world::{
    BaselineCommand, BaselineCoordinate, BaselineSnapshot, TargetedBaselineCommand,
};

const MAGIC: &[u8; 8] = b"RFWSESS\0";
const CONTAINER_VERSION: u16 = 1;
const RECORD_SCHEMA: u16 = 1;
const HEADER_LEN: u64 = 18;
/// Native-frame V1's frozen 32-byte header plus 16-byte authentication tag.
/// Changing this requires a new wire version and corresponding session pin validation.
const NATIVE_FRAME_V1_OVERHEAD_BYTES: u16 = 32 + 16;

/// Hard allocation limits supplied by the application configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionLimits {
    pub(crate) max_manifest_bytes: u32,
    pub(crate) max_record_bytes: u32,
}

/// Non-secret replay admission facts pinned by a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireAdmissionPin {
    pub(crate) wire_version: u8,
    pub(crate) device_id: DeviceId,
    pub(crate) key_epoch: KeyEpoch,
    pub(crate) firmware_build_digest: [u8; 32],
    pub(crate) capability_digest: [u8; 32],
    pub(crate) maximum_plaintext_bytes: u16,
    pub(crate) transport_datagram_budget_bytes: u16,
}

/// All inputs that pin faithful replay for one session.
#[derive(Clone, Debug)]
pub(crate) struct SessionManifest {
    pub(crate) session_id: SessionId,
    pub(crate) started_utc_ns: i64,
    pub(crate) replay_config: ReplayConfig,
    pub(crate) config_digest: [u8; 32],
    pub(crate) application_version: String,
    pub(crate) build_fingerprint: [u8; 32],
    pub(crate) decoder_version: String,
    pub(crate) wire_admission: Vec<WireAdmissionPin>,
    pub(crate) conditioning_version: String,
    pub(crate) algorithm_version: String,
    pub(crate) initial_baselines: Vec<BaselineSnapshot>,
}

/// One entry in the session total order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SessionRecord {
    pub(crate) record_seq: u64,
    pub(crate) at: SessionTime,
    pub(crate) kind: SessionRecordKind,
}

/// Persisted facts and ordered control inputs.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SessionRecordKind {
    Packet { receive_utc_ns: i64, peer: SocketAddr, wire_format: WireFormat, bytes: Box<[u8]> },
    BaselineCommand(TargetedBaselineCommand),
    TimelineAdvance,
    Closed,
}

/// Result of scanning a session file.
#[derive(Clone, Debug)]
pub(crate) struct ReadSession {
    pub(crate) manifest: SessionManifest,
    pub(crate) records: Vec<SessionRecord>,
    pub(crate) seal: SessionSeal,
}

/// Whether a file ended normally or was recovery-sealed at a crash tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionSeal {
    Open,
    Closed,
    RecoverySealed { truncated_at: u64 },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("session I/O failed at byte offset {offset}: {source}")]
    Io {
        offset: u64,
        #[source]
        source: io::Error,
    },
    #[error("invalid session magic")]
    Magic,
    #[error("unsupported container version {0}")]
    ContainerVersion(u16),
    #[error("manifest length {length} exceeds limit {limit}")]
    ManifestTooLarge { length: u32, limit: u32 },
    #[error("record length {length} at byte offset {offset} exceeds limit {limit}")]
    RecordTooLarge { offset: u64, length: u32, limit: u32 },
    #[error("CRC-32C mismatch at byte offset {offset}")]
    Crc { offset: u64 },
    #[error("invalid CBOR at byte offset {offset}: {message}")]
    Cbor { offset: u64, message: String },
    #[error("session schema is invalid: {0}")]
    Schema(String),
    #[error("replay configuration is invalid: {0}")]
    ReplayConfig(String),
    #[error("manifest config digest does not match its ReplayConfig")]
    ConfigDigest,
    #[error("record sequence {actual} does not equal expected {expected}")]
    Sequence { expected: u64, actual: u64 },
    #[error("record time {actual} precedes previous time {previous}")]
    TimeReversed { previous: u64, actual: u64 },
    #[error("cannot append after Closed")]
    Closed,
    #[error("session lock is already held")]
    Locked,
}

/// Exclusive append owner for one active session.
#[derive(Debug)]
pub(crate) struct SessionWriter {
    file: File,
    next_seq: u64,
    last_at: Option<u64>,
    closed: bool,
    durable_through_record_seq: Option<u64>,
}

/// Process-wide advisory ownership for capture, replay mutation, and retention.
#[derive(Debug)]
pub(crate) struct RuntimeLock {
    _file: File,
}

impl RuntimeLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, SessionError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| SessionError::Io { offset: 0, source })?;
        file.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => SessionError::Locked,
            fs::TryLockError::Error(source) => SessionError::Io { offset: 0, source },
        })?;
        Ok(Self { _file: file })
    }
}

impl SessionWriter {
    pub(crate) fn create(
        path: &Path,
        manifest: &SessionManifest,
        limits: SessionLimits,
    ) -> Result<Self, SessionError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| SessionError::Io { offset: 0, source })?;
        let bytes = encode_manifest(manifest)?;
        let length = u32::try_from(bytes.len()).map_err(|_| SessionError::ManifestTooLarge {
            length: u32::MAX,
            limit: limits.max_manifest_bytes,
        })?;
        if length > limits.max_manifest_bytes {
            return Err(SessionError::ManifestTooLarge {
                length,
                limit: limits.max_manifest_bytes,
            });
        }
        file.write_all(MAGIC)
            .and_then(|()| file.write_all(&CONTAINER_VERSION.to_le_bytes()))
            .and_then(|()| file.write_all(&length.to_le_bytes()))
            .and_then(|()| file.write_all(&crc32c::crc32c(&bytes).to_le_bytes()))
            .and_then(|()| file.write_all(&bytes))
            .map_err(|source| SessionError::Io { offset: 0, source })?;
        Ok(Self {
            file,
            next_seq: 0,
            last_at: None,
            closed: false,
            durable_through_record_seq: None,
        })
    }

    pub(crate) fn append(
        &mut self,
        record: &SessionRecord,
        limits: SessionLimits,
    ) -> Result<(), SessionError> {
        self.validate_next(record)?;
        let bytes = encode_record(record)?;
        let length = u32::try_from(bytes.len()).map_err(|_| SessionError::RecordTooLarge {
            offset: self.file.stream_position().unwrap_or(0),
            length: u32::MAX,
            limit: limits.max_record_bytes,
        })?;
        let offset =
            self.file.stream_position().map_err(|source| SessionError::Io { offset: 0, source })?;
        if length > limits.max_record_bytes {
            return Err(SessionError::RecordTooLarge {
                offset,
                length,
                limit: limits.max_record_bytes,
            });
        }
        let mut framed = Vec::with_capacity(8 + bytes.len());
        framed.extend_from_slice(&length.to_le_bytes());
        framed.extend_from_slice(&crc32c::crc32c(&bytes).to_le_bytes());
        framed.extend_from_slice(&bytes);
        self.file.write_all(&framed).map_err(|source| SessionError::Io { offset, source })?;
        self.next_seq += 1;
        self.last_at = Some(record.at.as_nanos());
        self.closed = matches!(record.kind, SessionRecordKind::Closed);
        Ok(())
    }

    fn validate_next(&self, record: &SessionRecord) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::Closed);
        }
        if record.record_seq != self.next_seq {
            return Err(SessionError::Sequence {
                expected: self.next_seq,
                actual: record.record_seq,
            });
        }
        if let Some(previous) = self.last_at.filter(|previous| record.at.as_nanos() < *previous) {
            return Err(SessionError::TimeReversed { previous, actual: record.at.as_nanos() });
        }
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<(), SessionError> {
        let offset = self.file.stream_position().unwrap_or(0);
        self.file.flush().map_err(|source| SessionError::Io { offset, source })
    }

    pub(crate) fn sync(&mut self) -> Result<(), SessionError> {
        self.flush()?;
        let offset = self.file.stream_position().unwrap_or(0);
        self.file.sync_data().map_err(|source| SessionError::Io { offset, source })?;
        self.durable_through_record_seq = self.next_seq.checked_sub(1);
        Ok(())
    }

    pub(crate) const fn durable_through_record_seq(&self) -> Option<u64> {
        self.durable_through_record_seq
    }

    pub(crate) fn record_boundary(&mut self) -> Result<u64, SessionError> {
        self.flush()?;
        self.file.stream_position().map_err(|source| SessionError::Io { offset: 0, source })
    }
}

pub(crate) fn read(path: &Path, limits: SessionLimits) -> Result<ReadSession, SessionError> {
    let mut file = File::open(path).map_err(|source| SessionError::Io { offset: 0, source })?;
    let file_len = file.metadata().map_err(|source| SessionError::Io { offset: 0, source })?.len();
    let mut header = [0_u8; HEADER_LEN as usize];
    file.read_exact(&mut header).map_err(|source| SessionError::Io { offset: 0, source })?;
    if &header[..8] != MAGIC {
        return Err(SessionError::Magic);
    }
    let version = u16::from_le_bytes(header[8..10].try_into().expect("fixed header"));
    if version != CONTAINER_VERSION {
        return Err(SessionError::ContainerVersion(version));
    }
    let manifest_len = u32::from_le_bytes(header[10..14].try_into().expect("fixed header"));
    if manifest_len > limits.max_manifest_bytes {
        return Err(SessionError::ManifestTooLarge {
            length: manifest_len,
            limit: limits.max_manifest_bytes,
        });
    }
    let manifest_crc = u32::from_le_bytes(header[14..18].try_into().expect("fixed header"));
    let mut manifest_bytes = vec![0; manifest_len as usize];
    file.read_exact(&mut manifest_bytes)
        .map_err(|source| SessionError::Io { offset: HEADER_LEN, source })?;
    if crc32c::crc32c(&manifest_bytes) != manifest_crc {
        return Err(SessionError::Crc { offset: HEADER_LEN });
    }
    let manifest = decode_manifest(&manifest_bytes, HEADER_LEN)?;
    let mut records = Vec::new();
    let mut expected = 0;
    let mut last_at = None;
    let mut seal = SessionSeal::Open;
    loop {
        let offset =
            file.stream_position().map_err(|source| SessionError::Io { offset: 0, source })?;
        if offset == file_len {
            break;
        }
        if file_len - offset < 8 {
            seal = SessionSeal::RecoverySealed { truncated_at: offset };
            break;
        }
        let mut framing = [0_u8; 8];
        file.read_exact(&mut framing).map_err(|source| SessionError::Io { offset, source })?;
        let length = u32::from_le_bytes(framing[..4].try_into().expect("record header"));
        if length > limits.max_record_bytes {
            return Err(SessionError::RecordTooLarge {
                offset,
                length,
                limit: limits.max_record_bytes,
            });
        }
        if file_len - (offset + 8) < u64::from(length) {
            seal = SessionSeal::RecoverySealed { truncated_at: offset };
            break;
        }
        let expected_crc = u32::from_le_bytes(framing[4..].try_into().expect("record header"));
        let mut body = vec![0; length as usize];
        file.read_exact(&mut body)
            .map_err(|source| SessionError::Io { offset: offset + 8, source })?;
        if crc32c::crc32c(&body) != expected_crc {
            return Err(SessionError::Crc { offset });
        }
        let record = decode_record(&body, offset + 8)?;
        if record.record_seq != expected {
            return Err(SessionError::Sequence { expected, actual: record.record_seq });
        }
        if let Some(previous) = last_at.filter(|previous| record.at.as_nanos() < *previous) {
            return Err(SessionError::TimeReversed { previous, actual: record.at.as_nanos() });
        }
        expected += 1;
        last_at = Some(record.at.as_nanos());
        if matches!(record.kind, SessionRecordKind::Closed) {
            seal = SessionSeal::Closed;
            if file.stream_position().map_err(|source| SessionError::Io { offset, source })?
                != file_len
            {
                return Err(SessionError::Schema("data follows Closed record".into()));
            }
        }
        records.push(record);
    }
    if seal == SessionSeal::Open {
        seal = SessionSeal::RecoverySealed { truncated_at: file_len };
    }
    Ok(ReadSession { manifest, records, seal })
}

/// Deletes eligible files by session start time toward `keep`, excluding `active` and open files.
pub(crate) fn retain_oldest_closed(
    sessions: &mut [(PathBuf, SessionSeal, i64)],
    active: &Path,
    keep: usize,
) -> Result<Vec<PathBuf>, SessionError> {
    sessions.sort_by(|left, right| left.2.cmp(&right.2).then_with(|| left.0.cmp(&right.0)));
    let mut remove = sessions.len().saturating_sub(keep);
    let mut removed = Vec::new();
    for (path, seal, _) in sessions.iter() {
        if remove == 0 {
            break;
        }
        if path != active && *seal != SessionSeal::Open {
            fs::remove_file(path).map_err(|source| SessionError::Io { offset: 0, source })?;
            removed.push(path.clone());
            remove -= 1;
        }
    }
    Ok(removed)
}

fn encode_manifest(manifest: &SessionManifest) -> Result<Vec<u8>, SessionError> {
    if manifest.config_digest != manifest.replay_config.digest() {
        return Err(SessionError::ConfigDigest);
    }
    for pin in &manifest.wire_admission {
        validate_pin(pin)?;
    }
    encode(&Value::Map(vec![
        field("schema", unsigned(1)),
        field("session_id", text(manifest.session_id.as_str())),
        field("started_utc_ns", signed(manifest.started_utc_ns)),
        field(
            "replay_config",
            Value::serialized(&manifest.replay_config)
                .map_err(|error| SessionError::ReplayConfig(error.to_string()))?,
        ),
        field("config_digest", bytes(&manifest.config_digest)),
        field("application_version", text(&manifest.application_version)),
        field("build_fingerprint", bytes(&manifest.build_fingerprint)),
        field("decoder_version", text(&manifest.decoder_version)),
        field(
            "wire_admission",
            Value::Array(manifest.wire_admission.iter().map(pin_value).collect()),
        ),
        field("conditioning_version", text(&manifest.conditioning_version)),
        field("algorithm_version", text(&manifest.algorithm_version)),
        field(
            "initial_baselines",
            Value::Array(manifest.initial_baselines.iter().map(snapshot_value).collect()),
        ),
    ]))
}

fn decode_manifest(bytes: &[u8], offset: u64) -> Result<SessionManifest, SessionError> {
    let mut map = named_map(decode(bytes, offset)?)?;
    require_schema(&mut map, 1)?;
    let replay_value = take(&mut map, "replay_config")?;
    let replay_bytes = encode(&replay_value)?;
    let replay_config = ReplayConfig::from_canonical_bytes(&replay_bytes)
        .map_err(|error| SessionError::ReplayConfig(error.to_string()))?;
    let config_digest = take_digest(&mut map, "config_digest")?;
    if config_digest != replay_config.digest() {
        return Err(SessionError::ConfigDigest);
    }
    let manifest = SessionManifest {
        session_id: SessionId::new(take_text(&mut map, "session_id")?)
            .map_err(|error| SessionError::Schema(error.to_string()))?,
        started_utc_ns: take_i64(&mut map, "started_utc_ns")?,
        replay_config,
        config_digest,
        application_version: take_text(&mut map, "application_version")?,
        build_fingerprint: take_digest(&mut map, "build_fingerprint")?,
        decoder_version: take_text(&mut map, "decoder_version")?,
        wire_admission: take_array(&mut map, "wire_admission")?
            .into_iter()
            .map(decode_pin)
            .collect::<Result<_, _>>()?,
        conditioning_version: take_text(&mut map, "conditioning_version")?,
        algorithm_version: take_text(&mut map, "algorithm_version")?,
        initial_baselines: take_array(&mut map, "initial_baselines")?
            .into_iter()
            .map(decode_snapshot)
            .collect::<Result<_, _>>()?,
    };
    reject_extra(&map)?;
    Ok(manifest)
}

fn command_value(command: &TargetedBaselineCommand) -> Value {
    let mut fields = vec![
        field("link", text(command.target().link().as_str())),
        field("profile", bytes(&command.target().profile().as_bytes())),
    ];
    let kind = match command.command() {
        BaselineCommand::BeginLearning => "begin_learning",
        BaselineCommand::Commit => "commit",
        BaselineCommand::Freeze => "freeze",
        BaselineCommand::Resume => "resume",
        BaselineCommand::ActivateSnapshot { snapshot } => {
            fields.push(field("snapshot", snapshot_value(snapshot)));
            "activate_snapshot"
        }
    };
    fields.push(field("command", text(kind)));
    Value::Map(fields)
}

fn decode_command(value: Value) -> Result<TargetedBaselineCommand, SessionError> {
    let mut map = named_map(value)?;
    let link = RadioLinkId::new(take_text(&mut map, "link")?)
        .map_err(|error| SessionError::Schema(error.to_string()))?;
    let profile = CaptureProfileId::from_bytes(take_digest(&mut map, "profile")?);
    let command = match take_text(&mut map, "command")?.as_str() {
        "begin_learning" => BaselineCommand::BeginLearning,
        "commit" => BaselineCommand::Commit,
        "freeze" => BaselineCommand::Freeze,
        "resume" => BaselineCommand::Resume,
        "activate_snapshot" => BaselineCommand::ActivateSnapshot {
            snapshot: decode_snapshot(take(&mut map, "snapshot")?)?,
        },
        _ => return Err(schema("baseline command")),
    };
    reject_extra(&map)?;
    Ok(TargetedBaselineCommand::new(LinkProfileKey::new(link, profile), command))
}

fn snapshot_value(snapshot: &BaselineSnapshot) -> Value {
    Value::Map(vec![
        field("deployment", text(snapshot.deployment().as_str())),
        field("space", text(snapshot.space().as_str())),
        field("link", text(snapshot.key().link().as_str())),
        field("profile", bytes(&snapshot.key().profile().as_bytes())),
        field("conditioning_version", text(snapshot.conditioning_version().as_str())),
        field("revision", unsigned(snapshot.revision().get())),
        field("contract", bytes(&snapshot.contract().as_bytes())),
        field(
            "coordinates",
            Value::Array(snapshot.coordinates().iter().map(coordinate_value).collect()),
        ),
    ])
}

fn decode_snapshot(value: Value) -> Result<BaselineSnapshot, SessionError> {
    let mut map = named_map(value)?;
    let deployment = DeploymentId::new(take_text(&mut map, "deployment")?)
        .map_err(|error| SessionError::Schema(error.to_string()))?;
    let space = SpaceId::new(take_text(&mut map, "space")?)
        .map_err(|error| SessionError::Schema(error.to_string()))?;
    let link = RadioLinkId::new(take_text(&mut map, "link")?)
        .map_err(|error| SessionError::Schema(error.to_string()))?;
    let profile = CaptureProfileId::from_bytes(take_digest(&mut map, "profile")?);
    let conditioning = ConditioningVersion::new(take_text(&mut map, "conditioning_version")?)
        .map_err(|error| SessionError::Schema(error.to_string()))?;
    let revision = BaselineRevision::new(take_u64(&mut map, "revision")?);
    let contract = BaselineContractId::from_bytes(take_digest(&mut map, "contract")?);
    let coordinates = take_array(&mut map, "coordinates")?
        .into_iter()
        .map(decode_coordinate)
        .collect::<Result<Vec<_>, _>>()?;
    reject_extra(&map)?;
    BaselineSnapshot::try_new(
        deployment,
        space,
        LinkProfileKey::new(link, profile),
        conditioning,
        revision,
        contract,
        coordinates,
    )
    .map_err(|error| SessionError::Schema(error.to_string()))
}

fn coordinate_value(coordinate: &BaselineCoordinate) -> Value {
    Value::Map(vec![
        field("path", path_value(coordinate.path())),
        field("coordinate", sample_coordinate_value(coordinate.coordinate())),
        field("count", unsigned(coordinate.count())),
        field("mean", Value::Float(coordinate.mean())),
        field("variance", Value::Float(coordinate.variance())),
        field("accepted_exposure_ns", unsigned(coordinate.accepted_exposure_ns())),
    ])
}

fn decode_coordinate(value: Value) -> Result<BaselineCoordinate, SessionError> {
    let mut map = named_map(value)?;
    let coordinate = BaselineCoordinate::try_new(
        decode_path(take(&mut map, "path")?)?,
        decode_sample_coordinate(take(&mut map, "coordinate")?)?,
        take_u64(&mut map, "count")?,
        take_f64(&mut map, "mean")?,
        take_f64(&mut map, "variance")?,
        take_u64(&mut map, "accepted_exposure_ns")?,
    )
    .map_err(|error| SessionError::Schema(error.to_string()))?;
    reject_extra(&map)?;
    Ok(coordinate)
}

fn path_value(path: CsiPath) -> Value {
    match path {
        CsiPath::TxRx { tx_stream, rx_chain } => Value::Map(vec![
            field("kind", text("tx_rx")),
            field("tx_stream", unsigned(tx_stream.into())),
            field("rx_chain", unsigned(rx_chain.into())),
        ]),
        CsiPath::RawPathOrdinal(ordinal) => Value::Map(vec![
            field("kind", text("raw_path_ordinal")),
            field("ordinal", unsigned(ordinal.into())),
        ]),
    }
}

fn decode_path(value: Value) -> Result<CsiPath, SessionError> {
    let mut map = named_map(value)?;
    let path = match take_text(&mut map, "kind")?.as_str() {
        "tx_rx" => CsiPath::TxRx {
            tx_stream: take_u16(&mut map, "tx_stream")?,
            rx_chain: take_u16(&mut map, "rx_chain")?,
        },
        "raw_path_ordinal" => CsiPath::RawPathOrdinal(take_u16(&mut map, "ordinal")?),
        _ => return Err(schema("CSI path")),
    };
    reject_extra(&map)?;
    Ok(path)
}

fn sample_coordinate_value(coordinate: CsiSampleCoordinate) -> Value {
    match coordinate {
        CsiSampleCoordinate::OpaqueSampleOrdinal(value) => Value::Map(vec![
            field("kind", text("opaque_sample_ordinal")),
            field("value", unsigned(value.into())),
        ]),
        CsiSampleCoordinate::IeeeToneIndex(value) => Value::Map(vec![
            field("kind", text("ieee_tone_index")),
            field("value", signed(value.into())),
        ]),
        CsiSampleCoordinate::FrequencyHz(value) => {
            Value::Map(vec![field("kind", text("frequency_hz")), field("value", unsigned(value))])
        }
    }
}

fn decode_sample_coordinate(value: Value) -> Result<CsiSampleCoordinate, SessionError> {
    let mut map = named_map(value)?;
    let coordinate = match take_text(&mut map, "kind")?.as_str() {
        "opaque_sample_ordinal" => {
            CsiSampleCoordinate::OpaqueSampleOrdinal(take_u16(&mut map, "value")?)
        }
        "ieee_tone_index" => CsiSampleCoordinate::IeeeToneIndex(
            i16::try_from(take_i64(&mut map, "value")?).map_err(|_| schema("tone index"))?,
        ),
        "frequency_hz" => CsiSampleCoordinate::FrequencyHz(take_u64(&mut map, "value")?),
        _ => return Err(schema("sample coordinate")),
    };
    reject_extra(&map)?;
    Ok(coordinate)
}

fn reject_extra(map: &[(String, Value)]) -> Result<(), SessionError> {
    if let Some((field, _)) = map.first() {
        Err(SessionError::Schema(format!("unknown field {field}")))
    } else {
        Ok(())
    }
}

fn encode_record(record: &SessionRecord) -> Result<Vec<u8>, SessionError> {
    let (kind, body) = match &record.kind {
        SessionRecordKind::Packet { receive_utc_ns, peer, wire_format, bytes: packet } => (
            "packet",
            Value::Map(vec![
                field("receive_utc_ns", signed(*receive_utc_ns)),
                field("peer", text(&peer.to_string())),
                field("wire_format", text(wire_format_name(*wire_format))),
                field("bytes", Value::Bytes(packet.to_vec())),
            ]),
        ),
        SessionRecordKind::BaselineCommand(command) => ("baseline_command", command_value(command)),
        SessionRecordKind::TimelineAdvance => ("timeline_advance", Value::Null),
        SessionRecordKind::Closed => ("closed", Value::Null),
    };
    encode(&Value::Map(vec![
        field("schema", unsigned(RECORD_SCHEMA.into())),
        field("record_seq", unsigned(record.record_seq)),
        field("at", unsigned(record.at.as_nanos())),
        field("kind", text(kind)),
        field("body", body),
    ]))
}

fn decode_record(bytes: &[u8], offset: u64) -> Result<SessionRecord, SessionError> {
    let mut map = named_map(decode(bytes, offset)?)?;
    require_schema(&mut map, u64::from(RECORD_SCHEMA))?;
    let record_seq = take_u64(&mut map, "record_seq")?;
    let at = SessionTime::from_nanos(take_u64(&mut map, "at")?);
    let kind = take_text(&mut map, "kind")?;
    let body = take(&mut map, "body")?;
    if !map.is_empty() {
        return Err(SessionError::Schema(format!("unknown field {}", map[0].0)));
    }
    let kind = match kind.as_str() {
        "packet" => {
            let mut body = named_map(body)?;
            let receive_utc_ns = take_i64(&mut body, "receive_utc_ns")?;
            let peer = take_text(&mut body, "peer")?
                .parse()
                .map_err(|_| SessionError::Schema("invalid peer".into()))?;
            let wire_format = parse_wire_format(&take_text(&mut body, "wire_format")?)?;
            let bytes = take_bytes(&mut body, "bytes")?.into_boxed_slice();
            if !body.is_empty() {
                return Err(SessionError::Schema("unknown packet field".into()));
            }
            SessionRecordKind::Packet { receive_utc_ns, peer, wire_format, bytes }
        }
        "baseline_command" => SessionRecordKind::BaselineCommand(decode_command(body)?),
        "timeline_advance" if body == Value::Null => SessionRecordKind::TimelineAdvance,
        "closed" if body == Value::Null => SessionRecordKind::Closed,
        _ => return Err(SessionError::Schema(format!("invalid record kind {kind}"))),
    };
    Ok(SessionRecord { record_seq, at, kind })
}

fn pin_value(pin: &WireAdmissionPin) -> Value {
    Value::Map(vec![
        field("wire_version", unsigned(pin.wire_version.into())),
        field("device_id", unsigned(pin.device_id.get())),
        field("key_epoch", unsigned(pin.key_epoch.get().into())),
        field("firmware_build_digest", bytes(&pin.firmware_build_digest)),
        field("capability_digest", bytes(&pin.capability_digest)),
        field("maximum_plaintext_bytes", unsigned(pin.maximum_plaintext_bytes.into())),
        field(
            "transport_datagram_budget_bytes",
            unsigned(pin.transport_datagram_budget_bytes.into()),
        ),
    ])
}
fn decode_pin(value: Value) -> Result<WireAdmissionPin, SessionError> {
    let mut map = named_map(value)?;
    let pin = WireAdmissionPin {
        wire_version: u8::try_from(take_u64(&mut map, "wire_version")?)
            .map_err(|_| schema("wire_version"))?,
        device_id: DeviceId::new(take_u64(&mut map, "device_id")?),
        key_epoch: KeyEpoch::try_new(
            u16::try_from(take_u64(&mut map, "key_epoch")?).map_err(|_| schema("key_epoch"))?,
        )
        .map_err(|error| SessionError::Schema(error.to_string()))?,
        firmware_build_digest: take_digest(&mut map, "firmware_build_digest")?,
        capability_digest: take_digest(&mut map, "capability_digest")?,
        maximum_plaintext_bytes: u16::try_from(take_u64(&mut map, "maximum_plaintext_bytes")?)
            .map_err(|_| schema("maximum_plaintext_bytes"))?,
        transport_datagram_budget_bytes: u16::try_from(take_u64(
            &mut map,
            "transport_datagram_budget_bytes",
        )?)
        .map_err(|_| schema("transport_datagram_budget_bytes"))?,
    };
    reject_extra(&map)?;
    validate_pin(&pin)?;
    Ok(pin)
}

fn validate_pin(pin: &WireAdmissionPin) -> Result<(), SessionError> {
    if pin.wire_version != 1
        || pin.maximum_plaintext_bytes == 0
        || pin.transport_datagram_budget_bytes == 0
        || pin
            .maximum_plaintext_bytes
            .checked_add(NATIVE_FRAME_V1_OVERHEAD_BYTES)
            .is_none_or(|datagram_bytes| datagram_bytes > pin.transport_datagram_budget_bytes)
    {
        return Err(schema("invalid wire admission pin"));
    }
    Ok(())
}

fn encode(value: &Value) -> Result<Vec<u8>, SessionError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|error| SessionError::Cbor { offset: 0, message: error.to_string() })?;
    Ok(bytes)
}
fn decode(bytes: &[u8], offset: u64) -> Result<Value, SessionError> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| SessionError::Cbor { offset, message: error.to_string() })?;
    if cursor.position() != bytes.len() as u64 {
        return Err(SessionError::Cbor {
            offset: offset + cursor.position(),
            message: "trailing CBOR data".into(),
        });
    }
    Ok(value)
}
fn field(name: &str, value: Value) -> (Value, Value) {
    (text(name), value)
}
fn text(value: &str) -> Value {
    Value::Text(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn unsigned(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}
fn signed(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}
fn schema(name: &str) -> SessionError {
    SessionError::Schema(format!("invalid {name}"))
}
fn named_map(value: Value) -> Result<Vec<(String, Value)>, SessionError> {
    let Value::Map(values) = value else {
        return Err(schema("named-field map"));
    };
    values
        .into_iter()
        .map(|(key, value)| match key {
            Value::Text(key) => Ok((key, value)),
            _ => Err(schema("non-text field name")),
        })
        .collect()
}
fn take(map: &mut Vec<(String, Value)>, name: &str) -> Result<Value, SessionError> {
    let index = map
        .iter()
        .position(|(key, _)| key == name)
        .ok_or_else(|| schema(&format!("missing {name}")))?;
    Ok(map.remove(index).1)
}
fn take_text(map: &mut Vec<(String, Value)>, name: &str) -> Result<String, SessionError> {
    match take(map, name)? {
        Value::Text(value) => Ok(value),
        _ => Err(schema(name)),
    }
}
fn take_bytes(map: &mut Vec<(String, Value)>, name: &str) -> Result<Vec<u8>, SessionError> {
    match take(map, name)? {
        Value::Bytes(value) => Ok(value),
        _ => Err(schema(name)),
    }
}
fn take_array(map: &mut Vec<(String, Value)>, name: &str) -> Result<Vec<Value>, SessionError> {
    match take(map, name)? {
        Value::Array(value) => Ok(value),
        _ => Err(schema(name)),
    }
}
fn take_u64(map: &mut Vec<(String, Value)>, name: &str) -> Result<u64, SessionError> {
    let Value::Integer(value) = take(map, name)? else {
        return Err(schema(name));
    };
    u64::try_from(value).map_err(|_| schema(name))
}
fn take_i64(map: &mut Vec<(String, Value)>, name: &str) -> Result<i64, SessionError> {
    let Value::Integer(value) = take(map, name)? else {
        return Err(schema(name));
    };
    i64::try_from(value).map_err(|_| schema(name))
}
fn take_u16(map: &mut Vec<(String, Value)>, name: &str) -> Result<u16, SessionError> {
    u16::try_from(take_u64(map, name)?).map_err(|_| schema(name))
}
fn take_f64(map: &mut Vec<(String, Value)>, name: &str) -> Result<f64, SessionError> {
    match take(map, name)? {
        Value::Float(value) => Ok(value),
        Value::Integer(value) => {
            i64::try_from(value).map(|value| value as f64).map_err(|_| schema(name))
        }
        _ => Err(schema(name)),
    }
}
fn take_digest(map: &mut Vec<(String, Value)>, name: &str) -> Result<[u8; 32], SessionError> {
    take_bytes(map, name)?.try_into().map_err(|_| schema(name))
}
fn require_schema(map: &mut Vec<(String, Value)>, expected: u64) -> Result<(), SessionError> {
    let actual = take_u64(map, "schema")?;
    if actual == expected {
        Ok(())
    } else {
        Err(SessionError::Schema(format!("schema {actual}, expected {expected}")))
    }
}

fn wire_format_name(format: WireFormat) -> &'static str {
    match format {
        WireFormat::NativeFrameUdp => "native_frame_udp",
    }
}

fn parse_wire_format(value: &str) -> Result<WireFormat, SessionError> {
    match value {
        "native_frame_udp" => Ok(WireFormat::NativeFrameUdp),
        _ => Err(schema("wire_format")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
    const LIMITS: SessionLimits =
        SessionLimits { max_manifest_bytes: 16 * 1024, max_record_bytes: 16 * 1024 };

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "whisper-session-{}-{}-{name}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn manifest() -> SessionManifest {
        let replay_config = crate::config::parse_config(include_str!(
            "../tests/fixtures/config/valid-two-esp32.toml"
        ))
        .expect("valid config")
        .replay()
        .clone();
        SessionManifest {
            session_id: SessionId::new("session-1").expect("session id"),
            started_utc_ns: -5,
            config_digest: replay_config.digest(),
            replay_config,
            application_version: "0.1.0".into(),
            build_fingerprint: [0x22; 32],
            decoder_version: "native-frame-v1".into(),
            wire_admission: vec![WireAdmissionPin {
                wire_version: 1,
                device_id: DeviceId::new(7),
                key_epoch: KeyEpoch::try_new(3).expect("key epoch"),
                firmware_build_digest: [0x33; 32],
                capability_digest: [0x44; 32],
                maximum_plaintext_bytes: 705,
                transport_datagram_budget_bytes: 900,
            }],
            conditioning_version: "condition-v1".into(),
            algorithm_version: "baseline-v1".into(),
            initial_baselines: vec![baseline()],
        }
    }

    fn baseline() -> BaselineSnapshot {
        BaselineSnapshot::try_new(
            DeploymentId::new("lab").expect("deployment"),
            SpaceId::new("room").expect("space"),
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            ConditioningVersion::new("amplitude-v1").expect("conditioning"),
            BaselineRevision::new(7),
            BaselineContractId::from_bytes([0x66; 32]),
            vec![
                BaselineCoordinate::try_new(
                    CsiPath::RawPathOrdinal(0),
                    CsiSampleCoordinate::OpaqueSampleOrdinal(0),
                    2,
                    1.0,
                    0.5,
                    10,
                )
                .expect("coordinate"),
            ],
        )
        .expect("baseline")
    }

    fn command(command: BaselineCommand) -> TargetedBaselineCommand {
        TargetedBaselineCommand::new(
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            command,
        )
    }

    fn records() -> Vec<SessionRecord> {
        vec![
            SessionRecord {
                record_seq: 0,
                at: SessionTime::from_nanos(10),
                kind: SessionRecordKind::Packet {
                    receive_utc_ns: 50,
                    peer: "192.0.2.1:9000".parse().expect("peer"),
                    wire_format: WireFormat::NativeFrameUdp,
                    bytes: vec![1, 2, 3, 4].into_boxed_slice(),
                },
            },
            SessionRecord {
                record_seq: 1,
                at: SessionTime::from_nanos(10),
                kind: SessionRecordKind::BaselineCommand(command(BaselineCommand::Freeze)),
            },
            SessionRecord {
                record_seq: 2,
                at: SessionTime::from_nanos(11),
                kind: SessionRecordKind::TimelineAdvance,
            },
            SessionRecord {
                record_seq: 3,
                at: SessionTime::from_nanos(11),
                kind: SessionRecordKind::Closed,
            },
        ]
    }

    fn write_session(path: &Path, records: &[SessionRecord]) {
        let mut writer = SessionWriter::create(path, &manifest(), LIMITS).expect("create");
        for record in records {
            writer.append(record, LIMITS).expect("append");
        }
        writer.sync().expect("sync");
        assert_eq!(writer.durable_through_record_seq(), records.last().map(|r| r.record_seq));
    }

    #[test]
    fn fixed_header_manifest_records_and_pins_roundtrip() {
        assert_eq!(crc32c::crc32c(b"123456789"), 0xe306_9283);
        let path = path("roundtrip.rfws");
        let expected_records = records();
        write_session(&path, &expected_records);
        let bytes = fs::read(&path).expect("read bytes");
        let fixture = include_str!("../tests/fixtures/session/session-v1.hex").trim();
        assert_eq!(hex(&bytes), fixture);
        assert_eq!(&bytes[..10], b"RFWSESS\0\x01\x00");
        let actual = read(&path, LIMITS).expect("read session");
        assert_eq!(actual.manifest.replay_config.digest(), manifest().replay_config.digest());
        assert_eq!(
            actual.manifest.replay_config.canonical_bytes().expect("config bytes"),
            manifest().replay_config.canonical_bytes().expect("config bytes")
        );
        assert_eq!(actual.manifest.config_digest, manifest().config_digest);
        assert_eq!(actual.manifest.session_id, manifest().session_id);
        assert_eq!(actual.records, expected_records);
        assert_eq!(actual.seal, SessionSeal::Closed);
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn manifest_rejects_config_digest_mismatch_and_excludes_runtime_secrets() {
        let path = path("manifest-boundary.rfws");
        let manifest = manifest();
        let encoded = encode_manifest(&manifest).expect("manifest");
        let text = String::from_utf8_lossy(&encoded);
        assert!(!text.contains("./data/secrets"));
        assert!(!text.contains("runtime"));
        assert!(!text.contains("secret_root"));
        assert!(!text.contains("aes_key"));
        assert!(!text.contains("[capture]"));
        assert!(!text.contains("[[routes]]"));
        assert!(!encoded.windows(32).any(|bytes| bytes == [0x77; 32]));

        let mut value = decode(&encoded, 0).expect("manifest value");
        let Value::Map(fields) = &mut value else { panic!("manifest must be a map") };
        let digest = fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("config_digest".into()))
            .expect("digest");
        digest.1 = Value::Bytes(vec![0; 32]);
        let bad = encode(&value).expect("bad manifest");
        write_manifest_only(&path, &bad);
        assert!(matches!(read(&path, LIMITS), Err(SessionError::ConfigDigest)));
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn decoded_session_rejects_invalid_strong_identity_and_wire_values() {
        let encoded = encode_manifest(&manifest()).expect("manifest");
        let mut value = decode(&encoded, 0).expect("manifest value");
        let Value::Map(fields) = &mut value else { panic!("manifest must be a map") };
        fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("session_id".into()))
            .expect("session id")
            .1 = Value::Text(" ".into());
        assert!(matches!(
            decode_manifest(&encode(&value).expect("encode"), 0),
            Err(SessionError::Schema(_))
        ));

        let mut pin = pin_value(&manifest().wire_admission[0]);
        let Value::Map(fields) = &mut pin else { panic!("pin must be a map") };
        fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("wire_version".into()))
            .expect("wire version")
            .1 = Value::Integer(0.into());
        assert!(matches!(decode_pin(pin), Err(SessionError::Schema(_))));

        let mut invalid_manifest = manifest();
        invalid_manifest.wire_admission[0].maximum_plaintext_bytes = 0;
        assert!(matches!(encode_manifest(&invalid_manifest), Err(SessionError::Schema(_))));
        invalid_manifest.wire_admission[0].maximum_plaintext_bytes = 900;
        invalid_manifest.wire_admission[0].transport_datagram_budget_bytes = 900;
        assert!(matches!(encode_manifest(&invalid_manifest), Err(SessionError::Schema(_))));

        assert!(matches!(parse_wire_format("unknown"), Err(SessionError::Schema(_))));
    }

    #[test]
    fn baseline_commands_and_initial_snapshot_roundtrip_strong_values() {
        let variants = vec![
            BaselineCommand::BeginLearning,
            BaselineCommand::Commit,
            BaselineCommand::Freeze,
            BaselineCommand::Resume,
            BaselineCommand::ActivateSnapshot { snapshot: baseline() },
        ];
        for (record_seq, variant) in variants.into_iter().enumerate() {
            let expected = SessionRecord {
                record_seq: record_seq as u64,
                at: SessionTime::from_nanos(20),
                kind: SessionRecordKind::BaselineCommand(command(variant)),
            };
            assert_eq!(
                decode_record(&encode_record(&expected).expect("encode"), 0).expect("decode"),
                expected
            );
        }

        let expected = manifest();
        let actual =
            decode_manifest(&encode_manifest(&expected).expect("encode"), 0).expect("decode");
        assert_eq!(actual.initial_baselines, expected.initial_baselines);
        let snapshot = &actual.initial_baselines[0];
        assert_eq!(snapshot.coordinates(), baseline().coordinates());
        assert_eq!(snapshot.contract(), baseline().contract());
    }

    #[test]
    fn baseline_decoder_rejects_invalid_and_extra_payload_fields() {
        let mut value = command_value(&command(BaselineCommand::Freeze));
        let Value::Map(fields) = &mut value else { panic!("command must be a map") };
        fields.iter_mut().find(|(key, _)| key == &Value::Text("link".into())).expect("link").1 =
            Value::Text(" ".into());
        assert!(decode_command(value).is_err());

        let mut value = command_value(&command(BaselineCommand::Freeze));
        let Value::Map(fields) = &mut value else { panic!("command must be a map") };
        fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("profile".into()))
            .expect("profile")
            .1 = Value::Bytes(vec![0; 31]);
        assert!(decode_command(value).is_err());

        let mut value = snapshot_value(&baseline());
        let Value::Map(fields) = &mut value else { panic!("snapshot must be a map") };
        let coordinates = fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("coordinates".into()))
            .expect("coordinates");
        let Value::Array(coordinates) = &mut coordinates.1 else { panic!("coordinates array") };
        coordinates.push(coordinates[0].clone());
        assert!(decode_snapshot(value).is_err());

        let mut value = snapshot_value(&baseline());
        let Value::Map(fields) = &mut value else { panic!("snapshot must be a map") };
        fields.push(field("extra", Value::Null));
        assert!(decode_snapshot(value).is_err());
    }

    #[test]
    fn runtime_lock_conflicts_releases_and_session_files_do_not_claim_it() {
        let lock_path = path("runtime.lock");
        let first = RuntimeLock::acquire(&lock_path).expect("first lock");
        assert!(matches!(RuntimeLock::acquire(&lock_path), Err(SessionError::Locked)));
        drop(first);
        let second = RuntimeLock::acquire(&lock_path).expect("released lock");
        drop(second);
        fs::remove_file(lock_path).expect("cleanup lock");

        let session_path = path("unlocked-session.rfws");
        let writer = SessionWriter::create(&session_path, &manifest(), LIMITS).expect("session");
        let probe = OpenOptions::new().read(true).write(true).open(&session_path).expect("probe");
        probe.try_lock().expect("session file must not own runtime lock");
        drop(probe);
        drop(writer);
        fs::remove_file(session_path).expect("cleanup session");
    }

    #[test]
    fn writer_rejects_sequence_time_and_closed_without_changing_boundary() {
        let path = path("writer-validation.rfws");
        let mut writer = SessionWriter::create(&path, &manifest(), LIMITS).expect("create");
        let initial = writer.record_boundary().expect("boundary");
        let mut record = records().remove(0);
        record.record_seq = 1;
        assert!(matches!(writer.append(&record, LIMITS), Err(SessionError::Sequence { .. })));
        assert_eq!(writer.record_boundary().expect("boundary"), initial);
        record.record_seq = 0;
        writer.append(&record, LIMITS).expect("first");
        assert!(matches!(writer.append(&record, LIMITS), Err(SessionError::Sequence { .. })));
        let mut reversed = SessionRecord {
            record_seq: 1,
            at: SessionTime::from_nanos(9),
            kind: SessionRecordKind::TimelineAdvance,
        };
        assert!(matches!(writer.append(&reversed, LIMITS), Err(SessionError::TimeReversed { .. })));
        reversed.at = SessionTime::from_nanos(10);
        reversed.kind = SessionRecordKind::Closed;
        writer.append(&reversed, LIMITS).expect("close");
        assert!(matches!(
            writer.append(
                &SessionRecord {
                    record_seq: 2,
                    at: SessionTime::from_nanos(10),
                    kind: SessionRecordKind::TimelineAdvance
                },
                LIMITS
            ),
            Err(SessionError::Closed)
        ));
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn every_crash_tail_recovers_only_the_complete_prefix() {
        let complete = path("complete.rfws");
        let expected = records();
        write_session(&complete, &expected);
        let bytes = fs::read(&complete).expect("bytes");
        let manifest_len = u32::from_le_bytes(bytes[10..14].try_into().expect("length")) as usize;
        let first_record = HEADER_LEN as usize + manifest_len;
        for cut in first_record..bytes.len() {
            let truncated = path("truncated.rfws");
            fs::write(&truncated, &bytes[..cut]).expect("write truncation");
            let recovered = read(&truncated, LIMITS).expect("recover tail");
            assert!(matches!(
                recovered.seal,
                SessionSeal::RecoverySealed { .. } | SessionSeal::Open
            ));
            assert!(expected.starts_with(&recovered.records));
            fs::remove_file(truncated).expect("cleanup");
        }
        fs::remove_file(complete).expect("cleanup");
    }

    #[test]
    fn mid_file_crc_failure_reports_record_offset() {
        let path = path("crc.rfws");
        write_session(&path, &records());
        let mut bytes = fs::read(&path).expect("bytes");
        let manifest_len = u32::from_le_bytes(bytes[10..14].try_into().expect("length")) as usize;
        let first_offset = HEADER_LEN as usize + manifest_len;
        bytes[first_offset + 8] ^= 1;
        fs::write(&path, bytes).expect("corrupt");
        assert!(
            matches!(read(&path, LIMITS), Err(SessionError::Crc { offset }) if offset == first_offset as u64)
        );
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn declared_lengths_are_rejected_before_body_allocation() {
        let manifest_path = path("manifest-limit.rfws");
        let mut header = Vec::from(MAGIC.as_slice());
        header.extend_from_slice(&CONTAINER_VERSION.to_le_bytes());
        header.extend_from_slice(&(LIMITS.max_manifest_bytes + 1).to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes());
        fs::write(&manifest_path, header).expect("header");
        assert!(matches!(read(&manifest_path, LIMITS), Err(SessionError::ManifestTooLarge { .. })));
        fs::remove_file(manifest_path).expect("cleanup");

        let record_path = path("record-limit.rfws");
        let manifest_bytes = encode_manifest(&manifest()).expect("manifest");
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.extend_from_slice(&CONTAINER_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc32c::crc32c(&manifest_bytes).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&(LIMITS.max_record_bytes + 1).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        fs::write(&record_path, bytes).expect("record header");
        assert!(matches!(read(&record_path, LIMITS), Err(SessionError::RecordTooLarge { .. })));
        fs::remove_file(record_path).expect("cleanup");
    }

    #[test]
    fn retention_removes_only_oldest_sealed_non_active_files() {
        let closed = path("z-older-closed");
        let recovered = path("a-newer-recovered");
        let open = path("003-open");
        let active = path("004-active");
        for path in [&closed, &recovered, &open, &active] {
            fs::write(path, []).expect("file");
        }
        let mut sessions = vec![
            (active.clone(), SessionSeal::Closed, 40),
            (open.clone(), SessionSeal::Open, 10),
            (recovered.clone(), SessionSeal::RecoverySealed { truncated_at: 9 }, 30),
            (closed.clone(), SessionSeal::Closed, 20),
        ];
        let removed = retain_oldest_closed(&mut sessions, &active, 3).expect("retain");
        assert_eq!(removed.as_slice(), std::slice::from_ref(&closed));
        assert!(removed.iter().all(|path| !path.exists()));
        assert!(recovered.exists() && open.exists() && active.exists());
        for path in [closed, recovered, open, active] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn reader_rejects_sequence_time_schema_and_cbor_trailing_data() {
        let first = records().remove(0);
        let cases = [
            (
                "duplicate",
                vec![
                    first.clone(),
                    SessionRecord {
                        record_seq: 0,
                        at: SessionTime::from_nanos(10),
                        kind: SessionRecordKind::TimelineAdvance,
                    },
                ],
                "sequence",
            ),
            (
                "time",
                vec![
                    first,
                    SessionRecord {
                        record_seq: 1,
                        at: SessionTime::from_nanos(9),
                        kind: SessionRecordKind::TimelineAdvance,
                    },
                ],
                "time",
            ),
            (
                "skip",
                vec![
                    records().remove(0),
                    SessionRecord {
                        record_seq: 2,
                        at: SessionTime::from_nanos(10),
                        kind: SessionRecordKind::TimelineAdvance,
                    },
                ],
                "sequence",
            ),
        ];
        for (name, records, expected) in cases {
            let path = path(name);
            write_raw(&path, &records);
            let error = read(&path, LIMITS).expect_err("invalid order");
            assert!(matches!(
                (&error, expected),
                (SessionError::Sequence { .. }, "sequence")
                    | (SessionError::TimeReversed { .. }, "time")
            ));
            fs::remove_file(path).expect("cleanup");
        }

        let mut record = encode_record(&records()[0]).expect("record");
        record.push(0xf6);
        let trailing = path("trailing");
        write_raw_bodies(&trailing, &[record]);
        assert!(matches!(read(&trailing, LIMITS), Err(SessionError::Cbor { .. })));
        fs::remove_file(trailing).expect("cleanup");

        let after_closed = path("after-closed");
        let mut records = records();
        records.push(SessionRecord {
            record_seq: 4,
            at: SessionTime::from_nanos(11),
            kind: SessionRecordKind::TimelineAdvance,
        });
        write_raw(&after_closed, &records);
        assert!(matches!(read(&after_closed, LIMITS), Err(SessionError::Schema(_))));
        fs::remove_file(after_closed).expect("cleanup");

        let wrong_schema = Value::Map(vec![field("schema", unsigned(2))]);
        let schema = path("schema");
        write_raw_bodies(&schema, &[encode(&wrong_schema).expect("encode")]);
        assert!(matches!(read(&schema, LIMITS), Err(SessionError::Schema(_))));
        fs::remove_file(schema).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn append_and_sync_failures_never_advance_publishable_sequence() {
        let read_only_path = path("read-only");
        fs::write(&read_only_path, []).expect("file");
        let file = File::open(&read_only_path).expect("read only");
        let mut writer = SessionWriter {
            file,
            next_seq: 0,
            last_at: None,
            closed: false,
            durable_through_record_seq: None,
        };
        assert!(matches!(writer.append(&records()[0], LIMITS), Err(SessionError::Io { .. })));
        assert_eq!(writer.next_seq, 0);
        assert_eq!(writer.durable_through_record_seq(), None);
        fs::remove_file(read_only_path).expect("cleanup");

        let file = OpenOptions::new().write(true).open("/dev/null").expect("dev null");
        let mut writer = SessionWriter {
            file,
            next_seq: 1,
            last_at: Some(10),
            closed: false,
            durable_through_record_seq: None,
        };
        assert!(writer.sync().is_err());
        assert_eq!(writer.durable_through_record_seq(), None);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn write_raw(path: &Path, records: &[SessionRecord]) {
        let bodies =
            records.iter().map(encode_record).collect::<Result<Vec<_>, _>>().expect("encode");
        write_raw_bodies(path, &bodies);
    }

    fn write_raw_bodies(path: &Path, bodies: &[Vec<u8>]) {
        let manifest = encode_manifest(&manifest()).expect("manifest");
        write_manifest_and_bodies(path, &manifest, bodies);
    }

    fn write_manifest_only(path: &Path, manifest: &[u8]) {
        write_manifest_and_bodies(path, manifest, &[]);
    }

    fn write_manifest_and_bodies(path: &Path, manifest: &[u8], bodies: &[Vec<u8>]) {
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.extend_from_slice(&CONTAINER_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc32c::crc32c(manifest).to_le_bytes());
        bytes.extend_from_slice(manifest);
        for body in bodies {
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&crc32c::crc32c(body).to_le_bytes());
            bytes.extend_from_slice(body);
        }
        fs::write(path, bytes).expect("raw session");
    }
}
