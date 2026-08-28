//! Strong session manifest and record contracts for deterministic replay.

#![cfg_attr(not(test), expect(dead_code, reason = "consumed by work-package 2.2"))]

use std::collections::BTreeMap;
use std::io::Cursor;
use std::net::SocketAddr;

use ciborium::value::{Integer, Value};

use crate::capture::WireFormat;
use crate::config::ReplayConfig;
use crate::domain::csi::{CaptureProfileId, CsiPath, CsiSampleCoordinate};
use crate::domain::identity::{
    BaselineContractId, BaselineRevision, BaselineStateSequence, ConditioningVersion, DeploymentId,
    DeviceId, KeyEpoch, LinkProfileKey, RadioLinkId, SessionId, SpaceId,
};
use crate::domain::time::SessionTime;
use crate::domain::world::{
    BaselineCommand, BaselineCompatibilityReceipt, BaselineCoordinate, BaselineCoordinateKey,
    BaselineLifecycle, BaselineSnapshot, BaselineStaleReason, BaselineState, EwState,
    TargetedBaselineCommand, WelfordState,
};

/// Native-frame V1's frozen 32-byte header plus 16-byte authentication tag.
/// Changing this requires a new wire version and corresponding session pin validation.
const NATIVE_FRAME_V1_OVERHEAD_BYTES: u16 = 32 + 16;

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
    pub(crate) initial_baseline_states: Vec<BaselineState>,
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

#[derive(Debug)]
pub(crate) struct ControlRecordInput {
    record: SessionRecord,
}

impl ControlRecordInput {
    pub(crate) fn baseline_command(
        record_seq: u64,
        at: SessionTime,
        command: TargetedBaselineCommand,
    ) -> Self {
        Self {
            record: SessionRecord {
                record_seq,
                at,
                kind: SessionRecordKind::BaselineCommand(command),
            },
        }
    }

    pub(crate) fn timeline_advance(record_seq: u64, at: SessionTime) -> Self {
        Self { record: SessionRecord { record_seq, at, kind: SessionRecordKind::TimelineAdvance } }
    }

    pub(crate) fn closed(record_seq: u64, at: SessionTime) -> Self {
        Self { record: SessionRecord { record_seq, at, kind: SessionRecordKind::Closed } }
    }

    pub(crate) const fn record(&self) -> &SessionRecord {
        &self.record
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordKind {
    Packet,
    BaselineCommand,
    TimelineAdvance,
    Closed,
}

impl RecordKind {
    pub(crate) const fn from_record(record: &SessionRecordKind) -> Self {
        match record {
            SessionRecordKind::Packet { .. } => Self::Packet,
            SessionRecordKind::BaselineCommand(_) => Self::BaselineCommand,
            SessionRecordKind::TimelineAdvance => Self::TimelineAdvance,
            SessionRecordKind::Closed => Self::Closed,
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, SessionError> {
        match value {
            "packet" => Ok(Self::Packet),
            "baseline_command" => Ok(Self::BaselineCommand),
            "timeline_advance" => Ok(Self::TimelineAdvance),
            "closed" => Ok(Self::Closed),
            _ => Err(schema("record kind")),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Packet => "packet",
            Self::BaselineCommand => "baseline_command",
            Self::TimelineAdvance => "timeline_advance",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("invalid CBOR at byte offset {offset}: {message}")]
    Cbor { offset: u64, message: String },
    #[error("session schema is invalid: {0}")]
    Schema(String),
    #[error("replay configuration is invalid: {0}")]
    ReplayConfig(String),
    #[error("manifest config digest does not match its ReplayConfig")]
    ConfigDigest,
}

pub(crate) fn encode_manifest(manifest: &SessionManifest) -> Result<Vec<u8>, SessionError> {
    if manifest.config_digest != manifest.replay_config.digest() {
        return Err(SessionError::ConfigDigest);
    }
    validate_manifest_replay_contract(manifest)?;
    validate_initial_baseline_states(manifest)?;
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
            "initial_baseline_states",
            Value::Array(manifest.initial_baseline_states.iter().map(state_value).collect()),
        ),
    ]))
}

pub(crate) fn decode_manifest(bytes: &[u8], offset: u64) -> Result<SessionManifest, SessionError> {
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
        initial_baseline_states: take_array(&mut map, "initial_baseline_states")?
            .into_iter()
            .map(decode_state)
            .collect::<Result<_, _>>()?,
    };
    reject_extra(&map)?;
    validate_manifest_replay_contract(&manifest)?;
    validate_initial_baseline_states(&manifest)?;
    if encode_manifest(&manifest)? != bytes {
        return Err(schema("canonical manifest"));
    }
    Ok(manifest)
}

fn validate_manifest_replay_contract(manifest: &SessionManifest) -> Result<(), SessionError> {
    if manifest.conditioning_version != manifest.replay_config.conditioning().version().as_str() {
        return Err(schema("manifest conditioning version"));
    }
    let registry = manifest.replay_config.registry();
    let routes = registry.routes();
    if manifest.wire_admission.len() != routes.len() {
        return Err(schema("manifest wire admission routes"));
    }
    for (pin, route) in manifest.wire_admission.iter().zip(routes) {
        validate_pin(pin)?;
        let link = registry
            .links()
            .get(route.link())
            .ok_or_else(|| schema("manifest wire admission link"))?;
        let sensor = registry
            .sensors()
            .get(link.receiver())
            .ok_or_else(|| schema("manifest wire admission sensor"))?;
        if pin.device_id != route.device_id()
            || pin.key_epoch != route.key_epoch()
            || pin.firmware_build_digest != sensor.firmware_build_digest()
            || pin.capability_digest != sensor.capability_digest()
            || pin.maximum_plaintext_bytes != sensor.maximum_plaintext_bytes()
            || pin.transport_datagram_budget_bytes
                != route.admission_limits().maximum_datagram_bytes()
        {
            return Err(schema("manifest wire admission pin"));
        }
    }
    Ok(())
}

fn validate_initial_baseline_states(manifest: &SessionManifest) -> Result<(), SessionError> {
    if manifest.initial_baseline_states.windows(2).any(|pair| pair[0].key() >= pair[1].key()) {
        return Err(schema("initial baseline state order"));
    }
    for state in &manifest.initial_baseline_states {
        if state.adaptation_armed() || state.session_last_eligible_at().is_some() {
            return Err(schema("initial baseline state session-local fields"));
        }
        let Some(link) = manifest.replay_config.registry().links().get(state.key().link()) else {
            return Err(schema("initial baseline state link"));
        };
        let compatibility = state.compatibility();
        if compatibility.deployment() != manifest.replay_config.deployment().id()
            || compatibility.space() != link.space()
            || compatibility.conditioning_version()
                != manifest.replay_config.conditioning().version()
        {
            return Err(schema("initial baseline state compatibility"));
        }
    }
    Ok(())
}

pub(crate) fn encode_baseline_state(state: &BaselineState) -> Result<Vec<u8>, SessionError> {
    encode(&state_value(state))
}

pub(crate) fn decode_baseline_state(bytes: &[u8]) -> Result<BaselineState, SessionError> {
    let state = decode_state(decode(bytes, 0)?)?;
    if encode_baseline_state(&state)? != bytes {
        return Err(schema("canonical baseline state"));
    }
    Ok(state)
}

fn state_value(state: &BaselineState) -> Value {
    Value::Map(vec![
        field("link", text(state.key().link().as_str())),
        field("profile", bytes(&state.key().profile().as_bytes())),
        field("lifecycle", lifecycle_value(state.lifecycle())),
        field(
            "learning",
            Value::Array(
                state
                    .learning()
                    .iter()
                    .map(|(key, value)| {
                        Value::Map(vec![
                            field("path", path_value(key.path())),
                            field("coordinate", sample_coordinate_value(key.coordinate())),
                            field("count", unsigned(value.count())),
                            field("mean", Value::Float(value.mean())),
                            field("m2", Value::Float(value.m2())),
                            field("accepted_exposure_ns", unsigned(value.accepted_exposure_ns())),
                        ])
                    })
                    .collect(),
            ),
        ),
        field(
            "active",
            Value::Array(
                state
                    .active()
                    .iter()
                    .map(|(key, value)| {
                        Value::Map(vec![
                            field("path", path_value(key.path())),
                            field("coordinate", sample_coordinate_value(key.coordinate())),
                            field("count", unsigned(value.count())),
                            field("mean", Value::Float(value.mean())),
                            field("variance", Value::Float(value.variance())),
                            field("accepted_exposure_ns", unsigned(value.accepted_exposure_ns())),
                        ])
                    })
                    .collect(),
            ),
        ),
        field("revision", state.revision().map_or(Value::Null, |value| unsigned(value.get()))),
        field(
            "state_sequence",
            state.state_sequence().map_or(Value::Null, |value| unsigned(value.get())),
        ),
        field("adaptation_armed", Value::Bool(state.adaptation_armed())),
        field(
            "session_last_eligible_at",
            state
                .session_last_eligible_at()
                .map_or(Value::Null, |value| unsigned(value.as_nanos())),
        ),
        field("compatibility", compatibility_value(state.compatibility())),
    ])
}

fn decode_state(value: Value) -> Result<BaselineState, SessionError> {
    let mut map = named_map(value)?;
    let key = LinkProfileKey::new(
        RadioLinkId::new(take_text(&mut map, "link")?)
            .map_err(|error| SessionError::Schema(error.to_string()))?,
        CaptureProfileId::from_bytes(take_digest(&mut map, "profile")?),
    );
    let lifecycle = decode_lifecycle(take(&mut map, "lifecycle")?)?;
    let learning = decode_learning(take_array(&mut map, "learning")?)?;
    let active = decode_active(take_array(&mut map, "active")?)?;
    let revision = take_optional_u64(&mut map, "revision")?.map(BaselineRevision::new);
    let state_sequence =
        take_optional_u64(&mut map, "state_sequence")?.map(BaselineStateSequence::new);
    let adaptation_armed = take_bool(&mut map, "adaptation_armed")?;
    let session_last_eligible_at =
        take_optional_u64(&mut map, "session_last_eligible_at")?.map(SessionTime::from_nanos);
    let compatibility = decode_compatibility(take(&mut map, "compatibility")?)?;
    reject_extra(&map)?;
    BaselineState::try_new(
        key,
        lifecycle,
        learning,
        active,
        revision,
        state_sequence,
        adaptation_armed,
        session_last_eligible_at,
        compatibility,
    )
    .map_err(|error| SessionError::Schema(error.to_string()))
}

fn lifecycle_value(lifecycle: BaselineLifecycle) -> Value {
    match lifecycle {
        BaselineLifecycle::Learning { accepted_windows, accepted_exposure_ns } => Value::Map(vec![
            field("kind", text("learning")),
            field("accepted_windows", unsigned(accepted_windows)),
            field("accepted_exposure_ns", unsigned(accepted_exposure_ns)),
        ]),
        BaselineLifecycle::Active => Value::Map(vec![field("kind", text("active"))]),
        BaselineLifecycle::Frozen => Value::Map(vec![field("kind", text("frozen"))]),
        BaselineLifecycle::Stale { reason } => Value::Map(vec![
            field("kind", text("stale")),
            field(
                "reason",
                text(match reason {
                    BaselineStaleReason::Age => "age",
                    BaselineStaleReason::Incompatible => "incompatible",
                }),
            ),
        ]),
    }
}

fn decode_lifecycle(value: Value) -> Result<BaselineLifecycle, SessionError> {
    let mut map = named_map(value)?;
    let lifecycle = match take_text(&mut map, "kind")?.as_str() {
        "learning" => BaselineLifecycle::Learning {
            accepted_windows: take_u64(&mut map, "accepted_windows")?,
            accepted_exposure_ns: take_u64(&mut map, "accepted_exposure_ns")?,
        },
        "active" => BaselineLifecycle::Active,
        "frozen" => BaselineLifecycle::Frozen,
        "stale" => BaselineLifecycle::Stale {
            reason: match take_text(&mut map, "reason")?.as_str() {
                "age" => BaselineStaleReason::Age,
                "incompatible" => BaselineStaleReason::Incompatible,
                _ => return Err(schema("baseline stale reason")),
            },
        },
        _ => return Err(schema("baseline lifecycle")),
    };
    reject_extra(&map)?;
    Ok(lifecycle)
}

fn decode_learning(
    values: Vec<Value>,
) -> Result<BTreeMap<BaselineCoordinateKey, WelfordState>, SessionError> {
    let mut output = BTreeMap::new();
    let mut previous = None;
    for value in values {
        let mut map = named_map(value)?;
        let key = BaselineCoordinateKey::new(
            decode_path(take(&mut map, "path")?)?,
            decode_sample_coordinate(take(&mut map, "coordinate")?)?,
        );
        let state = WelfordState::try_new(
            take_u64(&mut map, "count")?,
            take_f64(&mut map, "mean")?,
            take_f64(&mut map, "m2")?,
            take_u64(&mut map, "accepted_exposure_ns")?,
        )
        .map_err(|error| SessionError::Schema(error.to_string()))?;
        reject_extra(&map)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(schema("learning coordinate order"));
        }
        previous = Some(key);
        output.insert(key, state);
    }
    Ok(output)
}

fn decode_active(
    values: Vec<Value>,
) -> Result<BTreeMap<BaselineCoordinateKey, EwState>, SessionError> {
    let mut output = BTreeMap::new();
    let mut previous = None;
    for value in values {
        let mut map = named_map(value)?;
        let key = BaselineCoordinateKey::new(
            decode_path(take(&mut map, "path")?)?,
            decode_sample_coordinate(take(&mut map, "coordinate")?)?,
        );
        let state = EwState::try_new(
            take_u64(&mut map, "count")?,
            take_f64(&mut map, "mean")?,
            take_f64(&mut map, "variance")?,
            take_u64(&mut map, "accepted_exposure_ns")?,
        )
        .map_err(|error| SessionError::Schema(error.to_string()))?;
        reject_extra(&map)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(schema("active coordinate order"));
        }
        previous = Some(key);
        output.insert(key, state);
    }
    Ok(output)
}

fn compatibility_value(receipt: &BaselineCompatibilityReceipt) -> Value {
    Value::Map(vec![
        field("deployment", text(receipt.deployment().as_str())),
        field("space", text(receipt.space().as_str())),
        field("conditioning_version", text(receipt.conditioning_version().as_str())),
        field("contract", bytes(&receipt.contract().as_bytes())),
    ])
}

fn decode_compatibility(value: Value) -> Result<BaselineCompatibilityReceipt, SessionError> {
    let mut map = named_map(value)?;
    let receipt = BaselineCompatibilityReceipt::new(
        DeploymentId::new(take_text(&mut map, "deployment")?)
            .map_err(|error| SessionError::Schema(error.to_string()))?,
        SpaceId::new(take_text(&mut map, "space")?)
            .map_err(|error| SessionError::Schema(error.to_string()))?,
        ConditioningVersion::new(take_text(&mut map, "conditioning_version")?)
            .map_err(|error| SessionError::Schema(error.to_string()))?,
        BaselineContractId::from_bytes(take_digest(&mut map, "contract")?),
    );
    reject_extra(&map)?;
    Ok(receipt)
}

fn command_value(command: &TargetedBaselineCommand) -> Value {
    let mut fields = vec![
        field("link", text(command.target().link().as_str())),
        field("profile", bytes(&command.target().profile().as_bytes())),
    ];
    let (kind, snapshot) = match command.command() {
        BaselineCommand::BeginLearning => ("begin_learning", None),
        BaselineCommand::Commit => ("commit", None),
        BaselineCommand::Freeze => ("freeze", None),
        BaselineCommand::Resume => ("resume", None),
        BaselineCommand::ActivateSnapshot { snapshot } => ("activate_snapshot", Some(snapshot)),
    };
    fields.push(field("command", text(kind)));
    if let Some(snapshot) = snapshot {
        fields.push(field("snapshot", snapshot_value(snapshot)));
    }
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

pub(crate) fn encode_record_body(kind: &SessionRecordKind) -> Result<Vec<u8>, SessionError> {
    let body = match kind {
        SessionRecordKind::Packet { receive_utc_ns, peer, wire_format, bytes: packet } => {
            Value::Map(vec![
                field("receive_utc_ns", signed(*receive_utc_ns)),
                field("peer", text(&peer.to_string())),
                field("wire_format", text(wire_format_name(*wire_format))),
                field("bytes", Value::Bytes(packet.to_vec())),
            ])
        }
        SessionRecordKind::BaselineCommand(command) => command_value(command),
        SessionRecordKind::TimelineAdvance | SessionRecordKind::Closed => Value::Null,
    };
    encode(&body)
}

pub(crate) fn decode_record_body(
    kind: RecordKind,
    bytes: &[u8],
) -> Result<SessionRecordKind, SessionError> {
    let body = decode(bytes, 0)?;
    let record = match kind {
        RecordKind::Packet => {
            let mut body = named_map(body)?;
            let receive_utc_ns = take_i64(&mut body, "receive_utc_ns")?;
            let peer = take_text(&mut body, "peer")?
                .parse()
                .map_err(|_| SessionError::Schema("invalid peer".into()))?;
            let wire_format = parse_wire_format(&take_text(&mut body, "wire_format")?)?;
            let bytes = take_bytes(&mut body, "bytes")?.into_boxed_slice();
            reject_extra(&body)?;
            SessionRecordKind::Packet { receive_utc_ns, peer, wire_format, bytes }
        }
        RecordKind::BaselineCommand => SessionRecordKind::BaselineCommand(decode_command(body)?),
        RecordKind::TimelineAdvance if body == Value::Null => SessionRecordKind::TimelineAdvance,
        RecordKind::Closed if body == Value::Null => SessionRecordKind::Closed,
        _ => return Err(schema("record body")),
    };
    if encode_record_body(&record)? != bytes {
        return Err(schema("canonical record body"));
    }
    Ok(record)
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
fn take_bool(map: &mut Vec<(String, Value)>, name: &str) -> Result<bool, SessionError> {
    match take(map, name)? {
        Value::Bool(value) => Ok(value),
        _ => Err(schema(name)),
    }
}
fn take_u64(map: &mut Vec<(String, Value)>, name: &str) -> Result<u64, SessionError> {
    let Value::Integer(value) = take(map, name)? else {
        return Err(schema(name));
    };
    u64::try_from(value).map_err(|_| schema(name))
}
fn take_optional_u64(
    map: &mut Vec<(String, Value)>,
    name: &str,
) -> Result<Option<u64>, SessionError> {
    match take(map, name)? {
        Value::Null => Ok(None),
        Value::Integer(value) => u64::try_from(value).map(Some).map_err(|_| schema(name)),
        _ => Err(schema(name)),
    }
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
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[derive(Debug)]
    enum FixtureValue {
        Manifest(Box<SessionManifest>),
        BaselineState(BaselineState),
        RecordBody(SessionRecordKind),
        CommandBody(TargetedBaselineCommand),
    }

    #[derive(Debug)]
    struct FixtureCase {
        file_name: &'static str,
        value: FixtureValue,
    }

    fn fixture_cases() -> Vec<FixtureCase> {
        vec![
            FixtureCase {
                file_name: "manifest.cbor",
                value: FixtureValue::Manifest(Box::new(manifest())),
            },
            FixtureCase {
                file_name: "baseline-learning.cbor",
                value: FixtureValue::BaselineState(learning_state("link-a", 0x55)),
            },
            FixtureCase {
                file_name: "baseline-active.cbor",
                value: FixtureValue::BaselineState(committed_state(BaselineLifecycle::Active)),
            },
            FixtureCase {
                file_name: "baseline-frozen.cbor",
                value: FixtureValue::BaselineState(committed_state(BaselineLifecycle::Frozen)),
            },
            FixtureCase {
                file_name: "baseline-stale-age.cbor",
                value: FixtureValue::BaselineState(committed_state(BaselineLifecycle::Stale {
                    reason: BaselineStaleReason::Age,
                })),
            },
            FixtureCase {
                file_name: "baseline-stale-incompatible.cbor",
                value: FixtureValue::BaselineState(committed_state(BaselineLifecycle::Stale {
                    reason: BaselineStaleReason::Incompatible,
                })),
            },
            FixtureCase {
                file_name: "record-packet.cbor",
                value: FixtureValue::RecordBody(SessionRecordKind::Packet {
                    receive_utc_ns: i64::MIN,
                    peer: "[2001:db8::1]:9000".parse().expect("fixture peer"),
                    wire_format: WireFormat::NativeFrameUdp,
                    bytes: vec![0, 1, 2, 0xfe, 0xff].into_boxed_slice(),
                }),
            },
            FixtureCase {
                file_name: "record-timeline-advance.cbor",
                value: FixtureValue::RecordBody(SessionRecordKind::TimelineAdvance),
            },
            FixtureCase {
                file_name: "record-closed.cbor",
                value: FixtureValue::RecordBody(SessionRecordKind::Closed),
            },
            FixtureCase {
                file_name: "command-begin-learning.cbor",
                value: FixtureValue::CommandBody(fixture_command(BaselineCommand::BeginLearning)),
            },
            FixtureCase {
                file_name: "command-commit.cbor",
                value: FixtureValue::CommandBody(fixture_command(BaselineCommand::Commit)),
            },
            FixtureCase {
                file_name: "command-freeze.cbor",
                value: FixtureValue::CommandBody(fixture_command(BaselineCommand::Freeze)),
            },
            FixtureCase {
                file_name: "command-resume.cbor",
                value: FixtureValue::CommandBody(fixture_command(BaselineCommand::Resume)),
            },
            FixtureCase {
                file_name: "command-activate-snapshot.cbor",
                value: FixtureValue::CommandBody(fixture_command(
                    BaselineCommand::ActivateSnapshot { snapshot: baseline() },
                )),
            },
        ]
    }

    fn fixture_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session/v1")
    }

    fn fixture_bytes(case: &FixtureCase) -> Vec<u8> {
        let path = fixture_directory().join(case.file_name);
        fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read canonical session fixture {}: {error}; regenerate with `cargo test --locked --lib session::tests::regenerate_canonical_session_fixtures -- --ignored --exact`",
                path.display()
            )
        })
    }

    fn encode_fixture(case: &FixtureCase) -> Result<Vec<u8>, SessionError> {
        match &case.value {
            FixtureValue::Manifest(value) => encode_manifest(value),
            FixtureValue::BaselineState(value) => encode_baseline_state(value),
            FixtureValue::RecordBody(value) => encode_record_body(value),
            FixtureValue::CommandBody(value) => {
                encode_record_body(&SessionRecordKind::BaselineCommand(value.clone()))
            }
        }
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
            wire_admission: fixture_wire_admission(),
            conditioning_version: "amplitude-v1".into(),
            algorithm_version: "baseline-v1".into(),
            initial_baseline_states: vec![
                learning_seed_state("link-a", 0x55),
                active_seed_state("link-b", 0x56),
            ],
        }
    }

    fn fixture_wire_admission() -> Vec<WireAdmissionPin> {
        vec![
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
        ]
    }

    fn compatibility() -> BaselineCompatibilityReceipt {
        BaselineCompatibilityReceipt::new(
            DeploymentId::new("lab").expect("deployment"),
            SpaceId::new("room").expect("space"),
            ConditioningVersion::new("amplitude-v1").expect("conditioning"),
            BaselineContractId::from_bytes([0x66; 32]),
        )
    }

    fn state_coordinate() -> BaselineCoordinateKey {
        BaselineCoordinateKey::new(
            CsiPath::RawPathOrdinal(u16::MAX),
            CsiSampleCoordinate::FrequencyHz(u64::MAX),
        )
    }

    fn learning_state(link: &str, profile: u8) -> BaselineState {
        learning_state_with_compatibility(link, profile, compatibility())
    }

    fn learning_state_with_compatibility(
        link: &str,
        profile: u8,
        compatibility: BaselineCompatibilityReceipt,
    ) -> BaselineState {
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new(link).expect("link"),
                CaptureProfileId::from_bytes([profile; 32]),
            ),
            BaselineLifecycle::Learning {
                accepted_windows: u64::MAX,
                accepted_exposure_ns: u64::MAX,
            },
            BTreeMap::from([(
                state_coordinate(),
                WelfordState::try_new(u64::MAX, 1.25, 3.5, u64::MAX).expect("welford"),
            )]),
            BTreeMap::new(),
            None,
            None,
            false,
            Some(SessionTime::from_nanos(u64::MAX)),
            compatibility,
        )
        .expect("learning state")
    }

    fn active_state(link: &str, profile: u8) -> BaselineState {
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new(link).expect("link"),
                CaptureProfileId::from_bytes([profile; 32]),
            ),
            BaselineLifecycle::Active,
            BTreeMap::new(),
            BTreeMap::from([(
                state_coordinate(),
                EwState::try_new(u64::MAX, 2.5, 0.75, u64::MAX).expect("EW"),
            )]),
            Some(BaselineRevision::new(u64::MAX)),
            Some(BaselineStateSequence::new(u64::MAX)),
            true,
            Some(SessionTime::from_nanos(u64::MAX)),
            compatibility(),
        )
        .expect("active state")
    }

    fn learning_seed_state(link: &str, profile: u8) -> BaselineState {
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new(link).expect("link"),
                CaptureProfileId::from_bytes([profile; 32]),
            ),
            BaselineLifecycle::Learning {
                accepted_windows: u64::MAX,
                accepted_exposure_ns: u64::MAX,
            },
            BTreeMap::from([(
                state_coordinate(),
                WelfordState::try_new(u64::MAX, 1.25, 3.5, u64::MAX).expect("welford"),
            )]),
            BTreeMap::new(),
            None,
            None,
            false,
            None,
            compatibility(),
        )
        .expect("learning seed state")
    }

    fn active_seed_state(link: &str, profile: u8) -> BaselineState {
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new(link).expect("link"),
                CaptureProfileId::from_bytes([profile; 32]),
            ),
            BaselineLifecycle::Active,
            BTreeMap::new(),
            BTreeMap::from([(
                state_coordinate(),
                EwState::try_new(u64::MAX, 2.5, 0.75, u64::MAX).expect("EW"),
            )]),
            Some(BaselineRevision::new(u64::MAX)),
            Some(BaselineStateSequence::new(u64::MAX)),
            false,
            None,
            compatibility(),
        )
        .expect("active seed state")
    }

    fn committed_state(lifecycle: BaselineLifecycle) -> BaselineState {
        let coordinates = BTreeMap::from([
            (
                BaselineCoordinateKey::new(
                    CsiPath::TxRx { tx_stream: u16::MAX, rx_chain: u16::MAX - 1 },
                    CsiSampleCoordinate::OpaqueSampleOrdinal(u16::MAX),
                ),
                EwState::try_new(u64::MAX, 1.5, 0.25, u64::MAX).expect("opaque EW state"),
            ),
            (
                BaselineCoordinateKey::new(
                    CsiPath::RawPathOrdinal(u16::MAX),
                    CsiSampleCoordinate::IeeeToneIndex(i16::MIN),
                ),
                EwState::try_new(u64::MAX - 1, 2.5, 0.5, u64::MAX - 1).expect("tone EW state"),
            ),
            (
                BaselineCoordinateKey::new(
                    CsiPath::RawPathOrdinal(0),
                    CsiSampleCoordinate::FrequencyHz(u64::MAX),
                ),
                EwState::try_new(u64::MAX - 2, 3.5, 0.75, u64::MAX - 2)
                    .expect("frequency EW state"),
            ),
        ]);
        BaselineState::try_new(
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            lifecycle,
            BTreeMap::new(),
            coordinates,
            Some(BaselineRevision::new(u64::MAX)),
            Some(BaselineStateSequence::new(u64::MAX)),
            matches!(lifecycle, BaselineLifecycle::Active),
            Some(SessionTime::from_nanos(u64::MAX)),
            compatibility(),
        )
        .expect("committed baseline state")
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
            BaselineRevision::new(u64::MAX),
            BaselineContractId::from_bytes([0x66; 32]),
            vec![
                BaselineCoordinate::try_new(
                    CsiPath::RawPathOrdinal(u16::MAX),
                    CsiSampleCoordinate::FrequencyHz(u64::MAX),
                    u64::MAX,
                    1.0,
                    0.5,
                    u64::MAX,
                )
                .expect("coordinate"),
            ],
        )
        .expect("baseline")
    }

    fn fixture_command(command: BaselineCommand) -> TargetedBaselineCommand {
        TargetedBaselineCommand::new(
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            command,
        )
    }

    #[test]
    fn canonical_manifest_fixture_roundtrips_complete_replay_semantics() {
        let case = fixture_cases().into_iter().next().expect("manifest fixture case");
        let FixtureValue::Manifest(expected) = &case.value else {
            panic!("first fixture case is not the manifest")
        };
        let bytes = fixture_bytes(&case);
        let actual = decode_manifest(&bytes, 0).expect("decode canonical manifest fixture");
        let text = String::from_utf8_lossy(&bytes);

        assert_eq!(actual.session_id, expected.session_id);
        assert_eq!(actual.started_utc_ns, expected.started_utc_ns);
        assert_eq!(actual.config_digest, expected.config_digest);
        assert_eq!(actual.replay_config.digest(), expected.replay_config.digest());
        assert_eq!(actual.application_version, expected.application_version);
        assert_eq!(actual.build_fingerprint, expected.build_fingerprint);
        assert_eq!(actual.decoder_version, expected.decoder_version);
        assert_eq!(actual.wire_admission, expected.wire_admission);
        assert_eq!(actual.conditioning_version, expected.conditioning_version);
        assert_eq!(actual.algorithm_version, expected.algorithm_version);
        assert_eq!(actual.initial_baseline_states, expected.initial_baseline_states);
        assert!(actual.initial_baseline_states.iter().all(|state| {
            !state.adaptation_armed() && state.session_last_eligible_at().is_none()
        }));
        assert_eq!(
            actual.initial_baseline_states[0].learning()[&state_coordinate()]
                .accepted_exposure_ns(),
            u64::MAX
        );
        assert_eq!(
            actual.initial_baseline_states[1].active()[&state_coordinate()].variance(),
            0.75
        );
        for forbidden in [
            "./data/whisper.sqlite3",
            "./data/secrets",
            "database_path",
            "secret_root",
            "[deployment]",
            "[[routes]]",
        ] {
            assert!(!text.contains(forbidden), "manifest fixture leaked {forbidden}");
        }
        assert_eq!(encode_manifest(&actual).expect("re-encode manifest fixture"), bytes);
    }

    #[test]
    fn canonical_baseline_fixtures_cover_every_lifecycle_and_strong_coordinate() {
        let cases = fixture_cases()
            .into_iter()
            .filter(|case| matches!(case.value, FixtureValue::BaselineState(_)))
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 5);

        for case in cases {
            let FixtureValue::BaselineState(expected) = &case.value else {
                panic!("filtered fixture is not a baseline state")
            };
            let bytes = fixture_bytes(&case);
            let actual =
                decode_baseline_state(&bytes).expect("decode canonical baseline state fixture");
            assert_eq!(&actual, expected, "{} semantics", case.file_name);
            assert_eq!(
                encode_baseline_state(&actual).expect("re-encode baseline fixture"),
                bytes,
                "{} canonical bytes",
                case.file_name
            );
        }

        let active = committed_state(BaselineLifecycle::Active);
        assert!(active.active().contains_key(&BaselineCoordinateKey::new(
            CsiPath::TxRx { tx_stream: u16::MAX, rx_chain: u16::MAX - 1 },
            CsiSampleCoordinate::OpaqueSampleOrdinal(u16::MAX),
        )));
        assert!(active.active().contains_key(&BaselineCoordinateKey::new(
            CsiPath::RawPathOrdinal(u16::MAX),
            CsiSampleCoordinate::IeeeToneIndex(i16::MIN),
        )));
        assert!(active.active().contains_key(&BaselineCoordinateKey::new(
            CsiPath::RawPathOrdinal(0),
            CsiSampleCoordinate::FrequencyHz(u64::MAX),
        )));
    }

    #[test]
    fn canonical_record_fixtures_cover_packet_and_exact_null_controls() {
        let cases = fixture_cases()
            .into_iter()
            .filter(|case| matches!(case.value, FixtureValue::RecordBody(_)))
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 3);

        for case in cases {
            let FixtureValue::RecordBody(expected) = &case.value else {
                panic!("filtered fixture is not a record body")
            };
            let bytes = fixture_bytes(&case);
            let kind = RecordKind::from_record(expected);
            let actual = decode_record_body(kind, &bytes).expect("decode canonical record fixture");
            assert_eq!(&actual, expected, "{} semantics", case.file_name);
            assert_eq!(
                encode_record_body(&actual).expect("re-encode record fixture"),
                bytes,
                "{} canonical bytes",
                case.file_name
            );
            if matches!(expected, SessionRecordKind::TimelineAdvance | SessionRecordKind::Closed) {
                assert_eq!(bytes, [0xf6], "{} exact CBOR null", case.file_name);
            }
        }
    }

    #[test]
    fn canonical_command_fixtures_cover_every_baseline_command() {
        let cases = fixture_cases()
            .into_iter()
            .filter(|case| matches!(case.value, FixtureValue::CommandBody(_)))
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 5);

        for case in cases {
            let FixtureValue::CommandBody(expected) = &case.value else {
                panic!("filtered fixture is not a command body")
            };
            let bytes = fixture_bytes(&case);
            let actual = decode_record_body(RecordKind::BaselineCommand, &bytes)
                .expect("decode canonical command fixture");
            let expected = SessionRecordKind::BaselineCommand(expected.clone());
            assert_eq!(actual, expected, "{} semantics", case.file_name);
            assert_eq!(
                encode_record_body(&actual).expect("re-encode command fixture"),
                bytes,
                "{} canonical bytes",
                case.file_name
            );
        }
    }

    #[test]
    #[ignore = "writes canonical fixture files under tests/fixtures/session/v1"]
    fn regenerate_canonical_session_fixtures() {
        let directory = fixture_directory();
        fs::create_dir_all(&directory).unwrap_or_else(|error| {
            panic!("failed to create fixture directory {}: {error}", directory.display())
        });
        for case in fixture_cases() {
            let path = directory.join(case.file_name);
            let bytes = encode_fixture(&case).unwrap_or_else(|error| {
                panic!("failed to encode canonical fixture {}: {error}", path.display())
            });
            fs::write(&path, bytes).unwrap_or_else(|error| {
                panic!("failed to write canonical fixture {}: {error}", path.display())
            });
        }
    }

    #[test]
    fn session_manifest_roundtrips_strong_replay_config_without_runtime_or_secrets() {
        let expected = manifest();
        let bytes = encode_manifest(&expected).expect("encode manifest");
        let text = String::from_utf8_lossy(&bytes);
        for forbidden in ["./data/secrets", "runtime", "secret_root", "aes_key", "[capture]"] {
            assert!(!text.contains(forbidden));
        }
        assert!(!text.contains("initial_baselines"));
        let actual = decode_manifest(&bytes, 0).expect("decode manifest");
        assert_eq!(actual.session_id, expected.session_id);
        assert_eq!(actual.config_digest, expected.config_digest);
        assert_eq!(actual.replay_config.digest(), expected.replay_config.digest());
        assert_eq!(actual.wire_admission.len(), 2);
        assert_eq!(actual.wire_admission[0].device_id.get(), 1);
        assert_eq!(actual.wire_admission[0].key_epoch.get(), 1);
        assert_eq!(actual.wire_admission[1].device_id.get(), 2);
        assert_eq!(actual.wire_admission[1].key_epoch.get(), 1);
        assert_eq!(actual.decoder_version, "native-frame-v1");
        assert_eq!(actual.conditioning_version, "amplitude-v1");
        assert_eq!(actual.algorithm_version, "baseline-v1");
        assert_eq!(actual.initial_baseline_states, expected.initial_baseline_states);
        assert_eq!(actual.initial_baseline_states[0].learning()[&state_coordinate()].m2(), 3.5);
        assert_eq!(
            actual.initial_baseline_states[0].learning()[&state_coordinate()]
                .accepted_exposure_ns(),
            u64::MAX
        );
        assert_eq!(
            actual.initial_baseline_states[1].active()[&state_coordinate()].variance(),
            0.75
        );
        assert_eq!(
            actual.initial_baseline_states[1].active()[&state_coordinate()].count(),
            u64::MAX
        );
        assert_eq!(
            actual.initial_baseline_states[1].state_sequence().expect("state sequence").get(),
            u64::MAX
        );
        assert!(actual.initial_baseline_states.iter().all(|state| {
            !state.adaptation_armed() && state.session_last_eligible_at().is_none()
        }));
    }

    #[test]
    fn manifest_replay_contract_rejects_each_cross_field_mismatch() {
        let expected = manifest();
        encode_manifest(&expected).expect("valid manifest replay contract");
        let mut invalid = Vec::new();

        let mut conditioning = expected.clone();
        conditioning.conditioning_version = "other".into();
        invalid.push(("conditioning", conditioning));

        let mut length = expected.clone();
        length.wire_admission.pop();
        invalid.push(("pin length", length));

        let mut order = expected.clone();
        order.wire_admission.swap(0, 1);
        invalid.push(("pin order", order));

        let mut device = expected.clone();
        device.wire_admission[0].device_id = DeviceId::new(99);
        invalid.push(("device", device));

        let mut epoch = expected.clone();
        epoch.wire_admission[0].key_epoch = KeyEpoch::try_new(2).expect("key epoch");
        invalid.push(("key epoch", epoch));

        let mut firmware = expected.clone();
        firmware.wire_admission[0].firmware_build_digest = [0x09; 32];
        invalid.push(("firmware", firmware));

        let mut capability = expected.clone();
        capability.wire_admission[0].capability_digest = [0x09; 32];
        invalid.push(("capability", capability));

        let mut plaintext = expected.clone();
        plaintext.wire_admission[0].maximum_plaintext_bytes = 704;
        invalid.push(("maximum plaintext", plaintext));

        let mut datagram = expected;
        datagram.wire_admission[0].transport_datagram_budget_bytes = 2047;
        invalid.push(("datagram budget", datagram));

        for (field, invalid) in invalid {
            assert!(
                matches!(encode_manifest(&invalid), Err(SessionError::Schema(_))),
                "accepted mismatched {field}"
            );
        }
    }

    #[test]
    fn manifest_initial_baseline_seeds_reject_armed_or_session_local_state() {
        let mut invalid = manifest();
        invalid.initial_baseline_states =
            vec![learning_state("link-a", 0x55), active_state("link-b", 0x56)];
        assert!(invalid.initial_baseline_states.iter().any(BaselineState::adaptation_armed));
        assert!(
            invalid
                .initial_baseline_states
                .iter()
                .any(|state| state.session_last_eligible_at().is_some())
        );

        assert!(matches!(encode_manifest(&invalid), Err(SessionError::Schema(_))));
    }

    #[test]
    fn session_manifest_rejects_digest_mismatch_unknown_fields_and_trailing_data() {
        let expected = manifest();
        let mut mismatched = expected.clone();
        mismatched.config_digest = [0; 32];
        assert!(matches!(encode_manifest(&mismatched), Err(SessionError::ConfigDigest)));

        let mut value = decode(&encode_manifest(&expected).expect("encode"), 0).expect("value");
        let Value::Map(fields) = &mut value else { panic!("manifest map") };
        fields.push(field("unknown", Value::Null));
        assert!(matches!(
            decode_manifest(&encode(&value).expect("encode unknown"), 0),
            Err(SessionError::Schema(_))
        ));

        let mut bytes = encode_manifest(&expected).expect("manifest");
        bytes.push(0xf6);
        assert!(matches!(decode_manifest(&bytes, 0), Err(SessionError::Cbor { .. })));
    }

    #[test]
    fn session_decoders_reject_missing_duplicate_reordered_and_noncanonical_fields() {
        let canonical_manifest = encode_manifest(&manifest()).expect("canonical manifest");

        let mut missing = decode(&canonical_manifest, 0).expect("manifest value");
        let Value::Map(fields) = &mut missing else { panic!("manifest map") };
        fields.retain(|(key, _)| key != &Value::Text("algorithm_version".into()));
        assert!(matches!(
            decode_manifest(&encode(&missing).expect("missing field bytes"), 0),
            Err(SessionError::Schema(_))
        ));

        let mut duplicate = decode(&canonical_manifest, 0).expect("manifest value");
        let Value::Map(fields) = &mut duplicate else { panic!("manifest map") };
        let session_id = fields
            .iter()
            .find(|(key, _)| key == &Value::Text("session_id".into()))
            .expect("session ID field")
            .clone();
        fields.push(session_id);
        assert!(matches!(
            decode_manifest(&encode(&duplicate).expect("duplicate field bytes"), 0),
            Err(SessionError::Schema(_))
        ));

        let mut noncanonical = canonical_manifest.clone();
        assert_eq!(noncanonical[8], 1, "canonical schema value location changed");
        noncanonical.insert(8, 0x18);
        assert!(decode_manifest(&noncanonical, 0).is_err(), "accepted an overlong CBOR encoding");

        let mut reordered = decode(
            &encode_baseline_state(&committed_state(BaselineLifecycle::Active))
                .expect("canonical baseline"),
            0,
        )
        .expect("baseline value");
        let Value::Map(fields) = &mut reordered else { panic!("baseline map") };
        fields.reverse();
        assert!(
            decode_baseline_state(&encode(&reordered).expect("reordered baseline")).is_err(),
            "accepted reordered baseline fields"
        );
    }

    #[test]
    fn unit_control_record_bodies_are_exact_cbor_null() {
        let timeline_advance = SessionRecord {
            record_seq: 7,
            at: SessionTime::from_nanos(11),
            kind: SessionRecordKind::TimelineAdvance,
        };
        let closed = SessionRecord {
            record_seq: 8,
            at: SessionTime::from_nanos(12),
            kind: SessionRecordKind::Closed,
        };

        assert_eq!(
            encode_record_body(&timeline_advance.kind).expect("timeline advance body"),
            [0xf6]
        );
        assert_eq!(encode_record_body(&closed.kind).expect("closed body"), [0xf6]);
    }

    #[test]
    fn record_body_codec_roundtrips_all_variants() {
        let command = TargetedBaselineCommand::new(
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            BaselineCommand::Freeze,
        );
        let variants = [
            SessionRecordKind::Packet {
                receive_utc_ns: i64::MIN,
                peer: "[2001:db8::1]:9000".parse().expect("peer"),
                wire_format: WireFormat::NativeFrameUdp,
                bytes: vec![0, 1, 2].into_boxed_slice(),
            },
            SessionRecordKind::BaselineCommand(command),
            SessionRecordKind::TimelineAdvance,
            SessionRecordKind::Closed,
        ];

        for expected in variants {
            let tag = RecordKind::from_record(&expected);
            let body = encode_record_body(&expected).expect("encode body");
            assert_eq!(decode_record_body(tag, &body).expect("decode body"), expected);
        }
    }

    #[test]
    fn control_inputs_construct_only_their_allowed_record_kinds() {
        let command = TargetedBaselineCommand::new(
            LinkProfileKey::new(
                RadioLinkId::new("link-a").expect("link"),
                CaptureProfileId::from_bytes([0x55; 32]),
            ),
            BaselineCommand::Freeze,
        );
        assert!(matches!(
            ControlRecordInput::baseline_command(1, SessionTime::from_nanos(11), command)
                .record()
                .kind,
            SessionRecordKind::BaselineCommand(_)
        ));
        assert!(matches!(
            ControlRecordInput::timeline_advance(2, SessionTime::from_nanos(12)).record().kind,
            SessionRecordKind::TimelineAdvance
        ));
        assert!(matches!(
            ControlRecordInput::closed(3, SessionTime::from_nanos(13)).record().kind,
            SessionRecordKind::Closed
        ));
    }

    #[test]
    fn record_body_decoder_rejects_unknown_tags_noncanonical_and_trailing_input() {
        for (tag, expected) in [
            ("packet", RecordKind::Packet),
            ("baseline_command", RecordKind::BaselineCommand),
            ("timeline_advance", RecordKind::TimelineAdvance),
            ("closed", RecordKind::Closed),
        ] {
            assert_eq!(RecordKind::parse(tag).expect("accepted record kind"), expected);
            assert_eq!(expected.as_str(), tag);
        }
        assert!(RecordKind::parse("unknown").is_err());

        let packet = SessionRecordKind::Packet {
            receive_utc_ns: -1,
            peer: "192.0.2.1:9000".parse().expect("peer"),
            wire_format: WireFormat::NativeFrameUdp,
            bytes: vec![1, 2, 3].into_boxed_slice(),
        };
        let mut reordered =
            decode(&encode_record_body(&packet).expect("packet body"), 0).expect("packet value");
        let Value::Map(fields) = &mut reordered else { panic!("packet map") };
        fields.reverse();
        assert!(
            decode_record_body(RecordKind::Packet, &encode(&reordered).expect("reordered body"))
                .is_err()
        );

        let mut repeated_envelope =
            decode(&encode_record_body(&packet).expect("packet body"), 0).expect("packet value");
        let Value::Map(fields) = &mut repeated_envelope else { panic!("packet map") };
        fields.push(field("record_seq", unsigned(7)));
        assert!(
            decode_record_body(
                RecordKind::Packet,
                &encode(&repeated_envelope).expect("body with envelope field")
            )
            .is_err()
        );

        assert!(decode_record_body(RecordKind::Closed, &[0xf4]).is_err());
        assert!(decode_record_body(RecordKind::TimelineAdvance, &[0xf6, 0xf6]).is_err());
    }

    #[test]
    fn session_baseline_command_bodies_and_snapshot_roundtrip_strong_values() {
        let target = LinkProfileKey::new(
            RadioLinkId::new("link-a").expect("link"),
            CaptureProfileId::from_bytes([0x55; 32]),
        );
        let variants = [
            BaselineCommand::BeginLearning,
            BaselineCommand::Commit,
            BaselineCommand::Freeze,
            BaselineCommand::Resume,
            BaselineCommand::ActivateSnapshot { snapshot: baseline() },
        ];
        for command in variants {
            let expected = SessionRecordKind::BaselineCommand(TargetedBaselineCommand::new(
                target.clone(),
                command,
            ));
            assert_eq!(
                decode_record_body(
                    RecordKind::BaselineCommand,
                    &encode_record_body(&expected).expect("encode body")
                )
                .expect("decode body"),
                expected
            );
        }

        let expected = manifest();
        let actual = decode_manifest(&encode_manifest(&expected).expect("encode"), 0)
            .expect("decode complete state");
        assert_eq!(actual.initial_baseline_states, expected.initial_baseline_states);
    }

    #[test]
    fn session_decoder_rejects_invalid_strong_identity_and_wire_pin() {
        let mut value = decode(&encode_manifest(&manifest()).expect("encode"), 0).expect("value");
        let Value::Map(fields) = &mut value else { panic!("manifest map") };
        fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("session_id".into()))
            .expect("session id")
            .1 = Value::Text(" ".into());
        assert!(matches!(
            decode_manifest(&encode(&value).expect("encode invalid"), 0),
            Err(SessionError::Schema(_))
        ));

        let mut invalid = manifest();
        invalid.wire_admission[0].maximum_plaintext_bytes = 900;
        invalid.wire_admission[0].transport_datagram_budget_bytes = 900;
        assert!(matches!(encode_manifest(&invalid), Err(SessionError::Schema(_))));
    }

    #[test]
    fn session_baseline_state_codec_rejects_invalid_unordered_and_incompatible_values() {
        let expected = active_state("link-a", 0x55);
        assert_eq!(
            decode_baseline_state(&encode_baseline_state(&expected).expect("encode"))
                .expect("decode"),
            expected
        );

        let mut value = state_value(&expected);
        let Value::Map(fields) = &mut value else { panic!("state map") };
        let active = fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("active".into()))
            .expect("active");
        let Value::Array(coordinates) = &mut active.1 else { panic!("coordinate array") };
        coordinates.push(coordinates[0].clone());
        assert!(decode_state(value).is_err());

        let mut value = state_value(&expected);
        let Value::Map(fields) = &mut value else { panic!("state map") };
        fields.push(field("extra", Value::Null));
        assert!(decode_state(value).is_err());

        let mut unordered = manifest();
        unordered.initial_baseline_states.reverse();
        assert!(matches!(encode_manifest(&unordered), Err(SessionError::Schema(_))));

        let receipt = |deployment, space, conditioning| {
            BaselineCompatibilityReceipt::new(
                DeploymentId::new(deployment).expect("deployment"),
                SpaceId::new(space).expect("space"),
                ConditioningVersion::new(conditioning).expect("conditioning"),
                BaselineContractId::from_bytes([0x66; 32]),
            )
        };
        let incompatible = [
            learning_state("missing-link", 0x55),
            learning_state_with_compatibility(
                "link-a",
                0x55,
                receipt("other", "room", "amplitude-v1"),
            ),
            learning_state_with_compatibility(
                "link-a",
                0x55,
                receipt("lab", "other", "amplitude-v1"),
            ),
            learning_state_with_compatibility("link-a", 0x55, receipt("lab", "room", "other")),
        ];
        for state in incompatible {
            let mut invalid = manifest();
            invalid.initial_baseline_states = vec![state];
            assert!(matches!(encode_manifest(&invalid), Err(SessionError::Schema(_))));
        }
    }
}
