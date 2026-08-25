//! TOML configuration, topology registry, and deterministic effective settings.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use ciborium::ser::into_writer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::{
    AcquisitionMode, ConditioningVersion, DeploymentId, HardwareKind, IdError, LtfMerge,
    LtfSelection, RadioLinkId, SensorId, SpaceId, TransmitterId, ValidityDialect,
};

/// Errors returned while reading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("could not read configuration: {0}")]
    Read(#[source] std::io::Error),
    /// TOML syntax or shape was invalid.
    #[error("could not parse TOML configuration: {0}")]
    Parse(String),
    /// A required value was missing or malformed.
    #[error("invalid configuration field {field}: {reason}")]
    Invalid {
        /// Dotted configuration field path.
        field: String,
        /// Validation explanation.
        reason: String,
    },
    /// A named object was duplicated.
    #[error("duplicate {kind} id {id}")]
    Duplicate {
        /// Kind of object whose identity was repeated.
        kind: &'static str,
        /// Repeated identity.
        id: String,
    },
    /// A reference did not resolve to a configured object.
    #[error("unknown {kind} reference {id}")]
    UnknownReference {
        /// Kind of referenced object.
        kind: &'static str,
        /// Unresolved identity.
        id: String,
    },
    /// A route could not be made unambiguous.
    #[error("ambiguous route for node {node_id} and peer {peer}")]
    AmbiguousRoute {
        /// Receiver node identifier.
        node_id: u8,
        /// Conflicting peer address or wildcard marker.
        peer: String,
    },
    /// A route/channel contract conflicts with its link.
    #[error("route for node {node_id} conflicts with channel policy")]
    ChannelPolicyConflict {
        /// Receiver node identifier.
        node_id: u8,
    },
    /// A configured hardware family has no first-slice decoder.
    #[error("unsupported hardware {hardware} for sensor {sensor}")]
    UnsupportedHardware {
        /// Sensor identity.
        sensor: String,
        /// Hardware family that has no first-slice decoder.
        hardware: HardwareKind,
    },
    /// The candidate mode is intentionally not available in this slice.
    #[error("candidate mode {0:?} is unsupported; only \"disabled\" is accepted")]
    UnsupportedCandidateMode(String),
    /// Canonical CBOR encoding unexpectedly failed.
    #[error("canonical configuration encoding failed: {0}")]
    CanonicalEncoding(String),
}

impl ConfigError {
    fn id(field: &'static str, error: IdError) -> Self {
        Self::Invalid { field: field.to_owned(), reason: error.to_string() }
    }

    fn parse(error: toml::de::Error) -> Self {
        Self::Parse(error.to_string())
    }

    /// Converts a file read error.
    pub fn read(error: std::io::Error) -> Self {
        Self::Read(error)
    }
}

/// Parses and validates a complete TOML configuration.
pub fn parse_config(source: &str) -> Result<EffectiveConfig, ConfigError> {
    let raw: RawConfig = toml::from_str(source).map_err(ConfigError::parse)?;
    EffectiveConfig::from_raw(raw)
}

/// Reads, parses, and validates a configuration file.
#[expect(dead_code, reason = "consumed by work-package 2.2 application startup")]
pub fn load_config(path: impl AsRef<Path>) -> Result<EffectiveConfig, ConfigError> {
    let source = fs::read_to_string(path).map_err(ConfigError::Read)?;
    parse_config(&source)
}

/// A deserializable configuration input. Use [`parse_config`] for validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    deployment: Option<RawDeployment>,
    capture: Option<RawCapture>,
    session: Option<RawSession>,
    window: Option<RawWindow>,
    conditioning: Option<RawConditioning>,
    quality: Option<RawQuality>,
    baseline: Option<RawBaseline>,
    view: Option<RawView>,
    server: Option<RawServer>,
    performance: Option<RawPerformance>,
    candidate: Option<RawCandidate>,
    #[serde(default)]
    spaces: Vec<RawIdEntry>,
    #[serde(default)]
    transmitters: Vec<RawIdEntry>,
    #[serde(default)]
    sensors: Vec<RawSensor>,
    #[serde(default)]
    links: Vec<RawLink>,
    #[serde(default)]
    routes: Vec<RawRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeployment {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdEntry {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapture {
    bind: String,
    max_datagram_bytes: u32,
    socket_buffer_bytes: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSession {
    directory: String,
    max_manifest_bytes: u64,
    max_record_bytes: u64,
    max_session_duration_ns: u64,
    max_session_bytes: u64,
    retention_max_sessions: u32,
    flush_policy: RawFlushPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RawFlushPolicy {
    EveryRecord,
    Window,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindow {
    width_ns: u64,
    step_ns: u64,
    allowed_lateness_ns: u64,
    inactive_after_ns: u64,
    reorder_horizon: u32,
    probable_restart_after_ns: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConditioning {
    version: String,
    recipe: String,
    scale_numerator: u32,
    scale_denominator: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuality {
    minimum_frames: u32,
    minimum_coordinate_coverage: f64,
    maximum_gap_ratio: f64,
    maximum_receive_jitter_ns: u64,
    minimum_time_quality: RawTimeQuality,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RawTimeQuality {
    ReceiveOnly,
    ClockCorrected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBaseline {
    minimum_learning_windows: u32,
    minimum_valid_exposure_ns: u64,
    minimum_samples_per_coordinate: u32,
    minimum_exposure_per_coordinate_ns: u64,
    minimum_ready_coordinate_coverage: f64,
    variance_floor: f64,
    ew_time_constant_ns: u64,
    deviation_quantile: f64,
    rf_dynamics_quantile: f64,
    adaptation_gate: f64,
    stable_threshold: f64,
    changing_threshold: f64,
    stale_after_ns: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawView {
    recent_range_ns: u64,
    max_time_buckets: u32,
    max_signal_points: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    bind: String,
    recent_range_ns: u64,
    command_queue_capacity: u32,
    websocket_queue_capacity: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPerformance {
    max_rss_bytes: u64,
    max_cpu_threads: u32,
    snapshot_deadline_ns: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCandidate {
    #[serde(default = "default_candidate_mode")]
    mode: String,
}

fn default_candidate_mode() -> String {
    "disabled".to_owned()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RawHardwareKind {
    Esp32S3,
    Esp32C6,
    Intel5300,
}

impl From<RawHardwareKind> for HardwareKind {
    fn from(value: RawHardwareKind) -> Self {
        match value {
            RawHardwareKind::Esp32S3 => Self::Esp32S3,
            RawHardwareKind::Esp32C6 => Self::Esp32C6,
            RawHardwareKind::Intel5300 => Self::Intel5300,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSensor {
    id: String,
    hardware_kind: RawHardwareKind,
    node_id: u8,
    expected_peer_ip: String,
    firmware: String,
    adr018: RawAdr018,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdr018 {
    firmware_dialect: String,
    he_tagging: bool,
    csi_acquire: String,
    ltf_selection: String,
    ltf_merge: String,
    validity_dialect: String,
    #[serde(default)]
    multi_path: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLink {
    id: String,
    space: String,
    transmitter: String,
    receiver: String,
    source_contract: RawSourceContract,
    channel_policy: RawChannelPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSourceContract {
    provisioned: bool,
    fixed_source_mac_filter: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChannelPolicy {
    allowed: Vec<u16>,
    #[serde(default)]
    expected: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    peer: Option<String>,
    node_id: u8,
    link: String,
    peak_packets_per_second: u32,
    maximum_valid_datagram_bytes: u32,
    #[serde(default)]
    channel: Option<u16>,
}

/// Validated deployment identity.
#[derive(Clone, Debug, Serialize)]
pub struct Deployment {
    id: DeploymentId,
}

impl Deployment {
    /// Returns the deployment ID.
    #[must_use]
    pub const fn id(&self) -> &DeploymentId {
        &self.id
    }
}

/// Validated capture limits and bind address.
#[derive(Clone, Debug, Serialize)]
pub struct CaptureConfig {
    bind: SocketAddr,
    max_datagram_bytes: u32,
    socket_buffer_bytes: u32,
}

impl CaptureConfig {
    /// Returns the configured bind address.
    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }
    /// Returns the application datagram limit.
    #[must_use]
    pub const fn max_datagram_bytes(&self) -> u32 {
        self.max_datagram_bytes
    }
    /// Returns the receive-buffer size.
    #[must_use]
    pub const fn socket_buffer_bytes(&self) -> u32 {
        self.socket_buffer_bytes
    }
}

/// Validated session persistence limits.
#[derive(Clone, Debug, Serialize)]
pub struct SessionConfig {
    directory: PathBuf,
    max_manifest_bytes: u64,
    max_record_bytes: u64,
    max_session_duration_ns: u64,
    max_session_bytes: u64,
    retention_max_sessions: u32,
    flush_policy: FlushPolicy,
}

#[expect(dead_code, reason = "consumed by work-package 2.x session persistence")]
impl SessionConfig {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) const fn max_manifest_bytes(&self) -> u64 {
        self.max_manifest_bytes
    }

    pub(crate) const fn max_record_bytes(&self) -> u64 {
        self.max_record_bytes
    }

    pub(crate) const fn max_session_duration_ns(&self) -> u64 {
        self.max_session_duration_ns
    }

    pub(crate) const fn max_session_bytes(&self) -> u64 {
        self.max_session_bytes
    }

    pub(crate) const fn retention_max_sessions(&self) -> u32 {
        self.retention_max_sessions
    }

    pub(crate) const fn flush_policy(&self) -> FlushPolicy {
        self.flush_policy
    }
}

/// Session flush policy.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum FlushPolicy {
    /// Flush every record boundary.
    EveryRecord,
    /// Flush at the window boundary.
    Window,
}

/// Validated fixed-window contract.
#[derive(Clone, Debug, Serialize)]
pub struct WindowConfig {
    width_ns: u64,
    step_ns: u64,
    allowed_lateness_ns: u64,
    inactive_after_ns: u64,
    reorder_horizon: u32,
    probable_restart_after_ns: u64,
}

#[expect(dead_code, reason = "consumed by work-package 3.1 windowing")]
impl WindowConfig {
    pub(crate) const fn width_ns(&self) -> u64 {
        self.width_ns
    }

    pub(crate) const fn step_ns(&self) -> u64 {
        self.step_ns
    }

    pub(crate) const fn allowed_lateness_ns(&self) -> u64 {
        self.allowed_lateness_ns
    }

    pub(crate) const fn inactive_after_ns(&self) -> u64 {
        self.inactive_after_ns
    }

    pub(crate) const fn reorder_horizon(&self) -> u32 {
        self.reorder_horizon
    }

    pub(crate) const fn probable_restart_after_ns(&self) -> u64 {
        self.probable_restart_after_ns
    }
}

/// Validated native-coordinate conditioning recipe and rational scale.
#[derive(Clone, Debug, Serialize)]
pub struct ConditioningConfig {
    version: ConditioningVersion,
    recipe: ConditioningRecipe,
    scale_numerator: u32,
    scale_denominator: u32,
}

#[expect(dead_code, reason = "consumed by work-package 3.2 conditioning")]
impl ConditioningConfig {
    pub(crate) const fn version(&self) -> &ConditioningVersion {
        &self.version
    }

    pub(crate) const fn recipe(&self) -> ConditioningRecipe {
        self.recipe
    }

    pub(crate) const fn scale_numerator(&self) -> u32 {
        self.scale_numerator
    }

    pub(crate) const fn scale_denominator(&self) -> u32 {
        self.scale_denominator
    }
}

/// The one conditioning recipe implemented by the first slice.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ConditioningRecipe {
    /// `ln(1 + hypot(i, q) * scale)` per native coordinate.
    LogOnePlusHypot,
}

/// Validated quality conjunction thresholds.
#[derive(Clone, Debug, Serialize)]
pub struct QualityConfig {
    minimum_frames: u32,
    minimum_coordinate_coverage: f64,
    maximum_gap_ratio: f64,
    maximum_receive_jitter_ns: u64,
    minimum_time_quality: TimeQualityConfig,
}

#[expect(dead_code, reason = "consumed by work-package 3.3 quality evaluation")]
impl QualityConfig {
    pub(crate) const fn minimum_frames(&self) -> u32 {
        self.minimum_frames
    }

    pub(crate) const fn minimum_coordinate_coverage(&self) -> f64 {
        self.minimum_coordinate_coverage
    }

    pub(crate) const fn maximum_gap_ratio(&self) -> f64 {
        self.maximum_gap_ratio
    }

    pub(crate) const fn maximum_receive_jitter_ns(&self) -> u64 {
        self.maximum_receive_jitter_ns
    }

    pub(crate) const fn minimum_time_quality(&self) -> TimeQualityConfig {
        self.minimum_time_quality
    }
}

/// Quality capability required by the estimator.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum TimeQualityConfig {
    /// Host receive monotonic time is sufficient.
    ReceiveOnly,
    /// A verified corrected clock is required.
    ClockCorrected,
}

/// Validated baseline lifecycle and scoring thresholds.
#[derive(Clone, Debug, Serialize)]
pub struct BaselineConfig {
    minimum_learning_windows: u32,
    minimum_valid_exposure_ns: u64,
    minimum_samples_per_coordinate: u32,
    minimum_exposure_per_coordinate_ns: u64,
    minimum_ready_coordinate_coverage: f64,
    variance_floor: f64,
    ew_time_constant_ns: u64,
    deviation_quantile: f64,
    rf_dynamics_quantile: f64,
    adaptation_gate: f64,
    stable_threshold: f64,
    changing_threshold: f64,
    stale_after_ns: u64,
}

#[expect(dead_code, reason = "consumed by work-package 3.3 baseline evaluation")]
impl BaselineConfig {
    pub(crate) const fn minimum_learning_windows(&self) -> u32 {
        self.minimum_learning_windows
    }

    pub(crate) const fn minimum_valid_exposure_ns(&self) -> u64 {
        self.minimum_valid_exposure_ns
    }

    pub(crate) const fn minimum_samples_per_coordinate(&self) -> u32 {
        self.minimum_samples_per_coordinate
    }

    pub(crate) const fn minimum_exposure_per_coordinate_ns(&self) -> u64 {
        self.minimum_exposure_per_coordinate_ns
    }

    pub(crate) const fn minimum_ready_coordinate_coverage(&self) -> f64 {
        self.minimum_ready_coordinate_coverage
    }

    pub(crate) const fn variance_floor(&self) -> f64 {
        self.variance_floor
    }

    pub(crate) const fn ew_time_constant_ns(&self) -> u64 {
        self.ew_time_constant_ns
    }

    pub(crate) const fn deviation_quantile(&self) -> f64 {
        self.deviation_quantile
    }

    pub(crate) const fn rf_dynamics_quantile(&self) -> f64 {
        self.rf_dynamics_quantile
    }

    pub(crate) const fn adaptation_gate(&self) -> f64 {
        self.adaptation_gate
    }

    pub(crate) const fn stable_threshold(&self) -> f64 {
        self.stable_threshold
    }

    pub(crate) const fn changing_threshold(&self) -> f64 {
        self.changing_threshold
    }

    pub(crate) const fn stale_after_ns(&self) -> u64 {
        self.stale_after_ns
    }
}

/// Validated bounded view settings.
#[derive(Clone, Debug, Serialize)]
pub struct ViewConfig {
    recent_range_ns: u64,
    max_time_buckets: u32,
    max_signal_points: u64,
}

#[expect(dead_code, reason = "consumed by work-package 4.x view delivery")]
impl ViewConfig {
    pub(crate) const fn recent_range_ns(&self) -> u64 {
        self.recent_range_ns
    }

    pub(crate) const fn max_time_buckets(&self) -> u32 {
        self.max_time_buckets
    }

    pub(crate) const fn max_signal_points(&self) -> u64 {
        self.max_signal_points
    }
}

/// Validated HTTP/command delivery settings.
#[derive(Clone, Debug, Serialize)]
pub struct ServerConfig {
    bind: SocketAddr,
    recent_range_ns: u64,
    command_queue_capacity: u32,
    websocket_queue_capacity: u32,
}

#[expect(dead_code, reason = "consumed by work-package 4.x server delivery")]
impl ServerConfig {
    pub(crate) const fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub(crate) const fn recent_range_ns(&self) -> u64 {
        self.recent_range_ns
    }

    pub(crate) const fn command_queue_capacity(&self) -> u32 {
        self.command_queue_capacity
    }

    pub(crate) const fn websocket_queue_capacity(&self) -> u32 {
        self.websocket_queue_capacity
    }
}

/// Validated process resource limits.
#[derive(Clone, Debug, Serialize)]
pub struct PerformanceConfig {
    max_rss_bytes: u64,
    max_cpu_threads: u32,
    snapshot_deadline_ns: u64,
}

#[expect(dead_code, reason = "consumed by application performance work")]
impl PerformanceConfig {
    pub(crate) const fn max_rss_bytes(&self) -> u64 {
        self.max_rss_bytes
    }

    pub(crate) const fn max_cpu_threads(&self) -> u32 {
        self.max_cpu_threads
    }

    pub(crate) const fn snapshot_deadline_ns(&self) -> u64 {
        self.snapshot_deadline_ns
    }
}

/// Candidate settings; only disabled exists in this first slice.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum CandidateMode {
    /// No candidate learner or shadow path is enabled.
    Disabled,
}

/// A configured space.
#[derive(Clone, Debug, Serialize)]
pub struct SpaceConfig {
    id: SpaceId,
}

/// A configured transmitter.
#[derive(Clone, Debug, Serialize)]
pub struct TransmitterConfig {
    id: TransmitterId,
}

/// Explicit source contract for a physical link.
#[derive(Clone, Debug, Serialize)]
pub struct SourceContract {
    provisioned: bool,
    fixed_source_mac_filter: bool,
}

impl SourceContract {
    /// Reports whether the route has enough configured source evidence for inference.
    #[must_use]
    pub const fn inference_eligible(&self) -> bool {
        self.provisioned || self.fixed_source_mac_filter
    }
}

/// Channel policy for one physical link.
#[derive(Clone, Debug, Serialize)]
pub struct ChannelPolicy {
    allowed: Box<[u16]>,
    expected: Option<u16>,
}

#[expect(dead_code, reason = "consumed by the work-package 1.2 decoder")]
impl ChannelPolicy {
    pub(crate) fn allowed(&self) -> &[u16] {
        &self.allowed
    }
    pub(crate) const fn expected(&self) -> Option<u16> {
        self.expected
    }
}

/// A configured sensor and its wire capability declaration.
#[derive(Clone, Debug, Serialize)]
pub struct SensorConfig {
    id: SensorId,
    hardware_kind: HardwareKind,
    node_id: u8,
    expected_peer_ip: IpAddr,
    firmware: String,
    adr018: Adr018Capabilities,
}

#[expect(dead_code, reason = "consumed by the work-package 1.2 decoder")]
impl SensorConfig {
    pub(crate) const fn id(&self) -> &SensorId {
        &self.id
    }
    pub(crate) const fn hardware_kind(&self) -> HardwareKind {
        self.hardware_kind
    }
    pub(crate) const fn node_id(&self) -> u8 {
        self.node_id
    }
    pub(crate) const fn expected_peer_ip(&self) -> IpAddr {
        self.expected_peer_ip
    }
    pub(crate) fn firmware(&self) -> &str {
        &self.firmware
    }
    pub(crate) const fn adr018(&self) -> &Adr018Capabilities {
        &self.adr018
    }
}

/// Explicit ADR-018 capability declaration.
#[derive(Clone, Debug, Serialize)]
pub struct Adr018Capabilities {
    firmware_dialect: FirmwareDialect,
    he_tagging: bool,
    csi_acquire: AcquisitionMode,
    ltf_selection: LtfSelection,
    ltf_merge: LtfMerge,
    validity_dialect: ValidityDialect,
    multi_path: bool,
}

#[expect(dead_code, reason = "consumed by the work-package 1.2 decoder")]
impl Adr018Capabilities {
    pub(crate) const fn firmware_dialect(&self) -> FirmwareDialect {
        self.firmware_dialect
    }
    pub(crate) const fn he_tagging(&self) -> bool {
        self.he_tagging
    }
    pub(crate) const fn csi_acquire(&self) -> AcquisitionMode {
        self.csi_acquire
    }
    pub(crate) const fn ltf_selection(&self) -> LtfSelection {
        self.ltf_selection
    }
    pub(crate) const fn ltf_merge(&self) -> LtfMerge {
        self.ltf_merge
    }
    pub(crate) const fn validity_dialect(&self) -> ValidityDialect {
        self.validity_dialect
    }
    pub(crate) const fn multi_path(&self) -> bool {
        self.multi_path
    }
}

/// Supported ADR-018 firmware dialects.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum FirmwareDialect {
    /// ESP-IDF legacy/HT CSI dialect.
    EspIdf,
    /// ESP-IDF HE/C6 dialect.
    EspIdfHe,
}

/// A physical transmitter-to-receiver link.
#[derive(Clone, Debug, Serialize)]
pub struct LinkConfig {
    id: RadioLinkId,
    space: SpaceId,
    transmitter: TransmitterId,
    receiver: SensorId,
    source_contract: SourceContract,
    channel_policy: ChannelPolicy,
}

#[expect(dead_code, reason = "consumed by the work-package 1.2 decoder")]
impl LinkConfig {
    pub(crate) const fn id(&self) -> &RadioLinkId {
        &self.id
    }
    pub(crate) const fn space(&self) -> &SpaceId {
        &self.space
    }
    pub(crate) const fn transmitter(&self) -> &TransmitterId {
        &self.transmitter
    }
    pub(crate) const fn receiver(&self) -> &SensorId {
        &self.receiver
    }
    pub(crate) const fn source_contract(&self) -> &SourceContract {
        &self.source_contract
    }
    pub(crate) const fn channel_policy(&self) -> &ChannelPolicy {
        &self.channel_policy
    }
    /// Reports whether the configured source contract can be used for inference.
    #[must_use]
    pub fn inference_eligible(&self) -> bool {
        self.source_contract.inference_eligible()
    }
}

/// A route binding node/peer wire identity to one link.
#[derive(Clone, Debug, Serialize)]
pub struct RouteConfig {
    peer: Option<IpAddr>,
    node_id: u8,
    link: RadioLinkId,
    peak_packets_per_second: u32,
    maximum_valid_datagram_bytes: u32,
    channel: Option<u16>,
}

#[expect(dead_code, reason = "consumed by the work-package 1.2 decoder")]
impl RouteConfig {
    pub(crate) const fn peer(&self) -> Option<IpAddr> {
        self.peer
    }
    pub(crate) const fn node_id(&self) -> u8 {
        self.node_id
    }
    pub(crate) const fn link(&self) -> &RadioLinkId {
        &self.link
    }
    pub(crate) const fn peak_packets_per_second(&self) -> u32 {
        self.peak_packets_per_second
    }
    pub(crate) const fn maximum_valid_datagram_bytes(&self) -> u32 {
        self.maximum_valid_datagram_bytes
    }
    pub(crate) const fn channel(&self) -> Option<u16> {
        self.channel
    }
}

/// A route resolution result with no socket or I/O ownership.
#[derive(Clone, Debug)]
pub struct ResolvedRoute<'a> {
    /// Sensor selected by the route's link receiver.
    pub sensor: &'a SensorConfig,
    /// Physical link selected by the route.
    pub link: &'a LinkConfig,
    /// Exact route entry selected by node and peer.
    pub route: &'a RouteConfig,
}

/// Errors returned by runtime route lookup.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteError {
    /// No configured route matched node and peer.
    #[error("unknown route for node {node_id} and peer {peer}")]
    Unknown {
        /// Receiver node identifier.
        node_id: u8,
        /// Incoming peer address.
        peer: IpAddr,
    },
    /// More than one route matched.
    #[error("ambiguous route for node {node_id} and peer {peer}")]
    Ambiguous {
        /// Receiver node identifier.
        node_id: u8,
        /// Incoming peer address.
        peer: IpAddr,
    },
}

/// Static deployment registry used by the decoder and later timeline.
#[derive(Clone, Debug, Serialize)]
pub struct Registry {
    spaces: BTreeMap<SpaceId, SpaceConfig>,
    transmitters: BTreeMap<TransmitterId, TransmitterConfig>,
    sensors: BTreeMap<SensorId, SensorConfig>,
    links: BTreeMap<RadioLinkId, LinkConfig>,
    routes: Vec<RouteConfig>,
}

impl Registry {
    /// Resolves an incoming `(peer, node_id)` without using source ports.
    pub fn resolve_route(
        &self,
        peer: IpAddr,
        node_id: u8,
    ) -> Result<ResolvedRoute<'_>, RouteError> {
        let exact: Vec<&RouteConfig> = self
            .routes
            .iter()
            .filter(|route| route.node_id == node_id && route.peer == Some(peer))
            .collect();
        let wildcard: Vec<&RouteConfig> = self
            .routes
            .iter()
            .filter(|route| {
                if route.node_id != node_id || route.peer.is_some() {
                    return false;
                }
                self.links
                    .get(&route.link)
                    .and_then(|link| self.sensors.get(&link.receiver))
                    .is_some_and(|sensor| sensor.expected_peer_ip == peer)
            })
            .collect();
        let route = if exact.len() == 1 {
            exact[0]
        } else if exact.len() > 1 {
            return Err(RouteError::Ambiguous { node_id, peer });
        } else if wildcard.len() == 1 {
            wildcard[0]
        } else if wildcard.len() > 1 {
            return Err(RouteError::Ambiguous { node_id, peer });
        } else {
            return Err(RouteError::Unknown { node_id, peer });
        };
        let link = self.links.get(&route.link).ok_or(RouteError::Unknown { node_id, peer })?;
        let sensor =
            self.sensors.get(&link.receiver).ok_or(RouteError::Unknown { node_id, peer })?;
        Ok(ResolvedRoute { sensor, link, route })
    }

    /// Returns all configured sensors.
    #[must_use]
    pub const fn sensors(&self) -> &BTreeMap<SensorId, SensorConfig> {
        &self.sensors
    }
    /// Returns all configured links.
    #[must_use]
    pub const fn links(&self) -> &BTreeMap<RadioLinkId, LinkConfig> {
        &self.links
    }
    /// Returns all configured routes in file order.
    #[must_use]
    pub fn routes(&self) -> &[RouteConfig] {
        &self.routes
    }
}

/// Complete validated, immutable configuration snapshot.
#[derive(Clone, Debug, Serialize)]
pub struct EffectiveConfig {
    deployment: Deployment,
    capture: CaptureConfig,
    session: SessionConfig,
    window: WindowConfig,
    conditioning: ConditioningConfig,
    quality: QualityConfig,
    baseline: BaselineConfig,
    view: ViewConfig,
    server: ServerConfig,
    performance: PerformanceConfig,
    candidate: CandidateMode,
    registry: Registry,
    #[serde(skip)]
    digest: [u8; 32],
}

impl EffectiveConfig {
    /// Validates raw configuration and computes its canonical digest.
    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let RawDeployment { id } = raw.deployment.ok_or_else(|| missing("deployment.id"))?;
        let deployment = Deployment {
            id: DeploymentId::new(id).map_err(|error| ConfigError::id("deployment.id", error))?,
        };
        let capture = build_capture(raw.capture.ok_or_else(|| missing("capture"))?)?;
        let session = build_session(raw.session.ok_or_else(|| missing("session"))?)?;
        let window = build_window(raw.window.ok_or_else(|| missing("window"))?)?;
        let conditioning =
            build_conditioning(raw.conditioning.ok_or_else(|| missing("conditioning"))?)?;
        let quality = build_quality(raw.quality.ok_or_else(|| missing("quality"))?)?;
        let baseline = build_baseline(raw.baseline.ok_or_else(|| missing("baseline"))?)?;
        let view = build_view(raw.view.ok_or_else(|| missing("view"))?)?;
        let server = build_server(raw.server.ok_or_else(|| missing("server"))?)?;
        let performance = build_performance(
            raw.performance.ok_or_else(|| missing("performance"))?,
            window.step_ns,
        )?;
        let candidate = build_candidate(raw.candidate)?;
        let registry = build_registry(
            raw.spaces,
            raw.transmitters,
            raw.sensors,
            raw.links,
            raw.routes,
            capture.max_datagram_bytes,
        )?;
        let mut config = Self {
            deployment,
            capture,
            session,
            window,
            conditioning,
            quality,
            baseline,
            view,
            server,
            performance,
            candidate,
            registry,
            digest: [0; 32],
        };
        let bytes = config.canonical_bytes()?;
        config.digest = Sha256::digest(bytes).into();
        Ok(config)
    }

    /// Returns deployment settings.
    #[must_use]
    pub const fn deployment(&self) -> &Deployment {
        &self.deployment
    }
    /// Returns capture settings.
    #[must_use]
    pub const fn capture(&self) -> &CaptureConfig {
        &self.capture
    }
    /// Returns session settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 2.x session persistence")]
    pub(crate) const fn session(&self) -> &SessionConfig {
        &self.session
    }
    /// Returns window settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 3.1 windowing")]
    pub(crate) const fn window(&self) -> &WindowConfig {
        &self.window
    }
    /// Returns the conditioning recipe and declared rational scale.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 3.2 conditioning")]
    pub(crate) const fn conditioning(&self) -> &ConditioningConfig {
        &self.conditioning
    }
    /// Returns quality settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 3.3 quality evaluation")]
    pub(crate) const fn quality(&self) -> &QualityConfig {
        &self.quality
    }
    /// Returns baseline settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 3.3 baseline evaluation")]
    pub(crate) const fn baseline(&self) -> &BaselineConfig {
        &self.baseline
    }
    /// Returns view settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 4.x view delivery")]
    pub(crate) const fn view(&self) -> &ViewConfig {
        &self.view
    }
    /// Returns server settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by work-package 4.x server delivery")]
    pub(crate) const fn server(&self) -> &ServerConfig {
        &self.server
    }
    /// Returns performance settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by application performance work")]
    pub(crate) const fn performance(&self) -> &PerformanceConfig {
        &self.performance
    }
    /// Returns candidate mode.
    #[must_use]
    #[expect(dead_code, reason = "consumed by the candidate work package")]
    pub(crate) const fn candidate(&self) -> CandidateMode {
        self.candidate
    }
    /// Returns the validated topology registry.
    #[must_use]
    pub const fn registry(&self) -> &Registry {
        &self.registry
    }
    /// Returns the SHA-256 of canonical effective configuration bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Returns canonical CBOR bytes used by [`Self::digest`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        let mut bytes = Vec::new();
        into_writer(self, &mut bytes)
            .map_err(|error| ConfigError::CanonicalEncoding(error.to_string()))?;
        Ok(bytes)
    }
}

fn missing(field: &'static str) -> ConfigError {
    ConfigError::Invalid { field: field.to_owned(), reason: "missing required value".to_owned() }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid { field: field.to_owned(), reason: reason.into() }
}

fn parse_socket(field: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse::<SocketAddr>().map_err(|error| invalid(field, error.to_string()))
}

fn build_capture(raw: RawCapture) -> Result<CaptureConfig, ConfigError> {
    if raw.max_datagram_bytes == 0 || raw.max_datagram_bytes > 65_535 {
        return Err(invalid("capture.max_datagram_bytes", "must be in 1..=65535"));
    }
    if raw.socket_buffer_bytes < raw.max_datagram_bytes {
        return Err(invalid("capture.socket_buffer_bytes", "must cover max_datagram_bytes"));
    }
    Ok(CaptureConfig {
        bind: parse_socket("capture.bind", &raw.bind)?,
        max_datagram_bytes: raw.max_datagram_bytes,
        socket_buffer_bytes: raw.socket_buffer_bytes,
    })
}

fn build_session(raw: RawSession) -> Result<SessionConfig, ConfigError> {
    if raw.directory.trim().is_empty()
        || raw.max_manifest_bytes == 0
        || raw.max_record_bytes == 0
        || raw.max_session_bytes == 0
        || raw.max_session_duration_ns == 0
        || raw.retention_max_sessions == 0
    {
        return Err(invalid("session", "directory and all limits must be valid and positive"));
    }
    if raw.max_record_bytes > raw.max_session_bytes
        || raw.max_manifest_bytes > raw.max_session_bytes
    {
        return Err(invalid("session", "manifest/record limits exceed max_session_bytes"));
    }
    let flush_policy = match raw.flush_policy {
        RawFlushPolicy::EveryRecord => FlushPolicy::EveryRecord,
        RawFlushPolicy::Window => FlushPolicy::Window,
    };
    Ok(SessionConfig {
        directory: PathBuf::from(raw.directory),
        max_manifest_bytes: raw.max_manifest_bytes,
        max_record_bytes: raw.max_record_bytes,
        max_session_duration_ns: raw.max_session_duration_ns,
        max_session_bytes: raw.max_session_bytes,
        retention_max_sessions: raw.retention_max_sessions,
        flush_policy,
    })
}

fn build_window(raw: RawWindow) -> Result<WindowConfig, ConfigError> {
    if raw.width_ns == 0
        || raw.step_ns == 0
        || raw.step_ns < raw.width_ns
        || raw.inactive_after_ns == 0
        || raw.probable_restart_after_ns == 0
    {
        return Err(invalid(
            "window",
            "width/step must be positive and non-overlapping; durations must be positive",
        ));
    }
    Ok(WindowConfig {
        width_ns: raw.width_ns,
        step_ns: raw.step_ns,
        allowed_lateness_ns: raw.allowed_lateness_ns,
        inactive_after_ns: raw.inactive_after_ns,
        reorder_horizon: raw.reorder_horizon,
        probable_restart_after_ns: raw.probable_restart_after_ns,
    })
}

fn build_conditioning(raw: RawConditioning) -> Result<ConditioningConfig, ConfigError> {
    if raw.version.trim().is_empty() || raw.recipe.trim().is_empty() {
        return Err(invalid("conditioning", "version and recipe must not be empty"));
    }
    if raw.scale_numerator == 0 || raw.scale_denominator == 0 {
        return Err(invalid("conditioning", "scale numerator and denominator must be positive"));
    }
    let divisor = gcd(raw.scale_numerator, raw.scale_denominator);
    let version = ConditioningVersion::new(raw.version)
        .map_err(|error| ConfigError::id("conditioning.version", error))?;
    let recipe = match raw.recipe.as_str() {
        "log1p-hypot" => ConditioningRecipe::LogOnePlusHypot,
        other => {
            return Err(invalid("conditioning.recipe", format!("unsupported recipe {other:?}")));
        }
    };
    Ok(ConditioningConfig {
        version,
        recipe,
        scale_numerator: raw.scale_numerator / divisor,
        scale_denominator: raw.scale_denominator / divisor,
    })
}

const fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn build_quality(raw: RawQuality) -> Result<QualityConfig, ConfigError> {
    if raw.minimum_frames == 0 {
        return Err(invalid("quality.minimum_frames", "must be positive"));
    }
    validate_fraction("quality.minimum_coordinate_coverage", raw.minimum_coordinate_coverage)?;
    validate_fraction("quality.maximum_gap_ratio", raw.maximum_gap_ratio)?;
    let minimum_time_quality = match raw.minimum_time_quality {
        RawTimeQuality::ReceiveOnly => TimeQualityConfig::ReceiveOnly,
        RawTimeQuality::ClockCorrected => TimeQualityConfig::ClockCorrected,
    };
    Ok(QualityConfig {
        minimum_frames: raw.minimum_frames,
        minimum_coordinate_coverage: raw.minimum_coordinate_coverage,
        maximum_gap_ratio: raw.maximum_gap_ratio,
        maximum_receive_jitter_ns: raw.maximum_receive_jitter_ns,
        minimum_time_quality,
    })
}

fn build_baseline(raw: RawBaseline) -> Result<BaselineConfig, ConfigError> {
    if raw.minimum_learning_windows == 0
        || raw.minimum_valid_exposure_ns == 0
        || raw.minimum_samples_per_coordinate < 2
        || raw.minimum_exposure_per_coordinate_ns == 0
        || raw.variance_floor <= 0.0
        || !raw.variance_floor.is_finite()
        || raw.ew_time_constant_ns == 0
        || raw.stale_after_ns == 0
    {
        return Err(invalid(
            "baseline",
            "counts, exposure, variance, time constant and age must be valid",
        ));
    }
    validate_fraction(
        "baseline.minimum_ready_coordinate_coverage",
        raw.minimum_ready_coordinate_coverage,
    )?;
    validate_quantile("baseline.deviation_quantile", raw.deviation_quantile)?;
    validate_quantile("baseline.rf_dynamics_quantile", raw.rf_dynamics_quantile)?;
    if !raw.stable_threshold.is_finite()
        || !raw.changing_threshold.is_finite()
        || raw.stable_threshold < 0.0
        || raw.stable_threshold >= raw.changing_threshold
    {
        return Err(invalid(
            "baseline",
            "stable/change thresholds must be finite, non-negative and ordered",
        ));
    }
    if !raw.adaptation_gate.is_finite()
        || raw.adaptation_gate < 0.0
        || raw.adaptation_gate > raw.stable_threshold
    {
        return Err(invalid(
            "baseline.adaptation_gate",
            "must be finite, non-negative and no greater than stable_threshold",
        ));
    }
    Ok(BaselineConfig {
        minimum_learning_windows: raw.minimum_learning_windows,
        minimum_valid_exposure_ns: raw.minimum_valid_exposure_ns,
        minimum_samples_per_coordinate: raw.minimum_samples_per_coordinate,
        minimum_exposure_per_coordinate_ns: raw.minimum_exposure_per_coordinate_ns,
        minimum_ready_coordinate_coverage: raw.minimum_ready_coordinate_coverage,
        variance_floor: raw.variance_floor,
        ew_time_constant_ns: raw.ew_time_constant_ns,
        deviation_quantile: raw.deviation_quantile,
        rf_dynamics_quantile: raw.rf_dynamics_quantile,
        adaptation_gate: raw.adaptation_gate,
        stable_threshold: raw.stable_threshold,
        changing_threshold: raw.changing_threshold,
        stale_after_ns: raw.stale_after_ns,
    })
}

fn build_view(raw: RawView) -> Result<ViewConfig, ConfigError> {
    if raw.recent_range_ns == 0 || raw.max_time_buckets == 0 || raw.max_signal_points == 0 {
        return Err(invalid("view", "range and point limits must be positive"));
    }
    Ok(ViewConfig {
        recent_range_ns: raw.recent_range_ns,
        max_time_buckets: raw.max_time_buckets,
        max_signal_points: raw.max_signal_points,
    })
}

fn build_server(raw: RawServer) -> Result<ServerConfig, ConfigError> {
    if raw.recent_range_ns == 0
        || raw.command_queue_capacity == 0
        || raw.websocket_queue_capacity == 0
    {
        return Err(invalid("server", "range and queue capacities must be positive"));
    }
    Ok(ServerConfig {
        bind: parse_socket("server.bind", &raw.bind)?,
        recent_range_ns: raw.recent_range_ns,
        command_queue_capacity: raw.command_queue_capacity,
        websocket_queue_capacity: raw.websocket_queue_capacity,
    })
}

fn build_performance(raw: RawPerformance, step_ns: u64) -> Result<PerformanceConfig, ConfigError> {
    if raw.max_rss_bytes == 0 || raw.max_cpu_threads == 0 || raw.snapshot_deadline_ns == 0 {
        return Err(invalid("performance", "resource limits must be positive"));
    }
    let twice = raw
        .snapshot_deadline_ns
        .checked_mul(2)
        .ok_or_else(|| invalid("performance.snapshot_deadline_ns", "overflow"))?;
    if twice > step_ns {
        return Err(invalid("performance.snapshot_deadline_ns", "must be <= half window.step_ns"));
    }
    Ok(PerformanceConfig {
        max_rss_bytes: raw.max_rss_bytes,
        max_cpu_threads: raw.max_cpu_threads,
        snapshot_deadline_ns: raw.snapshot_deadline_ns,
    })
}

fn build_candidate(raw: Option<RawCandidate>) -> Result<CandidateMode, ConfigError> {
    let mode = raw.map_or_else(default_candidate_mode, |value| value.mode);
    if mode != "disabled" {
        return Err(ConfigError::UnsupportedCandidateMode(mode));
    }
    Ok(CandidateMode::Disabled)
}

fn validate_fraction(field: &'static str, value: f64) -> Result<(), ConfigError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(invalid(field, "must be finite and within 0..=1"));
    }
    Ok(())
}

fn validate_quantile(field: &'static str, value: f64) -> Result<(), ConfigError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) || value == 0.0 {
        return Err(invalid(field, "must be finite and within (0, 1]"));
    }
    Ok(())
}

fn build_registry(
    spaces: Vec<RawIdEntry>,
    transmitters: Vec<RawIdEntry>,
    sensors: Vec<RawSensor>,
    links: Vec<RawLink>,
    routes: Vec<RawRoute>,
    max_datagram_bytes: u32,
) -> Result<Registry, ConfigError> {
    if spaces.is_empty()
        || transmitters.is_empty()
        || sensors.is_empty()
        || links.is_empty()
        || routes.is_empty()
    {
        return Err(invalid(
            "registry",
            "spaces, transmitters, sensors, links and routes are required",
        ));
    }
    let spaces = build_spaces(spaces)?;
    let transmitters = build_transmitters(transmitters)?;
    let sensors = build_sensors(sensors)?;
    let links = build_links(links, &spaces, &transmitters, &sensors)?;
    let routes = build_routes(routes, &links, &sensors, max_datagram_bytes)?;
    Ok(Registry { spaces, transmitters, sensors, links, routes })
}

fn build_spaces(values: Vec<RawIdEntry>) -> Result<BTreeMap<SpaceId, SpaceConfig>, ConfigError> {
    let mut output = BTreeMap::new();
    for entry in values {
        let id = SpaceId::new(entry.id).map_err(|error| ConfigError::id("spaces[].id", error))?;
        if output.insert(id.clone(), SpaceConfig { id: id.clone() }).is_some() {
            return Err(ConfigError::Duplicate { kind: "space", id: id.to_string() });
        }
    }
    Ok(output)
}

fn build_transmitters(
    values: Vec<RawIdEntry>,
) -> Result<BTreeMap<TransmitterId, TransmitterConfig>, ConfigError> {
    let mut output = BTreeMap::new();
    for entry in values {
        let id = TransmitterId::new(entry.id)
            .map_err(|error| ConfigError::id("transmitters[].id", error))?;
        if output.insert(id.clone(), TransmitterConfig { id: id.clone() }).is_some() {
            return Err(ConfigError::Duplicate { kind: "transmitter", id: id.to_string() });
        }
    }
    Ok(output)
}

fn build_sensors(values: Vec<RawSensor>) -> Result<BTreeMap<SensorId, SensorConfig>, ConfigError> {
    let mut output = BTreeMap::new();
    for raw in values {
        let id = SensorId::new(raw.id).map_err(|error| ConfigError::id("sensors[].id", error))?;
        let hardware_kind = raw.hardware_kind.into();
        if hardware_kind == HardwareKind::Intel5300 {
            return Err(ConfigError::UnsupportedHardware {
                sensor: id.to_string(),
                hardware: hardware_kind,
            });
        }
        if raw.firmware.trim().is_empty() {
            return Err(invalid("sensors[].firmware", "must not be empty"));
        }
        let expected_peer_ip = raw
            .expected_peer_ip
            .parse::<IpAddr>()
            .map_err(|error| invalid("sensors[].expected_peer_ip", error.to_string()))?;
        let firmware_dialect = parse_firmware_dialect(&raw.adr018.firmware_dialect)?;
        let csi_acquire = parse_acquisition_mode(&raw.adr018.csi_acquire)?;
        let ltf_selection = parse_ltf_selection(&raw.adr018.ltf_selection)?;
        let ltf_merge = parse_ltf_merge(&raw.adr018.ltf_merge)?;
        let validity_dialect = parse_validity_dialect(&raw.adr018.validity_dialect)?;
        let sensor = SensorConfig {
            id: id.clone(),
            hardware_kind,
            node_id: raw.node_id,
            expected_peer_ip,
            firmware: raw.firmware,
            adr018: Adr018Capabilities {
                firmware_dialect,
                he_tagging: raw.adr018.he_tagging,
                csi_acquire,
                ltf_selection,
                ltf_merge,
                validity_dialect,
                multi_path: raw.adr018.multi_path,
            },
        };
        if output.insert(id.clone(), sensor).is_some() {
            return Err(ConfigError::Duplicate { kind: "sensor", id: id.to_string() });
        }
    }
    Ok(output)
}

fn parse_firmware_dialect(value: &str) -> Result<FirmwareDialect, ConfigError> {
    match value {
        "esp-idf" => Ok(FirmwareDialect::EspIdf),
        "esp-idf-he" => Ok(FirmwareDialect::EspIdfHe),
        other => Err(invalid(
            "sensors[].adr018.firmware_dialect",
            format!("unsupported value {other:?}"),
        )),
    }
}

fn parse_acquisition_mode(value: &str) -> Result<AcquisitionMode, ConfigError> {
    match value {
        "wifi-csi" => Ok(AcquisitionMode::WifiCsi),
        other => {
            Err(invalid("sensors[].adr018.csi_acquire", format!("unsupported value {other:?}")))
        }
    }
}

fn parse_ltf_selection(value: &str) -> Result<LtfSelection, ConfigError> {
    match value {
        "legacy" => Ok(LtfSelection::Legacy),
        "ht" => Ok(LtfSelection::Ht),
        "he" => Ok(LtfSelection::He),
        other => {
            Err(invalid("sensors[].adr018.ltf_selection", format!("unsupported value {other:?}")))
        }
    }
}

fn parse_ltf_merge(value: &str) -> Result<LtfMerge, ConfigError> {
    match value {
        "none" => Ok(LtfMerge::None),
        "firmware-defined" => Ok(LtfMerge::FirmwareDefined),
        other => Err(invalid("sensors[].adr018.ltf_merge", format!("unsupported value {other:?}"))),
    }
}

fn parse_validity_dialect(value: &str) -> Result<ValidityDialect, ConfigError> {
    match value {
        "explicit-flag" => Ok(ValidityDialect::ExplicitFlag),
        "first-word-invalid" => Ok(ValidityDialect::FirstWordInvalid),
        "missing-frame-validity" => Ok(ValidityDialect::MissingFrameValidity),
        other => Err(invalid(
            "sensors[].adr018.validity_dialect",
            format!("unsupported value {other:?}"),
        )),
    }
}

fn build_links(
    values: Vec<RawLink>,
    spaces: &BTreeMap<SpaceId, SpaceConfig>,
    transmitters: &BTreeMap<TransmitterId, TransmitterConfig>,
    sensors: &BTreeMap<SensorId, SensorConfig>,
) -> Result<BTreeMap<RadioLinkId, LinkConfig>, ConfigError> {
    let mut output = BTreeMap::new();
    for raw in values {
        let id = RadioLinkId::new(raw.id).map_err(|error| ConfigError::id("links[].id", error))?;
        let space =
            SpaceId::new(raw.space).map_err(|error| ConfigError::id("links[].space", error))?;
        let transmitter = TransmitterId::new(raw.transmitter)
            .map_err(|error| ConfigError::id("links[].transmitter", error))?;
        let receiver = SensorId::new(raw.receiver)
            .map_err(|error| ConfigError::id("links[].receiver", error))?;
        if !spaces.contains_key(&space) {
            return Err(ConfigError::UnknownReference { kind: "space", id: space.to_string() });
        }
        if !transmitters.contains_key(&transmitter) {
            return Err(ConfigError::UnknownReference {
                kind: "transmitter",
                id: transmitter.to_string(),
            });
        }
        if !sensors.contains_key(&receiver) {
            return Err(ConfigError::UnknownReference { kind: "sensor", id: receiver.to_string() });
        }
        let channel_policy = build_channel_policy(raw.channel_policy)?;
        let link = LinkConfig {
            id: id.clone(),
            space,
            transmitter,
            receiver,
            source_contract: SourceContract {
                provisioned: raw.source_contract.provisioned,
                fixed_source_mac_filter: raw.source_contract.fixed_source_mac_filter,
            },
            channel_policy,
        };
        if output.insert(id.clone(), link).is_some() {
            return Err(ConfigError::Duplicate { kind: "link", id: id.to_string() });
        }
    }
    Ok(output)
}

fn build_channel_policy(raw: RawChannelPolicy) -> Result<ChannelPolicy, ConfigError> {
    let RawChannelPolicy { allowed, expected } = raw;
    if allowed.is_empty() || allowed.contains(&0) {
        return Err(invalid(
            "links[].channel_policy",
            "allowed channels must be non-empty and positive",
        ));
    }
    let set: BTreeSet<u16> = allowed.iter().copied().collect();
    if set.len() != allowed.len() {
        return Err(invalid("links[].channel_policy", "allowed channels must be unique"));
    }
    if expected.is_some_and(|channel| !set.contains(&channel)) {
        return Err(invalid("links[].channel_policy.expected", "must be one of allowed channels"));
    }
    Ok(ChannelPolicy { allowed: allowed.into_boxed_slice(), expected })
}

fn build_routes(
    values: Vec<RawRoute>,
    links: &BTreeMap<RadioLinkId, LinkConfig>,
    sensors: &BTreeMap<SensorId, SensorConfig>,
    max_datagram_bytes: u32,
) -> Result<Vec<RouteConfig>, ConfigError> {
    let mut output = Vec::with_capacity(values.len());
    let mut identities = BTreeSet::new();
    for raw in values {
        if raw.peak_packets_per_second == 0
            || raw.maximum_valid_datagram_bytes == 0
            || raw.maximum_valid_datagram_bytes > max_datagram_bytes
        {
            return Err(invalid(
                "routes[]",
                "rate/maximum_valid_datagram_bytes exceed capture limits",
            ));
        }
        let link =
            RadioLinkId::new(raw.link).map_err(|error| ConfigError::id("routes[].link", error))?;
        let link_config = links
            .get(&link)
            .ok_or_else(|| ConfigError::UnknownReference { kind: "link", id: link.to_string() })?;
        let peer = raw
            .peer
            .as_deref()
            .map(|value| {
                value.parse::<IpAddr>().map_err(|error| invalid("routes[].peer", error.to_string()))
            })
            .transpose()?;
        if !identities.insert((raw.node_id, peer)) {
            return Err(ConfigError::AmbiguousRoute {
                node_id: raw.node_id,
                peer: peer.map_or_else(|| "*".to_owned(), |value| value.to_string()),
            });
        }
        if let Some(channel) = raw.channel
            && (!link_config.channel_policy.allowed.contains(&channel)
                || link_config.channel_policy.expected.is_some_and(|expected| expected != channel))
        {
            return Err(ConfigError::ChannelPolicyConflict { node_id: raw.node_id });
        }
        let receiver = sensors.get(&link_config.receiver).ok_or_else(|| {
            ConfigError::UnknownReference { kind: "sensor", id: link_config.receiver.to_string() }
        })?;
        if peer.is_some_and(|value| value != receiver.expected_peer_ip) {
            return Err(invalid("routes[].peer", "does not match receiver expected_peer_ip"));
        }
        if receiver.node_id != raw.node_id {
            return Err(invalid("routes[].node_id", "does not match receiver node_id"));
        }
        output.push(RouteConfig {
            peer,
            node_id: raw.node_id,
            link,
            peak_packets_per_second: raw.peak_packets_per_second,
            maximum_valid_datagram_bytes: raw.maximum_valid_datagram_bytes,
            channel: raw.channel,
        });
    }
    let mut wildcard_nodes = BTreeSet::new();
    let mut exact_nodes = BTreeSet::new();
    for route in &output {
        if let Some(peer) = route.peer {
            exact_nodes.insert((route.node_id, peer));
        } else if !wildcard_nodes.insert(route.node_id) {
            return Err(ConfigError::AmbiguousRoute {
                node_id: route.node_id,
                peer: "*".to_owned(),
            });
        }
    }
    for route in &output {
        if route.peer.is_none() && exact_nodes.iter().any(|(node_id, _)| *node_id == route.node_id)
        {
            return Err(ConfigError::AmbiguousRoute {
                node_id: route.node_id,
                peer: "*".to_owned(),
            });
        }
    }
    Ok(output)
}
