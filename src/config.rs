//! TOML configuration, topology registry, and deterministic effective settings.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use ciborium::ser::into_writer;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::domain::route::{AdmissionLimits, HeaderRoute};
use crate::domain::{
    ConditioningVersion, DeploymentId, DeviceId, HardwareKind, IdError, KeyEpoch, RadioLinkId,
    SensorId, SpaceId, TransmitterId,
};

/// The largest raw CSI buffer admitted by the ESP32-S3 native-frame profile.
const MAX_S3_RAW_CSI_BYTES: u16 = 612;
/// The largest authenticated cleartext body admitted by the native-frame profile.
const MAX_S3_PLAINTEXT_BYTES: u16 = 705;
/// The fixed native-frame header and authentication tag overhead.
const NATIVE_FRAME_OVERHEAD_BYTES: u16 = 32 + 16;

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
    /// A route identity was repeated or could not be made exact.
    #[error("ambiguous route for peer {peer}, device {device_id}, and key epoch {key_epoch}")]
    AmbiguousRoute {
        /// Peer address in the conflicting route.
        peer: String,
        /// Device identity in the conflicting route.
        device_id: u64,
        /// Key epoch in the conflicting route.
        key_epoch: u16,
    },
    /// A route's radio policy conflicts with the referenced link.
    #[error("route for peer {peer} conflicts with link radio policy")]
    ChannelPolicyConflict {
        /// Peer address in the conflicting route.
        peer: String,
    },
    /// A configured hardware family has no first-slice decoder.
    #[error("unsupported hardware {hardware} for sensor {sensor}")]
    UnsupportedHardware {
        /// Sensor identity.
        sensor: String,
        /// Hardware family that has no first-slice decoder.
        hardware: HardwareKind,
    },
    /// A configured digest was not exactly 32 bytes of hexadecimal data.
    #[error("invalid {field}: expected exactly 64 hexadecimal characters")]
    InvalidDigest {
        /// Configuration field containing the digest.
        field: &'static str,
    },
    /// A configured MAC address was not exactly six octets.
    #[error("invalid {field}: expected six hexadecimal octets")]
    InvalidMac {
        /// Configuration field containing the MAC address.
        field: &'static str,
    },
    /// Canonical CBOR encoding unexpectedly failed.
    #[error("canonical configuration encoding failed: {0}")]
    CanonicalEncoding(String),
    /// Canonical replay configuration decoding failed.
    #[error("canonical replay configuration decoding failed: {0}")]
    CanonicalDecoding(String),
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
pub fn parse_config(source: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(source).map_err(ConfigError::parse)?;
    Config::from_raw(raw)
}

/// Reads, parses, and validates a configuration file.
#[expect(dead_code, reason = "consumed by the application startup work package")]
pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    parse_config(&fs::read_to_string(path).map_err(ConfigError::Read)?)
}

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayConfigDto {
    schema: u16,
    deployment: RawDeployment,
    window: RawWindow,
    conditioning: RawConditioning,
    quality: RawQuality,
    baseline: RawBaseline,
    spaces: Vec<RawIdEntry>,
    transmitters: Vec<RawIdEntry>,
    sensors: Vec<RawSensor>,
    links: Vec<RawLink>,
    routes: Vec<RawRoute>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawDeployment {
    id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapture {
    bind: String,
    max_datagram_bytes: u32,
    socket_buffer_bytes: u32,
    secret_root: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSession {
    database_path: String,
    max_manifest_bytes: u64,
    max_record_bytes: u64,
    max_session_duration_ns: u64,
    max_session_bytes: u64,
    retention_max_sessions: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawWindow {
    width_ns: u64,
    step_ns: u64,
    allowed_lateness_ns: u64,
    inactive_after_ns: u64,
    reorder_horizon: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawConditioning {
    version: String,
    recipe: String,
    scale_numerator: u32,
    scale_denominator: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawView {
    recent_range_ns: u64,
    max_time_buckets: u32,
    max_signal_points: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    bind: String,
    recent_range_ns: u64,
    command_queue_capacity: u32,
    websocket_queue_capacity: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPerformance {
    max_rss_bytes: u64,
    max_cpu_threads: u32,
    snapshot_deadline_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum RawHardwareKind {
    #[serde(rename = "esp32-s3")]
    Esp32S3,
    #[serde(rename = "esp32-c6")]
    Esp32C6,
    #[serde(rename = "intel-5300")]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawSensor {
    id: String,
    hardware_kind: RawHardwareKind,
    device_id: u64,
    key_epoch: u16,
    expected_peer_ip: String,
    firmware_build_digest: String,
    capability_digest: String,
    maximum_raw_csi_bytes: u16,
    maximum_plaintext_bytes: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawIdEntry {
    id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawLink {
    id: String,
    space: String,
    transmitter: String,
    receiver: String,
    expected_transmitter_mac: String,
    channel_policy: RawChannelPolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawChannelPolicy {
    allowed: Vec<u8>,
    #[serde(default)]
    expected: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    peer: String,
    device_id: u64,
    key_epoch: u16,
    link: String,
    peak_packets_per_second: u32,
    maximum_valid_datagram_bytes: u16,
    maximum_authenticated_bytes_per_second: u64,
    replay_window_packets: u16,
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

/// Validated capture limits, bind address, and secret-store root.
#[derive(Clone, Debug, Serialize)]
pub struct CaptureConfig {
    bind: SocketAddr,
    max_datagram_bytes: u32,
    socket_buffer_bytes: u32,
    secret_root: PathBuf,
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

    /// Returns the configured secret-store root without exposing key bytes.
    #[must_use]
    pub fn secret_root(&self) -> &Path {
        &self.secret_root
    }
}

/// Validated session persistence limits.
#[derive(Clone, Debug, Serialize)]
pub struct SessionConfig {
    database_path: PathBuf,
    max_manifest_bytes: u64,
    max_record_bytes: u64,
    max_session_duration_ns: u64,
    max_session_bytes: u64,
    retention_max_sessions: u32,
}

#[expect(dead_code, reason = "consumed by later session work packages")]
impl SessionConfig {
    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
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
}

/// Validated fixed-window contract.
#[derive(Clone, Debug, Serialize)]
pub struct WindowConfig {
    width_ns: u64,
    step_ns: u64,
    allowed_lateness_ns: u64,
    inactive_after_ns: u64,
    reorder_horizon: u32,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct TestWindowConfig {
    pub(crate) width_ns: u64,
    pub(crate) step_ns: u64,
    pub(crate) allowed_lateness_ns: u64,
    pub(crate) inactive_after_ns: u64,
    pub(crate) reorder_horizon: u32,
}

impl WindowConfig {
    #[cfg(test)]
    pub(crate) const fn for_test(input: TestWindowConfig) -> Self {
        assert!(input.width_ns > 0, "test window width must be positive");
        assert!(input.step_ns >= input.width_ns, "test window step must be at least its width");
        assert!(input.inactive_after_ns > 0, "test inactivity threshold must be positive");
        Self {
            width_ns: input.width_ns,
            step_ns: input.step_ns,
            allowed_lateness_ns: input.allowed_lateness_ns,
            inactive_after_ns: input.inactive_after_ns,
            reorder_horizon: input.reorder_horizon,
        }
    }

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
}

/// Validated native-coordinate conditioning recipe and rational scale.
#[derive(Clone, Debug, Serialize)]
pub struct ConditioningConfig {
    version: ConditioningVersion,
    recipe: ConditioningRecipe,
    scale_numerator: u32,
    scale_denominator: u32,
}

#[expect(dead_code, reason = "consumed by later conditioning work package")]
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

#[expect(dead_code, reason = "consumed by later estimator work package")]
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

#[expect(dead_code, reason = "consumed by later estimator work package")]
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

#[expect(dead_code, reason = "consumed by later view work package")]
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

#[expect(dead_code, reason = "consumed by later server work package")]
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

#[expect(dead_code, reason = "consumed by later application work package")]
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

/// A configured space.
#[derive(Clone, Debug, Serialize)]
pub struct SpaceConfig {
    id: SpaceId,
}

impl SpaceConfig {
    pub(crate) const fn id(&self) -> &SpaceId {
        &self.id
    }
}

/// A configured transmitter.
#[derive(Clone, Debug, Serialize)]
pub struct TransmitterConfig {
    id: TransmitterId,
}

impl TransmitterConfig {
    pub(crate) const fn id(&self) -> &TransmitterId {
        &self.id
    }
}

/// A channel allowlist for one physical link.
#[derive(Clone, Debug, Serialize)]
pub struct ChannelPolicy {
    allowed: Box<[u8]>,
    expected: Option<u8>,
}

#[allow(dead_code)]
impl ChannelPolicy {
    /// Returns channels allowed by this link.
    #[must_use]
    pub(crate) fn allowed(&self) -> &[u8] {
        &self.allowed
    }

    /// Returns the expected channel, when the deployment pins one.
    #[must_use]
    pub(crate) const fn expected(&self) -> Option<u8> {
        self.expected
    }
}

/// A configured sensor and its native-frame admission pins.
#[derive(Clone, Debug, Serialize)]
pub struct SensorConfig {
    id: SensorId,
    hardware_kind: HardwareKind,
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    expected_peer_ip: IpAddr,
    firmware_build_digest: [u8; 32],
    capability_digest: [u8; 32],
    maximum_raw_csi_bytes: u16,
    maximum_plaintext_bytes: u16,
}

#[expect(dead_code, reason = "consumed by the native-frame decoder and session work")]
impl SensorConfig {
    pub(crate) const fn id(&self) -> &SensorId {
        &self.id
    }

    pub(crate) const fn hardware_kind(&self) -> HardwareKind {
        self.hardware_kind
    }

    pub(crate) const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub(crate) const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub(crate) const fn expected_peer_ip(&self) -> IpAddr {
        self.expected_peer_ip
    }

    pub(crate) const fn firmware_build_digest(&self) -> [u8; 32] {
        self.firmware_build_digest
    }

    pub(crate) const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    pub(crate) const fn maximum_raw_csi_bytes(&self) -> u16 {
        self.maximum_raw_csi_bytes
    }

    pub(crate) const fn maximum_plaintext_bytes(&self) -> u16 {
        self.maximum_plaintext_bytes
    }
}

/// A physical transmitter-to-receiver link with authenticated source policy.
#[derive(Clone, Debug, Serialize)]
pub struct LinkConfig {
    id: RadioLinkId,
    space: SpaceId,
    transmitter: TransmitterId,
    receiver: SensorId,
    expected_transmitter_mac: [u8; 6],
    channel_policy: ChannelPolicy,
}

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

    pub(crate) const fn expected_transmitter_mac(&self) -> [u8; 6] {
        self.expected_transmitter_mac
    }

    pub(crate) const fn channel_policy(&self) -> &ChannelPolicy {
        &self.channel_policy
    }
}

/// A route binding exact peer/device/key identity to one link.
#[derive(Clone, Debug, Serialize)]
pub struct RouteConfig {
    peer: IpAddr,
    device_id: DeviceId,
    key_epoch: KeyEpoch,
    link: RadioLinkId,
    admission_limits: AdmissionLimits,
}

#[expect(dead_code, reason = "consumed by the native-frame decoder and session work")]
impl RouteConfig {
    pub(crate) const fn peer(&self) -> IpAddr {
        self.peer
    }

    pub(crate) const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub(crate) const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub(crate) const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    pub(crate) const fn admission_limits(&self) -> AdmissionLimits {
        self.admission_limits
    }
}

/// A route resolution result with no socket or secret ownership.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedRoute<'a> {
    /// Sensor selected by the route's link receiver.
    pub(crate) sensor: &'a SensorConfig,
    /// Physical link selected by the route.
    pub(crate) link: &'a LinkConfig,
    /// Exact route entry selected by peer/device/key identity.
    pub(crate) route: &'a RouteConfig,
}

/// Errors returned by exact route lookup.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteError {
    /// No configured route matched all three pre-authentication identity facts.
    #[error("unknown route for peer {peer}, device {device_id}, and key epoch {key_epoch}")]
    Unknown {
        /// Incoming peer IP address.
        peer: IpAddr,
        /// Authenticated header device identity.
        device_id: DeviceId,
        /// Authenticated header key epoch.
        key_epoch: KeyEpoch,
    },
    /// More than one exact route matched.
    #[error("ambiguous route for peer {peer}, device {device_id}, and key epoch {key_epoch}")]
    Ambiguous {
        /// Incoming peer IP address.
        peer: IpAddr,
        /// Authenticated header device identity.
        device_id: DeviceId,
        /// Authenticated header key epoch.
        key_epoch: KeyEpoch,
    },
}

/// Static deployment registry used by the wire decoder and later timeline.
#[derive(Clone, Debug, Serialize)]
pub struct Registry {
    spaces: BTreeMap<SpaceId, SpaceConfig>,
    transmitters: BTreeMap<TransmitterId, TransmitterConfig>,
    sensors: BTreeMap<SensorId, SensorConfig>,
    links: BTreeMap<RadioLinkId, LinkConfig>,
    routes: Vec<RouteConfig>,
}

impl Registry {
    /// Selects only pre-authentication peer, device, key, and budget facts.
    pub(crate) fn resolve_header_route(
        &self,
        peer: IpAddr,
        device_id: DeviceId,
        key_epoch: KeyEpoch,
    ) -> Result<HeaderRoute, RouteError> {
        let route = self.find_route(peer, device_id, key_epoch)?;
        Ok(HeaderRoute::new(peer, device_id, key_epoch, route.admission_limits))
    }

    /// Resolves sensor and link identity only after authenticated header facts exist.
    pub(crate) fn resolve_authenticated_route(
        &self,
        header_route: HeaderRoute,
    ) -> Result<ResolvedRoute<'_>, RouteError> {
        let peer = header_route.peer();
        let device_id = header_route.device();
        let key_epoch = header_route.key_epoch();
        let route = self.find_route(peer, device_id, key_epoch)?;
        let link = self.links.get(&route.link).ok_or(RouteError::Unknown {
            peer,
            device_id,
            key_epoch,
        })?;
        let sensor = self.sensors.get(&link.receiver).ok_or(RouteError::Unknown {
            peer,
            device_id,
            key_epoch,
        })?;
        Ok(ResolvedRoute { sensor, link, route })
    }

    fn find_route(
        &self,
        peer: IpAddr,
        device_id: DeviceId,
        key_epoch: KeyEpoch,
    ) -> Result<&RouteConfig, RouteError> {
        let mut matched = self.routes.iter().filter(|route| {
            route.peer == peer && route.device_id == device_id && route.key_epoch == key_epoch
        });
        let route = matched.next().ok_or(RouteError::Unknown { peer, device_id, key_epoch })?;
        if matched.next().is_some() {
            return Err(RouteError::Ambiguous { peer, device_id, key_epoch });
        }
        Ok(route)
    }

    /// Returns all configured sensors.
    #[must_use]
    pub const fn sensors(&self) -> &BTreeMap<SensorId, SensorConfig> {
        &self.sensors
    }

    pub(crate) const fn spaces(&self) -> &BTreeMap<SpaceId, SpaceConfig> {
        &self.spaces
    }

    pub(crate) const fn transmitters(&self) -> &BTreeMap<TransmitterId, TransmitterConfig> {
        &self.transmitters
    }

    /// Returns all configured links.
    #[must_use]
    pub const fn links(&self) -> &BTreeMap<RadioLinkId, LinkConfig> {
        &self.links
    }

    /// Returns all configured exact routes in file order.
    #[must_use]
    pub fn routes(&self) -> &[RouteConfig] {
        &self.routes
    }
}

/// Complete validated, immutable configuration split by replay semantics.
#[derive(Clone, Debug)]
pub struct Config {
    replay: ReplayConfig,
    runtime: RuntimeConfig,
}

/// Configuration whose values determine faithful replay results.
#[derive(Clone, Debug)]
pub struct ReplayConfig {
    deployment: Deployment,
    window: WindowConfig,
    conditioning: ConditioningConfig,
    quality: QualityConfig,
    baseline: BaselineConfig,
    registry: Registry,
    dto: ReplayConfigDto,
    digest: [u8; 32],
}

impl Serialize for ReplayConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.dto.serialize(serializer)
    }
}

/// Process-only configuration that does not affect replay semantics.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    capture: CaptureConfig,
    session: SessionConfig,
    view: ViewConfig,
    server: ServerConfig,
    performance: PerformanceConfig,
}

impl Config {
    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let RawConfig {
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
            spaces,
            transmitters,
            sensors,
            links,
            routes,
        } = raw;
        let capture = build_capture(capture.ok_or_else(|| missing("capture"))?)?;
        let replay = ReplayConfig::from_dto(
            ReplayConfigDto {
                schema: 1,
                deployment: deployment.ok_or_else(|| missing("deployment.id"))?,
                window: window.ok_or_else(|| missing("window"))?,
                conditioning: conditioning.ok_or_else(|| missing("conditioning"))?,
                quality: quality.ok_or_else(|| missing("quality"))?,
                baseline: baseline.ok_or_else(|| missing("baseline"))?,
                spaces,
                transmitters,
                sensors,
                links,
                routes,
            },
            capture.max_datagram_bytes,
        )?;
        let runtime = RuntimeConfig {
            session: build_session(session.ok_or_else(|| missing("session"))?)?,
            view: build_view(view.ok_or_else(|| missing("view"))?)?,
            server: build_server(server.ok_or_else(|| missing("server"))?)?,
            performance: build_performance(
                performance.ok_or_else(|| missing("performance"))?,
                replay.window.step_ns,
            )?,
            capture,
        };
        Ok(Self { replay, runtime })
    }

    /// Returns the semantic configuration embedded in sessions.
    #[must_use]
    pub const fn replay(&self) -> &ReplayConfig {
        &self.replay
    }

    /// Returns process-only configuration excluded from replay identity.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeConfig {
        &self.runtime
    }

    /// Returns deployment settings.
    #[must_use]
    pub const fn deployment(&self) -> &Deployment {
        self.replay.deployment()
    }

    /// Returns capture settings.
    #[must_use]
    pub const fn capture(&self) -> &CaptureConfig {
        self.runtime.capture()
    }

    /// Returns session settings.
    #[must_use]
    pub(crate) const fn session(&self) -> &SessionConfig {
        self.runtime.session()
    }

    /// Returns window settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by later timeline work package")]
    pub(crate) const fn window(&self) -> &WindowConfig {
        self.replay.window()
    }

    /// Returns conditioning settings.
    #[must_use]
    pub(crate) const fn conditioning(&self) -> &ConditioningConfig {
        self.replay.conditioning()
    }

    /// Returns quality settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by later estimator work package")]
    pub(crate) const fn quality(&self) -> &QualityConfig {
        self.replay.quality()
    }

    /// Returns baseline settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by later estimator work package")]
    pub(crate) const fn baseline(&self) -> &BaselineConfig {
        self.replay.baseline()
    }

    /// Returns view settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by later view work package")]
    pub(crate) const fn view(&self) -> &ViewConfig {
        self.runtime.view()
    }

    /// Returns server settings.
    #[must_use]
    pub(crate) const fn server(&self) -> &ServerConfig {
        self.runtime.server()
    }

    /// Returns process performance settings.
    #[must_use]
    #[expect(dead_code, reason = "consumed by later application work package")]
    pub(crate) const fn performance(&self) -> &PerformanceConfig {
        self.runtime.performance()
    }

    /// Returns the validated topology registry.
    #[must_use]
    pub const fn registry(&self) -> &Registry {
        self.replay.registry()
    }
}

impl ReplayConfig {
    fn from_dto(
        dto: ReplayConfigDto,
        maximum_live_datagram_bytes: u32,
    ) -> Result<Self, ConfigError> {
        if dto.schema != 1 {
            return Err(invalid("replay.schema", "must equal 1"));
        }
        let deployment = Deployment {
            id: DeploymentId::new(dto.deployment.id.clone())
                .map_err(|error| ConfigError::id("deployment.id", error))?,
        };
        let window = build_window(dto.window.clone())?;
        let conditioning = build_conditioning(dto.conditioning.clone())?;
        let quality = build_quality(dto.quality.clone())?;
        let baseline = build_baseline(dto.baseline.clone())?;
        let registry = build_registry(
            dto.spaces.clone(),
            dto.transmitters.clone(),
            dto.sensors.clone(),
            dto.links.clone(),
            dto.routes.clone(),
            maximum_live_datagram_bytes,
        )?;
        let mut replay = Self {
            deployment,
            window,
            conditioning,
            quality,
            baseline,
            registry,
            dto,
            digest: [0; 32],
        };
        replay.digest = Sha256::digest(replay.canonical_bytes()?).into();
        Ok(replay)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let mut cursor = Cursor::new(bytes);
        let dto: ReplayConfigDto = ciborium::de::from_reader(&mut cursor)
            .map_err(|error| ConfigError::CanonicalDecoding(error.to_string()))?;
        if cursor.position() != bytes.len() as u64 {
            return Err(ConfigError::CanonicalDecoding("trailing data".into()));
        }
        Self::from_dto(dto, u32::from(u16::MAX))
    }

    /// Returns the SHA-256 of canonical replay configuration bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns canonical CBOR bytes used by [`Self::digest`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        let mut bytes = Vec::new();
        into_writer(&self.dto, &mut bytes)
            .map_err(|error| ConfigError::CanonicalEncoding(error.to_string()))?;
        Ok(bytes)
    }

    pub const fn deployment(&self) -> &Deployment {
        &self.deployment
    }
    pub(crate) const fn window(&self) -> &WindowConfig {
        &self.window
    }
    pub(crate) const fn conditioning(&self) -> &ConditioningConfig {
        &self.conditioning
    }
    pub(crate) const fn quality(&self) -> &QualityConfig {
        &self.quality
    }
    pub(crate) const fn baseline(&self) -> &BaselineConfig {
        &self.baseline
    }
    pub const fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl RuntimeConfig {
    pub const fn capture(&self) -> &CaptureConfig {
        &self.capture
    }
    pub(crate) const fn session(&self) -> &SessionConfig {
        &self.session
    }
    pub(crate) const fn view(&self) -> &ViewConfig {
        &self.view
    }
    pub(crate) const fn server(&self) -> &ServerConfig {
        &self.server
    }
    pub(crate) const fn performance(&self) -> &PerformanceConfig {
        &self.performance
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
    if raw.max_datagram_bytes == 0 || raw.max_datagram_bytes > u32::from(u16::MAX) {
        return Err(invalid("capture.max_datagram_bytes", "must be in 1..=65535"));
    }
    if raw.socket_buffer_bytes < raw.max_datagram_bytes {
        return Err(invalid("capture.socket_buffer_bytes", "must cover max_datagram_bytes"));
    }
    if raw.secret_root.trim().is_empty() {
        return Err(invalid("capture.secret_root", "must not be empty"));
    }
    Ok(CaptureConfig {
        bind: parse_socket("capture.bind", &raw.bind)?,
        max_datagram_bytes: raw.max_datagram_bytes,
        socket_buffer_bytes: raw.socket_buffer_bytes,
        secret_root: PathBuf::from(raw.secret_root),
    })
}

fn build_session(raw: RawSession) -> Result<SessionConfig, ConfigError> {
    if raw.database_path.trim().is_empty()
        || raw.max_manifest_bytes == 0
        || raw.max_record_bytes == 0
        || raw.max_session_bytes == 0
        || raw.max_session_duration_ns == 0
        || raw.retention_max_sessions == 0
    {
        return Err(invalid("session", "database_path and all limits must be valid and positive"));
    }
    if raw.max_record_bytes > raw.max_session_bytes
        || raw.max_manifest_bytes > raw.max_session_bytes
    {
        return Err(invalid("session", "manifest/record limits exceed max_session_bytes"));
    }
    Ok(SessionConfig {
        database_path: PathBuf::from(raw.database_path),
        max_manifest_bytes: raw.max_manifest_bytes,
        max_record_bytes: raw.max_record_bytes,
        max_session_duration_ns: raw.max_session_duration_ns,
        max_session_bytes: raw.max_session_bytes,
        retention_max_sessions: raw.retention_max_sessions,
    })
}

fn build_window(raw: RawWindow) -> Result<WindowConfig, ConfigError> {
    if raw.width_ns == 0
        || raw.step_ns == 0
        || raw.step_ns < raw.width_ns
        || raw.inactive_after_ns == 0
    {
        return Err(invalid(
            "window",
            "width/step must be positive and non-overlapping; inactive_after_ns must be positive",
        ));
    }
    Ok(WindowConfig {
        width_ns: raw.width_ns,
        step_ns: raw.step_ns,
        allowed_lateness_ns: raw.allowed_lateness_ns,
        inactive_after_ns: raw.inactive_after_ns,
        reorder_horizon: raw.reorder_horizon,
    })
}

fn build_conditioning(raw: RawConditioning) -> Result<ConditioningConfig, ConfigError> {
    if raw.version.trim().is_empty() || raw.recipe != "log1p-hypot" {
        return Err(invalid(
            "conditioning",
            "version must be non-empty and recipe must be log1p-hypot",
        ));
    }
    if raw.scale_numerator == 0 || raw.scale_denominator == 0 {
        return Err(invalid("conditioning", "scale numerator and denominator must be positive"));
    }
    let divisor = gcd(raw.scale_numerator, raw.scale_denominator);
    Ok(ConditioningConfig {
        version: ConditioningVersion::new(raw.version)
            .map_err(|error| ConfigError::id("conditioning.version", error))?,
        recipe: ConditioningRecipe::LogOnePlusHypot,
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
    Ok(QualityConfig {
        minimum_frames: raw.minimum_frames,
        minimum_coordinate_coverage: raw.minimum_coordinate_coverage,
        maximum_gap_ratio: raw.maximum_gap_ratio,
        maximum_receive_jitter_ns: raw.maximum_receive_jitter_ns,
        minimum_time_quality: match raw.minimum_time_quality {
            RawTimeQuality::ReceiveOnly => TimeQualityConfig::ReceiveOnly,
            RawTimeQuality::ClockCorrected => TimeQualityConfig::ClockCorrected,
        },
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
    let mut device_ids = BTreeSet::new();
    for raw in values {
        let id = SensorId::new(raw.id).map_err(|error| ConfigError::id("sensors[].id", error))?;
        let hardware_kind = raw.hardware_kind.into();
        if hardware_kind != HardwareKind::Esp32S3 {
            return Err(ConfigError::UnsupportedHardware {
                sensor: id.to_string(),
                hardware: hardware_kind,
            });
        }
        let device_id = DeviceId::new(raw.device_id);
        let key_epoch = KeyEpoch::try_new(raw.key_epoch)
            .map_err(|error| ConfigError::id("sensors[].key_epoch", error))?;
        if !device_ids.insert(device_id) {
            return Err(ConfigError::Duplicate { kind: "device", id: device_id.to_string() });
        }
        let expected_peer_ip = raw
            .expected_peer_ip
            .parse::<IpAddr>()
            .map_err(|error| invalid("sensors[].expected_peer_ip", error.to_string()))?;
        if raw.maximum_raw_csi_bytes == 0 || raw.maximum_raw_csi_bytes > MAX_S3_RAW_CSI_BYTES {
            return Err(invalid(
                "sensors[].maximum_raw_csi_bytes",
                format!("must be in 1..={MAX_S3_RAW_CSI_BYTES}"),
            ));
        }
        if raw.maximum_plaintext_bytes == 0 || raw.maximum_plaintext_bytes > MAX_S3_PLAINTEXT_BYTES
        {
            return Err(invalid(
                "sensors[].maximum_plaintext_bytes",
                format!("must be in 1..={MAX_S3_PLAINTEXT_BYTES}"),
            ));
        }
        let firmware_build_digest =
            parse_digest("sensors[].firmware_build_digest", &raw.firmware_build_digest)?;
        let capability_digest =
            parse_digest("sensors[].capability_digest", &raw.capability_digest)?;
        let sensor = SensorConfig {
            id: id.clone(),
            hardware_kind,
            device_id,
            key_epoch,
            expected_peer_ip,
            firmware_build_digest,
            capability_digest,
            maximum_raw_csi_bytes: raw.maximum_raw_csi_bytes,
            maximum_plaintext_bytes: raw.maximum_plaintext_bytes,
        };
        if output.insert(id.clone(), sensor).is_some() {
            return Err(ConfigError::Duplicate { kind: "sensor", id: id.to_string() });
        }
    }
    Ok(output)
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
        let sensor = sensors.get(&receiver).ok_or_else(|| ConfigError::UnknownReference {
            kind: "sensor",
            id: receiver.to_string(),
        })?;
        let expected_transmitter_mac =
            parse_mac("links[].expected_transmitter_mac", &raw.expected_transmitter_mac)?;
        let channel_policy = build_channel_policy(raw.channel_policy)?;
        let link = LinkConfig {
            id: id.clone(),
            space,
            transmitter,
            receiver,
            expected_transmitter_mac,
            channel_policy,
        };
        if output.insert(id.clone(), link).is_some() {
            return Err(ConfigError::Duplicate { kind: "link", id: id.to_string() });
        }
        let _ = sensor;
    }
    Ok(output)
}

fn build_channel_policy(raw: RawChannelPolicy) -> Result<ChannelPolicy, ConfigError> {
    if raw.allowed.is_empty() || raw.allowed.contains(&0) || raw.allowed.iter().any(|v| *v > 14) {
        return Err(invalid(
            "links[].channel_policy.allowed",
            "must contain unique ESP32 Wi-Fi channels in 1..=14",
        ));
    }
    let set: BTreeSet<u8> = raw.allowed.iter().copied().collect();
    if set.len() != raw.allowed.len() {
        return Err(invalid("links[].channel_policy.allowed", "must be unique"));
    }
    if raw.expected.is_some_and(|channel| !set.contains(&channel)) {
        return Err(invalid("links[].channel_policy.expected", "must be one of allowed channels"));
    }
    Ok(ChannelPolicy { allowed: raw.allowed.into_boxed_slice(), expected: raw.expected })
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
        let peer = raw
            .peer
            .parse::<IpAddr>()
            .map_err(|error| invalid("routes[].peer", error.to_string()))?;
        let device_id = DeviceId::new(raw.device_id);
        let key_epoch = KeyEpoch::try_new(raw.key_epoch)
            .map_err(|error| ConfigError::id("routes[].key_epoch", error))?;
        if !identities.insert((peer, device_id, key_epoch)) {
            return Err(ConfigError::AmbiguousRoute {
                peer: peer.to_string(),
                device_id: device_id.get(),
                key_epoch: key_epoch.get(),
            });
        }
        if raw.maximum_valid_datagram_bytes == 0
            || u32::from(raw.maximum_valid_datagram_bytes) > max_datagram_bytes
            || raw.maximum_valid_datagram_bytes < NATIVE_FRAME_OVERHEAD_BYTES
        {
            return Err(invalid(
                "routes[].maximum_valid_datagram_bytes",
                "must fit the capture limit and fixed native-frame overhead",
            ));
        }
        let link =
            RadioLinkId::new(raw.link).map_err(|error| ConfigError::id("routes[].link", error))?;
        let link_config = links
            .get(&link)
            .ok_or_else(|| ConfigError::UnknownReference { kind: "link", id: link.to_string() })?;
        let sensor = sensors.get(&link_config.receiver).ok_or_else(|| {
            ConfigError::UnknownReference { kind: "sensor", id: link_config.receiver.to_string() }
        })?;
        let minimum_datagram_bytes = NATIVE_FRAME_OVERHEAD_BYTES + sensor.maximum_plaintext_bytes;
        if raw.maximum_valid_datagram_bytes < minimum_datagram_bytes {
            return Err(invalid(
                "routes[].maximum_valid_datagram_bytes",
                "must cover native-frame overhead plus the receiver plaintext limit",
            ));
        }
        if sensor.expected_peer_ip != peer {
            return Err(invalid("routes[].peer", "must match the receiver expected_peer_ip"));
        }
        if sensor.device_id != device_id || sensor.key_epoch != key_epoch {
            return Err(invalid(
                "routes[].device_id/key_epoch",
                "must match the referenced receiver identity",
            ));
        }
        let admission_limits = AdmissionLimits::try_new(
            raw.maximum_valid_datagram_bytes,
            raw.peak_packets_per_second,
            raw.maximum_authenticated_bytes_per_second,
            raw.replay_window_packets,
        )
        .map_err(|error| invalid("routes[]", error.to_string()))?;
        output.push(RouteConfig { peer, device_id, key_epoch, link, admission_limits });
    }
    Ok(output)
}

fn parse_digest(field: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    let value = value.trim();
    if value.len() != 64 {
        return Err(ConfigError::InvalidDigest { field });
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_value(chunk[0]).ok_or(ConfigError::InvalidDigest { field })? << 4)
            | hex_value(chunk[1]).ok_or(ConfigError::InvalidDigest { field })?;
    }
    Ok(digest)
}

fn parse_mac(field: &'static str, value: &str) -> Result<[u8; 6], ConfigError> {
    let parts: Vec<&str> = value.trim().split(':').collect();
    if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
        return Err(ConfigError::InvalidMac { field });
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        let bytes = part.as_bytes();
        mac[index] = (hex_value(bytes[0]).ok_or(ConfigError::InvalidMac { field })? << 4)
            | hex_value(bytes[1]).ok_or(ConfigError::InvalidMac { field })?;
    }
    if mac == [0; 6] {
        return Err(ConfigError::InvalidMac { field });
    }
    Ok(mac)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use ciborium::value::Value;

    fn replay() -> ReplayConfig {
        parse_config(include_str!("../tests/fixtures/config/valid-two-esp32.toml"))
            .expect("valid config")
            .replay
    }

    #[test]
    fn canonical_replay_config_roundtrips_through_validating_decoder() {
        let expected = replay();
        let bytes = expected.canonical_bytes().expect("canonical bytes");
        let actual = ReplayConfig::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(actual.digest(), expected.digest());
        assert_eq!(actual.canonical_bytes().expect("bytes"), bytes);
        assert_eq!(actual.registry().routes().len(), 2);
    }

    #[test]
    fn replay_decoder_rejects_unknown_trailing_and_invalid_fields() {
        let bytes = replay().canonical_bytes().expect("bytes");
        let mut value: Value = ciborium::de::from_reader(bytes.as_slice()).expect("value");
        let Value::Map(fields) = &mut value else { panic!("replay config must be a map") };
        fields.push((Value::Text("unknown".into()), Value::Null));
        let mut unknown = Vec::new();
        ciborium::ser::into_writer(&value, &mut unknown).expect("encode");
        assert!(ReplayConfig::from_canonical_bytes(&unknown).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0xf6);
        assert!(ReplayConfig::from_canonical_bytes(&trailing).is_err());

        let mut value: Value = ciborium::de::from_reader(bytes.as_slice()).expect("value");
        let Value::Map(fields) = &mut value else { panic!("replay config must be a map") };
        let window = fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("window".into()))
            .expect("window");
        let Value::Map(window) = &mut window.1 else { panic!("window must be a map") };
        window
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("width_ns".into()))
            .expect("width")
            .1 = Value::Integer(0.into());
        let mut invalid = Vec::new();
        ciborium::ser::into_writer(&value, &mut invalid).expect("encode");
        assert!(ReplayConfig::from_canonical_bytes(&invalid).is_err());
    }
}
