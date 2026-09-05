//! Canonical sealed spatial artifacts and their validation boundary.

use std::backtrace::Backtrace;
use std::fmt;

use sha2::{Digest, Sha256};

/// Canonical artifact envelope magic (`WSA1`).
const ARTIFACT_MAGIC: &[u8; 4] = b"WSA1";
/// Exact artifact schema version accepted by this hard-rebuild Store.
const ARTIFACT_SCHEMA_VERSION: u16 = 1;
/// SHA-256 digest width appended to every sealed envelope.
const DIGEST_BYTES: usize = 32;
/// Bytes before the payload: magic, schema, kind, reserved byte, and length.
const HEADER_BYTES: usize = 12;
/// Absolute collection-item ceiling enforced before allocation while decoding.
const MAX_ENCODED_COLLECTION_ITEMS: usize = 100_000;
/// Default sealed artifact ceiling: 16 MiB, chosen to bound phone uploads and
/// SQLite allocations while leaving room for structured room geometry.
const DEFAULT_MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
/// Default immutable artifacts retained by one Store.
const DEFAULT_MAX_ARTIFACTS: usize = 4_096;
/// Default structured geometry element ceiling per scene.
const DEFAULT_MAX_GEOMETRY_ELEMENTS: usize = 100_000;
/// Default supervision sample ceiling per segment.
const DEFAULT_MAX_SUPERVISION_SAMPLES: usize = 100_000;
/// Conservative first-room position-error ceiling in metres.
const DEFAULT_MAX_POSITION_ERROR_M: f64 = 0.75;

macro_rules! unsigned_unit {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Returns the underlying unit value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }
    };
}

unsigned_unit!(UtcNanoseconds, "A UTC timestamp in nanoseconds since the Unix epoch.");
unsigned_unit!(PhoneNanoseconds, "A timestamp in a declared phone monotonic clock domain.");
unsigned_unit!(HostNanoseconds, "A timestamp in the Host monotonic clock domain.");
unsigned_unit!(ClockErrorNanoseconds, "A conservative clock-relation error in nanoseconds.");

/// A Host-minus-phone clock offset in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockOffsetNanoseconds(i64);

impl ClockOffsetNanoseconds {
    /// Returns the signed Host-minus-phone offset.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl From<i64> for ClockOffsetNanoseconds {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

/// One phone tracking continuity epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrackingEpoch(u32);

impl TrackingEpoch {
    /// Returns the phone-native epoch value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for TrackingEpoch {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

/// A finite non-negative speed bound in metres per second.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct MetersPerSecond(f64);

impl MetersPerSecond {
    /// Creates a finite non-negative speed bound.
    ///
    /// # Errors
    ///
    /// Returns an error for negative or non-finite values.
    pub fn new(value: f64) -> Result<Self, ArtifactError> {
        require_nonnegative_finite(value)?;
        Ok(Self(value))
    }

    /// Returns the speed in metres per second.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

/// A bounded mapping from one phone clock to Host monotonic time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhoneTimeRelation {
    relation_id: [u8; 16],
    offset_at_reference: ClockOffsetNanoseconds,
    drift_parts_per_billion: i64,
    reference_phone_time: PhoneNanoseconds,
    maximum_error: ClockErrorNanoseconds,
    valid_from_phone_time: PhoneNanoseconds,
    valid_until_phone_time: PhoneNanoseconds,
}

impl PhoneTimeRelation {
    /// Creates a relation with an ordered validity range and bounded drift.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty validity interval, a reference outside it,
    /// or drift beyond 100,000 parts per billion.
    pub fn new(
        relation_id: [u8; 16],
        offset_at_reference: ClockOffsetNanoseconds,
        drift_parts_per_billion: i64,
        reference_phone_time: PhoneNanoseconds,
        maximum_error: ClockErrorNanoseconds,
        valid_from_phone_time: PhoneNanoseconds,
        valid_until_phone_time: PhoneNanoseconds,
    ) -> Result<Self, ArtifactError> {
        if valid_from_phone_time >= valid_until_phone_time
            || reference_phone_time < valid_from_phone_time
            || reference_phone_time > valid_until_phone_time
            || drift_parts_per_billion.unsigned_abs() > 100_000
        {
            return Err(ArtifactError::new("phone time relation range or drift is invalid"));
        }
        Ok(Self {
            relation_id,
            offset_at_reference,
            drift_parts_per_billion,
            reference_phone_time,
            maximum_error,
            valid_from_phone_time,
            valid_until_phone_time,
        })
    }

    /// Returns the stable relation identity.
    #[must_use]
    pub const fn relation_id(self) -> [u8; 16] {
        self.relation_id
    }

    /// Returns the Host-minus-phone offset at the reference time.
    #[must_use]
    pub const fn offset_at_reference(self) -> ClockOffsetNanoseconds {
        self.offset_at_reference
    }

    /// Returns the estimated drift in parts per billion.
    #[must_use]
    pub const fn drift_parts_per_billion(self) -> i64 {
        self.drift_parts_per_billion
    }

    /// Returns the phone reference timestamp.
    #[must_use]
    pub const fn reference_phone_time(self) -> PhoneNanoseconds {
        self.reference_phone_time
    }

    /// Returns the conservative error at the reference timestamp.
    #[must_use]
    pub const fn maximum_error(self) -> ClockErrorNanoseconds {
        self.maximum_error
    }

    /// Returns the first qualified phone timestamp.
    #[must_use]
    pub const fn valid_from_phone_time(self) -> PhoneNanoseconds {
        self.valid_from_phone_time
    }

    /// Returns the last qualified phone timestamp.
    #[must_use]
    pub const fn valid_until_phone_time(self) -> PhoneNanoseconds {
        self.valid_until_phone_time
    }

    pub(crate) fn error_at(self, time: PhoneNanoseconds) -> Option<ClockErrorNanoseconds> {
        if time < self.valid_from_phone_time || time > self.valid_until_phone_time {
            return None;
        }
        let elapsed = time.get().abs_diff(self.reference_phone_time.get());
        let drift_error = u128::from(elapsed)
            .checked_mul(u128::from(self.drift_parts_per_billion.unsigned_abs()))?
            .div_ceil(1_000_000_000);
        let error = u128::from(self.maximum_error.get()).checked_add(drift_error)?;
        u64::try_from(error).ok().map(ClockErrorNanoseconds)
    }
}

/// Kind of immutable spatial artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// Scene snapshot.
    Scene,
    /// Calibration bundle.
    Calibration,
    /// Supervision segment.
    Supervision,
}

impl ArtifactKind {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Scene => 1,
            Self::Calibration => 2,
            Self::Supervision => 3,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Scene),
            2 => Some(Self::Calibration),
            3 => Some(Self::Supervision),
            _ => None,
        }
    }
}

/// Import path that produced a candidate artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactOrigin {
    /// Explicit local recovery import.
    Local,
    /// Authenticated companion upload.
    Companion,
}

impl ArtifactOrigin {
    pub(crate) const fn database_value(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Companion => "companion",
        }
    }
}

/// Bounded validation and persistence limits for spatial artifact imports.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArtifactLimits {
    max_artifact_bytes: usize,
    max_artifacts: usize,
    max_geometry_elements: usize,
    max_supervision_samples: usize,
    max_position_error_m: f64,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            max_artifacts: DEFAULT_MAX_ARTIFACTS,
            max_geometry_elements: DEFAULT_MAX_GEOMETRY_ELEMENTS,
            max_supervision_samples: DEFAULT_MAX_SUPERVISION_SAMPLES,
            max_position_error_m: DEFAULT_MAX_POSITION_ERROR_M,
        }
    }
}

impl ArtifactLimits {
    /// Starts a semantic limits builder from conservative defaults.
    #[must_use]
    pub fn builder() -> ArtifactLimitsBuilder {
        ArtifactLimitsBuilder(Self::default())
    }

    pub(crate) const fn max_artifact_bytes(self) -> usize {
        self.max_artifact_bytes
    }

    pub(crate) const fn max_artifacts(self) -> usize {
        self.max_artifacts
    }

    pub(crate) const fn max_position_error_m(self) -> f64 {
        self.max_position_error_m
    }
}

/// Builder for independently named artifact resource and uncertainty limits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArtifactLimitsBuilder(ArtifactLimits);

impl ArtifactLimitsBuilder {
    /// Sets the maximum sealed bytes accepted for one artifact.
    #[must_use]
    pub const fn max_artifact_bytes(mut self, value: usize) -> Self {
        self.0.max_artifact_bytes = value;
        self
    }
    /// Sets the maximum artifacts retained by the Store.
    #[must_use]
    pub const fn max_artifacts(mut self, value: usize) -> Self {
        self.0.max_artifacts = value;
        self
    }
    /// Sets the maximum structured geometry elements per scene.
    #[must_use]
    pub const fn max_geometry_elements(mut self, value: usize) -> Self {
        self.0.max_geometry_elements = value;
        self
    }
    /// Sets the maximum samples per supervision segment.
    #[must_use]
    pub const fn max_supervision_samples(mut self, value: usize) -> Self {
        self.0.max_supervision_samples = value;
        self
    }
    /// Sets the maximum admitted combined spatial uncertainty in metres.
    #[must_use]
    pub const fn max_position_error_m(mut self, value: f64) -> Self {
        self.0.max_position_error_m = value;
        self
    }
    /// Validates and builds the limits.
    pub fn build(self) -> Result<ArtifactLimits, ArtifactError> {
        if self.0.max_artifact_bytes == 0
            || self.0.max_artifacts == 0
            || self.0.max_geometry_elements == 0
            || self.0.max_supervision_samples == 0
        {
            return Err(ArtifactError::new("artifact count and byte limits must be non-zero"));
        }
        require_nonnegative_finite(self.0.max_position_error_m)?;
        Ok(self.0)
    }
}

/// Fail-closed classification for a rejected artifact import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRejectReason {
    /// Envelope, schema, version, digest, or typed payload validation failed.
    InvalidArtifact,
    /// A configured byte or count limit was exceeded.
    LimitExceeded,
    /// The artifact's coordinate or timing relationships are invalid.
    InvalidRelation,
    /// A tracking reset lacks a qualified relocalization.
    TrackingNotRelocalized,
    /// The calibration names an RF identity unknown to this Host.
    UnknownRfIdentity,
    /// The calibration is outside its validity interval.
    Expired,
    /// A referenced scene has not been imported.
    MissingScene,
    /// Different bytes already occupy the immutable identity and revision.
    IdentityConflict,
    /// The sole Store writer was unavailable or persistence failed.
    Persistence,
}

/// Failure to validate or persist an artifact without replacing existing data.
#[derive(Debug)]
pub struct ArtifactImportError {
    kind: Box<ArtifactImportErrorKind>,
    backtrace: Box<Backtrace>,
}

#[derive(Debug, thiserror::Error)]
enum ArtifactImportErrorKind {
    #[error("{message}")]
    Rejected { reason: ArtifactRejectReason, message: &'static str },
    #[error("sealed artifact validation failed: {0}")]
    Artifact(#[source] ArtifactError),
    #[error("artifact Store operation failed: {0}")]
    Database(#[source] rusqlite::Error),
}

impl ArtifactImportError {
    pub(crate) fn new(reason: ArtifactRejectReason, message: &'static str) -> Self {
        Self {
            kind: Box::new(ArtifactImportErrorKind::Rejected { reason, message }),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    pub(crate) fn invalid_artifact(source: ArtifactError) -> Self {
        Self {
            kind: Box::new(ArtifactImportErrorKind::Artifact(source)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    pub(crate) fn database(source: rusqlite::Error) -> Self {
        Self {
            kind: Box::new(ArtifactImportErrorKind::Database(source)),
            backtrace: Box::new(Backtrace::capture()),
        }
    }

    /// Returns the fail-closed rejection classification.
    #[must_use]
    pub fn reason(&self) -> ArtifactRejectReason {
        match self.kind.as_ref() {
            ArtifactImportErrorKind::Rejected { reason, .. } => *reason,
            ArtifactImportErrorKind::Artifact(_) => ArtifactRejectReason::InvalidArtifact,
            ArtifactImportErrorKind::Database(_) => ArtifactRejectReason::Persistence,
        }
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for ArtifactImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for ArtifactImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.kind.as_ref())
    }
}

/// Receipt for one committed immutable candidate artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedArtifact {
    digest: ArtifactDigest,
    kind: ArtifactKind,
    artifact_id: String,
    revision: u32,
    origin: ArtifactOrigin,
}

impl ImportedArtifact {
    /// Returns the content digest.
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    /// Returns the artifact kind.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Returns the stable artifact identity.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns the immutable revision.
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// Returns the import path recorded on first commit.
    #[must_use]
    pub const fn origin(&self) -> ArtifactOrigin {
        self.origin
    }

    pub(crate) fn from_parts(
        digest: ArtifactDigest,
        kind: ArtifactKind,
        artifact_id: String,
        revision: u32,
        origin: ArtifactOrigin,
    ) -> Self {
        Self { digest, kind, artifact_id, revision, origin }
    }
}

/// A stable identity for the external source that produced an artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    /// Domain of the source identity.
    pub namespace: String,
    /// Stable identity within `namespace`.
    pub identity: String,
}

/// Shared immutable identity, revision, and provenance for every spatial artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadata {
    /// Stable artifact identity.
    pub artifact_id: String,
    /// Immutable revision of this identity.
    pub revision: u32,
    /// Sources from which this artifact was produced.
    pub provenance: Vec<SourceIdentity>,
}

/// Kind of structure represented by a geometry element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryKind {
    /// A wall or fixed wall segment.
    Wall,
    /// A door opening or door boundary.
    Door,
    /// A furniture surface or volume.
    Furniture,
}

/// One structured scene-geometry element in world coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct GeometryElement {
    /// Semantic structure kind.
    pub kind: GeometryKind,
    /// Ordered vertices in metres in the scene world coordinate system.
    pub vertices_m: Vec<[f64; 3]>,
}

/// One sampled world-coordinate coverage cell.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageCell {
    /// Cell centre in world-coordinate metres.
    pub position_m: [f64; 3],
    /// Whether this cell was observed by the scan.
    pub covered: bool,
}

/// A versioned spatial coordinate system, geometry, coverage, and uncertainty.
#[derive(Clone, Debug, PartialEq)]
pub struct SceneSnapshot {
    /// Shared immutable identity and provenance.
    pub metadata: ArtifactMetadata,
    /// Stable world-coordinate-system identity.
    pub world_coordinate_system: String,
    /// Structured walls, doors, and furniture.
    pub geometry: Vec<GeometryElement>,
    /// Validity mask corresponding one-for-one with structured geometry.
    pub geometry_validity_mask: Vec<bool>,
    /// Explicit spatial coverage mask retaining observed and unobserved cells.
    pub coverage_mask: Vec<CoverageCell>,
    /// Fraction of the room scan covered, in the inclusive range zero to one.
    pub scan_coverage: f64,
    /// Conservative scene-coordinate error in metres.
    pub map_error_m: f64,
    /// Optional non-authoritative display asset reference.
    pub usdz_display_reference: Option<String>,
}

/// A bounded transform between two explicitly identified coordinate systems.
#[derive(Clone, Debug, PartialEq)]
pub struct CoordinateTransform {
    /// Coordinate system in which input points are expressed.
    pub source_coordinate_system: String,
    /// Coordinate system in which transformed points are expressed.
    pub target_coordinate_system: String,
    /// Row-major homogeneous four-by-four transform.
    pub matrix: [f64; 16],
    /// Conservative transform error in metres.
    pub max_error_m: f64,
}

/// One RF port-to-physical-antenna condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortCondition {
    /// Source-native port number.
    pub port: u16,
    /// Physical antenna identity.
    pub antenna_identity: String,
}

/// A versioned RF device, antenna, transform, port, and phase calibration.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationBundle {
    /// Shared immutable identity and provenance.
    pub metadata: ArtifactMetadata,
    /// Scene in whose world coordinates this calibration is expressed.
    pub scene_digest: ArtifactDigest,
    /// Registered RF source identity.
    pub rf_device_identity: String,
    /// Physical antenna reference used during registration.
    pub antenna_reference: String,
    /// Transform from device reference coordinates to scene coordinates.
    pub world_transform: CoordinateTransform,
    /// Explicit port-to-antenna conditions.
    pub ports: Vec<PortCondition>,
    /// Separately established phase/coherence condition.
    pub coherence_scope: CoherenceScope,
    /// Array geometry and element condition.
    pub array_condition: ArrayCondition,
    /// Calibration continuity epoch.
    pub calibration_epoch: CalibrationEpoch,
    /// Conservative combined calibration error in metres.
    pub max_error_m: f64,
    /// First UTC nanosecond for which the calibration is valid.
    pub valid_from_utc: UtcNanoseconds,
    /// Last UTC nanosecond for which the calibration is valid.
    pub valid_until_utc: UtcNanoseconds,
}

/// Scope over which RF phase coherence was established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoherenceScope {
    /// No usable phase relationship was established.
    None,
    /// Phase coherence holds only within one packet.
    Packet,
    /// Phase coherence holds within one declared capture interval.
    CaptureInterval,
}

/// One calibration continuity epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CalibrationEpoch(u32);

impl CalibrationEpoch {
    /// Creates an epoch identity from its source-native value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the source-native epoch value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Declared physical array identity and element count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayCondition {
    /// Stable array identity.
    pub array_identity: String,
    /// Number of physical elements established by this calibration.
    pub physical_element_count: u16,
}

/// Camera tracking quality associated with one supervision sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackingQuality {
    /// Tracking is operating normally.
    Normal,
    /// Tracking is limited and its uncertainty must be retained.
    Limited,
}

/// Depth observation quality associated with one supervision sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepthQuality {
    /// Depth was directly measured.
    Measured,
    /// Depth was inferred and is explicitly distinguished from measurement.
    Estimated,
    /// No depth was observed.
    Missing,
}

/// Spatial scope within which a supervision label is authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelScope {
    /// Only the camera-visible region was observed.
    LocallyVisible,
    /// The complete room was independently observed.
    WholeRoom,
}

/// One visible person's bounded station, pose, and position label.
#[derive(Clone, Debug, PartialEq)]
pub struct PersonLabel {
    /// Collection station identity.
    pub station: String,
    /// Declared pose label.
    pub pose: String,
    /// World-coordinate position in metres.
    pub position_m: [f64; 3],
    /// Conservative individual position error in metres.
    pub max_error_m: f64,
}

/// Joint supervision content without inventing unseen-room occupancy.
#[derive(Clone, Debug, PartialEq)]
pub enum JointLabel {
    /// No occupancy conclusion is available.
    Unknown,
    /// A possibly partial set of visible people.
    VisibleSet(Vec<PersonLabel>),
    /// An independently observed whole-room empty label.
    WholeRoomEmpty,
}

/// One aligned RGB, depth, pose, visibility, and joint-label sample.
#[derive(Clone, Debug, PartialEq)]
pub struct SupervisionSample {
    /// Immutable RGB sample reference.
    pub rgb_reference: String,
    /// Immutable depth sample reference, absent only when depth is missing.
    pub depth_reference: Option<String>,
    /// Immutable camera-pose sample reference.
    pub pose_reference: String,
    /// RGB capture time in the declared phone clock domain.
    pub rgb_time: PhoneNanoseconds,
    /// Depth capture time in the same clock domain.
    pub depth_time: PhoneNanoseconds,
    /// Camera-pose capture time in the same clock domain.
    pub pose_time: PhoneNanoseconds,
    /// Maximum admitted difference among sample timestamps.
    pub maximum_time_error: ClockErrorNanoseconds,
    /// Tracking continuity epoch.
    pub tracking_epoch: TrackingEpoch,
    /// Whether this sample establishes relocalization into the scene coordinates.
    pub relocalized: bool,
    /// Camera tracking quality.
    pub tracking_quality: TrackingQuality,
    /// Depth quality.
    pub depth_quality: DepthQuality,
    /// Spatial authority of the label.
    pub scope: LabelScope,
    /// Visibility fraction for each visible labeled person.
    pub person_visibility: Vec<f64>,
    /// Joint person-set label.
    pub label: JointLabel,
    /// Camera-coordinate transform into the referenced scene.
    pub camera_to_world: CoordinateTransform,
    /// Direct source of this sample.
    pub sample_source: SourceIdentity,
    /// Joint sample-level spatial uncertainty in metres.
    pub joint_error_m: f64,
}

/// A bounded sequence of supervision labels with shared provenance and error.
#[derive(Clone, Debug, PartialEq)]
pub struct SupervisionSegment {
    /// Shared immutable identity and provenance.
    pub metadata: ArtifactMetadata,
    /// Scene in whose world coordinates labels are expressed.
    pub scene_digest: ArtifactDigest,
    /// Row-major three-by-three camera intrinsic matrix.
    pub camera_intrinsics: [f64; 9],
    /// Time-ordered supervision samples.
    pub samples: Vec<SupervisionSample>,
    /// Conservative position error shared by the joint labels, in metres.
    pub shared_position_error_m: f64,
    /// Persisted phone-to-Host clock relation used by every sample.
    pub time_relation: PhoneTimeRelation,
    /// Maximum physical person speed used to convert time error to position error.
    pub maximum_person_velocity: MetersPerSecond,
}

/// A decoded spatial artifact.
#[derive(Clone, Debug, PartialEq)]
pub enum Artifact {
    /// Spatial scene snapshot.
    Scene(SceneSnapshot),
    /// RF device and antenna calibration bundle.
    Calibration(CalibrationBundle),
    /// Camera-derived supervision segment.
    Supervision(SupervisionSegment),
}

impl Artifact {
    pub(crate) const fn kind(&self) -> ArtifactKind {
        match self {
            Self::Scene(_) => ArtifactKind::Scene,
            Self::Calibration(_) => ArtifactKind::Calibration,
            Self::Supervision(_) => ArtifactKind::Supervision,
        }
    }

    pub(crate) fn artifact_id(&self) -> &str {
        match self {
            Self::Scene(value) => &value.metadata.artifact_id,
            Self::Calibration(value) => &value.metadata.artifact_id,
            Self::Supervision(value) => &value.metadata.artifact_id,
        }
    }

    pub(crate) const fn revision(&self) -> u32 {
        match self {
            Self::Scene(value) => value.metadata.revision,
            Self::Calibration(value) => value.metadata.revision,
            Self::Supervision(value) => value.metadata.revision,
        }
    }

    pub(crate) fn referenced_scene(&self) -> Option<ArtifactDigest> {
        match self {
            Self::Scene(_) => None,
            Self::Calibration(value) => Some(value.scene_digest),
            Self::Supervision(value) => Some(value.scene_digest),
        }
    }

    pub(crate) fn validate_import(
        &self,
        limits: ArtifactLimits,
        known_rf_identities: &std::collections::BTreeSet<String>,
        now_utc_ns: u64,
    ) -> Result<(), ArtifactImportError> {
        match self {
            Self::Scene(scene) => {
                if scene.geometry.len() > limits.max_geometry_elements {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::LimitExceeded,
                        "scene geometry element limit exceeded",
                    ));
                }
                if scene.map_error_m > limits.max_position_error_m {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "scene error exceeds the conservative position budget",
                    ));
                }
            }
            Self::Calibration(calibration) => {
                if !known_rf_identities.contains(&calibration.rf_device_identity) {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::UnknownRfIdentity,
                        "calibration names an unknown RF identity",
                    ));
                }
                if now_utc_ns < calibration.valid_from_utc.get()
                    || now_utc_ns > calibration.valid_until_utc.get()
                {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::Expired,
                        "calibration is outside its validity interval",
                    ));
                }
                if calibration.max_error_m > limits.max_position_error_m
                    || calibration.world_transform.max_error_m > limits.max_position_error_m
                {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "calibration error exceeds the conservative position budget",
                    ));
                }
                let matrix = &calibration.world_transform.matrix;
                if matrix[12] != 0.0 || matrix[13] != 0.0 || matrix[14] != 0.0 || matrix[15] != 1.0
                {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "coordinate transform is not affine homogeneous",
                    ));
                }
                let determinant = matrix[0] * (matrix[5] * matrix[10] - matrix[6] * matrix[9])
                    - matrix[1] * (matrix[4] * matrix[10] - matrix[6] * matrix[8])
                    + matrix[2] * (matrix[4] * matrix[9] - matrix[5] * matrix[8]);
                if determinant.abs() <= f64::EPSILON {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "coordinate transform is singular",
                    ));
                }
            }
            Self::Supervision(supervision) => {
                if supervision.samples.len() > limits.max_supervision_samples {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::LimitExceeded,
                        "supervision sample limit exceeded",
                    ));
                }
                if supervision.shared_position_error_m > limits.max_position_error_m {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "supervision error exceeds the conservative position budget",
                    ));
                }
                let mut prior_epoch = None;
                for sample in &supervision.samples {
                    if prior_epoch.is_some_and(|epoch| epoch != sample.tracking_epoch)
                        && !sample.relocalized
                    {
                        return Err(ArtifactImportError::new(
                            ArtifactRejectReason::TrackingNotRelocalized,
                            "tracking reset was not relocalized",
                        ));
                    }
                    prior_epoch = Some(sample.tracking_epoch);
                    if let JointLabel::VisibleSet(people) = &sample.label
                        && people.iter().any(|person| {
                            person.max_error_m + supervision.shared_position_error_m
                                > limits.max_position_error_m
                        })
                    {
                        return Err(ArtifactImportError::new(
                            ArtifactRejectReason::InvalidRelation,
                            "supervision error exceeds the conservative position budget",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_against_scene(
        &self,
        scene: &SceneSnapshot,
        limits: ArtifactLimits,
    ) -> Result<(), ArtifactImportError> {
        match self {
            Self::Scene(_) => Ok(()),
            Self::Calibration(calibration) => {
                if calibration.world_transform.target_coordinate_system
                    != scene.world_coordinate_system
                {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "calibration transform target does not match the referenced scene",
                    ));
                }
                if scene.map_error_m
                    + calibration.world_transform.max_error_m
                    + calibration.max_error_m
                    > limits.max_position_error_m()
                {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "combined scene and calibration error exceeds the position budget",
                    ));
                }
                if calibration.ports.len()
                    > usize::from(calibration.array_condition.physical_element_count)
                {
                    return Err(ArtifactImportError::new(
                        ArtifactRejectReason::InvalidRelation,
                        "calibration ports exceed the declared physical array elements",
                    ));
                }
                Ok(())
            }
            Self::Supervision(supervision) => {
                for sample in &supervision.samples {
                    if sample.camera_to_world.target_coordinate_system
                        != scene.world_coordinate_system
                    {
                        return Err(ArtifactImportError::new(
                            ArtifactRejectReason::InvalidRelation,
                            "camera pose target does not match the referenced scene",
                        ));
                    }
                    let relation_error =
                        supervision.time_relation.error_at(sample.pose_time).ok_or_else(|| {
                            ArtifactImportError::new(
                                ArtifactRejectReason::InvalidRelation,
                                "supervision sample is outside the phone time relation",
                            )
                        })?;
                    let time_error_ns = relation_error
                        .get()
                        .checked_add(sample.maximum_time_error.get())
                        .ok_or_else(|| {
                            ArtifactImportError::new(
                                ArtifactRejectReason::InvalidRelation,
                                "supervision time error overflows",
                            )
                        })?;
                    let temporal_error_m = supervision.maximum_person_velocity.get()
                        * (time_error_ns as f64 / 1_000_000_000.0);
                    let individual_error = match &sample.label {
                        JointLabel::VisibleSet(people) => people
                            .iter()
                            .map(|person| person.max_error_m)
                            .reduce(f64::max)
                            .unwrap_or(0.0),
                        JointLabel::Unknown | JointLabel::WholeRoomEmpty => 0.0,
                    };
                    if scene.map_error_m
                        + supervision.shared_position_error_m
                        + sample.camera_to_world.max_error_m
                        + sample.joint_error_m
                        + individual_error
                        + temporal_error_m
                        > limits.max_position_error_m()
                    {
                        return Err(ArtifactImportError::new(
                            ArtifactRejectReason::InvalidRelation,
                            "combined spatial and time uncertainty exceeds the position budget",
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

/// Content digest of one exact sealed artifact byte sequence.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactDigest([u8; DIGEST_BYTES]);

impl ArtifactDigest {
    /// Returns the exact SHA-256 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ArtifactDigest({self})")
    }
}

impl fmt::Display for ArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Canonical immutable bytes for one validated spatial artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedArtifact {
    bytes: Box<[u8]>,
    digest: ArtifactDigest,
}

impl SealedArtifact {
    /// Validates and canonically seals an artifact.
    ///
    /// # Errors
    ///
    /// Returns an error if required identities are empty, numeric values are
    /// non-finite or outside their declared range, or encoded lengths overflow.
    pub fn seal(artifact: Artifact) -> Result<Self, ArtifactError> {
        validate_artifact(&artifact)?;
        let mut payload = Vec::new();
        let kind = match &artifact {
            Artifact::Scene(scene) => {
                encode_scene(&mut payload, scene)?;
                1
            }
            Artifact::Calibration(calibration) => {
                encode_calibration(&mut payload, calibration)?;
                2
            }
            Artifact::Supervision(supervision) => {
                encode_supervision(&mut payload, supervision)?;
                3
            }
        };
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| ArtifactError::new("artifact payload exceeds the format limit"))?;
        if HEADER_BYTES + payload.len() + DIGEST_BYTES > DEFAULT_MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::new("artifact exceeds the format byte limit"));
        }
        let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len() + DIGEST_BYTES);
        bytes.extend_from_slice(ARTIFACT_MAGIC);
        bytes.extend_from_slice(&ARTIFACT_SCHEMA_VERSION.to_le_bytes());
        bytes.push(kind);
        bytes.push(0);
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let digest = ArtifactDigest(Sha256::digest(&bytes).into());
        bytes.extend_from_slice(digest.as_bytes());
        Ok(Self { bytes: bytes.into_boxed_slice(), digest })
    }

    /// Parses and validates an existing sealed artifact envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unsupported, non-canonical, or
    /// digest-mismatched bytes.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, ArtifactError> {
        let bytes = bytes.as_ref();
        if bytes.len() > DEFAULT_MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::new("artifact exceeds the format byte limit"));
        }
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || &bytes[..4] != ARTIFACT_MAGIC
            || u16::from_le_bytes([bytes[4], bytes[5]]) != ARTIFACT_SCHEMA_VERSION
            || bytes[7] != 0
        {
            return Err(ArtifactError::new("artifact schema or envelope is unsupported"));
        }
        let payload_len = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed header width"));
        let expected_len = HEADER_BYTES
            .checked_add(payload_len as usize)
            .and_then(|length| length.checked_add(DIGEST_BYTES))
            .ok_or_else(|| ArtifactError::new("artifact length overflows"))?;
        if bytes.len() != expected_len {
            return Err(ArtifactError::new("artifact envelope length is invalid"));
        }
        let digest_offset = bytes.len() - DIGEST_BYTES;
        let computed = ArtifactDigest(Sha256::digest(&bytes[..digest_offset]).into());
        if bytes[digest_offset..] != computed.0 {
            return Err(ArtifactError::new("artifact digest does not match its bytes"));
        }
        let sealed = Self { bytes: bytes.to_vec().into_boxed_slice(), digest: computed };
        let artifact = sealed.decode()?;
        let canonical = Self::seal(artifact)?;
        if canonical.bytes != sealed.bytes {
            return Err(ArtifactError::new("artifact encoding is not canonical"));
        }
        Ok(sealed)
    }

    /// Returns the exact sealed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the digest of the exact bytes before the appended digest field.
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    /// Decodes the validated artifact content.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained bytes no longer form a valid envelope.
    pub fn decode(&self) -> Result<Artifact, ArtifactError> {
        let payload_end = self.bytes.len() - DIGEST_BYTES;
        let mut reader = Reader::new(&self.bytes[HEADER_BYTES..payload_end]);
        let artifact = match self.bytes[6] {
            1 => Artifact::Scene(decode_scene(&mut reader)?),
            2 => Artifact::Calibration(decode_calibration(&mut reader)?),
            3 => Artifact::Supervision(decode_supervision(&mut reader)?),
            _ => return Err(ArtifactError::new("artifact kind is unsupported")),
        };
        if !reader.is_empty() {
            return Err(ArtifactError::new("artifact payload has trailing bytes"));
        }
        validate_artifact(&artifact)?;
        Ok(artifact)
    }
}

/// Failure to encode, parse, or validate a spatial artifact.
#[derive(Debug)]
pub struct ArtifactError {
    message: &'static str,
    backtrace: Box<Backtrace>,
}

impl ArtifactError {
    fn new(message: &'static str) -> Self {
        Self { message, backtrace: Box::new(Backtrace::capture()) }
    }

    /// Returns the captured construction backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ArtifactError {}

fn validate_artifact(artifact: &Artifact) -> Result<(), ArtifactError> {
    match artifact {
        Artifact::Scene(scene) => {
            validate_metadata(&scene.metadata)?;
            require_text(&scene.world_coordinate_system)?;
            require_unit_interval(scene.scan_coverage)?;
            require_nonnegative_finite(scene.map_error_m)?;
            if scene.geometry.is_empty()
                || scene.geometry_validity_mask.len() != scene.geometry.len()
                || scene.coverage_mask.is_empty()
            {
                return Err(ArtifactError::new("scene geometry and provenance must not be empty"));
            }
            for element in &scene.geometry {
                if element.vertices_m.is_empty()
                    || element.vertices_m.iter().flatten().any(|value| !value.is_finite())
                {
                    return Err(ArtifactError::new("scene geometry must contain finite vertices"));
                }
            }
            if let Some(reference) = &scene.usdz_display_reference {
                require_text(reference)?;
            }
            for cell in &scene.coverage_mask {
                if cell.position_m.iter().any(|value| !value.is_finite()) {
                    return Err(ArtifactError::new("scene coverage positions must be finite"));
                }
            }
            Ok(())
        }
        Artifact::Calibration(calibration) => validate_calibration(calibration),
        Artifact::Supervision(supervision) => validate_supervision(supervision),
    }
}

fn validate_calibration(calibration: &CalibrationBundle) -> Result<(), ArtifactError> {
    validate_metadata(&calibration.metadata)?;
    require_text(&calibration.rf_device_identity)?;
    require_text(&calibration.antenna_reference)?;
    require_text(&calibration.world_transform.source_coordinate_system)?;
    require_text(&calibration.world_transform.target_coordinate_system)?;
    if calibration.world_transform.matrix.iter().any(|value| !value.is_finite()) {
        return Err(ArtifactError::new("coordinate transform must contain finite values"));
    }
    require_nonnegative_finite(calibration.world_transform.max_error_m)?;
    require_nonnegative_finite(calibration.max_error_m)?;
    if calibration.valid_from_utc >= calibration.valid_until_utc {
        return Err(ArtifactError::new("calibration validity interval is empty"));
    }
    if calibration.ports.is_empty() {
        return Err(ArtifactError::new("calibration port conditions must not be empty"));
    }
    require_text(&calibration.array_condition.array_identity)?;
    if calibration.array_condition.physical_element_count == 0 {
        return Err(ArtifactError::new("array physical element count must be non-zero"));
    }
    let mut ports = std::collections::BTreeSet::new();
    for port in &calibration.ports {
        require_text(&port.antenna_identity)?;
        if !ports.insert(port.port) {
            return Err(ArtifactError::new("calibration port conditions must be unique"));
        }
    }
    Ok(())
}

fn validate_supervision(supervision: &SupervisionSegment) -> Result<(), ArtifactError> {
    validate_metadata(&supervision.metadata)?;
    if supervision.camera_intrinsics.iter().any(|value| !value.is_finite()) {
        return Err(ArtifactError::new("camera intrinsics must contain finite values"));
    }
    require_nonnegative_finite(supervision.shared_position_error_m)?;
    if supervision.samples.is_empty() {
        return Err(ArtifactError::new("supervision samples must not be empty"));
    }
    let mut previous_time = None;
    for sample in &supervision.samples {
        require_text(&sample.rgb_reference)?;
        require_text(&sample.pose_reference)?;
        match (&sample.depth_quality, &sample.depth_reference) {
            (DepthQuality::Missing, None) => {}
            (DepthQuality::Measured | DepthQuality::Estimated, Some(reference)) => {
                require_text(reference)?;
            }
            _ => return Err(ArtifactError::new("depth reference and quality are inconsistent")),
        }
        require_text(&sample.sample_source.namespace)?;
        require_text(&sample.sample_source.identity)?;
        require_nonnegative_finite(sample.joint_error_m)?;
        require_text(&sample.camera_to_world.source_coordinate_system)?;
        require_text(&sample.camera_to_world.target_coordinate_system)?;
        if sample.camera_to_world.matrix.iter().any(|value| !value.is_finite()) {
            return Err(ArtifactError::new("camera pose transform must contain finite values"));
        }
        require_nonnegative_finite(sample.camera_to_world.max_error_m)?;
        let minimum = sample.rgb_time.min(sample.depth_time).min(sample.pose_time);
        let maximum = sample.rgb_time.max(sample.depth_time).max(sample.pose_time);
        if maximum.get() - minimum.get() > sample.maximum_time_error.get() {
            return Err(ArtifactError::new("supervision sample times exceed their error bound"));
        }
        if previous_time.is_some_and(|time| sample.pose_time < time) {
            return Err(ArtifactError::new("supervision samples are not time ordered"));
        }
        previous_time = Some(sample.pose_time);
        for visibility in &sample.person_visibility {
            require_unit_interval(*visibility)?;
        }
        match &sample.label {
            JointLabel::Unknown => {
                if !sample.person_visibility.is_empty() {
                    return Err(ArtifactError::new("unknown label cannot name visible people"));
                }
            }
            JointLabel::VisibleSet(people) => {
                if people.len() != sample.person_visibility.len() {
                    return Err(ArtifactError::new("person labels and visibility masks differ"));
                }
                for person in people {
                    require_text(&person.station)?;
                    require_text(&person.pose)?;
                    if person.position_m.iter().any(|value| !value.is_finite()) {
                        return Err(ArtifactError::new("person position must be finite"));
                    }
                    require_nonnegative_finite(person.max_error_m)?;
                }
            }
            JointLabel::WholeRoomEmpty => {
                if sample.scope != LabelScope::WholeRoom || !sample.person_visibility.is_empty() {
                    return Err(ArtifactError::new(
                        "empty-room label requires independently observed whole-room scope",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_metadata(metadata: &ArtifactMetadata) -> Result<(), ArtifactError> {
    require_text(&metadata.artifact_id)?;
    validate_sources(&metadata.provenance)
}

fn require_text(value: &str) -> Result<(), ArtifactError> {
    if value.is_empty() {
        Err(ArtifactError::new("artifact identities and references must not be empty"))
    } else {
        Ok(())
    }
}

fn require_unit_interval(value: f64) -> Result<(), ArtifactError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(ArtifactError::new("artifact fraction must be finite and between zero and one"))
    }
}

fn require_nonnegative_finite(value: f64) -> Result<(), ArtifactError> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(ArtifactError::new("artifact uncertainty must be finite and non-negative"))
    }
}

fn validate_sources(sources: &[SourceIdentity]) -> Result<(), ArtifactError> {
    if sources.is_empty() {
        return Err(ArtifactError::new("artifact provenance must not be empty"));
    }
    for source in sources {
        require_text(&source.namespace)?;
        require_text(&source.identity)?;
    }
    Ok(())
}

fn encode_scene(output: &mut Vec<u8>, scene: &SceneSnapshot) -> Result<(), ArtifactError> {
    encode_metadata(output, &scene.metadata)?;
    put_string(output, &scene.world_coordinate_system)?;
    put_len(output, scene.geometry.len())?;
    for element in &scene.geometry {
        output.push(match element.kind {
            GeometryKind::Wall => 1,
            GeometryKind::Door => 2,
            GeometryKind::Furniture => 3,
        });
        put_len(output, element.vertices_m.len())?;
        for vertex in &element.vertices_m {
            for coordinate in vertex {
                output.extend_from_slice(&coordinate.to_le_bytes());
            }
        }
    }
    put_len(output, scene.geometry_validity_mask.len())?;
    for valid in &scene.geometry_validity_mask {
        output.push(u8::from(*valid));
    }
    put_len(output, scene.coverage_mask.len())?;
    for cell in &scene.coverage_mask {
        for coordinate in cell.position_m {
            output.extend_from_slice(&coordinate.to_le_bytes());
        }
        output.push(u8::from(cell.covered));
    }
    output.extend_from_slice(&scene.scan_coverage.to_le_bytes());
    output.extend_from_slice(&scene.map_error_m.to_le_bytes());
    match &scene.usdz_display_reference {
        Some(reference) => {
            output.push(1);
            put_string(output, reference)?;
        }
        None => output.push(0),
    }
    Ok(())
}

fn decode_scene(reader: &mut Reader<'_>) -> Result<SceneSnapshot, ArtifactError> {
    let metadata = decode_metadata(reader)?;
    let world_coordinate_system = reader.string()?;
    let geometry_len = reader.len()?;
    let mut geometry = Vec::with_capacity(geometry_len);
    for _ in 0..geometry_len {
        let kind = match reader.u8()? {
            1 => GeometryKind::Wall,
            2 => GeometryKind::Door,
            3 => GeometryKind::Furniture,
            _ => return Err(ArtifactError::new("scene geometry kind is unsupported")),
        };
        let vertices_len = reader.len()?;
        let mut vertices_m = Vec::with_capacity(vertices_len);
        for _ in 0..vertices_len {
            vertices_m.push([reader.f64()?, reader.f64()?, reader.f64()?]);
        }
        geometry.push(GeometryElement { kind, vertices_m });
    }
    let validity_len = reader.len()?;
    let mut geometry_validity_mask = Vec::with_capacity(validity_len);
    for _ in 0..validity_len {
        geometry_validity_mask.push(reader.bool()?);
    }
    let coverage_len = reader.len()?;
    let mut coverage_mask = Vec::with_capacity(coverage_len);
    for _ in 0..coverage_len {
        coverage_mask.push(CoverageCell {
            position_m: [reader.f64()?, reader.f64()?, reader.f64()?],
            covered: reader.bool()?,
        });
    }
    let scan_coverage = reader.f64()?;
    let map_error_m = reader.f64()?;
    let usdz_display_reference = match reader.u8()? {
        0 => None,
        1 => Some(reader.string()?),
        _ => return Err(ArtifactError::new("scene display reference marker is invalid")),
    };
    Ok(SceneSnapshot {
        metadata,
        world_coordinate_system,
        geometry,
        geometry_validity_mask,
        coverage_mask,
        scan_coverage,
        map_error_m,
        usdz_display_reference,
    })
}

fn encode_calibration(
    output: &mut Vec<u8>,
    calibration: &CalibrationBundle,
) -> Result<(), ArtifactError> {
    encode_metadata(output, &calibration.metadata)?;
    output.extend_from_slice(calibration.scene_digest.as_bytes());
    put_string(output, &calibration.rf_device_identity)?;
    put_string(output, &calibration.antenna_reference)?;
    put_string(output, &calibration.world_transform.source_coordinate_system)?;
    put_string(output, &calibration.world_transform.target_coordinate_system)?;
    for value in calibration.world_transform.matrix {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output.extend_from_slice(&calibration.world_transform.max_error_m.to_le_bytes());
    put_len(output, calibration.ports.len())?;
    for port in &calibration.ports {
        output.extend_from_slice(&port.port.to_le_bytes());
        put_string(output, &port.antenna_identity)?;
    }
    output.push(match calibration.coherence_scope {
        CoherenceScope::None => 0,
        CoherenceScope::Packet => 1,
        CoherenceScope::CaptureInterval => 2,
    });
    put_string(output, &calibration.array_condition.array_identity)?;
    output.extend_from_slice(&calibration.array_condition.physical_element_count.to_le_bytes());
    output.extend_from_slice(&calibration.calibration_epoch.get().to_le_bytes());
    output.extend_from_slice(&calibration.max_error_m.to_le_bytes());
    output.extend_from_slice(&calibration.valid_from_utc.get().to_le_bytes());
    output.extend_from_slice(&calibration.valid_until_utc.get().to_le_bytes());
    Ok(())
}

fn decode_calibration(reader: &mut Reader<'_>) -> Result<CalibrationBundle, ArtifactError> {
    let metadata = decode_metadata(reader)?;
    let scene_digest = reader.digest()?;
    let rf_device_identity = reader.string()?;
    let antenna_reference = reader.string()?;
    let source_coordinate_system = reader.string()?;
    let target_coordinate_system = reader.string()?;
    let mut matrix = [0.0; 16];
    for value in &mut matrix {
        *value = reader.f64()?;
    }
    let max_transform_error = reader.f64()?;
    let ports_len = reader.len()?;
    let mut ports = Vec::with_capacity(ports_len);
    for _ in 0..ports_len {
        ports.push(PortCondition { port: reader.u16()?, antenna_identity: reader.string()? });
    }
    let coherence_scope = match reader.u8()? {
        0 => CoherenceScope::None,
        1 => CoherenceScope::Packet,
        2 => CoherenceScope::CaptureInterval,
        _ => return Err(ArtifactError::new("calibration phase condition is unsupported")),
    };
    Ok(CalibrationBundle {
        metadata,
        scene_digest,
        rf_device_identity,
        antenna_reference,
        world_transform: CoordinateTransform {
            source_coordinate_system,
            target_coordinate_system,
            matrix,
            max_error_m: max_transform_error,
        },
        ports,
        coherence_scope,
        array_condition: ArrayCondition {
            array_identity: reader.string()?,
            physical_element_count: reader.u16()?,
        },
        calibration_epoch: CalibrationEpoch::new(reader.u32()?),
        max_error_m: reader.f64()?,
        valid_from_utc: reader.u64()?.into(),
        valid_until_utc: reader.u64()?.into(),
    })
}

fn encode_supervision(
    output: &mut Vec<u8>,
    supervision: &SupervisionSegment,
) -> Result<(), ArtifactError> {
    encode_metadata(output, &supervision.metadata)?;
    output.extend_from_slice(supervision.scene_digest.as_bytes());
    for value in supervision.camera_intrinsics {
        output.extend_from_slice(&value.to_le_bytes());
    }
    put_len(output, supervision.samples.len())?;
    for sample in &supervision.samples {
        put_string(output, &sample.rgb_reference)?;
        match &sample.depth_reference {
            Some(reference) => {
                output.push(1);
                put_string(output, reference)?;
            }
            None => output.push(0),
        }
        put_string(output, &sample.pose_reference)?;
        output.extend_from_slice(&sample.rgb_time.get().to_le_bytes());
        output.extend_from_slice(&sample.depth_time.get().to_le_bytes());
        output.extend_from_slice(&sample.pose_time.get().to_le_bytes());
        output.extend_from_slice(&sample.maximum_time_error.get().to_le_bytes());
        output.extend_from_slice(&sample.tracking_epoch.get().to_le_bytes());
        output.push(u8::from(sample.relocalized));
        output.push(match sample.tracking_quality {
            TrackingQuality::Normal => 1,
            TrackingQuality::Limited => 2,
        });
        output.push(match sample.depth_quality {
            DepthQuality::Measured => 1,
            DepthQuality::Estimated => 2,
            DepthQuality::Missing => 3,
        });
        output.push(match sample.scope {
            LabelScope::LocallyVisible => 1,
            LabelScope::WholeRoom => 2,
        });
        put_len(output, sample.person_visibility.len())?;
        for visibility in &sample.person_visibility {
            output.extend_from_slice(&visibility.to_le_bytes());
        }
        match &sample.label {
            JointLabel::Unknown => output.push(0),
            JointLabel::VisibleSet(people) => {
                output.push(1);
                put_len(output, people.len())?;
                for person in people {
                    put_string(output, &person.station)?;
                    put_string(output, &person.pose)?;
                    for coordinate in person.position_m {
                        output.extend_from_slice(&coordinate.to_le_bytes());
                    }
                    output.extend_from_slice(&person.max_error_m.to_le_bytes());
                }
            }
            JointLabel::WholeRoomEmpty => output.push(2),
        }
        encode_transform(output, &sample.camera_to_world)?;
        encode_source(output, &sample.sample_source)?;
        output.extend_from_slice(&sample.joint_error_m.to_le_bytes());
    }
    output.extend_from_slice(&supervision.shared_position_error_m.to_le_bytes());
    encode_time_relation(output, supervision.time_relation);
    output.extend_from_slice(&supervision.maximum_person_velocity.get().to_le_bytes());
    Ok(())
}

fn decode_supervision(reader: &mut Reader<'_>) -> Result<SupervisionSegment, ArtifactError> {
    let metadata = decode_metadata(reader)?;
    let scene_digest = reader.digest()?;
    let mut camera_intrinsics = [0.0; 9];
    for value in &mut camera_intrinsics {
        *value = reader.f64()?;
    }
    let sample_len = reader.len()?;
    let mut samples = Vec::with_capacity(sample_len);
    for _ in 0..sample_len {
        let rgb_reference = reader.string()?;
        let depth_reference = match reader.u8()? {
            0 => None,
            1 => Some(reader.string()?),
            _ => return Err(ArtifactError::new("depth reference marker is invalid")),
        };
        let pose_reference = reader.string()?;
        let rgb_time = reader.u64()?.into();
        let depth_time = reader.u64()?.into();
        let pose_time = reader.u64()?.into();
        let maximum_time_error = reader.u64()?.into();
        let tracking_epoch = reader.u32()?.into();
        let relocalized = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ArtifactError::new("relocalization marker is invalid")),
        };
        let tracking_quality = match reader.u8()? {
            1 => TrackingQuality::Normal,
            2 => TrackingQuality::Limited,
            _ => return Err(ArtifactError::new("tracking quality is unsupported")),
        };
        let depth_quality = match reader.u8()? {
            1 => DepthQuality::Measured,
            2 => DepthQuality::Estimated,
            3 => DepthQuality::Missing,
            _ => return Err(ArtifactError::new("depth quality is unsupported")),
        };
        let scope = match reader.u8()? {
            1 => LabelScope::LocallyVisible,
            2 => LabelScope::WholeRoom,
            _ => return Err(ArtifactError::new("label scope is unsupported")),
        };
        let visibility_len = reader.len()?;
        let mut person_visibility = Vec::with_capacity(visibility_len);
        for _ in 0..visibility_len {
            person_visibility.push(reader.f64()?);
        }
        let label = match reader.u8()? {
            0 => JointLabel::Unknown,
            1 => {
                let people_len = reader.len()?;
                let mut people = Vec::with_capacity(people_len);
                for _ in 0..people_len {
                    people.push(PersonLabel {
                        station: reader.string()?,
                        pose: reader.string()?,
                        position_m: [reader.f64()?, reader.f64()?, reader.f64()?],
                        max_error_m: reader.f64()?,
                    });
                }
                JointLabel::VisibleSet(people)
            }
            2 => JointLabel::WholeRoomEmpty,
            _ => return Err(ArtifactError::new("joint label kind is unsupported")),
        };
        samples.push(SupervisionSample {
            rgb_reference,
            depth_reference,
            pose_reference,
            rgb_time,
            depth_time,
            pose_time,
            maximum_time_error,
            tracking_epoch,
            relocalized,
            tracking_quality,
            depth_quality,
            scope,
            person_visibility,
            label,
            camera_to_world: decode_transform(reader)?,
            sample_source: decode_source(reader)?,
            joint_error_m: reader.f64()?,
        });
    }
    Ok(SupervisionSegment {
        metadata,
        scene_digest,
        camera_intrinsics,
        samples,
        shared_position_error_m: reader.f64()?,
        time_relation: decode_time_relation(reader)?,
        maximum_person_velocity: MetersPerSecond::new(reader.f64()?)?,
    })
}

fn encode_metadata(output: &mut Vec<u8>, metadata: &ArtifactMetadata) -> Result<(), ArtifactError> {
    put_identity(output, &metadata.artifact_id, metadata.revision)?;
    encode_sources(output, &metadata.provenance)
}

fn decode_metadata(reader: &mut Reader<'_>) -> Result<ArtifactMetadata, ArtifactError> {
    let (artifact_id, revision) = reader.identity()?;
    Ok(ArtifactMetadata { artifact_id, revision, provenance: decode_sources(reader)? })
}

fn encode_transform(
    output: &mut Vec<u8>,
    transform: &CoordinateTransform,
) -> Result<(), ArtifactError> {
    put_string(output, &transform.source_coordinate_system)?;
    put_string(output, &transform.target_coordinate_system)?;
    for value in transform.matrix {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output.extend_from_slice(&transform.max_error_m.to_le_bytes());
    Ok(())
}

fn decode_transform(reader: &mut Reader<'_>) -> Result<CoordinateTransform, ArtifactError> {
    let source_coordinate_system = reader.string()?;
    let target_coordinate_system = reader.string()?;
    let mut matrix = [0.0; 16];
    for value in &mut matrix {
        *value = reader.f64()?;
    }
    Ok(CoordinateTransform {
        source_coordinate_system,
        target_coordinate_system,
        matrix,
        max_error_m: reader.f64()?,
    })
}

fn encode_source(output: &mut Vec<u8>, source: &SourceIdentity) -> Result<(), ArtifactError> {
    put_string(output, &source.namespace)?;
    put_string(output, &source.identity)
}

fn decode_source(reader: &mut Reader<'_>) -> Result<SourceIdentity, ArtifactError> {
    Ok(SourceIdentity { namespace: reader.string()?, identity: reader.string()? })
}

fn encode_time_relation(output: &mut Vec<u8>, relation: PhoneTimeRelation) {
    output.extend_from_slice(&relation.relation_id());
    output.extend_from_slice(&relation.offset_at_reference().get().to_le_bytes());
    output.extend_from_slice(&relation.drift_parts_per_billion().to_le_bytes());
    output.extend_from_slice(&relation.reference_phone_time().get().to_le_bytes());
    output.extend_from_slice(&relation.maximum_error().get().to_le_bytes());
    output.extend_from_slice(&relation.valid_from_phone_time().get().to_le_bytes());
    output.extend_from_slice(&relation.valid_until_phone_time().get().to_le_bytes());
}

fn decode_time_relation(reader: &mut Reader<'_>) -> Result<PhoneTimeRelation, ArtifactError> {
    PhoneTimeRelation::new(
        reader.take(16)?.try_into().expect("fixed relation identity width"),
        i64::from_le_bytes(reader.take(8)?.try_into().expect("fixed i64 width")).into(),
        i64::from_le_bytes(reader.take(8)?.try_into().expect("fixed i64 width")),
        reader.u64()?.into(),
        reader.u64()?.into(),
        reader.u64()?.into(),
        reader.u64()?.into(),
    )
}

fn put_identity(output: &mut Vec<u8>, id: &str, revision: u32) -> Result<(), ArtifactError> {
    put_string(output, id)?;
    output.extend_from_slice(&revision.to_le_bytes());
    Ok(())
}

fn encode_sources(output: &mut Vec<u8>, sources: &[SourceIdentity]) -> Result<(), ArtifactError> {
    put_len(output, sources.len())?;
    for source in sources {
        put_string(output, &source.namespace)?;
        put_string(output, &source.identity)?;
    }
    Ok(())
}

fn decode_sources(reader: &mut Reader<'_>) -> Result<Vec<SourceIdentity>, ArtifactError> {
    let len = reader.len()?;
    let mut sources = Vec::with_capacity(len);
    for _ in 0..len {
        sources.push(SourceIdentity { namespace: reader.string()?, identity: reader.string()? });
    }
    Ok(sources)
}

fn put_len(output: &mut Vec<u8>, value: usize) -> Result<(), ArtifactError> {
    if value > MAX_ENCODED_COLLECTION_ITEMS {
        return Err(ArtifactError::new("artifact collection exceeds the format limit"));
    }
    let value = u32::try_from(value)
        .map_err(|_| ArtifactError::new("artifact collection exceeds the format limit"))?;
    output.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), ArtifactError> {
    put_len(output, value.len())?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ArtifactError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| ArtifactError::new("artifact field length overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ArtifactError::new("artifact payload is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ArtifactError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, ArtifactError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ArtifactError::new("artifact boolean marker is invalid")),
        }
    }

    fn u32(&mut self) -> Result<u32, ArtifactError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed u32 width")))
    }

    fn u16(&mut self) -> Result<u16, ArtifactError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed u16 width")))
    }

    fn u64(&mut self) -> Result<u64, ArtifactError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed u64 width")))
    }

    fn len(&mut self) -> Result<usize, ArtifactError> {
        let value = self.u32()? as usize;
        if value > MAX_ENCODED_COLLECTION_ITEMS || value > self.bytes.len() {
            return Err(ArtifactError::new("artifact collection length exceeds its bound"));
        }
        Ok(value)
    }

    fn f64(&mut self) -> Result<f64, ArtifactError> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().expect("fixed f64 width")))
    }

    fn string(&mut self) -> Result<String, ArtifactError> {
        let len = self.len()?;
        std::str::from_utf8(self.take(len)?)
            .map(str::to_owned)
            .map_err(|_| ArtifactError::new("artifact text is not UTF-8"))
    }

    fn digest(&mut self) -> Result<ArtifactDigest, ArtifactError> {
        Ok(ArtifactDigest(self.take(DIGEST_BYTES)?.try_into().expect("fixed digest width")))
    }

    fn identity(&mut self) -> Result<(String, u32), ArtifactError> {
        Ok((self.string()?, self.u32()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
