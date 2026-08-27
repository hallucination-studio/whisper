//! Stable knowledge, baseline, evidence, and world-snapshot values.

use std::collections::BTreeMap;

use serde::Serialize;

use super::csi::{CaptureProfileId, CsiPath, CsiSampleCoordinate};
use super::identity::{
    AlgorithmVersion, BaselineContractId, BaselineRevision, BaselineStateSequence,
    BuildFingerprint, ConditioningVersion, DecoderVersion, DeploymentId, LinkProfileKey,
    RadioLinkId, SensorId, SessionId, SnapshotId, SpaceId, StreamInstanceId, WindowId,
};
use super::time::{TimeInterval, TimeQuality};

/// A value that explicitly records the boundary of current knowledge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Knowledge<T> {
    /// Evidence was sufficient to establish a value.
    Known(T),
    /// Evidence was insufficient, with a typed reason.
    Unknown {
        /// Typed reason for insufficient knowledge.
        reason: UnknownReason,
    },
}

impl<T> Knowledge<T> {
    /// Wraps a known value.
    #[must_use]
    pub const fn known(value: T) -> Self {
        Self::Known(value)
    }

    /// Creates an unknown value with an explicit reason.
    #[must_use]
    pub const fn unknown(reason: UnknownReason) -> Self {
        Self::Unknown { reason }
    }

    /// Returns a borrowed known value, if present.
    #[must_use]
    pub const fn as_known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown { .. } => None,
        }
    }

    /// Returns the unknown reason, if the value is unknown.
    #[must_use]
    pub const fn unknown_reason(&self) -> Option<&UnknownReason> {
        match self {
            Self::Known(_) => None,
            Self::Unknown { reason } => Some(reason),
        }
    }
}

/// Reasons why a world value cannot currently be known.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum UnknownReason {
    /// A baseline has not been started.
    BaselineMissing,
    /// A baseline is still learning and has not been committed.
    BaselineLearning,
    /// No eligible physical link covered the space.
    InsufficientCoverage,
    /// Evidence did not satisfy a quality predicate.
    LowQuality,
    /// Evidence lies between configured stable/change thresholds.
    AmbiguousEvidence,
    /// Event-time uncertainty exceeded the contract.
    TimeUncertain,
    /// Required samples were missing.
    MissingData,
    /// The profile does not match the active contract.
    ProfileMismatch,
    /// The baseline became too old or incompatible with the active contract.
    Stale,
    /// The baseline was explicitly frozen.
    Frozen,
    /// The stream is inactive.
    Inactive,
    /// A value was not finite or ordered.
    NonFinite,
}

/// The two semantic link states produced by a baseline decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum StableOrChanging {
    /// Residual evidence is below the stable threshold.
    Stable,
    /// Residual evidence is above the changing threshold.
    Changing,
}

/// Typed reasons for a baseline becoming stale.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum BaselineStaleReason {
    /// The active revision exceeded its configured age.
    Age,
    /// A compatible contract was no longer available.
    Incompatible,
}

/// Baseline lifecycle state, without estimator behavior.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum BaselineStatus {
    /// No learning revision exists.
    Missing,
    /// A revision is learning and remains non-authoritative.
    Learning {
        /// Number of quality-accepted windows.
        accepted_windows: u64,
        /// Whether configured maturity predicates are met.
        mature: bool,
    },
    /// A committed revision is active.
    Active {
        /// Immutable baseline revision.
        revision: BaselineRevision,
        /// Mutable state sequence within the revision.
        state_sequence: BaselineStateSequence,
    },
    /// Updates are explicitly disabled for this revision.
    Frozen {
        /// Immutable revision retained while adaptation is disabled.
        revision: BaselineRevision,
    },
    /// A revision cannot be used without an explicit lifecycle command.
    Stale {
        /// Revision that became stale.
        revision: BaselineRevision,
        /// Why the revision became stale.
        reason: BaselineStaleReason,
    },
}

/// Baseline lifecycle commands persisted in session order.
#[expect(dead_code, reason = "consumed by work-package 2.1 session records and 3.3 estimator")]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum BaselineCommand {
    /// Start a new learning revision.
    BeginLearning,
    /// Commit a mature learning revision.
    Commit,
    /// Stop adaptation while retaining the revision.
    Freeze,
    /// Re-arm a compatible stale/frozen revision.
    Resume,
    /// Install a complete immutable baseline snapshot.
    ActivateSnapshot {
        /// Complete immutable baseline payload to install.
        snapshot: BaselineSnapshot,
    },
}

/// A command targeted at one link/profile baseline.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TargetedBaselineCommand {
    target: LinkProfileKey,
    command: BaselineCommand,
}

#[expect(dead_code, reason = "consumed by work-package 2.1 session records and 3.3 estimator")]
impl TargetedBaselineCommand {
    /// Creates a targeted command.
    #[must_use]
    pub fn new(target: LinkProfileKey, command: BaselineCommand) -> Self {
        Self { target, command }
    }

    /// Returns the target key.
    #[must_use]
    pub const fn target(&self) -> &LinkProfileKey {
        &self.target
    }

    /// Returns the lifecycle command.
    #[must_use]
    pub const fn command(&self) -> &BaselineCommand {
        &self.command
    }
}

/// One persisted coordinate statistic in an immutable baseline snapshot.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BaselineCoordinate {
    /// Native path coordinate.
    path: CsiPath,
    /// Native sample coordinate.
    coordinate: CsiSampleCoordinate,
    /// Number of accepted samples.
    count: u64,
    /// Welford mean in log-amplitude units.
    mean: f64,
    /// Population/sample variance estimate in log-amplitude units squared.
    variance: f64,
    /// Accepted exposure in nanoseconds.
    accepted_exposure_ns: u64,
}

impl BaselineCoordinate {
    /// Validates one coordinate statistic.
    pub fn try_new(
        path: CsiPath,
        coordinate: CsiSampleCoordinate,
        count: u64,
        mean: f64,
        variance: f64,
        accepted_exposure_ns: u64,
    ) -> Result<Self, WorldValueError> {
        if !mean.is_finite() || !variance.is_finite() {
            return Err(WorldValueError::NonFiniteStatistic { path, coordinate });
        }
        if variance < 0.0 {
            return Err(WorldValueError::NegativeVariance { path, coordinate });
        }
        if count < 2 || accepted_exposure_ns == 0 {
            return Err(WorldValueError::EmptyBaselineCoordinate { path, coordinate });
        }
        Ok(Self { path, coordinate, count, mean, variance, accepted_exposure_ns })
    }

    /// Returns the native path.
    #[must_use]
    pub const fn path(&self) -> CsiPath {
        self.path
    }

    /// Returns the native sample coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> CsiSampleCoordinate {
        self.coordinate
    }

    /// Returns the accepted sample count.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the Welford mean.
    #[must_use]
    pub const fn mean(&self) -> f64 {
        self.mean
    }

    /// Returns variance.
    #[must_use]
    pub const fn variance(&self) -> f64 {
        self.variance
    }

    /// Returns accepted exposure in nanoseconds.
    #[must_use]
    pub const fn accepted_exposure_ns(&self) -> u64 {
        self.accepted_exposure_ns
    }
}

/// Errors found while constructing immutable baseline values.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum WorldValueError {
    /// A statistic was NaN or infinite.
    #[error("baseline statistic for {path:?}/{coordinate:?} is not finite")]
    NonFiniteStatistic {
        /// Native path coordinate.
        path: CsiPath,
        /// Native sample coordinate.
        coordinate: CsiSampleCoordinate,
    },
    /// A variance cannot be negative.
    #[error("baseline variance for {path:?}/{coordinate:?} is negative")]
    NegativeVariance {
        /// Native path coordinate.
        path: CsiPath,
        /// Native sample coordinate.
        coordinate: CsiSampleCoordinate,
    },
    /// A persisted coordinate had fewer than two accepted samples or no exposure.
    #[error(
        "baseline coordinate {path:?}/{coordinate:?} must have at least two samples and exposure"
    )]
    EmptyBaselineCoordinate {
        /// Native path coordinate.
        path: CsiPath,
        /// Native sample coordinate.
        coordinate: CsiSampleCoordinate,
    },
    /// A baseline snapshot had no coordinate statistics.
    #[error("baseline snapshot must contain at least one coordinate")]
    EmptyBaselineSnapshot,
    /// A coordinate appeared twice or was out of stable order.
    #[error("baseline coordinates must be strictly ordered and unique")]
    UnorderedCoordinates,
    /// A snapshot identity does not match its source receipt.
    #[error("snapshot identity does not match its source receipt")]
    InvalidSnapshotIdentity,
    /// A predecessor snapshot does not precede the current snapshot in the same session.
    #[error("previous snapshot identity must share the session and precede the current window")]
    InvalidPreviousSnapshotIdentity,
    /// A receipt's record bounds are not monotonic.
    #[error("receipt record bounds must satisfy first <= last <= durable")]
    InvalidReceiptOrder,
    /// An evidence receipt's record bounds are not monotonic.
    #[error("evidence record bounds must satisfy first <= last")]
    InvalidEvidenceReceiptOrder,
    /// A baseline state sequence was supplied without a baseline revision.
    #[error("baseline state sequences require a baseline revision")]
    BaselineSequenceRequiresRevision,
    /// A resulting baseline state sequence was supplied without a scored sequence.
    #[error("a resulting baseline state sequence requires a scored sequence")]
    ResultingSequenceRequiresScored,
    /// A resulting baseline state sequence precedes the scored sequence.
    #[error("resulting baseline state sequence {resulting} precedes scored sequence {scored}")]
    BaselineSequenceReversed {
        /// Sequence used for scoring.
        scored: u64,
        /// Sequence after the update.
        resulting: u64,
    },
    /// An optional coordinate evidence value was not finite.
    #[error("coordinate evidence value {field} must be finite")]
    NonFiniteEvidence {
        /// Evidence field containing the non-finite value.
        field: &'static str,
    },
    /// A diagnostic score was not finite or non-negative.
    #[error("link diagnostic {field} must be finite and non-negative")]
    InvalidDiagnostic {
        /// Diagnostic field that violated the value contract.
        field: &'static str,
    },
    /// A link/profile stream key did not match its evidence key.
    #[error("stream link/profile identity does not match evidence link/profile key")]
    StreamLinkProfileMismatch,
    /// Coordinate evidence was not strictly ordered and unique.
    #[error("coordinate evidence must be strictly ordered and unique")]
    UnorderedEvidenceCoordinates,
    /// No capture profiles were supplied for a link contribution.
    #[error("link contribution requires at least one capture profile")]
    EmptyProfiles,
    /// Capture profiles were not strictly ordered and unique.
    #[error("link contribution profiles must be strictly ordered and unique")]
    UnorderedProfiles,
    /// Link contributions were not strictly ordered and unique.
    #[error("space contributions must be strictly ordered and unique")]
    UnorderedContributions,
    /// A residual statistic is not finite or non-negative.
    #[error("residual statistic {field} must be finite and non-negative")]
    InvalidResidual {
        /// Residual field that violated the finite/non-negative contract.
        field: &'static str,
    },
    /// A quality fraction is not finite or outside 0..=1.
    #[error("quality fraction {field} must be finite and within 0..=1")]
    InvalidFraction {
        /// Fraction field that violated the finite range contract.
        field: &'static str,
    },
    /// A world interval was reversed.
    #[error(transparent)]
    Time(#[from] super::time::TimeError),
}

fn validate_baseline_sequences(
    baseline_revision: Option<BaselineRevision>,
    scored: Option<BaselineStateSequence>,
    resulting: Option<BaselineStateSequence>,
) -> Result<(), WorldValueError> {
    if baseline_revision.is_none() && (scored.is_some() || resulting.is_some()) {
        return Err(WorldValueError::BaselineSequenceRequiresRevision);
    }
    if scored.is_none() && resulting.is_some() {
        return Err(WorldValueError::ResultingSequenceRequiresScored);
    }
    if let (Some(scored), Some(resulting)) = (scored, resulting)
        && resulting.get() < scored.get()
    {
        return Err(WorldValueError::BaselineSequenceReversed {
            scored: scored.get(),
            resulting: resulting.get(),
        });
    }
    Ok(())
}

/// A complete immutable baseline revision payload.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BaselineSnapshot {
    deployment: DeploymentId,
    space: SpaceId,
    key: LinkProfileKey,
    conditioning_version: ConditioningVersion,
    revision: BaselineRevision,
    contract: BaselineContractId,
    coordinates: Box<[BaselineCoordinate]>,
}

impl BaselineSnapshot {
    /// Validates and creates a baseline snapshot.
    pub fn try_new(
        deployment: DeploymentId,
        space: SpaceId,
        key: LinkProfileKey,
        conditioning_version: ConditioningVersion,
        revision: BaselineRevision,
        contract: BaselineContractId,
        coordinates: impl Into<Box<[BaselineCoordinate]>>,
    ) -> Result<Self, WorldValueError> {
        let coordinates = coordinates.into();
        if coordinates.is_empty() {
            return Err(WorldValueError::EmptyBaselineSnapshot);
        }
        let mut previous: Option<(CsiPath, CsiSampleCoordinate)> = None;
        for coordinate in &coordinates {
            if coordinate.count < 2 || coordinate.accepted_exposure_ns == 0 {
                return Err(WorldValueError::EmptyBaselineCoordinate {
                    path: coordinate.path,
                    coordinate: coordinate.coordinate,
                });
            }
            if !coordinate.mean.is_finite() || !coordinate.variance.is_finite() {
                return Err(WorldValueError::NonFiniteStatistic {
                    path: coordinate.path,
                    coordinate: coordinate.coordinate,
                });
            }
            if coordinate.variance < 0.0 {
                return Err(WorldValueError::NegativeVariance {
                    path: coordinate.path,
                    coordinate: coordinate.coordinate,
                });
            }
            let key = (coordinate.path, coordinate.coordinate);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(WorldValueError::UnorderedCoordinates);
            }
            previous = Some(key);
        }
        Ok(Self { deployment, space, key, conditioning_version, revision, contract, coordinates })
    }

    /// Returns the immutable revision.
    #[must_use]
    pub const fn revision(&self) -> BaselineRevision {
        self.revision
    }

    /// Returns the deployment identity.
    #[must_use]
    pub const fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// Returns the space identity.
    #[must_use]
    pub const fn space(&self) -> &SpaceId {
        &self.space
    }

    /// Returns the link/profile compatibility key.
    #[must_use]
    pub const fn key(&self) -> &LinkProfileKey {
        &self.key
    }

    /// Returns the conditioning version.
    #[must_use]
    pub const fn conditioning_version(&self) -> &ConditioningVersion {
        &self.conditioning_version
    }

    /// Returns the baseline contract identity.
    #[must_use]
    pub const fn contract(&self) -> BaselineContractId {
        self.contract
    }

    /// Returns persisted coordinate statistics in stable order.
    #[must_use]
    pub fn coordinates(&self) -> &[BaselineCoordinate] {
        &self.coordinates
    }
}

/// The reason a coordinate or link was excluded from evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ExclusionReason {
    /// The protocol marked the sample invalid.
    InvalidSample,
    /// No sample covered the coordinate.
    Missing,
    /// Coverage was below the configured threshold.
    LowCoverage,
    /// Phase was not supported by the active recipe.
    UnsupportedPhase,
    /// The frame arrived after the window was published.
    Late,
    /// The profile did not match the active contract.
    ProfileMismatch,
    /// Time quality or ordering was insufficient.
    TimeUncertain,
    /// A value was non-finite.
    NonFinite,
    /// A source sequence gap was present.
    Gap,
    /// The source could not be resolved to one transmitter.
    UnresolvedSource,
    /// A quality conjunction failed.
    Quality,
}

/// A compact residual summary attached to evidence.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ResidualSummary {
    /// Number of finite residuals.
    count: u32,
    /// Mean absolute standardized residual.
    mean_absolute: f64,
    /// Configured nearest-rank residual score.
    quantile: f64,
}

impl ResidualSummary {
    /// Validates a residual summary.
    pub fn try_new(count: u32, mean_absolute: f64, quantile: f64) -> Result<Self, WorldValueError> {
        if !mean_absolute.is_finite() || mean_absolute < 0.0 {
            return Err(WorldValueError::InvalidResidual { field: "mean_absolute" });
        }
        if !quantile.is_finite() || quantile < 0.0 {
            return Err(WorldValueError::InvalidResidual { field: "quantile" });
        }
        Ok(Self { count, mean_absolute, quantile })
    }

    /// Returns the finite residual count.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Returns mean absolute residual.
    #[must_use]
    pub const fn mean_absolute(self) -> f64 {
        self.mean_absolute
    }

    /// Returns nearest-rank quantile score.
    #[must_use]
    pub const fn quantile(self) -> f64 {
        self.quantile
    }
}

/// Every quality predicate and its measured values for one link/profile.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LinkQuality {
    /// Number of frames used by the window.
    frame_count: u32,
    /// Fraction of ready coordinates covered by valid data.
    ready_coordinate_coverage: f64,
    /// Fraction of the interval exposed to packet gaps.
    packet_gap_ratio: f64,
    /// Receive-time jitter in nanoseconds.
    receive_jitter_ns: u64,
    /// Whether used values and timestamps were finite and ordered.
    finite_and_ordered: bool,
    /// Event-time source quality.
    time_quality: TimeQuality,
    /// Whether source/link/profile resolution succeeded.
    resolved_and_compatible: bool,
    /// Reasons for rejection, if any.
    exclusions: Box<[ExclusionReason]>,
}

impl LinkQuality {
    /// Validates quality fractions and finite measurements.
    #[expect(clippy::too_many_arguments, reason = "the quality value is a fixed contract record")]
    pub fn try_new(
        frame_count: u32,
        ready_coordinate_coverage: f64,
        packet_gap_ratio: f64,
        receive_jitter_ns: u64,
        finite_and_ordered: bool,
        time_quality: TimeQuality,
        resolved_and_compatible: bool,
        exclusions: impl Into<Box<[ExclusionReason]>>,
    ) -> Result<Self, WorldValueError> {
        if !ready_coordinate_coverage.is_finite()
            || !(0.0..=1.0).contains(&ready_coordinate_coverage)
            || !packet_gap_ratio.is_finite()
            || !(0.0..=1.0).contains(&packet_gap_ratio)
        {
            return Err(WorldValueError::InvalidFraction {
                field: "ready_coordinate_coverage or packet_gap_ratio",
            });
        }
        Ok(Self {
            frame_count,
            ready_coordinate_coverage,
            packet_gap_ratio,
            receive_jitter_ns,
            finite_and_ordered,
            time_quality,
            resolved_and_compatible,
            exclusions: exclusions.into(),
        })
    }

    /// Returns the frame count.
    #[must_use]
    pub const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Returns ready-coordinate coverage.
    #[must_use]
    pub const fn ready_coordinate_coverage(&self) -> f64 {
        self.ready_coordinate_coverage
    }

    /// Returns packet gap ratio.
    #[must_use]
    pub const fn packet_gap_ratio(&self) -> f64 {
        self.packet_gap_ratio
    }

    /// Returns receive jitter in nanoseconds.
    #[must_use]
    pub const fn receive_jitter_ns(&self) -> u64 {
        self.receive_jitter_ns
    }

    /// Returns whether values and times were finite and ordered.
    #[must_use]
    pub const fn finite_and_ordered(&self) -> bool {
        self.finite_and_ordered
    }

    /// Returns the event-time quality.
    #[must_use]
    pub const fn time_quality(&self) -> TimeQuality {
        self.time_quality
    }

    /// Returns source/link/profile resolution status.
    #[must_use]
    pub const fn resolved_and_compatible(&self) -> bool {
        self.resolved_and_compatible
    }

    /// Returns quality exclusions.
    #[must_use]
    pub fn exclusions(&self) -> &[ExclusionReason] {
        &self.exclusions
    }
}

/// Per-coordinate evidence from a predict/score/gate step.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CoordinateEvidence {
    /// Native path coordinate.
    path: CsiPath,
    /// Native sample coordinate.
    coordinate: CsiSampleCoordinate,
    /// Observed window mean, when included.
    observed: Option<f64>,
    /// Pre-update baseline prediction, when available.
    predicted: Option<f64>,
    /// Signed log-amplitude residual.
    signed_residual_log_amplitude: Option<f64>,
    /// Standardized pre-update residual.
    standardized_residual: Option<f64>,
    /// Explicit exclusion, if this coordinate did not participate.
    exclusion: Option<ExclusionReason>,
}

impl CoordinateEvidence {
    /// Creates coordinate evidence after checking every optional numeric value.
    pub fn try_new(
        path: CsiPath,
        coordinate: CsiSampleCoordinate,
        observed: Option<f64>,
        predicted: Option<f64>,
        signed_residual_log_amplitude: Option<f64>,
        standardized_residual: Option<f64>,
        exclusion: Option<ExclusionReason>,
    ) -> Result<Self, WorldValueError> {
        for (field, value) in [
            ("observed", observed),
            ("predicted", predicted),
            ("signed_residual_log_amplitude", signed_residual_log_amplitude),
            ("standardized_residual", standardized_residual),
        ] {
            if value.is_some_and(|value| !value.is_finite()) {
                return Err(WorldValueError::NonFiniteEvidence { field });
            }
        }
        Ok(Self {
            path,
            coordinate,
            observed,
            predicted,
            signed_residual_log_amplitude,
            standardized_residual,
            exclusion,
        })
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 estimator/evidence")]
impl CoordinateEvidence {
    pub(crate) const fn path(&self) -> CsiPath {
        self.path
    }

    pub(crate) const fn coordinate(&self) -> CsiSampleCoordinate {
        self.coordinate
    }

    pub(crate) const fn observed(&self) -> Option<f64> {
        self.observed
    }

    pub(crate) const fn predicted(&self) -> Option<f64> {
        self.predicted
    }

    pub(crate) const fn signed_residual_log_amplitude(&self) -> Option<f64> {
        self.signed_residual_log_amplitude
    }

    pub(crate) const fn standardized_residual(&self) -> Option<f64> {
        self.standardized_residual
    }

    pub(crate) const fn exclusion(&self) -> Option<ExclusionReason> {
        self.exclusion
    }
}

/// A link/profile-level evidence record.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EvidenceReceipt {
    /// Source session.
    session_id: SessionId,
    /// First source record represented.
    first_record_seq: u64,
    /// Last source record represented.
    last_record_seq: u64,
    /// Physical link.
    link: RadioLinkId,
    /// Capture profile.
    profile: CaptureProfileId,
    /// Conditioning version.
    conditioning_version: ConditioningVersion,
    /// Residual contract.
    baseline_contract: BaselineContractId,
    /// Baseline revision used for scoring.
    baseline_revision: Option<BaselineRevision>,
    /// State sequence used for scoring.
    scored_against_baseline_state_sequence: Option<BaselineStateSequence>,
    /// State sequence after an accepted update.
    resulting_baseline_state_sequence: Option<BaselineStateSequence>,
    /// Compact residual statistics.
    residual_summary: Option<ResidualSummary>,
    /// Number of included coordinates.
    included_coordinates: u32,
    /// Exclusion counts by reason.
    excluded: BTreeMap<ExclusionReason, u32>,
}

impl EvidenceReceipt {
    /// Creates an evidence receipt after checking record and baseline sequence order.
    #[expect(
        clippy::too_many_arguments,
        reason = "the receipt records one complete link evidence contract"
    )]
    pub fn try_new(
        session_id: SessionId,
        first_record_seq: u64,
        last_record_seq: u64,
        link: RadioLinkId,
        profile: CaptureProfileId,
        conditioning_version: ConditioningVersion,
        baseline_contract: BaselineContractId,
        baseline_revision: Option<BaselineRevision>,
        scored_against_baseline_state_sequence: Option<BaselineStateSequence>,
        resulting_baseline_state_sequence: Option<BaselineStateSequence>,
        residual_summary: Option<ResidualSummary>,
        included_coordinates: u32,
        excluded: BTreeMap<ExclusionReason, u32>,
    ) -> Result<Self, WorldValueError> {
        if first_record_seq > last_record_seq {
            return Err(WorldValueError::InvalidEvidenceReceiptOrder);
        }
        validate_baseline_sequences(
            baseline_revision,
            scored_against_baseline_state_sequence,
            resulting_baseline_state_sequence,
        )?;
        Ok(Self {
            session_id,
            first_record_seq,
            last_record_seq,
            link,
            profile,
            conditioning_version,
            baseline_contract,
            baseline_revision,
            scored_against_baseline_state_sequence,
            resulting_baseline_state_sequence,
            residual_summary,
            included_coordinates,
            excluded,
        })
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 estimator/evidence")]
impl EvidenceReceipt {
    pub(crate) const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(crate) const fn first_record_seq(&self) -> u64 {
        self.first_record_seq
    }

    pub(crate) const fn last_record_seq(&self) -> u64 {
        self.last_record_seq
    }

    pub(crate) const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    pub(crate) const fn profile(&self) -> CaptureProfileId {
        self.profile
    }

    pub(crate) const fn conditioning_version(&self) -> &ConditioningVersion {
        &self.conditioning_version
    }

    pub(crate) const fn baseline_contract(&self) -> BaselineContractId {
        self.baseline_contract
    }

    pub(crate) const fn baseline_revision(&self) -> Option<BaselineRevision> {
        self.baseline_revision
    }

    pub(crate) const fn scored_against_baseline_state_sequence(
        &self,
    ) -> Option<BaselineStateSequence> {
        self.scored_against_baseline_state_sequence
    }

    pub(crate) const fn resulting_baseline_state_sequence(&self) -> Option<BaselineStateSequence> {
        self.resulting_baseline_state_sequence
    }

    pub(crate) const fn residual_summary(&self) -> Option<ResidualSummary> {
        self.residual_summary
    }

    pub(crate) const fn included_coordinates(&self) -> u32 {
        self.included_coordinates
    }

    pub(crate) fn excluded(&self) -> &BTreeMap<ExclusionReason, u32> {
        &self.excluded
    }
}

/// Diagnostics that remain meaningful even when a status is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct LinkDiagnostics {
    /// Nearest-rank standardized residual score.
    deviation_score: f64,
    /// Temporal absolute slope in log-amplitude/second.
    rf_dynamics_log_amplitude_per_second: f64,
    /// Residual summary.
    prediction_error_summary: ResidualSummary,
}

impl LinkDiagnostics {
    /// Creates link diagnostics after checking both score values.
    pub fn try_new(
        deviation_score: f64,
        rf_dynamics_log_amplitude_per_second: f64,
        prediction_error_summary: ResidualSummary,
    ) -> Result<Self, WorldValueError> {
        for (field, value) in [
            ("deviation_score", deviation_score),
            ("rf_dynamics_log_amplitude_per_second", rf_dynamics_log_amplitude_per_second),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(WorldValueError::InvalidDiagnostic { field });
            }
        }
        Ok(Self { deviation_score, rf_dynamics_log_amplitude_per_second, prediction_error_summary })
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 estimator/evidence")]
impl LinkDiagnostics {
    pub(crate) const fn deviation_score(&self) -> f64 {
        self.deviation_score
    }

    pub(crate) const fn rf_dynamics_log_amplitude_per_second(&self) -> f64 {
        self.rf_dynamics_log_amplitude_per_second
    }

    pub(crate) const fn prediction_error_summary(&self) -> ResidualSummary {
        self.prediction_error_summary
    }
}

/// The evidence emitted for one stream by a future estimator step.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LinkStepEvidence {
    /// Stream whose window was scored.
    stream: StreamInstanceId,
    /// Link/profile baseline key.
    link_profile: LinkProfileKey,
    /// Baseline contract.
    baseline_contract: BaselineContractId,
    /// Baseline revision used for scoring.
    baseline_revision: Option<BaselineRevision>,
    /// State sequence used for scoring.
    scored_against_baseline_state_sequence: Option<BaselineStateSequence>,
    /// State sequence after update.
    resulting_baseline_state_sequence: Option<BaselineStateSequence>,
    /// Lifecycle decision.
    baseline_decision: BaselineDecision,
    /// Link status.
    link_status: Knowledge<StableOrChanging>,
    /// Quality conjunction.
    quality: LinkQuality,
    /// Per-coordinate evidence in stable order.
    coordinates: Vec<CoordinateEvidence>,
}

impl LinkStepEvidence {
    /// Creates link-step evidence after checking identity, sequence, and coordinate order.
    #[expect(
        clippy::too_many_arguments,
        reason = "the evidence record contains one complete scored-window contract"
    )]
    pub fn try_new(
        stream: StreamInstanceId,
        link_profile: LinkProfileKey,
        baseline_contract: BaselineContractId,
        baseline_revision: Option<BaselineRevision>,
        scored_against_baseline_state_sequence: Option<BaselineStateSequence>,
        resulting_baseline_state_sequence: Option<BaselineStateSequence>,
        baseline_decision: BaselineDecision,
        link_status: Knowledge<StableOrChanging>,
        quality: LinkQuality,
        coordinates: impl Into<Vec<CoordinateEvidence>>,
    ) -> Result<Self, WorldValueError> {
        if stream.key().link() != link_profile.link()
            || stream.key().profile() != link_profile.profile()
        {
            return Err(WorldValueError::StreamLinkProfileMismatch);
        }
        validate_baseline_sequences(
            baseline_revision,
            scored_against_baseline_state_sequence,
            resulting_baseline_state_sequence,
        )?;
        let coordinates = coordinates.into();
        let mut previous: Option<(CsiPath, CsiSampleCoordinate)> = None;
        for coordinate in &coordinates {
            let current = (coordinate.path, coordinate.coordinate);
            if previous.is_some_and(|prior| prior >= current) {
                return Err(WorldValueError::UnorderedEvidenceCoordinates);
            }
            previous = Some(current);
        }
        Ok(Self {
            stream,
            link_profile,
            baseline_contract,
            baseline_revision,
            scored_against_baseline_state_sequence,
            resulting_baseline_state_sequence,
            baseline_decision,
            link_status,
            quality,
            coordinates,
        })
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 estimator/evidence")]
impl LinkStepEvidence {
    pub(crate) const fn stream(&self) -> &StreamInstanceId {
        &self.stream
    }

    pub(crate) const fn link_profile(&self) -> &LinkProfileKey {
        &self.link_profile
    }

    pub(crate) const fn baseline_contract(&self) -> BaselineContractId {
        self.baseline_contract
    }

    pub(crate) const fn baseline_revision(&self) -> Option<BaselineRevision> {
        self.baseline_revision
    }

    pub(crate) const fn scored_against_baseline_state_sequence(
        &self,
    ) -> Option<BaselineStateSequence> {
        self.scored_against_baseline_state_sequence
    }

    pub(crate) const fn resulting_baseline_state_sequence(&self) -> Option<BaselineStateSequence> {
        self.resulting_baseline_state_sequence
    }

    pub(crate) const fn baseline_decision(&self) -> &BaselineDecision {
        &self.baseline_decision
    }

    pub(crate) const fn link_status(&self) -> &Knowledge<StableOrChanging> {
        &self.link_status
    }

    pub(crate) const fn quality(&self) -> &LinkQuality {
        &self.quality
    }

    pub(crate) fn coordinates(&self) -> &[CoordinateEvidence] {
        &self.coordinates
    }
}

/// The gate outcome for one baseline window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum BaselineDecision {
    /// A first quality-accepted window seeded a baseline.
    BootstrapAccepted,
    /// An active baseline accepted a gated adaptation.
    AdaptationAccepted,
    /// The window did not change baseline state.
    Rejected {
        /// Typed reason the estimator update was not accepted.
        reason: BaselineRejectionReason,
    },
}

/// Typed reasons for rejecting an estimator update.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum BaselineRejectionReason {
    /// Quality data was insufficient.
    LowQuality,
    /// Samples or timestamps were missing.
    MissingData,
    /// Event time was too uncertain.
    TimeUncertain,
    /// Profile did not match the incumbent contract.
    ProfileMismatch,
    /// Baseline is stale.
    Stale,
    /// Baseline is frozen.
    Frozen,
    /// Residual exceeded the adaptation gate.
    DeviationAboveGate,
    /// Learning has not been explicitly committed.
    BaselineLearning,
}

/// A physical link's contribution to a space-level belief.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LinkContribution {
    /// Physical link.
    link: RadioLinkId,
    /// Profiles that contributed or were excluded.
    profiles: Box<[CaptureProfileId]>,
    /// Per-link semantic status.
    status: Knowledge<StableOrChanging>,
    /// Exclusions preventing contribution.
    exclusions: Box<[ExclusionReason]>,
}

impl LinkContribution {
    /// Creates a link contribution after checking its profile set.
    pub fn try_new(
        link: RadioLinkId,
        profiles: impl Into<Box<[CaptureProfileId]>>,
        status: Knowledge<StableOrChanging>,
        exclusions: impl Into<Box<[ExclusionReason]>>,
    ) -> Result<Self, WorldValueError> {
        let profiles = profiles.into();
        if profiles.is_empty() {
            return Err(WorldValueError::EmptyProfiles);
        }
        for (index, profile) in profiles.iter().enumerate() {
            if profiles[..index].last().is_some_and(|previous| previous >= profile) {
                return Err(WorldValueError::UnorderedProfiles);
            }
        }
        Ok(Self { link, profiles, status, exclusions: exclusions.into() })
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 world aggregation")]
impl LinkContribution {
    pub(crate) const fn link(&self) -> &RadioLinkId {
        &self.link
    }

    pub(crate) fn profiles(&self) -> &[CaptureProfileId] {
        &self.profiles
    }

    pub(crate) const fn status(&self) -> &Knowledge<StableOrChanging> {
        &self.status
    }

    pub(crate) fn exclusions(&self) -> &[ExclusionReason] {
        &self.exclusions
    }
}

/// A conservative room/space belief.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SpaceBelief {
    /// Stable/change/unknown status.
    status: Knowledge<StableOrChanging>,
    /// All link contributions and exclusions.
    contributions: Vec<LinkContribution>,
}

impl SpaceBelief {
    /// Creates a space belief after checking link contribution order.
    pub fn try_new(
        status: Knowledge<StableOrChanging>,
        contributions: impl Into<Vec<LinkContribution>>,
    ) -> Result<Self, WorldValueError> {
        let contributions = contributions.into();
        let mut previous: Option<&RadioLinkId> = None;
        for contribution in &contributions {
            if previous.is_some_and(|prior| prior >= contribution.link()) {
                return Err(WorldValueError::UnorderedContributions);
            }
            previous = Some(contribution.link());
        }
        Ok(Self { status, contributions })
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 world aggregation")]
impl SpaceBelief {
    pub(crate) const fn status(&self) -> &Knowledge<StableOrChanging> {
        &self.status
    }

    pub(crate) fn contributions(&self) -> &[LinkContribution] {
        &self.contributions
    }
}

/// Health associated with one sensor.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SensorHealth {
    /// Whether the source is currently active.
    active: bool,
    /// Time quality observed for the source.
    time_quality: TimeQuality,
    /// Number of source-level sequence gaps.
    sequence_gaps: u64,
}

impl SensorHealth {
    /// Combines already validated sensor health values.
    #[must_use]
    pub const fn new(active: bool, time_quality: TimeQuality, sequence_gaps: u64) -> Self {
        Self { active, time_quality, sequence_gaps }
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 world aggregation")]
impl SensorHealth {
    pub(crate) const fn active(&self) -> bool {
        self.active
    }

    pub(crate) const fn time_quality(&self) -> TimeQuality {
        self.time_quality
    }

    pub(crate) const fn sequence_gaps(&self) -> u64 {
        self.sequence_gaps
    }
}

/// A link belief retained in a world snapshot.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LinkBelief {
    /// Stable/change/unknown status.
    status: Knowledge<StableOrChanging>,
    /// Optional residual diagnostics.
    diagnostics: Option<LinkDiagnostics>,
    /// Quality predicates and measurements.
    quality: LinkQuality,
    /// Baseline lifecycle.
    baseline: BaselineStatus,
    /// Source evidence receipt.
    evidence: EvidenceReceipt,
}

impl LinkBelief {
    /// Combines already validated link belief values.
    #[must_use]
    pub fn new(
        status: Knowledge<StableOrChanging>,
        diagnostics: Option<LinkDiagnostics>,
        quality: LinkQuality,
        baseline: BaselineStatus,
        evidence: EvidenceReceipt,
    ) -> Self {
        Self { status, diagnostics, quality, baseline, evidence }
    }
}

#[expect(dead_code, reason = "consumed by work-package 3.3 world aggregation")]
impl LinkBelief {
    pub(crate) const fn status(&self) -> &Knowledge<StableOrChanging> {
        &self.status
    }

    pub(crate) const fn diagnostics(&self) -> Option<&LinkDiagnostics> {
        self.diagnostics.as_ref()
    }

    pub(crate) const fn quality(&self) -> &LinkQuality {
        &self.quality
    }

    pub(crate) const fn baseline(&self) -> &BaselineStatus {
        &self.baseline
    }

    pub(crate) const fn evidence(&self) -> &EvidenceReceipt {
        &self.evidence
    }
}

/// Snapshot provenance shared by all derived world values.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DerivationReceipt {
    /// Source session.
    source_session: SessionId,
    /// First record represented.
    first_record_seq: u64,
    /// Last record represented.
    last_record_seq: u64,
    /// Last durable record represented.
    durable_through_record_seq: u64,
    /// Effective configuration digest.
    config_digest: [u8; 32],
    /// Build fingerprint.
    build_fingerprint: BuildFingerprint,
    /// Decoder version.
    decoder_version: DecoderVersion,
    /// Conditioning version.
    conditioning_version: ConditioningVersion,
    /// Algorithm version.
    algorithm_version: AlgorithmVersion,
}

impl DerivationReceipt {
    /// Creates a receipt after checking monotonic record bounds.
    #[expect(
        clippy::too_many_arguments,
        reason = "the receipt records the complete provenance contract"
    )]
    pub fn try_new(
        source_session: SessionId,
        first_record_seq: u64,
        last_record_seq: u64,
        durable_through_record_seq: u64,
        config_digest: [u8; 32],
        build_fingerprint: BuildFingerprint,
        decoder_version: DecoderVersion,
        conditioning_version: ConditioningVersion,
        algorithm_version: AlgorithmVersion,
    ) -> Result<Self, WorldValueError> {
        if first_record_seq > last_record_seq || last_record_seq > durable_through_record_seq {
            return Err(WorldValueError::InvalidReceiptOrder);
        }
        Ok(Self {
            source_session,
            first_record_seq,
            last_record_seq,
            durable_through_record_seq,
            config_digest,
            build_fingerprint,
            decoder_version,
            conditioning_version,
            algorithm_version,
        })
    }

    /// Returns the source session.
    #[must_use]
    pub const fn source_session(&self) -> &SessionId {
        &self.source_session
    }

    /// Returns the first source record.
    #[must_use]
    pub const fn first_record_seq(&self) -> u64 {
        self.first_record_seq
    }

    /// Returns the last source record.
    #[must_use]
    pub const fn last_record_seq(&self) -> u64 {
        self.last_record_seq
    }

    /// Returns the durable-through record.
    #[must_use]
    pub const fn durable_through_record_seq(&self) -> u64 {
        self.durable_through_record_seq
    }

    /// Returns the effective configuration digest.
    #[must_use]
    pub const fn config_digest(&self) -> [u8; 32] {
        self.config_digest
    }

    /// Returns the build fingerprint.
    #[must_use]
    pub const fn build_fingerprint(&self) -> BuildFingerprint {
        self.build_fingerprint
    }

    /// Returns the decoder version.
    #[must_use]
    pub const fn decoder_version(&self) -> &DecoderVersion {
        &self.decoder_version
    }

    /// Returns the conditioning version.
    #[must_use]
    pub const fn conditioning_version(&self) -> &ConditioningVersion {
        &self.conditioning_version
    }

    /// Returns the algorithm version.
    #[must_use]
    pub const fn algorithm_version(&self) -> &AlgorithmVersion {
        &self.algorithm_version
    }
}

/// A deterministic world snapshot for one closed or advanced window.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WorldSnapshot {
    /// Stable snapshot identity.
    id: SnapshotId,
    /// Previous snapshot identity, if any.
    previous_id: Option<SnapshotId>,
    /// Deployment identity.
    deployment: DeploymentId,
    /// Window identity.
    window: WindowId,
    /// Valid half-open interval.
    valid_interval: TimeInterval,
    /// Sensor health by sensor identity.
    sensors: BTreeMap<SensorId, SensorHealth>,
    /// Link/profile beliefs in stable key order.
    links: BTreeMap<LinkProfileKey, LinkBelief>,
    /// Space beliefs in stable key order.
    spaces: BTreeMap<SpaceId, SpaceBelief>,
    /// Full derivation receipt.
    receipt: DerivationReceipt,
}

impl WorldSnapshot {
    /// Validates the stable identity/time relation of a snapshot.
    #[expect(
        clippy::too_many_arguments,
        reason = "the snapshot constructor validates each stable field"
    )]
    pub fn try_new(
        id: SnapshotId,
        previous_id: Option<SnapshotId>,
        deployment: DeploymentId,
        window: WindowId,
        valid_interval: TimeInterval,
        sensors: BTreeMap<SensorId, SensorHealth>,
        links: BTreeMap<LinkProfileKey, LinkBelief>,
        spaces: BTreeMap<SpaceId, SpaceBelief>,
        receipt: DerivationReceipt,
    ) -> Result<Self, WorldValueError> {
        if id.session() != receipt.source_session() || id.window() != window {
            return Err(WorldValueError::InvalidSnapshotIdentity);
        }
        if previous_id.as_ref().is_some_and(|previous| {
            previous.session() != id.session() || previous.window() >= id.window()
        }) {
            return Err(WorldValueError::InvalidPreviousSnapshotIdentity);
        }
        Ok(Self {
            id,
            previous_id,
            deployment,
            window,
            valid_interval,
            sensors,
            links,
            spaces,
            receipt,
        })
    }

    /// Returns the snapshot identity.
    #[must_use]
    pub const fn id(&self) -> &SnapshotId {
        &self.id
    }

    /// Returns the predecessor identity, if any.
    #[must_use]
    pub const fn previous_id(&self) -> Option<&SnapshotId> {
        self.previous_id.as_ref()
    }

    /// Returns the deployment identity.
    #[must_use]
    pub const fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// Returns the window identity.
    #[must_use]
    pub const fn window(&self) -> WindowId {
        self.window
    }

    /// Returns the valid interval.
    #[must_use]
    pub const fn valid_interval(&self) -> TimeInterval {
        self.valid_interval
    }

    /// Returns sensor health in stable identity order.
    #[must_use]
    pub const fn sensors(&self) -> &BTreeMap<SensorId, SensorHealth> {
        &self.sensors
    }

    /// Returns link/profile beliefs in stable identity order.
    #[must_use]
    pub const fn links(&self) -> &BTreeMap<LinkProfileKey, LinkBelief> {
        &self.links
    }

    /// Returns space beliefs in stable identity order.
    #[must_use]
    pub const fn spaces(&self) -> &BTreeMap<SpaceId, SpaceBelief> {
        &self.spaces
    }

    /// Returns the derivation receipt.
    #[must_use]
    pub const fn receipt(&self) -> &DerivationReceipt {
        &self.receipt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_snapshot_rejects_single_sample_coordinate() {
        let coordinate = BaselineCoordinate {
            path: CsiPath::RawPathOrdinal(0),
            coordinate: CsiSampleCoordinate::OpaqueSampleOrdinal(0),
            count: 1,
            mean: 0.0,
            variance: 0.0,
            accepted_exposure_ns: 1,
        };
        let result = BaselineSnapshot::try_new(
            DeploymentId::new("deployment").expect("deployment"),
            SpaceId::new("space").expect("space"),
            LinkProfileKey::new(
                RadioLinkId::new("link").expect("link"),
                CaptureProfileId::from_bytes([1; 32]),
            ),
            ConditioningVersion::new("conditioning").expect("conditioning"),
            BaselineRevision::new(1),
            BaselineContractId::from_bytes([2; 32]),
            vec![coordinate],
        );

        assert!(matches!(result, Err(WorldValueError::EmptyBaselineCoordinate { .. })));
    }
}
