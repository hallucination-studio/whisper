//! Private canonical Timeline, conditioning, and relationship-estimator coordinator.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::Config;
use crate::config::TimeQualityConfig;
use crate::domain::csi::CsiObservation;
use crate::domain::identity::{
    BaselineContractId, BaselineRevision, BaselineStateSequence, LinkProfileKey, RadioLinkId,
    SpaceId, StreamInstanceId,
};
use crate::domain::time::{EventTimeSource, SessionTime, TimeInterval};
use crate::domain::world::{
    BaselineCommand, BaselineCompatibilityReceipt, BaselineCoordinateKey, BaselineLifecycle,
    BaselineState, EwState, Knowledge, StableOrChanging, TargetedBaselineCommand, UnknownReason,
    WelfordState,
};
use crate::session::SessionManifest;
use crate::timeline::{
    AlignedWindow, SequenceClassification, StreamSegmentId, Timeline, TimelineConfig,
    TimelineError, TimelineInput,
};

// `baseline-v1` is the canonical algorithm identity imported by #147. Changing
// it invalidates persisted processing receipts and query compatibility.
const ALGORITHM_VERSION: &str = "baseline-v1";

#[derive(Debug, thiserror::Error)]
pub(super) enum CoordinatorError {
    #[error("Timeline configuration is incompatible: {0}")]
    Config(#[from] crate::timeline::TimelineConfigError),
    #[error("Timeline transition failed: {0}")]
    Timeline(#[from] TimelineError),
    #[error("baseline state is incompatible: {0}")]
    Baseline(#[from] crate::domain::world::WorldValueError),
    #[error("baseline command targets an unknown Link")]
    UnknownLink,
    #[error("BeginLearning requires a missing baseline")]
    BaselineAlreadyPresent,
    #[error("baseline learning has not reached configured maturity")]
    BaselineNotMature,
    #[error("Commit requires a learning baseline")]
    CommitRequiresLearning,
    #[error("only BeginLearning and Commit are implemented by this bounded coordinator")]
    UnsupportedCommand,
    #[error("relationship estimator arithmetic overflowed")]
    ArithmeticOverflow,
}

#[derive(Clone, Debug)]
pub(super) struct RelationshipCoordinator {
    timeline: Timeline,
    baselines: BTreeMap<LinkProfileKey, BaselineState>,
    deployment: crate::domain::identity::DeploymentId,
    link_spaces: BTreeMap<RadioLinkId, SpaceId>,
    conditioning_version: crate::domain::identity::ConditioningVersion,
    baseline_contract: BaselineContractId,
    conditioning_scale: f64,
    minimum_frames: u32,
    minimum_coordinate_coverage: f64,
    maximum_gap_ratio: f64,
    maximum_receive_jitter_ns: u64,
    minimum_time_quality: TimeQualityConfig,
    minimum_learning_windows: u32,
    minimum_valid_exposure_ns: u64,
    minimum_samples_per_coordinate: u32,
    minimum_exposure_per_coordinate_ns: u64,
    minimum_ready_coordinate_coverage: f64,
    variance_floor: f64,
    ew_time_constant_ns: u64,
    deviation_quantile: f64,
    adaptation_gate: f64,
    stable_threshold: f64,
    changing_threshold: f64,
}

#[derive(Clone, Debug)]
pub(super) struct RelationshipResult {
    pub(super) key: LinkProfileKey,
    pub(super) knowledge: Knowledge<StableOrChanging>,
    pub(super) result_time: SessionTime,
}

#[derive(Debug)]
struct ConditionedWindow {
    coordinates: BTreeMap<BaselineCoordinateKey, ConditionedCoordinate>,
    accepted_exposure_ns: u64,
    eligible: bool,
    unknown_reason: Option<UnknownReason>,
}

#[derive(Clone, Copy, Debug)]
struct ConditionedCoordinate {
    observed: f64,
    accepted_exposure_ns: u64,
}

#[derive(Debug, Default)]
struct CoordinateFold {
    sum: f64,
    valid_count: usize,
    previous_valid: BTreeMap<(StreamInstanceId, StreamSegmentId), SessionTime>,
    valid_coverage: Vec<(SessionTime, SessionTime)>,
    non_finite: bool,
}

#[derive(Clone, Debug)]
pub(super) struct CoordinatorTransition {
    pub(super) timeline_digest: [u8; 32],
    pub(super) baseline_states: Vec<BaselineState>,
    pub(super) relationships: Vec<RelationshipResult>,
}

impl RelationshipCoordinator {
    pub(super) fn new(
        manifest: &SessionManifest,
        config: &Config,
    ) -> Result<Self, CoordinatorError> {
        let timeline =
            Timeline::new(TimelineConfig::try_new(manifest, config.session().max_record_bytes())?)?;
        let baseline_contract = BaselineContractId::from_bytes(config.replay().digest());
        let link_spaces = config
            .registry()
            .links()
            .iter()
            .map(|(id, link)| (id.clone(), link.space().clone()))
            .collect();
        let conditioning = config.conditioning();
        let quality = config.quality();
        let baseline = config.baseline();
        Ok(Self {
            timeline,
            baselines: BTreeMap::new(),
            deployment: config.deployment().id().clone(),
            link_spaces,
            conditioning_version: config.conditioning().version().clone(),
            baseline_contract,
            conditioning_scale: f64::from(conditioning.scale_numerator())
                / f64::from(conditioning.scale_denominator()),
            minimum_frames: quality.minimum_frames(),
            minimum_coordinate_coverage: quality.minimum_coordinate_coverage(),
            maximum_gap_ratio: quality.maximum_gap_ratio(),
            maximum_receive_jitter_ns: quality.maximum_receive_jitter_ns(),
            minimum_time_quality: quality.minimum_time_quality(),
            minimum_learning_windows: baseline.minimum_learning_windows(),
            minimum_valid_exposure_ns: baseline.minimum_valid_exposure_ns(),
            minimum_samples_per_coordinate: baseline.minimum_samples_per_coordinate(),
            minimum_exposure_per_coordinate_ns: baseline.minimum_exposure_per_coordinate_ns(),
            minimum_ready_coordinate_coverage: baseline.minimum_ready_coordinate_coverage(),
            variance_floor: baseline.variance_floor(),
            ew_time_constant_ns: baseline.ew_time_constant_ns(),
            deviation_quantile: baseline.deviation_quantile(),
            adaptation_gate: baseline.adaptation_gate(),
            stable_threshold: baseline.stable_threshold(),
            changing_threshold: baseline.changing_threshold(),
        })
    }

    pub(super) fn begin_learning(
        &self,
        command: &TargetedBaselineCommand,
    ) -> Result<(Self, CoordinatorTransition), CoordinatorError> {
        if !matches!(command.command(), BaselineCommand::BeginLearning) {
            return Err(CoordinatorError::UnsupportedCommand);
        }
        let mut staged = self.clone();
        let key = command.target().clone();
        if staged.baselines.contains_key(&key) {
            return Err(CoordinatorError::BaselineAlreadyPresent);
        }
        let space =
            staged.link_spaces.get(key.link()).cloned().ok_or(CoordinatorError::UnknownLink)?;
        let state = BaselineState::try_new(
            key.clone(),
            BaselineLifecycle::Learning { accepted_windows: 0, accepted_exposure_ns: 0 },
            BTreeMap::new(),
            BTreeMap::new(),
            None,
            None,
            false,
            None,
            BaselineCompatibilityReceipt::new(
                staged.deployment.clone(),
                space,
                staged.conditioning_version.clone(),
                staged.baseline_contract,
            ),
        )?;
        staged.baselines.insert(key, state.clone());
        let timeline_digest: [u8; 32] = Sha256::digest(staged.timeline.state()?.as_bytes()).into();
        Ok((
            staged,
            CoordinatorTransition {
                timeline_digest,
                baseline_states: vec![state],
                relationships: Vec::new(),
            },
        ))
    }

    pub(super) fn command(
        &self,
        command: &TargetedBaselineCommand,
    ) -> Result<(Self, CoordinatorTransition), CoordinatorError> {
        match command.command() {
            BaselineCommand::BeginLearning => self.begin_learning(command),
            BaselineCommand::Commit => self.commit(command),
            _ => Err(CoordinatorError::UnsupportedCommand),
        }
    }

    fn commit(
        &self,
        command: &TargetedBaselineCommand,
    ) -> Result<(Self, CoordinatorTransition), CoordinatorError> {
        let mut staged = self.clone();
        let key = command.target();
        let previous = staged.baselines.get(key).ok_or(CoordinatorError::CommitRequiresLearning)?;
        let BaselineLifecycle::Learning { accepted_windows, accepted_exposure_ns } =
            previous.lifecycle()
        else {
            return Err(CoordinatorError::CommitRequiresLearning);
        };
        let ready = previous
            .learning()
            .iter()
            .filter(|(_, state)| {
                state.count() >= u64::from(staged.minimum_samples_per_coordinate)
                    && state.accepted_exposure_ns() >= staged.minimum_exposure_per_coordinate_ns
            })
            .collect::<Vec<_>>();
        let ready_coverage = if previous.learning().is_empty() {
            0.0
        } else {
            ready.len() as f64 / previous.learning().len() as f64
        };
        if accepted_windows < u64::from(staged.minimum_learning_windows)
            || accepted_exposure_ns < staged.minimum_valid_exposure_ns
            || ready.is_empty()
            || ready_coverage < staged.minimum_ready_coordinate_coverage
        {
            return Err(CoordinatorError::BaselineNotMature);
        }
        let mut active = BTreeMap::new();
        for (coordinate, state) in ready {
            let variance = (state.m2() / (state.count() - 1) as f64).max(staged.variance_floor);
            active.insert(
                *coordinate,
                EwState::try_new(
                    state.count(),
                    state.mean(),
                    variance,
                    state.accepted_exposure_ns(),
                )?,
            );
        }
        let next = BaselineState::try_new(
            key.clone(),
            BaselineLifecycle::Active,
            BTreeMap::new(),
            active,
            Some(BaselineRevision::new(1)),
            Some(BaselineStateSequence::new(1)),
            false,
            previous.session_last_eligible_at(),
            previous.compatibility().clone(),
        )?;
        staged.baselines.insert(key.clone(), next.clone());
        let timeline_digest: [u8; 32] = Sha256::digest(staged.timeline.state()?.as_bytes()).into();
        Ok((
            staged,
            CoordinatorTransition {
                timeline_digest,
                baseline_states: vec![next],
                relationships: Vec::new(),
            },
        ))
    }

    pub(super) fn observe(
        &self,
        observation: CsiObservation,
    ) -> Result<(Self, CoordinatorTransition), CoordinatorError> {
        let mut staged = self.clone();
        let transition = staged.timeline.apply(TimelineInput::Observation(observation))?;
        let (baseline_states, relationships) =
            staged.process_windows(transition.published_windows())?;
        let timeline_digest: [u8; 32] = Sha256::digest(transition.state().as_bytes()).into();
        Ok((staged, CoordinatorTransition { timeline_digest, baseline_states, relationships }))
    }

    pub(super) fn advance(
        &self,
        record_seq: u64,
        at: SessionTime,
    ) -> Result<(Self, CoordinatorTransition), CoordinatorError> {
        let mut staged = self.clone();
        let transition =
            staged.timeline.apply(TimelineInput::TimelineAdvance { record_seq, at })?;
        let (baseline_states, relationships) =
            staged.process_windows(transition.published_windows())?;
        let timeline_digest: [u8; 32] = Sha256::digest(transition.state().as_bytes()).into();
        Ok((staged, CoordinatorTransition { timeline_digest, baseline_states, relationships }))
    }

    pub(super) fn unchanged(&self) -> Result<CoordinatorTransition, CoordinatorError> {
        Ok(CoordinatorTransition {
            timeline_digest: Sha256::digest(self.timeline.state()?.as_bytes()).into(),
            baseline_states: Vec::new(),
            relationships: Vec::new(),
        })
    }

    fn process_windows(
        &mut self,
        windows: &[AlignedWindow],
    ) -> Result<(Vec<BaselineState>, Vec<RelationshipResult>), CoordinatorError> {
        let mut changed = BTreeMap::new();
        let mut relationships = Vec::new();
        for window in windows {
            let mut keys = self.baselines.keys().cloned().collect::<BTreeSet<_>>();
            keys.extend(window.observations().iter().map(|item| {
                LinkProfileKey::new(item.observation().link().clone(), item.observation().profile())
            }));
            keys.extend(window.missing_spans().iter().map(|span| {
                LinkProfileKey::new(
                    span.stream().key().link().clone(),
                    *span.stream().key().profile(),
                )
            }));

            for key in keys {
                let (next, knowledge) = match self.baselines.get(&key).map(BaselineState::lifecycle)
                {
                    None => (None, Knowledge::unknown(UnknownReason::BaselineMissing)),
                    Some(BaselineLifecycle::Learning { .. }) => (
                        self.update_learning_state(&key, window)?,
                        Knowledge::unknown(UnknownReason::BaselineLearning),
                    ),
                    Some(BaselineLifecycle::Active) => self.update_active_state(&key, window)?,
                    Some(BaselineLifecycle::Frozen) => {
                        (None, Knowledge::unknown(UnknownReason::Frozen))
                    }
                    Some(BaselineLifecycle::Stale { .. }) => {
                        (None, Knowledge::unknown(UnknownReason::Stale))
                    }
                };
                if let Some(next) = next {
                    self.baselines.insert(key.clone(), next.clone());
                    changed.insert(key.clone(), next);
                }
                relationships.push(RelationshipResult {
                    key,
                    knowledge,
                    result_time: window.interval().end(),
                });
            }
        }
        Ok((changed.into_values().collect(), relationships))
    }

    fn update_active_state(
        &self,
        key: &LinkProfileKey,
        window: &AlignedWindow,
    ) -> Result<(Option<BaselineState>, Knowledge<StableOrChanging>), CoordinatorError> {
        let previous = self.baselines.get(key).ok_or(CoordinatorError::CommitRequiresLearning)?;
        let conditioned = self.condition_window(key, window)?;
        let covered = conditioned
            .coordinates
            .iter()
            .filter(|(coordinate, _)| previous.active().contains_key(coordinate))
            .collect::<Vec<_>>();
        let ready_coverage = covered.len() as f64 / previous.active().len() as f64;
        if !conditioned.eligible || ready_coverage < self.minimum_ready_coordinate_coverage {
            return Ok((
                None,
                Knowledge::unknown(conditioned.unknown_reason.unwrap_or(UnknownReason::LowQuality)),
            ));
        }
        let mut residuals = covered
            .iter()
            .map(|(coordinate, observed)| {
                let baseline =
                    previous.active().get(coordinate).expect("covered Active coordinate");
                ((observed.observed - baseline.mean())
                    / baseline.variance().max(self.variance_floor).sqrt())
                .abs()
            })
            .collect::<Vec<_>>();
        let Some(deviation) = nearest_rank(&mut residuals, self.deviation_quantile) else {
            return Ok((None, Knowledge::unknown(UnknownReason::MissingData)));
        };
        let knowledge = if deviation <= self.stable_threshold {
            Knowledge::known(StableOrChanging::Stable)
        } else if deviation >= self.changing_threshold {
            Knowledge::known(StableOrChanging::Changing)
        } else {
            Knowledge::unknown(UnknownReason::AmbiguousEvidence)
        };

        let mut active = previous.active().clone();
        let first_active_window = !previous.adaptation_armed();
        let adaptation_accepted = !first_active_window && deviation <= self.adaptation_gate;
        if adaptation_accepted {
            for (coordinate, observed) in covered {
                let current = active.get(coordinate).copied().expect("covered Active coordinate");
                let alpha = 1.0
                    - (-(observed.accepted_exposure_ns as f64 / self.ew_time_constant_ns as f64))
                        .exp();
                let delta = observed.observed - current.mean();
                let mean = current.mean() + alpha * delta;
                let variance = (1.0 - alpha) * (current.variance() + alpha * delta * delta);
                active.insert(
                    *coordinate,
                    EwState::try_new(
                        current
                            .count()
                            .checked_add(1)
                            .ok_or(CoordinatorError::ArithmeticOverflow)?,
                        mean,
                        variance,
                        current
                            .accepted_exposure_ns()
                            .checked_add(observed.accepted_exposure_ns)
                            .ok_or(CoordinatorError::ArithmeticOverflow)?,
                    )?,
                );
            }
        }
        let sequence = previous.state_sequence().ok_or(CoordinatorError::CommitRequiresLearning)?;
        let sequence = if first_active_window || adaptation_accepted {
            BaselineStateSequence::new(
                sequence.get().checked_add(1).ok_or(CoordinatorError::ArithmeticOverflow)?,
            )
        } else {
            sequence
        };
        let next = BaselineState::try_new(
            key.clone(),
            BaselineLifecycle::Active,
            BTreeMap::new(),
            active,
            previous.revision(),
            Some(sequence),
            true,
            Some(window.interval().end()),
            previous.compatibility().clone(),
        )?;
        Ok((Some(next), knowledge))
    }

    fn update_learning_state(
        &self,
        key: &LinkProfileKey,
        window: &AlignedWindow,
    ) -> Result<Option<BaselineState>, CoordinatorError> {
        let Some(previous) = self.baselines.get(key) else {
            return Ok(None);
        };
        let BaselineLifecycle::Learning { accepted_windows, accepted_exposure_ns } =
            previous.lifecycle()
        else {
            return Ok(None);
        };
        let conditioned = self.condition_window(key, window)?;
        if !conditioned.eligible {
            return Ok(None);
        }

        let mut learning = previous.learning().clone();
        for (coordinate, observed) in conditioned.coordinates {
            let next = if let Some(current) = learning.get(&coordinate).copied() {
                let count =
                    current.count().checked_add(1).ok_or(CoordinatorError::ArithmeticOverflow)?;
                let delta = observed.observed - current.mean();
                let mean = current.mean() + delta / count as f64;
                let m2 = current.m2() + delta * (observed.observed - mean);
                WelfordState::try_new(
                    count,
                    mean,
                    m2,
                    current
                        .accepted_exposure_ns()
                        .checked_add(observed.accepted_exposure_ns)
                        .ok_or(CoordinatorError::ArithmeticOverflow)?,
                )?
            } else {
                WelfordState::try_new(1, observed.observed, 0.0, observed.accepted_exposure_ns)?
            };
            learning.insert(coordinate, next);
        }
        let next = BaselineState::try_new(
            key.clone(),
            BaselineLifecycle::Learning {
                accepted_windows: accepted_windows
                    .checked_add(1)
                    .ok_or(CoordinatorError::ArithmeticOverflow)?,
                accepted_exposure_ns: accepted_exposure_ns
                    .checked_add(conditioned.accepted_exposure_ns)
                    .ok_or(CoordinatorError::ArithmeticOverflow)?,
            },
            learning,
            BTreeMap::new(),
            None,
            None,
            false,
            Some(window.interval().end()),
            previous.compatibility().clone(),
        )?;
        Ok(Some(next))
    }

    fn condition_window(
        &self,
        key: &LinkProfileKey,
        window: &AlignedWindow,
    ) -> Result<ConditionedWindow, CoordinatorError> {
        let mut observations = window
            .observations()
            .iter()
            .filter(|item| {
                item.observation().link() == key.link()
                    && item.observation().profile() == *key.profile()
            })
            .collect::<Vec<_>>();
        observations.sort_by_key(|item| item.observation().input().record_seq().get());
        let frame_count =
            u32::try_from(observations.len()).map_err(|_| CoordinatorError::ArithmeticOverflow)?;
        let finite_and_ordered = observations.windows(2).all(|pair| {
            pair[0].observation().timing().event() <= pair[1].observation().timing().event()
        });
        let receive_intervals = observations
            .windows(2)
            .filter_map(|pair| {
                pair[1]
                    .observation()
                    .timing()
                    .received()
                    .checked_duration_since(pair[0].observation().timing().received())
            })
            .collect::<Vec<_>>();
        let receive_jitter_ns =
            match (receive_intervals.iter().min(), receive_intervals.iter().max()) {
                (Some(minimum), Some(maximum)) => maximum - minimum,
                _ => 0,
            };
        let missing_packets = observations.iter().try_fold(0_u64, |total, item| {
            let missing = match item.classification() {
                SequenceClassification::Gap { missing } => missing,
                _ => 0,
            };
            total.checked_add(missing).ok_or(CoordinatorError::ArithmeticOverflow)
        })?;
        let packet_total = u64::from(frame_count)
            .checked_add(missing_packets)
            .ok_or(CoordinatorError::ArithmeticOverflow)?;
        let gap_ratio =
            if packet_total == 0 { 0.0 } else { missing_packets as f64 / packet_total as f64 };
        let time_quality_sufficient =
            observations.iter().all(|item| match self.minimum_time_quality {
                TimeQualityConfig::ReceiveOnly => matches!(
                    item.observation().timing().source(),
                    EventTimeSource::ReceiveOnly | EventTimeSource::ClockCorrected
                ),
                TimeQualityConfig::ClockCorrected => {
                    item.observation().timing().source() == EventTimeSource::ClockCorrected
                }
            });

        let mut missing_by_contributor =
            BTreeMap::<(StreamInstanceId, StreamSegmentId), Vec<TimeInterval>>::new();
        for span in window.missing_spans().iter().filter(|span| {
            span.stream().key().link() == key.link()
                && span.stream().key().profile() == key.profile()
        }) {
            missing_by_contributor
                .entry((span.stream().clone(), span.segment_id()))
                .or_default()
                .push(span.interval());
        }

        let mut folds = BTreeMap::<BaselineCoordinateKey, CoordinateFold>::new();
        for item in &observations {
            let observation = item.observation();
            let capture = observation.csi();
            let encoding = capture.encoding();
            let scale = self.conditioning_scale * f64::from(encoding.scale_numerator())
                / f64::from(encoding.scale_denominator());
            for ((path, coordinate), sample) in
                capture.coordinates().into_iter().zip(capture.samples())
            {
                let fold = folds.entry(BaselineCoordinateKey::new(path, coordinate)).or_default();
                let contributor = (item.stream_instance().clone(), item.segment_id());
                if !sample.valid {
                    fold.previous_valid.remove(&contributor);
                    continue;
                }
                let amplitude = f64::from(sample.i).hypot(f64::from(sample.q)) * scale;
                let value = amplitude.ln_1p();
                let sum = fold.sum + value;
                if !value.is_finite() || !sum.is_finite() {
                    fold.non_finite = true;
                    fold.previous_valid.remove(&contributor);
                    continue;
                }
                fold.sum = sum;
                fold.valid_count += 1;
                let at = observation.timing().received();
                if let Some(previous) = fold.previous_valid.get(&contributor).copied()
                    && !matches!(item.classification(), SequenceClassification::Gap { .. })
                {
                    fold.valid_coverage.extend(valid_coverage_spans(
                        previous,
                        at,
                        window.interval(),
                        missing_by_contributor
                            .get(&contributor)
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                    ));
                }
                fold.previous_valid.insert(contributor, at);
            }
        }

        let total_coordinates = folds.len();
        let folds_non_finite = folds.values().any(|fold| fold.non_finite);
        let mut coordinates = BTreeMap::new();
        let mut aggregate_valid_coverage = Vec::new();
        for (key, fold) in folds {
            let coordinate_coverage = if frame_count == 0 {
                0.0
            } else {
                fold.valid_count as f64 / f64::from(frame_count)
            };
            let exposure = union_exposure_ns(
                fold.valid_coverage.iter().copied(),
                window.interval().duration_ns(),
            )?;
            if fold.non_finite
                || fold.valid_count == 0
                || coordinate_coverage < self.minimum_coordinate_coverage
                || exposure == 0
            {
                continue;
            }
            let observed = fold.sum / fold.valid_count as f64;
            if observed.is_finite() {
                aggregate_valid_coverage.extend(fold.valid_coverage);
                coordinates.insert(
                    key,
                    ConditionedCoordinate { observed, accepted_exposure_ns: exposure },
                );
            }
        }
        let accepted_exposure_ns =
            union_exposure_ns(aggregate_valid_coverage, window.interval().duration_ns())?;
        let coordinate_coverage = if total_coordinates == 0 {
            0.0
        } else {
            coordinates.len() as f64 / total_coordinates as f64
        };
        let eligible = frame_count >= self.minimum_frames
            && coordinate_coverage >= self.minimum_coordinate_coverage
            && gap_ratio <= self.maximum_gap_ratio
            && receive_jitter_ns <= self.maximum_receive_jitter_ns
            && finite_and_ordered
            && time_quality_sufficient
            && accepted_exposure_ns > 0;
        let unknown_reason = if observations.is_empty() {
            Some(UnknownReason::MissingData)
        } else if folds_non_finite {
            Some(UnknownReason::NonFinite)
        } else if !finite_and_ordered || !time_quality_sufficient {
            Some(UnknownReason::TimeUncertain)
        } else if !eligible {
            Some(UnknownReason::LowQuality)
        } else {
            None
        };
        Ok(ConditionedWindow { coordinates, accepted_exposure_ns, eligible, unknown_reason })
    }
}

fn nearest_rank(values: &mut [f64], quantile: f64) -> Option<f64> {
    values.sort_by(f64::total_cmp);
    let rank = (quantile * values.len() as f64).ceil() as usize;
    values.get(rank.saturating_sub(1)).copied()
}

fn valid_coverage_spans(
    start: SessionTime,
    end: SessionTime,
    window: TimeInterval,
    missing: &[TimeInterval],
) -> Vec<(SessionTime, SessionTime)> {
    let start = start.max(window.start());
    let end = end.min(window.end());
    if end <= start {
        return Vec::new();
    }
    let mut missing = missing.to_vec();
    missing.sort_unstable_by_key(|span| (span.start(), span.end()));
    let mut cursor = start;
    let mut valid = Vec::new();
    for span in missing {
        let missing_start = span.start().max(start);
        let missing_end = span.end().min(end);
        if missing_end <= cursor {
            continue;
        }
        if missing_start > cursor {
            valid.push((cursor, missing_start.min(end)));
        }
        cursor = cursor.max(missing_end);
        if cursor >= end {
            return valid;
        }
    }
    if cursor < end {
        valid.push((cursor, end));
    }
    valid
}

fn union_exposure_ns(
    spans: impl IntoIterator<Item = (SessionTime, SessionTime)>,
    maximum: u64,
) -> Result<u64, CoordinatorError> {
    let mut spans = spans.into_iter().filter(|(start, end)| end > start).collect::<Vec<_>>();
    spans.sort_unstable();
    let Some((mut current_start, mut current_end)) = spans.first().copied() else {
        return Ok(0);
    };
    let mut exposure = 0_u64;
    for (start, end) in spans.into_iter().skip(1) {
        if start <= current_end {
            current_end = current_end.max(end);
        } else {
            exposure = exposure
                .checked_add(
                    current_end
                        .checked_duration_since(current_start)
                        .ok_or(CoordinatorError::ArithmeticOverflow)?,
                )
                .ok_or(CoordinatorError::ArithmeticOverflow)?;
            current_start = start;
            current_end = end;
        }
    }
    exposure = exposure
        .checked_add(
            current_end
                .checked_duration_since(current_start)
                .ok_or(CoordinatorError::ArithmeticOverflow)?,
        )
        .ok_or(CoordinatorError::ArithmeticOverflow)?;
    Ok(exposure.min(maximum))
}

pub(super) const fn algorithm_version() -> &'static str {
    ALGORITHM_VERSION
}
