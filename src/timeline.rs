//! Deterministic temporal classification for authenticated source observations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ciborium::ser::into_writer;
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod state_codec;

use crate::config::{ReplayConfig, WindowConfig};
use crate::domain::csi::CsiObservation;
use crate::domain::identity::{
    DecoderVersion, DeviceEpoch, SessionId, StreamInstanceId, StreamKey, WindowContractId, WindowId,
};
use crate::domain::time::{SessionTime, TimeInterval};
use crate::session::SessionManifest;
use crate::wire::{CSI_FIXED_BODY_BYTES, HEADER_BYTES, LTF_BLOCK_BYTES, TAG_BYTES};

use self::state_codec::{RouteReceiptCaps, StateBoundError, StateBoundInput};

fn encode_window_contract(config: &WindowConfig) -> Vec<u8> {
    let contract = Value::Map(vec![
        (Value::Text("schema_version".into()), Value::Integer(1u64.into())),
        (Value::Text("timeline_version".into()), Value::Text("timeline-v1".into())),
        (Value::Text("width_ns".into()), Value::Integer(config.width_ns().into())),
        (Value::Text("step_ns".into()), Value::Integer(config.step_ns().into())),
        (Value::Text("alignment".into()), Value::Text("session_time_zero".into())),
        (
            Value::Text("allowed_lateness_ns".into()),
            Value::Integer(config.allowed_lateness_ns().into()),
        ),
        (
            Value::Text("inactive_after_ns".into()),
            Value::Integer(config.inactive_after_ns().into()),
        ),
        (Value::Text("reorder_horizon".into()), Value::Integer(config.reorder_horizon().into())),
        (Value::Text("missing_data".into()), Value::Text("explicit_spans_no_zero_fill".into())),
        (
            Value::Text("event_time_admission".into()),
            Value::Text("absolute_difference_at_most_allowed_lateness".into()),
        ),
        (Value::Text("inactivity".into()), Value::Text("greater_than_or_equal".into())),
    ]);
    let mut canonical = Vec::new();
    into_writer(&contract, &mut canonical).expect(
        "serializing the fixed 11-entry window contract into an in-memory Vec must not fail",
    );
    canonical
}

fn derive_window_contract(config: &WindowConfig) -> WindowContractId {
    let canonical = encode_window_contract(config);
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    WindowContractId::from_bytes(digest)
}

/// Nanoseconds in the receive-rate interval defined by the route contract.
const ROUTE_RATE_INTERVAL_NS: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum DerivedBoundsError {
    #[error("three times the allowed lateness overflows")]
    LatenessTripling,
    #[error("inactivity plus three times the allowed lateness overflows")]
    InactivityAndLateness,
    #[error("adding the window width to the retention duration overflows")]
    RetentionDuration,
    #[error("adding the extra receive-rate interval overflows")]
    RateQuanta,
    #[error("one route's packet rate multiplied by the receive-rate intervals overflows")]
    RouteCapacity,
    #[error("summing the route observation capacities overflows")]
    BufferedObservations,
    #[error("counting configured routes overflows")]
    RouteCount,
    #[error("adding the two open-window margins overflows")]
    OpenWindows,
    #[error("adding the route count to the buffered observation bound overflows")]
    RetainedState,
    #[error("adding the newest sequence value to the buffered observation bound overflows")]
    SeenValues,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DerivedBounds {
    retention_duration_ns: u64,
    rate_quanta: u64,
    max_buffered_observations: u64,
    route_count: u64,
    max_open_windows: u64,
    max_retained_stream_segments: u64,
    max_retained_missing_spans: u64,
    max_retained_source_epochs: u64,
    max_seen_sequence_values_per_source: u64,
    max_seen_sequence_ranges_per_source: u64,
}

impl DerivedBounds {
    fn try_new(
        config: &WindowConfig,
        route_peak_rates: impl IntoIterator<Item = u32>,
    ) -> Result<Self, DerivedBoundsError> {
        let tripled_lateness = config
            .allowed_lateness_ns()
            .checked_mul(3)
            .ok_or(DerivedBoundsError::LatenessTripling)?;
        let inactivity_and_lateness = config
            .inactive_after_ns()
            .checked_add(tripled_lateness)
            .ok_or(DerivedBoundsError::InactivityAndLateness)?;
        let retention_duration_ns = inactivity_and_lateness
            .checked_add(config.width_ns())
            .ok_or(DerivedBoundsError::RetentionDuration)?;

        let rate_quanta = ceil_div(retention_duration_ns, ROUTE_RATE_INTERVAL_NS)
            .checked_add(1)
            .ok_or(DerivedBoundsError::RateQuanta)?;
        let mut max_buffered_observations = 0u64;
        let mut route_count = 0u64;
        for route_peak_rate in route_peak_rates {
            route_count = route_count.checked_add(1).ok_or(DerivedBoundsError::RouteCount)?;
            let route_capacity = u64::from(route_peak_rate)
                .checked_mul(rate_quanta)
                .ok_or(DerivedBoundsError::RouteCapacity)?;
            max_buffered_observations = max_buffered_observations
                .checked_add(route_capacity)
                .ok_or(DerivedBoundsError::BufferedObservations)?;
        }

        let max_open_windows = ceil_div(retention_duration_ns, config.step_ns())
            .checked_add(2)
            .ok_or(DerivedBoundsError::OpenWindows)?;
        let max_retained_per_collection = max_buffered_observations
            .checked_add(route_count)
            .ok_or(DerivedBoundsError::RetainedState)?;
        let max_seen_by_horizon = u64::from(config.reorder_horizon()) + 1;
        let max_seen_by_observations =
            max_buffered_observations.checked_add(1).ok_or(DerivedBoundsError::SeenValues)?;
        let max_seen_sequence_values_per_source = max_seen_by_horizon.min(max_seen_by_observations);
        // Alternating retained and absent values maximizes the number of maximal ranges.
        let max_fragmented_ranges = ceil_div(max_seen_by_horizon, 2);
        let max_seen_sequence_ranges_per_source =
            max_seen_by_observations.min(max_fragmented_ranges);

        Ok(Self {
            retention_duration_ns,
            rate_quanta,
            max_buffered_observations,
            route_count,
            max_open_windows,
            max_retained_stream_segments: max_retained_per_collection,
            max_retained_missing_spans: max_retained_per_collection,
            max_retained_source_epochs: max_retained_per_collection,
            max_seen_sequence_values_per_source,
            max_seen_sequence_ranges_per_source,
        })
    }
}

fn ceil_div(dividend: u64, divisor: u64) -> u64 {
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    quotient + u64::from(remainder != 0)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum TimelineConfigError {
    #[error("timeline maximum record size must be positive, got {max}")]
    InvalidMaxRecordBytes { max: u64 },
    #[error("manifest decoder version is invalid")]
    InvalidDecoderVersion,
    #[error("manifest has {pins} wire admission pins for {routes} routes")]
    WireAdmissionCount { routes: usize, pins: usize },
    #[error("wire admission pin {route_index} does not match its configured route")]
    WireAdmissionMismatch { route_index: usize },
    #[error("configured route {route_index} references a missing link")]
    MissingLink { route_index: usize },
    #[error("configured route {route_index} references a missing sensor")]
    MissingSensor { route_index: usize },
    #[error(
        "route {route_index} permits only {plaintext_bytes} CSI plaintext bytes, which cannot contain one logical sample"
    )]
    CsiCapacityTooSmall { route_index: usize, plaintext_bytes: u64 },
    #[error("timeline cardinality derivation failed: {source}")]
    DerivedBounds { source: DerivedBoundsError },
    #[error("timeline canonical state size arithmetic overflow while sizing {stage}")]
    StateBoundArithmetic { stage: &'static str },
    #[error("timeline canonical state sizing requires at least one route")]
    StateBoundMissingRouteCaps,
    #[error("timeline state-bound route count {actual} does not match derived count {expected}")]
    StateBoundRouteCountMismatch { expected: u64, actual: u64 },
    #[error(
        "timeline state-bound observation capacity {actual} does not match derived count {expected}"
    )]
    StateBoundObservationCapacityMismatch { expected: u64, actual: u64 },
    #[error("canonical timeline state requires {required} bytes, exceeding maximum {max}")]
    EncodedStateTooLarge { required: u64, max: u64 },
}

#[derive(Clone, Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "constructed for the Timeline state codec integration slice")
)]
#[cfg_attr(
    test,
    expect(dead_code, reason = "later state codec work consumes the retained strong receipts")
)]
pub(crate) struct TimelineConfig {
    session_id: SessionId,
    decoder_version: DecoderVersion,
    replay_config: ReplayConfig,
    window_config: WindowConfig,
    window_contract_id: WindowContractId,
    max_record_bytes: u64,
    derived_bounds: DerivedBounds,
    maximum_encoded_timeline_state_bytes: u64,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "constructed for the Timeline state codec integration slice")
)]
impl TimelineConfig {
    pub(crate) fn try_new(
        manifest: &SessionManifest,
        max_record_bytes: u64,
    ) -> Result<Self, TimelineConfigError> {
        if max_record_bytes == 0 {
            return Err(TimelineConfigError::InvalidMaxRecordBytes { max: max_record_bytes });
        }
        let decoder_version = DecoderVersion::new(manifest.decoder_version.clone())
            .map_err(|_| TimelineConfigError::InvalidDecoderVersion)?;
        let replay_config = manifest.replay_config.clone();
        let registry = replay_config.registry();
        let routes = registry.routes();
        if manifest.wire_admission.len() != routes.len() {
            return Err(TimelineConfigError::WireAdmissionCount {
                routes: routes.len(),
                pins: manifest.wire_admission.len(),
            });
        }
        let derived_bounds = DerivedBounds::try_new(
            replay_config.window(),
            routes.iter().map(|route| route.admission_limits().peak_packets_per_second()),
        )
        .map_err(|source| TimelineConfigError::DerivedBounds { source })?;

        let mut route_caps = Vec::with_capacity(routes.len());
        for (route_index, (route, pin)) in routes.iter().zip(&manifest.wire_admission).enumerate() {
            let link = registry
                .links()
                .get(route.link())
                .ok_or(TimelineConfigError::MissingLink { route_index })?;
            let sensor = registry
                .sensors()
                .get(link.receiver())
                .ok_or(TimelineConfigError::MissingSensor { route_index })?;
            if pin.wire_version != 1
                || pin.device_id != route.device_id()
                || pin.key_epoch != route.key_epoch()
                || pin.firmware_build_digest != sensor.firmware_build_digest()
                || pin.capability_digest != sensor.capability_digest()
                || pin.maximum_plaintext_bytes != sensor.maximum_plaintext_bytes()
                || pin.transport_datagram_budget_bytes
                    != route.admission_limits().maximum_datagram_bytes()
            {
                return Err(TimelineConfigError::WireAdmissionMismatch { route_index });
            }

            let logical_samples = derive_logical_sample_cap(
                route_index,
                sensor.maximum_raw_csi_bytes(),
                sensor.maximum_plaintext_bytes(),
                pin.maximum_plaintext_bytes,
                route.admission_limits().maximum_datagram_bytes(),
                pin.transport_datagram_budget_bytes,
            )?;
            let observation_capacity =
                u64::from(route.admission_limits().peak_packets_per_second())
                    .checked_mul(derived_bounds.rate_quanta)
                    .ok_or(TimelineConfigError::DerivedBounds {
                        source: DerivedBoundsError::RouteCapacity,
                    })?;
            route_caps.push(RouteReceiptCaps {
                sensor_text_bytes: sensor.id().as_str().len(),
                link_text_bytes: link.id().as_str().len(),
                hardware_text_bytes: sensor.hardware_kind().to_string().len(),
                logical_samples,
                observation_capacity,
            });
        }

        let maximum_encoded_timeline_state_bytes =
            state_codec::canonical_max_len(StateBoundInput {
                session_text_bytes: manifest.session_id.as_str().len(),
                decoder_text_bytes: decoder_version.as_str().len(),
                reorder_horizon: replay_config.window().reorder_horizon(),
                bounds: &derived_bounds,
                routes: &route_caps,
            })
            .map_err(|source| match source {
                StateBoundError::Arithmetic { stage } => {
                    TimelineConfigError::StateBoundArithmetic { stage: stage.as_str() }
                }
                StateBoundError::MissingRouteCaps => {
                    TimelineConfigError::StateBoundMissingRouteCaps
                }
                StateBoundError::RouteCountMismatch { expected, actual } => {
                    TimelineConfigError::StateBoundRouteCountMismatch { expected, actual }
                }
                StateBoundError::ObservationCapacityMismatch { expected, actual } => {
                    TimelineConfigError::StateBoundObservationCapacityMismatch { expected, actual }
                }
            })?;
        if maximum_encoded_timeline_state_bytes > max_record_bytes {
            return Err(TimelineConfigError::EncodedStateTooLarge {
                required: maximum_encoded_timeline_state_bytes,
                max: max_record_bytes,
            });
        }

        Ok(Self {
            session_id: manifest.session_id.clone(),
            decoder_version,
            replay_config,
            window_config: manifest.replay_config.window().clone(),
            window_contract_id: derive_window_contract(manifest.replay_config.window()),
            max_record_bytes,
            derived_bounds,
            maximum_encoded_timeline_state_bytes,
        })
    }

    fn window(&self) -> &WindowConfig {
        &self.window_config
    }
}

fn derive_logical_sample_cap(
    route_index: usize,
    maximum_raw_csi_bytes: u16,
    maximum_plaintext_bytes: u16,
    pin_plaintext_bytes: u16,
    maximum_datagram_bytes: u16,
    pin_datagram_bytes: u16,
) -> Result<u64, TimelineConfigError> {
    let datagram_bytes = u64::from(maximum_datagram_bytes.min(pin_datagram_bytes));
    let envelope_bytes = u64::try_from(HEADER_BYTES)
        .expect("native-frame header size fits u64")
        .checked_add(u64::try_from(TAG_BYTES).expect("native-frame tag size fits u64"))
        .expect("native-frame envelope size fits u64");
    let Some(datagram_body_bytes) = datagram_bytes.checked_sub(envelope_bytes) else {
        return Err(TimelineConfigError::CsiCapacityTooSmall { route_index, plaintext_bytes: 0 });
    };
    let plaintext_bytes = u64::from(maximum_plaintext_bytes)
        .min(u64::from(pin_plaintext_bytes))
        .min(datagram_body_bytes);
    let fixed_csi_bytes = u64::try_from(CSI_FIXED_BODY_BYTES)
        .expect("native-frame fixed CSI size fits u64")
        .checked_add(u64::try_from(LTF_BLOCK_BYTES).expect("native-frame LTF size fits u64"))
        .expect("native-frame fixed CSI and LTF sizes fit u64");
    let Some(raw_from_plaintext_bytes) = plaintext_bytes.checked_sub(fixed_csi_bytes) else {
        return Err(TimelineConfigError::CsiCapacityTooSmall { route_index, plaintext_bytes });
    };
    let logical_samples = u64::from(maximum_raw_csi_bytes).min(raw_from_plaintext_bytes) / 2;
    if logical_samples == 0 {
        return Err(TimelineConfigError::CsiCapacityTooSmall { route_index, plaintext_bytes });
    }
    Ok(logical_samples)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequenceClassification {
    First,
    InOrder,
    Gap { missing: u64 },
    Duplicate,
    Reordered { distance: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LateReason {
    BeyondReorderHorizon,
    ClosedWindow,
    EventTimeOutsideLateness,
}

impl LateReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BeyondReorderHorizon => "beyond_reorder_horizon",
            Self::ClosedWindow => "closed_window",
            Self::EventTimeOutsideLateness => "event_time_outside_lateness",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StreamSegmentId(u64);

impl StreamSegmentId {
    pub(crate) const fn new(first_record_seq: u64) -> Self {
        Self(first_record_seq)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MissingSpanReason {
    Inactive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MissingSpan {
    stream: StreamInstanceId,
    segment_id: StreamSegmentId,
    interval: TimeInterval,
    reason: MissingSpanReason,
}

impl MissingSpan {
    pub(crate) const fn stream(&self) -> &StreamInstanceId {
        &self.stream
    }

    pub(crate) const fn segment_id(&self) -> StreamSegmentId {
        self.segment_id
    }

    pub(crate) const fn interval(&self) -> TimeInterval {
        self.interval
    }

    pub(crate) const fn reason(&self) -> MissingSpanReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationDisposition {
    Windowed { window_id: WindowId },
    InterWindowGap,
    Duplicate,
    Late { reason: LateReason },
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "observations stay owned on the per-frame hot path; boxing would add one heap allocation per frame"
)]
pub(crate) enum TimelineInput {
    Observation(CsiObservation),
    TimelineAdvance { record_seq: u64, at: SessionTime },
    Finish { record_seq: u64, at: SessionTime },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservationOutcome {
    stream_instance: StreamInstanceId,
    classification: SequenceClassification,
    disposition: ObservationDisposition,
}

impl ObservationOutcome {
    pub(crate) const fn stream_instance(&self) -> &StreamInstanceId {
        &self.stream_instance
    }

    pub(crate) const fn classification(&self) -> SequenceClassification {
        self.classification
    }

    pub(crate) const fn disposition(&self) -> ObservationDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WindowObservation {
    observation: Arc<CsiObservation>,
    stream_instance: StreamInstanceId,
    segment_id: StreamSegmentId,
    classification: SequenceClassification,
    disposition: ObservationDisposition,
}

impl WindowObservation {
    pub(crate) fn observation(&self) -> &CsiObservation {
        &self.observation
    }

    pub(crate) const fn stream_instance(&self) -> &StreamInstanceId {
        &self.stream_instance
    }

    pub(crate) const fn segment_id(&self) -> StreamSegmentId {
        self.segment_id
    }

    pub(crate) const fn classification(&self) -> SequenceClassification {
        self.classification
    }

    pub(crate) const fn disposition(&self) -> ObservationDisposition {
        self.disposition
    }
}

#[derive(Debug)]
pub(crate) struct AlignedWindow {
    id: WindowId,
    interval: TimeInterval,
    observations: Vec<WindowObservation>,
    missing_spans: Vec<MissingSpan>,
}

impl AlignedWindow {
    pub(crate) const fn id(&self) -> WindowId {
        self.id
    }

    pub(crate) const fn interval(&self) -> TimeInterval {
        self.interval
    }

    pub(crate) fn observations(&self) -> &[WindowObservation] {
        &self.observations
    }

    pub(crate) fn missing_spans(&self) -> &[MissingSpan] {
        &self.missing_spans
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TimelineState(Box<[u8]>);

impl TimelineState {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) struct TimelineTransition {
    observation: Option<ObservationOutcome>,
    published_windows: Vec<AlignedWindow>,
    state: TimelineState,
}

#[derive(Debug)]
struct StagedTransition {
    observation: Option<ObservationOutcome>,
    published_windows: Vec<AlignedWindow>,
}

impl TimelineTransition {
    pub(crate) const fn observation(&self) -> Option<&ObservationOutcome> {
        self.observation.as_ref()
    }

    pub(crate) fn published_windows(&self) -> &[AlignedWindow] {
        &self.published_windows
    }

    pub(crate) const fn state(&self) -> &TimelineState {
        &self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum TimelineError {
    #[error("timeline is already finished")]
    Finished,
    #[error("timeline record sequence {actual} is not greater than previous sequence {previous}")]
    RecordSequenceRegression { previous: u64, actual: u64 },
    #[error("timeline input time {actual}ns precedes previous time {previous}ns")]
    TimeRegression { previous: u64, actual: u64 },
    #[error("timeline window end overflows session time for event {event_ns}ns")]
    WindowArithmeticOverflow { event_ns: u64 },
    #[error(
        "timeline inactivity boundary overflows session time for last activity {last_activity_ns}ns and threshold {inactive_after_ns}ns"
    )]
    InactivityArithmeticOverflow { last_activity_ns: u64, inactive_after_ns: u64 },
    #[error(
        "encoded timeline state is {actual} bytes, exceeding canonical maximum {canonical_maximum} or runtime maximum {runtime_maximum}"
    )]
    EncodedStateTooLarge { actual: u64, canonical_maximum: u64, runtime_maximum: u64 },
}

#[derive(Clone, Debug)]
pub(crate) struct Timeline {
    config: Arc<TimelineConfig>,
    sources: BTreeMap<DeviceEpoch, SourceSequenceState>,
    streams: BTreeMap<StreamInstanceId, StreamState>,
    terminated_segments: BTreeMap<(StreamInstanceId, StreamSegmentId), TerminatedStream>,
    missing_spans: Vec<StoredMissingSpan>,
    open_windows: BTreeMap<WindowId, OpenWindow>,
    closed_frontier: Option<WindowId>,
    last_record_seq: Option<u64>,
    explicit_clock: Option<SessionTime>,
    last_advance: Option<SessionTime>,
    finished: bool,
}

#[derive(Clone, Debug)]
struct SourceSequenceState {
    maximum_seen: u64,
    recent_seen: BTreeSet<u64>,
}

#[derive(Clone, Copy, Debug)]
struct ActiveStream {
    segment_id: StreamSegmentId,
    last_activity: SessionTime,
    maximum_event_time: SessionTime,
}

#[derive(Clone, Copy, Debug)]
struct InactiveStream {
    segment_id: StreamSegmentId,
    last_activity: SessionTime,
    maximum_event_time: SessionTime,
    ended_at: SessionTime,
}

#[derive(Clone, Copy, Debug)]
enum StreamState {
    Active(ActiveStream),
    Inactive(InactiveStream),
}

#[derive(Clone, Debug)]
struct ExpiryPlan {
    stream: StreamInstanceId,
    inactive: InactiveStream,
}

#[derive(Clone, Debug)]
enum EpochTerminationPlan {
    Active { stream: StreamInstanceId, active: ActiveStream },
    Inactive { stream: StreamInstanceId, inactive: InactiveStream },
}

#[derive(Clone, Copy, Debug)]
enum WindowClosureMode {
    Evaluate,
    DeferEpochTerminationOnly,
}

#[derive(Clone, Copy, Debug)]
enum TerminationReason {
    Inactive,
    Epoch,
}

#[derive(Clone, Copy, Debug)]
struct EpochTermination {
    new_epoch: DeviceEpoch,
    record_seq: u64,
}

#[derive(Clone, Copy, Debug)]
struct TerminatedStream {
    last_activity: SessionTime,
    maximum_event_time: SessionTime,
    ended_at: SessionTime,
    reason: TerminationReason,
    epoch_termination: Option<EpochTermination>,
}

#[derive(Clone, Debug)]
struct StoredMissingSpan {
    stream: StreamInstanceId,
    segment_id: StreamSegmentId,
    start: SessionTime,
    end: Option<SessionTime>,
    reason: MissingSpanReason,
}

#[derive(Clone, Copy, Debug)]
struct WindowTarget {
    id: WindowId,
    interval: TimeInterval,
}

#[derive(Clone, Debug)]
struct OpenWindow {
    interval: TimeInterval,
    observations: Vec<WindowObservation>,
}

impl Timeline {
    pub(crate) fn new(config: TimelineConfig) -> Result<Self, TimelineError> {
        let timeline = Self {
            config: Arc::new(config),
            sources: BTreeMap::new(),
            streams: BTreeMap::new(),
            terminated_segments: BTreeMap::new(),
            missing_spans: Vec::new(),
            open_windows: BTreeMap::new(),
            closed_frontier: None,
            last_record_seq: None,
            explicit_clock: None,
            last_advance: None,
            finished: false,
        };
        timeline.encode_state()?;
        Ok(timeline)
    }

    #[cfg(test)]
    fn new_unchecked_for_behavior_test(window: WindowConfig) -> Self {
        let manifest = crate::session::decode_manifest(
            include_bytes!("../tests/fixtures/session/v1/manifest.cbor"),
            0,
        )
        .expect("decode canonical Timeline test manifest");
        let mut config = TimelineConfig::try_new(&manifest, u64::MAX)
            .expect("canonical Timeline test configuration");
        config.window_contract_id = derive_window_contract(&window);
        config.window_config = window;
        Self::new(config).expect("test Timeline configuration must encode its empty state")
    }

    fn encode_state(&self) -> Result<TimelineState, TimelineError> {
        let bytes = state_codec::encode(self);
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.config.maximum_encoded_timeline_state_bytes
            || self.config.maximum_encoded_timeline_state_bytes > self.config.max_record_bytes
        {
            return Err(TimelineError::EncodedStateTooLarge {
                actual,
                canonical_maximum: self.config.maximum_encoded_timeline_state_bytes,
                runtime_maximum: self.config.max_record_bytes,
            });
        }
        Ok(TimelineState(bytes))
    }

    fn classify_source_sequence(
        &mut self,
        source: DeviceEpoch,
        sequence: u64,
    ) -> SequenceClassification {
        let Some(state) = self.sources.get_mut(&source) else {
            self.sources.insert(source, SourceSequenceState::new(sequence));
            return SequenceClassification::First;
        };
        state.classify(sequence, u64::from(self.config.window().reorder_horizon()))
    }

    pub(crate) fn apply(
        &mut self,
        input: TimelineInput,
    ) -> Result<TimelineTransition, TimelineError> {
        let mut staged = self.clone();
        let StagedTransition { observation, published_windows } = staged.apply_in_place(input)?;
        staged.prune_retained_state();
        let state = staged.encode_state()?;
        *self = staged;
        Ok(TimelineTransition { observation, published_windows, state })
    }

    fn apply_in_place(&mut self, input: TimelineInput) -> Result<StagedTransition, TimelineError> {
        if self.finished {
            return Err(TimelineError::Finished);
        }
        match input {
            TimelineInput::Observation(observation) => self.apply_observation(observation),
            TimelineInput::TimelineAdvance { record_seq, at } => {
                self.validate_order(record_seq, at)?;
                let boundary_window = self.window_at_boundary(at)?;
                let expiry_plan = self.plan_expirations(at)?;
                self.commit_order(record_seq, at);
                self.last_advance = Some(at);
                self.commit_expirations(expiry_plan);
                if let Some(target) = boundary_window
                    && self.closed_frontier.is_none_or(|closed| target.id > closed)
                {
                    self.open_windows.entry(target.id).or_insert_with(|| OpenWindow {
                        interval: target.interval,
                        observations: Vec::new(),
                    });
                }
                let published_windows = self.close_publishable_windows(WindowClosureMode::Evaluate);
                Ok(StagedTransition { observation: None, published_windows })
            }
            TimelineInput::Finish { record_seq, at } => self.apply_finish(record_seq, at),
        }
    }

    fn apply_finish(
        &mut self,
        record_seq: u64,
        at: SessionTime,
    ) -> Result<StagedTransition, TimelineError> {
        self.validate_order(record_seq, at)?;
        let expiry_plan = self.plan_expirations(at)?;

        self.commit_order(record_seq, at);
        self.commit_expirations(expiry_plan);
        self.close_open_missing_spans(at);
        let ready: Vec<_> = self.open_windows.keys().copied().collect();
        let finished_frontier = ready.last().copied();
        let published_windows = self.publish_windows(ready);
        if let Some(frontier) = finished_frontier {
            self.closed_frontier =
                Some(self.closed_frontier.map_or(frontier, |closed| closed.max(frontier)));
        }
        self.streams.clear();
        self.terminated_segments.clear();
        self.missing_spans.clear();
        self.open_windows.clear();
        self.finished = true;
        Ok(StagedTransition { observation: None, published_windows })
    }

    fn apply_observation(
        &mut self,
        observation: CsiObservation,
    ) -> Result<StagedTransition, TimelineError> {
        let record_seq = observation.input().record_seq();
        let received = observation.timing().received();
        self.validate_order(record_seq, received)?;
        let event = observation.timing().event();
        let event_time_outside_lateness = event.as_nanos().abs_diff(received.as_nanos())
            > self.config.window().allowed_lateness_ns();
        let target_window =
            if event_time_outside_lateness { None } else { self.window_for_event(event)? };
        let expiry_plan = self.plan_expirations(received)?;

        let source = observation.device_epoch();
        let epoch_termination_plan = self.plan_epoch_terminations(source, &expiry_plan);
        let expires_stream = !expiry_plan.is_empty();
        let terminates_active_epoch = epoch_termination_plan
            .iter()
            .any(|termination| matches!(termination, EpochTerminationPlan::Active { .. }));
        let stream_instance = StreamInstanceId::new(
            StreamKey::new(
                observation.sensor().clone(),
                observation.link().clone(),
                observation.profile(),
            ),
            source,
        );
        self.commit_order(record_seq, received);
        self.commit_expirations(expiry_plan);
        self.commit_epoch_terminations(epoch_termination_plan, source, record_seq, received);
        let classification = self.classify_source_sequence(source, observation.capture_sequence());
        let disposition = match classification {
            SequenceClassification::Duplicate => ObservationDisposition::Duplicate,
            SequenceClassification::Reordered { distance }
                if distance > u64::from(self.config.window().reorder_horizon()) =>
            {
                ObservationDisposition::Late { reason: LateReason::BeyondReorderHorizon }
            }
            _ if event_time_outside_lateness => {
                ObservationDisposition::Late { reason: LateReason::EventTimeOutsideLateness }
            }
            _ if target_window.is_some_and(|window_id| {
                self.closed_frontier.is_some_and(|closed| window_id.id <= closed)
            }) =>
            {
                ObservationDisposition::Late { reason: LateReason::ClosedWindow }
            }
            _ => match target_window {
                Some(target) => ObservationDisposition::Windowed { window_id: target.id },
                None => ObservationDisposition::InterWindowGap,
            },
        };

        let admitted = !matches!(
            disposition,
            ObservationDisposition::Duplicate | ObservationDisposition::Late { .. }
        );
        if admitted {
            let segment_id = self.admit_observation(
                &stream_instance,
                record_seq,
                received,
                observation.timing().event(),
            );
            if let ObservationDisposition::Windowed { window_id } = disposition {
                let target =
                    target_window.expect("windowed observation must have a checked target");
                self.open_windows
                    .entry(window_id)
                    .or_insert_with(|| OpenWindow {
                        interval: target.interval,
                        observations: Vec::new(),
                    })
                    .observations
                    .push(WindowObservation {
                        observation: Arc::new(observation),
                        stream_instance: stream_instance.clone(),
                        segment_id,
                        classification,
                        disposition,
                    });
            }
        }

        let closure_mode = if !admitted && !expires_stream && terminates_active_epoch {
            WindowClosureMode::DeferEpochTerminationOnly
        } else {
            WindowClosureMode::Evaluate
        };
        let published_windows = self.close_publishable_windows(closure_mode);
        Ok(StagedTransition {
            observation: Some(ObservationOutcome { stream_instance, classification, disposition }),
            published_windows,
        })
    }

    fn validate_order(&self, record_seq: u64, at: SessionTime) -> Result<(), TimelineError> {
        if let Some(previous) = self.last_record_seq
            && record_seq <= previous
        {
            return Err(TimelineError::RecordSequenceRegression { previous, actual: record_seq });
        }
        if let Some(previous) = self.explicit_clock
            && at < previous
        {
            return Err(TimelineError::TimeRegression {
                previous: previous.as_nanos(),
                actual: at.as_nanos(),
            });
        }
        Ok(())
    }

    fn commit_order(&mut self, record_seq: u64, at: SessionTime) {
        self.last_record_seq = Some(record_seq);
        self.explicit_clock = Some(at);
    }

    fn plan_expirations(&self, at: SessionTime) -> Result<Vec<ExpiryPlan>, TimelineError> {
        let mut plan = Vec::new();
        for (stream, state) in &self.streams {
            let StreamState::Active(active) = state else {
                continue;
            };
            let threshold = active
                .last_activity
                .checked_add(self.config.window().inactive_after_ns())
                .ok_or(TimelineError::InactivityArithmeticOverflow {
                    last_activity_ns: active.last_activity.as_nanos(),
                    inactive_after_ns: self.config.window().inactive_after_ns(),
                })?;
            if threshold <= at {
                plan.push(ExpiryPlan {
                    stream: stream.clone(),
                    inactive: InactiveStream {
                        segment_id: active.segment_id,
                        last_activity: active.last_activity,
                        maximum_event_time: active.maximum_event_time,
                        ended_at: threshold,
                    },
                });
            }
        }
        Ok(plan)
    }

    fn commit_expirations(&mut self, plan: Vec<ExpiryPlan>) {
        for expiry in plan {
            let state = self
                .streams
                .get_mut(&expiry.stream)
                .expect("planned active stream must still exist at commit");
            *state = StreamState::Inactive(expiry.inactive);
            self.missing_spans.push(StoredMissingSpan {
                stream: expiry.stream,
                segment_id: expiry.inactive.segment_id,
                start: expiry.inactive.ended_at,
                end: None,
                reason: MissingSpanReason::Inactive,
            });
        }
    }

    fn plan_epoch_terminations(
        &self,
        new_epoch: DeviceEpoch,
        expiry_plan: &[ExpiryPlan],
    ) -> Vec<EpochTerminationPlan> {
        self.streams
            .iter()
            .filter_map(|(stream, state)| {
                let old_epoch = stream.device_epoch();
                let is_older_epoch = old_epoch.device() == new_epoch.device()
                    && old_epoch.boot_generation() < new_epoch.boot_generation();
                if !is_older_epoch {
                    return None;
                }

                match state {
                    StreamState::Active(active) => {
                        if let Some(expiry) =
                            expiry_plan.iter().find(|expiry| expiry.stream == *stream)
                        {
                            Some(EpochTerminationPlan::Inactive {
                                stream: stream.clone(),
                                inactive: expiry.inactive,
                            })
                        } else {
                            Some(EpochTerminationPlan::Active {
                                stream: stream.clone(),
                                active: *active,
                            })
                        }
                    }
                    StreamState::Inactive(inactive) => Some(EpochTerminationPlan::Inactive {
                        stream: stream.clone(),
                        inactive: *inactive,
                    }),
                }
            })
            .collect()
    }

    fn commit_epoch_terminations(
        &mut self,
        plan: Vec<EpochTerminationPlan>,
        new_epoch: DeviceEpoch,
        record_seq: u64,
        received: SessionTime,
    ) {
        for termination in plan {
            match termination {
                EpochTerminationPlan::Active { stream, active } => {
                    let removed = self
                        .streams
                        .remove(&stream)
                        .expect("planned active stream must still exist at commit");
                    assert!(
                        matches!(removed, StreamState::Active(_)),
                        "planned epoch termination must still refer to an active stream"
                    );
                    self.terminated_segments.insert(
                        (stream, active.segment_id),
                        TerminatedStream {
                            last_activity: active.last_activity,
                            maximum_event_time: active.maximum_event_time,
                            ended_at: received,
                            reason: TerminationReason::Epoch,
                            epoch_termination: Some(EpochTermination { new_epoch, record_seq }),
                        },
                    );
                }
                EpochTerminationPlan::Inactive { stream, inactive } => {
                    let removed = self
                        .streams
                        .remove(&stream)
                        .expect("planned inactive stream must still exist at commit");
                    assert!(
                        matches!(removed, StreamState::Inactive(_)),
                        "planned epoch transition must still refer to an inactive stream"
                    );
                    self.close_missing_span(&stream, inactive.segment_id, received);
                    self.terminated_segments.insert(
                        (stream, inactive.segment_id),
                        TerminatedStream {
                            last_activity: inactive.last_activity,
                            maximum_event_time: inactive.maximum_event_time,
                            ended_at: inactive.ended_at,
                            reason: TerminationReason::Inactive,
                            epoch_termination: None,
                        },
                    );
                }
            }
        }
    }

    fn admit_observation(
        &mut self,
        stream: &StreamInstanceId,
        record_seq: u64,
        received: SessionTime,
        event: SessionTime,
    ) -> StreamSegmentId {
        let active = match self.streams.remove(stream) {
            Some(StreamState::Active(mut active)) => {
                active.last_activity = received;
                active.maximum_event_time = active.maximum_event_time.max(event);
                active
            }
            Some(StreamState::Inactive(inactive)) => {
                self.close_missing_span(stream, inactive.segment_id, received);
                self.terminated_segments.insert(
                    (stream.clone(), inactive.segment_id),
                    TerminatedStream {
                        last_activity: inactive.last_activity,
                        maximum_event_time: inactive.maximum_event_time,
                        ended_at: inactive.ended_at,
                        reason: TerminationReason::Inactive,
                        epoch_termination: None,
                    },
                );
                ActiveStream {
                    segment_id: StreamSegmentId::new(record_seq),
                    last_activity: received,
                    maximum_event_time: event,
                }
            }
            None => ActiveStream {
                segment_id: StreamSegmentId::new(record_seq),
                last_activity: received,
                maximum_event_time: event,
            },
        };
        let segment_id = active.segment_id;
        self.streams.insert(stream.clone(), StreamState::Active(active));
        segment_id
    }

    fn close_missing_span(
        &mut self,
        stream: &StreamInstanceId,
        segment_id: StreamSegmentId,
        received: SessionTime,
    ) {
        let index = self
            .missing_spans
            .iter()
            .position(|span| {
                span.stream == *stream && span.segment_id == segment_id && span.end.is_none()
            })
            .unwrap_or_else(|| {
                panic!(
                    "inactive stream {stream:?} segment {} must have one open missing span at receive time {}ns",
                    segment_id.get(),
                    received.as_nanos()
                )
            });
        if self.missing_spans[index].start == received {
            self.missing_spans.remove(index);
        } else {
            self.missing_spans[index].end = Some(received);
        }
    }

    fn close_open_missing_spans(&mut self, at: SessionTime) {
        self.missing_spans.retain_mut(|span| {
            if span.end.is_some() {
                return true;
            }
            assert!(
                span.start <= at,
                "open missing span for stream {:?} segment {} starts at {}ns after finish time {}ns",
                span.stream,
                span.segment_id.get(),
                span.start.as_nanos(),
                at.as_nanos()
            );
            if span.start == at {
                false
            } else {
                span.end = Some(at);
                true
            }
        });
    }

    fn prune_retained_state(&mut self) {
        let open_windows = &self.open_windows;
        self.missing_spans.retain(|span| {
            span.end.is_none()
                || open_windows.values().any(|window| {
                    span.start < window.interval.end()
                        && span.end.is_some_and(|end| end > window.interval.start())
                })
        });

        let referenced_segments: BTreeSet<_> = self
            .open_windows
            .values()
            .flat_map(|window| {
                window.observations.iter().map(|observation| {
                    (observation.stream_instance.clone(), observation.segment_id)
                })
            })
            .chain(self.missing_spans.iter().map(|span| (span.stream.clone(), span.segment_id)))
            .collect();
        self.terminated_segments.retain(|segment, _| referenced_segments.contains(segment));

        let referenced_sources: BTreeSet<_> = self
            .streams
            .keys()
            .map(StreamInstanceId::device_epoch)
            .chain(self.terminated_segments.keys().map(|(stream, _)| stream.device_epoch()))
            .chain(self.missing_spans.iter().map(|span| span.stream.device_epoch()))
            .chain(self.open_windows.values().flat_map(|window| {
                window
                    .observations
                    .iter()
                    .map(|observation| observation.stream_instance.device_epoch())
            }))
            .collect();
        let mut newest_generation = BTreeMap::new();
        for epoch in self.sources.keys() {
            newest_generation
                .entry(epoch.device())
                .and_modify(|generation: &mut u32| {
                    *generation = (*generation).max(epoch.boot_generation().get());
                })
                .or_insert(epoch.boot_generation().get());
        }
        self.sources.retain(|epoch, _| {
            referenced_sources.contains(epoch)
                || newest_generation.get(&epoch.device()).copied()
                    == Some(epoch.boot_generation().get())
        });
    }

    fn window_for_event(&self, event: SessionTime) -> Result<Option<WindowTarget>, TimelineError> {
        let window_index = event.as_nanos() / self.config.window().step_ns();
        let target = self.window_target(window_index, event.as_nanos())?;
        Ok((event < target.interval.end()).then_some(target))
    }

    fn window_at_boundary(&self, at: SessionTime) -> Result<Option<WindowTarget>, TimelineError> {
        if !at.as_nanos().is_multiple_of(self.config.window().step_ns()) {
            return Ok(None);
        }
        let window_index = at.as_nanos() / self.config.window().step_ns();
        self.window_target(window_index, at.as_nanos()).map(Some)
    }

    fn window_target(
        &self,
        window_index: u64,
        input_time_ns: u64,
    ) -> Result<WindowTarget, TimelineError> {
        let start = window_index
            .checked_mul(self.config.window().step_ns())
            .ok_or(TimelineError::WindowArithmeticOverflow { event_ns: input_time_ns })?;
        let end = start
            .checked_add(self.config.window().width_ns())
            .ok_or(TimelineError::WindowArithmeticOverflow { event_ns: input_time_ns })?;
        let interval =
            TimeInterval::try_new(SessionTime::from_nanos(start), SessionTime::from_nanos(end))
                .expect("checked window end must not precede its start");
        Ok(WindowTarget { id: WindowId::new(window_index), interval })
    }

    fn global_watermark(&self) -> Option<SessionTime> {
        let active_watermark = self
            .streams
            .values()
            .filter_map(|state| match state {
                StreamState::Active(stream) => Some(SessionTime::from_nanos(
                    stream
                        .maximum_event_time
                        .as_nanos()
                        .saturating_sub(self.config.window().allowed_lateness_ns()),
                )),
                StreamState::Inactive(_) => None,
            })
            .min();
        active_watermark.or_else(|| {
            self.last_advance.map(|advance| {
                SessionTime::from_nanos(
                    advance.as_nanos().saturating_sub(self.config.window().allowed_lateness_ns()),
                )
            })
        })
    }

    fn missing_spans_for_interval(&self, interval: TimeInterval) -> Vec<MissingSpan> {
        let mut clipped: Vec<_> = self
            .missing_spans
            .iter()
            .filter_map(|span| {
                let start = span.start.max(interval.start());
                let end = span.end.unwrap_or(interval.end()).min(interval.end());
                (start < end).then(|| MissingSpan {
                    stream: span.stream.clone(),
                    segment_id: span.segment_id,
                    interval: TimeInterval::try_new(start, end)
                        .expect("clipped missing span end must follow its start"),
                    reason: span.reason,
                })
            })
            .collect();
        clipped.sort_by(|left, right| {
            left.stream
                .cmp(&right.stream)
                .then_with(|| left.segment_id.cmp(&right.segment_id))
                .then_with(|| left.interval.start().cmp(&right.interval.start()))
                .then_with(|| left.interval.end().cmp(&right.interval.end()))
        });
        clipped
    }

    fn close_publishable_windows(&mut self, mode: WindowClosureMode) -> Vec<AlignedWindow> {
        if matches!(mode, WindowClosureMode::DeferEpochTerminationOnly) {
            return Vec::new();
        }
        let Some(watermark) = self.global_watermark() else {
            return Vec::new();
        };
        if watermark.as_nanos() < self.config.window().width_ns() {
            return Vec::new();
        }
        let frontier = WindowId::new(
            (watermark.as_nanos() - self.config.window().width_ns())
                / self.config.window().step_ns(),
        );
        if self.closed_frontier.is_some_and(|closed| frontier <= closed) {
            return Vec::new();
        }

        let ready: Vec<_> = self.open_windows.range(..=frontier).map(|(id, _)| *id).collect();
        let published = self.publish_windows(ready);
        self.closed_frontier = Some(frontier);
        published
    }

    fn publish_windows(&mut self, ready: Vec<WindowId>) -> Vec<AlignedWindow> {
        let mut published = Vec::with_capacity(ready.len());
        for id in ready {
            let OpenWindow { interval, mut observations } =
                self.open_windows.remove(&id).unwrap_or_else(|| {
                    panic!("ready window {} must exist during publication", id.get())
                });
            observations.sort_by(|left, right| {
                left.stream_instance
                    .cmp(&right.stream_instance)
                    .then_with(|| left.segment_id.cmp(&right.segment_id))
                    .then_with(|| {
                        left.observation
                            .input()
                            .record_seq()
                            .cmp(&right.observation.input().record_seq())
                    })
            });
            let missing_spans = self.missing_spans_for_interval(interval);
            published.push(AlignedWindow { id, interval, observations, missing_spans });
        }
        published
    }
}

impl SourceSequenceState {
    fn new(sequence: u64) -> Self {
        Self { maximum_seen: sequence, recent_seen: BTreeSet::from([sequence]) }
    }

    fn classify(&mut self, sequence: u64, reorder_horizon: u64) -> SequenceClassification {
        if sequence > self.maximum_seen {
            let missing = sequence - self.maximum_seen - 1;
            self.maximum_seen = sequence;
            let oldest_retained = sequence.saturating_sub(reorder_horizon);
            self.recent_seen.retain(|seen| *seen >= oldest_retained);
            self.recent_seen.insert(sequence);
            if missing == 0 {
                SequenceClassification::InOrder
            } else {
                SequenceClassification::Gap { missing }
            }
        } else if self.recent_seen.contains(&sequence) {
            SequenceClassification::Duplicate
        } else {
            let distance = self.maximum_seen - sequence;
            if distance <= reorder_horizon {
                self.recent_seen.insert(sequence);
            }
            SequenceClassification::Reordered { distance }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        DerivedBounds, DerivedBoundsError, LateReason, MissingSpanReason, ObservationDisposition,
        ObservationOutcome, SequenceClassification, Timeline, TimelineConfig, TimelineConfigError,
        TimelineError, TimelineInput, derive_logical_sample_cap, derive_window_contract,
        encode_window_contract,
    };
    use crate::config::{TestWindowConfig, WindowConfig};
    use crate::domain::csi::{
        CaptureProfileId, ComplexOrder, CsiCapture, CsiLayout, CsiObservation, CsiPath,
        CsiSampleAxis, InputReceipt, IqSample, PhaseState, PpduKind, RadioMetadata, SampleEncoding,
        SampleOrder,
    };
    use crate::domain::identity::{
        BootGeneration, DecoderVersion, DeviceEpoch, DeviceId, HardwareKind, RadioLinkId, SensorId,
        SessionId, WindowId,
    };
    use crate::domain::time::{
        ClockMappingVersion, DeviceTimestamp, EventTimeSource, FrameTiming, SessionTime,
    };

    const TEST_CALLBACK_TICK_US: u64 = 500;

    fn timeline_manifest() -> crate::session::SessionManifest {
        crate::session::decode_manifest(
            include_bytes!("../tests/fixtures/session/v1/manifest.cbor"),
            0,
        )
        .expect("decode canonical manifest fixture")
    }

    #[test]
    fn timeline_config_accepts_exact_canonical_bound_and_rejects_one_less() {
        const REQUIRED: u64 = 33_351_411;
        let manifest = timeline_manifest();

        let config = TimelineConfig::try_new(&manifest, REQUIRED)
            .expect("the exact canonical maximum must be accepted");
        assert_eq!(config.maximum_encoded_timeline_state_bytes, REQUIRED);
        assert_eq!(config.max_record_bytes, REQUIRED);

        assert_eq!(
            TimelineConfig::try_new(&manifest, REQUIRED - 1)
                .expect_err("one byte below the canonical maximum must be rejected"),
            TimelineConfigError::EncodedStateTooLarge { required: REQUIRED, max: REQUIRED - 1 }
        );
    }

    #[test]
    fn timeline_config_rejects_zero_record_bound() {
        assert_eq!(
            TimelineConfig::try_new(&timeline_manifest(), 0)
                .expect_err("a zero record bound must be rejected"),
            TimelineConfigError::InvalidMaxRecordBytes { max: 0 }
        );
    }

    #[test]
    fn timeline_config_rejects_invalid_decoder_version() {
        let mut manifest = timeline_manifest();
        manifest.decoder_version = " \t".into();

        assert_eq!(
            TimelineConfig::try_new(&manifest, u64::MAX)
                .expect_err("a whitespace-only decoder version must be rejected"),
            TimelineConfigError::InvalidDecoderVersion
        );
    }

    #[test]
    fn timeline_config_rejects_short_wire_admission_pin_list() {
        let mut manifest = timeline_manifest();
        manifest.wire_admission.pop();

        assert_eq!(
            TimelineConfig::try_new(&manifest, u64::MAX)
                .expect_err("every configured route requires one ordered pin"),
            TimelineConfigError::WireAdmissionCount { routes: 2, pins: 1 }
        );
    }

    #[test]
    fn timeline_config_rejects_route_pin_identity_mismatch() {
        let mut manifest = timeline_manifest();
        manifest.wire_admission[0].device_id = DeviceId::new(99);

        assert_eq!(
            TimelineConfig::try_new(&manifest, u64::MAX)
                .expect_err("a pin must match its route identity and receipts"),
            TimelineConfigError::WireAdmissionMismatch { route_index: 0 }
        );
    }

    #[test]
    fn logical_sample_cap_rejects_plaintext_smaller_than_one_csi_block() {
        assert_eq!(
            derive_logical_sample_cap(3, 612, 80, 80, 128, 128),
            Err(TimelineConfigError::CsiCapacityTooSmall { route_index: 3, plaintext_bytes: 80 })
        );
    }

    fn epoch(device: u64, boot: u32) -> DeviceEpoch {
        DeviceEpoch::new(
            DeviceId::new(device),
            BootGeneration::try_new(boot).expect("nonzero boot generation"),
        )
    }

    fn observation(
        source: DeviceEpoch,
        profile: CaptureProfileId,
        capture_sequence: u64,
        record_seq: u64,
        received_ns: u64,
    ) -> CsiObservation {
        observation_with_event(
            source,
            profile,
            capture_sequence,
            record_seq,
            received_ns,
            received_ns,
        )
    }

    fn observation_with_event(
        source: DeviceEpoch,
        profile: CaptureProfileId,
        capture_sequence: u64,
        record_seq: u64,
        received_ns: u64,
        event_ns: u64,
    ) -> CsiObservation {
        observation_for_link_with_event(
            source,
            "link-a",
            profile,
            capture_sequence,
            record_seq,
            received_ns,
            event_ns,
        )
    }

    fn observation_for_link_with_event(
        source: DeviceEpoch,
        link: &str,
        profile: CaptureProfileId,
        capture_sequence: u64,
        record_seq: u64,
        received_ns: u64,
        event_ns: u64,
    ) -> CsiObservation {
        observation_for_receipt_with_event(
            source,
            link,
            profile,
            capture_sequence,
            record_seq,
            received_ns,
            event_ns,
            "timeline-session",
            "timeline-test-decoder",
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the fixture builder exposes each ordered observation receipt used by state vectors"
    )]
    fn observation_for_receipt_with_event(
        source: DeviceEpoch,
        link: &str,
        profile: CaptureProfileId,
        capture_sequence: u64,
        record_seq: u64,
        received_ns: u64,
        event_ns: u64,
        session: &str,
        decoder: &str,
    ) -> CsiObservation {
        let received = SessionTime::from_nanos(received_ns);
        let event = SessionTime::from_nanos(event_ns);
        let (device, time_source, mapping_version) = if event == received {
            (None, EventTimeSource::ReceiveOnly, None)
        } else {
            (
                Some(DeviceTimestamp::try_new(event_ns, "test-device-clock").expect("device time")),
                EventTimeSource::ClockCorrected,
                Some(ClockMappingVersion::new("test-mapping-v1").expect("mapping version")),
            )
        };
        let layout = CsiLayout::try_new(
            vec![CsiPath::RawPathOrdinal(0)],
            CsiSampleAxis::try_opaque(1).expect("non-empty sample axis"),
            SampleOrder::PathThenSample,
        )
        .expect("valid CSI layout");
        let csi = CsiCapture::try_new(
            layout,
            [IqSample::new(1, 2)],
            SampleEncoding::try_new(16, 1, 1, ComplexOrder::RealImaginary)
                .expect("valid sample encoding"),
            PhaseState::Unavailable,
        )
        .expect("valid CSI capture");
        CsiObservation::new(
            InputReceipt::new(
                SessionId::new(session).expect("session ID"),
                record_seq,
                DecoderVersion::new(decoder).expect("decoder version"),
            ),
            SensorId::new("sensor-a").expect("sensor ID"),
            HardwareKind::Esp32S3,
            RadioLinkId::new(link).expect("link ID"),
            source,
            capture_sequence,
            TEST_CALLBACK_TICK_US,
            FrameTiming::try_new(received, device, event, time_source, mapping_version, 0)
                .expect("valid frame timing"),
            RadioMetadata::try_new(None, None, None, None, -42, -90).expect("radio metadata"),
            profile,
            csi,
        )
    }

    fn corrected_fixture_observation(
        source: DeviceEpoch,
        profile: CaptureProfileId,
    ) -> CsiObservation {
        let received = SessionTime::from_nanos(5_100_000_000);
        let event = SessionTime::from_nanos(5_050_000_000);
        let layout = CsiLayout::try_new(
            vec![CsiPath::TxRx { tx_stream: 1, rx_chain: 2 }],
            CsiSampleAxis::try_ieee_tones([-1, 1]).expect("non-empty tone axis"),
            SampleOrder::PathThenSample,
        )
        .expect("valid CSI layout");
        let csi = CsiCapture::try_new(
            layout,
            [IqSample::new(-3, 4), IqSample::invalid(5, -6)],
            SampleEncoding::try_new(16, 1, 1, ComplexOrder::ImaginaryReal)
                .expect("valid sample encoding"),
            PhaseState::Raw,
        )
        .expect("valid CSI capture");
        CsiObservation::new(
            InputReceipt::new(
                SessionId::new("session-1").expect("session ID"),
                3,
                DecoderVersion::new("native-frame-v1").expect("decoder version"),
            ),
            SensorId::new("sensor-a").expect("sensor ID"),
            HardwareKind::Esp32S3,
            RadioLinkId::new("link-a").expect("link ID"),
            source,
            40,
            TEST_CALLBACK_TICK_US,
            FrameTiming::try_new(
                received,
                Some(DeviceTimestamp::try_new(1_234, "esp-clock").expect("device time")),
                event,
                EventTimeSource::ClockCorrected,
                Some(ClockMappingVersion::new("map-v1").expect("mapping version")),
                25,
            )
            .expect("valid corrected timing"),
            RadioMetadata::try_new(
                Some(6),
                Some(2_437_000_000),
                Some(20_000_000),
                Some(PpduKind::He),
                -42,
                -90,
            )
            .expect("valid radio metadata"),
            profile,
            csi,
        )
    }

    fn test_timeline() -> Timeline {
        Timeline::new_unchecked_for_behavior_test(WindowConfig::for_test(TestWindowConfig {
            width_ns: 1_000_000,
            step_ns: 1_000_000,
            allowed_lateness_ns: 1_000_000,
            inactive_after_ns: 2_000_000,
            reorder_horizon: 2,
        }))
    }

    fn apply_observation(
        timeline: &mut Timeline,
        observation: CsiObservation,
    ) -> ObservationOutcome {
        timeline
            .apply(TimelineInput::Observation(observation))
            .expect("observation must apply")
            .observation()
            .expect("observation input must return an outcome")
            .clone()
    }

    fn window_contract_fixture_field(name: &str) -> &'static str {
        const FIXTURE: &str =
            include_str!("../tests/fixtures/timeline-window-contract/vector-v1.txt");
        FIXTURE
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value)
            })
            .unwrap_or_else(|| panic!("window contract fixture field {name} must exist"))
    }

    fn decode_fixture_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2), "fixture hex must have an even length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digits = std::str::from_utf8(pair).expect("fixture hex must be ASCII");
                u8::from_str_radix(digits, 16).expect("fixture hex must contain hexadecimal digits")
            })
            .collect()
    }

    fn timeline_state_fixture_field(name: &str) -> &'static str {
        const FIXTURE: &str = include_str!("../tests/fixtures/timeline-state-v1/vector-v1.txt");
        FIXTURE
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value)
            })
            .unwrap_or_else(|| panic!("timeline state fixture field {name} must exist"))
    }

    #[test]
    fn canonical_state_matches_empty_advance_and_finish_fixture() {
        let manifest = timeline_manifest();
        let config = TimelineConfig::try_new(&manifest, 33_554_432)
            .expect("canonical manifest must produce a bounded Timeline configuration");
        let mut timeline = Timeline::new(config).expect("validated configuration starts Timeline");

        let advance = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 0,
                at: SessionTime::from_nanos(1_000_000_000),
            })
            .expect("boundary advance must succeed");
        assert_eq!(
            advance.state().as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("advance_cbor_hex"))
        );

        let finish = timeline
            .apply(TimelineInput::Finish {
                record_seq: 1,
                at: SessionTime::from_nanos(1_500_000_000),
            })
            .expect("finish must succeed");
        assert_eq!(
            finish.state().as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("finish_cbor_hex"))
        );
    }

    #[test]
    fn canonical_state_matches_inactivity_epoch_and_sorted_observation_fixture() {
        let manifest = timeline_manifest();
        let config = TimelineConfig::try_new(&manifest, 33_554_432)
            .expect("canonical manifest must produce a bounded Timeline configuration");
        let mut timeline = Timeline::new(config).expect("validated configuration starts Timeline");
        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile_a = CaptureProfileId::from_bytes([0xa1; 32]);
        let profile_b = CaptureProfileId::from_bytes([0xb2; 32]);

        timeline
            .apply(TimelineInput::Observation(observation_for_receipt_with_event(
                old_epoch,
                "link-a",
                profile_b,
                7,
                0,
                0,
                0,
                "session-1",
                "native-frame-v1",
            )))
            .expect("first old-epoch profile starts a stream");
        timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(5_000_000_000),
            })
            .expect("advance makes the first profile inactive");
        let mixed = timeline
            .apply(TimelineInput::Observation(observation_for_receipt_with_event(
                old_epoch,
                "link-a",
                profile_a,
                8,
                2,
                5_000_000_000,
                5_000_000_000,
                "session-1",
                "native-frame-v1",
            )))
            .expect("second profile remains active beside the inactive first profile");
        assert_eq!(
            mixed.state().as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("inactive_cbor_hex"))
        );

        let changed_epoch = timeline
            .apply(TimelineInput::Observation(corrected_fixture_observation(new_epoch, profile_a)))
            .expect("higher epoch terminates active and inactive old-epoch streams");
        assert_eq!(
            changed_epoch.state().as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("epoch_cbor_hex"))
        );

        let pruned = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 4,
                at: SessionTime::from_nanos(10_100_000_000),
            })
            .expect("later advance publishes the only referencing window and prunes old facts");
        assert_eq!(pruned.published_windows().len(), 1);
        assert_eq!(pruned.published_windows()[0].id(), WindowId::new(5));
        assert_eq!(
            pruned.state().as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("pruned_advance_cbor_hex"))
        );
    }

    #[test]
    fn failed_transition_preserves_canonical_state_for_exact_finish_retry() {
        let manifest = timeline_manifest();
        let config = TimelineConfig::try_new(&manifest, 33_554_432)
            .expect("canonical manifest must produce a bounded Timeline configuration");
        let mut timeline = Timeline::new(config).expect("validated configuration starts Timeline");
        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile_a = CaptureProfileId::from_bytes([0xa1; 32]);
        let profile_b = CaptureProfileId::from_bytes([0xb2; 32]);

        timeline
            .apply(TimelineInput::Observation(observation_for_receipt_with_event(
                old_epoch,
                "link-a",
                profile_b,
                7,
                0,
                0,
                0,
                "session-1",
                "native-frame-v1",
            )))
            .expect("first old-epoch profile starts a stream");
        timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(5_000_000_000),
            })
            .expect("advance makes the first profile inactive");
        timeline
            .apply(TimelineInput::Observation(observation_for_receipt_with_event(
                old_epoch,
                "link-a",
                profile_a,
                8,
                2,
                5_000_000_000,
                5_000_000_000,
                "session-1",
                "native-frame-v1",
            )))
            .expect("second profile remains active");
        let before_failure = timeline
            .apply(TimelineInput::Observation(corrected_fixture_observation(new_epoch, profile_a)))
            .expect("higher epoch transition succeeds")
            .state()
            .clone();

        assert_eq!(
            timeline
                .apply(TimelineInput::Finish {
                    record_seq: 3,
                    at: SessionTime::from_nanos(5_200_000_000),
                })
                .expect_err("record-sequence regression must fail atomically"),
            TimelineError::RecordSequenceRegression { previous: 3, actual: 3 }
        );

        let retry = timeline
            .apply(TimelineInput::Finish {
                record_seq: 4,
                at: SessionTime::from_nanos(5_200_000_000),
            })
            .expect("legal retry finishes the unchanged Timeline");
        assert_eq!(
            before_failure.as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("epoch_cbor_hex")),
            "failed input must not have changed the pre-retry state"
        );
        assert_eq!(
            retry.state().as_bytes(),
            decode_fixture_hex(timeline_state_fixture_field("atomic_finish_cbor_hex"))
        );
    }

    #[test]
    fn encoded_state_failure_is_atomic_before_the_same_observation_retry() {
        let manifest = timeline_manifest();
        let config = TimelineConfig::try_new(&manifest, 33_554_432)
            .expect("canonical manifest must produce a bounded Timeline configuration");
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let input = || {
            TimelineInput::Observation(observation_for_receipt_with_event(
                epoch(1, 1),
                "link-a",
                profile,
                7,
                0,
                0,
                0,
                "session-1",
                "native-frame-v1",
            ))
        };

        let mut control = Timeline::new(config.clone()).expect("validated control Timeline");
        let expected = control.apply(input()).expect("control observation succeeds");
        let forced_ceiling =
            u64::try_from(expected.state().as_bytes().len()).expect("state length fits u64") - 1;

        let mut faulted = Timeline::new(config).expect("validated fault Timeline");
        let validated_ceiling = faulted.config.maximum_encoded_timeline_state_bytes;
        Arc::make_mut(&mut faulted.config).maximum_encoded_timeline_state_bytes = forced_ceiling;
        assert!(matches!(
            faulted.apply(input()),
            Err(TimelineError::EncodedStateTooLarge { actual, canonical_maximum, .. })
                if actual == forced_ceiling + 1 && canonical_maximum == forced_ceiling
        ));

        Arc::make_mut(&mut faulted.config).maximum_encoded_timeline_state_bytes = validated_ceiling;
        let retry = faulted.apply(input()).expect("same input retries against unchanged state");
        assert_eq!(retry.observation(), expected.observation());
        assert_eq!(retry.published_windows().len(), expected.published_windows().len());
        assert_eq!(retry.state().as_bytes(), expected.state().as_bytes());
    }

    #[test]
    fn staging_preserves_buffered_csi_arc_allocation_identity() {
        let manifest = timeline_manifest();
        let config = TimelineConfig::try_new(&manifest, 33_554_432)
            .expect("canonical manifest must produce a bounded Timeline configuration");
        let mut timeline = Timeline::new(config).expect("validated Timeline");
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);

        timeline
            .apply(TimelineInput::Observation(observation_for_receipt_with_event(
                source,
                "link-a",
                profile,
                7,
                0,
                0,
                0,
                "session-1",
                "native-frame-v1",
            )))
            .expect("first buffered observation");
        let before =
            Arc::as_ptr(&timeline.open_windows[&WindowId::new(0)].observations[0].observation);

        timeline
            .apply(TimelineInput::Observation(observation_for_receipt_with_event(
                source,
                "link-a",
                profile,
                8,
                1,
                1,
                1,
                "session-1",
                "native-frame-v1",
            )))
            .expect("second observation stages and commits");
        let original = timeline.open_windows[&WindowId::new(0)]
            .observations
            .iter()
            .find(|observation| observation.observation.input().record_seq() == 0)
            .expect("original observation remains buffered");
        assert_eq!(Arc::as_ptr(&original.observation), before);
    }

    #[test]
    fn window_contract_id_matches_independent_fixture_and_covers_every_window_field() {
        let base = TestWindowConfig {
            width_ns: window_contract_fixture_field("width_ns").parse().expect("fixture width"),
            step_ns: window_contract_fixture_field("step_ns").parse().expect("fixture step"),
            allowed_lateness_ns: window_contract_fixture_field("allowed_lateness_ns")
                .parse()
                .expect("fixture lateness"),
            inactive_after_ns: window_contract_fixture_field("inactive_after_ns")
                .parse()
                .expect("fixture inactivity"),
            reorder_horizon: window_contract_fixture_field("reorder_horizon")
                .parse()
                .expect("fixture reorder horizon"),
        };
        let expected_canonical =
            decode_fixture_hex(window_contract_fixture_field("canonical_cbor_hex"));
        let expected_digest: [u8; 32] = decode_fixture_hex(window_contract_fixture_field("sha256"))
            .try_into()
            .expect("fixture digest must contain 32 bytes");

        let config = WindowConfig::for_test(base);
        let canonical = encode_window_contract(&config);
        let contract_id = derive_window_contract(&config);
        assert_eq!(canonical, expected_canonical);
        assert_eq!(contract_id.as_bytes(), expected_digest);

        for mutation in [
            TestWindowConfig { width_ns: base.width_ns - 1, ..base },
            TestWindowConfig { step_ns: base.step_ns + 1, ..base },
            TestWindowConfig { allowed_lateness_ns: base.allowed_lateness_ns + 1, ..base },
            TestWindowConfig { inactive_after_ns: base.inactive_after_ns + 1, ..base },
            TestWindowConfig { reorder_horizon: base.reorder_horizon + 1, ..base },
        ] {
            let mutated_id = derive_window_contract(&WindowConfig::for_test(mutation));
            assert_ne!(mutated_id, contract_id);
        }
    }

    #[test]
    fn derived_bounds_match_specification_fixture() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1_000_000_000,
            step_ns: 1_000_000_000,
            allowed_lateness_ns: 100_000_000,
            inactive_after_ns: 5_000_000_000,
            reorder_horizon: 64,
        });

        let bounds = DerivedBounds::try_new(&config, [100, 100]).expect("fixture must fit");

        assert_eq!(bounds.retention_duration_ns, 6_300_000_000);
        assert_eq!(bounds.rate_quanta, 8);
        assert_eq!(bounds.max_buffered_observations, 1_600);
        assert_eq!(bounds.route_count, 2);
        assert_eq!(bounds.max_open_windows, 9);
        assert_eq!(bounds.max_retained_stream_segments, 1_602);
        assert_eq!(bounds.max_retained_missing_spans, 1_602);
        assert_eq!(bounds.max_retained_source_epochs, 1_602);
        assert_eq!(bounds.max_seen_sequence_values_per_source, 65);
        assert_eq!(bounds.max_seen_sequence_ranges_per_source, 33);
    }

    #[test]
    fn derived_bounds_reject_tripled_lateness_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: 1,
            allowed_lateness_ns: u64::MAX / 3 + 1,
            inactive_after_ns: 1,
            reorder_horizon: 0,
        });

        assert_eq!(DerivedBounds::try_new(&config, []), Err(DerivedBoundsError::LatenessTripling));
    }

    #[test]
    fn derived_bounds_reject_inactivity_and_lateness_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: 1,
            allowed_lateness_ns: u64::MAX / 3,
            inactive_after_ns: 1,
            reorder_horizon: 0,
        });

        assert_eq!(
            DerivedBounds::try_new(&config, []),
            Err(DerivedBoundsError::InactivityAndLateness)
        );
    }

    #[test]
    fn derived_bounds_reject_retention_duration_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: 1,
            allowed_lateness_ns: 0,
            inactive_after_ns: u64::MAX,
            reorder_horizon: 0,
        });

        assert_eq!(DerivedBounds::try_new(&config, []), Err(DerivedBoundsError::RetentionDuration));
    }

    #[test]
    fn derived_bounds_ceil_divides_maximum_duration_without_false_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: u64::MAX,
            allowed_lateness_ns: 0,
            inactive_after_ns: u64::MAX - 1,
            reorder_horizon: 0,
        });

        let bounds = DerivedBounds::try_new(&config, [1]).expect("maximum duration must fit");

        assert_eq!(bounds.retention_duration_ns, u64::MAX);
        assert_eq!(bounds.rate_quanta, 18_446_744_075);
        assert_eq!(bounds.max_open_windows, 3);
    }

    #[test]
    fn derived_bounds_reject_route_capacity_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: u64::MAX,
            allowed_lateness_ns: 0,
            inactive_after_ns: u64::MAX - 1,
            reorder_horizon: 0,
        });

        assert_eq!(
            DerivedBounds::try_new(&config, [u32::MAX]),
            Err(DerivedBoundsError::RouteCapacity)
        );
    }

    #[test]
    fn derived_bounds_reject_buffered_observation_sum_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: u64::MAX,
            allowed_lateness_ns: 0,
            inactive_after_ns: u64::MAX - 1,
            reorder_horizon: 0,
        });

        assert_eq!(
            DerivedBounds::try_new(&config, [500_000_000, 500_000_000]),
            Err(DerivedBoundsError::BufferedObservations)
        );
    }

    #[test]
    fn derived_bounds_reject_open_window_margin_overflow() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: 1,
            allowed_lateness_ns: 0,
            inactive_after_ns: u64::MAX - 1,
            reorder_horizon: 0,
        });

        assert_eq!(DerivedBounds::try_new(&config, []), Err(DerivedBoundsError::OpenWindows));
    }

    #[test]
    fn derived_bounds_reject_retained_state_overflow() {
        const RETENTION_DURATION_NS: u64 = 4_294_967_295_000_000_001;
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: RETENTION_DURATION_NS,
            allowed_lateness_ns: 0,
            inactive_after_ns: RETENTION_DURATION_NS - 1,
            reorder_horizon: 0,
        });

        assert_eq!(
            DerivedBounds::try_new(&config, [u32::MAX]),
            Err(DerivedBoundsError::RetainedState)
        );
    }

    #[test]
    fn derived_bounds_limit_seen_ranges_by_observation_capacity() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: 1,
            allowed_lateness_ns: 0,
            inactive_after_ns: 1,
            reorder_horizon: 64,
        });

        let bounds = DerivedBounds::try_new(&config, [1]).expect("small bounds must fit");

        assert_eq!(bounds.max_buffered_observations, 2);
        assert_eq!(bounds.max_seen_sequence_values_per_source, 3);
        assert_eq!(bounds.max_seen_sequence_ranges_per_source, 3);
    }

    #[test]
    fn finish_publishes_a_materialized_partial_window() {
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 100,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 5)))
            .expect("observation materializes window zero");
        let finish = timeline
            .apply(TimelineInput::Finish { record_seq: 1, at: SessionTime::from_nanos(8) })
            .expect("finish publishes the partial materialized window");

        assert!(finish.observation().is_none());
        assert_eq!(finish.published_windows().len(), 1);
        let published = &finish.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(0));
        assert_eq!(published.interval().start(), SessionTime::from_nanos(0));
        assert_eq!(published.interval().end(), SessionTime::from_nanos(10));
        assert_eq!(published.observations().len(), 1);
        assert_eq!(published.observations()[0].observation().input().record_seq(), 0);
    }

    #[test]
    fn finish_publishes_only_sparse_materialized_windows_in_order() {
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 100,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 5)))
            .expect("low event watermark holds window zero open");
        let advance = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(20),
            })
            .expect("advance materializes only window two");
        assert!(advance.published_windows().is_empty());

        let finish = timeline
            .apply(TimelineInput::Finish { record_seq: 2, at: SessionTime::from_nanos(30) })
            .expect("finish drains materialized windows");
        assert_eq!(
            finish
                .published_windows()
                .iter()
                .map(|window| (window.id().get(), window.observations().len()))
                .collect::<Vec<_>>(),
            [(0, 1), (2, 0)]
        );
    }

    #[test]
    fn finish_closes_inactivity_spans_at_finish_time_and_omits_zero_length() {
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 10,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config.clone());

        timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 0)))
            .expect("observation starts the stream");
        timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(10),
            })
            .expect("advance starts the inactivity span and materializes window one");
        let finish = timeline
            .apply(TimelineInput::Finish { record_seq: 2, at: SessionTime::from_nanos(15) })
            .expect("finish closes the open inactivity span");

        assert_eq!(finish.published_windows().len(), 1);
        let published = &finish.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(1));
        assert_eq!(published.missing_spans().len(), 1);
        assert_eq!(published.missing_spans()[0].interval().start(), SessionTime::from_nanos(10));
        assert_eq!(published.missing_spans()[0].interval().end(), SessionTime::from_nanos(15));

        let mut equality_timeline = Timeline::new_unchecked_for_behavior_test(config);
        equality_timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 0)))
            .expect("equality observation starts the stream");
        let equality_finish = equality_timeline
            .apply(TimelineInput::Finish { record_seq: 1, at: SessionTime::from_nanos(10) })
            .expect("finish at inactivity equality omits the zero-length span");
        assert_eq!(
            equality_finish
                .published_windows()
                .iter()
                .map(|window| window.id().get())
                .collect::<Vec<_>>(),
            [0]
        );
        assert!(equality_finish.published_windows()[0].missing_spans().is_empty());
    }

    #[test]
    fn empty_finish_materializes_nothing_and_finished_takes_error_priority() {
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 100,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        let finish = timeline
            .apply(TimelineInput::Finish { record_seq: 10, at: SessionTime::from_nanos(10) })
            .expect("empty finish succeeds without materializing its boundary");
        assert!(finish.observation().is_none());
        assert!(finish.published_windows().is_empty());

        for input in [
            TimelineInput::Observation(observation(source, profile, 7, 10, 9)),
            TimelineInput::TimelineAdvance { record_seq: 9, at: SessionTime::from_nanos(9) },
            TimelineInput::Finish { record_seq: 10, at: SessionTime::from_nanos(9) },
        ] {
            assert_eq!(
                timeline.apply(input).expect_err("finished timeline rejects every later input"),
                TimelineError::Finished
            );
        }
    }

    #[test]
    fn failed_finish_is_atomic_and_the_same_record_retry_publishes_original_state() {
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 100,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 5)))
            .expect("observation materializes window zero");
        assert_eq!(
            timeline
                .apply(TimelineInput::Finish { record_seq: 0, at: SessionTime::from_nanos(6) })
                .expect_err("duplicate finish record sequence must fail"),
            TimelineError::RecordSequenceRegression { previous: 0, actual: 0 }
        );
        assert_eq!(
            timeline
                .apply(TimelineInput::Finish { record_seq: 1, at: SessionTime::from_nanos(4) })
                .expect_err("regressive finish time must fail"),
            TimelineError::TimeRegression { previous: 5, actual: 4 }
        );

        let retry = timeline
            .apply(TimelineInput::Finish { record_seq: 1, at: SessionTime::from_nanos(8) })
            .expect("same record retry finishes the unchanged timeline");
        assert_eq!(retry.published_windows().len(), 1);
        let published = &retry.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(0));
        assert_eq!(published.observations().len(), 1);
        assert_eq!(published.observations()[0].observation().input().record_seq(), 0);
    }

    #[test]
    fn inactivity_at_equality_reactivates_with_a_new_segment_and_clipped_missing_span() {
        use ObservationDisposition::Windowed;
        use SequenceClassification::{First, InOrder};

        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 5,
            inactive_after_ns: 10,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        let first = timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 0)))
            .expect("first segment observation");
        assert_eq!(first.observation().expect("observation outcome").classification(), First);

        let equality = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(10),
            })
            .expect("advance at the exact inactivity threshold");
        assert!(equality.published_windows().is_empty());

        let reactivated = timeline
            .apply(TimelineInput::Observation(observation(source, profile, 8, 2, 15)))
            .expect("admissible observation reactivates the stream");
        assert_eq!(
            reactivated.observation().expect("observation outcome").classification(),
            InOrder
        );
        assert_eq!(
            reactivated.observation().expect("observation outcome").disposition(),
            Windowed { window_id: WindowId::new(1) }
        );

        let closes_window_one = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 3,
                at: SessionTime::from_nanos(25),
            })
            .expect("later advance closes the reactivation window");
        assert_eq!(closes_window_one.published_windows().len(), 1);
        let published = &closes_window_one.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(1));
        assert_eq!(published.observations().len(), 1);
        assert_eq!(published.observations()[0].segment_id().get(), 2);
        assert_eq!(published.missing_spans().len(), 1);
        let missing = &published.missing_spans()[0];
        assert_eq!(missing.stream(), published.observations()[0].stream_instance());
        assert_eq!(missing.segment_id().get(), 0);
        assert_eq!(missing.interval().start(), SessionTime::from_nanos(10));
        assert_eq!(missing.interval().end(), SessionTime::from_nanos(15));
        assert_eq!(missing.reason(), MissingSpanReason::Inactive);
    }

    #[test]
    fn new_boot_epoch_terminates_older_active_segments_before_watermarking() {
        use SequenceClassification::First;

        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(old_epoch, profile, 7, 0, 5)))
            .expect("old epoch observation materializes window zero");
        let transition = timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 40, 1, 15)))
            .expect("new epoch observation terminates the old epoch");

        assert_eq!(transition.observation().expect("observation outcome").classification(), First);
        assert_eq!(transition.published_windows().len(), 1);
        let published = &transition.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(0));
        assert_eq!(published.observations().len(), 1);
        assert_eq!(published.observations()[0].observation().input().record_seq(), 0);
        assert!(published.missing_spans().is_empty());
    }

    #[test]
    fn higher_epoch_terminates_all_active_streams_across_profiles_and_links() {
        use SequenceClassification::First;

        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile_a = CaptureProfileId::from_bytes([0xa1; 32]);
        let profile_b = CaptureProfileId::from_bytes([0xb2; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation_for_link_with_event(
                old_epoch, "link-a", profile_a, 7, 0, 5, 5,
            )))
            .expect("first old-epoch stream");
        timeline
            .apply(TimelineInput::Observation(observation_for_link_with_event(
                old_epoch, "link-b", profile_b, 8, 1, 5, 5,
            )))
            .expect("second old-epoch stream");
        let epoch_change = timeline
            .apply(TimelineInput::Observation(observation_for_link_with_event(
                new_epoch, "link-a", profile_a, 40, 2, 15, 15,
            )))
            .expect("higher epoch terminates every old stream for the device");

        assert_eq!(
            epoch_change.observation().expect("observation outcome").classification(),
            First
        );
        assert_eq!(epoch_change.published_windows().len(), 1);
        let published = &epoch_change.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(0));
        assert_eq!(published.observations().len(), 2);
        assert_eq!(
            published
                .observations()
                .iter()
                .map(|windowed| windowed.observation().link().as_str())
                .collect::<Vec<_>>(),
            ["link-a", "link-b"]
        );
        assert!(published.missing_spans().is_empty());
    }

    #[test]
    fn new_boot_epoch_in_the_same_window_does_not_force_publication_or_a_missing_span() {
        use SequenceClassification::First;

        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(old_epoch, profile, 7, 0, 5)))
            .expect("old epoch observation materializes window zero");
        let epoch_change = timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 40, 1, 6)))
            .expect("same-window epoch change");

        assert_eq!(
            epoch_change.observation().expect("observation outcome").classification(),
            First
        );
        assert!(epoch_change.published_windows().is_empty());

        let closing = timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 41, 2, 15)))
            .expect("later new-epoch observation closes window zero");
        assert_eq!(closing.published_windows().len(), 1);
        assert!(closing.published_windows()[0].missing_spans().is_empty());
    }

    #[test]
    fn higher_epoch_closes_an_older_inactive_span_at_its_receive_time() {
        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 10,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(old_epoch, profile, 7, 0, 0)))
            .expect("old epoch observation");
        timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(10),
            })
            .expect("old epoch becomes inactive");
        timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 40, 2, 15)))
            .expect("higher epoch closes the old inactivity span");
        let closing = timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 41, 3, 25)))
            .expect("later observation publishes window one");

        assert_eq!(closing.published_windows().len(), 1);
        let published = &closing.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(1));
        assert_eq!(published.missing_spans().len(), 1);
        let missing = &published.missing_spans()[0];
        assert_eq!(missing.interval().start(), SessionTime::from_nanos(10));
        assert_eq!(missing.interval().end(), SessionTime::from_nanos(15));
    }

    #[test]
    fn same_input_inactivity_and_higher_epoch_omit_the_zero_length_span() {
        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 10,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(old_epoch, profile, 7, 0, 0)))
            .expect("old epoch observation");
        let epoch_change = timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 40, 1, 10)))
            .expect("higher epoch arrives at the inactivity threshold");
        assert_eq!(epoch_change.published_windows().len(), 1);
        assert!(epoch_change.published_windows()[0].missing_spans().is_empty());

        let closing = timeline
            .apply(TimelineInput::Observation(observation(new_epoch, profile, 41, 2, 20)))
            .expect("later observation publishes window one");
        assert_eq!(closing.published_windows().len(), 1);
        assert!(closing.published_windows()[0].missing_spans().is_empty());
    }

    #[test]
    fn unadmitted_epoch_termination_defers_the_recorded_advance_fallback() {
        use ObservationDisposition::Late;

        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 100,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(old_epoch, profile, 7, 0, 5)))
            .expect("old epoch holds window zero open");
        let held = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(20),
            })
            .expect("recorded advance is held behind the old active watermark");
        assert!(held.published_windows().is_empty());

        let epoch_change = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                new_epoch, profile, 40, 2, 21, 5,
            )))
            .expect("late higher epoch terminates the old active stream");
        assert_eq!(
            epoch_change.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::EventTimeOutsideLateness }
        );
        assert!(epoch_change.published_windows().is_empty());

        let next_advance = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 3,
                at: SessionTime::from_nanos(21),
            })
            .expect("next advance makes the recorded fallback eligible");
        assert_eq!(next_advance.published_windows().len(), 1);
        assert_eq!(next_advance.published_windows()[0].id(), WindowId::new(0));
        assert_eq!(next_advance.published_windows()[0].observations().len(), 1);
        assert_eq!(
            next_advance.published_windows()[0].observations()[0]
                .observation()
                .input()
                .record_seq(),
            0
        );
    }

    #[test]
    fn unadmitted_epoch_termination_defers_closure_with_another_active_stream() {
        use ObservationDisposition::Late;

        let old_epoch = epoch(1, 1);
        let new_epoch = epoch(1, 2);
        let other_device = epoch(2, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 100,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(old_epoch, profile, 7, 0, 5)))
            .expect("old epoch holds window zero open");
        timeline
            .apply(TimelineInput::Observation(observation(other_device, profile, 40, 1, 15)))
            .expect("other device advances beyond window zero");

        let epoch_change = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                new_epoch, profile, 50, 2, 21, 5,
            )))
            .expect("late higher epoch terminates the low-watermark stream");
        assert_eq!(
            epoch_change.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::EventTimeOutsideLateness }
        );
        assert!(epoch_change.published_windows().is_empty());

        let next_advance = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 3,
                at: SessionTime::from_nanos(21),
            })
            .expect("next advance evaluates closure against the remaining active stream");
        assert_eq!(next_advance.published_windows().len(), 1);
        assert_eq!(next_advance.published_windows()[0].id(), WindowId::new(0));
        assert_eq!(next_advance.published_windows()[0].observations().len(), 1);
        assert_eq!(
            next_advance.published_windows()[0].observations()[0]
                .observation()
                .input()
                .record_seq(),
            0
        );
    }

    #[test]
    fn duplicate_and_late_inputs_do_not_reactivate_or_replace_advance_fallback() {
        use ObservationDisposition::{Duplicate, Late};

        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let closed_source = epoch(1, 1);
        let duplicate_source = epoch(2, 1);
        let beyond_source = epoch(3, 1);
        let event_time_source = epoch(4, 1);
        let driver_source = epoch(5, 1);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 2,
            inactive_after_ns: 4,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        for (record_seq, source) in
            [closed_source, duplicate_source, beyond_source, event_time_source]
                .into_iter()
                .enumerate()
        {
            timeline
                .apply(TimelineInput::Observation(observation(
                    source,
                    profile,
                    10,
                    record_seq as u64,
                    6,
                )))
                .expect("initial stream observation");
        }

        let closes_zero = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                driver_source,
                profile,
                10,
                4,
                10,
                12,
            )))
            .expect("driver expires the initial streams and closes window zero");
        assert_eq!(
            closes_zero
                .published_windows()
                .iter()
                .map(|window| window.id().get())
                .collect::<Vec<_>>(),
            [0]
        );

        let closed = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                closed_source,
                profile,
                11,
                5,
                11,
                9,
            )))
            .expect("closed-window input remains a session fact");
        assert_eq!(
            closed.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::ClosedWindow }
        );

        let duplicate = timeline
            .apply(TimelineInput::Observation(observation(duplicate_source, profile, 10, 6, 12)))
            .expect("duplicate input remains a session fact");
        assert_eq!(duplicate.observation().expect("observation outcome").disposition(), Duplicate);

        let beyond = timeline
            .apply(TimelineInput::Observation(observation(beyond_source, profile, 7, 7, 13)))
            .expect("beyond-horizon input remains a session fact");
        assert_eq!(
            beyond.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::BeyondReorderHorizon }
        );

        let event_time = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                event_time_source,
                profile,
                11,
                8,
                14,
                20,
            )))
            .expect("event-time-late input expires the driver but does not reactivate");
        assert_eq!(
            event_time.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::EventTimeOutsideLateness }
        );
        assert!(event_time.published_windows().is_empty());

        let before_fallback_reaches_window_end = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 9,
                at: SessionTime::from_nanos(20),
            })
            .expect("first recorded advance establishes the empty-active fallback");
        assert!(before_fallback_reaches_window_end.published_windows().is_empty());

        let closes_one = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 10,
                at: SessionTime::from_nanos(22),
            })
            .expect("recorded advance watermark closes window one");
        assert_eq!(closes_one.published_windows().len(), 1);
        let published = &closes_one.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(1));
        assert_eq!(published.missing_spans().len(), 5);
        assert_eq!(
            published
                .missing_spans()
                .iter()
                .map(|span| (
                    span.segment_id().get(),
                    span.interval().start().as_nanos(),
                    span.interval().end().as_nanos(),
                ))
                .collect::<Vec<_>>(),
            [(0, 10, 20), (1, 10, 20), (2, 10, 20), (3, 10, 20), (4, 14, 20)]
        );
    }

    #[test]
    fn inactivity_boundary_overflow_is_atomic_across_the_same_record_retry() {
        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 1,
            step_ns: 1,
            allowed_lateness_ns: 0,
            inactive_after_ns: 10,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);
        let last_activity_ns = u64::MAX - 9;

        timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, last_activity_ns)))
            .expect("initial observation has a representable window");

        let expected =
            TimelineError::InactivityArithmeticOverflow { last_activity_ns, inactive_after_ns: 10 };
        for _ in 0..2 {
            assert_eq!(
                timeline
                    .apply(TimelineInput::TimelineAdvance {
                        record_seq: 1,
                        at: SessionTime::from_nanos(last_activity_ns),
                    })
                    .expect_err("inactivity boundary must remain unrepresentable"),
                expected
            );
        }
    }

    #[test]
    fn failed_apply_is_atomic_for_record_time_and_window_arithmetic_errors() {
        use ObservationDisposition::Windowed;
        use SequenceClassification::{First, InOrder};

        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = || {
            WindowConfig::for_test(TestWindowConfig {
                width_ns: 10,
                step_ns: 10,
                allowed_lateness_ns: 0,
                inactive_after_ns: 1_000,
                reorder_horizon: 2,
            })
        };

        let mut record_timeline = Timeline::new_unchecked_for_behavior_test(config());
        apply_observation(&mut record_timeline, observation(source, profile, 7, 0, 1));
        assert_eq!(
            record_timeline
                .apply(TimelineInput::Observation(observation(source, profile, 8, 0, 2)))
                .expect_err("duplicate record sequence must fail"),
            TimelineError::RecordSequenceRegression { previous: 0, actual: 0 }
        );
        let after_record_error =
            apply_observation(&mut record_timeline, observation(source, profile, 8, 1, 2));
        assert_eq!(after_record_error.classification(), InOrder);
        assert_eq!(after_record_error.disposition(), Windowed { window_id: WindowId::new(0) });

        let mut time_timeline = Timeline::new_unchecked_for_behavior_test(config());
        apply_observation(&mut time_timeline, observation(source, profile, 7, 0, 5));
        assert_eq!(
            time_timeline
                .apply(TimelineInput::Observation(observation(source, profile, 8, 1, 4)))
                .expect_err("decreasing receive time must fail"),
            TimelineError::TimeRegression { previous: 5, actual: 4 }
        );
        let after_time_error =
            apply_observation(&mut time_timeline, observation(source, profile, 8, 1, 6));
        assert_eq!(after_time_error.classification(), InOrder);
        assert_eq!(after_time_error.disposition(), Windowed { window_id: WindowId::new(0) });

        let mut arithmetic_timeline = Timeline::new_unchecked_for_behavior_test(config());
        assert_eq!(
            arithmetic_timeline
                .apply(TimelineInput::Observation(observation(source, profile, 7, 0, u64::MAX,)))
                .expect_err("overflowing window end must fail"),
            TimelineError::WindowArithmeticOverflow { event_ns: u64::MAX }
        );
        let after_arithmetic_error =
            apply_observation(&mut arithmetic_timeline, observation(source, profile, 7, 0, 5));
        assert_eq!(after_arithmetic_error.classification(), First);
        assert_eq!(after_arithmetic_error.disposition(), Windowed { window_id: WindowId::new(0) });
    }

    #[test]
    fn event_time_admission_uses_absolute_lateness_and_retains_late_input_as_a_fact() {
        use ObservationDisposition::{Late, Windowed};
        use SequenceClassification::{First, InOrder};

        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 5,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        let before_receive = timeline
            .apply(TimelineInput::Observation(observation_with_event(source, profile, 7, 0, 5, 0)))
            .expect("event at the early lateness boundary");
        assert_eq!(
            before_receive.observation().expect("observation outcome").classification(),
            First
        );
        assert_eq!(
            before_receive.observation().expect("observation outcome").disposition(),
            Windowed { window_id: WindowId::new(0) }
        );

        let after_receive = timeline
            .apply(TimelineInput::Observation(observation_with_event(source, profile, 8, 1, 6, 11)))
            .expect("event at the late lateness boundary");
        assert_eq!(
            after_receive.observation().expect("observation outcome").classification(),
            InOrder
        );
        assert_eq!(
            after_receive.observation().expect("observation outcome").disposition(),
            Windowed { window_id: WindowId::new(1) }
        );

        let outside = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                source, profile, 9, 2, 7, 100,
            )))
            .expect("event outside the lateness boundary remains a classified fact");
        assert_eq!(outside.observation().expect("observation outcome").classification(), InOrder);
        assert_eq!(
            outside.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::EventTimeOutsideLateness }
        );
        assert_eq!(LateReason::EventTimeOutsideLateness.as_str(), "event_time_outside_lateness");
        assert!(outside.published_windows().is_empty());

        assert_eq!(
            timeline
                .apply(TimelineInput::TimelineAdvance {
                    record_seq: 3,
                    at: SessionTime::from_nanos(6),
                })
                .expect_err("late observation must still advance the explicit clock"),
            TimelineError::TimeRegression { previous: 7, actual: 6 }
        );

        let closing = timeline
            .apply(TimelineInput::Observation(observation(source, profile, 10, 3, 120)))
            .expect("later observation closes eligible materialized windows");
        assert_eq!(
            closing.published_windows().iter().map(|window| window.id().get()).collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn an_event_within_lateness_is_late_when_its_window_is_logically_closed() {
        use ObservationDisposition::{Late, Windowed};

        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 5,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        let first = timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 5)))
            .expect("first window observation");
        assert_eq!(
            first.observation().expect("observation outcome").disposition(),
            Windowed { window_id: WindowId::new(0) }
        );

        let closes_first = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                source, profile, 8, 1, 10, 15,
            )))
            .expect("boundary observation closes the first window");
        assert_eq!(
            closes_first
                .published_windows()
                .iter()
                .map(|window| window.id().get())
                .collect::<Vec<_>>(),
            [0]
        );

        let closed = timeline
            .apply(TimelineInput::Observation(observation_with_event(source, profile, 9, 2, 11, 9)))
            .expect("within-lateness event targeting a closed window");
        assert_eq!(
            closed.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::ClosedWindow }
        );
        assert_eq!(LateReason::ClosedWindow.as_str(), "closed_window");
        assert!(closed.published_windows().is_empty());
    }

    #[test]
    fn recorded_advances_materialize_only_exact_boundaries_and_drive_an_empty_timeline() {
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 20,
            allowed_lateness_ns: 5,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        let at_zero = timeline
            .apply(TimelineInput::TimelineAdvance { record_seq: 0, at: SessionTime::from_nanos(0) })
            .expect("advance at the first exact boundary");
        assert!(at_zero.published_windows().is_empty());

        let closes_zero = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 1,
                at: SessionTime::from_nanos(15),
            })
            .expect("later advance closes the first materialized window");
        assert_eq!(
            closes_zero
                .published_windows()
                .iter()
                .map(|window| (window.id().get(), window.observations().len()))
                .collect::<Vec<_>>(),
            [(0, 0)]
        );

        let skips_boundary = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 2,
                at: SessionTime::from_nanos(35),
            })
            .expect("advance past an unrecorded boundary");
        assert!(skips_boundary.published_windows().is_empty());

        let at_forty = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 3,
                at: SessionTime::from_nanos(40),
            })
            .expect("advance at the next recorded boundary");
        assert!(at_forty.published_windows().is_empty());

        let closes_forty = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 4,
                at: SessionTime::from_nanos(55),
            })
            .expect("later advance closes only the recorded boundary window");
        assert_eq!(
            closes_forty
                .published_windows()
                .iter()
                .map(|window| (window.id().get(), window.observations().len()))
                .collect::<Vec<_>>(),
            [(2, 0)]
        );
    }

    #[test]
    fn published_windows_expose_intervals_segments_quality_and_canonical_observation_order() {
        use ObservationDisposition::Windowed;
        use SequenceClassification::{First, InOrder};

        let source = epoch(1, 1);
        let profile_a = CaptureProfileId::from_bytes([0xa1; 32]);
        let profile_b = CaptureProfileId::from_bytes([0xb2; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 10,
            allowed_lateness_ns: 0,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        timeline
            .apply(TimelineInput::Observation(observation(source, profile_b, 7, 0, 5)))
            .expect("lexicographically later stream arrives first");
        timeline
            .apply(TimelineInput::Observation(observation(source, profile_a, 8, 1, 6)))
            .expect("lexicographically earlier stream arrives second");
        timeline
            .apply(TimelineInput::Observation(observation(source, profile_b, 9, 2, 15)))
            .expect("later stream advances to the next window");
        let closing = timeline
            .apply(TimelineInput::Observation(observation(source, profile_a, 10, 3, 16)))
            .expect("earlier stream advances and closes the first window");

        assert_eq!(closing.published_windows().len(), 1);
        let published = &closing.published_windows()[0];
        assert_eq!(published.id(), WindowId::new(0));
        assert_eq!(published.interval().start(), SessionTime::from_nanos(0));
        assert_eq!(published.interval().end(), SessionTime::from_nanos(10));
        assert_eq!(
            published
                .observations()
                .iter()
                .map(|windowed| windowed.observation().input().record_seq())
                .collect::<Vec<_>>(),
            [1, 0]
        );
        assert_eq!(
            published
                .observations()
                .iter()
                .map(|windowed| windowed.segment_id().get())
                .collect::<Vec<_>>(),
            [1, 0]
        );
        assert_eq!(
            published
                .observations()
                .iter()
                .map(|windowed| windowed.classification())
                .collect::<Vec<_>>(),
            [InOrder, First]
        );
        assert_eq!(
            published
                .observations()
                .iter()
                .map(|windowed| windowed.disposition())
                .collect::<Vec<_>>(),
            [Windowed { window_id: WindowId::new(0) }, Windowed { window_id: WindowId::new(0) },]
        );
    }

    #[test]
    fn windows_use_width_step_and_active_event_watermarks() {
        use ObservationDisposition::{InterWindowGap, Late, Windowed};
        use SequenceClassification::{First, InOrder};

        let source = epoch(1, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let config = WindowConfig::for_test(TestWindowConfig {
            width_ns: 10,
            step_ns: 20,
            allowed_lateness_ns: 5,
            inactive_after_ns: 1_000,
            reorder_horizon: 2,
        });
        let mut timeline = Timeline::new_unchecked_for_behavior_test(config);

        let first = timeline
            .apply(TimelineInput::Observation(observation(source, profile, 7, 0, 9)))
            .expect("first observation");
        assert_eq!(first.observation().expect("observation outcome").classification(), First);
        assert_eq!(
            first.observation().expect("observation outcome").disposition(),
            Windowed { window_id: WindowId::new(0) }
        );
        assert!(first.published_windows().is_empty());

        let gap = timeline
            .apply(TimelineInput::Observation(observation(source, profile, 8, 1, 10)))
            .expect("inter-window observation");
        assert_eq!(gap.observation().expect("observation outcome").classification(), InOrder);
        assert_eq!(gap.observation().expect("observation outcome").disposition(), InterWindowGap);
        assert!(gap.published_windows().is_empty());

        let advance = timeline
            .apply(TimelineInput::TimelineAdvance {
                record_seq: 2,
                at: SessionTime::from_nanos(30),
            })
            .expect("recorded advance");
        assert!(advance.observation().is_none());
        assert!(advance.published_windows().is_empty());

        let later = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                source, profile, 9, 3, 31, 29,
            )))
            .expect("later window observation");
        assert_eq!(later.observation().expect("observation outcome").classification(), InOrder);
        assert_eq!(
            later.observation().expect("observation outcome").disposition(),
            Windowed { window_id: WindowId::new(1) }
        );
        assert_eq!(later.published_windows().len(), 1);
        assert_eq!(later.published_windows()[0].id().get(), 0);
        assert_eq!(later.published_windows()[0].observations().len(), 1);
        assert_eq!(
            later.published_windows()[0].observations()[0].stream_instance(),
            first.observation().expect("observation outcome").stream_instance()
        );
        assert_eq!(later.published_windows()[0].observations()[0].classification(), First);
        assert_eq!(
            later.published_windows()[0].observations()[0].observation().input().record_seq(),
            0
        );

        let late = timeline
            .apply(TimelineInput::Observation(observation_with_event(
                source, profile, 10, 4, 32, 9,
            )))
            .expect("observation targeting a closed window");
        assert_eq!(late.observation().expect("observation outcome").classification(), InOrder);
        assert_eq!(
            late.observation().expect("observation outcome").disposition(),
            Late { reason: LateReason::EventTimeOutsideLateness }
        );
        assert!(late.published_windows().is_empty());
    }

    #[test]
    fn source_sequence_classification_is_independent_per_device_epoch() {
        use SequenceClassification::{Duplicate, First, Gap, InOrder, Reordered};

        let source_a = epoch(1, 1);
        let source_b = epoch(2, 1);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let mut timeline = test_timeline();

        let actual = [
            apply_observation(&mut timeline, observation(source_a, profile, 7, 0, 100))
                .classification(),
            apply_observation(&mut timeline, observation(source_b, profile, 40, 1, 101))
                .classification(),
            apply_observation(&mut timeline, observation(source_a, profile, 8, 2, 102))
                .classification(),
            apply_observation(&mut timeline, observation(source_a, profile, 11, 3, 103))
                .classification(),
            apply_observation(&mut timeline, observation(source_b, profile, 41, 4, 104))
                .classification(),
            apply_observation(&mut timeline, observation(source_a, profile, 10, 5, 105))
                .classification(),
            apply_observation(&mut timeline, observation(source_a, profile, 10, 6, 106))
                .classification(),
        ];

        assert_eq!(
            actual,
            [
                First,
                First,
                InOrder,
                Gap { missing: 2 },
                InOrder,
                Reordered { distance: 1 },
                Duplicate,
            ]
        );
    }

    #[test]
    fn source_sequence_horizon_epoch_and_u64_boundaries_are_classified_through_timeline() {
        use SequenceClassification::{Duplicate, First, Gap, InOrder, Reordered};

        let source = epoch(1, 1);
        let maximum_source = epoch(2, 1);
        let next_boot = epoch(2, 2);
        let profile = CaptureProfileId::from_bytes([0xa1; 32]);
        let mut timeline = test_timeline();

        let actual = [
            apply_observation(&mut timeline, observation(source, profile, 10, 0, 200))
                .classification(),
            apply_observation(&mut timeline, observation(source, profile, 13, 1, 201))
                .classification(),
            apply_observation(&mut timeline, observation(source, profile, 11, 2, 202))
                .classification(),
            apply_observation(&mut timeline, observation(source, profile, 11, 3, 203))
                .classification(),
            apply_observation(&mut timeline, observation(source, profile, 10, 4, 204))
                .classification(),
            apply_observation(&mut timeline, observation(source, profile, 10, 5, 205))
                .classification(),
            apply_observation(
                &mut timeline,
                observation(maximum_source, profile, u64::MAX - 1, 6, 206),
            )
            .classification(),
            apply_observation(
                &mut timeline,
                observation(maximum_source, profile, u64::MAX, 7, 207),
            )
            .classification(),
            apply_observation(&mut timeline, observation(maximum_source, profile, 0, 8, 208))
                .classification(),
            apply_observation(&mut timeline, observation(next_boot, profile, u64::MAX, 9, 209))
                .classification(),
        ];

        assert_eq!(
            actual,
            [
                First,
                Gap { missing: 2 },
                Reordered { distance: 2 },
                Duplicate,
                Reordered { distance: 3 },
                Reordered { distance: 3 },
                First,
                InOrder,
                Reordered { distance: u64::MAX },
                First,
            ]
        );

        let beyond_horizon =
            apply_observation(&mut timeline, observation(source, profile, 9, 10, 210));
        assert_eq!(beyond_horizon.classification(), Reordered { distance: 4 });
        assert_eq!(
            beyond_horizon.disposition(),
            ObservationDisposition::Late { reason: LateReason::BeyondReorderHorizon }
        );
        assert_eq!(LateReason::BeyondReorderHorizon.as_str(), "beyond_reorder_horizon");
    }

    #[test]
    fn apply_classifies_before_profile_partition() {
        use SequenceClassification::{First, InOrder};

        let profile_a = CaptureProfileId::from_bytes([0xa1; 32]);
        let profile_b = CaptureProfileId::from_bytes([0xb2; 32]);
        let source = epoch(1, 1);
        let mut timeline = test_timeline();

        let first = apply_observation(&mut timeline, observation(source, profile_a, 7, 0, 300));
        let second = apply_observation(&mut timeline, observation(source, profile_b, 8, 1, 301));
        let third = apply_observation(&mut timeline, observation(source, profile_a, 9, 2, 302));

        assert_eq!(
            [first.classification(), second.classification(), third.classification()],
            [First, InOrder, InOrder]
        );
        assert_eq!(first.stream_instance(), third.stream_instance());
        assert_ne!(first.stream_instance(), second.stream_instance());
    }
}
