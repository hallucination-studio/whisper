use thiserror::Error;

use super::DerivedBounds;
use super::{
    ObservationDisposition, SequenceClassification, StreamState, TerminationReason, Timeline,
    WindowObservation,
};
use crate::domain::csi::{
    ComplexOrder, CsiCapture, CsiObservation, CsiPath, CsiSampleAxis, PhaseState, PpduKind,
    SampleOrder,
};
use crate::domain::identity::{DeviceEpoch, HardwareKind, StreamInstanceId};
use crate::domain::time::MAX_TIMELINE_CLOCK_TEXT_BYTES;
use crate::domain::time::{EventTimeSource, FrameTiming};
use ciborium::ser::into_writer;
use ciborium::value::Value;

const ROOT_KEYS: &[&str] = &[
    "schema_version",
    "window_contract_id",
    "session_id",
    "last_record_seq",
    "explicit_clock_ns",
    "last_advance_ns",
    "source_states",
    "stream_states",
    "closed_window_frontier",
    "open_windows",
    "missing_spans",
    "finished",
];
const DEVICE_EPOCH_KEYS: &[&str] = &["device", "boot_generation"];
const EPOCH_TERMINATION_KEYS: &[&str] = &["record_seq", "received_ns", "new_device_epoch"];
const STREAM_IDENTITY_KEYS: &[&str] = &["sensor", "link", "profile", "device_epoch"];
const SEEN_RANGE_KEYS: &[&str] = &["first", "last"];
const SOURCE_STATE_KEYS: &[&str] = &["device_epoch", "maximum_sequence", "seen_ranges"];
const STREAM_STATE_KEYS: &[&str] = &[
    "stream",
    "segment_id",
    "status",
    "last_activity_ns",
    "maximum_event_ns",
    "ended_at_ns",
    "end_reason",
    "epoch_termination",
];
const OPEN_WINDOW_KEYS: &[&str] = &["window_id", "start_ns", "end_ns", "observations"];
const MISSING_SPAN_KEYS: &[&str] = &["stream", "segment_id", "start_ns", "end_ns", "reason"];
const BUFFERED_OBSERVATION_KEYS: &[&str] =
    &["segment_id", "classification", "disposition", "observation"];
const CLASSIFICATION_KEYS: &[&str] = &["kind", "value"];
const DISPOSITION_KEYS: &[&str] = &["kind", "window_id", "reason"];
const CSI_OBSERVATION_KEYS: &[&str] = &[
    "input",
    "sensor",
    "hardware",
    "link",
    "device_epoch",
    "capture_sequence",
    "callback_tick_us",
    "timing",
    "radio",
    "profile",
    "csi",
];
const INPUT_RECEIPT_KEYS: &[&str] = &["session", "record_seq", "decoder_version"];
const DEVICE_TIMESTAMP_KEYS: &[&str] = &["ticks", "clock_domain"];
const FRAME_TIMING_KEYS: &[&str] =
    &["received_ns", "device", "event_ns", "source", "mapping_version", "uncertainty_ns"];
const RADIO_METADATA_KEYS: &[&str] =
    &["channel", "centre_frequency_hz", "bandwidth_hz", "ppdu", "rssi_dbm", "noise_floor_dbm"];
const CSI_CAPTURE_KEYS: &[&str] = &["layout", "samples", "encoding", "phase_state"];
const CSI_LAYOUT_KEYS: &[&str] = &["paths", "samples", "order"];
const SAMPLE_ENCODING_KEYS: &[&str] =
    &["signed_bits", "scale_numerator", "scale_denominator", "complex_order"];
const IQ_SAMPLE_KEYS: &[&str] = &["i", "q", "valid"];
const CSI_PATH_TX_RX_KEYS: &[&str] = &["kind", "tx_stream", "rx_chain"];
const CSI_PATH_RAW_KEYS: &[&str] = &["kind", "ordinal"];
const SAMPLE_AXIS_COUNT_KEYS: &[&str] = &["kind", "count"];
const SAMPLE_AXIS_VALUES_KEYS: &[&str] = &["kind", "values"];

const MAX_U64_LEN: u64 = 9;
const MAX_U32_LEN: u64 = 5;
const MAX_U16_LEN: u64 = 3;
const MAX_U8_LEN: u64 = 2;
const MAX_I32_LEN: u64 = 5;
const MAX_I8_LEN: u64 = 2;
const NULL_LEN: u64 = 1;
const BOOL_LEN: u64 = 1;
const CAPTURE_PROFILE_ID_BYTES: u64 = 32;
const WINDOW_CONTRACT_ID_BYTES: u64 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RouteReceiptCaps {
    pub(super) sensor_text_bytes: usize,
    pub(super) link_text_bytes: usize,
    pub(super) hardware_text_bytes: usize,
    pub(super) logical_samples: u64,
    pub(super) observation_capacity: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct StateBoundInput<'a> {
    pub(super) session_text_bytes: usize,
    pub(super) decoder_text_bytes: usize,
    pub(super) reorder_horizon: u32,
    pub(super) bounds: &'a DerivedBounds,
    pub(super) routes: &'a [RouteReceiptCaps],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SizingStage {
    InputValidation,
    Text,
    Map,
    Array,
    Layout,
    ObservationArrayHeaders,
    Observation,
    Root,
}

impl SizingStage {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InputValidation => "input_validation",
            Self::Text => "text",
            Self::Map => "map",
            Self::Array => "array",
            Self::Layout => "layout",
            Self::ObservationArrayHeaders => "observation_array_headers",
            Self::Observation => "observation",
            Self::Root => "root",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum StateBoundError {
    #[error("canonical CBOR size arithmetic overflow while sizing {stage:?}")]
    Arithmetic { stage: SizingStage },
    #[error("no route receipt caps were supplied for timeline state sizing")]
    MissingRouteCaps,
    #[error("state-bound route count {actual} does not match derived route count {expected}")]
    RouteCountMismatch { expected: u64, actual: u64 },
    #[error(
        "state-bound observation capacity {actual} does not match derived buffered observation count {expected}"
    )]
    ObservationCapacityMismatch { expected: u64, actual: u64 },
}

pub(super) fn canonical_max_len(input: StateBoundInput<'_>) -> Result<u64, StateBoundError> {
    if input.routes.is_empty() {
        return Err(StateBoundError::MissingRouteCaps);
    }
    let actual_route_count = u64::try_from(input.routes.len())
        .map_err(|_| StateBoundError::Arithmetic { stage: SizingStage::InputValidation })?;
    if actual_route_count != input.bounds.route_count {
        return Err(StateBoundError::RouteCountMismatch {
            expected: input.bounds.route_count,
            actual: actual_route_count,
        });
    }
    let observation_capacity = input.routes.iter().try_fold(0u64, |total, route| {
        total
            .checked_add(route.observation_capacity)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::InputValidation })
    })?;
    if observation_capacity != input.bounds.max_buffered_observations {
        return Err(StateBoundError::ObservationCapacityMismatch {
            expected: input.bounds.max_buffered_observations,
            actual: observation_capacity,
        });
    }
    let retained_entries = observation_capacity
        .checked_add(actual_route_count)
        .ok_or(StateBoundError::Arithmetic { stage: SizingStage::InputValidation })?;

    let device_epoch = map_len(DEVICE_EPOCH_KEYS, &[MAX_U64_LEN, MAX_U32_LEN])?;
    let epoch_termination =
        map_len(EPOCH_TERMINATION_KEYS, &[MAX_U64_LEN, MAX_U64_LEN, device_epoch])?;
    let seen_range = map_len(SEEN_RANGE_KEYS, &[MAX_U64_LEN, MAX_U64_LEN])?;
    let seen_ranges = array_len(
        input.bounds.max_seen_sequence_ranges_per_source,
        seen_range,
        SizingStage::Array,
    )?;
    let source_state = map_len(SOURCE_STATE_KEYS, &[device_epoch, MAX_U64_LEN, seen_ranges])?;

    let gap_classification = map_len(CLASSIFICATION_KEYS, &[text_len("gap")?, MAX_U64_LEN])?;
    let reordered_classification = map_len(
        CLASSIFICATION_KEYS,
        &[text_len("reordered")?, cbor_header_len(u64::from(input.reorder_horizon))],
    )?;
    let maximum_classification = gap_classification.max(reordered_classification);
    let windowed_disposition =
        map_len(DISPOSITION_KEYS, &[text_len("windowed")?, MAX_U64_LEN, NULL_LEN])?;
    let input_receipt = map_len(
        INPUT_RECEIPT_KEYS,
        &[
            bounded_text_len(input.session_text_bytes)?,
            MAX_U64_LEN,
            bounded_text_len(input.decoder_text_bytes)?,
        ],
    )?;
    let mut stream_state_payload = 0u64;
    let mut missing_span_payload = 0u64;
    let mut observation_payload = 0u64;
    for route in input.routes {
        let stream_identity = stream_identity_len(*route, device_epoch)?;
        let terminated_epoch_stream = map_len(
            STREAM_STATE_KEYS,
            &[
                stream_identity,
                MAX_U64_LEN,
                text_len("terminated")?,
                MAX_U64_LEN,
                MAX_U64_LEN,
                MAX_U64_LEN,
                text_len("epoch")?,
                epoch_termination,
            ],
        )?;
        let missing_span = map_len(
            MISSING_SPAN_KEYS,
            &[stream_identity, MAX_U64_LEN, MAX_U64_LEN, MAX_U64_LEN, text_len("inactive")?],
        )?;
        let buffered_observation = map_len(
            BUFFERED_OBSERVATION_KEYS,
            &[
                MAX_U64_LEN,
                maximum_classification,
                windowed_disposition,
                observation_len(*route, input_receipt, device_epoch)?,
            ],
        )?;
        let retained_route_states = route
            .observation_capacity
            .checked_add(1)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Root })?;
        stream_state_payload = stream_state_payload
            .checked_add(checked_mul(
                retained_route_states,
                terminated_epoch_stream,
                SizingStage::Root,
            )?)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Root })?;
        missing_span_payload = missing_span_payload
            .checked_add(checked_mul(retained_route_states, missing_span, SizingStage::Root)?)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Root })?;
        observation_payload = observation_payload
            .checked_add(checked_mul(
                route.observation_capacity,
                buffered_observation,
                SizingStage::Root,
            )?)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Root })?;
    }

    let observation_array_headers = maximum_array_header_sum(
        input.bounds.max_open_windows,
        input.bounds.max_buffered_observations,
    )?;
    let open_window_without_observation_header =
        map_len(OPEN_WINDOW_KEYS, &[MAX_U64_LEN, MAX_U64_LEN, MAX_U64_LEN, 0])?;
    let open_window_state = checked_sum(
        &[
            cbor_header_len(input.bounds.max_open_windows),
            checked_mul(
                input.bounds.max_open_windows,
                open_window_without_observation_header,
                SizingStage::Root,
            )?,
            observation_array_headers,
            observation_payload,
        ],
        SizingStage::Root,
    )?;

    let source_states = array_len(retained_entries, source_state, SizingStage::Root)?;
    let stream_states = cbor_header_len(retained_entries)
        .checked_add(stream_state_payload)
        .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Root })?;
    let missing_spans = cbor_header_len(retained_entries)
        .checked_add(missing_span_payload)
        .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Root })?;
    let root = map_len(
        ROOT_KEYS,
        &[
            cbor_header_len(1),
            byte_string_len(WINDOW_CONTRACT_ID_BYTES)?,
            bounded_text_len(input.session_text_bytes)?,
            MAX_U64_LEN,
            MAX_U64_LEN,
            MAX_U64_LEN,
            source_states,
            stream_states,
            MAX_U64_LEN,
            open_window_state,
            missing_spans,
            BOOL_LEN,
        ],
    )?;
    Ok(root)
}

fn observation_len(
    route: RouteReceiptCaps,
    input_receipt: u64,
    device_epoch: u64,
) -> Result<u64, StateBoundError> {
    let device_timestamp = map_len(
        DEVICE_TIMESTAMP_KEYS,
        &[MAX_U64_LEN, bounded_text_len(MAX_TIMELINE_CLOCK_TEXT_BYTES)?],
    )?;
    let frame_timing = map_len(
        FRAME_TIMING_KEYS,
        &[
            MAX_U64_LEN,
            device_timestamp,
            MAX_U64_LEN,
            text_len("clock_corrected")?,
            bounded_text_len(MAX_TIMELINE_CLOCK_TEXT_BYTES)?,
            MAX_U64_LEN,
        ],
    )?;
    let radio_metadata = map_len(
        RADIO_METADATA_KEYS,
        &[MAX_U16_LEN, MAX_U64_LEN, MAX_U64_LEN, text_len("legacy")?, MAX_I8_LEN, MAX_I8_LEN],
    )?;
    let sample_encoding = map_len(
        SAMPLE_ENCODING_KEYS,
        &[MAX_U8_LEN, MAX_U32_LEN, MAX_U32_LEN, text_len("real_imaginary")?],
    )?;
    let iq_sample = map_len(IQ_SAMPLE_KEYS, &[MAX_I32_LEN, MAX_I32_LEN, BOOL_LEN])?;
    let csi_capture = map_len(
        CSI_CAPTURE_KEYS,
        &[
            maximum_csi_layout_len(route.logical_samples)?,
            array_len(route.logical_samples, iq_sample, SizingStage::Observation)?,
            sample_encoding,
            text_len("unavailable")?,
        ],
    )?;
    map_len(
        CSI_OBSERVATION_KEYS,
        &[
            input_receipt,
            bounded_text_len(route.sensor_text_bytes)?,
            bounded_text_len(route.hardware_text_bytes)?,
            bounded_text_len(route.link_text_bytes)?,
            device_epoch,
            MAX_U64_LEN,
            MAX_U64_LEN,
            frame_timing,
            radio_metadata,
            byte_string_len(CAPTURE_PROFILE_ID_BYTES)?,
            csi_capture,
        ],
    )
}

fn stream_identity_len(route: RouteReceiptCaps, device_epoch: u64) -> Result<u64, StateBoundError> {
    map_len(
        STREAM_IDENTITY_KEYS,
        &[
            bounded_text_len(route.sensor_text_bytes)?,
            bounded_text_len(route.link_text_bytes)?,
            byte_string_len(CAPTURE_PROFILE_ID_BYTES)?,
            device_epoch,
        ],
    )
}

fn maximum_csi_layout_len(logical_samples: u64) -> Result<u64, StateBoundError> {
    layout_len(logical_samples, 1, PathVariant::TxRx, AxisVariant::FrequencyHz)
}

#[derive(Clone, Copy)]
enum PathVariant {
    TxRx,
    RawPathOrdinal,
}

#[derive(Clone, Copy)]
enum AxisVariant {
    OpaqueSampleOrdinal,
    IeeeToneIndex,
    FrequencyHz,
}

fn layout_len(
    paths: u64,
    axis_values: u64,
    path_variant: PathVariant,
    axis_variant: AxisVariant,
) -> Result<u64, StateBoundError> {
    let path = match path_variant {
        PathVariant::TxRx => {
            map_len(CSI_PATH_TX_RX_KEYS, &[text_len("tx_rx")?, MAX_U16_LEN, MAX_U16_LEN])?
        }
        PathVariant::RawPathOrdinal => {
            map_len(CSI_PATH_RAW_KEYS, &[text_len("raw_path_ordinal")?, MAX_U16_LEN])?
        }
    };
    let axis = match axis_variant {
        AxisVariant::OpaqueSampleOrdinal => map_len(
            SAMPLE_AXIS_COUNT_KEYS,
            &[text_len("opaque_sample_ordinal")?, cbor_header_len(axis_values)],
        )?,
        AxisVariant::IeeeToneIndex => map_len(
            SAMPLE_AXIS_VALUES_KEYS,
            &[
                text_len("ieee_tone_index")?,
                array_len(axis_values, MAX_U16_LEN, SizingStage::Layout)?,
            ],
        )?,
        AxisVariant::FrequencyHz => map_len(
            SAMPLE_AXIS_VALUES_KEYS,
            &[text_len("frequency_hz")?, array_len(axis_values, MAX_U64_LEN, SizingStage::Layout)?],
        )?,
    };
    map_len(
        CSI_LAYOUT_KEYS,
        &[array_len(paths, path, SizingStage::Layout)?, axis, text_len("path_then_sample")?],
    )
}

fn maximum_array_header_sum(arrays: u64, elements: u64) -> Result<u64, StateBoundError> {
    let mut total = arrays;
    let mut remaining = elements;
    let mut eligible = arrays;
    for (additional_elements, header_bonus) in
        [(24u64, 1u64), (232, 1), (65_280, 2), (4_294_901_760, 4)]
    {
        let upgraded = eligible.min(remaining / additional_elements);
        remaining = remaining
            .checked_sub(checked_mul(
                upgraded,
                additional_elements,
                SizingStage::ObservationArrayHeaders,
            )?)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::ObservationArrayHeaders })?;
        total = total
            .checked_add(checked_mul(upgraded, header_bonus, SizingStage::ObservationArrayHeaders)?)
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::ObservationArrayHeaders })?;
        eligible = upgraded;
    }
    Ok(total)
}

fn map_len(keys: &[&str], values: &[u64]) -> Result<u64, StateBoundError> {
    assert_eq!(keys.len(), values.len(), "TimelineState schema map key/value arity mismatch");
    let key_count = u64::try_from(keys.len())
        .map_err(|_| StateBoundError::Arithmetic { stage: SizingStage::Map })?;
    let mut total = cbor_header_len(key_count);
    for (key, value) in keys.iter().zip(values) {
        total = total
            .checked_add(text_len(key)?)
            .and_then(|size| size.checked_add(*value))
            .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Map })?;
    }
    Ok(total)
}

fn array_len(count: u64, item: u64, stage: SizingStage) -> Result<u64, StateBoundError> {
    cbor_header_len(count)
        .checked_add(checked_mul(count, item, stage)?)
        .ok_or(StateBoundError::Arithmetic { stage })
}

fn byte_string_len(bytes: u64) -> Result<u64, StateBoundError> {
    cbor_header_len(bytes)
        .checked_add(bytes)
        .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Text })
}

fn text_len(value: &str) -> Result<u64, StateBoundError> {
    bounded_text_len(value.len())
}

fn bounded_text_len(bytes: usize) -> Result<u64, StateBoundError> {
    let bytes = u64::try_from(bytes)
        .map_err(|_| StateBoundError::Arithmetic { stage: SizingStage::Text })?;
    bounded_text_len_u64(bytes)
}

fn bounded_text_len_u64(bytes: u64) -> Result<u64, StateBoundError> {
    cbor_header_len(bytes)
        .checked_add(bytes)
        .ok_or(StateBoundError::Arithmetic { stage: SizingStage::Text })
}

fn checked_mul(left: u64, right: u64, stage: SizingStage) -> Result<u64, StateBoundError> {
    left.checked_mul(right).ok_or(StateBoundError::Arithmetic { stage })
}

fn checked_sum(values: &[u64], stage: SizingStage) -> Result<u64, StateBoundError> {
    values.iter().try_fold(0u64, |total, value| {
        total.checked_add(*value).ok_or(StateBoundError::Arithmetic { stage })
    })
}

pub(super) fn encode(timeline: &Timeline) -> Box<[u8]> {
    let root = table_map(
        ROOT_KEYS,
        vec![
            unsigned(1),
            Value::Bytes(timeline.config.window_contract_id.as_bytes().to_vec()),
            text(timeline.config.session_id.as_str()),
            optional_unsigned(timeline.last_record_seq),
            optional_unsigned(timeline.explicit_clock.map(|time| time.as_nanos())),
            optional_unsigned(timeline.last_advance.map(|time| time.as_nanos())),
            source_states(timeline),
            stream_states(timeline),
            optional_unsigned(timeline.closed_frontier.map(|id| id.get())),
            open_windows(timeline),
            missing_spans(timeline),
            Value::Bool(timeline.finished),
        ],
    );
    let mut bytes = Vec::new();
    into_writer(&root, &mut bytes)
        .expect("serializing canonical Timeline state into an in-memory Vec must not fail");
    bytes.into_boxed_slice()
}

fn source_states(timeline: &Timeline) -> Value {
    Value::Array(
        timeline
            .sources
            .iter()
            .map(|(epoch, state)| {
                let mut ranges = Vec::new();
                let mut values = state.recent_seen.iter().copied();
                if let Some(mut first) = values.next() {
                    let mut last = first;
                    for value in values {
                        if last.checked_add(1) == Some(value) {
                            last = value;
                        } else {
                            ranges.push(seen_range(first, last));
                            first = value;
                            last = value;
                        }
                    }
                    ranges.push(seen_range(first, last));
                }
                table_map(
                    SOURCE_STATE_KEYS,
                    vec![device_epoch(*epoch), unsigned(state.maximum_seen), Value::Array(ranges)],
                )
            })
            .collect(),
    )
}

fn seen_range(first: u64, last: u64) -> Value {
    table_map(SEEN_RANGE_KEYS, vec![unsigned(first), unsigned(last)])
}

enum EncodedStreamState<'a> {
    Live(&'a StreamInstanceId, &'a StreamState),
    Terminated(&'a StreamInstanceId, super::StreamSegmentId, &'a super::TerminatedStream),
}

impl EncodedStreamState<'_> {
    fn key(&self) -> (&StreamInstanceId, super::StreamSegmentId) {
        match self {
            Self::Live(stream, StreamState::Active(state)) => (stream, state.segment_id),
            Self::Live(stream, StreamState::Inactive(state)) => (stream, state.segment_id),
            Self::Terminated(stream, segment, _) => (stream, *segment),
        }
    }
}

fn stream_states(timeline: &Timeline) -> Value {
    let mut states: Vec<_> = timeline
        .streams
        .iter()
        .map(|(stream, state)| EncodedStreamState::Live(stream, state))
        .chain(timeline.terminated_segments.iter().map(|((stream, segment), state)| {
            EncodedStreamState::Terminated(stream, *segment, state)
        }))
        .collect();
    states.sort_by(|left, right| left.key().cmp(&right.key()));
    Value::Array(states.into_iter().map(stream_state).collect())
}

fn stream_state(state: EncodedStreamState<'_>) -> Value {
    let (stream, segment, status, last_activity, maximum_event, ended_at, reason, termination) =
        match state {
            EncodedStreamState::Live(stream, StreamState::Active(state)) => (
                stream,
                state.segment_id,
                "active",
                state.last_activity.as_nanos(),
                state.maximum_event_time.as_nanos(),
                None,
                None,
                Value::Null,
            ),
            EncodedStreamState::Live(stream, StreamState::Inactive(state)) => (
                stream,
                state.segment_id,
                "inactive",
                state.last_activity.as_nanos(),
                state.maximum_event_time.as_nanos(),
                Some(state.ended_at.as_nanos()),
                Some("inactive"),
                Value::Null,
            ),
            EncodedStreamState::Terminated(stream, segment, state) => (
                stream,
                segment,
                "terminated",
                state.last_activity.as_nanos(),
                state.maximum_event_time.as_nanos(),
                Some(state.ended_at.as_nanos()),
                Some(match state.reason {
                    TerminationReason::Inactive => "inactive",
                    TerminationReason::Epoch => "epoch",
                }),
                state.epoch_termination.map_or(Value::Null, |receipt| {
                    table_map(
                        EPOCH_TERMINATION_KEYS,
                        vec![
                            unsigned(receipt.record_seq),
                            unsigned(state.ended_at.as_nanos()),
                            device_epoch(receipt.new_epoch),
                        ],
                    )
                }),
            ),
        };
    table_map(
        STREAM_STATE_KEYS,
        vec![
            stream_identity(stream),
            unsigned(segment.get()),
            text(status),
            unsigned(last_activity),
            unsigned(maximum_event),
            optional_unsigned(ended_at),
            reason.map_or(Value::Null, text),
            termination,
        ],
    )
}

fn open_windows(timeline: &Timeline) -> Value {
    Value::Array(
        timeline
            .open_windows
            .iter()
            .map(|(id, window)| {
                let mut observations: Vec<_> = window.observations.iter().collect();
                observations
                    .sort_by(|left, right| observation_key(left).cmp(&observation_key(right)));
                table_map(
                    OPEN_WINDOW_KEYS,
                    vec![
                        unsigned(id.get()),
                        unsigned(window.interval.start().as_nanos()),
                        unsigned(window.interval.end().as_nanos()),
                        Value::Array(observations.into_iter().map(buffered_observation).collect()),
                    ],
                )
            })
            .collect(),
    )
}

fn observation_key(
    observation: &WindowObservation,
) -> (&StreamInstanceId, super::StreamSegmentId, u64) {
    (
        &observation.stream_instance,
        observation.segment_id,
        observation.observation.input().record_seq(),
    )
}

fn missing_spans(timeline: &Timeline) -> Value {
    let mut spans: Vec<_> = timeline.missing_spans.iter().collect();
    spans.sort_by(|left, right| {
        left.stream
            .cmp(&right.stream)
            .then_with(|| left.segment_id.cmp(&right.segment_id))
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| match (left.end, right.end) {
                (Some(left), Some(right)) => left.cmp(&right),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
    });
    Value::Array(
        spans
            .into_iter()
            .map(|span| {
                table_map(
                    MISSING_SPAN_KEYS,
                    vec![
                        stream_identity(&span.stream),
                        unsigned(span.segment_id.get()),
                        unsigned(span.start.as_nanos()),
                        optional_unsigned(span.end.map(|end| end.as_nanos())),
                        text("inactive"),
                    ],
                )
            })
            .collect(),
    )
}

fn buffered_observation(windowed: &WindowObservation) -> Value {
    table_map(
        BUFFERED_OBSERVATION_KEYS,
        vec![
            unsigned(windowed.segment_id.get()),
            classification(windowed.classification),
            disposition(windowed.disposition),
            csi_observation(&windowed.observation),
        ],
    )
}

fn classification(value: SequenceClassification) -> Value {
    let (kind, payload) = match value {
        SequenceClassification::First => ("first", Value::Null),
        SequenceClassification::InOrder => ("in_order", Value::Null),
        SequenceClassification::Gap { missing } => ("gap", unsigned(missing)),
        SequenceClassification::Duplicate => ("duplicate", Value::Null),
        SequenceClassification::Reordered { distance } => ("reordered", unsigned(distance)),
    };
    table_map(CLASSIFICATION_KEYS, vec![text(kind), payload])
}

fn disposition(value: ObservationDisposition) -> Value {
    let (kind, window, reason) = match value {
        ObservationDisposition::Windowed { window_id } => {
            ("windowed", unsigned(window_id.get()), Value::Null)
        }
        ObservationDisposition::InterWindowGap => ("inter_window_gap", Value::Null, Value::Null),
        ObservationDisposition::Duplicate => ("duplicate", Value::Null, Value::Null),
        ObservationDisposition::Late { reason } => ("late", Value::Null, text(reason.as_str())),
    };
    table_map(DISPOSITION_KEYS, vec![text(kind), window, reason])
}

fn csi_observation(observation: &CsiObservation) -> Value {
    table_map(
        CSI_OBSERVATION_KEYS,
        vec![
            table_map(
                INPUT_RECEIPT_KEYS,
                vec![
                    text(observation.input().session().as_str()),
                    unsigned(observation.input().record_seq()),
                    text(observation.input().decoder_version().as_str()),
                ],
            ),
            text(observation.sensor().as_str()),
            text(match observation.hardware() {
                HardwareKind::Esp32S3 => "esp32-s3",
                HardwareKind::Esp32C6 => "esp32-c6",
                HardwareKind::Intel5300 => "intel-5300",
            }),
            text(observation.link().as_str()),
            device_epoch(observation.device_epoch()),
            unsigned(observation.capture_sequence()),
            unsigned(observation.callback_tick_us()),
            frame_timing(observation.timing()),
            radio_metadata(observation),
            Value::Bytes(observation.profile().as_bytes().to_vec()),
            csi_capture(observation.csi()),
        ],
    )
}

fn frame_timing(timing: &FrameTiming) -> Value {
    let device = timing.device().map_or(Value::Null, |device| {
        table_map(
            DEVICE_TIMESTAMP_KEYS,
            vec![unsigned(device.ticks()), text(device.clock_domain())],
        )
    });
    table_map(
        FRAME_TIMING_KEYS,
        vec![
            unsigned(timing.received().as_nanos()),
            device,
            unsigned(timing.event().as_nanos()),
            text(match timing.source() {
                EventTimeSource::ReceiveOnly => "receive_only",
                EventTimeSource::ClockCorrected => "clock_corrected",
            }),
            timing.mapping_version().map_or(Value::Null, |version| text(version.as_str())),
            unsigned(timing.uncertainty_ns()),
        ],
    )
}

fn radio_metadata(observation: &CsiObservation) -> Value {
    let radio = observation.radio();
    table_map(
        RADIO_METADATA_KEYS,
        vec![
            optional_unsigned(radio.channel().map(u64::from)),
            optional_unsigned(radio.centre_frequency_hz()),
            optional_unsigned(radio.bandwidth_hz()),
            radio.ppdu().map_or(Value::Null, |ppdu| {
                text(match ppdu {
                    PpduKind::Legacy => "legacy",
                    PpduKind::Ht => "ht",
                    PpduKind::He => "he",
                })
            }),
            signed(i64::from(radio.rssi_dbm())),
            signed(i64::from(radio.noise_floor_dbm())),
        ],
    )
}

fn csi_capture(capture: &CsiCapture) -> Value {
    table_map(
        CSI_CAPTURE_KEYS,
        vec![
            table_map(
                CSI_LAYOUT_KEYS,
                vec![
                    Value::Array(capture.layout().paths().iter().copied().map(csi_path).collect()),
                    sample_axis(capture.layout().samples()),
                    text(match capture.layout().order() {
                        SampleOrder::PathThenSample => "path_then_sample",
                    }),
                ],
            ),
            Value::Array(
                capture
                    .samples()
                    .iter()
                    .map(|sample| {
                        table_map(
                            IQ_SAMPLE_KEYS,
                            vec![
                                signed(i64::from(sample.i)),
                                signed(i64::from(sample.q)),
                                Value::Bool(sample.valid),
                            ],
                        )
                    })
                    .collect(),
            ),
            table_map(
                SAMPLE_ENCODING_KEYS,
                vec![
                    unsigned(u64::from(capture.encoding().signed_bits())),
                    unsigned(u64::from(capture.encoding().scale_numerator())),
                    unsigned(u64::from(capture.encoding().scale_denominator())),
                    text(match capture.encoding().complex_order() {
                        ComplexOrder::RealImaginary => "real_imaginary",
                        ComplexOrder::ImaginaryReal => "imaginary_real",
                    }),
                ],
            ),
            text(match capture.phase_state() {
                PhaseState::Unavailable => "unavailable",
                PhaseState::Raw => "raw",
                PhaseState::Calibrated => "calibrated",
            }),
        ],
    )
}

fn csi_path(path: CsiPath) -> Value {
    match path {
        CsiPath::TxRx { tx_stream, rx_chain } => table_map(
            CSI_PATH_TX_RX_KEYS,
            vec![text("tx_rx"), unsigned(u64::from(tx_stream)), unsigned(u64::from(rx_chain))],
        ),
        CsiPath::RawPathOrdinal(ordinal) => table_map(
            CSI_PATH_RAW_KEYS,
            vec![text("raw_path_ordinal"), unsigned(u64::from(ordinal))],
        ),
    }
}

fn sample_axis(axis: &CsiSampleAxis) -> Value {
    match axis {
        CsiSampleAxis::OpaqueSampleOrdinal { count } => table_map(
            SAMPLE_AXIS_COUNT_KEYS,
            vec![text("opaque_sample_ordinal"), unsigned(u64::from(*count))],
        ),
        CsiSampleAxis::IeeeToneIndex(values) => table_map(
            SAMPLE_AXIS_VALUES_KEYS,
            vec![
                text("ieee_tone_index"),
                Value::Array(values.iter().map(|value| signed(i64::from(*value))).collect()),
            ],
        ),
        CsiSampleAxis::FrequencyHz(values) => table_map(
            SAMPLE_AXIS_VALUES_KEYS,
            vec![
                text("frequency_hz"),
                Value::Array(values.iter().copied().map(unsigned).collect()),
            ],
        ),
    }
}

fn stream_identity(stream: &StreamInstanceId) -> Value {
    table_map(
        STREAM_IDENTITY_KEYS,
        vec![
            text(stream.key().sensor().as_str()),
            text(stream.key().link().as_str()),
            Value::Bytes(stream.key().profile().as_bytes().to_vec()),
            device_epoch(stream.device_epoch()),
        ],
    )
}

fn device_epoch(epoch: DeviceEpoch) -> Value {
    table_map(
        DEVICE_EPOCH_KEYS,
        vec![unsigned(epoch.device().get()), unsigned(u64::from(epoch.boot_generation().get()))],
    )
}

fn table_map(keys: &[&str], values: Vec<Value>) -> Value {
    assert_eq!(keys.len(), values.len(), "Timeline state schema key/value mismatch");
    Value::Map(keys.iter().zip(values).map(|(key, value)| (text(*key), value)).collect())
}

fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn signed(value: i64) -> Value {
    Value::Integer(value.into())
}

fn optional_unsigned(value: Option<u64>) -> Value {
    value.map_or(Value::Null, unsigned)
}

const fn cbor_header_len(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AxisVariant, PathVariant, RouteReceiptCaps, StateBoundError, StateBoundInput,
        canonical_max_len, layout_len, maximum_array_header_sum, maximum_csi_layout_len,
    };
    use crate::timeline::DerivedBounds;

    fn synthetic_bounds() -> DerivedBounds {
        DerivedBounds {
            retention_duration_ns: 1,
            rate_quanta: 1,
            max_buffered_observations: 11,
            route_count: 2,
            max_open_windows: 2,
            max_retained_stream_segments: 13,
            max_retained_missing_spans: 13,
            max_retained_source_epochs: 13,
            max_seen_sequence_values_per_source: 2,
            max_seen_sequence_ranges_per_source: 1,
        }
    }

    fn synthetic_bound(routes: &[RouteReceiptCaps]) -> u64 {
        canonical_max_len(StateBoundInput {
            session_text_bytes: 9,
            decoder_text_bytes: 15,
            reorder_horizon: 1,
            bounds: &synthetic_bounds(),
            routes,
        })
        .expect("synthetic state bound")
    }

    #[test]
    fn route_capacity_remains_associated_with_its_receipt_shape() {
        let large = RouteReceiptCaps {
            sensor_text_bytes: 30,
            link_text_bytes: 24,
            hardware_text_bytes: 10,
            logical_samples: 306,
            observation_capacity: 10,
        };
        let small = RouteReceiptCaps {
            sensor_text_bytes: 8,
            link_text_bytes: 6,
            hardware_text_bytes: 8,
            logical_samples: 1,
            observation_capacity: 1,
        };

        let large_weighted = synthetic_bound(&[large, small]);
        let small_weighted = synthetic_bound(&[
            RouteReceiptCaps { observation_capacity: 1, ..large },
            RouteReceiptCaps { observation_capacity: 10, ..small },
        ]);

        assert!(
            large_weighted > small_weighted,
            "the larger route receipt must contribute once per observation capacity"
        );
    }

    #[test]
    fn state_bound_rejects_route_count_and_capacity_sum_mismatches() {
        let route = RouteReceiptCaps {
            sensor_text_bytes: 8,
            link_text_bytes: 6,
            hardware_text_bytes: 8,
            logical_samples: 1,
            observation_capacity: 11,
        };
        let bounds = synthetic_bounds();
        let short_routes = [route];
        let wrong_capacity_routes = [
            RouteReceiptCaps { observation_capacity: 10, ..route },
            RouteReceiptCaps { observation_capacity: 2, ..route },
        ];

        assert_eq!(
            canonical_max_len(StateBoundInput {
                session_text_bytes: 9,
                decoder_text_bytes: 15,
                reorder_horizon: 1,
                bounds: &bounds,
                routes: &short_routes,
            }),
            Err(StateBoundError::RouteCountMismatch { expected: 2, actual: 1 })
        );
        assert_eq!(
            canonical_max_len(StateBoundInput {
                session_text_bytes: 9,
                decoder_text_bytes: 15,
                reorder_horizon: 1,
                bounds: &bounds,
                routes: &wrong_capacity_routes,
            }),
            Err(StateBoundError::ObservationCapacityMismatch { expected: 11, actual: 12 })
        );
    }

    #[test]
    fn algebraic_layout_maximum_matches_exhaustive_factorizations_through_s3_cap() {
        for coordinate_cap in 1..=306 {
            let expected = maximum_csi_layout_len(coordinate_cap).expect("algebraic size");
            let mut brute = 0;
            for paths in 1..=coordinate_cap {
                for axis_values in 1..=coordinate_cap / paths {
                    for path_variant in [PathVariant::TxRx, PathVariant::RawPathOrdinal] {
                        for axis_variant in [
                            AxisVariant::OpaqueSampleOrdinal,
                            AxisVariant::IeeeToneIndex,
                            AxisVariant::FrequencyHz,
                        ] {
                            brute = brute.max(
                                layout_len(paths, axis_values, path_variant, axis_variant)
                                    .expect("brute-force layout size"),
                            );
                        }
                    }
                }
            }
            assert_eq!(expected, brute, "coordinate cap {coordinate_cap}");
        }
    }

    #[test]
    fn observation_array_headers_cross_every_cbor_threshold_exactly() {
        assert_eq!(maximum_array_header_sum(9, 1_600), Ok(23));
        assert_eq!(maximum_array_header_sum(1, 23), Ok(1));
        assert_eq!(maximum_array_header_sum(1, 24), Ok(2));
        assert_eq!(maximum_array_header_sum(1, 255), Ok(2));
        assert_eq!(maximum_array_header_sum(1, 256), Ok(3));
        assert_eq!(maximum_array_header_sum(1, 65_535), Ok(3));
        assert_eq!(maximum_array_header_sum(1, 65_536), Ok(5));
        assert_eq!(maximum_array_header_sum(1, u64::from(u32::MAX)), Ok(5));
        assert_eq!(maximum_array_header_sum(1, u64::from(u32::MAX) + 1), Ok(9));
    }

    #[test]
    #[should_panic(expected = "TimelineState schema map key/value arity mismatch")]
    fn schema_map_arity_is_enforced_in_release_builds() {
        super::map_len(&["one", "two"], &[1]).expect("arity mismatch must panic first");
    }
}
