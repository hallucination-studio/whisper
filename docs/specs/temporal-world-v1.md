# Temporal world v1 specification

Status: accepted target

Applicability: Timeline, conditioning, baselines, Engine, World, semantic
recovery, and semantic replay belong to the deferred Semantic Program. The
bounded Demo imports only the Capture Profile identity, native-coordinate
`CsiObservation` value, and standalone CBOR root, as routed by
[Demo Slice v1](demo-slice-v1.md); deriving or committing those values does not
claim that any other contract in this document ran.

This specification is the sole normative owner of Whisper v1 Capture Profile
identity, native-coordinate `CsiObservation`, Timeline, conditioning,
statistical baseline estimation, world aggregation, Engine, runtime
publication, and semantic replay behavior. Current implementation and execution
maturity are recorded separately in the
[world/runtime evidence index](../evidence/world-runtime.md).

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

## Scope

V1 transforms admitted, resolved dynamic CSI observations into deterministic
per-link evidence and one world snapshot per global window. Its production
state path is the statistical baseline estimator defined here. It preserves
native coordinates, explicit time quality, profile isolation, typed knowledge
limits, and source receipts.

Semantic processing begins after an input has become a typed, authenticated
`CsiObservation`. The applicable wire specification owns datagram bytes,
authentication, and route admission. The persistence specification owns session
schemas, replay eligibility, and ordered record decoding. This specification
owns Profile identity, the observation value, and the semantic result obtained
from those ordered inputs.

HTTP resources, WebSocket delivery, signal tiles, and UI behavior are outside
this specification. Delivery metadata MUST NOT affect a semantic result.

## Semantic identity

Every semantic run MUST be pinned by:

- the session manifest and ordered session records;
- the replay configuration digest;
- executable build fingerprint and target;
- decoder, conditioning, and estimator algorithm versions;
- the window and baseline contracts; and
- the complete initial baseline states.

The core MUST receive time explicitly. It MUST NOT read a wall clock, sleep,
use randomness, depend on hash-map iteration order, or derive semantic state
from delivery timing. Stable map order or an explicit stable sort MUST define
all stream, coordinate, link, and space reductions.

## Capture Profile identity

A `CaptureProfileId` is SHA-256 of one Capture Profile v1 descriptor encoded as
deterministic CBOR. The descriptor contains exactly one definite-length map,
uses shortest-width integers and definite-length text, arrays, and nested maps,
and contains no float, tag, indefinite item, unknown key, duplicate key, or
trailing byte. Map keys are ordered by their deterministic CBOR encoding:
shorter encoded keys first, then bytewise lexical order for equal lengths.
Decoders MUST reject bytes that are not identical to canonical re-encoding.

The root map has exactly these keys in encoded order:

| Order | Key | Value |
| ---: | --- | --- |
| 1 | `ppdu` | `Legacy`, `Ht`, `He`, or `null` |
| 2 | `stbc` | boolean or `null` |
| 3 | `layout` | profile-layout map |
| 4 | `channel` | nonzero `u16` or `null` |
| 5 | `encoding` | profile-encoding map |
| 6 | `firmware` | non-whitespace version text |
| 7 | `hardware` | `Esp32S3`, `Esp32C6`, or `Intel5300` |
| 8 | `acquisition` | acquisition map |
| 9 | `phase_state` | `Unavailable`, `Raw`, or `Calibrated` |
| 10 | `bandwidth_hz` | nonzero `u64` or `null` |
| 11 | `clock_domain` | non-whitespace text of at most `MAX_TIMELINE_CLOCK_TEXT_BYTES` bytes or `null` |
| 12 | `time_quality` | `Unknown`, `ReceiveOnly`, or `ClockCorrected` |
| 13 | `capability_id` | non-whitespace version text |
| 14 | `schema_version` | unsigned integer `1` |
| 15 | `decoder_version` | validated version text |
| 16 | `secondary_channel` | `u8` in `0..=2` or `null` |
| 17 | `centre_frequency_hz` | nonzero `u64` or `null` |

The nested maps and enum representations are exact:

| Type | Exact encoded keys and values |
| --- | --- |
| profile-layout | `order`: exact text `PathThenSample`; `paths`: nonempty unique array of profile-path values in native order; `samples`: one profile-sample-axis value |
| profile-path `TxRx` | one-key map `TxRx`: map containing `rx_chain: u16`, then `tx_stream: u16` |
| profile-path `RawPathOrdinal` | one-key map `RawPathOrdinal`: `u16` |
| profile-sample-axis opaque | one-key map `OpaqueSampleOrdinal`: map containing `count`: nonzero `u16` |
| profile-sample-axis tone | one-key map `IeeeToneIndex`: nonempty unique array of `i16` in native order |
| profile-sample-axis frequency | one-key map `FrequencyHz`: nonempty unique array of `u64` in native order |
| profile-encoding | `signed_bits`: `u8` in `1..=32`; `complex_order`: `RealImaginary` or `ImaginaryReal`; `scale_numerator`: nonzero `u32`; `scale_denominator`: nonzero `u32` |
| acquisition | `mode`: exact text `WifiCsi`; `ltf_merge`: `None`, `FirmwareDefined`, or `Unknown`; `ltf_selection`: `Legacy`, `Ht`, `He`, or `Unknown`; `validity_dialect`: `ExplicitFlag`, `FirstWordInvalid`, `MissingFrameValidity`, or `Unknown` |

The scale fraction MUST be reduced. `ClockCorrected` requires a non-null clock
domain; `ReceiveOnly` and `Unknown` require `clock_domain = null`. All layouts
MUST satisfy the native-coordinate uniqueness and checked cardinality rules.
Equal descriptor bytes produce the same Profile ID, and any descriptor-byte
change produces a different digest preimage.

## Timeline

### Interface

The v1 typed interface is:

```rust
enum TimelineInput {
    Observation(CsiObservation),
    TimelineAdvance { record_seq: u64, at: SessionTime },
    Finish { record_seq: u64, at: SessionTime },
}

struct ObservationOutcome {
    classification: SequenceClassification,
    disposition: ObservationDisposition,
}

struct WindowObservation {
    segment_id: StreamSegmentId,
    classification: SequenceClassification,
    disposition: ObservationDisposition,
    observation: CsiObservation,
}

struct MissingSpan {
    stream: StreamInstanceId,
    segment_id: StreamSegmentId,
    interval: TimeInterval,
    reason: MissingSpanReason,
}

struct AlignedWindow {
    id: WindowId,
    interval: TimeInterval,
    observations: Vec<WindowObservation>,
    missing_spans: Vec<MissingSpan>,
}

struct TimelineTransition {
    observation: Option<ObservationOutcome>,
    published_windows: Vec<AlignedWindow>,
    state: TimelineState,
}
```

```text
Timeline::new(TimelineConfig) -> Result<Timeline, TimelineError>
Timeline::apply(&mut self, TimelineInput) -> Result<TimelineTransition, TimelineError>
```

Host recovery calls `Timeline::new` and replays the manifest's ordered SQLite
facts. Timeline state has a deterministic canonical encoder only so its bytes
can form the cursor-bound SHA-256 determinism tripwire; v1 defines no state
decoder or restore interface.

`TimelineConfig` is a validated strong value binding the exact semantic
receipts from `SessionManifest`: `session_id`, `decoder_version`, the
`ReplayConfig` registry, window contract, and routes, the derived
`WindowContractId`, and the runtime resources needed by Timeline.

`observation` MUST be `Some` exactly for `Observation` and MUST contain that
input's sequence classification and disposition. It MUST be `None` for
`TimelineAdvance` and `Finish`. `MissingSpanReason` is exactly `Inactive`.
Window spans MUST be clipped to the window interval and empty intersections
MUST be omitted. Live processing, replay, and recovery MUST feed identical
ordered `TimelineInput` values. Dependency direction and state ownership are
defined once in the [world runtime architecture](../architecture/world-runtime.md).

Time regression, record-sequence regression or duplication, window arithmetic
overflow, input after finish, and invalid internal state are `TimelineError`s.
A failed `Timeline::new` returns no Timeline. A failed `Timeline::apply` MUST
leave the receiver unchanged.

### Time

Host receive-monotonic session time is the v1 record-order and inactivity
authority. Validated event time is the window-membership and watermark
authority. UTC time is display and cross-artifact location metadata only. A
device time MAY be retained as a raw fact.

An event time has a `ReceiveOnly` or `ClockCorrected` source, a mapping version
when corrected, and an uncertainty bound. `ClockCorrected` MUST be produced only
from a verified capture timestamp and mapping. It does not imply phase
coherence. A `ReceiveOnly` event time MUST equal its receive-monotonic time.

`MAX_TIMELINE_CLOCK_TEXT_BYTES` is `128` UTF-8 bytes. It bounds
`DeviceTimestamp.clock_domain` and `ClockMappingVersion`/`mapping_version` so
the persisted Timeline state has a fixed text maximum. Constructors and
decoders MUST reject these values when empty, whitespace-only, or longer than
128 UTF-8 bytes. This v1 resource-contract limit accommodates namespaced
clock-domain and mapping-version identifiers while independently bounding
per-observation state size; it is not copied from a protocol or hardware limit.
Changing this constant requires a new Timeline state schema.

Timeline maintains an explicit session clock from ordered observation receive
times and recorded advance/finish times. These times MUST be nondecreasing in
session-record order. Inactivity is measured only against this explicit clock;
processing time and wall time MUST NOT enter the calculation.

### Atomic apply order

For each input, Timeline MUST perform this order atomically:

1. Validate increasing `record_seq` and nondecreasing explicit time, and
   precompute every checked arithmetic result and state/output change without
   mutation.
2. Advance the explicit clock and expire inactivity whose threshold is less
   than or equal to that clock, omitting zero-length missing spans.
3. For `Observation`, apply the higher-epoch transitions below to every
   older-epoch stream state for the same `DeviceId`, then classify its source
   sequence.
4. Determine disposition. Duplicate and Late observations MUST NOT be admitted.
   A within-horizon Reordered observation MUST be admitted if and only if its
   target window is logically open.
5. For an admitted observation, create or reactivate its segment, update
   activity and maximum event time, and materialize its target window when it
   has one.
6. Irreversibly close eligible windows subject to the recorded-advance fallback
   timing below, produce outputs, and encode the complete resulting state.

Only after every step succeeds may Timeline commit the plan. Any error commits
none of its state or outputs. Sequence classification, disposition, and missing
spans are Timeline quality facts; conditioning and later modules derive metrics
from them.

### Sequence classification

The sequence source key is the authenticated `DeviceEpoch`. Timeline MUST
classify every non-wrapping `u64` capture sequence independently as:

```text
First
InOrder
Gap { missing }
Duplicate
Reordered { distance }
```

Classification MUST occur before an observation is partitioned by profile.
Interleaved profiles from one source therefore MUST NOT create source gaps. A
short regression is reordered; a value outside the configured reorder horizon
is late/reordered input. Neither case creates a new epoch. For source maximum
`m` and horizon `h`, Timeline retains seen values only in the inclusive range
`[saturating_sub(m, h), m]`. A sequence below that floor is Reordered and Late
even if it appeared previously. Within the retained range, seen values classify
as Duplicate and unseen regressions classify as Reordered. A device tick
regression is health evidence and MUST NOT change the authenticated epoch.

A duplicate has disposition `Duplicate`. It MUST NOT enter a window or update
stream activity, maximum event time, or a watermark. Its ordered input time
still advances the explicit session clock and may therefore make other streams
inactive.

A within-horizon reordered observation enters and materializes its target if
and only if that window is logically open, retaining `record_seq` order. It is
otherwise `Late` with reason `closed_window`. A reordered observation beyond
the horizon is `Late` with reason `beyond_reorder_horizon`. Late input remains a
classified session fact but MUST NOT revise output.

A higher boot generation observation MUST transition every old-epoch stream
state for the same `DeviceId`. An old Active state becomes Terminated with
reason `epoch`, `ended_at_ns` equal to the new observation receive time, and the
matching epoch-termination receipt. An old Inactive state, including one
created by the same input's inactivity step, retains its inactivity
`ended_at_ns` and reason, closes its open missing span at the new observation
receive time, and becomes Terminated with reason `inactive`. A zero-length span
is omitted. Closing that existing inactivity span does not manufacture a span,
and the higher-epoch transitions MUST NOT by themselves force global window
publication. An admitted new-epoch observation creates a new stream instance.
A capture sequence MUST NOT wrap. The sender must establish a new authenticated
epoch before producing more CSI.

### Streams, watermarks, and windows

The stream key is sensor, physical link, and capture profile; a stream instance
also includes the device epoch. Profile changes and epoch changes MUST create
new stream instances. Windows MUST NOT cross either change.

`StreamSegmentId` is the `u64 record_seq` of the first admitted observation in
that segment. An otherwise admissible, non-duplicate observation updates its
stream's last activity from its receive time and its maximum event time from
its event time. A stream is inactive when the explicit session clock minus its
last activity is greater than or equal to `inactive_after`; equality MUST make
it inactive and end that segment.

Inactivity creates a missing span beginning at the checked sum
`last_activity + inactive_after`. The span ends at the receive time of the next
admissible observation for that stream, at the receive time of a higher-epoch
transition for the same `DeviceId`, or at `Finish`. On reactivation, the matching
span closes, the prior inactive state becomes terminated with reason `inactive`
and is retained only while an open window or span references it, and the
observation starts a segment identified by its `record_seq`. Epoch termination
and `Finish` terminate segments but MUST NOT themselves create missing spans.
Overflow while computing a missing-span boundary is a classified error and
leaves Timeline unchanged.

For each active stream:

```text
stream watermark = saturating_sub(maximum seen event time, allowed lateness)
global watermark = minimum active stream watermark
```

Every Timeline watermark subtraction MUST saturate at `SessionTime` zero.

A `TimelineAdvance` advances the explicit clock and evaluates inactivity. It
MUST NOT manufacture or increase an active stream's maximum event time or
stream watermark. When the active set is empty, and only then, the global
watermark is the last recorded `TimelineAdvance.at` minus allowed lateness,
saturating at `SessionTime` zero. Before any recorded advance in an empty active
set, there is no global watermark. If an Observation is not admitted and its
only active-set change is higher-epoch termination, that apply MUST NOT use the
recorded-advance fallback to publish a window; the fallback becomes eligible on
the next `TimelineAdvance`.

V1 windows have positive width and step, MUST satisfy `width <= step`, and are
non-overlapping half-open intervals aligned to session time zero. For an event
time, Timeline MUST use checked integer arithmetic:

```text
k     = floor(event_time / step)
start = checked_mul(k, step)
end   = checked_add(start, width)
window = [start, end)
```

Overflow is a classified error and leaves Timeline unchanged.

An observation is window-eligible only when the checked absolute difference
between event time and receive time is at most `allowed_lateness`. Outside that
bound it is `Late` with reason `event_time_outside_lateness` and MUST NOT update
activity, maximum event time, a watermark, or a window.

An admissible observation belongs to at most one window. If `step > width`, an
observation in an uncovered interval is still sequence-classified and may
update activity and watermarks under the rules above, but it has disposition
`InterWindowGap` and MUST NOT enter an `AlignedWindow`.

A window becomes irreversibly closed when its exclusive end is less than or
equal to the global watermark. A materialized closed window publishes one
`AlignedWindow`; an unmaterialized closed window is skipped without output.
`closed_window_frontier` is the greatest closed `WindowId`, and every ID at or
below it is closed whether published or skipped. An `AlignedWindow` MUST retain
each stream's actual timestamps, observations, profile, gaps, clipped missing
spans, and quality facts. Missing data MUST NOT become zero-valued CSI. Rate,
jitter, and temporal calculations MUST use actual time deltas.

A target window is logically open exactly when its ID is greater than the
closed frontier, treating a null frontier as preceding every ID, and its
exclusive end is greater than the current global watermark, treating an absent
watermark as preceding session time zero. Materialization is not required for
logical openness.

A window is materialized only when an observation is included in it or when a
recorded `TimelineAdvance.at` equals that window's start boundary. An advance
materializes only that exact boundary; skipped boundaries and their windows
MUST NOT be manufactured.

Each live boundary MUST first append a `TimelineAdvance` record. When a packet
or command coincides with a boundary, the advance has the lower record sequence
and the packet or command belongs to the next `[start, end)` window. Replay MUST
advance Timeline only from those ordered records. A late observation remains a
session fact but MUST NOT revise an already published snapshot.

`Finish` MUST be derived from the ordered `Closed` record and is terminal. It
advances the explicit clock to the Closed record time, evaluates inactivity,
closes any open inactivity spans at that time, and terminates every remaining
stream segment without creating a new missing span. Timeline MUST then
irreversibly publish only its already-materialized open windows, in `WindowId`
order; a materialized window MAY be partial. `Finish` MUST NOT materialize a
window merely because its start precedes the finish time and MUST NOT create a
window starting at the finish time. The final Engine transition MUST emit the
resulting complete Timeline state and complete baseline-state handoff. That
state MUST clear stream, open-window, and missing-span arrays. Timeline MUST
reject every input after `Finish`.

`WindowContractId` is SHA-256 over one canonical Whisper persistence-profile
map with exactly these keys in table order:

| Key | Value |
| --- | --- |
| `schema_version` | unsigned integer `1` |
| `timeline_version` | exact text `timeline-v1` |
| `width_ns` | `u64` |
| `step_ns` | `u64` |
| `alignment` | exact text `session_time_zero` |
| `allowed_lateness_ns` | `u64` |
| `inactive_after_ns` | `u64` |
| `reorder_horizon` | `u32` |
| `missing_data` | exact text `explicit_spans_no_zero_fill` |
| `event_time_admission` | exact text `absolute_difference_at_most_allowed_lateness` |
| `inactivity` | exact text `greater_than_or_equal` |

The map MUST NOT contain a session ID, session start, or window instance ID.

Timeline MUST use these exact lexicographic orders:

- source states: `(device, boot_generation)`;
- stream identity tuple: `(sensor UTF-8 bytes, link UTF-8 bytes, profile bytes,
  device, boot_generation)`;
- stream states: `(stream identity tuple, segment_id)`;
- open and published windows: `WindowId`;
- window observations: `(stream identity tuple, segment_id, record_seq)`; and
- root missing spans: `(stream identity tuple, segment_id, start_ns, end_ns)`,
  with an integer end before `null`.

Ties are forbidden. A terminated stream state MUST be removed when no open
window or missing span references it. A closed missing span MUST be removed
when no open window can intersect it. Source seen state MUST be pruned to the
reorder horizon, and a superseded source epoch MUST be removed when no open
window, stream state, or missing span references it. Stable iteration or an
explicit stable sort MUST establish these orders before encoding or returning
a transition.

### Timeline state CBOR

`TimelineState` v1 bytes MUST be produced only by Timeline's canonical encoder.
Persistence stores only their cursor-bound SHA-256 digest, never the bytes as
recovery or resume state. No decoder accepts these bytes as Timeline input.

The codec MUST use the Whisper v1 deterministic CBOR profile defined by the
persistence specification. In particular, CBOR tags are forbidden. The v1 root
is one definite-length map. Its exact lowercase ASCII text keys MUST each appear
exactly once, in this table order, with no unknown keys:

| Key | Value |
| --- | --- |
| `schema_version` | unsigned integer `1` |
| `window_contract_id` | bound `WindowContractId`, byte string of exactly 32 bytes |
| `session_id` | validated `SessionId`, UTF-8 text |
| `last_record_seq` | last accepted session record sequence, `u64` or `null` |
| `explicit_clock_ns` | unsigned session nanoseconds or `null` before any input |
| `last_advance_ns` | unsigned session nanoseconds or `null` |
| `source_states` | ordered source sequence states |
| `stream_states` | ordered active, inactive, and terminated stream-segment states |
| `closed_window_frontier` | greatest irreversibly closed window index, `u64` or `null` |
| `open_windows` | ordered unpublished windows and their buffered observations |
| `missing_spans` | ordered missing spans |
| `finished` | boolean |

Every nested value below is a definite-length map with exactly the listed keys
in table order.

| Type | Exact keys and values |
| --- | --- |
| `device_epoch` | `device`: `u64`; `boot_generation`: nonzero `u32` |
| `epoch_termination` | `record_seq`: `u64`; `received_ns`: `u64`; `new_device_epoch`: `device_epoch` map |
| `stream_identity` | `sensor`: validated `SensorId` text; `link`: validated `RadioLinkId` text; `profile`: 32-byte `CaptureProfileId`; `device_epoch`: `device_epoch` map |
| `seen_range` | `first`: `u64`; `last`: `u64`, inclusive and not less than `first` |
| `source_state` | `device_epoch`: `device_epoch` map; `maximum_sequence`: `u64`; `seen_ranges`: ordered array of `seen_range` maps |
| `stream_state` | `stream`: `stream_identity` map; `segment_id`: first admitted `record_seq` as `u64`; `status`: `active`, `inactive`, or `terminated`; `last_activity_ns`: `u64`; `maximum_event_ns`: `u64`; `ended_at_ns`: `u64` or `null`; `end_reason`: `inactive`, `epoch`, or `null`; `epoch_termination`: `epoch_termination` map or `null` |
| `open_window` | `window_id`: `u64`; `start_ns`: `u64`; `end_ns`: `u64`; `observations`: ordered array of `buffered_observation` maps |
| `missing_span` | `stream`: `stream_identity` map; `segment_id`: `u64`; `start_ns`: `u64`; `end_ns`: `u64` or `null` while open; `reason`: exact text `inactive` |
| `buffered_observation` | `segment_id`: `u64`; `classification`: `classification` map; `disposition`: `disposition` map; `observation`: `csi_observation` map |

The `classification` map has exactly `kind`, then `value`. `kind` is exactly
`first`, `in_order`, `gap`, `duplicate`, or `reordered`. `value` is a positive
`u64` missing count only for `gap`, a positive `u64` distance only for
`reordered`, and `null` otherwise. An admitted `reordered` observation has
distance at most `reorder_horizon`.

The `disposition` map has exactly `kind`, `window_id`, then `reason`. `kind` is
exactly `windowed`, `inter_window_gap`, `duplicate`, or `late`. `window_id` is a
`u64` only for `windowed` and is `null` otherwise. `reason` is
`beyond_reorder_horizon`, `closed_window`, or
`event_time_outside_lateness` only for `late` and is `null` otherwise.

Seen ranges MUST be the unique maximal encoding of retained values: strictly
sorted, non-overlapping, non-adjacent inclusive ranges within
`[saturating_sub(maximum_sequence, reorder_horizon), maximum_sequence]`, with
the greatest `last` equal to `maximum_sequence`. A buffered wrapper MUST contain
only `segment_id`, `classification`, `disposition`, and `observation`.

#### CsiObservation state schema

The `csi_observation` map has exactly these keys in table order:

| Key | Value |
| --- | --- |
| `input` | `input_receipt` map |
| `sensor` | validated `SensorId` text |
| `hardware` | `esp32-s3`, `esp32-c6`, or `intel-5300` |
| `link` | validated `RadioLinkId` text |
| `device_epoch` | `device_epoch` map |
| `capture_sequence` | `u64` |
| `callback_tick_us` | `u64` |
| `timing` | `frame_timing` map |
| `radio` | `radio_metadata` map |
| `profile` | 32-byte `CaptureProfileId` |
| `csi` | `csi_capture` map |

The remaining observation maps have exactly these keys in table order:

| Type | Exact keys and values |
| --- | --- |
| `input_receipt` | `session`: validated `SessionId` text; `record_seq`: `u64`; `decoder_version`: validated `DecoderVersion` text |
| `device_timestamp` | `ticks`: `u64`; `clock_domain`: non-whitespace UTF-8 text of at most `MAX_TIMELINE_CLOCK_TEXT_BYTES` bytes |
| `frame_timing` | `received_ns`: `u64`; `device`: `device_timestamp` map or `null`; `event_ns`: `u64`; `source`: `receive_only` or `clock_corrected`; `mapping_version`: non-whitespace UTF-8 text of at most `MAX_TIMELINE_CLOCK_TEXT_BYTES` bytes or `null`; `uncertainty_ns`: `u64` |
| `radio_metadata` | `channel`: nonzero `u16` or `null`; `centre_frequency_hz`: nonzero `u64` or `null`; `bandwidth_hz`: nonzero `u64` or `null`; `ppdu`: `legacy`, `ht`, `he`, or `null`; `rssi_dbm`: `i8`; `noise_floor_dbm`: `i8` |
| `csi_capture` | `layout`: `csi_layout` map; `samples`: array of `iq_sample` maps; `encoding`: `sample_encoding` map; `phase_state`: `unavailable`, `raw`, or `calibrated` |
| `csi_layout` | `paths`: nonempty array of unique `csi_path` maps in native order; `samples`: `sample_axis` map; `order`: exact text `path_then_sample` |
| `sample_encoding` | `signed_bits`: `u8` in `1..=32`; `scale_numerator`: nonzero `u32`; `scale_denominator`: nonzero `u32`; `complex_order`: `real_imaginary` or `imaginary_real` |
| `iq_sample` | `i`: `i32`; `q`: `i32`; `valid`: boolean |

A `csi_path` is either the map `kind: "tx_rx", tx_stream: u16,
rx_chain: u16` in that key order, or `kind: "raw_path_ordinal", ordinal: u16`
in that key order. A `sample_axis` is exactly one of:

| `kind` | Remaining key and value |
| --- | --- |
| `opaque_sample_ordinal` | `count`: nonzero `u16` |
| `ieee_tone_index` | `values`: nonempty array of unique `i16` values in native order |
| `frequency_hz` | `values`: nonempty array of unique `u64` values in native order |

For `receive_only`, `mapping_version` MUST be `null`, `event_ns` MUST equal
`received_ns`, and `device` MAY retain a raw `device_timestamp` or be `null`.
For `clock_corrected`, `device` and `mapping_version` MUST both be present. The
input receipt session MUST equal root `session_id`. The sample scale fraction
MUST be reduced. The number of `iq_sample` maps MUST equal the checked product
of path count and sample-axis length. All numeric values MUST fit the stated
width, all typed identities and layouts MUST satisfy their domain invariants,
and arithmetic overflow is invalid state. No profile descriptor is encoded in
`TimelineState`; `profile` is its opaque 32-byte ID.

Sources, streams, windows, observations, and spans MUST be strictly ordered and
unique under the Timeline ordering rule. Seen ranges MUST be ordered,
non-overlapping, and consistent with the maximum sequence. Window bounds and
membership MUST match the bound window contract and closed frontier. Each
buffered disposition MUST be `windowed` with the enclosing `window_id`; its
derived stream identity, explicit `segment_id`, and `record_seq` MUST determine
its ordering. Active stream state has null `ended_at_ns` and `end_reason`;
inactive state has its exact inactivity-threshold end, reason `inactive`, and
exactly one matching open missing span. Active and inactive states have null
`epoch_termination`. A terminated state with reason `inactive` also has null
`epoch_termination` and `ended_at_ns` equal to checked
`last_activity_ns + inactive_after_ns`. A terminated state with reason `epoch`
MUST have an `epoch_termination` whose device matches the stream device, boot
generation is strictly greater, `record_seq` is greater than `segment_id`, and
`received_ns` equals `ended_at_ns`. The receipt is retained and pruned with its
segment. New state has null `last_record_seq`, `explicit_clock_ns`, `last_advance_ns`, and
`closed_window_frontier`, empty arrays, and `finished = false`. After any input,
`last_record_seq` and
`explicit_clock_ns` MUST both be present. Root record/time, activity, watermark,
segment, span, classification, disposition, and typed observation invariants
MUST all be mutually consistent. Finished state has empty `stream_states`,
`open_windows`, and `missing_spans` and rejects later input.

Every map, array, byte string, and text string emitted by the canonical encoder
MUST have a definite length and satisfy the ordering, identity, and typed-state
invariants above. The resulting exact bytes are only the Timeline digest
preimage. Runtime pruned-state capacities and allocation bounds are
implementation concerns; v1 defines no normative encoded-state maximum,
`max_record_bytes` preflight, decoder, or continuation-from-bytes contract.

## Conditioning

For each `AlignedWindow`, Engine computes the window key set as the union of:

1. every distinct `LinkProfileKey` named by a contributor in that window; and
2. every `LinkProfileKey` for which Engine currently holds baseline state.

Conditioning MUST produce exactly one `ConditionedLinkWindow` for every key in
that computed set. The complete output array is strictly ordered and unique by
Link-ID UTF-8 bytes then Profile-ID bytes. The set and output array may be empty.
A key with neither a contributor nor current baseline state MUST NOT be
invented. Each conditioned link window retains its dynamic native coordinate
set and one ordered contributor receipt; conditioning MUST NOT emit a fixed
tensor.

A contributor is one `StreamSegmentIdentity(stream, segment_id)`, where
`segment_id` is that segment's first admitted `record_seq`. A segment is a
window contributor when the `AlignedWindow` contains either one of its
observations or a clipped missing span for it. Contributors are strictly ordered
and unique by the Timeline stream-identity tuple and then `segment_id`. The
array is empty when a key comes only from current baseline state. Every
contributor's stream link and profile MUST equal the conditioned key. An
observation or missing span contributes through exactly one matching stream
segment and MUST NOT be copied between contributors.

For every valid native coordinate in every valid frame, the v1 recipe is:

```text
amplitude = hypot(i, q) * declared_sample_scale
value     = ln(1 + amplitude)
```

`declared_sample_scale` MUST be finite and positive. The configured rational
scale is part of the conditioning contract.

Each coordinate MUST be aggregated independently. For one conditioned
Link/Profile and native coordinate, let `v_1, ..., v_n` be that coordinate's
finite `value` results from valid, included frames across all contributors in
the window. Before the numeric fold, Conditioning MUST explicitly sort all
matching observations by ascending session-global `record_seq`. Record
sequences are unique within the session, so ties are impossible. Conditioning
MUST NOT derive fold order from `AlignedWindow` vector iteration order. A value
from a different physical link, profile, path, or coordinate MUST NOT enter the
reduction. The per-window observation is:

```text
observed = x_t = (v_1 + ... + v_n) / n
```

The sum MUST be evaluated in that explicit order using the configured numeric
precision. A measured zero is a valid included value. Missing, invalid, late,
profile-mismatched, or non-finite values MUST NOT enter the sum and MUST remain
accounted for by their exclusion reasons. A coordinate excluded for low
coverage MUST NOT produce an `observed` value. If `n = 0`, `observed` is absent
and the exclusion counts retain why no value was included. If the
ordered sum or quotient is non-finite, `observed` is absent and the result MUST
be accounted for as an invalid-sample exclusion. In either case, the coordinate
MUST NOT enter Learning, Active scoring, or update.

This `observed` value is the single per-window, per-link/profile
native-coordinate statistic consumed by the estimator and retained as `x_t` in
the formulas below. Temporal absolute slope MUST use adjacent valid per-frame
values within the same stream segment and their actual positive
receive-monotonic time delta, with units of log-amplitude per second. A slope
MUST NOT cross a stream-segment boundary. Zero, regressed, non-finite, or
otherwise invalid time pairs MUST be excluded.

Quality and accepted exposure are computed once for the aggregate
`ConditionedLinkWindow`, not once per contributor. Each admitted frame is
counted at most once. Per-coordinate valid exposure is the union of its valid
coverage within the window, capped by the window width; overlap between
contributors MUST NOT multiply exposure. Contributor count MUST NOT multiply
frame coverage, quality, learning-window count, or estimator updates.

Conditioning MUST NOT interpolate across devices or profiles, pad frequencies,
normalize each segment to `[0, 1]`, infer physical coordinates, or use raw phase
for v1 estimation. It MUST retain explicit counts by exclusion reason,
including invalid sample, missing data, low coverage, unsupported phase, late
input, and profile mismatch.

Each conditioning receipt MUST identify the conditioning version, Link/Profile,
ordered contributor array, window, inclusive source record range, included
coordinate count, and exclusion counts. An empty-contributor receipt retains
the window source range and typed missing-data accounting. Coordinates and
exclusions MUST have stable ordering.

## Statistical baseline estimator

### State key and lifecycle

Estimator state is isolated by deployment, space, physical link, capture
profile, and conditioning version. Coordinate statistics are additionally
keyed by native path and sample coordinate. State from different links or
profiles MUST NOT mix.

For every published window, the estimator MUST execute exactly one step for
every key in the window's computed Link/Profile set, in that set's strict order.
A baseline-state key with no contributors still produces one typed missing-data
decision and evidence result; it does not disappear and cannot update coordinate
state or accrue exposure. If the computed set is empty, the estimator executes
no link step and MUST NOT invent a Profile key.

The lifecycle is:

```text
Missing -> BeginLearning -> Learning -> Commit -> Active
Active  -> Freeze -> Frozen
Active  -> Stale
Frozen or Stale -> Resume, BeginLearning, or ActivateSnapshot
```

Lifecycle and revision changes MUST be caused by ordered baseline commands.
V1 commands are exactly `BeginLearning`, `Commit`, `Freeze`, `Resume`, and
`ActivateSnapshot` carrying a complete immutable snapshot. Learning output is
always `Unknown::BaselineLearning`, even after maturity, until an explicit
`Commit`.

`BaselineRevision` identifies an immutable persisted snapshot and is created
only by commit, explicit snapshot activation, explicit session-finish handoff,
or limit-rotation handoff. Stopping only the Host process is never a handoff.
`BaselineStateSequence` advances on each accepted Active update. Missing and
Learning state MUST NOT invent revision or sequence zero.

### Learning

Learning MUST accept only eligible windows. Each coordinate maintains Welford
`count`, `mean`, `M2`, and accepted exposure. The first accepted `observed`
value sets `count = 1`, `mean = observed`, and `M2 = 0`; subsequent `observed`
values use the standard Welford update.

Accepted exposure is only the actual valid coverage span for that coordinate
within an accepted window. Rejected or missing gaps MUST NOT accrue exposure,
and persisted state MUST NOT treat session timestamps as cross-session clocks.

A coordinate is ready only when it reaches both the configured minimum sample
count, which is at least two, and minimum exposure. Commit variance is:

```text
max(M2 / (count - 1), variance_floor)
```

The learning state is mature only when the configured learning-window,
aggregate valid-exposure, and ready-coordinate coverage requirements are met.
`Commit` MUST include only ready coordinates. An unready coordinate is excluded
as `BaselineCoordinateUnready`; `variance_floor` MUST NOT make it ready.

### Active prediction and update

For each valid ready coordinate, Active state MUST score against the pre-update
state. `observed` is exactly the conditioned `x_t` defined above; no per-frame
value or other reduction may substitute for it:

```text
predicted = previous EW mean
residual  = (observed - predicted)
           / sqrt(max(previous variance, variance_floor))
alpha     = 1 - exp(-accepted_exposure / ew_time_constant)
```

When the gate accepts adaptation:

```text
delta        = observed - previous mean
next mean    = previous mean + alpha * delta
next variance = (1 - alpha)
                * (previous variance + alpha * delta^2)
```

Accepted exposure is the coordinate's valid coverage in this accepted window,
capped by the window width. It MUST NOT accumulate across missing or rejected
windows.

After a new session or rotation, `adaptation_armed` is false. The first accepted
Active window MUST be scored and arm adaptation without updating EW state. A
later accepted window uses only its own exposure. A compatible Host restart
rebuilds the same active session from its manifest and facts and therefore MUST
recover the exact current arming state; process lifetime cannot reset it or
create a semantic boundary.

The link deviation score is the configured nearest-rank quantile of finite
absolute standardized residuals. Values are sorted stably and the 1-based rank
is `ceil(q * n)`. No values yields Unknown. Interpolated quantiles are
forbidden.

`rf_dynamics` is the same nearest-rank reduction over finite temporal absolute
slopes. It retains log-amplitude-per-second units, has no separate baseline,
and is diagnostic only. It MUST NOT affect Stable/Changing classification.

### Eligibility and decisions

Eligibility is the conjunction of:

- minimum frame count;
- minimum ready-coordinate coverage;
- maximum packet-gap ratio;
- maximum receive jitter;
- finite and ordered values and timestamps;
- configured minimum event-time quality; and
- resolved, compatible source, link, and profile.

Every predicate and measured value MUST be retained in link quality evidence.
`ReceiveOnly` is eligible for the v1 non-coherent estimator when it meets the
configured time-quality threshold.

An Active update MUST follow `predict -> score -> decide -> optionally update`.
Low quality, missing data, excess time uncertainty, non-finite input, profile
incompatibility, stale/frozen state, or deviation above the adaptation gate
MUST reject adaptation. Significant deviation MUST NOT be learned immediately
as normal.

The decision is `BootstrapAccepted`, `AdaptationAccepted`, or a typed rejection.
`Stale` MUST NOT silently relearn. Baseline age uses session-monotonic age from
the session start or most recent eligible evidence; a persisted snapshot MUST
NOT use UTC to continue that timer across sessions.

`BaselineContractId` is the canonical identity of the residual, prediction,
normalization, numeric precision, and eligibility semantics. It excludes
learned values, revision, and state sequence.

## World state

Each processed global window MUST produce exactly one `WorldSnapshot`, even
when multiple sensors, streams, links, or profiles contribute. Its stable
identity is `(SessionId, WindowId)`, and `previous_id` MUST refer to the prior
snapshot in the same session when present.

A snapshot MUST contain deployment and interval identity, sensor health,
per-link/profile beliefs, per-space beliefs, and a derivation receipt. The
receipt MUST bind the source session and record range, durable record boundary,
configuration digest, build fingerprint, and decoder, conditioning, and
algorithm versions.

Knowledge is either `Known(Stable | Changing)` or `Unknown(reason)`.
Unknown is a normal knowledge state, not an application error. Diagnostics MAY
remain available for ambiguous evidence. They are absent only when no
coordinate can be scored or no compatible baseline exists. V1 MUST NOT expose
an uncalibrated probability or confidence value.

### Conservative aggregation

Aggregation MUST follow this order:

1. Score every `(physical link, profile)` independently.
2. Exclude ineligible profile beliefs with typed reasons.
3. Apply that profile's own baseline revision and ordered stable/changing
   thresholds; raw scores MUST NOT be compared across profiles or links.
4. Reduce profiles of one physical link: any eligible Changing is Changing;
   all eligible profiles Stable is Stable; other cases are Unknown.
5. Count distinct eligible physical links for space coverage. Multiple profiles
   of one link count once.
6. A space with insufficient physical-link coverage is
   `Unknown::InsufficientCoverage`; any eligible Changing link makes the space
   Changing; all eligible links Stable makes it Stable; other combinations are
   `Unknown::AmbiguousEvidence`.

All profile and physical-link contributions and exclusions MUST be retained in
stable order. The stable threshold MUST be lower than the changing threshold.

### Evidence

Each link step MUST retain its ordered, possibly empty stream-segment
contributors and link/profile identity, the baseline contract and revision,
pre-update and resulting state sequences, decision, knowledge state, quality,
and native-coordinate evidence. Its durable identity is snapshot plus
Link/Profile; contributors are provenance and do not alter that identity.
Coordinates MUST be strictly increasing and unique.

Coordinate evidence MUST identify observed and predicted values, signed and
standardized residuals when available, and exactly one exclusion when not
included. The observed field MUST be the same conditioned `x_t` consumed by
that coordinate's estimator step. Standardized residuals MUST be calculated
from the pre-update state used by the same decision.

## Durable projection CBOR

`observation_cbor`, `snapshot_cbor`, and `evidence_cbor` use the
[Whisper v1 deterministic CBOR profile](persistence-v1.md#session-cbor-profile).
Each root and nested map has exactly the keys below in table order; unknown,
missing, duplicate, or reordered keys, non-canonical values, tags, indefinite
items, and trailing bytes are invalid. These language-neutral tables, not a
Rust type layout or serializer default, define the durable bytes.

Shared text identities use their validated UTF-8 values. Profile, contract,
configuration, and build identities are byte strings of exactly 32 bytes.
The exact text values for `time_quality` are `unknown`, `receive_only`, and
`clock_corrected`. Exclusion reasons are exactly, in this order,
`invalid_sample`, `missing`, `low_coverage`, `unsupported_phase`, `late`,
`profile_mismatch`, `time_uncertain`, `non_finite`, `gap`,
`unresolved_source`, and `quality`. Arrays of exclusions are strictly ordered
and unique in that order. All statistical floats are finite and obey their
semantic non-negative or fraction bounds.

A `knowledge` map is exactly one of:

| Kind | Exact ordered keys and values |
| --- | --- |
| Known | `kind: "known"`; `value: "stable" | "changing"` |
| Unknown | `kind: "unknown"`; `reason`: one of `baseline_missing`, `baseline_learning`, `insufficient_coverage`, `low_quality`, `ambiguous_evidence`, `time_uncertain`, `missing_data`, `profile_mismatch`, `stale`, `frozen`, `inactive`, or `non_finite` |

### CsiObservation root

The standalone CsiObservation v1 root has exactly these keys:

| Order | Key | Value |
| ---: | --- | --- |
| 1 | `schema_version` | unsigned integer `1` |
| 2 | `config_digest` | 32-byte ReplayConfig digest |
| 3 | `conditioning_version` | validated version text |
| 4 | `observation` | the exact `csi_observation` map defined by the [Timeline state schema](#csiobservation-state-schema) |

The observation input session and record sequence, timing receive nanoseconds,
sensor, link, profile, decoder version, configuration digest, and conditioning
version MUST equal the session record, manifest, and projection-row envelope
that carry these bytes. The root contains no raw packet bytes and cannot replace
the authoritative packet fact.

### LinkStepEvidence root

The standalone LinkStepEvidence v1 root has exactly these keys:

| Order | Key | Value |
| ---: | --- | --- |
| 1 | `schema_version` | unsigned integer `1` |
| 2 | `snapshot_id` | `snapshot_identity` map below |
| 3 | `source_record_start` | unsigned `u64` |
| 4 | `source_record_end` | unsigned `u64`, not less than start |
| 5 | `conditioning_version` | validated version text |
| 6 | `algorithm_version` | validated version text |
| 7 | `evidence` | `link_step_evidence` map below |

The `link_step_evidence` map has exactly these keys:

| Order | Key | Value |
| ---: | --- | --- |
| 1 | `stream_segments` | ordered array of `stream_segment_identity` maps below; may be empty |
| 2 | `link_profile` | map with `link` identifier text, then 32-byte `profile` |
| 3 | `baseline_contract` | 32-byte BaselineContractId |
| 4 | `baseline_revision` | nonzero unsigned `u64` or `null` |
| 5 | `scored_against_baseline_state_sequence` | nonzero unsigned `u64` or `null` |
| 6 | `resulting_baseline_state_sequence` | nonzero unsigned `u64` or `null` |
| 7 | `baseline_decision` | decision map below |
| 8 | `link_status` | `knowledge` map |
| 9 | `quality` | `link_quality` map below |
| 10 | `coordinates` | strictly ordered array of `coordinate_evidence` maps |

A `stream_segment_identity` map has exact ordered keys `stream` (the exact
`stream_identity` map defined above) and `segment_id` (the first admitted
`record_seq` as `u64`). The array is strictly ordered and unique by stream
identity tuple and then segment ID. Every member's stream link/profile equals
`link_profile`; the array is empty exactly when no stream segment contributed
to the aggregate step.

A baseline-decision map is `kind: "bootstrap_accepted"`,
`kind: "adaptation_accepted"`, or the ordered keys `kind: "rejected"`, then
`reason`. A rejection reason is exactly `low_quality`, `missing_data`,
`time_uncertain`, `profile_mismatch`, `stale`, `frozen`,
`deviation_above_gate`, or `baseline_learning`.

`link_quality` has exact ordered keys `frame_count` (`u32`),
`ready_coordinate_coverage` (binary64 fraction), `packet_gap_ratio` (binary64
fraction), `receive_jitter_ns` (`u64`), `finite_and_ordered` (boolean),
`time_quality` (text above), `resolved_and_compatible` (boolean), and
`exclusions` (ordered exclusion-reason text array).

A `coordinate_evidence` map has exact ordered keys `path`, `coordinate`,
`observed`, `predicted`, `signed_residual_log_amplitude`,
`standardized_residual`, and `exclusion`. Path is the exact `csi_path` map
defined above. Coordinate is exactly one of these maps:

| Coordinate | Exact ordered keys and values |
| --- | --- |
| Opaque ordinal | `kind: "opaque_sample_ordinal"`; `value: u16` |
| IEEE tone | `kind: "ieee_tone_index"`; `value: i16` |
| Frequency | `kind: "frequency_hz"`; `value: u64` |

The four numeric evidence fields are finite statistical floats or `null`;
`exclusion` is one exclusion-reason text or `null`. An included coordinate has
an observed value and null exclusion; an excluded coordinate has null observed
and exactly one exclusion. Coordinates are strictly ordered and unique by path
then coordinate: `tx_rx` precedes `raw_path_ordinal`, and path fields order
numerically; coordinate kinds order as in the table, then by signed or unsigned
numeric value.

Every stream-segment contributor MUST resolve in the Timeline for the source
session, every record attributed to it for this evidence MUST lie within the
source range, and its stream link/profile MUST equal `link_profile` and the
persistence row. A segment may have started before that range. Snapshot session,
link/profile, source range, conditioning version, and algorithm version MUST
equal the associated WorldSnapshot and row envelope. Baseline sequences require
a baseline revision; a resulting sequence requires a scored sequence and cannot
precede it.

### WorldSnapshot root

The standalone WorldSnapshot v1 root has exactly these keys:

| Order | Key | Value |
| ---: | --- | --- |
| 1 | `schema_version` | unsigned integer `1` |
| 2 | `id` | `snapshot_identity` map |
| 3 | `previous_id` | `snapshot_identity` map or `null` |
| 4 | `deployment` | validated Deployment identifier text |
| 5 | `window` | unsigned `u64` WindowId |
| 6 | `valid_interval` | `time_interval` map |
| 7 | `sensors` | ordered array of `sensor_entry` maps |
| 8 | `links` | ordered array of `link_entry` maps |
| 9 | `spaces` | ordered array of `space_entry` maps |
| 10 | `receipt` | `derivation_receipt` map |

The shared identity and interval maps are:

| Type | Exact ordered keys and values |
| --- | --- |
| `snapshot_identity` | `session`: validated Session identifier text; `window`: `u64` |
| `time_interval` | `start_ns`: `u64`; `end_ns`: `u64` not less than start |

The collection entries and world maps are:

| Type | Exact ordered keys and values |
| --- | --- |
| `sensor_entry` | `sensor`: Sensor identifier text; `health`: `sensor_health` map |
| `sensor_health` | `active`: boolean; `time_quality`: exact text above; `sequence_gaps`: `u64` |
| `link_entry` | `link_profile`: link/profile map above; `belief`: `link_belief` map |
| `link_belief` | `status`: `knowledge`; `diagnostics`: `link_diagnostics` map or `null`; `quality`: `link_quality`; `baseline`: baseline-status map; `evidence`: evidence-receipt map |
| `space_entry` | `space`: Space identifier text; `belief`: `space_belief` map |
| `space_belief` | `status`: `knowledge`; `contributions`: ordered array of link-contribution maps |
| `link_contribution` | `link`: Link identifier text; `profiles`: nonempty ordered unique array of 32-byte Profile IDs; `status`: `knowledge`; `exclusions`: ordered unique exclusion-reason array |

`link_diagnostics` has ordered keys `deviation_score`,
`rf_dynamics_log_amplitude_per_second`, and `prediction_error_summary`; the
first two are finite non-negative statistical floats. `residual_summary`, used
for the final field and below, has ordered keys `count` (`u32`),
`mean_absolute` (finite non-negative statistical float), and `quantile` (finite
non-negative statistical float).

A baseline-status map is exactly one of:

| Status | Exact ordered keys and values |
| --- | --- |
| Missing | `kind: "missing"` |
| Learning | `kind: "learning"`; `accepted_windows: u64`; `mature: boolean` |
| Active | `kind: "active"`; `revision: nonzero u64`; `state_sequence: nonzero u64` |
| Frozen | `kind: "frozen"`; `revision: nonzero u64` |
| Stale | `kind: "stale"`; `revision: nonzero u64`; `reason: "age" | "incompatible"` |

An `evidence_receipt` map has exact ordered keys `session_id`,
`first_record_seq`, `last_record_seq`, `link`, `profile`,
`conditioning_version`, `baseline_contract`, `baseline_revision`,
`scored_against_baseline_state_sequence`,
`resulting_baseline_state_sequence`, `residual_summary`,
`included_coordinates`, and `excluded`. Profile and contract are 32-byte values;
record values are `u64`, while every optional baseline revision or state-sequence
value is nonzero `u64` or `null`;
`included_coordinates` is `u32`; `residual_summary` is its map or `null`.
`excluded` is an ordered array of maps with `reason` then positive `u32` `count`,
with at most one entry per exclusion reason.

The `derivation_receipt` map has exact ordered keys `source_session`,
`first_record_seq`, `last_record_seq`, `durable_through_record_seq`,
`config_digest`, `build_fingerprint`, `decoder_version`,
`conditioning_version`, and `algorithm_version`. Record bounds satisfy
`first <= last <= durable_through`; both digests are 32-byte values and versions
are validated text.

Sensors are strictly ordered and unique by Sensor-ID UTF-8 bytes; links by
Link-ID UTF-8 bytes then Profile-ID bytes; spaces by Space-ID UTF-8 bytes; and
link contributions by Link-ID UTF-8 bytes. Root `id.session` equals the receipt
source session, `id.window` equals `window`, and `previous_id`, when present,
uses the same session and a smaller window. Every link entry, belief receipt,
space contribution, Sensor, source range, interval, configuration, and version
MUST be mutually consistent with the same transition. The SQLite row envelope
MUST equal root session/window, interval, source range, algorithm version, and
configuration digest.

The snapshot `links` keys and its associated LinkStepEvidence keys MUST both
equal exactly that window's computed Link/Profile set. Each key occurs exactly
once and both collections use the same strict Link-ID/Profile-ID order. Both may
be empty; a baseline-state key without a contributor still has evidence whose
`stream_segments` array is empty.

## Engine and runtime behavior

Engine accepts push observation, advance to explicit time, apply ordered
baseline command, and finish at explicit time operations.

Each operation MUST return one concrete transition containing the resulting
Timeline state, every changed complete baseline state, and zero or more
`WindowProjection` values. A `WindowProjection` is one WorldSnapshot paired
with its complete strictly ordered LinkStepEvidence set defined above. Engine
owns construction, validation, grouping, and ordering of that indivisible
value. The application MUST commit each exact complete projection and persist
the canonical Timeline digest; it MUST NOT regroup, sort, drop, duplicate, or
recompute Timeline, estimator state, evidence, or snapshots.

An `EngineTransition` is only the semantic variant of the application-owned
private processed-record transition. An authenticated decoder reject never
enters Timeline or Engine and cannot be represented as an `EngineTransition`.
The persistence specification owns the closed wrapper, its unforgeable
construction by the `CaptureRun` processing coordinator, and transaction-B
cursor/commit behavior for both variants.

Engine operations MUST be applied sequentially.

Raw admission MUST become durable before decoding starts or Engine receives a
packet or command. Semantic state, the cursor-bound Timeline digest, query
projections, and the next monotonic Projection commit identity MUST be atomic at
the durability seam. Before that commit succeeds, memory mirrors, HTTP views,
and notifications MUST retain the previous committed state. A raw transaction
failure leaves the decoder and Engine untouched. A semantic transaction
failure rolls back the entire transition and stops capture before publication.

Evidence insufficiency returns typed Unknown output. Invalid numbers, broken
state-machine invariants, incompatible receipts, or configuration/version
conflicts return classified errors. Engine MUST preserve estimator error
classification.

Explicit session finish and limit rotation MUST stop new input, drain accepted
input, durably order a Closed record, finish Engine at that record's time, and
publish the final transition before the session becomes sealed. Session-local
adaptation arming and age cursors reset at handoff; complete estimator values
otherwise survive exactly. Stopping only the Host process drains accepted work
and preserves the active session without an Engine finish or handoff.

## Faithful semantic replay

The persistence contract determines whether a session is eligible and supplies
the manifest plus strict ordered records. Once supplied, live processing and
replay MUST use the same decoder, identity resolution, Timeline, conditioning,
estimator, Engine, initial baseline states, commands, and explicit times.

Replay MUST preserve packet and command total order and MUST call the same
Timeline and Engine interfaces with identical ordered `TimelineInput`,
including recorded `TimelineAdvance` and `Finish` inputs. Recovery MUST do the
same from a fresh `Timeline::new`; no serialized Timeline state is an input.
Replay MUST NOT run HTTP, WebSocket, notification, or other delivery side
effects.

For the same sealed session, executable, target, and pinned semantic identity,
live and replay MUST produce equal typed semantic snapshots, link evidence,
Timeline state, and complete baseline state. Processing duration, delivery
sequence, and current host metadata are not semantic fields.

A different decoder or semantic contract is a reinterpretation with a distinct
output identity; it MUST NOT claim the original session's conclusions.

## Resource budget

Runtime configuration MUST provide positive maximum RSS bytes, maximum CPU
threads, and a snapshot deadline. The snapshot deadline MUST be no greater than
half the global window step. These limits govern the v1 statistical runtime and
MUST NOT change semantic replay identity.

Durable raw ingestion has priority over statistical world processing, which has
priority over bounded read views. Pressure MUST be visible as classified health
or an explicit stop; the runtime MUST NOT silently skip admitted semantic input,
alter estimator behavior, or drop raw facts to meet a deadline.

## Acceptance

V1 temporal/world acceptance requires behavior tests or retained end-to-end
receipts that demonstrate all of the following through Timeline and Engine:

- independent sequence domains, duplicate/gap/reorder behavior,
  horizon-bounded duplicate memory, duplicate non-effects,
  within-horizon reorder insertion if and only if the target is open,
  irreversible typed Late behavior, and epoch transition without forced global
  publication;
- non-overlapping width/step membership including `InterWindowGap`, half-open
  boundaries, event-time lateness rejection, inactivity at equality,
  zero-saturating watermarks, and recorded no-packet advances that do not
  manufacture active-stream event time;
- terminal `Finish` publication in window order, including partial and
  advance-materialized empty windows, no manufactured or finish-boundary
  window, final state handoff, and
  rejection of later input;
- atomic error rollback, deterministic ordering and pruning, closed-frontier
  behavior, deterministic canonical digest preimages, and equal digest/state
  after rebuilding the same ordered prefix from a fresh Timeline;
- clock-domain and mapping text acceptance at exactly 128 UTF-8 bytes and
  rejection when empty, whitespace-only, or 129 bytes;
- rejection of missing, inconsistent, or corrupted epoch-termination receipts;
- dynamic coordinates with missing and invalid data preserved, actual-time
  slopes, stable ordering, and complete conditioning receipts;
- Learning/Commit maturity, unready-coordinate exclusion, pollution gates,
  exposure behavior, restart arming, lifecycle commands, and revision/state
  sequence preservation;
- Link/Profile identity preservation for the Program 1 path, physical-link
  coverage counting, conservative space aggregation, typed Unknown reasons, and
  one snapshot per global window;
- transaction rollback without partial state or publication, exact handoff,
  recovery from the current manifest seed, and retained-state equality; and
- equal live and faithful-replay semantic results for the Program 1 fixture
  under one pinned build and target. Generated multi-route and multi-Profile
  scenarios MAY additionally test isolation without becoming physical evidence;
  fixture cardinality and evidence classification are owned by the
  [development E2E v1 specification](development-e2e-v1.md).

Checked-in test source is not proof that these cases executed. The retained
evidence status and open gates are indexed in
[world/runtime evidence](../evidence/world-runtime.md).
