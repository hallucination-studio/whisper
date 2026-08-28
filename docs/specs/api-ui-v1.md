# Query, API, WebSocket, and diagnostic UI specification v1

- Status: accepted target
- Version: v1
- Scope: host query projections, HTTP delivery, live invalidation, and the
  diagnostic browser UI
- Tracking issue: [#5](https://github.com/hallucination-studio/whisper/issues/5)

This specification is the sole normative owner for v1 query and UI behavior.
It does not claim that the target is implemented. Runtime ownership and
composition are described in
[`../architecture/query-runtime.md`](../architecture/query-runtime.md), and
current receipts and maturity are recorded in
[`../evidence/query-ui.md`](../evidence/query-ui.md).

The domain vocabulary comes from [`../../src/CONTEXT.md`](../../src/CONTEXT.md).
Temporal and world semantics are imported from
[`temporal-world-v1.md`](temporal-world-v1.md). Committed session, projection,
and retention semantics are imported from
[`persistence-v1.md`](persistence-v1.md). This specification uses those meanings
without redefining their contracts.

## Contract principles

1. Every query reads committed typed projections derived from the authoritative
   session records in the same SQLite database. A query never reads an Engine
   working state, reinterprets raw records, or starts replay.
2. One HTTP response is pinned to one SQLite read snapshot. Its receipt
   identifies the session and source-record range and the relevant decoder,
   conditioning, algorithm, and baseline versions. Related rows within that
   response cannot come from different read snapshots.
3. Signal shape is dynamic. Results preserve stream, profile, path, native
   coordinate, time, quality, missingness, and provenance. Results from
   different streams or profiles are separate tiles, never padded, truncated,
   concatenated, or repeated into a common tensor.
4. Missing data and measured zero are distinct. Insufficient evidence is a
   typed `Unknown(reason)`, not an application failure or an invented value.
5. Queries are bounded by configured time, bucket, point, and connection
   budgets. A valid request outside retained/queryable data returns a typed
   range error; the server does not reconstruct history on demand.
6. WebSocket traffic is an invalidation channel. Semantic state is obtained by
   HTTP GET, not reconstructed from delivery notifications.

## JSON and DTO wire profile

The machine-readable
[API/UI v1 JSON Schema](schemas/api-ui-v1.schema.json) is part of this
specification. It uses JSON Schema 2020-12, defines every v1 HTTP body and
WebSocket text message under `$defs`, and admits only those roots through its
top-level `oneOf`. The prose below owns validation that JSON Schema cannot
express by itself.

Every property name is lowercase `snake_case`. Every object is closed:
unknown properties are invalid, including inside enum payloads and errors.
Request decoders MUST detect and reject duplicate properties before converting
the JSON object to a map or DTO. Arrays retain the semantic order stated by this
specification and the imported domain contracts.

### Scalars and identities

| Domain value | Exact JSON representation |
| --- | --- |
| `u8`, `u16`, `u32`, `i8`, `i16`, `i32` | JSON integer in the complete range of that type |
| `u64` | canonical decimal JSON string `0` or a nonzero value without a leading zero, range `0..=18446744073709551615` |
| `i64` | canonical decimal JSON string `0`, a positive value without a leading zero, or `-` plus a nonzero value without a leading zero, range `-9223372036854775808..=9223372036854775807`; `-0` is invalid |
| `f64` | finite JSON number; NaN and infinities are invalid, input semantic negative zero is invalid, and output negative zero is emitted as JSON `0` |
| 32-byte identity or digest | exactly 64 lowercase ASCII hexadecimal digits |
| text ID or version | exact UTF-8 text satisfying the imported identifier grammar; no trimming, normalization, or case folding |

All session times, UTC times, durations, full-width numeric IDs, record and
delivery sequences, window IDs, baseline revisions/state sequences, and
`u64` counts use the canonical decimal string form. Smaller typed counts
remain JSON integers in their declared range. A producer MUST NOT emit a
full-width value as a JSON number, and a consumer MUST NOT coerce its decimal
string through a JavaScript `Number`.

Unit enum variants are lowercase `snake_case` JSON strings. A variant carrying
payload is a closed object with an adjacent `kind` discriminator and its
payload properties; there is no nested generic `value` or `data` wrapper
unless the schema names that property for the domain value itself.
`Knowledge::Unknown` is always a closed tagged object whose `kind` is exactly
`unknown` and whose `reason` is exactly one `UnknownReason` string; an absent
or null value MUST NOT stand for Unknown.

An optional property is omitted when absent. JSON `null` is accepted only for
one missing `SignalTile.cells` position. No request, receipt, enum, optional
field, empty result, or other response may use null. Measured numeric zero is a
normal value and is never missing.

### Snapshot identity

`SnapshotId` has one lossless representation in both JSON and the
`{snapshot_id}` path segment:

```text
s1.<session_base64url>.<window_decimal>
```

`session_base64url` is RFC 4648 base64url without padding over the exact
SessionId UTF-8 bytes. `window_decimal` is the canonical `u64` decimal string.
A decoder MUST reject invalid base64url, padding, non-UTF-8 bytes, an invalid
SessionId, an out-of-range or non-canonical window, and any value whose decoded
parts do not re-encode byte-for-byte to the input. The period separators are
not in the base64url alphabet, so the form is unambiguous and is already safe as
one URL path segment.

### JSON processing

V1 defines no canonical JSON byte serialization. Property order, insignificant
whitespace, and valid JSON number spelling do not carry identity. Producers
MUST emit values accepted by the schema and this profile; consumers MUST parse
strict JSON, reject duplicate or unknown properties, validate the applicable
schema root, enforce the custom integer/identifier/SnapshotId/finite-float
rules, and only then construct a domain value.

## HTTP interface

HTTP JSON bodies use `Content-Type: application/json`. Every HTTP body carries
`http_schema_version: 1`. The v1 methods, routes, request definitions, and
successful response definitions are:

| Method and route | Request | Nonempty success |
| --- | --- | --- |
| `GET /api/topology` | no query properties | 200 `$defs.TopologyOk` |
| `GET /api/signals` | exact Signal query below | 200 `$defs.SignalsOk` |
| `GET /api/timeline` | exact Timeline query below | 200 `$defs.TimelineOk` |
| `GET /api/world` | exact World query below | 200 `$defs.WorldListOk` |
| `GET /api/world/latest` | no query properties | 200 `$defs.WorldLatestOk` |
| `GET /api/world/{snapshot_id}/evidence` | canonical SnapshotId path plus exact Evidence query below | 200 `$defs.EvidenceOk` |
| `GET /api/baselines` | exact Baseline query below | 200 `$defs.BaselinesOk` |
| `POST /api/baselines/commands` | `$defs.BaselineCommandRequest` | 202 `$defs.AcceptedEnvelope` |
| `GET /api/live` with WebSocket upgrade | no query properties or HTTP body | WebSocket `$defs.LiveEnvelope` text messages |

Query values are decoded from URL query syntax exactly once. Text IDs retain
their decoded UTF-8 bytes and use the identifier profile above; profile values
are lowercase hex64. `from` and `to` are canonical `u64` decimal strings with
`TimeInterval` and `SessionTime` semantics. Positive `u32` query values are
decimal without a leading zero. The path selector is exactly
`tx_rx:<tx_stream>:<rx_chain>` or `raw_path_ordinal:<ordinal>`, with each
ordinal a canonical decimal `u16`. Unknown keys, duplicate keys, malformed
identities, reversed intervals, unsupported metrics, and values outside
configured limits are invalid requests.

| Query | Required keys | Optional keys |
| --- | --- | --- |
| Signal | `sensor`, `link`, `from`, `to`, `metric`, `max_time_buckets` | `profile`, `path` |
| Timeline | `sensor`, `link`, `from`, `to` | none |
| World | `from`, `to` | none |
| Evidence | none | `link`, `profile` |
| Baseline | none | `link`, `profile` |

All successful query responses carry a `ViewReceipt` with enough information
to locate their committed projection snapshot. Its exact closed shape is
`$defs.ViewReceipt`: `session_id`, `first_record_seq`, `last_record_seq`,
`decoder_version`, `conditioning_version`, and `algorithm_version`.
Snapshot identity, baseline contract, baseline revision, and baseline state
sequence appear in the exact data DTO where applicable and MUST NOT be omitted
merely because the UI does not display them.

### Errors and empty results

Every non-success body is `$defs.ErrorEnvelope`. Status and `error.code`
mapping is exact:

| HTTP status | `error.code` | Condition |
| ---: | --- | --- |
| 400 | `invalid_request` | malformed JSON/query, duplicate or unknown property/key, invalid scalar/identity/enum/interval, unsupported metric, or invalid baseline command |
| 404 | `snapshot_not_found` | the canonical evidence-route SnapshotId has no committed snapshot |
| 416 | `range_unavailable` | a valid interval or snapshot evidence lies outside retained/queryable projections |
| 422 | `phase_over_budget` | wrapped phase would exceed the raw point budget |
| 500 | `projection_failed` | committed projection reading or DTO construction fails; no partial data is returned |
| 503 | `command_queue_full` | the ordered baseline command queue has no capacity |

`RangeUnavailable` includes `available_from` and `available_to` when any range
is queryable. A valid query with no matching identity or rows returns a typed
200 `$defs.EmptyEnvelope` rather than fabricated data; its `resource` is
exactly the requested resource. `GET /api/world/latest` uses the same empty
envelope when no snapshot exists. A world or link value with insufficient
evidence retains tagged `Knowledge::Unknown` inside an ok response. An empty
result is not an error, and an error never carries partial `data`.

## Query projections

### Topology

`GET /api/topology` returns `$defs.TopologyData`: deployment; ordered spaces;
ordered sensors with hardware and full-width device identity; and ordered links
with space, transmitter, receiver, and ordered observed/admitted profile
identities. It preserves explicit link relationships and does not infer
geometry or physical coordinates that are not present in committed facts.

### SignalView

The signals route accepts the exact Signal query table above. `metric` is one of
`i`, `q`, `amplitude`, or `phase`.

`$defs.SignalsData` contains the requested metric and an ordered nonempty
`tiles` array. Each `$defs.SignalTile` contains exactly `stream`, `profile`,
`time_axis`, `path_axis`, `sample_axis`, `order`,
`cells`, `aggregation`, `missing_spans`, and `receipt`. `CsiPath` and
`CsiSampleAxis` use all current domain variants in their respective schema
definitions; full-width frequency values remain decimal strings.

There is exactly one tile per returned stream/profile pair. Omitting `profile`
may return multiple tiles but never merges them. Axes are ordered according to
their domain ordering, cells have one documented flattening order, and every
cell position is interpretable from the axes. `cells` length MUST equal
`time_axis.length * path_axis.length * sample_axis.length`. A missing cell is
JSON null and numeric zero is a `SignalBucket` value; no other null is valid.

For `i`, `q`, and `amplitude`, a range within the point budget returns raw
samples. A wider viewport is aggregated at request time into no more than
`max_time_buckets`, with each non-empty bucket carrying minimum, maximum, mean,
RMS, and count. Persisted viewport tiles and multiresolution caches are outside
v1.

`phase` is returned only as raw wrapped phase. The server does not calculate a
linear minimum, mean, RMS, or other downsampled phase value. A phase request
over the raw point budget returns 422 and directs the caller to request a
smaller interval.

### Timeline

`GET /api/timeline` returns ordered committed diagnostics for the selected
sensor/link interval, including sequence gaps, device-epoch boundaries, rate,
jitter, profile changes, and baseline command records where applicable. Each
entry preserves its session time, stream/link/profile identity, typed event
kind, typed details, and receipt. Absence of an event is not filled with a
synthetic normal event.

The exact `$defs.TimelineEvent` variants are `sequence_gap` with `missing`;
`device_epoch_boundary` with device and boot generation plus an omitted
`previous_boot_generation` only for the first known epoch; `rate` with
`packets_per_second`; `jitter` with `receive_jitter_ns`; `profile_changed`
with the new profile and an omitted previous profile only when none existed;
and `baseline_command` with the exact target and command. No other timeline
event kind is a v1 DTO.

### World and evidence

`GET /api/world` returns ordered world snapshots in the requested interval.
`GET /api/world/latest` returns a typed empty result when no committed snapshot
exists. Both preserve the snapshot identity, interval, predecessor identity,
space `Stable | Changing | Unknown(reason)`, link beliefs, contributions,
exclusions, RF dynamics, quality, baseline status, and derivation receipts
defined by [`temporal-world-v1.md`](temporal-world-v1.md).

`$defs.WorldSnapshot` exhaustively carries the current domain fields `id`,
optional `previous_id`, `deployment`, `window`, `valid_interval`, ordered
sensor/link/space entries, and `DerivationReceipt`. Dynamic-key domain maps use
ordered entry arrays so identifier text remains data and unknown JSON object
properties remain rejectable.

`GET /api/world/{snapshot_id}/evidence` is pinned to the named committed
snapshot. Optional `link` and `profile` selectors only filter evidence belonging
to that snapshot. Returned coordinate evidence preserves ordered
`CsiPath x CsiSampleAxis`, observed and predicted values, signed residual,
standardized residual when present, exact included/excluded state, exclusion
reason, and the baseline revision/state sequence used to score it. Later
baseline updates cannot change the interpretation of an existing snapshot.
The response data is exactly `$defs.EvidenceData` and each entry is
`$defs.LinkStepEvidence`. Included and excluded coordinate evidence are
adjacently tagged; optional numeric evidence is omitted when unavailable, and
an excluded coordinate always carries one typed `exclusion`.

If the snapshot exists but its exact evidence projections are no longer
retained, the route returns typed `RangeUnavailable` semantics. Faithful replay
may rebuild the projections through an explicit replay workflow; the HTTP
request itself does not do so.

### Baselines and commands

`GET /api/baselines` returns committed baseline state for the selected link and
profile, including lifecycle, maturity/coverage, revision, state sequence,
compatibility receipt, and the most recent decision when available. Missing or
learning state remains typed and is not promoted to active.

Each `$defs.BaselineItem` contains exactly link/profile identity, the complete
`BaselineLifecycle` variant, optional nonzero revision/state sequence, optional
learning `BaselineMaturity`, compatibility receipt, and optional latest
`BaselineDecision`. Those optional properties are omitted when the domain value
does not exist. Runtime validation MUST enforce the imported lifecycle
combinations rather than accepting a schema-valid but contradictory set.

`POST /api/baselines/commands` accepts exactly one targeted baseline command
defined by [`temporal-world-v1.md`](temporal-world-v1.md). Successful admission
means the command was placed on the bounded ordered command queue; it does not
mean the Engine has applied or persisted it. The response identifies the
accepted target and an opaque delivery correlation value. Queue exhaustion
returns 503; a command is never silently dropped or applied out of
session-record order.

The request is exactly `$defs.BaselineCommandRequest`. `begin_learning`,
`commit`, `freeze`, and `resume` are unit strings. `activate_snapshot` is the
closed adjacent-tag object carrying `$defs.BaselineSnapshot` with every
coordinate; no shorthand, omitted coordinate state, compatibility alias, or
second command in one body is accepted. The 202 body is exactly
`$defs.AcceptedEnvelope` and reports the accepted target and opaque correlation
ID without claiming that Engine applied the command.

## WebSocket invalidation

`/api/live` sends one `$defs.LiveEnvelope` JSON value in each WebSocket text
message. Binary messages, batched roots, and partial payloads are invalid. The
closed envelope contains `http_schema_version: 1`, canonical-string
`delivery_sequence`, and one `$defs.LivePayload`:

| `payload.kind` | Other required payload properties |
| --- | --- |
| `sensor_health_changed` | `sensor` |
| `world_snapshot_added` | `snapshot_id` |
| `baseline_changed` | `link`, `profile`, `revision` |

The table and `$defs.LivePayload` are exhaustive; no payload property is
optional.

`delivery_sequence` is strictly increasing within one connection and is only a
delivery diagnostic. It, the connection identity, coalescing, and delivery mode
never enter a semantic snapshot or replay result.

The per-client queue is bounded. A slow client may observe a delivery-sequence
gap, receive only a newer invalidation, or be disconnected. The queue cannot
block ingest, SQLite writes, Engine progress, or another client. After a gap or
reconnect, a client discards notification-derived assumptions and refreshes the
affected resource by HTTP GET. The returned `ViewReceipt` is the resync proof.

The server does not stream full signal history, complete world snapshots, or
coordinate evidence through the WebSocket.

## Diagnostic UI

The v1 browser surface is one two-dimensional diagnostic page. It hydrates from
the HTTP interface, uses WebSocket messages only to invalidate HTTP resources,
and provides:

- topology plus link/profile selection;
- one time-by-native-coordinate signal facet per stream/profile;
- a sequence, gap, device-epoch, rate, jitter, profile, and baseline-command
  timeline;
- per-link predicted/observed evidence, deviation, RF dynamics, and quality;
- space `Stable | Changing | UNKNOWN`, contributions, and exclusions; and
- baseline lifecycle, maturity, revision, and latest decision.

All visible axes name their coordinate semantics and units. An
`OpaqueSampleOrdinal` is labelled as an opaque CSI sample ordinal, never as a
subcarrier, tone, frequency, or MHz. Without geometry, the UI does not render a
spatial heatmap. Without human labels, it does not render people, presence,
pose, or other human semantics.

Different stream/profile layouts remain separate facets. Resizing or zooming
changes only the viewport and aggregation, never the stream/profile identity or
native coordinate meaning. Missing values and measured zeros are visually
distinct.

On WebSocket disconnect the page visibly enters `DISCONNECTED`. It may retain
the last committed HTTP result only when marked stale; it cannot present it as
live, fabricate replacement samples, select only the first sensor by default,
or repeat a shorter series to fill a view. On reconnect it performs HTTP
resynchronization before returning to a live state.

## Acceptance

The target requires behavior-focused source tests for strict query and JSON
validation, snapshot consistency, dynamic layouts, missing-versus-zero, phase
budget rejection, typed unknown/empty/range errors, ordered command admission,
slow-client isolation, and disconnect/resync. Every schema root and every enum
variant requires an accepted fixture plus rejection fixtures for unknown and
duplicate properties, wrong scalar representation, invalid range, forbidden
null, non-finite/negative-zero float input, and optional-as-null.

Cross-language fixtures MUST roundtrip `u64::MAX`, `i64::MIN`, `i64::MAX`,
record/delivery sequences, revisions/counts, non-ASCII and URL-sensitive
SessionIds inside SnapshotId, and lowercase hex64 identities through Rust and a
JavaScript consumer without precision or identity loss. They MUST prove
SnapshotId decode/re-encode equality and reject padding, noncanonical decimal
strings, uppercase hex, unsafe JavaScript-number coercion, and every
out-of-range integer.

The browser MUST validate each HTTP body and WebSocket text message against the
2020-12 schema plus the mandatory runtime formats before using it, preserve
full-width decimal strings or convert them directly to `BigInt`, and enter a
visible protocol-error state on invalid input. Browser acceptance uses at least
two different dynamic profile lengths simultaneously and verifies axis labels,
missingness, resize/zoom identity, and disconnected state.

End-to-end acceptance additionally proves committed capture-derived
projections can be queried through HTTP, invalidated through WebSocket, and
rendered by the browser without a second fact store or synthetic data. Test
source, browser execution, disconnect/resync execution, and end-to-end
execution are separate evidence classes; each executed claim requires its own
retained receipt.
