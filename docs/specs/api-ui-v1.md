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

Applicability: the complete route set, semantic query sources, command path,
disconnect/recovery behavior, and full schema-validation matrix belong to the
deferred Semantic Program. [Demo Slice v1](demo-slice-v1.md) is first-applicable
for its bounded topology/signals/live subset and imports the named JSON
definitions without redefining their wire shapes.

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
   identifies the Store and monotonic projection commit watermark, session and
   source-record range, and the relevant decoder, conditioning, algorithm, and
   baseline versions. Related rows within that response cannot come from
   different read snapshots.
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

All session times, UTC times, durations, full-width numeric IDs, record,
delivery, and projection-commit sequences, window IDs,
baseline revisions/state sequences, and `u64` counts use the canonical decimal
string form. Smaller typed counts remain JSON integers in their declared range.
A producer MUST NOT emit a full-width value as a JSON number, and a consumer
MUST NOT coerce its decimal string through a JavaScript `Number`.

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
| `GET /api/world/latest` | exact World-latest query below | 200 `$defs.WorldLatestOk` |
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
| Signal | `session`, `sensor`, `link`, `from`, `to`, `metric`, `max_time_buckets` | `profile`, `path` |
| Timeline | `session`, `sensor`, `link`, `from`, `to` | none |
| World | `session`, `from`, `to` | none |
| World latest | `session` | none |
| Evidence | none | `link`, `profile` |
| Baseline | `session` | `link`, `profile` |

Topology is Store-scoped and carries exactly `$defs.StoreViewReceipt`, whose
sole field is the `projection_commit` observed from `store_state` in the same
SQLite read snapshot. Its sequence may be zero for a provisioned Store with no
transaction B. Signals, Timeline, World, evidence, baselines, and their typed
empty results are session-scoped and carry exactly `$defs.ViewReceipt`:
`projection_commit`, `session_id`, `first_record_seq`, `last_record_seq`,
`decoder_version`, `conditioning_version`, and `algorithm_version`. Its session
ID equals the required query session, or for evidence the session decoded from
the canonical SnapshotId. Its Projection commit sequence is nonzero, its record
range is committed and satisfies `first_record_seq <= last_record_seq`, and all
fields come from the same SQLite read snapshot. A sequence-zero Store watermark
MUST NOT fabricate a session receipt or record range.

The `projection_commit` in both receipt types is exactly the current
`store_state` Store ID and projection sequence from that read snapshot.
`session_processing_state.projection_commit_seq` is only the session's
cursor/commit binding and visibility predicate; it MUST NOT replace the global
Store watermark in a session-scoped receipt.

For every session-scoped receipt, `last_record_seq` is exactly that snapshot's
`session_processing_state.processed_through_record_seq`, never the maximum raw
record in the base fact table. `first_record_seq` is the least retained record
not greater than that cursor. Query implementations MUST use the persistence
contract's `visible_sessions` and `visible_records` views; transaction-A-only
sessions and fact tails cannot affect an HTTP body or receipt.

For equal Store IDs, commit sequences are totally ordered; identities from
different Store IDs are incomparable and MUST NOT be treated as progress.
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
| 416 | `range_unavailable` | a required session is absent from `visible_sessions`, or a valid interval, snapshot evidence, or superseded session baseline lies outside retained/queryable projections |
| 422 | `phase_over_budget` | wrapped phase would exceed the raw point budget |
| 500 | `projection_failed` | committed projection reading or DTO construction fails; no partial data is returned |
| 503 | `command_queue_full` | the ordered baseline command queue has no capacity |

`RangeUnavailable` includes `available_from` and `available_to` when any range
is queryable. A session-scoped query may return a typed 200
`$defs.EmptyEnvelope` only after its required session is present in
`visible_sessions` and the reader can construct the complete `ViewReceipt` from
the same snapshot. It then means no row or selected identity matched inside
that visible session, rather than fabricated data; its `resource` is exactly
the requested resource. A valid required session that is unknown,
transaction-A-only, or no longer retained returns `RangeUnavailable`, never an
empty envelope with a fabricated receipt. `GET /api/world/latest` uses the same
empty envelope when its visible session has no snapshot. A world or link value
with insufficient evidence retains tagged `Knowledge::Unknown` inside an ok
response. An empty result is not an error, and an error never carries partial
`data`.

## Query projections

### Topology

`GET /api/topology` returns `$defs.TopologyData`: deployment; the dynamic
strictly ordered and unique collection of known session IDs; ordered spaces;
ordered sensors with hardware and full-width device identity; and ordered links
with space, transmitter, receiver, and ordered observed/admitted profile
identities. The session collection contains only sessions whose
`session_processing_state.projection_commit_seq` is non-NULL. A newly created
session is omitted until its first successful transaction B assigns that value
and advances the Store watermark; therefore sequence zero can name only the
empty-session topology. The collection may be empty, and inclusion does not
imply that a session has a nonempty semantic result. Topology preserves explicit
link relationships and does not infer geometry or physical coordinates that are
not present in committed facts.

Deployment, Space, Transmitter, Sensor, and Link identity comes only from the
immutable provisioned Store topology manifest read in the same SQLite snapshot.
Current TOML is not a query source. Each Link's Profile collection is the strictly
ordered unique set present in committed observation or baseline-state
projections at or before that snapshot's visibility cut; it is empty at
sequence zero. This makes a manifest-seeded Profile discoverable after the
first transaction B even when that record is a decode reject. A Store topology
change requires another Store in v1.

### SignalView

The signals route accepts the exact Signal query table above and reads only the
selected session. `metric` is one of `i`, `q`, `amplitude`, or `phase`.

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

`GET /api/timeline` returns ordered committed diagnostics for the explicitly
selected session and sensor/link interval, including sequence gaps, device-epoch
boundaries, rate, jitter, profile changes, and baseline command records where
applicable. Each entry preserves its session time, stream/link/profile identity,
typed event kind, typed details, and receipt. Absence of an event is not filled
with a synthetic normal event.

The exact `$defs.TimelineEvent` variants are `sequence_gap` with `missing`;
`device_epoch_boundary` with device and boot generation plus an omitted
`previous_boot_generation` only for the first known epoch; `rate` with
`packets_per_second`; `jitter` with `receive_jitter_ns`; `profile_changed`
with the new profile and an omitted previous profile only when none existed;
and `baseline_command` with the exact target and command. No other timeline
event kind is a v1 DTO.

### World and evidence

`GET /api/world` returns ordered world snapshots in the requested interval for
the explicitly selected session. `GET /api/world/latest` returns the latest
snapshot for its required session, or a typed empty result when that session has
no committed snapshot. Both preserve the snapshot identity, interval, predecessor identity,
space `Stable | Changing | Unknown(reason)`, link beliefs, contributions,
exclusions, RF dynamics, quality, baseline status, and derivation receipts
defined by [`temporal-world-v1.md`](temporal-world-v1.md).

`$defs.WorldSnapshot` exhaustively carries the current domain fields `id`,
optional `previous_id`, `deployment`, `window`, `valid_interval`, ordered
sensor/link/space entries, and `DerivationReceipt`. Dynamic-key domain maps use
ordered entry arrays so identifier text remains data and unknown JSON object
properties remain rejectable.

`GET /api/world/{snapshot_id}/evidence` is pinned to the named committed
snapshot. The route decodes the SnapshotId session and MUST require the
committed snapshot plus response ViewReceipt to carry that exact session;
cross-session lookup or substitution is invalid. Optional `link` and `profile`
selectors only filter evidence belonging to that snapshot. Returned coordinate evidence preserves ordered
`CsiPath x CsiSampleAxis`, observed and predicted values, signed residual,
standardized residual when present, exact included/excluded state, exclusion
reason, and the baseline revision/state sequence used to score it. Later
baseline updates cannot change the interpretation of an existing snapshot.
The response data is exactly `$defs.EvidenceData` and each entry is
`$defs.LinkStepEvidence`. Included and excluded coordinate evidence are
adjacently tagged; optional numeric evidence is omitted when unavailable, and
an excluded coordinate always carries one typed `exclusion`.

Each LinkStepEvidence entry carries `stream_segments`, not a singular stream.
Each element is the closed `StreamSegmentIdentity` value containing `stream`
and `segment_id`. The array may be empty and is strictly ordered and unique by
stream identity and then segment ID. Entry identity remains snapshot plus
Link/Profile. Without selectors, `EvidenceData.entries` is the snapshot's
complete computed evidence set; optional selectors produce only an
order-preserving filter of that complete set. The array may be empty and is
strictly ordered and unique by Link-ID UTF-8 bytes then Profile-ID bytes.

If the snapshot exists but its exact evidence projections are no longer
retained, the route returns typed `RangeUnavailable` semantics. Faithful replay
may rebuild the projections through an explicit replay workflow; the HTTP
request itself does not do so.

### Baselines and commands

`GET /api/baselines` returns committed baseline state for the required session
and selected link/profile, including lifecycle, maturity/coverage, revision,
state sequence, compatibility receipt, and the most recent decision when
available. Missing or learning state remains typed and is not promoted to
active.

`baseline_states` is the latest operational projection rather than
session-scoped history. The selected session MUST be visible and every returned
row's `source_session_id` MUST equal it. Once a later session's first transaction
B publishes its complete baseline set, a query for a retained predecessor
session returns `RangeUnavailable`; it MUST NOT return the successor's state or
misrepresent absence as a never-observed empty baseline. Historical snapshot
evidence remains available through its snapshot-pinned route.

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
`delivery_sequence`, the latest committed `projection_commit` visible when the
message is enqueued, and one `$defs.LivePayload`:

| `payload.kind` | Other required payload properties |
| --- | --- |
| `projection_watermark` | none |
| `retention_changed` | none |
| `sensor_health_changed` | `sensor` |
| `world_snapshot_added` | `snapshot_id` |
| `baseline_changed` | `link`, `profile`, `revision` |

The table and `$defs.LivePayload` are exhaustive; no payload property is
optional.

Immediately after a connection is established, before resource invalidations,
the server MUST send one `projection_watermark` envelope carrying the current
Store-bound Projection watermark. This handshake is sent even when no
new semantic event occurs. It gives reconnect a watermark without inventing a
state change. The handshake value is a zero-capable Projection watermark; only
transaction B or retention yields a nonzero Committed projection identity that
may authorize postcommit invalidation publication.

`delivery_sequence` is strictly increasing within one connection and is only a
delivery diagnostic. Projection commit sequence is the global query-visible
Store watermark and is monotonically nondecreasing within one Store on that
connection. An invalidation caused by transaction B MUST carry that
transaction's exact identity. A retention transaction that deletes
query-visible rows advances the watermark exactly once and, only after commit,
emits `retention_changed` with that exact identity; clients invalidate retained
ranges and refresh affected HTTP resources. A health invalidation that does not
change query-visible state carries the latest zero-capable Projection watermark
and is not postcommit publication.
Delivery sequence, connection identity, coalescing, and delivery mode never
enter a semantic snapshot or replay result.

The per-client queue is bounded. A slow client may observe a delivery-sequence
gap, receive only a newer invalidation, or be disconnected. The queue cannot
block ingest, SQLite writes, Engine progress, or another client. After a gap or
reconnect, a client discards notification-derived assumptions and refreshes the
affected resource by HTTP GET. The returned `ViewReceipt` is the resync proof
only when its Store ID equals the connection watermark Store ID and its commit
sequence is at least the watermark sequence.

The server does not stream full signal history, complete world snapshots, or
coordinate evidence through the WebSocket.

## Diagnostic UI

The v1 browser surface is one read-only two-dimensional diagnostic page. It
hydrates from the HTTP interface, uses WebSocket messages only to invalidate
HTTP resources, and provides:

- explicit Deployment, Sensor, Link, Profile, and session context plus topology
  selection;
- one time-by-native-coordinate signal facet per stream/profile;
- a sequence, gap, device-epoch, rate, jitter, profile, and baseline-command
  timeline;
- per-link predicted/observed evidence, deviation, RF dynamics, and quality;
- space `Stable | Changing | UNKNOWN`, contributions, and exclusions; and
- baseline lifecycle, maturity, revision, and latest decision.

The page exposes no baseline command or other state-changing control. Baseline
commands remain part of the HTTP API for authenticated tests and operators.

All visible axes name their coordinate semantics and units. An
`OpaqueSampleOrdinal` is labelled as an opaque CSI sample ordinal, never as a
subcarrier, tone, frequency, or MHz. Without geometry, the UI does not render a
spatial heatmap. Without human labels, it does not render people, presence,
pose, or other human semantics.

Different stream/profile layouts remain separate facets. Resizing or zooming
changes only the viewport and aggregation, never the stream/profile identity or
native coordinate meaning. Missing values and measured zeros are visually
distinct.

On WebSocket disconnect the page visibly enters `DISCONNECTED`, then marks any
retained committed HTTP result `STALE`; it cannot present stale data as live,
fabricate replacement samples, select only the first Sensor by default, or
repeat a shorter series to fill a view. On reconnect it visibly enters
`RESYNCHRONIZING`, waits for the mandatory `projection_watermark`, performs
canonical HTTP reads and validation, and enters `LIVE` only after every
required read returns the same Store ID at or beyond that watermark. A changed
Store ID invalidates all retained context and requires fresh topology and
resource reads; it is never compared numerically with the previous Store.

V1 does not promise one atomic snapshot spanning multiple HTTP requests. Each
resource is internally complete under its own receipt. A watermark invalidates
mounted resources independently, and the page remains `RESYNCHRONIZING` until
each required resource has returned the same Store ID and a sequence at least
the last handled watermark. A newer transaction may commit between reads;
resources may therefore carry different qualifying sequences. Fixed `as_of`
queries and multiversion projections are outside Program 1.

## Acceptance

The target requires behavior-focused source tests for strict query and JSON
validation, snapshot consistency, receipt watermark sourcing across retention,
dynamic layouts, missing-versus-zero, phase
budget rejection, typed unknown/empty/range errors, ordered command admission,
slow-client isolation, and disconnect/resync. Every schema root and every enum
variant requires an accepted fixture plus rejection fixtures for unknown and
duplicate properties, wrong scalar representation, invalid range, forbidden
null, non-finite/negative-zero float input, and optional-as-null.

Cross-language fixtures MUST roundtrip `u64::MAX`, `i64::MIN`, `i64::MAX`,
record/delivery/projection sequences, revisions/counts, non-ASCII and URL-sensitive
SessionIds inside SnapshotId, and lowercase hex64 identities through Rust and a
JavaScript consumer without precision or identity loss. They MUST prove
SnapshotId decode/re-encode equality and reject padding, noncanonical decimal
strings, uppercase hex, unsafe JavaScript-number coercion, and every
out-of-range integer.

The browser MUST validate each HTTP body and WebSocket text message against the
2020-12 schema plus the mandatory runtime formats before using it, preserve
full-width decimal strings or convert them directly to `BigInt`, and enter a
visible protocol-error state on invalid input. Program 1 browser acceptance uses
its one physical Sensor and Profile fixture in real Google Chrome, retains the
exact Chrome version, page interactions, network activity, and screenshots, and
verifies context selection, axis labels, missingness, resize/zoom identity, and
the `DISCONNECTED`, `STALE`, `RESYNCHRONIZING`, and `LIVE` states in two
independent scenarios. A transport-only reconnect keeps the Host process and
page instance unchanged, quiesces ingest, receives the same Projection
watermark as the first message on a new connection, returns equal HTTP
watermarks, and leaves both projection state and retained commit-index row count
unchanged. A Host-restart recovery keeps the page instance and active session,
uses a new connection, recovers the durable tail, commits the next new record,
and advances projection state. Neither scenario may satisfy the other.
Generated scenarios MAY exercise two different dynamic profile lengths
simultaneously, but do not become physical evidence. The browser implementation
and all selectors, collections, and layouts remain dynamic in Sensor and
Profile count as required by the
[development E2E v1 specification](development-e2e-v1.md).

End-to-end acceptance additionally proves committed capture-derived
projections can be queried through HTTP, invalidated through WebSocket, and
rendered by the browser without a second fact store or synthetic data. Test
source, browser execution, disconnect/resync execution, and end-to-end
execution are distinct claim surfaces, not additional Program 1 evidence-mode
classifications. Corpus artifacts retain input lineage only. The Program 1
verifier derives one execution-result classification only from the typed claim
ancestry owned by
[development E2E v1](development-e2e-v1.md#input-lineage-and-executed-classifications).
