# Demo Slice v1 specification

- Status: accepted target
- Version: `demo-slice-v1`
- Scope: bounded ESP32-S3-to-Chrome development demonstration
- Tracking issue: [#118](https://github.com/hallucination-studio/whisper/issues/118)

This specification is the first-applicable normative owner for the bounded
Demo Slice:

```text
ESP32-S3
  -> native-frame AES-256-GCM
  -> route/rate/replay admission
  -> one SQLite atomic ingest
  -> committed native-coordinate CSI
  -> topology/signals/live
  -> read-only Chrome
```

It defines an intentionally smaller persistence and delivery contract than the
future Semantic Program. Current implementation and executed demonstration
maturity remain separate from this accepted target. Architecture ownership is
recorded in [Demo Slice architecture](../architecture/demo-slice.md), and open
work and blockers remain in GitHub Issues.

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

## Imported authorities

The Demo Slice imports the following contracts without changing their bytes or
domain meaning:

| Imported contract | Canonical owner |
| --- | --- |
| Native-frame v1 envelope, AES-256-GCM authentication, outer reject-phase ordering, capability descriptor, CSI body, and provisioning compatibility | [Native-frame v1](native-frame-v1.md) |
| Identifier grammar, canonical `ReplayConfig` bytes and digest, route budgets, replay-window identity and algorithm, `StoreTopologyManifestV1`, Store ID, and Projection watermark representation | [Host persistence v1](persistence-v1.md) |
| `RuntimeConfig.capture.secret_root` boundary, relative epoch-key path grammar, pre/post metadata and file-identity checks, exact 32-byte read, and `WrongEpoch`/`Missing` results | [Host persistence v1](persistence-v1.md#program-1-development-secret-store) |
| Managed store root and object trust, retained `HostLifecycle` lease, staged initialization, atomic no-replace publication, and common non-creating open | [Host persistence v1](persistence-v1.md#managed-store-identity-and-cooperative-lease) |
| Capture Profile identity, native-coordinate `CsiObservation` value, and standalone CBOR root | [Temporal world v1](temporal-world-v1.md#capture-profile-identity) and [CsiObservation root](temporal-world-v1.md#csiobservation-root) |
| JSON scalar profile and the named `$defs.TopologyOk`, `$defs.SignalsOk`, `$defs.EmptyEnvelope`, `$defs.ErrorEnvelope`, `$defs.StoreViewReceipt`, `$defs.ViewReceipt`, `$defs.LiveEnvelope`, and their transitive DTOs | [API/UI v1](api-ui-v1.md) and its [JSON Schema](schemas/api-ui-v1.schema.json) |

Where this document gives Demo-specific schema, Capture Session, ingest,
visibility, or browser-state rules, those rules are first-applicable for
`demo-slice-v1`. They do not amend the imported Managed-store lifecycle or the
contract for a Semantic Session.

## Scope and deferrals

A Demo Store and each Capture Session remain dynamic in configured Sensor,
Link, Profile, packet, and observation count. One physical ESP32-S3 is the
executed `demo-smoke` scope, not a runtime cardinality limit. No implementation
may select the first configured Sensor, Link, Profile, Capture Session, or
observation as an implicit singleton.

The Demo Slice includes exact encrypted packet retention, durable replay
admission, committed capability authority, native-coordinate CSI, the canonical
topology/signals/live API subset, and a read-only browser.

The following are explicitly deferred to the Semantic Program:

- Semantic Sessions and compatible restart inside one Semantic Session;
- Timeline, conditioning beyond retaining the imported version identity,
  statistical baseline, Engine, World, semantic replay, calibration, and
  evaluation;
- transaction A/B processing, `projection_commits`, Timeline digests,
  baselines, pending handoff, rotation, retention, and recovery of a durable
  semantic tail;
- the complete API/UI route and schema-validation matrix;
- development-E2E claim graphs, BrowserTrace, formal evidence classification,
  storage/resource qualification, and Program-completion receipts; and
- physical Multi-sensor acceptance.

A Host process failure ends the current Capture Session. Starting `serve` again
creates another Capture Session; it does not recover or continue the prior one.
Durable replay admission and committed capability rows remain Store-scoped and
survive that boundary.

## Configuration and commands

`parse_config` and the accepted `ReplayConfig`/`RuntimeConfig` split from host
persistence v1 remain the sole TOML grammar and general validation contract.
Demo implementation may ignore deferred semantic values at runtime, but it
MUST parse, validate, canonicalize, digest, persist, and compare the complete
imported ReplayConfig. It MUST NOT create a second configuration root or a
Demo-only key field.

The accepted commands are:

```text
whisper check-config <config>
whisper init-admission <config>
whisper serve <config>
```

`check-config` performs only the imported TOML parse and general validation. It
MUST NOT apply the Demo-only network-role admission below or create or mutate a
Store.

`init-admission` is the only command allowed to create a Demo Store. It creates,
validates, closes, and exits; it never starts capture, HTTP, or WebSocket work.
It MUST enter through the imported `HostLifecycle`, retain the Managed store
root lease through final validation and connection close, and fail rather than
replace a final database path that already exists.

`serve` is the only running command. It MUST open the configured Store without
creation, validation repair, migration, reset, or replacement. It validates the
Store identity and exact ReplayConfig and topology bytes, validates every
configured admission epoch, creates a new Capture Session, then starts capture
and delivery. Any failure before the Capture Session commit starts no runtime
work. Any later fatal writer or Store error stops capture and delivery.
`serve` MUST enter through the same imported `HostLifecycle`, acquire the
Managed store root lease before opening the Store or committing the Capture
Session, and retain the lease until capture and delivery have stopped and every
SQLite connection has closed.

After the imported configuration parse succeeds and before lease acquisition or
Store mutation, `serve` applies the Demo network-role admission. The
`RuntimeConfig.server.bind` value MUST name a loopback IP socket address; a
wildcard, LAN, multicast, or other non-loopback server address is invalid. The
`RuntimeConfig.capture.bind` value MUST permit packets from the configured
board-facing network: its IP is either unspecified or a local non-loopback
unicast address. A loopback-only, multicast, or non-local capture address is
invalid. These are `serve` admission rules, not additions to `parse_config`'s
shared grammar. They prevent exposing the Demo HTTP service while still
allowing the physical board to reach UDP capture.

## Demo Store identity and initialization

A Demo Store is one SQLite database whose header has both:

```text
PRAGMA application_id = 0x57535044; -- decimal 1465077828, ASCII WSPD
PRAGMA user_version = 1;
```

Both values are identity, not migration hints. `application_id=0`, any other
application ID, any other user version, a missing table/index, an extra
user-defined table/index/trigger/view, malformed state, or incompatible SQLite
setting MUST fail closed. The implementation MUST NOT adopt, migrate, repair,
overwrite, or reinterpret a legacy database.

The Demo uses the imported Managed store root, fixed root-relative lease, and
managed-object ownership, file-type, link-count, exact-mode, and no-follow
rules unchanged. Both `init-admission` and `serve` hold the root lease as the
sole cooperative lifecycle writer fence; Store ID is never a second fence.

`init-admission` creates and initializes only one private collision-resistant
staging database inside the validated root. It applies the exact Demo header,
schema, initial rows, and settings below, then follows the imported checkpoint,
synchronization, close, non-creating validation, atomic no-replace publication,
root synchronization, and final non-creating verification sequence. A failure
MUST remove only its own unpublished staging artifacts when safe to do so and
MUST leave the final component absent or byte-identical to the pre-existing
object. It MUST NOT create a partial database at the final path.

Initialization selects WAL mode before schema creation and applies and verifies
`synchronous=FULL`. Every connection enables and verifies `foreign_keys=ON` and
`trusted_schema=OFF`; reader connections additionally enable `query_only=ON`.
The `serve` writer also applies and verifies connection-local
`synchronous=FULL`; readers require no synchronous setting. The writer uses an
explicit zero busy timeout so lock conflict is a bounded failure rather than
hidden retry. Initialization checkpoints WAL with
`wal_checkpoint(TRUNCATE)` before its final validation and close. A later
`serve` may allow normal SQLite WAL recovery but MUST NOT run application-level
repair.

Initialization uses one `BEGIN IMMEDIATE` transaction to create exactly the six
tables and indexes below, insert exactly one `store_state` row, and insert
exactly one empty `admission_epochs` row for every configured route epoch.
`store_id` is 32 cryptographically random bytes. `projection_commit_seq` begins
as eight zero bytes. Replay and other unsigned integer BLOBs are fixed-width
big-endian so SQLite byte order matches unsigned numeric order.

```sql
CREATE TABLE store_state (
    singleton INTEGER NOT NULL CHECK(singleton = 1),
    store_id BLOB NOT NULL CHECK(length(store_id) = 32),
    topology_manifest_cbor BLOB NOT NULL,
    topology_manifest_digest BLOB NOT NULL
        CHECK(length(topology_manifest_digest) = 32),
    replay_config_cbor BLOB NOT NULL,
    replay_config_digest BLOB NOT NULL
        CHECK(length(replay_config_digest) = 32),
    projection_commit_seq BLOB NOT NULL
        CHECK(length(projection_commit_seq) = 8),
    PRIMARY KEY (singleton)
) WITHOUT ROWID;

CREATE TABLE admission_epochs (
    device_id BLOB NOT NULL CHECK(length(device_id) = 8),
    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 2),
    replay_window_identity BLOB NOT NULL
        CHECK(length(replay_window_identity) = 32),
    replay_window_size INTEGER NOT NULL
        CHECK(replay_window_size BETWEEN 1 AND 65535),
    highest_boot_generation BLOB
        CHECK(highest_boot_generation IS NULL
              OR length(highest_boot_generation) = 4),
    maximum_message_sequence BLOB
        CHECK(maximum_message_sequence IS NULL
              OR length(maximum_message_sequence) = 8),
    seen_bitmap BLOB NOT NULL,
    PRIMARY KEY (device_id, key_epoch),
    CHECK((highest_boot_generation IS NULL)
          = (maximum_message_sequence IS NULL)),
    CHECK(length(seen_bitmap) = (replay_window_size + 7) / 8)
) WITHOUT ROWID;

CREATE TABLE capture_sessions (
    session_id TEXT NOT NULL,
    started_utc_ns BLOB NOT NULL CHECK(length(started_utc_ns) = 8),
    replay_config_digest BLOB NOT NULL
        CHECK(length(replay_config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    committed_through_record_seq BLOB
        CHECK(committed_through_record_seq IS NULL
              OR length(committed_through_record_seq) = 8),
    last_session_time_ns BLOB
        CHECK(last_session_time_ns IS NULL
              OR length(last_session_time_ns) = 8),
    projection_commit_seq BLOB
        CHECK(projection_commit_seq IS NULL
              OR length(projection_commit_seq) = 8),
    PRIMARY KEY (session_id),
    CHECK((committed_through_record_seq IS NULL)
          = (last_session_time_ns IS NULL)),
    CHECK((committed_through_record_seq IS NULL)
          = (projection_commit_seq IS NULL))
) WITHOUT ROWID;

CREATE TABLE packet_records (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time_ns BLOB NOT NULL CHECK(length(session_time_ns) = 8),
    receive_utc_ns BLOB NOT NULL CHECK(length(receive_utc_ns) = 8),
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL CHECK(peer_port BETWEEN 0 AND 65535),
    device_id BLOB NOT NULL CHECK(length(device_id) = 8),
    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 2),
    boot_generation BLOB NOT NULL CHECK(length(boot_generation) = 4),
    message_sequence BLOB NOT NULL CHECK(length(message_sequence) = 8),
    message_kind INTEGER NOT NULL CHECK(message_kind BETWEEN 0 AND 255),
    disposition TEXT NOT NULL CHECK(disposition IN (
        'unknown_kind',
        'malformed_known_body',
        'capability_pin_mismatch',
        'capability_committed',
        'health_committed',
        'capability_unavailable',
        'build_mismatch',
        'capability_mismatch',
        'source_mismatch',
        'radio_mismatch',
        'body_budget_mismatch',
        'decoded_domain_rejected',
        'csi_committed'
    )),
    encrypted_datagram BLOB NOT NULL,
    PRIMARY KEY (session_id, record_seq),
    UNIQUE (device_id, key_epoch, boot_generation, message_sequence),
    FOREIGN KEY (session_id) REFERENCES capture_sessions(session_id)
) WITHOUT ROWID;

CREATE INDEX packet_records_time
    ON packet_records(session_id, session_time_ns, record_seq);

CREATE TABLE capability_epochs (
    device_id BLOB NOT NULL CHECK(length(device_id) = 8),
    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 2),
    boot_generation BLOB NOT NULL CHECK(length(boot_generation) = 4),
    capability_digest BLOB NOT NULL CHECK(length(capability_digest) = 32),
    descriptor_bytes BLOB NOT NULL CHECK(length(descriptor_bytes) = 79),
    first_session_id TEXT NOT NULL,
    first_record_seq BLOB NOT NULL CHECK(length(first_record_seq) = 8),
    PRIMARY KEY (device_id, key_epoch, boot_generation),
    FOREIGN KEY (first_session_id, first_record_seq)
        REFERENCES packet_records(session_id, record_seq)
) WITHOUT ROWID;

CREATE TABLE csi_observations (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time_ns BLOB NOT NULL CHECK(length(session_time_ns) = 8),
    sensor_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    observation_cbor BLOB NOT NULL,
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    replay_config_digest BLOB NOT NULL
        CHECK(length(replay_config_digest) = 32),
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id, record_seq)
        REFERENCES packet_records(session_id, record_seq)
) WITHOUT ROWID;

CREATE INDEX csi_by_link_time
    ON csi_observations(
        session_id, sensor_id, link_id, profile_id,
        session_time_ns, record_seq
    );

PRAGMA application_id = 1465077828;
PRAGMA user_version = 1;
```

`init-admission` stores the exact imported canonical ReplayConfig and
`StoreTopologyManifestV1` bytes and their SHA-256 digests. It derives every
replay-window identity exactly as host persistence v1 specifies. It checkpoints
and closes the initialized database before reporting success. No WAL or SHM
content may be required to interpret the closed result.

Every `serve` generates a new Session ID as exact text
`capture-<32-lowercase-hex-digits>` from 16 operating-system random bytes. It
captures one monotonic origin and inserts the new `capture_sessions` row in one
`BEGIN IMMEDIATE` transaction before receiving UDP. Session creation does not
advance the Store watermark and an empty Capture Session is not query-visible.
`started_utc_ns` is the checked nonnegative nanosecond count since the Unix
epoch. `decoder_version` is exactly `native-frame-v1`, `conditioning_version`
is the imported ReplayConfig conditioning version, and `algorithm_version` is
exactly `demo-native-coordinate-v1`. The latter two are API compatibility and
input-identity fields; they do not claim that conditioning or a semantic
algorithm ran.

## Admission and pure candidate decode

For every received datagram, `serve` performs these steps in order before any
SQLite transaction:

1. capture receive UTC, receive-monotonic time, and the exact peer socket;
2. validate the datagram budget and native-frame fixed header;
3. select the exact configured HeaderRoute and load its exact key;
4. authenticate the complete native frame;
5. apply the authenticated per-route packet and byte rate limits; and
6. produce one pure `WireCandidate` from the authenticated header and plaintext
   body.

`session_time_ns` is the nonnegative nanosecond duration from the current
Capture Session's monotonic origin to UDP receipt. Candidate construction MUST
NOT read or mutate SQLite, replay state, capability state, a Profile catalog,
query state, or any other authority. It performs bounded syntax decoding only
and contains enough typed data to complete the disposition inside the writer
transaction. It creates no observation and authorizes no side effect.

An unauthenticated, route/rate/byte rejected, or writer-queue-dropped datagram
does not enter SQLite and does not advance replay state, a Capture Session
cursor, or the Store watermark. Authenticated rate accounting may remain
process-local and resets for a new `serve`; replay admission never does.

## One atomic admitted-packet transaction

The single blocking writer owns the only writer connection and handles queued
candidates sequentially. For each candidate it executes exactly one
`BEGIN IMMEDIATE` transaction and, in order:

1. reads the current Store watermark and Capture Session cursor;
2. rereads and validates the configured `admission_epochs` row;
3. rejects a replay or atomically advances the imported replay window;
4. resolves capability, route, Profile, and final disposition solely from the
   candidate, immutable Store configuration, and rows visible in this
   transaction;
5. assigns record sequence zero for the first committed packet, otherwise the
   checked successor of the prior cursor, and requires nondecreasing
   `session_time_ns`;
6. inserts exactly one `packet_records` row with the exact encrypted datagram;
7. inserts or validates the applicable `capability_epochs` row and inserts
   exactly one `csi_observations` row only when required by the disposition;
8. updates the Capture Session cursor, time, and commit binding; and
9. advances `store_state.projection_commit_seq` to its checked successor with a
   compare-and-set update that affects exactly one row.

Every listed effect commits or rolls back together. Sequence overflow,
constraint failure, capability conflict, non-monotonic session time, or a Store
compare-and-set failure rolls back replay admission, packet, capability,
observation, cursor, and watermark, then stops the running Host before any
publication. There is no transaction A/B split and no `projection_commits`
table in the Demo Store.

SQLite is the sole capability, Profile-membership, visibility, and query
authority. A derived map may exist only inside one writer or reader transaction
and MUST be discarded before that transaction ends. No process-lifetime
`ProfileCatalog`, capability cache, or other memory state may survive rollback
as authority or supply a query result.

The final candidate disposition and transaction effects are exhaustive. The
writer evaluates these rows from top to bottom and applies only the first
matching row. This first-match order is the total precedence rule when one
candidate satisfies more than one failure condition:

| Authenticated candidate outcome | Replay state | Packet | Capability row | CSI observation | Cursor/watermark |
| --- | --- | --- | --- | --- | --- |
| Replay duplicate, too old, or invalid generation | unchanged | none | none | none | unchanged |
| Unknown v1 kind | advanced | `unknown_kind` | none | none | advanced once |
| Malformed known body | advanced | `malformed_known_body` | none | none | advanced once |
| Capability body or descriptor malformed | advanced | `malformed_known_body` | none | none | advanced once |
| Capability firmware-build pin mismatch | advanced | `build_mismatch` | none | none | advanced once |
| Capability digest pin mismatch | advanced | `capability_pin_mismatch` | none | none | advanced once |
| First conforming capability for the epoch | advanced | `capability_committed` | inserted | none | advanced once |
| Repeated byte-equal conforming capability | advanced | `capability_committed` | exact row validated | none | advanced once |
| Conforming health body | advanced | `health_committed` | none | none | advanced once |
| CSI without an earlier committed epoch capability | advanced | `capability_unavailable` | none | none | advanced once |
| CSI firmware-build mismatch | advanced | `build_mismatch` | none | none | advanced once |
| CSI capability-digest mismatch | advanced | `capability_mismatch` | none | none | advanced once |
| CSI source mismatch | advanced | `source_mismatch` | none | none | advanced once |
| CSI radio mismatch | advanced | `radio_mismatch` | none | none | advanced once |
| CSI body-budget mismatch | advanced | `body_budget_mismatch` | none | none | advanced once |
| CSI decoded-domain failure | advanced | `decoded_domain_rejected` | none | none | advanced once |
| Fully conforming CSI | advanced | `csi_committed` | exact row validated | exactly one | advanced once |

An existing capability row that differs in digest or descriptor is corruption
or an epoch conflict, not another disposition: the entire transaction fails
closed. A capability row inserted by the current capability packet is durable
before any later CSI packet can use it because candidates are transacted one at
a time. Later capability arrival never retroactively decodes an earlier packet.

The committed `observation_cbor` is the imported standalone `CsiObservation`
root. Every root or observation value is determined as follows:

| Value | Exact Demo source |
| --- | --- |
| root `config_digest` | immutable Store ReplayConfig digest |
| root `conditioning_version` | immutable Store ReplayConfig conditioning version |
| `input` | current Capture Session ID, assigned packet `record_seq`, and exact decoder version `native-frame-v1` |
| `sensor` and `link` | the configured DecodedRoute selected from the authenticated source and radio facts |
| `hardware` | exact value `esp32-s3` |
| `device_epoch` | authenticated header `device_id` and `boot_generation` |
| `capture_sequence` | authenticated CSI body `capture_sequence` |
| `callback_tick_us` | authenticated CSI body `callback_tick_us` |
| `timing` | `received_ns = event_ns = session_time_ns`; `source = receive_only`; `mapping_version = null`; `uncertainty_ns = 0`; retained `device.ticks` from authenticated `driver_rx_timestamp_us`; `device.clock_domain = esp32s3-driver-ticks` |
| `radio` | authenticated channel, RSSI, and noise floor; `centre_frequency_hz = null`; bandwidth is `20000000` or `40000000` from the authenticated bandwidth value; PPDU is `legacy` for Non-HT and `ht` for HT |
| `profile` | imported Capture Profile v1 identity defined below |
| `csi` | one `raw_path_ordinal` path at ordinal zero; opaque sample count equal to authenticated `complex_sample_count`; authenticated I/Q pairs and validity; signed 8-bit `imaginary_real` encoding at scale `1/1`; `phase_state = raw` |

Zero timing uncertainty describes the defined receive-only equality; it does
not claim capture-clock accuracy or clock synchronization.

The Profile ID is the SHA-256 identity of the imported Capture Profile v1
descriptor. For this Demo its descriptor has `hardware = Esp32S3`; `firmware`
is the lowercase hexadecimal authenticated firmware-build digest;
`decoder_version = native-frame-v1`; and `capability_id` is the lowercase
hexadecimal authenticated capability digest. Acquisition has `mode = WifiCsi`,
`ltf_selection = Legacy` for Non-HT and `Ht` for HT, `ltf_merge = None`, and
`validity_dialect = FirstWordInvalid`.

The descriptor's channel, secondary-channel value, and STBC value are the
authenticated CSI body values. Bandwidth is `20000000` or `40000000` and PPDU
is `Legacy` or `Ht` under the same mapping as observation radio metadata;
centre frequency is `null`. Layout is one `RawPathOrdinal(0)`, an
`OpaqueSampleOrdinal` count equal to authenticated `complex_sample_count`, and
`PathThenSample` order. Encoding is signed 8-bit `ImaginaryReal` at scale
`1/1`; phase state is `Raw`; time quality is `ReceiveOnly`; and clock domain is
`null`. No Timeline, conditioning transform, baseline, Engine, or World step
runs.

Only after commit may the writer publish the new Projection watermark to the
delivery task. Notification delivery is not part of durability and cannot
authorize a query result.

## Canonical query and live subset

The Demo HTTP surface is exactly:

| Method and route | Request | Response contract |
| --- | --- | --- |
| `GET /api/topology` | no query properties or body | imported `$defs.TopologyOk` |
| `GET /api/signals` | imported exact Signal query | imported `$defs.SignalsOk`, `$defs.EmptyEnvelope`, or applicable `$defs.ErrorEnvelope` |
| `GET /api/live` | WebSocket upgrade only; no query properties or body | imported `$defs.LiveEnvelope` text messages |

Every other `/api/*` route is absent. `GET /api/live` without a valid WebSocket
upgrade returns HTTP 426 with a zero-length body and does not start long
polling, server-sent events, or an ordinary JSON response. The imported error
mapping applies only when an API error body is produced. The Demo emits only the imported
`projection_watermark` live payload; the other imported payload variants are
not produced.

The imported API/UI JSON scalar rules, strict query grammar, DTO ordering,
dynamic axes, signal metrics, error mapping, and message validation apply. The
selection, axis, aggregation, and phase-null rules below are the
first-applicable Demo qualifications of the imported signal contract. For
imported receipts, `session_id` names a Capture Session and the persisted
`decoder_version`, `conditioning_version`, and `algorithm_version` are identity
fields only; their presence does not claim that deferred semantic processing
ran.

Each HTTP response uses one read-only connection and exactly one
`BEGIN DEFERRED` transaction. Body data and its receipt MUST be derived inside
that same SQLite snapshot before the transaction ends. Topology comes from the
stored topology manifest plus Capture Sessions with non-NULL commit bindings
and Profile membership found in committed `csi_observations`. Signals select
only committed `csi_observations` rows at or below the selected Capture
Session's cursor whose Sensor and Link match the request and whose
`session_time_ns` is in the half-open interval `[from, to)`. The optional
Profile and path selectors filter that result without changing row identity.
An empty interval or no matching row yields the imported `EmptyEnvelope`.
Current TOML and process memory never supply Store or signal facts; validated
`RuntimeConfig.view.max_signal_points` and `max_time_buckets` provide only
request-admission and response-shaping bounds.

Each signals tile is keyed by its imported `(StreamInstanceId, profile)` pair,
so a Capture Session produces a separate tile for each committed device epoch.
The tile's `stream.key.sensor`, `stream.key.link`, `stream.key.profile`, and
`profile` values come from the selected `csi_observations` rows. Its
`stream.device_epoch.device_id` and `stream.device_epoch.boot_generation` come
from the `packet_records` row joined on `(session_id, record_seq)` in the same
snapshot. Tiles are strictly ordered by Sensor-ID UTF-8 bytes, Link-ID UTF-8
bytes, Profile-ID bytes, numeric device ID, and numeric boot generation. Because
Timeline missing-span derivation is deferred, every Demo
`SignalTile.missing_spans` value is exactly the empty array.

The raw point count is the checked sum across returned tiles of selected
observation positions times returned path positions times sample-coordinate
positions. Invalid sample positions count toward this budget. When the count is
at most `RuntimeConfig.view.max_signal_points`, `i`, `q`, `amplitude`, and
`phase` use `aggregation = "raw"`. Within each tile, observations are ordered
by numeric `(session_time_ns, record_seq)`. Its `time_axis` contains one
canonical-decimal `session_time_ns` for every observation in that order; equal
times remain as separate adjacent positions, and axis position `k` is sourced
only from observation `k`. Cells use the imported `time_path_coordinate`
flattening order.

If the raw point count exceeds the configured limit, a `phase` request returns
the imported `phase_over_budget` error. The other metrics use
`aggregation = "min_max_mean_rms_count"`. Let `B` be the request's positive
`max_time_buckets`, already bounded by the validated RuntimeConfig, and let
`D = to - from`. A nonempty selected result implies `D > 0`. The bucket width
is `w = ceil(D / B)` nanoseconds. The tile `time_axis` is the sequence
`from + k * w` for consecutive `k` starting at zero while that value is less
than `to`, so it has at most `B` positions. The position whose start is `s`
covers exactly `[s, s + min(w, to - s))`; its axis value is `s`, including for
an empty bucket. Implementations MUST use checked integer arithmetic and an
overflow-free ceiling division.

For a valid Demo I/Q pair, let `i` and `q` be the exact signed sample integers
converted to finite real values. The Profile scale is exactly `1/1`, so the
four raw metric values are `i`, `q`, `hypot(i, q)` for `amplitude`, and
`atan2(q, i)` radians for `phase`. Phase uses the principal range `(-pi, pi]`.
A valid pair with `i = q = 0` has measured amplitude zero but no direction, so
its phase cell is `null`. Every cell for a sample whose retained `valid` flag is
false is `null`; its retained integer values MUST NOT enter a signal result.
For `phase` only, the zero-vector `null` is the sole Demo-specific qualification
of the imported rule that otherwise reserves a `null` cell for missing data. It
does not reclassify measured zero amplitude, `i`, or `q` as missing. For each
aggregated `i`, `q`, or `amplitude` path/sample coordinate and time bucket,
observations whose `session_time_ns` lies in that bucket are visited in numeric
`(session_time_ns, record_seq)` order. Invalid samples are excluded; `count` is
exactly the checked `u32` number of included valid samples; `minimum` and
`maximum` cover those values; `mean` is their ordered sum divided by `count`;
and `rms` is the square root of their ordered sum of squares divided by `count`.
A coordinate/time bucket with no included valid sample is `null`. Any checked
count or finite-number construction failure returns the imported
`projection_failed` error with no partial body.

`StoreViewReceipt.projection_commit` and
`ViewReceipt.projection_commit` use the `store_state` Store ID and watermark
read in that same snapshot. The signals receipt range is zero through the
selected Capture Session cursor; a Capture Session with no committed packet is
not visible and cannot yield a fabricated receipt. A signal tile and its
enclosing body carry byte-equal receipts. A response construction or commit
failure returns no partial body.

Immediately after WebSocket upgrade, the server sends one
`projection_watermark` with the current Store watermark. After each admitted
packet commit, it makes that new watermark eligible for delivery. The
per-client queue is bounded and may coalesce to the newest watermark or
disconnect a slow client; it never blocks UDP receive or the SQLite writer.
Clients treat delivery only as invalidation and obtain state through HTTP.

## Read-only browser behavior

The Demo page is a read-only consumer. It provides explicit dynamic Capture
Session, Sensor, Link, and Profile selection and renders native-coordinate
signal values without implying subcarrier, geometry, presence, pose, or other
semantic meaning. It exposes no state-changing control. Missing cells and
measured zero are visibly distinct.

With an open WebSocket, the page enters `LIVE` only after receiving a watermark
and completing required topology/signals reads whose receipts have the same
Store ID and sequences at least that watermark. A Store-ID change discards all
retained context. From initial load until those conditions hold, the page is in
the visible `POLLING` state and runs the fixed interval below.

When the WebSocket is closed, the page enters the visible `POLLING` state and
starts a fixed 250 millisecond interval. Each tick reads topology and the
currently selected signals resource through ordinary HTTP, validates both
bodies, and replaces mounted data only with complete responses. `POLLING` is a
correct live-update mode but MUST NOT be labelled or styled as `LIVE`. A failed
poll leaves the last complete result visibly stale and retries on the next
tick; it never fabricates samples. On a later WebSocket upgrade, the page
continues polling while it resynchronizes against the handshake watermark and
stops the interval only after returning to `LIVE`.

## Sanitized demo-smoke receipt

An executed `demo-smoke` may produce one local `DemoSmokeReceipt` as a sanitized
operational summary. It is a closed JSON object with exactly:

- `schema_version: 1` and `classification: "demo-smoke"`;
- a lowercase 40-hex Git `host_revision`, plus lowercase-hex64
  `host_executable_sha256`, `firmware_image_sha256`,
  `firmware_build_digest`, and `screenshot_sha256`;
- lowercase-hex64 `store_id`, the Capture Session ID as `session_id`, canonical
  decimal `record_seq`, and canonical decimal `projection_commit_seq`;
- canonical decimal `admitted_packet_count`, `csi_observation_count`, and
  `queue_drop_count`;
- exact `chrome_version`, UTC `started_at`, UTC `finished_at`, and
  `result: "pass"`.

UTC strings are RFC 3339 `Z` instants with at most nanosecond precision and
`started_at <= finished_at`.

The Store ID, Capture Session ID, record sequence, Projection watermark, and
two SQLite counts come from the final signals read snapshot. `record_seq` is
the greatest committed CSI record sequence visible in that snapshot;
`admitted_packet_count` counts that Capture Session's `packet_records`, and
`csi_observation_count` counts its `csi_observations`. `queue_drop_count` is the
capture-to-writer queue's count for the same `serve` run. `chrome_version` is
the exact nonempty value returned by Playwright `browser.version()` for the
launched Chrome instance.

A passing receipt requires nonzero admitted-packet and CSI-observation counts,
`queue_drop_count="0"`, the named committed CSI record and watermark, and an
unchanged Chrome page visibly updating after a fresh physical-board packet.
The receipt MUST contain no raw key, Wi-Fi credential, SSID, private path,
private network address, MAC address, serial port, command line, or raw packet.

`DemoSmokeReceipt` is not a development-E2E claim graph, BrowserTrace,
provisioning receipt, evidence classification, hardware attestation, or proof
of any deferred semantic capability. Its presence does not establish execution;
the actual `demo-smoke` run and retained sanitized artifacts remain necessary.

## Acceptance

Source acceptance requires behavior-focused tests for Store identity and
closed schema, non-creating `serve`, per-serve Capture Sessions, exact candidate
dispositions, replay/capability persistence across Capture Sessions, complete
transaction rollback, monotonic time/cursors/watermarks, dynamic topology and
signals, same-snapshot receipts, WebSocket invalidation, bounded queue behavior,
250 millisecond polling, missing-versus-zero rendering, and loopback/LAN bind
role validation at `serve` admission.

Executed `demo-smoke` acceptance additionally requires a clean firmware image
and Host binary, a real ESP32-S3 packet committed as native-coordinate CSI,
zero queue drops, and a visible update in the same already-open Google Chrome
page. No broader execution classification may be reported.
