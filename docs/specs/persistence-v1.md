# Host persistence v1 specification

Status: accepted target

This specification is the sole normative owner of Whisper v1 host
configuration identity, session encoding, SQLite persistence, recovery,
retention, and faithful replay input behavior. Delivery and execution maturity
are recorded separately in the
[host persistence evidence index](../evidence/host-persistence.md).

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

## Scope

Host persistence v1 retains one admitted encrypted-packet fact log, the
ordered control inputs that affect replay, and rebuildable typed projections.
It defines the configuration split, the session manifest and record contract,
SQLite schema responsibilities, durability and publication order, recovery,
rotation, retention, and faithful replay eligibility.

This specification does not define native-frame bytes, Timeline or estimator
algorithms, HTTP representations, UI behavior, future reinterpretation, or a
public Rust SDK. Those contracts have their own versioned owners.

## Configuration identity

`parse_config` MUST be the only TOML parsing entry point. It MUST validate all
fields against this section, construct immutable contract values, and perform
cross-section checks in one pass.
Raw TOML data-transfer types MUST remain private to the configuration module;
another module MUST NOT define a second configuration root or parser.

The accepted immutable `Config` MUST contain exactly two semantic groups:

- `ReplayConfig` contains deployment, window, conditioning, quality, baseline,
  and registry values that can change typed replay results.
- `RuntimeConfig` contains capture, session, view, server, and performance
  values that control process operation without changing replay results.

The session storage path MUST be `SessionConfig.database_path`, MUST identify
one SQLite file rather than a directory, and MUST NOT accept the former
`directory` name as an alias. Configuration changes are applied by opening a
new session; v1 does not hot-update replay configuration, key epochs, or
routes.

`ReplayConfig` MUST own a strict named-field canonical CBOR encoding and a
SHA-256 digest of those bytes. TOML and CBOR decoding MUST both apply every
ReplayConfig rule below and reject unknown fields, malformed values, contract
violations, and trailing CBOR data. TOML parsing additionally applies the
RuntimeConfig and cross-group rules that cannot appear in ReplayConfig bytes.
A generic configuration/value decoder is forbidden.

The complete `Config` and `RuntimeConfig` MUST NOT have a canonical digest.
Changes limited to bind addresses, database path, retention, presentation, or
resource budgets MUST NOT change the replay digest. A session manifest MUST
embed the canonical `ReplayConfig` map and its digest; it MUST NOT persist TOML
source, `RuntimeConfig`, secret paths as replay inputs, or plaintext keys.

### Configuration grammar and validation

An identifier text is definite UTF-8 of at most `u32::MAX` (`4_294_967_295`)
bytes whose exact bytes contain at least one Unicode scalar outside this
whitespace set: `U+0009..U+000D`, `U+0020`, `U+0085`, `U+00A0`, `U+1680`,
`U+2000..U+200A`, `U+2028`, `U+2029`, `U+202F`, `U+205F`, and `U+3000`. V1 does
not trim, case-fold, or Unicode-normalize identifiers. This grammar and maximum
apply uniformly to deployment, space, sensor, transmitter, link, and session
IDs and to decoder, conditioning, algorithm, and application version text.
TOML validation and canonical CBOR decoding MUST both reject any governed text
whose UTF-8 encoding exceeds this maximum; a CBOR decoder MUST reject such a
declared length before allocation. V1 defines no smaller operational cap.
Equality and ordering use exact UTF-8 bytes.

An IP address in TOML is either four decimal IPv4 octets in `0..=255`, without
leading zeroes except the single digit `0`, or an RFC 4291 IPv6 address. Its
canonical text is IPv4 dotted decimal or RFC 5952 lowercase compressed IPv6.
A socket address is canonical IP text plus a decimal `u16` port without leading
zeroes; IPv6 is enclosed in brackets. A TOML digest is exactly 64 ASCII
hexadecimal digits and a TOML MAC address is exactly six two-digit ASCII
hexadecimal octets separated by `:`. Hexadecimal input is case-insensitive;
canonical CBOR stores the decoded 32 or 6 bytes, never the source spelling. A
MAC address of six zero bytes is invalid.

The TOML root contains exactly one each of `deployment`, `capture`, `session`,
`window`, `conditioning`, `quality`, `baseline`, `view`, `server`, and
`performance`, plus nonempty `spaces`, `transmitters`, `sensors`, `links`, and
`routes` arrays. Missing or unknown fields and unknown root tables are invalid.
Runtime-only values obey these rules:

| Group | Normative validation |
| --- | --- |
| capture | `bind` is a socket address; `max_datagram_bytes` is `1..=65535`; `socket_buffer_bytes:u32` is at least that maximum; `secret_root` is UTF-8 path text containing a non-`White_Space` scalar. |
| session | `database_path` is non-whitespace UTF-8 path text naming one SQLite file; `max_manifest_bytes`, `max_record_bytes`, `max_session_duration_ns`, and `max_session_bytes` are nonzero `u64`; each manifest/record limit is at most `max_session_bytes`; `retention_max_sessions` is nonzero `u32`. |
| view | `recent_range_ns:u64`, `max_time_buckets:u32`, and `max_signal_points:u64` are nonzero. |
| server | `bind` is a socket address; `recent_range_ns:u64`, `command_queue_capacity:u32`, and `websocket_queue_capacity:u32` are nonzero. |
| performance | `max_rss_bytes:u64`, `max_cpu_threads:u32`, and `snapshot_deadline_ns:u64` are nonzero, and `snapshot_deadline_ns <= floor(window.step_ns / 2)`. |

The cross-group datagram rule is
`route.maximum_valid_datagram_bytes <= capture.max_datagram_bytes`. Runtime
paths, bind addresses, retention, and view/server/performance values MUST NOT
enter ReplayConfig bytes. V1 has no flush-policy field or compatibility alias;
durability and publication are defined only by the transactions and SQLite
settings below.

### ReplayConfig CBOR

The canonical ReplayConfig is encoded from the accepted contract value, not
from TOML text, TOML table order, or private parser DTOs. It is one map using
the [session CBOR profile](#session-cbor-profile) with these exact keys:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `schema` | unsigned integer, exactly `1` |
| 2 | `deployment` | deployment map |
| 3 | `window` | window map |
| 4 | `conditioning` | conditioning map |
| 5 | `quality` | quality map |
| 6 | `baseline` | baseline map |
| 7 | `spaces` | array of space maps |
| 8 | `transmitters` | array of transmitter maps |
| 9 | `sensors` | array of sensor maps |
| 10 | `links` | array of link maps |
| 11 | `routes` | array of route maps |

The deployment map has only `id` (deployment identifier text). The following
maps use exactly the listed key order and values:

| Map | Exact ordered keys and CBOR values |
| --- | --- |
| window | `width_ns: nonzero u64`, `step_ns: nonzero u64`, `allowed_lateness_ns: u64`, `inactive_after_ns: nonzero u64`, `reorder_horizon: u32` |
| conditioning | `version: version text`, `recipe: "log1p-hypot"`, `scale_numerator: nonzero u32`, `scale_denominator: nonzero u32` |
| quality | `minimum_frames: nonzero u32`, `minimum_coordinate_coverage: float`, `maximum_gap_ratio: float`, `maximum_receive_jitter_ns: u64`, `minimum_time_quality: "receive_only" \| "clock_corrected"` |
| baseline | `minimum_learning_windows: nonzero u32`, `minimum_valid_exposure_ns: nonzero u64`, `minimum_samples_per_coordinate: u32`, `minimum_exposure_per_coordinate_ns: nonzero u64`, `minimum_ready_coordinate_coverage: float`, `variance_floor: float`, `ew_time_constant_ns: nonzero u64`, `deviation_quantile: float`, `rf_dynamics_quantile: float`, `adaptation_gate: float`, `stable_threshold: float`, `changing_threshold: float`, `stale_after_ns: nonzero u64` |

Conditioning scale numerator and denominator MUST be reduced to lowest terms.
`step_ns >= width_ns`. Both quality fractions and
`minimum_ready_coordinate_coverage` are finite binary64 values in `[0, 1]`.
`minimum_samples_per_coordinate >= 2`; `variance_floor` is finite and greater
than zero; both quantiles are finite and in `(0, 1]`; `stable_threshold` and
`changing_threshold` are finite with
`0 <= stable_threshold < changing_threshold`; and `adaptation_gate` is finite
with `0 <= adaptation_gate <= stable_threshold`. The remaining values use the
nonzero or full-width range stated in the table.

Each space and transmitter map has only `id` (its identifier text). A sensor
map has these exact ordered keys:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `id` | sensor identifier text |
| 2 | `hardware_kind` | text, exactly `esp32-s3` in v1 |
| 3 | `device_id` | unsigned `u64` |
| 4 | `key_epoch` | nonzero unsigned `u16` |
| 5 | `expected_peer_ip` | canonical IP-address text, without a port |
| 6 | `firmware_build_digest` | 32-byte byte string |
| 7 | `capability_digest` | 32-byte byte string |
| 8 | `maximum_raw_csi_bytes` | nonzero unsigned `u16` |
| 9 | `maximum_plaintext_bytes` | nonzero unsigned `u16` |

A link map has ordered keys `id`, `space`, `transmitter`, and `receiver`
(identifier text); `expected_transmitter_mac` (a nonzero six-byte byte string); and
`channel_policy`. The channel-policy map has `allowed` (a nonempty strictly
increasing array of unique unsigned `u8` channels in `1..=14`) and `expected`
(an unsigned `u8` member of `allowed`, or `null`).

A route map has these exact ordered keys:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `peer` | canonical IP-address text, without a port |
| 2 | `device_id` | unsigned `u64` |
| 3 | `key_epoch` | nonzero unsigned `u16` |
| 4 | `link` | link identifier text |
| 5 | `peak_packets_per_second` | nonzero unsigned `u32` |
| 6 | `maximum_valid_datagram_bytes` | nonzero unsigned `u16` |
| 7 | `maximum_authenticated_bytes_per_second` | nonzero unsigned `u64` |
| 8 | `replay_window_packets` | nonzero unsigned `u16` |

For one route, `peak_packets_per_second` is the maximum number of authenticated
and otherwise admitted packets permitted in every half-open receive-monotonic
interval of exactly `1_000_000_000` nanoseconds. Rate admission MUST occur
before the raw transaction. A packet exceeding this bound MUST be classified
and rejected and MUST NOT become a raw or semantic fact.

IPv4 and IPv6 use the canonical text grammar above.
The registry arrays are nonempty and strictly sorted by ID UTF-8 bytes for
spaces, transmitters, sensors, and links. Routes are strictly sorted by the
tuple `(address-family rank, network-order address bytes, device_id, key_epoch,
link ID UTF-8 bytes)`, where IPv4 ranks before IPv6. Space, transmitter,
sensor, link, device, and route `(peer, device_id, key_epoch)` identities are
unique.

Every link references an existing space, transmitter, and receiver sensor.
Every route references an existing link; that link's receiver sensor has the
same peer, device ID, and key epoch as the route. A sensor's device ID is unique
and its key epoch is nonzero. V1 sensor hardware is exactly `esp32-s3`;
`maximum_raw_csi_bytes` is exactly `612` and `maximum_plaintext_bytes` is
exactly `705`, as owned by the
[native-frame capability descriptor](native-frame-v1.md#capability-descriptor).
Each route budget is nonzero, its replay window is `1..=65535`, and
`maximum_valid_datagram_bytes >= 753`, where the
48-byte overhead is fixed by the
[native-frame datagram envelope](native-frame-v1.md#datagram-envelope).
Consequently, semantically equal accepted configurations have identical
canonical bytes regardless of TOML declaration order or textual spelling of IP
addresses, digests, or MACs.

## Authoritative packet and record facts

Only a complete encrypted UDP datagram that passes size, route, key,
authentication, replay, and configured admission budgets can become a raw
packet fact. Unknown peers or versions, missing keys, authentication failures,
replays, and admission-budget failures MUST update bounded health state only;
they MUST NOT create a session record.

After authentication and durable replay admission, the raw packet fact MUST
retain the exact encrypted bytes and receive context. Cleartext bodies and
typed observations are rebuildable derivatives and MUST NOT become a second
authoritative log.

Packet and control records share one session-local total order. Each record has
a `record_seq:u64`, monotonic `SessionTime`, and exactly one kind:

- packet body: receive UTC, peer, wire format, and exact encrypted bytes;
- targeted baseline command;
- timeline advance; or
- closed.

The persisted record body MUST encode only the kind-specific body. The
`record_seq`, session time, and kind stored in the row envelope MUST NOT also
be encoded inside `body_cbor`. A reader MUST require sequence zero first,
strictly increasing unique sequence values without gaps, nondecreasing session
time, a known strict body schema, bounded lengths, and no trailing CBOR data.
Nothing may follow a `Closed` record.

## Session CBOR profile

Manifest, record-body, complete-baseline, and baseline-snapshot values use the
Whisper v1 deterministic CBOR profile below. This profile, not a Rust enum or
serializer's defaults, defines the persisted bytes.

- Each document contains exactly one CBOR item and no trailing bytes.
- Arrays, maps, text strings, and byte strings use definite lengths.
- Every map key is the exact lowercase ASCII text shown in the tables below.
  Encoders emit keys in table order. Decoders reject non-text, unknown,
  missing, or duplicate keys. A persisted value is canonical only when it is
  byte-identical to re-encoding its accepted value in that order.
- Unsigned values use CBOR major type 0 and signed negative values use major
  type 1, each with the shortest additional-information width. Unsigned values
  MUST remain within the width named by the field.
- Statistical values use the shortest IEEE-754 half, single, or double CBOR
  float that preserves the exact binary64 value. They MUST remain floats, even
  when numerically integral. NaN, infinity, and negative variance are invalid.
- Booleans use CBOR `false` or `true`; optional scalar values use CBOR `null`
  when absent. Tags, indefinite items, and other simple values are invalid.
- Text is definite UTF-8. Identifier and version fields use the exact
  [configuration text grammar](#configuration-grammar-and-validation). A
  digest, baseline contract ID, or opaque profile ID is a definite 32-byte byte
  string, never hexadecimal text.
- `SessionTime` and exposure/duration values are unsigned integer nanoseconds.
  UTC values are signed integer nanoseconds. Socket peers use canonical text:
  IPv4 dotted decimal or RFC 5952 lowercase compressed IPv6 in brackets,
  followed by a decimal port without leading zeroes.

The encoded manifest length MUST be checked against `max_manifest_bytes`
before allocation. Every record body and other non-manifest CBOR blob MUST be
checked against `max_record_bytes` before allocation. A decoder MUST reject a
declared text, byte-string, array, or map length greater than the remaining
enclosing blob bytes before allocating. The exact collection cardinality rules
below are then applied to the decoded value.

## Session manifest

`sessions.manifest_cbor` is one map with these exact keys and values:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `schema` | unsigned integer, exactly `1` |
| 2 | `session_id` | session identifier text |
| 3 | `started_utc_ns` | signed `i64` integer nanoseconds |
| 4 | `replay_config` | the exact canonical ReplayConfig v1 map defined above, embedded as a map rather than a byte string |
| 5 | `config_digest` | 32-byte SHA-256 of the canonical `replay_config` bytes |
| 6 | `application_version` | version text |
| 7 | `build_fingerprint` | 32-byte SHA-256 of the complete deployed executable file bytes |
| 8 | `decoder_version` | version text |
| 9 | `wire_admission` | array of wire-admission-pin maps |
| 10 | `conditioning_version` | version text |
| 11 | `algorithm_version` | version text |
| 12 | `initial_baseline_states` | array of complete-baseline-state maps |

`config_digest` MUST equal SHA-256 of the canonical bytes obtained by encoding
the embedded ReplayConfig map as a standalone CBOR item. Manifest
`conditioning_version` MUST equal ReplayConfig `conditioning.version`.
Decoder and algorithm versions are independent version-text pins and faithful
replay requires exact equality with the selected decoder and algorithm.
`wire_admission`
is ordered by the matching ReplayConfig route order and contains exactly one
unique entry for every route `(device_id, key_epoch)`; every entry's device,
epoch, firmware digest, capability digest, plaintext maximum, and datagram
budget MUST equal that route and its receiver sensor. These pins use the
[native-frame capability](native-frame-v1.md#capability-identity) and
[datagram envelope](native-frame-v1.md#datagram-envelope) contracts.
Each wire-admission-pin map has exactly these keys:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `wire_version` | unsigned `u8`, exactly `1` |
| 2 | `device_id` | unsigned `u64` |
| 3 | `key_epoch` | nonzero unsigned `u16` |
| 4 | `firmware_build_digest` | 32-byte byte string |
| 5 | `capability_digest` | 32-byte byte string |
| 6 | `maximum_plaintext_bytes` | nonzero unsigned `u16` |
| 7 | `transport_datagram_budget_bytes` | nonzero unsigned `u16`, at least `maximum_plaintext_bytes + 48` |

For v1 every pin therefore has `maximum_plaintext_bytes=705` and
`transport_datagram_budget_bytes >= 753`.

Plaintext keys remain in the independent secret store. Manifest CBOR MUST NOT
contain TOML source, `RuntimeConfig`, secret paths as replay inputs, plaintext
keys, or candidate/artifact placeholders.

### Complete baseline state

`initial_baseline_states` is sorted strictly by link-ID UTF-8 bytes and then
the 32 profile-ID bytes. Duplicate keys are invalid. Absence of an entry means
Missing. The same map below is stored unchanged in
`baseline_states.estimator_state_cbor`; there is no session-specific DTO.

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `link` | link identifier text present in ReplayConfig |
| 2 | `profile` | 32-byte profile ID |
| 3 | `lifecycle` | lifecycle map below |
| 4 | `learning` | strictly ordered array of Welford-coordinate maps |
| 5 | `active` | strictly ordered array of EW-coordinate maps |
| 6 | `revision` | unsigned `u64`, or `null` |
| 7 | `state_sequence` | unsigned `u64`, or `null` |
| 8 | `adaptation_armed` | boolean |
| 9 | `session_last_eligible_at` | unsigned `u64` session nanoseconds, or `null` |
| 10 | `compatibility` | compatibility map below |

The lifecycle map is one of:

| Lifecycle | Exact map keys and values |
| --- | --- |
| Learning | `kind: "learning"`, `accepted_windows: u64`, `accepted_exposure_ns: u64` |
| Active | `kind: "active"` |
| Frozen | `kind: "frozen"` |
| Stale | `kind: "stale"`, `reason: "age" | "incompatible"` |

The fields in each row appear in the order shown. Learning has an empty Active
array, null revision/state sequence, and `adaptation_armed=false`. Its Learning
array is empty if and only if both accepted counters are zero; otherwise both
counters are nonzero, the array is nonempty, and every coordinate exposure is
at most lifecycle `accepted_exposure_ns`. Active, Frozen, and Stale have an
empty Learning array, a nonempty Active array, and nonzero revision/state
sequence. Frozen and Stale also require `adaptation_armed=false`; Active may
encode either boolean. For an initial manifest seed, every lifecycle requires
`adaptation_armed=false` and `session_last_eligible_at=null`, as required by the
[temporal baseline session-boundary rule](temporal-world-v1.md#active-prediction-and-update).

A Welford-coordinate map has ordered keys `path`, `coordinate`, `count`,
`mean`, `m2`, and `accepted_exposure_ns`. `count` and exposure are nonzero
`u64`; `mean` and `m2` are finite floats and `m2 >= 0`.

An EW-coordinate map has ordered keys `path`, `coordinate`, `count`, `mean`,
`variance`, and `accepted_exposure_ns`. `count` is a `u64` of at least two,
exposure is nonzero, and mean/variance are finite with `variance >= 0`.

The two coordinate arrays are strictly sorted and unique by the following
language-neutral order:

1. path rank: `tx_rx` before `raw_path_ordinal`;
2. within `tx_rx`, unsigned `tx_stream` then unsigned `rx_chain`; within
   `raw_path_ordinal`, unsigned `ordinal`;
3. coordinate rank: `opaque_sample_ordinal`, then `ieee_tone_index`, then
   `frequency_hz`; and
4. the variant's numeric value, using signed order only for tone index.

A path is either the ordered map `kind: "tx_rx", tx_stream: u16,
rx_chain: u16` or `kind: "raw_path_ordinal", ordinal: u16`. A sample
coordinate is either `kind: "opaque_sample_ordinal", value: u16`, `kind:
"ieee_tone_index", value: i16`, or `kind: "frequency_hz", value: u64`.

The compatibility map has ordered keys `deployment` (identifier text), `space`
(identifier text), `conditioning_version` (version text), and `contract`
(32-byte baseline-contract ID). Its deployment and conditioning version MUST
equal ReplayConfig; its space MUST equal the target link's ReplayConfig space.
The profile ID and coordinate identities are opaque persistence values, but
semantic use requires exact link/profile isolation under the
[temporal baseline state-key contract](temporal-world-v1.md#state-key-and-lifecycle)
and a profile admitted by the
[native-frame CSI contract](native-frame-v1.md#csi-data-body). Persistence
validates byte width and equality and MUST NOT guess a profile from coordinate
count or layout.

## Record-body CBOR

The SQLite row is the record envelope. `session_records.record_seq` owns total
order, `session_time` owns `SessionTime`, and `kind` owns the variant tag.
`body_cbor` contains only the kind-specific CBOR item below. It MUST NOT contain
`schema`, `record_seq`, `at`/`session_time`, `kind`, or an outer `body` key.
Schema version comes from SQLite `user_version=1` and the strict kind-body
contract.

| Row `kind` | Exact `body_cbor` item |
| --- | --- |
| `packet` | packet map |
| `baseline_command` | targeted-command map |
| `timeline_advance` | CBOR `null`, exactly byte `f6` |
| `closed` | CBOR `null`, exactly byte `f6` |

The packet map has ordered keys:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `receive_utc_ns` | signed `i64` integer nanoseconds |
| 2 | `peer` | canonical socket-address text |
| 3 | `wire_format` | text, exactly `native_frame_udp` |
| 4 | `bytes` | exact complete authenticated encrypted datagram as a byte string |

The packet peer IP, header device ID/key epoch, firmware/capability identity,
plaintext length, and complete datagram length MUST match one ReplayConfig
route and manifest pin. Header/body bytes, authentication, and rejection MUST
conform exactly to the
[native-frame datagram envelope](native-frame-v1.md#datagram-envelope),
[capability identity](native-frame-v1.md#capability-identity), and
[reject behavior](native-frame-v1.md#replay-interaction-and-reject-behavior).
The peer port and exact encrypted datagram bytes are retained unchanged.

The targeted-command map has ordered keys `link` (a ReplayConfig link identifier),
`profile` (32-byte profile ID), and `command` (one of `begin_learning`,
`commit`, `freeze`, `resume`, or `activate_snapshot`). Only
`activate_snapshot` adds the fourth key `snapshot`, whose value is the complete
immutable baseline-snapshot map below. Other command tags with `snapshot`, or
`activate_snapshot` without it, are invalid.

| Order | Snapshot key | CBOR value |
| ---: | --- | --- |
| 1 | `deployment` | deployment identifier text equal to ReplayConfig |
| 2 | `space` | space identifier text equal to the target link's ReplayConfig space |
| 3 | `link` | link identifier text equal to the command target |
| 4 | `profile` | 32-byte profile ID, equal to the command target |
| 5 | `conditioning_version` | version text equal to ReplayConfig conditioning version |
| 6 | `revision` | nonzero unsigned `u64` |
| 7 | `contract` | 32-byte baseline-contract ID |
| 8 | `coordinates` | nonempty, strictly ordered array of snapshot-coordinate maps |

A snapshot-coordinate map has ordered keys `path`, `coordinate`, `count`,
`mean`, `variance`, and `accepted_exposure_ns`. It uses the exact path,
coordinate, float, count, exposure, ordering, and uniqueness rules of the
EW-coordinate array. The array is nonempty; revision is nonzero; target link
and profile equal the command; and deployment, space, and conditioning version
match ReplayConfig as stated in the table. The contract ID is any 32-byte value
and is interpreted under the
[temporal baseline contract](temporal-world-v1.md#statistical-baseline-estimator).

Readers reconstruct one `SessionRecord` contract value from the relational envelope
and decoded body, then verify sequence starts at zero, increases by exactly
one without duplicates, session time never decreases, and no row follows
`closed`. A mismatch or non-canonical body is corruption, not a value to
cross-check and continue.

## Session fact bytes

`max_session_bytes` limits a logical, storage-engine-independent quantity. For
one session, its exact value is:

```text
len(manifest_cbor)
+ sum(8 record_seq + 8 session_time + len(kind UTF-8 bytes) + len(body_cbor))
```

The sum includes every authoritative record and excludes the repeated session
ID, the stored counter, admission state, derived rows, indexes, SQLite pages,
WAL and checkpoint bytes, free pages, and rolled-back writes. Physical database
or filesystem size MUST NOT be substituted. This decision and tradeoff are
recorded in
[ADR 0005](../adr/0005-logical-session-fact-bytes.md).

`sessions.fact_bytes` is the derived counter for this quantity. It is an
unsigned `u64` encoded as eight big-endian bytes. Session creation sets it to
`len(manifest_cbor)`, and every record-inserting transaction A atomically adds
that record's logical cost. A rollback leaves it unchanged.

Operational open and recovery MUST recompute the value from the manifest and
all ordered record envelopes and bodies. A mismatch enters the derived-state
rebuild path; only the final derived-state rebuild transaction may replace the
counter after validating the complete authoritative fact log. No open-time
counter-only repair is permitted.

The exact logical cost of `Closed` is `8 + 8 + 6 + 1 = 23` bytes. Starting a
session requires `len(manifest_cbor) + 23 <= max_session_bytes`; otherwise
session creation fails with a fatal session-limit error. Before inserting any
non-`Closed` candidate record with logical cost `candidate_bytes`:

1. If `fact_bytes + candidate_bytes + 23 > max_session_bytes`, rotation MUST
   complete before mutating admission, facts, Engine, or projections for the
   candidate. The candidate is then evaluated against the fresh session; if it
   still cannot fit with the reserved `Closed`, capture fails with the fatal
   session-limit error.
2. If `fact_bytes + candidate_bytes + 23 = max_session_bytes`, transaction A
   commits the candidate and its counter update, then capture MUST immediately
   rotate before accepting another input.
3. If the sum is smaller, capture may continue in the current session.

## SQLite schema version 1

Embedded SQLite MUST be the sole authoritative host persistence system. One
database holds raw records and rebuildable projections; no authoritative
session file, decoded-frame log, external database, ORM, provider/repository
trait, connection pool, or generic migration/checkpoint framework may coexist
with it.

The following DDL is normative. Initialization executes it atomically for a
new database and sets `user_version=1`; v1 has no alternate table/column names
or migration path.

```sql
BEGIN IMMEDIATE;

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

CREATE TABLE sessions (
    session_id TEXT NOT NULL,
    started_utc_ns INTEGER NOT NULL,
    manifest_cbor BLOB NOT NULL,
    fact_bytes BLOB NOT NULL CHECK(length(fact_bytes) = 8),
    lifecycle TEXT NOT NULL
        CHECK(lifecycle IN ('active', 'sealed', 'recovery_sealed')),
    sealed_utc_ns INTEGER,
    PRIMARY KEY (session_id),
    CHECK((lifecycle = 'active') = (sealed_utc_ns IS NULL))
) WITHOUT ROWID;

CREATE UNIQUE INDEX one_active_session
    ON sessions(lifecycle) WHERE lifecycle = 'active';
CREATE INDEX sessions_retention
    ON sessions(lifecycle, started_utc_ns, session_id);

CREATE TABLE session_records (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time BLOB NOT NULL CHECK(length(session_time) = 8),
    kind TEXT NOT NULL
        CHECK(kind IN ('packet', 'baseline_command',
                       'timeline_advance', 'closed')),
    body_cbor BLOB NOT NULL,
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX session_records_time
    ON session_records(session_id, session_time, record_seq);

CREATE TABLE session_processing_state (
    session_id TEXT NOT NULL,
    processed_through_record_seq BLOB
        CHECK(processed_through_record_seq IS NULL
              OR length(processed_through_record_seq) = 8),
    timeline_state_cbor BLOB,
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (session_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE,
    FOREIGN KEY (session_id, processed_through_record_seq)
        REFERENCES session_records(session_id, record_seq)
) WITHOUT ROWID;

CREATE INDEX processing_by_cursor
    ON session_processing_state(processed_through_record_seq, session_id);

CREATE TABLE csi_observations (
    session_id TEXT NOT NULL,
    record_seq BLOB NOT NULL CHECK(length(record_seq) = 8),
    session_time BLOB NOT NULL CHECK(length(session_time) = 8),
    sensor_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    observation_cbor BLOB NOT NULL,
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    PRIMARY KEY (session_id, record_seq),
    FOREIGN KEY (session_id, record_seq)
        REFERENCES session_records(session_id, record_seq)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX csi_by_link_time
    ON csi_observations(link_id, profile_id, session_time, record_seq);
CREATE INDEX csi_by_sensor_time
    ON csi_observations(sensor_id, session_time, record_seq);

CREATE TABLE world_snapshots (
    session_id TEXT NOT NULL,
    snapshot_id BLOB NOT NULL CHECK(length(snapshot_id) = 8),
    interval_start BLOB NOT NULL CHECK(length(interval_start) = 8),
    interval_end BLOB NOT NULL CHECK(length(interval_end) = 8),
    snapshot_cbor BLOB NOT NULL,
    source_record_start BLOB NOT NULL CHECK(length(source_record_start) = 8),
    source_record_end BLOB NOT NULL CHECK(length(source_record_end) = 8),
    algorithm_version TEXT NOT NULL,
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    PRIMARY KEY (session_id, snapshot_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX snapshots_by_interval
    ON world_snapshots(interval_start, interval_end, snapshot_id);

CREATE TABLE snapshot_link_evidence (
    session_id TEXT NOT NULL,
    snapshot_id BLOB NOT NULL CHECK(length(snapshot_id) = 8),
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    evidence_cbor BLOB NOT NULL,
    source_record_start BLOB NOT NULL CHECK(length(source_record_start) = 8),
    source_record_end BLOB NOT NULL CHECK(length(source_record_end) = 8),
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (session_id, snapshot_id, link_id, profile_id),
    FOREIGN KEY (session_id, snapshot_id)
        REFERENCES world_snapshots(session_id, snapshot_id)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX evidence_by_link
    ON snapshot_link_evidence(link_id, profile_id, session_id, snapshot_id);

CREATE TABLE baseline_states (
    deployment_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
    estimator_state_cbor BLOB NOT NULL,
    source_session_id TEXT NOT NULL,
    source_record_seq BLOB
        CHECK(source_record_seq IS NULL OR length(source_record_seq) = 8),
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (deployment_id, link_id, profile_id),
    FOREIGN KEY (source_session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (source_session_id, source_record_seq)
        REFERENCES session_records(session_id, record_seq)
) WITHOUT ROWID;

CREATE INDEX baseline_by_source
    ON baseline_states(source_session_id, source_record_seq);

PRAGMA user_version = 1;
COMMIT;
```

### Replay-window identity

The replay-window identity is exactly the 32-byte SHA-256 digest of this
unambiguous preimage, concatenated in the listed order:

1. the ASCII bytes `whisper.replay-window.identity`;
2. one byte with value `0x00`;
3. `preimage_version`, one unsigned byte with value `1`;
4. `wire_version`, one unsigned byte with value `1`;
5. the length of the exact deployment-ID UTF-8 bytes as unsigned `u32`
   big-endian;
6. those exact deployment-ID UTF-8 bytes;
7. `device_id` as unsigned `u64` big-endian;
8. `key_epoch` as unsigned `u16` big-endian; and
9. the exact 32-byte epoch key.

The preimage and epoch key MUST NOT be persisted or logged; only the digest is
stored. The replay-window size is deliberately excluded from the digest and is
stored and compared separately. Peer address, link identity, packet and byte
rate budgets, datagram budgets, firmware and capability identity, and any
global ReplayConfig digest are also deliberately excluded. The rationale and
tradeoff are recorded in
[ADR 0006](../adr/0006-bind-replay-admission-to-epoch-key.md).

Provisioning MUST read the epoch key from the secret store, derive the identity,
and store it with the configured window size. A retry is idempotent only when
the stored identity and size match exactly and the admission row remains empty.
A mismatch or an advanced row MUST fail closed and MUST NOT reset admission.

Capture open MUST read the configured epoch keys, rederive every configured
epoch identity, and compare both identity and window size with the stored rows.
It MUST reject a missing, mismatched, corrupt, or advanced conflicting epoch
rather than creating or resetting one. Transaction A accepts only a private
validated `EpochHandle` produced by this comparison; no caller may supply raw
identity or window-size values to admission mutation.

### Replay admission window

`replay_window_size` is the matching route's `replay_window_packets` value
`W` in `1..=65535`. `seen_bitmap` is exactly `ceil(W / 8)` bytes. Age `a`,
where zero is the stored maximum message sequence, is bit
`1 << (a mod 8)` in byte `floor(a / 8)`. Unused high bits in the final byte are
zero. A fresh row has NULL boot generation, NULL maximum sequence, and an
all-zero bitmap.

An admitted native-frame boot generation is a nonzero `u32` and message
sequence is a nonzero `u64`, as defined by the
[native-frame datagram envelope](native-frame-v1.md#datagram-envelope). Given a
row whose identity and size have already matched, transaction A applies this
exact transition:

1. For a fresh row, store the packet boot and sequence, clear the bitmap, and
   set age zero.
2. A boot greater than the stored boot starts a new generation: store the new
   boot and sequence, clear the bitmap, and set age zero. A lower boot is a
   replay and is rejected without mutation.
3. At the same boot, a sequence greater than the stored maximum advances by
   `delta`. Increase every retained age by `delta`, discard ages `>= W`, store
   the new maximum, and set age zero.
4. At the same boot with `sequence <= maximum`, compute
   `age = maximum - sequence`. Reject without mutation when `age >= W` or its
   bit is already set; otherwise set that bit and leave the stored maximum.

NULL/non-NULL disagreement, wrong integer width, wrong bitmap length, nonzero
padding bits, zero stored boot/sequence, or a bitmap whose age-zero bit is
clear in a nonempty row is corruption and MUST fail closed. Admission-window
mutation and raw-record insertion remain one transaction, so any later insert
failure rolls back this transition.

A fresh `session_processing_state` row has NULL processed cursor and NULL
Timeline state. Stage two advances only the cursor and leaves Timeline state
NULL. Non-NULL Timeline, observation, snapshot, and evidence payloads must
represent the exact semantic values owned by the
[temporal Timeline](temporal-world-v1.md#timeline),
[world state](temporal-world-v1.md#world-state), and
[evidence](temporal-world-v1.md#evidence) contracts. Until those versioned
sections define a language-neutral deterministic CBOR layout for a payload,
that payload has no accepted persisted encoding and its row MUST NOT be
written. A Rust serializer, generic bytes/value interface, or private type
layout MUST NOT define the durable bytes implicitly.

Operational open or recovery of a non-NULL Timeline state MUST reconstruct the
typed facts and dynamic profile catalog from the manifest plus ordered raw
records through the stored processed cursor, rebuild Timeline state through the
same Timeline interface, and require byte-for-byte equality with the stored
state before using it. This replay comparison proves session, decoder, route,
and dynamic-profile receipts. A mismatch MUST enter the applicable deterministic
rebuild path or fail closed under the recovery rules below; the stored state
MUST NOT be trusted, repaired in place, or used before that proof succeeds.

All BLOB integer columns use unsigned fixed-width big-endian bytes: `key_epoch`
is two bytes, `highest_boot_generation` is four, and device IDs, record
sequences, session times, session fact-byte counters, snapshot IDs, interval
bounds, source-record bounds, and message sequences are eight. Equal-width
SQLite BLOB comparison is therefore unsigned numeric order. Writers and
readers MUST reject every other width and MUST NOT narrow, reinterpret as
signed, or cast these values to SQLite INTEGER. UTC nanoseconds remain signed
SQLite INTEGER because their domain is `i64`.

SQLite storage class is part of validation even where affinity or a `CHECK`
does not enforce it: declared BLOB, TEXT, and INTEGER columns MUST contain that
exact storage class. Session and projection text identities use the text
grammar above. `sessions.session_id` and `started_utc_ns` MUST equal the decoded
manifest fields. Processing and projection config/version receipts MUST equal
their manifest; source session/record/time and row key fields MUST equal their
decoded payload receipts. `baseline_states` row deployment/link/profile and
compatibility receipts MUST equal its decoded complete baseline map. Any
disagreement is corruption.

`session_records` are the sole event/packet fact log. Semantic replay authority
is the pair of one manifest and that session's ordered records. Observation,
processing, baseline, snapshot, and evidence rows remain derived state and MUST
be reproducible from that pair without a predecessor session.

The only persistent SQLite store-identity settings are `user_version=1` and
`journal_mode=WAL`. Provisioning MUST establish both. Operational open of an
existing store MUST query and require both before any database or application
state mutation and MUST NOT silently repair either. Every connection MUST then
apply and verify connection-local `foreign_keys=ON`. The writer connection MUST
also apply and verify connection-local `synchronous=FULL`; readers do not
require a synchronous setting.

### Managed database path and lock

All exclusive managed-data operations MUST use one application-owned path
resolver and lock acquirer. For an existing target, it resolves relative paths
and directory symlinks, canonicalizes the full database target, and follows a
final-component symlink. For provisioning, it requires the canonical parent
directory to exist and requires the final component to be absent and not a
symlink; it does not canonicalize a nonexistent final component.

The lock path is in the same canonical directory as the resolved database and
is formed injectively by appending `.whisper.lock` to the complete database
filename. The sidecar may be created or opened, but MUST NOT be truncated or
deleted as part of lock handling. Its existence is not lock authority. The
exclusive OS advisory lock held on the still-open sidecar file descriptor is
the sole lock authority until the operation completes.

Lock conflict, permission failure, canonicalization failure, and any path or
sidecar I/O failure MUST fail closed. Hard-link aliases are unsupported and
MUST NOT be treated as equivalent managed paths; when target metadata exposes
multiple hard links, the resolver MUST reject the target explicitly.

## Initialization and runtime ownership

`whisper init-admission <config> <device-id> <key-epoch>` MUST be the only host
entry point allowed to create schema version 1. Under the managed-database lock,
it MUST provision the persistent SQLite settings and schema and insert an empty
replay admission row whose derived identity and bounded window size exactly
match the configuration. Retry behavior is defined by
[Replay-window identity](#replay-window-identity).

Capture and replay MUST acquire the managed-database lock, open the canonical
database path with a non-create operation, query and reject incompatible
persistent settings, apply and verify their connection-local settings, and then
validate schema and configured epochs, in that order. A missing file, corrupt
SQLite database, wrong schema/version, incompatible setting, or epoch failure
MUST fail closed. Operational open MUST NOT create, reset, repair, or replace
the database or admission state as a side effect.

One sequential ingest owner MUST hold the sole synchronous writer connection.
Synchronous database work MUST run off asynchronous runtime and ingest
execution. Bounded read-only query connections MAY read the same WAL database,
but no connection pool or database actor is introduced. The process MUST hold
the managed-database advisory lock while performing mutually exclusive
managed-data work.

## Durable admission and processing transactions

Before database mutation, capture MUST validate datagram size, fixed header,
exact peer route, exact key lookup, authentication, and per-route packet/byte
budgets.

After authentication, transaction A MUST use `BEGIN IMMEDIATE` to:

1. consume the matching private validated `EpochHandle` and reread its
   provisioned admission epoch;
2. reject replay or atomically advance its bounded boot/message window; and
3. insert the exact encrypted packet record and receive context and atomically
   add its logical cost to `sessions.fact_bytes`.

Only a committed transaction A authorizes cleartext decoding or Engine
advance. Failure MUST roll back both admission and raw insertion, leave Engine
unchanged, and stop capture before publication.

After raw commit, the shared decoder and Engine path may process the record.
Transaction B MUST atomically persist the concrete transition: processing
cursor and state, changed complete baseline states, typed observation when
present, projections, and version/source receipts. Deterministic decode rejects
and control records MUST advance the cursor atomically with their concrete
state effect. The application MUST NOT reconstruct Engine state.

Memory mirrors, query-visible identifiers, and notifications MUST be replaced
or published only after transaction B commits. Transaction B failure MUST
leave the previous committed lifecycle, cursor, state, and projections intact
and stop capture before anything from the failed transition is exposed.

An authenticated unknown kind, malformed or unsupported cleartext body, or
source/radio mismatch remains a durable raw fact and a classified decode
reject; it MUST NOT enter Timeline or estimator processing. Baseline commands
and timeline advances MUST first be inserted in their own ordered transaction
A and committed before their semantic effect runs.

Each admitted packet uses one transaction in the v1 correctness baseline.
Batching or a separate writer task requires measured evidence and a later
contract change. Transaction A and transaction B commits, WAL mode, and writer
`synchronous=FULL` are the complete v1 durability and publication contract.

## Lifecycle, recovery, and rotation

A fresh session is active. Inserting `Closed` makes its raw stream
non-appendable but does not itself seal the lifecycle. Sealed and
recovery-sealed sessions are immutable replay inputs; active or otherwise
non-sealed sessions are not complete replay inputs.

SQLite transaction rollback replaces file-tail scanning and CRC recovery. The
application-owned `HostLifecycle` coordinates recovery; persistence MUST NOT
expose a bare seal or recovery-seal operation.

Under the managed-database lock, recovery of an active session MUST first read
and validate its complete ordered tail. If the last record is not `Closed`, one
transaction A appends `Closed` at the next sequence and the last record's
`SessionTime`; an empty tail uses sequence zero and `SessionTime` zero. That
transaction also updates `fact_bytes`. No record may follow the resulting
`Closed`.

Recovery MUST construct a fresh Engine from the manifest's complete baseline
seed, replay every ordered fact including the exact `Closed` tail, and finish
the Engine. The Engine produces a `FinishedTransition` and a complete
`BaselineState` set that is strictly sorted and unique. Persistence validates
and atomically stores those supplied strong values; it MUST NOT derive,
reconstruct, or fill in semantic baseline values.

The application then constructs a private `FinishedRecovery` proof binding the
manifest identity, exact `Closed` tail, final processing cursor and receipts,
and the `FinishedTransition`. One final transaction B MUST reread and match the
tail, cursor, and receipts, atomically commit the rebuilt derived state and
complete baselines, and change lifecycle to `recovery_sealed`. Any failure MUST
leave the session unsealed and MUST NOT create a successor. A durable `Closed`
alone is insufficient; the next session may be created only after successful
recovery sealing.

Graceful shutdown or rotation MUST first stop new input, drain accepted input,
and commit `Closed` and its fact-byte update as transaction A. The Engine then
finishes and returns the same complete, strictly sorted, unique baseline handoff
with its `FinishedTransition`. Persistence validates and stores the supplied
values only.

For rotation, one final transaction B MUST atomically persist the final cursor,
projections, and baselines, seal the old session, create the successor manifest,
and rebind exactly the same handoff values as that manifest's initial baseline
states and current baseline rows. An empty genesis set means Missing; it MUST
NOT replace a predecessor's nonempty handoff with an empty placeholder.
Graceful shutdown without a successor seals the session and leaves the baseline
source on that predecessor. On the next startup, `HostLifecycle` MUST create the
successor and rebind the exact handoff before retention can delete the
predecessor.

Both `max_session_duration_ns` and `max_session_bytes` are configured nonzero
rotation limits. Reaching the duration limit MUST pause new input and complete
the same close, finish, and final-transaction sequence. Byte-limit behavior is
defined by [Session fact bytes](#session-fact-bytes).

## Retention

`retention_max_sessions` MUST be positive. Retention MUST run in one
transaction and delete only the oldest sealed sessions and their foreign-key
owned records and projections. It MUST NOT delete an active or non-sealed
session, an admission epoch, or the current operational baseline.

Before deleting a predecessor, the complete operational baseline MUST already
be rebound to the current manifest and baseline rows so predecessor deletion
cannot remove resume authority. SQLite MAY reuse free pages. Hot-path `VACUUM`
and a generic garbage-collection framework are forbidden.

## Faithful replay

V1 implements faithful replay only. Replay MUST accept only a sealed or
recovery-sealed session; a non-sealed session MUST complete recovery first.

Replay MUST read one selected session's records in unsigned `record_seq` order
and validate strict record body/schema, nondecreasing session time,
replay-config digest, build fingerprint, wire-admission pins, decoder version,
conditioning version, and algorithm version. The secret store MUST still
provide the exact device/key-epoch keys needed by the session. Any mismatch or
missing key MUST reject faithful replay.

Exact encrypted bytes, peer, record time, and packet/control total order MUST
enter the same decoder, Timeline, conditioning, estimator, and Engine path as
live input. The core receives explicit session time and MUST NOT read wall
clock time, sleep, randomness, delivery mode, processing duration, or current
host identity. Replay MUST produce typed results without HTTP, WebSocket, or
notification side effects.

A later explicit reinterpretation mode MAY process old bytes under a new
contract and output namespace. It MUST NOT claim the original session's
semantic identity and is outside v1.

## Acceptance

Acceptance requires behavior-focused tests and retained execution receipts at
the specified interfaces. At minimum they MUST cover:

- schema, required connection state, version, foreign keys, indexes, fresh
  NULL state, nullable manifest-seeded baseline source, managed-path and lock
  identity, and transaction rollback;
- strict ReplayConfig and complete BaselineState manifest/database roundtrips,
  with a persisted fixture proving exclusion of TOML source, RuntimeConfig,
  secrets, and lossy snapshot-only baseline state;
- length limits before allocation and complete unsigned edge-value roundtrip
  and ordering;
- missing and corrupt databases, wrong persistent settings or schema,
  connection-local setting application, missing epochs, and no create/reset or
  silent-repair side effect from capture open;
- cross-language replay-window identity fixtures covering exact key-bound
  derivation, explicit exclusions, size comparison, and mismatch rejection;
- session fact-byte edge cases, reserved `Closed`, equality rotation,
  fresh-session overflow, rollback, recomputation, and physical-byte
  exclusions;
- duplicate and skipped record sequence, reversed time, and insertion after
  `Closed` or seal;
- transaction A rollback preserving admission and raw state and preventing
  decode/Engine advance;
- recovery and full rebuild before recovery seal or next-session creation;
- operational-open and recovery replay requiring exact Timeline-state byte
  equality through the processed cursor, with mismatch rebuild or fail-closed;
- retention preserving active/non-sealed sessions, admission epochs, and
  current operational baseline state; and
- faithful live/replay equality for bytes, receive context, record order,
  typed results, and deterministic rebuild after deleting projections.

Test source alone is not executed acceptance evidence.
