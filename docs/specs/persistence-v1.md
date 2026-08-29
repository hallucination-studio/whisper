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

The session storage path MUST be `SessionConfig.database_path` and MUST identify
one SQLite file rather than a directory. Its parent MUST be a dedicated trusted
local Managed store root for that database, its SQLite companions, the
cooperative lease, and private provisioning stages. It MUST NOT accept the
former `directory` name as an alias. Configuration changes are applied by
opening a new session; v1 does not hot-update replay configuration, key epochs,
or routes.

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
| session | `database_path` is non-whitespace UTF-8 path text naming one SQLite file whose parent is the dedicated trusted local Managed store root; `max_manifest_bytes`, `max_record_bytes`, `max_session_duration_ns`, and `max_session_bytes` are nonzero `u64`; each manifest/record limit is at most `max_session_bytes`; `retention_max_sessions` is nonzero `u32`. |
| view | `recent_range_ns:u64`, `max_time_buckets:u32`, and `max_signal_points:u64` are nonzero. |
| server | `bind` is a socket address; `recent_range_ns:u64`, `command_queue_capacity:u32`, and `websocket_queue_capacity:u32` are nonzero. |
| performance | `max_rss_bytes:u64`, `max_cpu_threads:u32`, and `snapshot_deadline_ns:u64` are nonzero, and `snapshot_deadline_ns <= floor(window.step_ns / 2)`. |

The cross-group datagram rule is
`route.maximum_valid_datagram_bytes <= capture.max_datagram_bytes`. Runtime
paths, bind addresses, retention, and view/server/performance values MUST NOT
enter ReplayConfig bytes. V1 has no flush-policy field or compatibility alias;
durability and publication are defined only by the transactions and SQLite
settings below.

### Program 1 development secret store

Program 1 fixture tooling MUST materialize the exact temporary key derived by
[native-frame v1](native-frame-v1.md#identities-and-route-phases) only in a
protected temporary secret store selected through the ordinary
`RuntimeConfig.capture.secret_root` boundary. The production Host key loader
MUST consume that material through its normal interface. Configuration MUST NOT
gain a raw-key field, and Host authentication MUST NOT gain a fixture-only
branch.

Missing, malformed, wrong-epoch, unreadable, or non-32-byte key material MUST
fail explicitly. Raw key bytes, secret-store paths, and SQLite database bytes
MUST NOT be committed, logged, displayed, screenshotted, or retained in corpus
manifests or evidence receipts.

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

Manifest, record-body, complete-baseline, baseline-snapshot, and temporal
projection values use the Whisper v1 deterministic CBOR profile below. This
profile, not a Rust enum or serializer's defaults, defines the persisted bytes.

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

## Store topology manifest

`StoreTopologyManifestV1` is the immutable provisioned map stored in
`store_state.topology_manifest_cbor`, with these exact keys and values:

| Order | Key | CBOR value |
| ---: | --- | --- |
| 1 | `schema` | unsigned integer, exactly `1` |
| 2 | `deployment` | deployment identifier text |
| 3 | `spaces` | strictly ordered unique array of space identifier text |
| 4 | `transmitters` | strictly ordered unique array of transmitter identifier text |
| 5 | `sensors` | strictly ordered unique array of topology-sensor maps |
| 6 | `links` | strictly ordered unique array of topology-link maps |

A topology-sensor map has ordered keys `id`, `hardware_kind`, and `device_id`.
`hardware_kind` is exactly `esp32-s3` in Program 1 and `device_id` is unsigned
`u64`. A topology-link map has ordered keys `id`, `space`, `transmitter`, and
`receiver`; its space, transmitter, and receiver references MUST resolve inside
the corresponding manifest arrays. Space, Transmitter, Sensor, and Link arrays
are ordered by ID UTF-8 bytes. The manifest is the exact
query-visible topology subset deterministically derived from ReplayConfig. It
contains no route peer, key epoch, secret, firmware/capability pin, socket,
budget, algorithm, baseline, or other runtime/replay-only field.

`store_state.topology_manifest_digest` MUST equal SHA-256 of the exact standalone
manifest bytes. Provisioning creates both once. Every later managed open derives
the manifest from the selected configuration and requires byte equality before
mutation. A topology change requires another Managed database in v1; current
TOML is never a query source. Link Profile collections are not stored in this
manifest: topology reads derive them only from committed observation or
baseline-state projections, so the sequence-zero profile collections are empty
and a first-B baseline seed is discoverable even after a decode reject.

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

`pending_session_handoff.handoff_cbor` is the complete baseline handoff encoded
as one strictly ordered array of the same complete-baseline-state maps. Its
digest is SHA-256 of those exact bytes. The pending row exists only after a
successful final transaction B and before the lazy-creation transaction A of a
later session consumes it. Genesis has no row and therefore supplies an empty
initial array, meaning Missing. The source identifiers are retained provenance,
not foreign-key ownership: the handoff bytes remain valid bootstrap authority
if retention later removes their sealed source. Once copied into a new session
manifest, that manifest and its ordered facts are the sole recovery authority
for that session.

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

CREATE TABLE store_state (
    singleton INTEGER NOT NULL CHECK(singleton = 1),
    store_id BLOB NOT NULL CHECK(length(store_id) = 32),
    topology_manifest_cbor BLOB NOT NULL,
    topology_manifest_digest BLOB NOT NULL
        CHECK(length(topology_manifest_digest) = 32),
    projection_commit_seq BLOB NOT NULL
        CHECK(length(projection_commit_seq) = 8),
    PRIMARY KEY (singleton)
) WITHOUT ROWID;

CREATE TABLE sessions (
    session_id TEXT NOT NULL,
    started_utc_ns INTEGER NOT NULL,
    manifest_cbor BLOB NOT NULL,
    fact_bytes BLOB NOT NULL CHECK(length(fact_bytes) = 8),
    lifecycle TEXT NOT NULL
        CHECK(lifecycle IN ('active', 'sealed')),
    sealed_utc_ns INTEGER,
    seal_reason TEXT
        CHECK(seal_reason IS NULL OR seal_reason IN
              ('finish', 'duration_limit', 'byte_limit')),
    PRIMARY KEY (session_id),
    CHECK((lifecycle = 'active') = (sealed_utc_ns IS NULL)),
    CHECK((lifecycle = 'active') = (seal_reason IS NULL))
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

CREATE TABLE projection_commits (
    commit_seq BLOB NOT NULL CHECK(length(commit_seq) = 8),
    session_id TEXT,
    record_seq BLOB
        CHECK(record_seq IS NULL OR length(record_seq) = 8),
    kind TEXT NOT NULL
        CHECK(kind IN ('semantic', 'decode_rejected', 'finish', 'retention')),
    timeline_state_digest BLOB
        CHECK(timeline_state_digest IS NULL
              OR length(timeline_state_digest) = 32),
    PRIMARY KEY (commit_seq),
    UNIQUE (session_id, record_seq, commit_seq),
    FOREIGN KEY (session_id, record_seq)
        REFERENCES session_records(session_id, record_seq)
        ON DELETE CASCADE,
    CHECK((session_id IS NULL) = (record_seq IS NULL)),
    CHECK((kind = 'retention') = (session_id IS NULL)),
    CHECK((kind = 'retention') = (timeline_state_digest IS NULL))
) WITHOUT ROWID;

CREATE UNIQUE INDEX one_commit_per_record
    ON projection_commits(session_id, record_seq)
    WHERE session_id IS NOT NULL;

CREATE UNIQUE INDEX one_retention_commit
    ON projection_commits(kind) WHERE kind = 'retention';

CREATE TABLE session_processing_state (
    session_id TEXT NOT NULL,
    processed_through_record_seq BLOB
        CHECK(processed_through_record_seq IS NULL
              OR length(processed_through_record_seq) = 8),
    timeline_state_digest BLOB
        CHECK(timeline_state_digest IS NULL
              OR length(timeline_state_digest) = 32),
    projection_commit_seq BLOB
        CHECK(projection_commit_seq IS NULL
              OR length(projection_commit_seq) = 8),
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (session_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE,
    FOREIGN KEY (session_id, processed_through_record_seq,
                 projection_commit_seq)
        REFERENCES projection_commits(session_id, record_seq, commit_seq),
    CHECK((processed_through_record_seq IS NULL)
          = (timeline_state_digest IS NULL)),
    CHECK((processed_through_record_seq IS NULL)
          = (projection_commit_seq IS NULL))
) WITHOUT ROWID;

CREATE INDEX processing_by_cursor
    ON session_processing_state(processed_through_record_seq, session_id);

CREATE TABLE pending_session_handoff (
    singleton INTEGER NOT NULL CHECK(singleton = 1),
    source_session_id TEXT NOT NULL,
    source_record_seq BLOB NOT NULL CHECK(length(source_record_seq) = 8),
    source_projection_commit_seq BLOB NOT NULL
        CHECK(length(source_projection_commit_seq) = 8),
    handoff_cbor BLOB NOT NULL,
    handoff_digest BLOB NOT NULL CHECK(length(handoff_digest) = 32),
    PRIMARY KEY (singleton)
) WITHOUT ROWID;

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
    source_record_seq BLOB NOT NULL CHECK(length(source_record_seq) = 8),
    config_digest BLOB NOT NULL CHECK(length(config_digest) = 32),
    decoder_version TEXT NOT NULL,
    conditioning_version TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    PRIMARY KEY (deployment_id, link_id, profile_id)
) WITHOUT ROWID;

CREATE INDEX baseline_by_source
    ON baseline_states(source_session_id, source_record_seq);

CREATE VIEW visible_sessions AS
SELECT s.session_id,
       s.started_utc_ns,
       s.lifecycle,
       s.sealed_utc_ns,
       s.seal_reason,
       p.processed_through_record_seq,
       p.projection_commit_seq,
       p.config_digest,
       p.decoder_version,
       p.conditioning_version,
       p.algorithm_version
FROM sessions AS s
JOIN session_processing_state AS p USING (session_id)
WHERE p.projection_commit_seq IS NOT NULL;

CREATE VIEW visible_records AS
SELECT r.session_id,
       r.record_seq,
       r.session_time,
       r.kind,
       r.body_cbor
FROM session_records AS r
JOIN session_processing_state AS p USING (session_id)
WHERE p.processed_through_record_seq IS NOT NULL
  AND r.record_seq <= p.processed_through_record_seq;

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

Provisioning MUST read every configured epoch key from the secret store, derive
each identity, and insert exactly one fresh empty admission row with its
configured window size into the staged database. Missing keys, duplicate epoch
identities, pre-existing staged rows, or any mismatch MUST fail closed and MUST
NOT publish the staged store.

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

A fresh `session_processing_state` row has a NULL processed cursor, Timeline
digest, and projection commit sequence. Transaction B writes all three together.
`timeline_state_digest` is exactly SHA-256 of the canonical TimelineState v1
bytes produced after replaying ordered facts through
`processed_through_record_seq`. The cursor and digest form one determinism
tripwire; the digest is never serialized resume state and cannot authorize
skipping any fact.

`projection_commits` is a retention-scoped structural commit index, not a
second payload log and not an immutable history. Each transaction B inserts one row whose
`commit_seq` is the same next value written to `store_state` and whose
session/record pair is the exact consumed durable fact. The partial unique index
provides at-most-once commit for each retained fact; recovery retry supplies the
corresponding completion path. A duplicate record binding, sequence gap,
sequence reuse, kind mismatch, or Timeline-digest mismatch MUST roll back the
whole transaction. The index carries no semantic payload or independently
encoded effect digest; normalized projection rows remain the query state and
manifest plus facts remain replay authority. Retention cascade-deletes the
index rows owned by each deleted session. Before inserting the new `retention`
row for its newly advanced sequence, the same transaction deletes any prior
retention row; the partial unique index therefore keeps at most one unowned
retention marker. A retained processing state is foreign-key-bound to the
commit row for that exact session and cursor. Callers MUST NOT treat row count
or a contiguous retained prefix as historical proof.

`observation_cbor`, `snapshot_cbor`, and `evidence_cbor` MUST respectively be
the exact standalone
[CsiObservation](temporal-world-v1.md#csiobservation-root),
[WorldSnapshot](temporal-world-v1.md#worldsnapshot-root), and
[LinkStepEvidence](temporal-world-v1.md#linkstepevidence-root) v1 bytes. Those
language-neutral temporal tables are the sole payload authority. A Rust
serializer, generic bytes/value interface, or private type layout MUST NOT
define durable bytes implicitly.

For `csi_observations`, the row session/record, session time, sensor, link,
profile, decoder, conditioning, and configuration receipts MUST equal the
decoded root. For `world_snapshots`, the row session/snapshot, interval, source
range, algorithm, and configuration receipts MUST equal the decoded root. For
`snapshot_link_evidence`, the row session/snapshot plus link/profile key
identifies one present aggregate evidence item, and its row receipts MUST equal
the decoded evidence and associated snapshot. Within one private semantic
`EngineTransition`, every emitted row/root identity and ordered collection MUST
be strictly ordered and unique. For each emitted snapshot, its present
Link/Profile keys and the present evidence-row keys MUST be equal, including
when both sets are empty.

For `baseline_states`, the row deployment/link/profile and compatibility
receipts MUST equal the decoded complete baseline map. Its source session and
non-NULL source record identify the exact transaction B that most recently
published that complete state. A new session's first transaction B binds every
row in its complete baseline set to that new session and first record.

The Engine owns semantic completeness. Persistence MUST validate canonical
bytes, row/root identity, receipts, ordering, uniqueness, and present-key
equality, but MUST NOT traverse facts or Timeline to recompute the window's
contributor/baseline union, reconstruct a projection, or decide that the Engine
omitted a semantic key. Such a mismatch is detected by Engine invariants or the
recovery/replay comparison seam, not by a second persistence implementation of
world semantics. Any independently observable mismatch or non-canonical value
is corruption and MUST fail transaction B or fail closed on read.

Operational recovery MUST construct a fresh Engine and Timeline from the
manifest and ordered raw records. Through the stored processed cursor, the
fresh processing path MUST compare each produced append-only observation and
each complete WindowProjection with the retained committed rows they produced;
the prefix writes nothing. Exactly at the cursor, recovery MUST compare the
fresh Engine's complete current baseline set with the latest `baseline_states`
rows and canonically encode rebuilt Timeline state to require its SHA-256 digest
to equal the stored cursor-bound digest. Missing or extra rows, identity
disagreement, byte disagreement, or digest mismatch is an explicit fail-closed
determinism or corruption condition. `baseline_states` remains the latest state
set and gains no history. A later session's first transaction B supersedes the
prior session's baseline query projection without changing retained historical
snapshots or evidence. Program 1 operational recovery MUST NOT restore from the
digest, trust a serialized Timeline value, skip to the cursor, rewrite the prefix,
or repair retained projections online.

All BLOB integer columns use unsigned fixed-width big-endian bytes: `key_epoch`
is two bytes, `highest_boot_generation` is four, and projection commit
sequences, device IDs, record sequences, session times, session fact-byte
counters, snapshot IDs, interval bounds, source-record bounds, and message
sequences are eight. Equal-width SQLite BLOB comparison is therefore unsigned
numeric order. Writers and readers MUST reject every other width and MUST NOT
narrow, reinterpret as signed, or cast these values to SQLite INTEGER. UTC
nanoseconds remain signed SQLite INTEGER because their domain is `i64`.

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

The required persistent SQLite settings are `user_version=1` and
`journal_mode=WAL`. Provisioning MUST establish both. Operational open of an
existing store MUST query and require both before any Host state mutation and
MUST NOT silently repair either. Every connection MUST then apply and verify
connection-local `foreign_keys=ON`. The writer connection MUST also apply and
verify connection-local `synchronous=FULL`; readers do not require a
synchronous setting.

### Managed store identity and cooperative lease

Program 1 assumes a trusted local development namespace. The canonical parent
of `database_path` is one dedicated Managed store root. That root MUST already
exist, MUST be a non-symlink directory owned by the process effective user ID,
and MUST have exact POSIX mode `0700`. The fixed root-relative lease and final
database, every private staging database, and SQLite WAL or SHM companion when
present MUST each be a non-symlink regular file with link count one, owned by
the process effective user ID, and have exact POSIX mode `0600`. These checks
use the object metadata obtained without following its final path component.
Cooperative Whisper processes MUST NOT rename, replace, delete, or mutate any
of those managed objects outside `HostLifecycle`.

The application MUST fail closed on an observed missing required object,
symlink, wrong file type, extra hard link, wrong effective-user ownership, or
wrong exact mode. It does not claim to prevent hostile root or same-credential
namespace mutation. A custom VFS, privileged broker, and hostile-namespace
isolation are outside Program 1.

Every managed operation MUST enter through `HostLifecycle`, validate and
canonicalize the configured existing root, open or create the fixed
root-relative `.whisper.lease` with no-follow semantics and exact mode `0600`,
acquire an exclusive OS advisory lock, and retain its open descriptor for the
complete managed operation. Creation MUST fail rather than follow or replace an
existing final component, and every existing managed component MUST pass the
ownership, type, link-count, and mode checks above before use. Lease content and
file existence are not authority. Connections MUST close before the descriptor
and lock are released. Lock conflict, permission failure, canonicalization
failure, metadata mismatch, and lease I/O failure MUST fail closed. Normal exit
and process termination MUST release the OS lock for a later lifecycle.

`store_state` contains exactly one row. `store_id` is 32 bytes generated once
from the operating system's cryptographic random source during provisioning;
it is stable for the store lifetime, public, and is not a credential or
attestation. The same row holds the immutable Store topology manifest and its
verified digest. `projection_commit_seq` begins at zero. The Store ID is a
private strong value held by the managed lifecycle and verified by read-only
query connections before they return a view. The retained OS lease, not a
database generation counter, is the sole cooperative lifecycle writer fence.

The Store ID and `projection_commit_seq` are the global query-visible Store
state watermark. Every transaction that changes query-visible rows MUST advance
the sequence exactly once in the same transaction; it MUST NOT reuse an earlier
identity for different visible state. Ordinary transaction B and a retention
transaction that actually deletes query-visible rows are the v1 mutation paths.
A transaction-A-only fact lies beyond the processing cursor and is not visible.
A newly created session with NULL
`session_processing_state.projection_commit_seq` is not query-visible and MUST
be omitted from topology. Its first successful transaction B both assigns its
non-NULL session projection commit and makes that session query-visible under
the newly advanced Store watermark. Its complete manifest-seeded baseline set
MUST be materialized for that session in the same first transaction B, including
when the record is a decode reject. A retention no-op does not advance the
sequence. Sequence overflow MUST fail closed without mutation.

`session_processing_state.projection_commit_seq` binds that session's processed
cursor to its retained commit-index row and determines whether the session is
visible. It is not the global query receipt watermark. Every Store-scoped or
session-scoped HTTP receipt takes its Store ID and projection sequence from the
current `store_state` row in the same SQLite read snapshot, including after a
retention commit advances only the Store watermark.

Program 1 query readers MUST obtain sessions through `visible_sessions` and raw
fact-backed Timeline ranges through `visible_records`; they MUST NOT read the
corresponding base tables. `ViewReceipt.last_record_seq` is exactly
`processed_through_record_seq`, never `MAX(session_records.record_seq)`. The
Store topology base comes only from the immutable topology manifest; profile
collections may add identities only from committed observation or baseline-state
projections in the same read snapshot. These rules are the visibility cut that makes
transaction A structurally unable to change a query result.

Program 1 MUST qualify one SQLite-bundled VFS on the identified current Apple
Silicon Mac and MUST test the default VFS first. The SQLite qualification covers
WAL plus writer `synchronous=FULL` under SIGKILL, SQLite recovery, lock
reacquisition, and same-process bounded readers with one writer. An independent
two-process qualification MUST prove the application root lease excludes the
second cooperative lifecycle. These checks do not establish hostile namespace
isolation or second-platform support, and Program 1 introduces no custom VFS.

## Initialization and runtime ownership

`whisper init-admission <config>` MUST be the only host
entry point allowed to create schema version 1. It MUST acquire the dedicated
root lease while the configured final database component is absent. Before
SQLite opens a staging database, provisioning MUST create its private
collision-resistant name inside the validated `0700` root using create-new and
no-follow semantics with exact mode `0600`; it MUST initialize only that staged
database. Initialization establishes
the required SQLite settings and schema, generates and inserts the one
`store_state` row with the exact immutable topology manifest and digest, and
inserts exactly one empty replay admission row for every configured route epoch.
Every derived identity and bounded window size MUST
match the configuration under
[Replay-window identity](#replay-window-identity).

Before publication, provisioning MUST commit all initialization, checkpoint
all WAL content into the staged main database, synchronize the staged main
database, close every staging connection, and validate the closed store with a
non-creating open. No staged WAL or SHM may be required to interpret the closed
store. It MUST then publish the staged main database to the final component
with a current-Mac primitive qualified as atomic and no-replace, synchronize
the Managed store root as required by that primitive, and re-open the final
store without creation to verify the same Store ID, topology manifest and
digest, schema, settings, and empty admission state. A pre-existing final
component, crash, conflict, or validation,
checkpoint, synchronization, close, publication, or re-open failure MUST fail
without replacing the final component or reporting success.

Capture, replay, and corpus export MUST use validated current configuration to
select the existing Managed database and its trusted root. After validating and
canonicalizing that root and acquiring the retained root lease, every such
existing-store lifecycle MUST perform this common open sequence in order:

1. mechanically open the database without creation through the qualified
   bundled VFS;
2. permit SQLite WAL and storage recovery as applicable;
3. query the required persistent settings and reject any incompatibility;
4. apply and verify every connection-local setting required for that
   connection;
5. validate the schema; and
6. validate the Store ID and require the Store's immutable topology manifest
   and digest to equal the topology identity derived from the selected
   configuration.

Capture and replay MUST then, in order, validate the configured admission
epochs applicable to the intent and validate the applicable replay identity.
A sealed-session faithful replay uses a verified read-only connection. No open
may proceed past a failed step. A missing file, corrupt SQLite database, wrong
schema/version, incompatible setting, Store ID failure, topology-manifest
mismatch, epoch failure where applicable, or replay-identity failure where
applicable MUST fail closed. Operational open MUST NOT create, reset, repair,
migrate, or replace the database or admission state as a side effect. No
lifecycle intent accepts a caller-selected database path or exposes a general
SQLite connection opener.

Corpus export MUST be a distinct `HostLifecycle` intent from capture, faithful
replay, and ordinary HTTP/query reads. Under one retained cooperative lease,
its open has exactly two connection phases. Phase one MUST use one short-lived
recovery/validation connection to perform the complete common sequence above,
in that order, through Store ID and immutable topology validation. It MUST NOT
require the current configured admission epochs or replay identity to equal the
selected historical session's values. After topology validation, phase one MUST
close its connection before phase two begins. WAL or storage recovery in phase
one is not semantic table mutation.

Without releasing the lease, phase two MUST perform this sequence in order:

1. mechanically open one read-only connection without creation through the
   same accepted qualified bundled VFS;
2. apply and verify the required reader-local settings;
3. begin exactly one SQLite read transaction, which fixes exactly one read
   snapshot;
4. inside that snapshot, revalidate the Store ID and immutable topology
   identity established by phase one, require the selected session to exist and
   have the sealed lifecycle, and validate the selected session's processed
   cursor and the global Projection watermark; and
5. return `CorpusExport` only after every preceding validation succeeds.

The resulting bounded `CorpusExport` shell MUST own that one read-only
connection and snapshot. All logical export readers MUST borrow that connection
and snapshot; they MUST NOT create another connection, transaction, or
snapshot. Current replay configuration and current admission epochs MUST NOT be
required to equal the selected historical sealed session manifest. Historical
route and replay identities for export come exclusively from that sealed
manifest. The shell MUST NOT mutate facts, projections, lifecycle, replay
admission, Engine state, or evidence classification. Dropping `CorpusExport`
MUST first end its read transaction and close its read-only connection, then
release the retained lease. Canonical `CorpusManifest` construction, corpus
artifact publication, and structural artifact validation are outside this
persistence contract.

One sequential ingest owner MUST hold the sole synchronous writer connection.
Synchronous database work MUST run off asynchronous runtime and ingest
execution. Under a lifecycle that has completed the common existing-store open
and retains its lease, bounded read-only query connections MAY read the same WAL
database. Each such connection MUST open mechanically without creation through
the same qualified bundled VFS, apply and verify its required reader-local
settings, and verify the Store ID inside its bounded read snapshot before
returning a view. These ordinary HTTP/query readers do not become replay or
corpus-export readers. No connection pool or database actor is introduced. The
lifecycle MUST hold the Managed store root lease until all managed writer and
reader work has stopped and every connection has closed.

## Durable admission and processing transactions

Before database mutation, capture MUST validate datagram size, fixed header,
exact peer route, exact key lookup, authentication, and per-route packet/byte
budgets.

Before accepting any input, `HostLifecycle` MUST compare the current replay
configuration digest, executable fingerprint, decoder, conditioning, algorithm,
and wire-admission pins with an existing active session manifest. Exact equality
authorizes recovery and continuation of that same session. Any mismatch MUST
fail closed without appending `Closed`, sealing the session, consuming a pending
handoff, or creating another session. Program 1 requires an explicitly finished
compatible session or another Managed database before changed replay identity
may capture.

After authentication, transaction A MUST use `BEGIN IMMEDIATE` to:

1. when no active session exists, construct one manifest from the current
   compatible identity and the exact pending handoff, or an empty genesis set,
   insert that session as `active` with an all-NULL processing row, and consume
   the pending handoff in the same transaction;
2. consume the matching private validated `EpochHandle` and reread its
   provisioned admission epoch;
3. reject replay or atomically advance its bounded boot/message window; and
4. insert the exact encrypted packet record and receive context and atomically
   add its logical cost to `sessions.fact_bytes`.

The lazy creation and first fact either both commit or both roll back. No empty,
prepared, or transaction-A-visible session exists. Ordered control and Timeline
advance inputs use the same lazy-creation rule but do not mutate replay
admission.

Only a committed transaction A authorizes cleartext decoding or Engine
advance. Failure MUST roll back both admission and raw insertion, leave Engine
unchanged, and stop capture before publication.

After raw commit, and never before it, the shared decoder and Engine path may
process the record. The `CaptureRun` processing coordinator MUST hold that
committed `DurableRecord` plus exclusive access to the current Engine and
Timeline and construct exactly one private, unforgeable, closed
`ProcessedRecordTransition`: either `Semantic(EngineTransition)` from the normal
Engine interface or `DecodeRejected` from the production decoder. For a
session's first record, the coordinator MUST also attach the Engine's complete
current baseline set after initialization from the manifest, regardless of the
variant; later records carry no first-commit set. Transaction B MUST consume that
value, read and retain the previous Store sequence, calculate its exact
successor, insert the matching `projection_commits` row, conditionally advance
`store_state.projection_commit_seq` from the retained previous value to that
successor, and atomically persist the processing cursor, cursor-bound Timeline
digest, the same projection commit sequence, and version/source receipts. The
conditional Store update MUST affect exactly one row. For `Semantic`, it
additionally persists
changed complete baseline states, typed observation when present, and every
complete `WindowProjection`; it fans each WindowProjection out to its one
`world_snapshots` row and complete ordered set of aggregate
`snapshot_link_evidence` rows inside that same transaction only after validating
the whole transition. `DecodeRejected` MUST bind the record and cursor, the
production decoder's typed authenticated unknown-kind,
malformed/unsupported-body, capability, or source/radio reject, and the current
unchanged Timeline digest, and MUST carry no changed semantic baseline state,
observation, or World projection. The required first-commit complete baseline
set is lifecycle publication, not a decode semantic effect. Transaction B MUST
validate and materialize exactly that full set under the new session and first
record, removing no-longer-present operational projection keys in the same
transaction, before assigning the session's first non-NULL projection commit.
No predecessor-owned baseline row may remain query-visible as if it belonged to
the new session. It MUST NOT
accept application-grouped, operator-selected, or caller-constructed variants
or WindowProjections, commit a snapshot or evidence row separately, or use
replace, upsert, delete-and-reinsert, or other per-row conflict handling.

The next sequence and Store ID form the Committed projection identity for that
transaction. Sequence zero is only a Projection watermark: it names the
provisioned Store topology with no visible session, and no transaction B owns
it. Every transaction B creates the next nonzero identity. Both processing
variants, including deterministic decode rejects, and every control record MUST
advance the cursor and projection commit identity atomically with their concrete
state effect. Only `Semantic` may write an Engine semantic effect. Persistence
MUST store the Engine's supplied semantic values and MUST NOT invent, regroup,
sort, or reconstruct semantic state.

Memory mirrors, query-visible identifiers, HTTP results, and notifications MUST
be replaced or published only after transaction B commits. Transaction B
failure MUST leave the previous committed lifecycle, cursor, digest,
projection commit identity, state, and projections intact and stop capture
before anything from the failed transition is exposed.

An authenticated unknown kind, malformed or unsupported cleartext body, or
source/radio mismatch remains a durable raw fact and a classified decode
reject; it MUST NOT enter Timeline or estimator processing. Baseline commands
and timeline advances MUST first be durably inserted by their own ordered
transaction A before their semantic effect runs.

Each admitted packet uses one transaction A and one transaction B in the v1
correctness baseline.
Batching or a separate writer task requires measured evidence and a later
contract change. Transaction A and transaction B commits, WAL mode, and writer
`synchronous=FULL` are the complete v1 durability and publication contract.

## Lifecycle, recovery, and rotation

Session lifecycle is exactly `active | sealed`. There is no `prepared` or
`recovery_sealed` state. Transaction A lazily creates an active session together
with its first fact; an empty session cannot exist. Inserting `Closed` makes its
raw stream non-appendable but does not itself seal the lifecycle. Only sealed
sessions are immutable faithful-replay inputs; active sessions are not complete
replay inputs.

SQLite transaction rollback replaces file-tail scanning and CRC recovery. The
application-owned `HostLifecycle` coordinates recovery; persistence MUST NOT
expose a bare seal, caller-selected lifecycle, or recovery-seal operation.

Under the Managed store root lease, recovery of an active session MUST first
read and validate its manifest and complete ordered fact tail and require the
current replay identity equality defined above. A tail without `Closed` remains
open. Recovery MUST NOT append `Closed` merely because a process stopped, and
MUST NOT seal or create a successor as a side effect of Host restart.

The manifest and `session_records` in unsigned sequence order are the sole Host
recovery authority. Recovery MUST construct a fresh Engine and Timeline from
the manifest's complete baseline seed and feed every fact through the same
production decoder and `CaptureRun` processing coordinator used by live capture.
Through the stored committed processing cursor, if present, replay only rebuilds
working state and compares every produced append-only observation and complete
WindowProjection with the retained committed prefix bytes and identities. It
MUST write nothing. Exactly at that cursor it MUST compare the fresh Engine's
complete current baseline set with the latest `baseline_states` rows and compare
the rebuilt cursor-bound Timeline digest with the stored digest. Missing, extra,
corrupt, identity-mismatched, or byte-mismatched retained prefix state MUST fail
closed; the comparison adds no baseline history, and Program 1 performs no
online projection repair. Recovery MUST NOT restore or resume from a digest,
derived row, memory snapshot, or serialized Timeline value.

For each ordered fact strictly after the committed cursor, recovery MUST obtain
one complete private `ProcessedRecordTransition` from that normal
decoder/coordinator path and immediately submit the unmodified transition to the
normal transaction B before processing the next fact. Every successful
transaction B advances the
processing cursor to that fact, stores its cursor-bound Timeline digest and
exact semantic effects, and advances `store_state.projection_commit_seq` by
exactly one. The application MUST NOT aggregate, reorder, drop, split, or
forge processing transitions in live capture or recovery. If recovery is
interrupted, a later attempt constructs another fresh Engine and Timeline,
rebuilds through the newly committed cursor without writes, validates its
digest, and continues with the next fact.

If the durable tail has no `Closed`, successful recovery stops at the tail and
then accepts later input in the same active session and record-sequence space.
If an earlier explicit finish or limit rotation already committed `Closed`,
recovery processes that exact tail through the ordinary finish path below. It
does not synthesize a second close.

Explicit finish or limit rotation MUST first stop new input, drain accepted
input, and commit `Closed` and its fact-byte update as transaction A. The Engine
then finishes and returns `FinishedTransition` plus one complete, strictly
sorted, unique baseline handoff. The `Closed` record's ordinary transaction B
MUST consume a private finished proof, reread and match its manifest, record,
cursor, digest, and transition bindings, then atomically:

1. persist the final cursor, digest, semantic projections, and complete current
   baseline projection;
2. insert the `finish` projection-commit row and advance the Store watermark;
3. change lifecycle to `sealed` with the exact finish or limit reason; and
4. install the exact complete pending baseline handoff and its digest.

Persistence validates and stores supplied strong values; it MUST NOT derive,
reconstruct, or fill in semantic baseline values. Any failure leaves the last
successful transaction-B state intact, leaves the session active with its
durable `Closed` tail, and installs no pending handoff. A later compatible
recovery retries that same final transaction. Final transaction B never creates
a successor.

Both `max_session_duration_ns` and `max_session_bytes` are configured nonzero
rotation limits. Reaching the duration limit MUST pause new input and complete
the same close, finish, and final-transaction sequence. Byte-limit behavior is
defined by [Session fact bytes](#session-fact-bytes). After any successful seal,
the next accepted fact triggers the ordinary lazy-creation transaction A, which
copies and consumes the pending handoff. A process stop alone is neither finish
nor rotation: after draining already accepted work, it closes the Managed store
and leaves the session active.

### Program 1 minimal Host restart

Program 1 minimal restart stops only the Host while the Sensor and Mac remain
running and retains the managed SQLite database. On restart, `HostLifecycle`
MUST reacquire the root lease, complete SQLite WAL recovery, reconstruct fresh
working Engine and Timeline state from the manifest and ordered facts, and
validate the retained committed processing cursor and query state under the
recovery rules above. It MUST NOT append `Closed`, seal, create a successor,
consume or install a handoff, rebuild committed query rows, or repair them. The
next datagram is admitted and processed exactly once in that same active session.

The restart proof records both the last durable record sequence and the
processed-through cursor before stop. Recovery first commits every A-only tail
record through ordinary transaction B. The first newly admitted record after
recovery is exactly one greater than the recovered durable tail, not necessarily
one greater than the pre-stop processing cursor. A controlled input may also
prove its exact device message sequence and resulting replay-window change;
general correctness MUST NOT assume an accepted out-of-order message always
raises `maximum_message_sequence`.

Minimal Host restart MUST NOT require rebooting the Sensor or Mac. Acceptance
MAY use the captured corpus, but that execution MUST NOT be classified as a new
live physical observation. Browser disconnect and canonical HTTP
resynchronization remain owned by [API/UI v1](api-ui-v1.md#diagnostic-ui).

## Retention

`retention_max_sessions` MUST be positive. Retention MUST run in one
transaction and delete only the oldest sealed sessions and their foreign-key
owned records, projections, and retained commit-index rows. It MUST NOT delete
an active session, an admission epoch, the current operational baseline, or the
pending handoff bytes.

When retention deletes any query-visible row, the same transaction MUST delete
the previous unowned retention marker, advance `store_state.projection_commit_seq`
exactly once regardless of the number of rows or sessions deleted, and insert
one `projection_commits(kind='retention')`
row at that exact sequence. Persistence hands the new Store-bound identity to
delivery only after commit. Rollback hands off nothing and preserves the prior
identity and rows. No other query-visible mutation may reuse an existing
identity. The API/UI specification alone owns the invalidation name and
publication behavior.

The complete handoff is already independent pending authority or has been
copied into the active manifest before its sealed source becomes retention
eligible; deleting that source cannot remove resume authority. Baseline source
columns remain provenance values rather than foreign-key ownership. SQLite MAY
reuse free pages. Hot-path `VACUUM` and a generic garbage-collection framework
are forbidden.

## Faithful replay

V1 implements faithful replay only. Replay MUST accept only a sealed session;
an active session MUST remain under operational recovery or be explicitly
finished before replay.

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

An acceptance check that deletes projections and compares deterministic replay
outputs MUST use an isolated copied store or isolated replay output sink. It
compares the fresh Engine-produced canonical projection bytes and identities
with the expected live outputs; it MUST NOT delete, rebuild, or write projection
rows in the operational Managed store.

A later explicit reinterpretation mode MAY process old bytes under a new
contract and output namespace. It MUST NOT claim the original session's
semantic identity and is outside v1.

## Acceptance

Acceptance requires behavior-focused tests and retained execution receipts at
the specified interfaces. At minimum they MUST cover:

- schema, required connection state, version, foreign keys, visibility views,
  fresh NULL state, Store ID, immutable topology manifest and digest, pending
  handoff, retained commit index, root lease, projection sequence, and
  transaction rollback;
- strict ReplayConfig and complete BaselineState manifest/database roundtrips,
  with a persisted fixture proving exclusion of TOML source, RuntimeConfig,
  secrets, and lossy snapshot-only baseline state;
- length limits before allocation and complete unsigned edge-value roundtrip
  and ordering;
- missing and corrupt databases, wrong persistent settings or schema,
  connection-local setting application, missing epochs, topology mismatch,
  active-manifest replay-identity mismatch, and no create/reset, synthetic
  close, rotation, or silent-repair side effect from capture open;
- non-creating corpus-export recovery/validation open through validated
  configuration, recovery-connection close before one read-only
  sealed-session snapshot, snapshot-local identity and cursor revalidation,
  active- and missing-session rejection, historical-manifest identity
  independence from current replay configuration and admission epochs, mutation
  exclusion, and snapshot/connection close before lease release;
- application-lease exclusion across two cooperative processes; chosen bundled
  VFS current-Mac qualification with the default tested first; WAL plus
  `synchronous=FULL` SIGKILL recovery, SQLite lock reacquisition, and
  same-process bounded readers with one writer; private same-root staging,
  closed-store validation, synchronization, and atomic no-replace publication
  without final-object replacement;
- cross-language replay-window identity fixtures covering exact key-bound
  derivation, explicit exclusions, size comparison, and mismatch rejection;
- session fact-byte edge cases, reserved `Closed`, equality rotation,
  fresh-session overflow, rollback, recomputation, and physical-byte
  exclusions;
- duplicate and skipped record sequence, reversed time, and insertion after
  `Closed` or seal;
- transaction A rollback preserving admission and raw state and preventing
  decode/Engine advance;
- transaction B rollback preserving the prior projection commit identity and
  preventing HTTP or WebSocket publication;
- the first transaction B publishing the complete manifest-seeded baseline set
  even for a decode rejection, while transaction A alone leaves its session,
  facts, and baseline seed invisible;
- one retained commit-index row per transaction B, duplicate record rejection,
  exact Store-sequence agreement, and explicit cascade behavior under retention;
- crash before transaction A, after A and before B, and after B before
  invalidation, with exactly-once fact processing and no uncommitted exposure;
- recovery prefix rebuild without writes followed by one ordinary transaction B
  per uncommitted fact; an open tail continues the same active session, while a
  previously durable `Closed` completes the ordinary atomic finish transaction;
- byte/identity equality between Engine-produced recovery-prefix projections
  and retained committed rows, with missing or mismatched rows failing closed
  and no operational repair;
- cursor-bound Timeline digest equality during fresh rebuild, with the digest
  rejected as resume state and mismatch failing closed;
- lazy creation atomically copying and consuming a pending handoff with the
  first fact, rollback leaving both unchanged, and identity mismatch creating no
  session or handoff mutation;
- restart receipts distinguishing the pre-stop durable tail from the processing
  cursor and proving the first new record continues at durable-tail plus one in
  the same session;
- retention preserving the active session, admission epochs, pending handoff,
  and current operational baseline state while deleting owned commit-index rows
  and atomically inserting and publishing one fresh retention commit for any
  query-visible deletion; and
- faithful live/replay equality for bytes, receive context, record order,
  typed results, and isolated deterministic output comparison after deleting
  copied projections.

Test source alone is not executed acceptance evidence.
