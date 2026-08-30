# Single-sensor development E2E v1 specification

Status: accepted target

Applicability: the typed claim graph, BrowserTrace, formal execution
classifications, qualification reports, Host-restart claim, and Program
Completion receipt belong to the deferred Semantic Program. The bounded Demo's
sanitized `demo-smoke` is owned by
[Demo Slice v2](demo-slice-v2.md#sanitized-demo-smoke-receipt) and MUST NOT be
treated as any classification defined here.

This specification is the sole normative owner of Program 1's bounded fixture
cardinality, evidence classifications, and composed physical-to-browser
acceptance. It does not redefine the component contracts it composes, claim
that the target is implemented, or claim that an acceptance run has executed.

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

`Program 1` is the delivery-scope short name for the Single-sensor development
E2E acceptance specified here. It does not name a domain object or runtime mode.

## Program 1 fixture

Program 1 acceptance uses exactly one physical Sensor, one authenticated route,
and one Link/Profile path through the production Host to the diagnostic Web.
This is a Single-sensor deployment acceptance fixture, not a single-sensor
runtime mode or product cardinality limit.

Configuration arrays, storage keys, schemas, API representations, UI
collections and selectors, runtime ownership, and resource formulas MUST remain
dynamic in Sensor count. They MUST NOT special-case one Sensor, assume that the
first Sensor is the only Sensor, or impose a product maximum of one or two
Sensors. Program 1 resource receipts MUST state the actual one-Sensor route,
Link, and Profile load that they exercised.

Program 1 acceptance does not require two routes, two Profiles, or two physical
Sensors. Generated scenarios MAY use multiple routes or Profiles to test
isolation and dynamic layout without changing the physical fixture or becoming
hardware evidence. Physical Multi-sensor deployment acceptance is future scope
owned by the [roadmap](../ROADMAP.md#multi-sensor-deployment-validation).

## Input lineage and executed classifications

The machine-readable [Program 1 artifact schema](schemas/development-e2e-v1.schema.json)
is part of this specification. It closes the distinct `CorpusManifest`,
`ExecutionClaimGraph`, `VerificationReceipt`, and `ProgramCompletionReceipt`
roots plus every retained provisioning, capture, projection, browser,
Host-restart, storage-qualification, resource-qualification, and diagnostic-UI
acceptance JSON root named under `$defs`.

### Corpus manifest

A `CorpusManifest` owns immutable content identity and declared input lineage
only. Its file is the RFC 8785 JSON Canonicalization Scheme encoding of the
schema-valid value, encoded as UTF-8 with no byte-order mark or trailing bytes.
The file MUST be byte-identical to re-canonicalization. JSON `U64` and `I64`
values are decimal strings as fixed by the schema; identifiers and lowercase
SHA-256 values retain their exact spelling.

The root has exactly these fields:

| Field | Value |
| --- | --- |
| `schema_version` | integer `1` |
| `exporter_identity` | nonempty export-tool identity |
| `source_snapshot` | the sealed read snapshot below |
| `source_kind` | `physical_capture` or `generated_scenario` |
| `lineage` | the matching physical or generated lineage below |
| `configuration_identity_sha256` | lowercase SHA-256 |
| `routes` | nonempty ordered array of route entries below |
| `content_sha256` | exact exported-content digest below |
| `datagrams` | nonempty ordered array of datagram entries below |

`source_snapshot` has exactly `store_id`, `session_id`, `lifecycle`,
`first_record_seq`, `last_record_seq`, `processed_through_record_seq`,
`projection_commit`, and `source_range_sha256`. Store ID is lowercase
hexadecimal for its 32 bytes. Lifecycle is exactly `sealed`.
Record fields are decimal-string `u64`s and satisfy
`first <= last <= processed_through`. `projection_commit.store_id` equals
`store_id` and names the projection state observed by the same SQLite read
snapshot.

A route entry has exactly `route_identity_sha256`, `sensor_id`, `device_id`,
`key_epoch`, `link_id`, and `profile_id`. Device ID is a decimal-string `u64`,
key epoch is a nonzero integer `u16`, and Profile ID is lowercase hexadecimal
for its 32 bytes. Routes are strictly ordered and unique by raw route-identity
digest bytes; every entry MUST match one ReplayConfig route in the source
session.

A datagram entry has exactly `order`, `record_seq`, `route_identity_sha256`,
`file`, `byte_length`, `sha256`, `peer`, `receive_monotonic_ns`, and
`receive_utc_ns`. Order starts at zero and increases by one; record sequence is
strictly increasing, with the first and last values equal to the
source-snapshot bounds. Route identity MUST resolve to exactly one manifest
route. File is exactly `datagrams/` followed by the 20-digit zero-padded decimal
order and `.bin`. Byte length is a nonzero decimal-string `u64`; peer is the
canonical socket address from persistence v1; receive monotonic and UTC values
use the schema's `U64` and `I64` forms. The file contains the exact complete
encrypted datagram and its SHA-256 and length MUST match the entry.

Physical lineage has exactly `kind=physical_capture` and `sources`. Each
nonempty source entry has exactly `route_identity_sha256`, `board_identity`,
`firmware_revision`, `firmware_image_sha256`,
`provisioning_receipt_sha256`, `capture_tool_identity`, `capture_started_at`,
and `capture_finished_at`, with start not after finish. Sources are strictly
ordered by route digest and contain exactly one entry for every manifest route.
Generated lineage has exactly `kind=generated_scenario`, `generator_identity`,
`generator_source_revision`, `scenario_id`, and `scenario_sha256`.
`source_kind` MUST equal `lineage.kind`. Physical fields are declared lineage;
they do not attest hardware or issue an execution classification.

`source_range_sha256` is SHA-256 over this concatenation, in order:

1. ASCII `whisper.corpus.source-range.v1` and one zero byte;
2. the 32 raw Store-ID bytes;
3. the session-ID UTF-8 length as unsigned `u32` big-endian and those bytes;
4. first and last record sequence as unsigned `u64` big-endian;
5. packet-fact count as unsigned `u64` big-endian; and
6. for every selected packet fact in record order: record sequence and session
   time as unsigned `u64` big-endian, canonical packet `body_cbor` length as
   unsigned `u64` big-endian, then the exact canonical `body_cbor` bytes.

The selected facts are every `packet` row in the inclusive bounds; non-packet
rows MAY occur between them but are not corpus content. `content_sha256` is
SHA-256 over ASCII `whisper.corpus.content.v1`, one zero byte, datagram count as
unsigned `u64` big-endian, then each datagram in order encoded as: order and
record sequence as unsigned `u64` big-endian; the 32 raw route-identity digest
bytes; peer UTF-8 length as unsigned `u32` big-endian and its bytes;
receive-monotonic nanoseconds as unsigned `u64` big-endian; receive-UTC
nanoseconds as signed two's-complement `i64` big-endian; datagram length as
unsigned `u64` big-endian; and the exact datagram bytes.

Export MUST enter through the lifecycle-owned corpus-export intent using
validated configuration to select an existing Managed database. It MUST NOT
open a caller-supplied arbitrary database path. The
[host persistence v1 specification](persistence-v1.md#initialization-and-runtime-ownership)
owns the non-creating open, recovery, snapshot, connection, and retained-lease
lifecycle. Export MUST match every selected record's session time and canonical
packet body to the proposed datagram entry and file. It MUST recompute both
aggregate digests, every individual digest, and all manifest invariants before
publication. SQLite database, WAL, and SHM bytes are never corpus artifacts.

The manifest SHA-256 is over its exact canonical file bytes and is not embedded
in the manifest. The immutable corpus version is `v1-<manifest_sha256>` and its
directory has that exact name. Its exact declared file set is one canonical
`manifest.json` plus every manifest `datagrams[].file`, and no other regular
file. Publication is atomic and no-replace.

Seal and every verification MUST open the version root first, then resolve each
`manifest.json` and datagram path component beneath that opened root without
following symlinks, require containment and a regular file, and reject missing
or undeclared files. The verifier MUST obtain each file's stable file identity,
reject any identity shared by the manifest or two datagrams, reject case aliases,
and require the platform link count to be exactly one for every declared file.
It then reads the exact bytes and rechecks every declared length and digest.

Repeating publication is idempotent only when the existing canonical manifest,
exact file set, identities, link counts, and every referenced file validate
byte-for-byte. An existing name with any mismatch is a collision or corruption
and MUST fail closed; it MUST NOT be repaired, replaced, or merged. Changing
content, order, receive context, source snapshot, lineage, file identity, or the
declared file set invalidates that version rather than proving an operating
system tamper guarantee. These checks close a retained artifact set; they do not
claim hostile same-credential namespace or filesystem security. Corpus
retention is independent of managed-session retention; deleting either artifact
MUST NOT silently delete or reclassify the other.

## Execution claim graph, verification receipts, and completion

An executed claim graph contains typed claims for physical capture, corpus
input, Host projection, browser observation, Host restart, storage
qualification, and resource qualification. Each claim binds its subjects,
parents, execution interval, result, tool/environment identities, and retained
artifacts.

One evidence package is one retained directory root. It contains exactly these
root files:

1. `execution-claim-graph.json`;
2. `board-capture-smoke-verification-receipt.json`;
3. `captured-corpus-e2e-verification-receipt.json`;
4. `scenario-e2e-verification-receipt.json`;
5. `live-physical-e2e-verification-receipt.json`; and
6. `diagnostic-ui-acceptance-report.json`; and
7. `program-completion-receipt.json`.

Apart from the directories needed to contain them, the package MUST contain
exactly those root files and one canonical member for every distinct path named
by any claim `artifacts`, `datagrams`, or `screenshots` locator. Multiple claims
MAY reference the same canonical member path only when every repeated locator
identity field and digest agrees exactly. Within one claim, artifact, datagram,
and screenshot locator paths remain unique. Diagnostic UI case BrowserTrace
paths remain distinct across cases. Unreferenced files, missing files,
conflicting references to one path, symlinks or symlink path components, and
nonregular files are invalid. Repeated path and digest fields in the Diagnostic
UI report, Host Restart receipt, or Program Completion receipt are equality
bindings to those root files or graph locators; they do not add files to the
closed package.

Every graph locator `path` and every repeated Diagnostic UI graph-locator path
uses the schema's canonical ASCII package-relative grammar under `artifacts/`.
The fixed package-root filenames above are not graph locators. Absolute paths,
drive prefixes, backslashes, empty components, `.` or `..` components, and any
path that escapes the package root are invalid. The verifier MUST resolve each
component beneath an already opened
package-root directory without following symlinks, require the result to remain
beneath that root and be a regular file, read its exact bytes, and recompute the
declared SHA-256. On the current platform, the verifier MUST also obtain the
stable file identity of every distinct canonical package member. It MUST reject
two different canonical paths that resolve to one file identity or are case
aliases. Repeated locator occurrences of the same canonical path are one member,
not a hard-link or case-alias violation, and MUST resolve to the same identity
and bytes. A filename, role, media type, or producer-supplied digest alone is
never evidence. These identity checks close the retained evidence set; they are
not hostile namespace or filesystem security hardening.

Every JSON root named by this schema, including `ExecutionClaimGraph`,
`VerificationReceipt`, `ProvisioningReceipt`, `AdmittedFactExport`,
`CaptureReceipt`, `HostCommitTrace`, `ProjectionStoreExport`,
`ProjectionReceipt`, `BrowserWebSocketTranscript`, `BrowserTrace`,
`HostRestartReceipt`, `StorageQualificationReport`,
`ResourceQualificationReport`, `DiagnosticUiAcceptanceReport`, and
`ProgramCompletionReceipt`, is the RFC 8785 JSON Canonicalization Scheme
encoding of its schema-valid value, encoded as UTF-8 with no byte-order mark or
trailing bytes. Each file MUST be byte-identical to re-canonicalization. A reader
MUST reject duplicate object members before constructing a map or DTO. All
schema `Timestamp` strings are UTC instants with at most nanosecond precision,
so they compare exactly with `receive_utc_ns`.

### Provisioning artifacts

Provisioning tooling MAY emit a private, untracked
`ProvisioningOperationRecord` for operator diagnosis or local continuation. If
emitted, it MUST contain only the private operational metadata necessary for
those purposes and MUST NOT contain raw keys, Wi-Fi credentials or passwords,
real SSIDs, or other secret material. It MUST NOT be committed, placed in an
evidence package, referenced by an artifact locator, or consumed by an execution
claim, verifier, classification, or Program-completion input. Calling such an
operational JSON object a receipt does not make it a `ProvisioningReceipt`.

`ProvisioningReceipt` is the distinct, retained Program 1 producer artifact
defined by the closed `$defs.ProvisioningReceipt` schema. It contains exactly
`schema_version`, `fixture_seed`, `derivation_version`, `sensor_id`, `device_id`,
`key_epoch`, `key_identity_sha256`, `route_identity_sha256`,
`firmware_image_sha256`, `provisioned_at`, and `result`. It MUST contain no raw
key, credential, SSID, secret/output/serial path, collector address, command,
log or log path, uncontrolled infrastructure identity, or unknown field.
Neither artifact assigns an evidence classification. The independent verifier
validates the schema-defined producer receipt as untrusted input; it does not
create that receipt and MUST NOT consume `ProvisioningOperationRecord`.

Claims are strictly ordered and unique by claim-ID raw UTF-8 bytes, and every
claim ID is unique. Within each claim, parent IDs are strictly ordered and
unique by raw UTF-8 bytes. Each claim's `artifacts` array has exactly the
following schema-fixed role/media tuples in the displayed order; an empty,
missing, duplicate, extra, reordered, or unknown role is invalid:

| Claim type | Exact `artifacts` role and media-type sequence | Dedicated variable locators |
| --- | --- | --- |
| `physical_capture` | `admitted_fact_export` `application/json`; `capture_receipt` `application/json`; `firmware_image` `application/octet-stream`; `host_commit_trace` `application/json`; `host_executable` `application/octet-stream`; `provisioning_receipt` `application/json` | one or more exact encrypted datagram files |
| `corpus_input` | `corpus_manifest` `application/json` | one or more exact corpus datagram files |
| `host_projection` | `host_commit_trace` `application/json`; `host_executable` `application/octet-stream`; `projection_receipt` `application/json`; `projection_store_export` `application/json` | none |
| `browser_observation` | `browser_trace` `application/json`; `http_body` `application/json`; `websocket_transcript` `application/json` | exactly one PNG screenshot |
| `host_restart` | `restart_receipt` `application/json` | none |
| `storage_qualification` | `storage_qualification_report` `application/json` | none |
| `resource_qualification` | `resource_qualification_report` `application/json` | none |

Every physical-capture and corpus-input claim's datagram array is strictly
ordered and unique by numeric `order`; each entry's `{path, sha256}` binds one
exact datagram file. A browser-observation claim has exactly one screenshot
locator; its `{path, sha256, trace_event_id}` binds one exact valid PNG and the
sole BrowserTrace screenshot event. A storage-qualification claim's checks are
strictly ordered by token raw UTF-8 bytes and therefore present exactly once in
this fixed order:
`application_lease_two_process_exclusion`, `fail_closed_corruption`,
`lock_reacquisition`, `same_process_readers`, `sigkill_lock_release`,
`staged_no_replace_publication`, `wal_recovery`.
Its nonempty `vfs_attempts` array is execution order, uses distinct VFS names,
starts with exactly one `default` attempt, and labels every later attempt
`fallback`. Each attempt carries that same fixed check order, individual
results, and its aggregate result.

The fixed-role artifacts have these additional validation and equality rules:

- `provisioning_receipt` validates as `$defs.ProvisioningReceipt`, contains no
  forbidden provisioning material or operational fields listed above, and
  matches the physical claim's fixture derivation, Sensor, device, key epoch,
  route, firmware image digest, execution result, and interval. A
  `ProvisioningOperationRecord` cannot substitute for this artifact.
- `admitted_fact_export` validates as `$defs.AdmittedFactExport`. It is exported
  from one SQLite read snapshot and contains only Store/session identity,
  record sequence, datagram digest, peer, receive context, and transaction-A
  trace-event binding. It retains no SQLite pages, encrypted datagram body,
  plaintext key, Wi-Fi credential, or other secret-bearing value.
- `capture_receipt` validates as `$defs.CaptureReceipt`; its Store/session, Host
  source/executable, admitted-export digest, Host-trace digest, result, and
  strictly ordered datagram entries match the physical claim and artifacts.
  For each exact retained datagram it binds order/path/digest/receive context,
  admitted record sequence, the matching transaction-A trace event, accepted
  production decode, decoded Sensor/Link/Profile, and the canonical
  CsiObservation digest. A successful `physical_capture` is invalid unless the
  independent verifier rederives the public fixture key, reauthenticates and
  decodes each exact datagram through the native-frame contract, recomputes the
  observation digest, and matches the production Host capture receipt,
  admitted-fact export, and Host commit trace. `claim.result=pass` or an opaque
  receipt digest never establishes `board-capture-smoke`.
- `corpus_manifest` validates as `$defs.CorpusManifest`; its exact canonical
  bytes have the claim's `manifest_sha256`, and each claim datagram locator binds
  exactly one manifest datagram by order and digest.
- `host_commit_trace` validates as `$defs.HostCommitTrace` and is emitted by the
  identified production Host. Events are strictly ordered and unique by
  contiguous numeric `event_seq`; event IDs are unique; `monotonic_ns` is
  strictly increasing; and UTC does not decrease. A transaction-A or
  transaction-B event is appended only after that commit succeeds and binds its
  Store, session, record, datagram or Projection identity. This trace is
  procedural executed evidence, not a SQLite commit timestamp, semantic input,
  PKI statement, or hardware attestation; its wall-clock values never enter the
  semantic database schema.
- `projection_store_export` validates as `$defs.ProjectionStoreExport`. During
  the live verification procedure, the verifier reads the real managed SQLite
  database in one read snapshot, validates it under persistence v1, and
  generates or validates this canonical non-secret export. Store/session,
  durable tail, cursor, Timeline digest, Projection identity, strictly ordered
  complete record descriptors, packet-fact digests and receive context, and
  strictly ordered snapshot/evidence digests MUST equal that snapshot. Record
  descriptors cover every durable record through the tail and contain exact
  record sequence, kind, and SHA-256 of canonical `body_cbor`; their final
  sequence equals `durable_tail_record_seq`, and the processed cursor is not
  greater. The package retains the JSON export, never SQLite, WAL, SHM, raw
  record bodies, raw datagrams, or secret bytes.
- `projection_receipt` validates as `$defs.ProjectionReceipt` and matches the
  Host claim's session, record range, Projection commit, commit time, and result.
  Its export and trace digests equal `projection_store_export` and
  `host_commit_trace`. Its nonempty `packet_fact_commits` is strictly ordered and
  unique by numeric `record_seq`. Every entry matches exactly one retained
  parent datagram and exported packet fact by order, record, and digest, plus
  exactly one transaction-A and its following transaction-B Host-trace event.
  Each referenced B event carries that entry's Projection identity; the final B
  event carries the Host claim identity and UTC equal to
  `projection_committed_at`. Missing, duplicate, extra, or unbound entries fail.
- `http_body` is one complete schema-valid successful HTTP body under API/UI v1.
  `websocket_transcript` validates as `$defs.BrowserWebSocketTranscript`; every
  event `text` decodes as exactly one API/UI-v1 `$defs.LiveEnvelope`, with no
  trailing bytes. `browser_trace` validates as `$defs.BrowserTrace`, contains
  the exact Chrome version, evidence-only page-instance and connection
  identities, and exactly one strictly ordered event of each required kind:
  matching WebSocket watermark receipt, HTTP body receipt with body digest and
  schema-valid ViewReceipt, visible DOM observation, and PNG screenshot capture.
  The trace connection identity MUST equal the WebSocket transcript connection
  identity and the browser claim; its page identity MUST equal the browser
  claim. Neither identity enters the live protocol. The DOM event retains its exact selector plus the queried
  element's lowercase tag, role, accessible name, and rendered visible text; it
  does not substitute a producer-reported digest for the observed value. Event
  IDs and sequences are unique, sequences are contiguous, monotonic time
  strictly increases, and UTC does not decrease. `browser_trace_sha256` equals
  the artifact digest. The verifier independently queries that selector in the
  identified Chrome page and exactly matches the structured DOM value, then
  matches the transcript event, HTTP bytes/API receipt, parent Store commit,
  sole PNG bytes, and screenshot locator's `trace_event_id`, path, and digest.
  An arbitrary JSON object, opaque DOM digest, or arbitrary PNG cannot satisfy a
  browser claim.
- `restart_receipt` validates as `$defs.HostRestartReceipt`, matches the restart
  claim and its exactly three parents. One Host-projection parent binds the
  active session and `before_projection`; the other binds the same session,
  `after_projection`, and exactly one newly admitted packet-fact commit whose
  record sequence and datagram digest equal `continued_record_seq` and
  `continued_datagram_sha256`. The third parent is the browser-observation claim
  for that same after projection; its claim ID, page/connection identities, and
  `browser_trace` path/digest equal the receipt. Both Host projections, the
  restart claim, and the receipt use equal Host source revision, executable
  digest, configuration identity, Store ID, and session ID. The verifier
  establishes from the before parent's retained Store export and Host trace that
  its ordered record descriptors end at `before_durable_tail_record_seq`, that
  restart appended no `Closed`, created no session, recovered every fact after
  `before_processed_through_record_seq` through
  `before_durable_tail_record_seq`, and then admitted the new fact exactly once
  at `continued_record_seq = before_durable_tail_record_seq + 1`.
  `recovered_through_record_seq` equals the pre-stop durable tail. The receipt
  orders Host stop, Host start, completed recovery, and continued-record commit
  within the claim interval; records one unchanged page instance and distinct
  old/new WebSocket connection identities; binds the exact ordered visible
  `DISCONNECTED`, `STALE`, `RESYNCHRONIZING`, and `LIVE` observations; and records
  that the Sensor and Mac were not restarted and the same SQLite store was
  retained. Those four observations equal the selected Diagnostic UI
  host-restart-recovery case byte-for-byte as JSON values.
- `storage_qualification_report` validates as
  `$defs.StorageQualificationReport`; Host source revision, Host executable
  digest, VFS, ordered VFS attempts, environment, fixed checks, individual
  results, and aggregate result equal the storage claim. On success, the
  selected VFS, checks, and result equal the first passing attempt, every prior
  attempt failed, and no later attempt exists. If all attempts fail, those
  fields equal the final attempt. A successful claim has seven successful
  selected-attempt checks. The selected Program storage and current-Mac resource claims have
  exactly equal environments, and the storage report repeats that same
  environment. The resource report's Mac, OS, and architecture fields MUST
  agree with it.
- `resource_qualification_report` validates as
  `$defs.ResourceQualificationReport` and matches the resource claim's Host
  revision, executable, configuration identity, corpus, interval, environment,
  configured memory, CPU-thread, and snapshot-deadline limits, and aggregate
  result. It identifies
  the target Host, macOS, CPU and thread policies, executable profile, exact Mac
  model, architecture, macOS/Rust/Node/Chrome versions, and exact procedure. It
  records the actual one-Sensor/one-route/one-Link/one-Profile packet and native
  coordinate load, window width and step, configured snapshot deadline, query
  load, missed deadlines, input loss, unexplained sequence gaps, write failures,
  peak RSS and thread count, p95/p99/maximum snapshot observations, and client
  backpressure. A successful report has no missed deadline, loss, unexplained
  gap, or write failure; remains within its configured RSS/thread limits;
  satisfies `p95 <= p99 <= maximum`; and confirms that semantic input,
  estimator behavior, and retained facts were unchanged. Its configured
  deadline remains the positive value constrained by temporal-world v1 and is
  never replaced by an invented fixed duration. Its `corpus_sha256` equals the
  `content_sha256` of the physical-source corpus selected through the
  `captured-corpus-e2e` receipt; that claim's `manifest_sha256` and
  `corpus_version` identify the exact manifest rather than an unrelated corpus
  digest.

Every parent ID MUST resolve to exactly one claim in the same graph, and the
parent MUST NOT be the child itself. The resulting directed graph MUST be
acyclic. Each claim's `started_at` MUST be no later than its `finished_at`.
Every physical-capture datagram's `receive_utc_ns` MUST fall within that claim's
inclusive execution interval. `projection_committed_at` MUST fall within its
Host-projection claim; `watermark_received_at`, `http_received_at`, and
`screenshot_captured_at` MUST each fall within their browser-observation claim.
The watermark time equals receipt of the transcript's matching
`projection_watermark`; HTTP time equals receipt of the retained body; and
screenshot time equals the selected PNG's bound BrowserTrace event. The contract
does not otherwise require every parent interval to be contained within its
child interval. Artifact bytes and digests, claim types, identity equality,
Store identity, record order, event time, and projection watermark relations
MUST validate before a graph can pass.

The verifier applies these minimum typed parent edges and equality checks:

| Parent -> child | Required equality and binding |
| --- | --- |
| `physical_capture` -> `corpus_input(source_kind=physical_capture)` | The physical claim's route, source identity, and ordered datagram digest/peer/receive facts equal the corpus manifest's physical lineage and datagrams; the corpus claim's manifest and content digests equal that manifest. |
| `corpus_input` -> `host_projection` | Configuration identity is equal, and the projection receipt, Host trace, and store export bind every corpus datagram in order to one transaction-A fact and its following transaction B. |
| `physical_capture` -> `host_projection` | Configuration identity, Host source revision, and Host executable digest are equal; the capture/export/Host-trace evidence and projection receipt bind each exact datagram to the same admitted fact and ordered A/B commit events. |
| `host_projection` -> `browser_observation` | HTTP and WebSocket Projection commit identities both equal the parent Host Projection commit identity; retained body, transcript, BrowserTrace, DOM observation, and PNG bind that same committed view. |
| `host_projection` -> `host_restart` | Exactly two distinct Host-projection parents are required. Both use the restart's same `session_id`. The before parent's Store export binds `before_projection`, `before_processed_through_record_seq`, every ordered durable record descriptor, and `before_durable_tail_record_seq`; the after parent binds `after_projection` and contains exactly one newly admitted packet-fact commit matching `continued_record_seq` and `continued_datagram_sha256`. The retained exports and Host trace prove recovery committed any A-only tail, appended no `Closed`, created no session, and committed the new record exactly once at pre-stop durable-tail plus one. Both parents and the restart claim have equal Host source revision, Host executable digest, configuration identity, Store ID, and session ID. |
| `browser_observation` -> `host_restart` | Exactly one browser-observation parent is required. Its sole Host-projection parent is the restart's after parent; its HTTP and WebSocket projection identities equal `after_projection`, and its fixed BrowserTrace locator, page identity, and new connection identity are the ones bound by the Host Restart receipt. |

Physical-capture, storage-qualification, and resource-qualification claims have
no parent. Resource qualification is a separately selected Program Completion
gate, not an E2E classification ancestor. Any parent edge used for a
classification that is not one of the typed edges above is invalid; extra
ancestry cannot substitute for a required edge.

A `corpus_input` claim's `manifest_sha256` MUST equal both the SHA-256 of its
referenced `corpus_manifest` artifact and the digest suffix of `corpus_version`.
Its `source_kind`, `content_sha256`, and datagram order, route identity, digests,
peer, and receive context MUST equal the decoded manifest. For
`physical_capture`, successful physical-capture parents MUST collectively bind
every declared physical source and datagram. For `generated_scenario`, it MUST
NOT have a physical capture parent. Manifest validation alone establishes
neither ancestry nor an executed classification.

Only the independent verifier emits a `VerificationReceipt`. Its
`graph_sha256` is SHA-256 over the original, exact ExecutionClaimGraph file
bytes after that file passes the JCS byte-identity check; it is not embedded in
the graph. The verifier MUST NOT parse and reserialize the graph to obtain the
hashed bytes. `root_claim_ids` is strictly ordered and unique by claim-ID raw
UTF-8 bytes; every ID resolves uniquely to a successful claim in the bound
graph. The verifier derives a classification solely from the ancestor closure
of those proof tips. Every claim on a required path MUST have `result=pass`, and
the proof-tip shapes below MUST support exactly one classification; zero or
multiple supported classifications produce no VerificationReceipt.

Each classification has one fixed, non-conflicting receipt filename:

| Classification | Root filename |
| --- | --- |
| `board-capture-smoke` | `board-capture-smoke-verification-receipt.json` |
| `captured-corpus-e2e` | `captured-corpus-e2e-verification-receipt.json` |
| `scenario-e2e` | `scenario-e2e-verification-receipt.json` |
| `live-physical-e2e` | `live-physical-e2e-verification-receipt.json` |

The filename does not issue or promote its classification. The decoded receipt,
bound exact graph bytes, and successful typed proof remain authoritative.

The minimum successful typed paths ending at a proof tip are:

| Classification | Required path |
| --- | --- |
| `board-capture-smoke` | proof-tip `physical_capture` |
| `captured-corpus-e2e` | `physical_capture -> corpus_input(source_kind=physical_capture) -> host_projection ->` proof-tip `browser_observation` |
| `scenario-e2e` | `corpus_input(source_kind=generated_scenario) -> host_projection ->` proof-tip `browser_observation`, with no physical-capture ancestor |
| `live-physical-e2e` | direct `physical_capture -> host_projection ->` proof-tip `browser_observation`, with no intervening `corpus_input` claim |

For `live-physical-e2e` only, every physical datagram bound into the direct
physical-to-Host edge has exactly one matching projection-receipt
`packet_fact_commits` entry. The same physical `receive_utc_ns` instant MUST lie
within both the physical-capture and Host-projection intervals, and the verifier
MUST establish this inclusive order separately for every retained datagram:

```text
physical datagram receive_utc_ns
    <= matching HostCommitTrace transaction-A event UTC
    <= matching HostCommitTrace transaction-B event UTC
    <= host_projection.projection_committed_at
    <= browser_observation.watermark_received_at
    <= browser_observation.http_received_at
    <= browser_observation.screenshot_captured_at
```

SQLite and the canonical store export prove committed state identity; the
HostCommitTrace proves the procedural A-before-B execution order after successful
commits. The existing Store and Projection commit equalities still apply to the
Host B event, WebSocket watermark, and HTTP ViewReceipt in that chain. A
`captured-corpus-e2e` or `scenario-e2e` proof still binds each replay transaction
A before its transaction B and retains each event inside its owning claim
interval, but MUST NOT compare the corpus's declared physical receive time with
the later replay commit times or otherwise make captured or generated input
contemporaneous with replay.

The receipt's `verified_at` MUST be no earlier than `finished_at` for every
claim used in the selected proof. Subject names, tool identities, graph edges,
and artifact digests provide procedural lineage only; they are not a PKI,
hardware attestation, or proof of physical origin without the required executed
claim path.

The classifications support these bounded meanings:

| Classification | Required successful ancestry and supported claim |
| --- | --- |
| `board-capture-smoke` | A `physical_capture` claim binds a contemporaneous identified ESP32-S3, ordinary provisioning, exact datagrams, and production Host admission/decoding. It does not prove browser, restart, resource, soak, or release behavior. |
| `captured-corpus-e2e` | A `corpus_input` with `source_kind=physical_capture` descends from a successful physical-capture claim, and its exact datagrams descend through a committed `host_projection` claim to a `browser_observation` claim. It is not a contemporaneous live physical run. |
| `scenario-e2e` | A `corpus_input` with `source_kind=generated_scenario` descends through committed Host projection to browser observation. It is neither captured hardware data nor physical proof. |
| `live-physical-e2e` | One fresh physical-capture claim, its transaction-A facts, transaction-B Projection commit identity, HTTP ViewReceipt, WebSocket invalidation, and visible Chrome observation form one time-consistent ancestry during the retained interval. |

A caller, corpus manifest, claim producer, filename, label, or opaque receipt
blob MUST NOT set or promote one of these classifications. One classification
MUST NOT satisfy another classification's physical or live step. Test source
remains distinct from executed evidence, and failed claims remain ineligible
ancestry rather than disappearing from a retained graph.

An early live browser tracer and every final browser claim retain the same exact
four-event `BrowserTrace`: watermark, HTTP body, visible DOM observation, then
one screenshot. The eleven-case Diagnostic UI report composes separately bound
browser claims; it does not enlarge one BrowserTrace or block an early tracer
from producing its bounded evidence.

Physical capture lineage is procedural in Program 1. The claim binds the
identified board, firmware image, schema-defined provisioning receipt, Sensor,
route, Link/Profile, capture tool, interval, receive context, and datagram
digests.
The public development fixture key and AES-256-GCM authenticate known fixture
bytes but do not attest hardware identity or physical origin. Program 1 makes
no hardware-attestation claim.

A final Program 1 graph MUST bind the source revisions; firmware image and Host
executable digests; board, route, Profile, and configuration identities; Store
ID; session and record bounds; Projection commit identity; HTTP ViewReceipt and
WebSocket watermark; browser and tool versions; execution intervals; trace,
screenshot, and all retained artifact digests.

### Diagnostic UI acceptance report

Only the independent verifier emits `diagnostic-ui-acceptance-report.json`. It
validates as `$defs.DiagnosticUiAcceptanceReport` and contains exactly these
passing behavior cases in order:

1. `context_and_dynamic_facets`;
2. `resize_zoom_identity`;
3. `axis_semantics_and_read_only_safety`;
4. `missing_vs_zero`;
5. `timeline_view`;
6. `world_view`;
7. `evidence_view`;
8. `baseline_view`;
9. `protocol_error`;
10. `transport_reconnect`; and
11. `host_restart_recovery`.

Every case binds one passing `browser_observation` claim in the same graph by
classification, claim ID, execution interval, exact `browser_trace` path and
digest, and its sole PNG screenshot locator. Its claim ID MUST occur in
`root_claim_ids` of the bound VerificationReceipt for that classification.
Claim IDs and BrowserTrace paths are unique across cases. The verifier requires
every binding to equal that claim's fixed-role artifact and screenshot locator,
validates the bound BrowserTrace and PNG, and independently queries each retained
selector in the identified Chrome version. The report's source revision and
Chrome version match those claims, its interval contains all case intervals,
and each case interval contains its recorded observations.

The context case retains exact visible Deployment, Sensor, Link, Profile, and
session observations plus at least two distinct `(stream_id, profile_id)` signal
facets from a dynamic-layout scenario. The resize/zoom case retains its exact
action, one shared stream/Profile/native-coordinate identity, and before/after
viewport width, viewport height, zoom percentage, and visible facet
observations. At least one viewport or zoom value MUST change; the shared
identity shape prevents the action from naming a different stream, Profile,
native-coordinate kind, or label as its after state.

The axis/safety case retains the actual native-coordinate kind and its raw
visible axis-label observation. The label MUST truthfully match the API/UI-v1
coordinate kind. For the Program 1 fixture it records `geometry_available=false`
and `human_labels_available=false`, then retains the exact queried selectors and
zero match counts for baseline-command controls, all state-changing controls,
spatial heatmaps, and person, presence, and pose semantics. A selector token or
zero count that the verifier did not query in Chrome is insufficient.

The missing-versus-zero case retains both queried values, their accessibility
values, and their computed color, background, opacity, display, and visibility
strings; the missing and measured zero observations MUST differ visibly and
accessibly. Each Timeline, World, evidence, and baseline case retains the raw
visible structured observation for that view.

The protocol-error case retains the exact invalid input used by the verifier and
the resulting visible protocol-error observation. The transport-reconnect case
keeps ingest quiescent and retains exactly one unchanged Host process instance,
page instance, session, and Projection identity; distinct before/after
connection identities; zero page navigations; equal before/after retained
commit-index row counts; and exactly `DISCONNECTED`, `STALE`,
`RESYNCHRONIZING`, then `LIVE`. The new connection's first message is the
mandatory matching Projection watermark, and the bound HTTP body carries that
same identity. Any transaction B, retention change, Host restart, navigation,
or changed projection disqualifies this case.

The host-restart-recovery case retains exactly `DISCONNECTED`, `STALE`,
`RESYNCHRONIZING`, then `LIVE`, with
nondecreasing observation times and a raw visible observation for each state;
its final `LIVE` observation matches the bound ordinary four-event BrowserTrace
DOM event. Its `host_restart_claim_id` resolves to the selected passing restart
claim, and its browser `claim_id`, trace, and screenshot equal that restart's
browser parent. The case repeats the restart's one session ID, before/after
projections, pre-stop durable tail and processing cursor, recovered-through
cursor, continued record sequence and datagram digest, unchanged page instance,
and distinct before/after connection identities. Its interval contains the Host
stop, start, completed recovery, and continued-record commit; `DISCONNECTED`
precedes `STALE`, which precedes
`RESYNCHRONIZING`, which precedes `LIVE`, and `LIVE` is observed only after the
bound continued record and after projection commit. No zero-semantic-event or
same-projection condition applies across this restart. The early connection
state tracer does not add events to or delay the final four-event BrowserTrace.
A selected Host Restart receipt's `connection_states` equals this case's
`states` exactly; neither the four-event BrowserTrace nor an aggregate pass
field can substitute for the ordered visible state observations.
A case name, aggregate `result=pass`, digest list, or producer-authored token
without these independently checked observations and graph locators is
insufficient.

### Program Completion receipt

Only the independent verifier emits `program-completion-receipt.json`. It
validates as `$defs.ProgramCompletionReceipt` and is the sole representation of
Program 1 completion. A valid `live-physical-e2e` VerificationReceipt is
necessary but is not by itself Program 1 completion.

The Program Completion receipt binds `execution-claim-graph.json` by exact path
and SHA-256. Its fixed four-entry `verification_receipts` array binds each
classification receipt above by its classification, exact root path, and
SHA-256. The verifier decodes each bound file as a successful
`VerificationReceipt`, requires its classification to match that entry, and
requires all four receipts and the Program Completion receipt to carry the same
`graph_sha256`. Missing, duplicate, substituted, reordered, or graph-mismatched
classification receipts fail closed.

Every Host-projection claim in any of the four selected receipt ancestries MUST
use the Program `source_revision`, `host_executable_sha256`, and
`configuration_identity_sha256`; the Stores for distinct runs MAY differ. Every
physical-capture claim used by the selected `board-capture-smoke`,
`captured-corpus-e2e`, or `live-physical-e2e` ancestry MUST use the Program
`source_revision` as its `firmware_revision` and use the Program
`firmware_image_sha256`. These graph equalities make the clean monorepo source
revision and firmware/Host identities verified ancestry, not top-level
self-report.

The receipt names one `host_restart`, one `storage_qualification`, and one
`resource_qualification` claim ID. Each ID MUST resolve uniquely in that graph
to a passing claim of the named type. Each accompanying artifact path and digest
MUST equal that claim's sole fixed-role receipt or report locator. The Program
Completion `verified_at` is no earlier than every selected claim's `finished_at`
or any of the four classification receipts' `verified_at`.

The selected restart claim and receipt use the Program source revision, Host
executable digest, configuration identity, and Store ID. Its before and after
Host-projection parents use those same values and the same session
with distinct before/after projection bindings above. The Program `host_restart` object repeats the
restart claim/report locator and its browser parent's claim ID and BrowserTrace
path/digest. Program `session_id` continues to name the final live proof-tip
session; it is not required to equal the restart session.

The selected storage claim and report use the Program source revision and Host
executable digest. The selected current-Mac resource claim and report also use
the Program source revision, Host executable digest, and configuration identity,
and the captured-corpus Host projection selected by the
`captured-corpus-e2e` receipt uses that same configuration identity. Storage and
resource claim environments are byte-for-byte equal as JSON values, the storage
report repeats that environment, and the resource report's Mac, OS, and
architecture fields agree with it. The resource `corpus_sha256` equals the
`content_sha256` of the selected physical-source corpus claim, whose manifest
digest and corpus version identify that exact corpus.

Its `diagnostic_ui` field binds `diagnostic-ui-acceptance-report.json` by exact
path and SHA-256. The verifier decodes those exact canonical bytes, requires all
eleven behavior cases above, and applies every graph/BrowserTrace/PNG equality.
Every case's browser claim has a Host-projection parent using the Program source
revision, Host executable digest, and configuration identity. The Program
Completion source revision and Chrome version equal the report. The
`host_restart_recovery` case binds the same restart claim, browser claim, and
BrowserTrace named by Program `host_restart` and repeats its session, durable
tail, processed cursor, continued record/datagram, connection, and projection
transition. A missing, failing,
structurally incomplete, or locator-mismatched diagnostic UI report prevents
Program Completion.

The receipt may be emitted only from a clean source tree at its bound
`source_revision`; `source_tree_status` is therefore exactly `clean`. The
selected `live-physical-e2e` browser proof tip has exactly one Host-projection
parent. That parent supplies the Program configuration identity, Store ID,
session ID, source revision, and Host executable digest; its direct physical
parent supplies the Program source revision as firmware revision and the Program
firmware image digest. Its Chrome version, browser
claim ID, BrowserTrace path and digest, and sole screenshot locator equal that
proof-tip browser claim. This binding establishes only the independently
queried visible DOM value and screenshot for the same committed HTTP and
WebSocket view. It cannot bypass those retained artifacts or stand in for the
separate Diagnostic UI acceptance report.

This composed receipt repeats only equality bindings and selected passing claim
IDs. It does not replace, weaken, or promote any of the four typed
classifications and is not an opaque aggregate proof.

All graph artifacts MUST satisfy the secret and sensitive-artifact exclusions
owned by [native-frame v1](native-frame-v1.md#provisioning-and-image-compatibility)
and [host persistence v1](persistence-v1.md#program-1-development-secret-store).

## Composed acceptance

Program 1 selects the deterministic development fixture key and ordinary
firmware provisioning contract from [native-frame v1](native-frame-v1.md), the
temporary secret-store and minimal Host restart contracts from
[host persistence v1](persistence-v1.md), the read-only diagnostic Web and real
Chrome recovery contract from [API/UI v1](api-ui-v1.md), and the current-Mac
resource contract from [evaluation v1](evaluation-v1.md). Those specifications
remain the sole owners of their exact component behavior.

The highest repeatable application seam is one lifecycle-owned `CaptureRuntime`:
the runner feeds received encrypted datagrams through the ordinary admission
path and observes committed Projection commit identities and HTTP results.
Tests MUST NOT bypass transaction A, inject decoded observations below capture,
or fabricate projection rows for Program 1 E2E classification.

Program 1 completes only when a valid `ProgramCompletionReceipt` composes all
four fixed VerificationReceipts, a passing Host-restart claim, a passing
storage-qualification claim, a passing current-Mac resource-qualification
claim, the final live visible committed browser result, and a passing Diagnostic
UI acceptance report with all eleven behavior cases. This requires repeatable
`captured-corpus-e2e` and `scenario-e2e` coverage, the independent
`board-capture-smoke` boundary, and one reconstructable `live-physical-e2e` run;
none substitutes for another. Their presence as accepted targets in this
specification is not evidence that any run occurred, and a live receipt without
the composed Program Completion receipt does not complete Program 1.

Operator calibration, calibration-quality HTTP, training-corpus lifecycle,
model training, hostile same-credential storage hardening, executed
second-platform qualification, and physical Multi-sensor acceptance are not
Program 1 completion criteria. Their future authorities remain the roadmap and
later issue graphs.
