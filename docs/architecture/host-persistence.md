# Host persistence architecture

This document owns the non-discoverable module responsibilities, interfaces,
seams, and invariants for host configuration, sessions, and persistence. Exact
schema, bytes, ordering, paths, errors, and runtime behavior live only in the
[host persistence v1 specification](../specs/persistence-v1.md).

## Module responsibilities

The configuration module owns the sole interface from human-authored TOML to a
validated immutable configuration. It separates replay-semantic identity from
process-only operation and supplies strong sub-configuration values. It does
not own session lifecycle or persistence.

The session module owns Store-topology manifest, session manifest,
ordered-record, complete-baseline-handoff, and strict codec interfaces shared
by live capture and replay. It does not own SQLite lifecycle or semantic
mutation.

The application module owns the only external lifecycle interface.
`HostLifecycle` accepts small operator intents for provisioning, capture,
replay, and corpus export, then coordinates trusted-root validation,
cooperative leasing, secrets, open, same-session recovery, lazy session
creation, and retention. A successful capture open
returns `CaptureRun`, which owns the complete managed-store lease, sole
synchronous writer connection, ingest order, rotation, shutdown, and publication
sequencing without exposing internal persistence or Engine operations. A
successful corpus-export open returns `CorpusExport`, a bounded read-only shell
that retains the same lifecycle lease through all of its export readers and
owns the sole connection and sealed-session SQLite read snapshot used by those
readers.

The managed-store module is a concrete internal module behind that lifecycle
seam. It owns the dedicated-root lease, staged provisioning and atomic
no-replace publication, non-creating SQLite opens, Store identity, writer
eligibility under the lifecycle lease, and qualified current-platform SQLite
VFS selection. It also owns the immutable provisioned Store topology manifest
used by sequence-zero and later Store-scoped reads. Its contract coordinates
cooperative Whisper processes in a trusted local development namespace; it is
not a same-credential filesystem security boundary.

The persistence module is a concrete internal module. It owns durable
admission, the authoritative record log, session lifecycle, rebuildable
projections, the retained projection-commit index, pending baseline handoff,
recovery commits, and retention. Its interface accepts strong
validated values and finished proofs rather than generic tables, bytes,
repositories, checkpoints, or caller-selected lifecycle states.

The Engine is a concrete internal module. It alone owns the mutable Timeline,
estimator, current World state, and semantic mutation, and produces concrete
transitions, complete WindowProjection values, and complete baseline handoffs.
A WindowProjection is one snapshot with the full ordered aggregate Link/Profile
evidence set. Persistence owns the committed rows and validates and stores those
supplied values at the commit seam; it does not reconstruct Engine state.

Query and delivery modules read committed projections. They cannot mutate raw
facts, Engine state, lifecycle, or baseline handoffs.

Corpus export is a separate application-owned read intent. It reads immutable
packet facts from one sealed session without entering the ordinary HTTP/query
projection seam or the replay processing seam, and cannot mutate facts,
projections, lifecycle, admission state, Engine state, or evidence
classification.

## Interfaces and seams

```text
operator intent
  -> HostLifecycle interface
  -> CaptureRun interface

validated configuration + secrets
  -> managed-open seam
  -> managed-store lease + Store identity
  -> admission handle seam

authenticated datagram + receive context
  -> durable fact seam
  -> decoder + CaptureRun processing coordinator
  -> Engine semantic seam or typed decode-reject seam
  -> transition commit seam
  -> publication seam

active manifest + ordered facts
  -> recovery/replay seam
  -> same-session continuation or explicit incompatibility

validated configuration + sealed session
  -> corpus-export seam
  -> retained managed-store lease + one read-only snapshot

finished Engine transition + complete baseline handoff
  -> seal/pending-handoff seam

first durable fact with no active session
  -> lazy-creation seam
  -> pending handoff copied into the new manifest
```

The application-owned surface is the following conceptual internal interface.
The names freeze module ownership and the operations available to implementation
leaves; they do not create a public Rust API or prescribe an async, callback, or
concrete error representation.

```text
HostLifecycle::provision(ProvisionIntent) -> StoreId
HostLifecycle::capture(CaptureIntent) -> CaptureRun
HostLifecycle::replay(ReplayIntent) -> ReplayResult
HostLifecycle::corpus_export(CorpusExportIntent) -> CorpusExport

CaptureRun::ingest(ReceivedDatagram) -> CommittedProjectionIdentity
CaptureRun::control(CaptureControl) -> CommittedProjectionIdentity
CaptureRun::finish(FinishIntent) -> FinishedCapture
```

`ProvisionIntent`, `CaptureIntent`, `ReplayIntent`, and `CorpusExportIntent`
contain validated operator choices only. `CorpusExportIntent` selects its
existing Managed database and immutable Store topology through validated
current configuration and identifies one sealed session; it does not accept an
arbitrary database path. Historical route and replay identities come exclusively
from that sealed session's manifest, not current replay configuration.
`CaptureRun` is the
sole live ingest owner. A complete encrypted datagram and its receive
context enter at `ingest`; no caller can enter at decoded observation, Engine
transition, persistence-row, or projection publication level. `control`
accepts only the ordered Timeline and baseline control inputs owned by the
session contract. `finish` owns stop-input, drain, durable `Closed`, Engine
finish, final transition commit, seal, and pending handoff publication; it does
not create a successor, and there is no separate caller-visible seal operation.

Behind `CaptureRun`, transaction A returns a private, unforgeable
`DurableRecord` capability only after replay admission and the exact encrypted
fact commit together. Decoder and Engine entry requires that capability and
cannot be invoked with caller-constructed bytes. An ordered control obtains the
same capability only after its exact control fact commits; recovery and replay
obtain it only from the lifecycle's verified ordered-fact iterator. The
processing coordinator owns the closed transition passed to the commit seam;
callers cannot forge, regroup, or partially persist that transition. Only the
committed projection identity returned by that seam may cross into publication.
The first transaction B of a lazily created session also carries the Engine's
complete current baseline set, even for a decode rejection, so making the
session visible cannot omit its manifest-seeded baseline projection.
The exact transition variants, reject categories, validation, and transaction
effects are owned by the
[host persistence v1 specification](../specs/persistence-v1.md).

The application interface has depth because small lifecycle intents hide
trusted-root validation, leasing, staged publication, non-creating open, SQLite
recovery, rotation, and publication ordering. This keeps those
invariants local instead of making every caller coordinate them.

The managed-store seam owns one complete lifetime: the root lease is acquired
before SQLite open and remains held until all writer and reader connections are
closed. Under that lease, corpus export uses a short-lived non-creating recovery
and validation connection, closes it, then owns one read-only connection and
one long-lived sealed-session snapshot borrowed by every export reader. Ending
that snapshot and closing its connection precede lease release. Exact open,
recovery, snapshot-validation, and close behavior is owned by the
[host persistence v1 specification](../specs/persistence-v1.md). Process
termination releases the operating-system lease; a later lifecycle performs
SQLite WAL recovery before Host fact replay.

The configuration and session interfaces provide leverage: the same strong
values and codecs serve live capture, recovery, and replay. Runtime-only values
stop at the manifest seam.

The durable fact seam precedes semantic interpretation. The transition commit
seam precedes publication, so readers cannot observe state that recovery would
discard.

The recovery/replay seam makes the active manifest and ordered facts the sole
inputs to fresh semantic state through the production processing path. It
cannot use a derived row or serialized Timeline value as resume authority,
bypass the normal commit seam, or repair committed state opportunistically. A
Host reopen whose replay identity exactly matches the active manifest rebuilds
and continues that same session; a mismatch fails closed without adding
`Closed`, sealing, or creating another session. Exact replay, comparison,
failure, and continuation behavior is owned by the
[host persistence v1 specification](../specs/persistence-v1.md).

The seal/pending-handoff seam carries one complete baseline handoff. Final
transaction B seals the old session and installs the pending handoff atomically.
When no session is active, the next transaction A lazily creates one and copies
that exact handoff into its manifest before consuming the pending value. The
pending value is therefore bootstrap authority even if retention removes its
sealed source. A retention deletion and its next global query-visible Store
watermark share one transaction; only the committed identity crosses the
invalidation seam.

## Adapters

SQLite's VFS, the OS advisory lock, and store publication are
implementation-local adapters with narrow seams inside the managed-store
module. They do not change the external lifecycle interface. Exact selection,
qualification, permissions, and publication behavior is owned by the
[host persistence v1 specification](../specs/persistence-v1.md). V1 introduces
no provider trait, repository interface, pool, actor, privileged broker, or
generic migration framework.

## Invariants

- One configuration root supplies every module; replay identity and runtime
  operation remain distinct.
- `HostLifecycle`, `CaptureRun`, and `CorpusExport` own external lifecycle
  sequencing. Persistence exposes no bare seal, caller-selected recovery state,
  or general database-path opener.
- One dedicated trusted local root and one lifecycle-owned OS lease coordinate
  cooperative Whisper processes. Hostile root or same-credential namespace
  mutation is outside Program 1's guarantee.
- Existing managed opens are non-creating. Provisioning alone initializes a
  private same-directory staged store and publishes the closed validated store
  atomically without replacement.
- The non-secret Store ID is stable for one provisioned store. The retained OS
  lease is the sole cooperative lifecycle writer fence.
- The provisioned Store topology manifest is immutable and is the only source
  for Deployment, Space, Transmitter, Sensor, and Link topology. A configured
  topology mismatch requires another Store; current TOML never changes a
  committed view.
- One SQLite database is the host fact store. A file log, decoded-frame log, or
  external database cannot become a second authority.
- One sequential ingest owner holds the writer and Engine mutation. Query and
  delivery remain readers of committed state.
- Ordinary HTTP/query, faithful replay, and corpus export are distinct read
  intents. Corpus export is bounded to one sealed-session snapshot and cannot
  become a mutation or evidence-classification seam.
- The record envelope owns order, time, and kind once. The kind-specific body
  does not duplicate that envelope.
- Raw packet and control records are immutable facts. Processing state,
  baselines, observations, snapshots, and evidence are rebuildable projections.
- Manifest plus ordered records are the sole recovery authority. Serialized
  Timeline bytes are never resume authority. Recovery uses the production
  processing and commit seams and does not create an alternate mutation path.
- Process restart is not a session boundary. Compatible restart recovers and
  continues the same active session and record sequence; incompatible replay
  identity fails closed rather than mutating that session.
- A manifest contains every non-secret input required to identify faithful
  replay; current disk configuration is not replay authority.
- Memory is disposable. Resume and publication authority comes from committed
  persistence plus deterministic rebuild from the manifest and ordered facts.
- Admission mutation and raw insertion share one durability unit. Semantic
  state and its projections share another. Neither can publish partial effects.
- Transaction A cannot change query-visible state. Query readers reach facts
  only through the committed processing cursor and reach sessions only after
  their first transaction B.
- The Store watermark advances once for every transaction that changes
  query-visible rows, including retention deletion. A committed visible state
  never reuses an earlier identity.
- The retained projection-commit index maps at most one transaction B to each
  retained record. Recovery supplies retry-to-completion; the index's unique
  record binding rejects a duplicate commit. Retention may remove old
  session-bound index rows, replaces the sole unowned retention marker, and
  records one new retention commit, so the index is not an immutable historical
  ledger.
- Each persisted snapshot and its evidence represent one Engine-owned
  WindowProjection. Persistence does not recompute Engine's
  contributor/baseline union or infer omitted keys.
- The Engine produces the complete baseline handoff; persistence validates and
  stores it without inventing semantic values.
- A pending baseline handoff is inter-session bootstrap authority, not a query
  projection. The first transaction B publishes a complete current baseline set
  before the lazily created session becomes visible.
- Active sessions are neither faithful-replay nor retention inputs. Recovery
  proves the committed prefix, commits the exact durable tail sequentially, and
  continues the same lifecycle without a synthetic finish.
- Synchronous database work does not block asynchronous socket, ingest, or
  query execution.

The rationale for SQLite authority, trusted development storage scope, logical
session accounting, key-bound replay admission, and same-session compatible
restart is recorded in
[ADR 0003](../adr/0003-sqlite-authoritative-session-store.md),
[ADR 0013](../adr/0013-trust-program-1-local-store-namespace.md),
[ADR 0005](../adr/0005-logical-session-fact-bytes.md),
[ADR 0006](../adr/0006-bind-replay-admission-to-epoch-key.md), and
[ADR 0015](../adr/0015-keep-compatible-host-restart-in-active-session.md).
Current receipts
and maturity are recorded in the
[host persistence evidence index](../evidence/host-persistence.md).
