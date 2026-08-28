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

The session module owns manifest, ordered-record, complete-baseline, and strict
codec interfaces shared by live capture and replay. It does not own SQLite
lifecycle or semantic mutation.

The application module owns the only external lifecycle interface.
`HostLifecycle` accepts small operator intents for provisioning, capture, and
replay, then coordinates managed-path resolution, exclusive locking, secrets,
open, recovery, successor creation, and retention. A successful capture open
returns `CaptureRun`, which owns the active lock, writer, ingest order,
rotation, shutdown, and publication sequencing without exposing internal
persistence or Engine operations.

The persistence module is a concrete internal module. It owns durable
admission, the authoritative record log, session lifecycle, rebuildable
projections, recovery commits, and retention. Its interface accepts strong
validated values and finished proofs rather than generic tables, bytes,
repositories, checkpoints, or caller-selected lifecycle states.

The Engine is a concrete internal module. It alone owns semantic mutation and
produces concrete transitions and complete baseline handoffs. Persistence
validates and stores those supplied values at the commit seam; it does not
reconstruct Engine state.

Query and delivery modules read committed projections. They cannot mutate raw
facts, Engine state, lifecycle, or baseline handoffs.

## Interfaces and seams

```text
operator intent
  -> HostLifecycle interface
  -> CaptureRun interface

validated configuration + secrets
  -> managed-open seam
  -> admission handle seam

authenticated datagram + receive context
  -> durable fact seam
  -> decoder and Engine seam
  -> transition commit seam
  -> publication seam

manifest + ordered facts
  -> recovery/replay seam
  -> finished-proof seam
  -> lifecycle commit seam

finished Engine transition + complete baseline handoff
  -> successor/retention seam
```

The application interface has depth because small lifecycle intents hide lock,
open, recovery, rotation, and publication ordering. This keeps those invariants
local instead of making every caller coordinate them.

The configuration and session interfaces provide leverage: the same strong
values and codecs serve live capture, recovery, and replay. Runtime-only values
stop at the manifest seam.

The durable fact seam precedes semantic interpretation. The transition commit
seam precedes publication, so readers cannot observe state that recovery would
discard.

The recovery/replay seam makes the manifest and ordered facts sufficient for a
fresh Engine. The finished-proof seam prevents a non-appendable tail from being
mistaken for completed recovery.

The successor/retention seam carries one complete baseline handoff. Retention
cannot remove its source until the successor owns the same handoff.

## Adapters

SQLite and the OS advisory lock are implementation-local adapters. Each has a
narrow seam inside the application or persistence implementation, and its
locality permits replacement there without changing the external lifecycle
interface. V1 has one implementation of each; no provider trait, repository
interface, pool, actor, or generic migration framework is introduced because it
would add variation without leverage.

## Invariants

- One configuration root supplies every module; replay identity and runtime
  operation remain distinct.
- `HostLifecycle` and `CaptureRun` own external lifecycle sequencing.
  Persistence exposes no bare seal or caller-selected recovery state.
- One SQLite database is the host fact store. A file log, decoded-frame log, or
  external database cannot become a second authority.
- One sequential ingest owner holds the writer and Engine mutation. Query and
  delivery remain readers of committed state.
- The record envelope owns order, time, and kind once. The kind-specific body
  does not duplicate that envelope.
- Raw packet and control records are immutable facts. Processing state,
  baselines, observations, snapshots, and evidence are rebuildable projections.
- A manifest contains every non-secret input required to identify faithful
  replay; current disk configuration is not replay authority.
- Memory is disposable. Resume and publication authority comes from committed
  persistence plus deterministic rebuild from the manifest and ordered facts.
- Admission mutation and raw insertion share one durability unit. Semantic
  state and its projections share another. Neither can publish partial effects.
- The Engine produces the complete baseline handoff; persistence validates and
  stores it without inventing semantic values.
- Active or incomplete sessions are neither replay nor retention inputs.
  Recovery proves the exact durable tail and derived state before lifecycle
  completion.
- Synchronous database work does not block asynchronous socket, ingest, or
  query execution.

The rationale for SQLite authority, logical session accounting, and
key-bound replay admission is recorded in [ADR 0003](../adr/0003-sqlite-authoritative-session-store.md),
[ADR 0005](../adr/0005-logical-session-fact-bytes.md), and
[ADR 0006](../adr/0006-bind-replay-admission-to-epoch-key.md). Current receipts
and maturity are recorded in the
[host persistence evidence index](../evidence/host-persistence.md).
